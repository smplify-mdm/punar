//! On-disk ledger: the per-session records, the index, retention
//! pruning, and purge (milestone-8.md sections 5.2, 6; docs/api/ipc.md
//! section 13.1).
//!
//! ```text
//! /var/lib/punar/agents/ledger/                  0700 root:root
//! /var/lib/punar/agents/ledger/<session_id>.json 0640 root:root
//! /var/lib/punar/agents/ledger/index.json        0640 root:root
//! ```
//!
//! Every write is one atomic `tmp` + `rename` at most **once per batch
//! per session** — never per audit event, never per sample. At idle
//! nothing writes at all, so the idle write rate is exactly 0 B/s (spec
//! section 6.4).
//!
//! # Deletion is durable (milestone-8.md section 10, guarantee 3)
//!
//! A purge unlinks the record file and replaces its index row with a
//! **tombstone** — `{session_id, user, purged_at}` and nothing else. The
//! tombstone is not bookkeeping: it *floors* audit re-ingestion, so a
//! later drain that re-reads the same bytes cannot resurrect what the
//! user deleted. It carries no resource data of its own.
//!
//! # The audit trail is not the ledger
//!
//! Nothing here touches `/var/log/punar/audit.jsonl`. Spec section 53's
//! log is the tamper-evident record of decisions the *system* made and is
//! outside a user's delete authority; the ledger, which is derived from
//! it, is not. Every purge surface prints that boundary.

use std::io;
use std::path::{Path, PathBuf};

use punar_common::agent::AgentStatus;
use punar_common::ledger::{
    LEDGER_INDEX_FILE, LEDGER_RETENTION_DAYS, LedgerCounts, LedgerIndex, LedgerIndexRow,
    LedgerRecord, MAX_INDEXED_SESSIONS,
};
use punar_common::time::rfc3339_utc_from_unix_seconds;

/// Seconds in a day — the retention arithmetic's only constant.
const SECS_PER_DAY: u64 = 86_400;

/// What one prune batch removed. Each non-empty list becomes **one**
/// `ledger.prune` audit event naming its count — never one event per file
/// (spec section 6.4 forbids exactly that write amplification).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PruneOutcome {
    /// Past `retention_expires_at`.
    pub expired: Vec<String>,
    /// Evicted to keep the index at [`MAX_INDEXED_SESSIONS`]; oldest
    /// **ended** sessions go first, and an active session is never
    /// evicted.
    pub index_cap: Vec<String>,
    /// Index rows whose file vanished underneath us.
    pub orphan: Vec<String>,
}

impl PruneOutcome {
    pub fn is_empty(&self) -> bool {
        self.expired.is_empty() && self.index_cap.is_empty() && self.orphan.is_empty()
    }

    /// `(reason, count)` per non-empty batch, in audit-emission order.
    pub fn batches(&self) -> Vec<(&'static str, usize)> {
        let mut batches = Vec::new();
        if !self.expired.is_empty() {
            batches.push(("expired", self.expired.len()));
        }
        if !self.index_cap.is_empty() {
            batches.push(("index_cap", self.index_cap.len()));
        }
        if !self.orphan.is_empty() {
            batches.push(("orphan", self.orphan.len()));
        }
        batches
    }
}

/// The ledger directory.
#[derive(Debug, Clone)]
pub struct LedgerStore {
    dir: PathBuf,
}

impl LedgerStore {
    pub fn new(dir: impl Into<PathBuf>) -> LedgerStore {
        LedgerStore { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Create the directory `0700 root:root` if it is not already there.
    /// tmpfiles owns this in the image; doing it here too means a test —
    /// and a daemon started before tmpfiles ran — behaves identically.
    pub fn ensure_dir(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::set_permissions(
            &self.dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
    }

    pub fn record_path(&self, session_id: &str) -> PathBuf {
        self.dir.join(format!("{session_id}.json"))
    }

    pub fn index_path(&self) -> PathBuf {
        self.dir.join(LEDGER_INDEX_FILE)
    }

    /// Read one session's record. A file that does not parse, or that
    /// fails [`LedgerRecord::validate`], is reported as `None` with a
    /// warning: a corrupt ledger must never be rendered as if it were
    /// true, and it must never stop the daemon.
    pub fn load_record(&self, session_id: &str) -> Option<LedgerRecord> {
        let path = self.record_path(session_id);
        let text = std::fs::read_to_string(&path).ok()?;
        match serde_json::from_str::<LedgerRecord>(&text) {
            Ok(record) => match record.validate() {
                Ok(()) => Some(record),
                Err(violations) => {
                    eprintln!(
                        "punar-agentd: ledger record {} is not conformant and was not \
                         used: {violations:?}",
                        path.display()
                    );
                    None
                }
            },
            Err(e) => {
                eprintln!(
                    "punar-agentd: ledger record {} could not be parsed: {e}",
                    path.display()
                );
                None
            }
        }
    }

    /// Write one record atomically, `0640`. Validation first, always: the
    /// file is a machine-readable contract the panel and CI both read, so
    /// a daemon bug fails loudly here rather than writing something no
    /// consumer can trust — the `RegistryStore::append` rule.
    pub fn write_record(&self, record: &LedgerRecord) -> io::Result<()> {
        if let Err(violations) = record.validate() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ledger record violates its own contract: {violations:?}"),
            ));
        }
        self.ensure_dir()?;
        let mut bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
        bytes.push(b'\n');
        crate::util::write_atomic(&self.record_path(&record.session_id), &bytes, 0o640)
    }

    /// Unlink one record. A missing file is success — purge is
    /// idempotent, because a user who deletes twice has still deleted.
    pub fn remove_record(&self, session_id: &str) -> io::Result<()> {
        match std::fs::remove_file(self.record_path(session_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Load the index, or a fresh empty one when it is absent or
    /// unreadable. An unreadable index costs the tail position (the drain
    /// restarts and idempotence absorbs it), never the daemon.
    pub fn load_index(&self) -> LedgerIndex {
        let Ok(text) = std::fs::read_to_string(self.index_path()) else {
            return LedgerIndex::default();
        };
        match serde_json::from_str::<LedgerIndex>(&text) {
            Ok(index) => index,
            Err(e) => {
                eprintln!(
                    "punar-agentd: ledger index {} could not be parsed ({e}); starting a \
                     fresh index — existing session files are still readable",
                    self.index_path().display()
                );
                LedgerIndex::default()
            }
        }
    }

    pub fn write_index(&self, index: &LedgerIndex) -> io::Result<()> {
        self.ensure_dir()?;
        let mut bytes = serde_json::to_vec(index).map_err(io::Error::other)?;
        bytes.push(b'\n');
        crate::util::write_atomic(&self.index_path(), &bytes, 0o640)
    }

    /// Session ids with a record file on disk (used to find orphans and
    /// strays).
    pub fn record_ids(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut ids: Vec<String> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_str()?.to_string();
                let id = name.strip_suffix(".json")?.to_string();
                punar_common::agent::session_id_ok(&id).then_some(id)
            })
            .collect();
        ids.sort();
        ids
    }
}

/// The index row for a record — the counts-only rollup `agents.list` and
/// retention read without opening every file.
pub fn index_row(record: &LedgerRecord) -> LedgerIndexRow {
    let first_seen = record
        .entries
        .iter()
        .map(|e| e.first_seen.as_str())
        .min()
        .unwrap_or(record.started_at.as_str())
        .to_string();
    let last_seen = record
        .entries
        .iter()
        .map(|e| e.last_seen.as_str())
        .max()
        .unwrap_or(record.updated_at.as_str())
        .to_string();
    LedgerIndexRow {
        session_id: record.session_id.clone(),
        agent: (!record.agent.is_empty()).then(|| record.agent.clone()),
        project: record.project.clone(),
        user: record.user.clone(),
        classification: record.classification,
        status: record.status,
        first_seen,
        last_seen,
        updated_at: record.updated_at.clone(),
        retention_expires_at: record.retention_expires_at.clone(),
        purged_at: record.purged_at.clone(),
        counts: record.counts(),
    }
}

/// The tombstone a purge leaves behind: identity, owner, and the moment
/// of deletion. `agent`, `project` and every count are gone, because a
/// tombstone that remembered the project would still be resource data.
pub fn tombstone_row(row: &LedgerIndexRow, purged_at: &str) -> LedgerIndexRow {
    LedgerIndexRow {
        session_id: row.session_id.clone(),
        agent: None,
        project: None,
        user: row.user.clone(),
        classification: row.classification,
        status: AgentStatus::Ended,
        first_seen: purged_at.to_string(),
        last_seen: purged_at.to_string(),
        updated_at: purged_at.to_string(),
        // A tombstone is itself minimized away, on the same clock.
        retention_expires_at: plus_days(purged_at, LEDGER_RETENTION_DAYS),
        purged_at: Some(purged_at.to_string()),
        counts: LedgerCounts::default(),
    }
}

/// One prune batch (milestone-8.md section 6.3), run at startup, at every
/// `agents.scan` pass, and at `agents.end` — event-driven, never on a
/// timer.
///
/// `active` names sessions that are still running: they are **never**
/// pruned however long they run, because the retention clock starts at
/// `ended_at`.
pub fn prune(
    store: &LedgerStore,
    index: &mut LedgerIndex,
    now: &str,
    active: &[String],
) -> PruneOutcome {
    let mut outcome = PruneOutcome::default();

    // 1. Expired: past retention_expires_at (tombstones included).
    let mut kept: Vec<LedgerIndexRow> = Vec::with_capacity(index.sessions.len());
    for row in std::mem::take(&mut index.sessions) {
        let expired = row
            .retention_expires_at
            .as_deref()
            .is_some_and(|at| at <= now)
            && !active.contains(&row.session_id);
        if expired {
            let _ = store.remove_record(&row.session_id);
            outcome.expired.push(row.session_id);
        } else {
            kept.push(row);
        }
    }
    index.sessions = kept;

    // 2. Orphans: an index row whose file vanished underneath us. A
    //    tombstone has no file by construction and is not an orphan.
    let on_disk = store.record_ids();
    let mut kept: Vec<LedgerIndexRow> = Vec::with_capacity(index.sessions.len());
    for row in std::mem::take(&mut index.sessions) {
        if row.is_tombstone() || on_disk.contains(&row.session_id) {
            kept.push(row);
        } else {
            outcome.orphan.push(row.session_id);
        }
    }
    index.sessions = kept;

    // 3. Index cap: oldest **ended** first, actives never evicted.
    if index.sessions.len() > MAX_INDEXED_SESSIONS {
        let mut evictable: Vec<(String, String)> = index
            .sessions
            .iter()
            .filter(|row| row.status == AgentStatus::Ended && !active.contains(&row.session_id))
            .map(|row| (row.updated_at.clone(), row.session_id.clone()))
            .collect();
        evictable.sort();
        let excess = index.sessions.len() - MAX_INDEXED_SESSIONS;
        for (_, session_id) in evictable.into_iter().take(excess) {
            let _ = store.remove_record(&session_id);
            index.sessions.retain(|row| row.session_id != session_id);
            outcome.index_cap.push(session_id);
        }
    }

    if !outcome.is_empty() {
        index.updated_at = now.to_string();
    }
    outcome
}

// ---------------------------------------------------------------------------
// Retention arithmetic
// ---------------------------------------------------------------------------

/// Parse the RFC 3339 UTC timestamps Punar itself writes
/// ([`punar_common::time::utc_now_rfc3339`]) back to Unix seconds.
///
/// Deliberately narrow, and honest about it: this is the inverse of the
/// one formatter Punar has, not a general RFC 3339 parser. It accepts
/// `YYYY-MM-DDTHH:MM:SS` with an optional fraction and a `Z`; any offset
/// form returns `None` rather than silently mis-dating a retention
/// deadline. A time crate for this would be a dependency for one
/// function (PERFORMANCE_BUDGETS.md section 6.2, the `time.rs` argument).
pub fn rfc3339_to_unix(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || !(bytes[10] == b'T' || bytes[10] == b't') {
        return None;
    }
    if !matches!(bytes[bytes.len() - 1], b'Z' | b'z') {
        return None;
    }
    let num = |range: std::ops::Range<usize>| value.get(range)?.parse::<i64>().ok();
    let year = num(0..4)?;
    let month = num(5..7)?;
    let day = num(8..10)?;
    let hour = num(11..13)?;
    let minute = num(14..16)?;
    let second = num(17..19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = days_from_civil(year, month as u32, day as u32);
    let secs = days * i64::from(SECS_PER_DAY as u32) + hour * 3_600 + minute * 60 + second;
    u64::try_from(secs).ok()
}

/// `days_from_civil` — Howard Hinnant's algorithm (public domain), the
/// exact inverse of the `civil_from_days` in `punar_common::time`.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let m = u64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + u64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// `timestamp + days`, or `None` when the timestamp is not one Punar
/// wrote. A `None` here means no retention deadline is stamped — the
/// record is kept rather than deleted on a date nobody can justify.
pub fn plus_days(timestamp: &str, days: u64) -> Option<String> {
    let base = rfc3339_to_unix(timestamp)?;
    Some(rfc3339_utc_from_unix_seconds(base + days * SECS_PER_DAY))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::temp_dir;
    use punar_common::agent::AgentClassification;
    use punar_common::ledger::{
        Evidence, LedgerSummary, ResourceCategory, ResourceClass, SecurityEventRef,
        SecurityEventType,
    };

    fn record(session_id: &str, status: AgentStatus) -> LedgerRecord {
        let mut record = LedgerRecord::new(
            session_id,
            "claude-code",
            "punar",
            Some(ResourceClass::new(ResourceCategory::Repositories, "atlas").unwrap()),
            AgentClassification::Managed,
            "2026-08-27T09:58:40Z",
        );
        record.status = status;
        record.observe(
            ResourceCategory::Repositories,
            ResourceClass::new(ResourceCategory::Repositories, "atlas").unwrap(),
            1,
            Evidence::WorkspaceBind,
            "2026-08-27T09:58:40Z",
        );
        record.observe(
            ResourceCategory::ProcessClasses,
            ResourceClass::new(ResourceCategory::ProcessClasses, "git").unwrap(),
            2,
            Evidence::CgroupScope,
            "2026-08-27T09:59:00Z",
        );
        record.observe_security_event(SecurityEventRef {
            event_id: "evt_502".into(),
            event_type: SecurityEventType::DeniedAccess,
            timestamp: Some("2026-08-27T09:59:12Z".into()),
        });
        record
    }

    #[test]
    fn records_round_trip_through_the_directory_at_0640_in_a_0700_dir() {
        let dir = temp_dir("ledger-store");
        let store = LedgerStore::new(dir.join("ledger"));
        let written = record("agt_4f21c09ab3e1", AgentStatus::Active);
        store.write_record(&written).unwrap();

        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(store.record_path("agt_4f21c09ab3e1"))
                .unwrap()
                .permissions(),
        );
        assert_eq!(mode & 0o777, 0o640);
        let dir_mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(store.dir()).unwrap().permissions(),
        );
        assert_eq!(dir_mode & 0o777, 0o700, "the ledger directory is root-only");

        assert_eq!(store.load_record("agt_4f21c09ab3e1"), Some(written));
        assert_eq!(store.record_ids(), vec!["agt_4f21c09ab3e1".to_string()]);
        assert!(store.load_record("agt_absent00001").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A hand-edited file cannot smuggle a path into the ledger: the
    /// `ResourceClass` deserializer refuses it, so the record does not
    /// load at all.
    #[test]
    fn a_tampered_record_with_a_path_does_not_load() {
        let dir = temp_dir("ledger-tamper");
        let store = LedgerStore::new(dir.join("ledger"));
        store
            .write_record(&record("agt_tampered001", AgentStatus::Active))
            .unwrap();
        let path = store.record_path("agt_tampered001");
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\"atlas\"", "\"/home/punar/atlas\"");
        std::fs::write(&path, text).unwrap();
        assert!(store.load_record("agt_tampered001").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_index_carries_the_rollup_and_the_tail_position() {
        let dir = temp_dir("ledger-index");
        let store = LedgerStore::new(dir.join("ledger"));
        let mut index = LedgerIndex::default();
        index.tail.offset = 4096;
        index.tail.ino = 77;
        index.upsert(index_row(&record("agt_4f21c09ab3e1", AgentStatus::Active)));
        store.write_index(&index).unwrap();

        let back = store.load_index();
        assert_eq!(back.tail.offset, 4096);
        let row = back.row("agt_4f21c09ab3e1").unwrap();
        assert_eq!(row.counts.resources, 2);
        assert_eq!(row.counts.process_classes, 1);
        assert_eq!(row.counts.security_events, 1);
        assert_eq!(row.first_seen, "2026-08-27T09:58:40Z");
        assert_eq!(row.last_seen, "2026-08-27T09:59:00Z");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tombstone_keeps_identity_and_forgets_everything_else() {
        let row = index_row(&record("agt_4f21c09ab3e1", AgentStatus::Ended));
        let stone = tombstone_row(&row, "2026-08-27T11:00:00Z");
        assert_eq!(stone.session_id, "agt_4f21c09ab3e1");
        assert_eq!(stone.user, "punar");
        assert_eq!(stone.agent, None);
        assert_eq!(stone.project, None, "the project is resource data");
        assert_eq!(stone.counts, LedgerCounts::default());
        assert_eq!(stone.purged_at.as_deref(), Some("2026-08-27T11:00:00Z"));
        assert_eq!(
            stone.retention_expires_at.as_deref(),
            Some("2026-09-10T11:00:00Z")
        );
        let text = serde_json::to_string(&stone).unwrap();
        assert!(!text.contains("atlas"), "{text}");
    }

    #[test]
    fn retention_arithmetic_round_trips_and_refuses_what_it_cannot_read() {
        assert_eq!(rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_to_unix("2026-08-27T09:58:40Z"), Some(1_787_824_720));
        assert_eq!(
            plus_days("2026-08-27T09:58:40Z", LEDGER_RETENTION_DAYS).as_deref(),
            Some("2026-09-10T09:58:40Z")
        );
        // Leap day, and the year boundary.
        assert_eq!(
            plus_days("2028-02-28T00:00:00Z", 1).as_deref(),
            Some("2028-02-29T00:00:00Z")
        );
        assert_eq!(
            plus_days("2026-12-31T23:00:00Z", 1).as_deref(),
            Some("2027-01-01T23:00:00Z")
        );
        // Offsets and junk are refused rather than mis-dated.
        assert_eq!(rfc3339_to_unix("2026-08-27T09:58:40+02:00"), None);
        assert_eq!(rfc3339_to_unix("yesterday"), None);
        assert_eq!(plus_days("yesterday", 14), None);
    }

    #[test]
    fn prune_deletes_expired_records_and_never_touches_an_active_session() {
        let dir = temp_dir("ledger-prune");
        let store = LedgerStore::new(dir.join("ledger"));
        let mut index = LedgerIndex::default();

        // Backdated: ended 30 days ago, so retention lapsed 16 days ago.
        let mut old = record("agt_expired00001", AgentStatus::Ended);
        old.ended_at = Some("2026-07-28T09:58:40Z".into());
        old.retention_expires_at = plus_days("2026-07-28T09:58:40Z", LEDGER_RETENTION_DAYS);
        store.write_record(&old).unwrap();
        index.upsert(index_row(&old));

        // A long-running active session with no deadline at all.
        let live = record("agt_live00000001", AgentStatus::Active);
        store.write_record(&live).unwrap();
        index.upsert(index_row(&live));

        // An index row whose file never existed.
        let mut ghost = index_row(&record("agt_orphan000001", AgentStatus::Ended));
        ghost.retention_expires_at = None;
        index.upsert(ghost);

        let outcome = prune(
            &store,
            &mut index,
            "2026-08-27T10:00:00Z",
            &["agt_live00000001".to_string()],
        );
        assert_eq!(outcome.expired, vec!["agt_expired00001".to_string()]);
        assert_eq!(outcome.orphan, vec!["agt_orphan000001".to_string()]);
        assert!(outcome.index_cap.is_empty());
        assert!(!store.record_path("agt_expired00001").exists());
        assert!(store.record_path("agt_live00000001").exists());
        assert!(index.row("agt_expired00001").is_none());
        assert!(index.row("agt_orphan000001").is_none());
        assert!(index.row("agt_live00000001").is_some());
        assert_eq!(
            outcome.batches(),
            vec![("expired", 1), ("orphan", 1)],
            "one audit event per batch, not per file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_index_cap_evicts_the_oldest_ended_session_first() {
        let dir = temp_dir("ledger-cap");
        let store = LedgerStore::new(dir.join("ledger"));
        let mut index = LedgerIndex::default();
        for n in 0..MAX_INDEXED_SESSIONS + 3 {
            let id = format!("agt_{n:012}");
            let mut r = record(&id, AgentStatus::Ended);
            r.updated_at = format!("2026-08-{:02}T10:00:00Z", 1 + (n % 27));
            store.write_record(&r).unwrap();
            index.upsert(index_row(&r));
        }
        let outcome = prune(&store, &mut index, "2026-08-27T10:00:00Z", &[]);
        assert_eq!(outcome.index_cap.len(), 3);
        assert_eq!(index.sessions.len(), MAX_INDEXED_SESSIONS);
        for evicted in &outcome.index_cap {
            assert!(!store.record_path(evicted).exists());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The summary the daemon serves is produced only by the projection,
    /// so a record round-tripped through disk still yields a
    /// schema-conformant document.
    #[test]
    fn a_reloaded_record_still_projects_a_schema_exact_summary() {
        let dir = temp_dir("ledger-project");
        let store = LedgerStore::new(dir.join("ledger"));
        store
            .write_record(&record("agt_4f21c09ab3e1", AgentStatus::Ended))
            .unwrap();
        let back = store.load_record("agt_4f21c09ab3e1").unwrap();
        let summary: LedgerSummary = back.summary("2026-08-27T10:00:02Z");
        let value = serde_json::to_value(&summary).unwrap();
        for category in ResourceCategory::ALL {
            assert!(value["resources"][category.as_str()].is_array());
        }
        assert_eq!(value["security_events"][0]["event_id"], "evt_502");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
