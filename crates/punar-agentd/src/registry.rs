//! The AI Agent Registry (spec sections 18–19): the in-memory now-view and
//! its append-only JSONL persistence.
//!
//! # Two halves, on purpose (milestone-7.md section 4)
//!
//! - **Sessions** are lifecycles Punar owns: they are registered by the
//!   managed launch path, they end, and every transition appends one
//!   **schema-exact** `schemas/ai-agent/registry-record.json` line to
//!   `/var/lib/punar/agents/registry.jsonl` (`active` at register, `ended`
//!   at end). At startup the file is replayed so a restarted daemon does
//!   not forget this boot's sessions, and a session whose process is gone
//!   is closed with a synthesized `ended` line — crash honesty, not a
//!   pretend-still-running row.
//! - **Detections** are point-in-time heuristics (spec section 23). M7
//!   kept them in memory and in `/run/punar/agents.json` only, because
//!   writing every scan pass into the registry file would churn
//!   sentinel-heavy records and imply a certainty the detector does not
//!   have.
//!
//!   **Milestone 10 changed that, and the reason the objection no longer
//!   applies is that M10 does not write passes — it writes *transitions*.**
//!   A detection's identity is stable for the life of its process
//!   ([`crate::identity`]), so the set-diff emits one record when a
//!   detection appears and one when it clears, and a pass that changes
//!   nothing writes nothing at all. Those records go to
//!   `/var/lib/punar/agents/detections.jsonl` ([`crate::detections`]),
//!   schema-exact, `classification: "unknown"`, and each opens a bounded
//!   ledger — closing the question M8 wrote down and left open
//!   (milestone-10.md section 6).
//!
//! Runtime extras that are *not* in the ten-field record (the verified
//! scope unit, the executable path, the launcher's authority display
//! summary, the owner uid) hang off [`Session`] in memory, because the
//! record schema is exact and stays that way.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use punar_common::agent::{
    AgentClassification, AgentStatus, AuthoritySummary, RegistryRecord, SessionRow,
    validate_registry_record,
};

/// A registered agent session, plus the runtime facts the record schema
/// deliberately does not carry.
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub record: RegistryRecord,
    /// `punar-agent-<id>.scope`, present when the cgroup proved managed
    /// attribution at registration (spec section 22).
    pub scope_unit: Option<String>,
    /// The scope's absolute cgroup path (`/user.slice/…/<unit>`), read
    /// from `/proc/<pid>/cgroup` at registration. The M8 Access Ledger
    /// samples `cgroup.procs` and `pids.peak` from it — the same
    /// kernel-attested chain that proved the classification, read once
    /// more (milestone-8.md section 3.2).
    pub scope_path: Option<String>,
    /// Executable path observed at registration, when one was readable.
    pub executable: Option<String>,
    /// What the launcher displayed (spec section 27 step 10) — display
    /// data, labeled `declared · M9/M12` by whoever renders it.
    pub authority: Option<AuthoritySummary>,
    /// Peer uid that registered the session; `None` for sessions replayed
    /// from disk whose recorded user name no longer resolves. `agents.end`
    /// authorization falls back to root-only in that case.
    pub owner_uid: Option<u32>,
}

impl Session {
    /// The wire row: the ten record fields plus the managed extras.
    pub fn row(&self) -> SessionRow {
        SessionRow {
            scope_unit: self.scope_unit.clone(),
            authority: self.authority.clone(),
            ..SessionRow::from_record(self.record.clone())
        }
    }
}

/// One current detection — `observed` (known agent outside the managed
/// runtime) or `unknown` (suspected agentic activity). Every surface that
/// renders one says *suspected*, never certain (spec section 23).
///
/// # The two `signature` fields, and why they are not one
///
/// M7 shipped a wire field named `signature_id` on detection rows whose
/// value is the **matched rule's name** (`downloads-foo-agent`) — see
/// `docs/api/ipc.md` section 10.2, the AI panel, and `punarctl`. M10
/// introduces a *different* thing that section 4.2 also calls
/// `signature_id`: `sig_` + 12 hex over `(exe, uid)`, the anti-nag key.
///
/// Both keep their names, in their own contracts:
///
/// - [`Detection::signature_name`] is the M7 value and is what the wire
///   row's `signature_id` carries. The shipped contract does not move
///   for a later milestone (the M8 Decision-0 law, third application).
/// - [`Detection::signature_id`] is the M10 identity and appears under
///   that name in `alerts.json` — a **new** file, whose field list
///   milestone-10.md section 5.3 fixes — beside a `signature` field
///   carrying the rule name.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub record: RegistryRecord,
    /// The single matched path — never a full command line
    /// (`crate::proc` module note; spec section 53).
    pub executable: String,
    /// Which rule matched: an adapter name for `observed`, a
    /// suspected-pattern or provenance-rule id for `unknown`. This is the
    /// value the wire row's `signature_id` field has carried since M7.
    pub signature_name: String,
    /// The M10 signature **identity** (`sig_` + 12 hex over exe + uid) —
    /// the alert key. One thing seen, however many times it restarts.
    pub signature_id: String,
    /// The zone **class** of where the executable lives (`downloads`,
    /// `tmp`, `home`, `system`). A class, never a path — it is what the
    /// unknown-agent ledger records instead of the location.
    pub zone: &'static str,
    /// When **this daemon** first saw the process, as distinct from
    /// `record.started_at`, which since M10 is the process's own start.
    pub observed_at: String,
    /// Owner uid, for `alerts.dismiss` authorization. `None` when
    /// `/proc/<pid>/status` did not answer — root-only, fail closed.
    pub owner_uid: Option<u32>,
}

impl Detection {
    /// The wire row, carrying the honesty label in the data.
    pub fn row(&self) -> SessionRow {
        SessionRow {
            suspected: Some(true),
            executable: Some(self.executable.clone()),
            // The M7 contract: this field is the matched rule's *name*.
            // The M10 `sig_` identity lives in `alerts.json`, not here.
            signature_id: Some(self.signature_name.clone()),
            ..SessionRow::from_record(self.record.clone())
        }
    }
}

/// The in-memory registry: sessions this boot (active **and** ended) and
/// the current detection set. `BTreeMap` rather than `HashMap` so every
/// listing, summary file, and test observation is deterministically
/// ordered — cheap at registry sizes, and it makes diffs readable.
#[derive(Debug, Default)]
pub struct Registry {
    sessions: BTreeMap<String, Session>,
    detections: BTreeMap<String, Detection>,
}

impl Registry {
    pub fn insert_session(&mut self, session: Session) {
        self.sessions
            .insert(session.record.session_id.clone(), session);
    }

    pub fn session(&self, session_id: &str) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    pub fn detection(&self, session_id: &str) -> Option<&Detection> {
        self.detections.get(session_id)
    }

    pub fn contains(&self, session_id: &str) -> bool {
        self.sessions.contains_key(session_id) || self.detections.contains_key(session_id)
    }

    pub fn sessions(&self) -> impl Iterator<Item = &Session> {
        self.sessions.values()
    }

    pub fn detections(&self) -> impl Iterator<Item = &Detection> {
        self.detections.values()
    }

    /// Session ids whose status is still `active` — the reap candidates.
    pub fn active_sessions(&self) -> Vec<(String, u32)> {
        self.sessions
            .values()
            .filter(|session| session.record.status == AgentStatus::Active)
            .map(|session| (session.record.session_id.clone(), session.record.process_id))
            .collect()
    }

    /// Pids of active sessions — the detector skips them (a managed
    /// session is already accounted for; re-reporting it as `observed`
    /// would double-count the same process).
    pub fn active_pids(&self) -> std::collections::HashSet<u32> {
        self.sessions
            .values()
            .filter(|session| session.record.status == AgentStatus::Active)
            .map(|session| session.record.process_id)
            .collect()
    }

    /// Flip a session to `ended` in memory, returning the record to
    /// persist (`None` when the id is unknown or already ended).
    ///
    /// `started_at` is left as it was: the record schema has one timestamp
    /// and it means *session start*. The end time is the audit event's, and
    /// the ordering of the two lines in the transition log.
    pub fn mark_ended(&mut self, session_id: &str) -> Option<RegistryRecord> {
        let session = self.sessions.get_mut(session_id)?;
        if session.record.status == AgentStatus::Ended {
            return None;
        }
        session.record.status = AgentStatus::Ended;
        Some(session.record.clone())
    }

    /// Replace the detection set, returning `(appeared, disappeared)` —
    /// exactly the transitions worth auditing (milestone-7.md section 10;
    /// the `enroll.sync` precedent of auditing changes, not passes).
    ///
    /// A detection that persists across passes keeps its original
    /// `observed_at`, so a still-running suspect does not appear to be
    /// freshly noticed every time someone opens the panel. `started_at`
    /// needs no such care since M10: it is the process's own start,
    /// derived from the kernel's tick stamp, and is the same on every
    /// pass by construction.
    pub fn replace_detections(
        &mut self,
        found: Vec<Detection>,
    ) -> (Vec<Detection>, Vec<Detection>) {
        let mut next: BTreeMap<String, Detection> = BTreeMap::new();
        let mut appeared = Vec::new();
        for mut detection in found {
            let id = detection.record.session_id.clone();
            match self.detections.get(&id) {
                Some(previous) => {
                    detection.observed_at = previous.observed_at.clone();
                    detection.record.started_at = previous.record.started_at.clone();
                }
                None => appeared.push(detection.clone()),
            }
            next.insert(id, detection);
        }
        let disappeared: Vec<Detection> = self
            .detections
            .values()
            .filter(|previous| !next.contains_key(&previous.record.session_id))
            .cloned()
            .collect();
        self.detections = next;
        (appeared, disappeared)
    }

    /// Per-classification counts for the panel masthead.
    pub fn counts(&self) -> punar_common::agent::AgentsSummaryCounts {
        let mut counts = punar_common::agent::AgentsSummaryCounts::default();
        for session in self.sessions.values() {
            if session.record.status != AgentStatus::Active {
                continue;
            }
            match session.record.classification {
                AgentClassification::Managed => counts.managed += 1,
                AgentClassification::Observed => counts.observed += 1,
                AgentClassification::Unknown => counts.unknown += 1,
            }
        }
        for detection in self.detections.values() {
            match detection.record.classification {
                AgentClassification::Managed => counts.managed += 1,
                AgentClassification::Observed => counts.observed += 1,
                AgentClassification::Unknown => counts.unknown += 1,
            }
        }
        counts
    }
}

/// Errors from the persistence layer.
#[derive(Debug)]
pub enum StoreError {
    /// The record violates `schemas/ai-agent/registry-record.json`;
    /// nothing was written. A non-conformant line can never reach the file.
    Schema(Vec<String>),
    Io(io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Schema(violations) => {
                write!(f, "registry record violates the schema: {violations:?}")
            }
            StoreError::Io(e) => write!(f, "registry persistence I/O failed: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

/// Append-only `registry.jsonl` (`0640 root:root`), one schema-exact
/// record per lifecycle transition.
#[derive(Debug, Clone)]
pub struct RegistryStore {
    path: PathBuf,
}

impl RegistryStore {
    pub fn new(path: impl Into<PathBuf>) -> RegistryStore {
        RegistryStore { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Validate, then append one line. Validation first, always: the file
    /// is a machine-readable contract that `jq` checks in CI, and a daemon
    /// bug must fail loudly here rather than write a record no consumer
    /// can trust.
    pub fn append(&self, record: &RegistryRecord) -> Result<(), StoreError> {
        validate_registry_record(record).map_err(StoreError::Schema)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_string(record).map_err(io::Error::other)?;
        debug_assert!(!line.contains('\n'));
        line.push('\n');
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o640);
        }
        let mut file = options.open(&self.path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o640))?;
        }
        file.write_all(line.as_bytes())?;
        file.sync_data()?;
        Ok(())
    }

    /// Read every record in file order. Unparsable lines are counted, not
    /// fatal (a torn write from a crash must not stop the daemon booting).
    pub fn replay(&self) -> io::Result<(Vec<RegistryRecord>, usize)> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
            Err(e) => return Err(e),
        };
        let mut records = Vec::new();
        let mut skipped = 0usize;
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            match serde_json::from_str::<RegistryRecord>(line) {
                Ok(record) => records.push(record),
                Err(_) => skipped += 1,
            }
        }
        Ok((records, skipped))
    }
}

/// What a startup replay found — reported honestly on stderr rather than
/// silently absorbed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReplayReport {
    /// Sessions still `active` in the file whose process is still alive.
    pub carried: Vec<String>,
    /// Sessions still `active` in the file whose process is gone; each got
    /// a synthesized `ended` record appended (crash recovery).
    pub reaped: Vec<String>,
    /// Lines that were not valid records.
    pub skipped_lines: usize,
}

/// Rebuild the in-memory registry from `registry.jsonl`.
///
/// The last line per `session_id` wins (the file is a transition log, so
/// that is the session's final known state). Sessions left `active` are
/// checked against `/proc`: alive ones are carried into the new process's
/// view, dead ones are closed with a synthesized `ended` append — the
/// daemon never claims a session is running because a file says so.
pub fn replay_into(
    store: &RegistryStore,
    proc: &crate::proc::ProcRoot,
    passwd_file: &Path,
) -> io::Result<(Registry, ReplayReport)> {
    let (records, skipped_lines) = store.replay()?;
    let mut registry = Registry::default();
    let mut report = ReplayReport {
        skipped_lines,
        ..ReplayReport::default()
    };
    let mut latest: BTreeMap<String, RegistryRecord> = BTreeMap::new();
    for record in records {
        latest.insert(record.session_id.clone(), record);
    }
    for (session_id, record) in latest {
        let alive = proc.is_alive(record.process_id);
        let owner_uid = crate::util::lookup_uid(passwd_file, &record.user);
        let scope_unit = matches!(record.classification, AgentClassification::Managed)
            .then(|| crate::proc::scope_unit_name(&session_id));
        let scope_path = scope_unit.as_ref().and_then(|_| {
            proc.entry(record.process_id)
                .and_then(|entry| entry.scope_path_of(&session_id))
        });
        let mut session = Session {
            record,
            scope_unit,
            scope_path,
            executable: None,
            // The launcher's authority summary is display data that was
            // never persisted (the record schema is exact), so a replayed
            // session honestly has none until it re-registers.
            authority: None,
            owner_uid,
        };
        if session.record.status == AgentStatus::Active && !alive {
            session.record.status = AgentStatus::Ended;
            let ended = session.record.clone();
            if let Err(e) = store.append(&ended) {
                eprintln!(
                    "punar-agentd: could not append the synthesized ended record for \
                     {session_id}: {e}"
                );
            }
            report.reaped.push(session_id.clone());
        } else if session.record.status == AgentStatus::Active {
            report.carried.push(session_id.clone());
        }
        registry.insert_session(session);
    }
    Ok((registry, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{fake_process, fixture_nss, fixture_proc, managed_cgroup, temp_dir};

    fn record(session_id: &str, pid: u32, status: AgentStatus) -> RegistryRecord {
        RegistryRecord {
            session_id: session_id.to_string(),
            agent: "claude-code".to_string(),
            version: "mock".to_string(),
            process_id: pid,
            user: "punar".to_string(),
            project: "atlas".to_string(),
            environment: "host".to_string(),
            status,
            classification: AgentClassification::Managed,
            started_at: "2026-08-27T09:58:40Z".to_string(),
        }
    }

    #[test]
    fn every_persisted_line_is_a_schema_exact_ten_field_record() {
        let dir = temp_dir("store");
        let store = RegistryStore::new(dir.join("agents/registry.jsonl"));
        store
            .append(&record("agt_4f21c09ab3e1", 2143, AgentStatus::Active))
            .unwrap();
        store
            .append(&record("agt_4f21c09ab3e1", 2143, AgentStatus::Ended))
            .unwrap();

        let text = std::fs::read_to_string(store.path()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one line per lifecycle transition");
        for line in lines {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            let mut keys: Vec<&str> = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                vec![
                    "agent",
                    "classification",
                    "environment",
                    "process_id",
                    "project",
                    "session_id",
                    "started_at",
                    "status",
                    "user",
                    "version",
                ],
                "exactly the ten registry-record.json fields, nothing more"
            );
            // And it round-trips through the strict record type.
            let _: RegistryRecord = serde_json::from_str(line).unwrap();
        }
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(store.path()).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o640, "registry.jsonl is 0640");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_non_conformant_record_never_reaches_the_file() {
        let dir = temp_dir("store-invalid");
        let store = RegistryStore::new(dir.join("registry.jsonl"));
        let mut bad = record("sess-1", 0, AgentStatus::Active);
        bad.version = String::new();
        match store.append(&bad) {
            Err(StoreError::Schema(violations)) => assert!(violations.len() >= 3, "{violations:?}"),
            other => panic!("expected a schema refusal, got {other:?}"),
        }
        assert!(!store.path().exists(), "nothing was written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replay_carries_live_sessions_and_reaps_dead_ones() {
        let dir = temp_dir("replay");
        let (_, passwd) = fixture_nss(&dir);
        let root = fixture_proc("replay");
        fake_process(
            &root,
            2143,
            "claude",
            "/usr/bin/claude",
            &["/usr/bin/claude"],
            1000,
            &managed_cgroup("agt_4f21c09ab3e1"),
        );
        let proc = crate::proc::ProcRoot::new(&root);

        let store = RegistryStore::new(dir.join("registry.jsonl"));
        store
            .append(&record("agt_4f21c09ab3e1", 2143, AgentStatus::Active))
            .unwrap();
        // A session from a previous boot whose process is long gone.
        store
            .append(&record("agt_deadbeef0001", 9999, AgentStatus::Active))
            .unwrap();
        // A cleanly ended session stays ended (and stays listable).
        store
            .append(&record("agt_c10sed000001", 4242, AgentStatus::Active))
            .unwrap();
        store
            .append(&record("agt_c10sed000001", 4242, AgentStatus::Ended))
            .unwrap();
        // A torn line must not stop the boot.
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(store.path())
                .unwrap();
            file.write_all(b"{\"session_id\":\"agt_torn\"\n").unwrap();
        }

        let (registry, report) = replay_into(&store, &proc, &passwd).unwrap();
        assert_eq!(report.carried, vec!["agt_4f21c09ab3e1".to_string()]);
        assert_eq!(report.reaped, vec!["agt_deadbeef0001".to_string()]);
        assert_eq!(report.skipped_lines, 1);
        assert_eq!(
            registry.session("agt_4f21c09ab3e1").unwrap().record.status,
            AgentStatus::Active
        );
        assert_eq!(
            registry.session("agt_deadbeef0001").unwrap().record.status,
            AgentStatus::Ended,
            "a session whose process is gone is never reported as running"
        );
        assert_eq!(
            registry.session("agt_4f21c09ab3e1").unwrap().owner_uid,
            Some(1000)
        );
        // The synthesized ended record was appended, not just held in RAM.
        let (records, _) = store.replay().unwrap();
        assert_eq!(
            records
                .iter()
                .filter(|r| r.session_id == "agt_deadbeef0001" && r.status == AgentStatus::Ended)
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detection_diffs_report_only_transitions_and_keep_first_seen_times() {
        let mut registry = Registry::default();
        let detection = |id: &str, at: &str| Detection {
            record: RegistryRecord {
                session_id: id.to_string(),
                agent: "foo-agent".to_string(),
                version: "unknown".to_string(),
                process_id: 2410,
                user: "punar".to_string(),
                project: "unknown".to_string(),
                environment: "host".to_string(),
                status: AgentStatus::Active,
                classification: AgentClassification::Unknown,
                started_at: at.to_string(),
            },
            executable: "/home/punar/Downloads/foo-agent".to_string(),
            signature_name: "downloads-foo-agent".to_string(),
            signature_id: "sig_a1b2c3d4e5f6".to_string(),
            zone: "downloads",
            observed_at: at.to_string(),
            owner_uid: Some(1000),
        };

        let (appeared, gone) = registry
            .replace_detections(vec![detection("agt_d11e0aa7c402", "2026-08-27T09:59:55Z")]);
        assert_eq!(appeared.len(), 1);
        assert!(gone.is_empty());

        // Same process, later pass: no transition, original time kept.
        let (appeared, gone) = registry
            .replace_detections(vec![detection("agt_d11e0aa7c402", "2026-08-27T10:05:00Z")]);
        assert!(appeared.is_empty(), "a persisting detection is not news");
        assert!(gone.is_empty());
        assert_eq!(
            registry
                .detection("agt_d11e0aa7c402")
                .unwrap()
                .record
                .started_at,
            "2026-08-27T09:59:55Z"
        );

        let (appeared, gone) = registry.replace_detections(Vec::new());
        assert!(appeared.is_empty());
        assert_eq!(gone.len(), 1, "the process going away is a transition");
        assert_eq!(registry.detections().count(), 0);
    }

    #[test]
    fn counts_cover_active_sessions_and_current_detections() {
        let mut registry = Registry::default();
        registry.insert_session(Session {
            record: record("agt_4f21c09ab3e1", 2143, AgentStatus::Active),
            scope_unit: Some("punar-agent-agt_4f21c09ab3e1.scope".into()),
            scope_path: None,
            executable: None,
            authority: None,
            owner_uid: Some(1000),
        });
        registry.insert_session(Session {
            record: record("agt_old000000001", 1111, AgentStatus::Ended),
            scope_unit: None,
            scope_path: None,
            executable: None,
            authority: None,
            owner_uid: Some(1000),
        });
        let counts = registry.counts();
        assert_eq!(
            counts.managed, 1,
            "ended sessions are listed, not counted as running"
        );
        assert_eq!(counts.unknown, 0);
    }
}
