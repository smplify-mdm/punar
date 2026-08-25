//! Persisted detection records — M8's open question, closed
//! (milestone-10.md section 6).
//!
//! M8 shipped this row and this promise:
//!
//! > unknown-agent detection transition … `unknown_ai_execution` …
//! > **partially** — the audit event exists today, but detections have no
//! > persisted session (M7 §4.4), so it attaches to **no** ledger in M8;
//! > **M10** owns the unknown-agent ledger.
//!
//! **Decision: detections do get a persisted record and a ledger.**
//!
//! # Why the privacy instinct points the same way
//!
//! The instinct that an unregistered process should not get a file is a
//! good one, and following it through reverses it. Punar already writes a
//! Level-4 `unknown_ai_execution` audit event about the detection;
//! recording a security event about a session while refusing to admit the
//! session exists is incoherent. And spec 21.2's never-record list is not
//! a rule about *which* agents get a ledger — it is a rule about *what a
//! ledger may contain*. Applied identically to unknowns, with strictly
//! fewer available sources, it produces a ledger strictly **smaller**
//! than a managed one. The privacy-preserving choice is not "no record"
//! but "a record that structurally cannot hold the sensitive things".
//!
//! `fixtures/agents/unknown-agent/` has described exactly this since M7 —
//! `agt_999`, `foo-agent`, `classification: "unknown"`, one
//! `unknown_ai_execution` event reference. M10 makes the fixture true.
//!
//! # Two files, because one schema is exact
//!
//! ```text
//! /var/lib/punar/agents/detections.jsonl        0600 root:root
//! /var/lib/punar/agents/detections-index.json   0600 root:root
//! ```
//!
//! The JSONL holds **schema-exact** `registry-record.json` documents, one
//! per detection *state change* (`active` when it appears, `ended` when it
//! clears) — never one per pass. Everything the shipped schema cannot
//! hold (`signature_id`, the matched signature name, the executable path,
//! the zone class, `cleared_at`) lives in the sibling index. That is the
//! third application of the M8 Decision-0 law: a shipped schema never
//! grows a property to suit a later milestone.
//!
//! # Retention
//!
//! Seven days after the detection clears — half M8's managed window
//! ([`punar_common::ledger::DETECTION_RETENTION_DAYS`]). Compaction
//! rewrites both files at once and only when something actually expired,
//! so the steady state writes nothing.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use punar_common::agent::{RegistryRecord, validate_registry_record};
use punar_common::ledger::DETECTION_RETENTION_DAYS;
use serde::{Deserialize, Serialize};

use crate::ledger::store::{plus_days, rfc3339_to_unix};

/// Mode of both files: `0600 root:root`. Stricter than `registry.jsonl`
/// (`0640 root:punar`) on purpose — a managed session's own user has a
/// claim on its transition log; a device-wide record of *suspected*
/// processes is a root-only artefact until a surface deliberately
/// projects a scoped view of it.
const DETECTIONS_MODE: u32 = 0o600;

/// Everything about a detection that `registry-record.json` cannot hold.
///
/// Note what is **not** here and never will be: no pid (it is in the
/// schema-exact record, where `/proc` already published it to the same
/// user, and it is not exported), no cmdline, no argv, no environment, no
/// `cwd`, no child-process list. Walking `/proc` for descendants of a
/// suspicious pid would produce a per-user process graph — precisely the
/// broad tracing spec 1.14 rules out, and a far more invasive artefact
/// than anything M8 collects about a *managed* agent. Refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionIndexRow {
    pub detection_id: String,
    /// `sig_` + 12 hex — the alert and fleet-dedup key.
    pub signature_id: String,
    /// The matched rule's name, the reviewable line in the data file.
    pub signature: String,
    /// The single matched path. Present here because the alert card and
    /// `punarctl agents list` both render it, and because it is a datum
    /// the owning user can already read from `/proc`. It never reaches
    /// the **ledger**, which holds the zone class instead.
    pub executable: String,
    /// `downloads` · `tmp` · `home` · `system` · `unknown`.
    pub zone: String,
    pub user: String,
    /// When this daemon first saw the process.
    pub observed_at: String,
    /// When the detection cleared; `None` while it is live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared_at: Option<String>,
    /// `cleared_at` + 7 days. `None` while live — an active detection is
    /// never pruned, exactly as an active session's ledger is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_expires_at: Option<String>,
}

/// The sibling index document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionIndex {
    pub v: u32,
    pub updated_at: String,
    pub rows: BTreeMap<String, DetectionIndexRow>,
}

impl Default for DetectionIndex {
    fn default() -> Self {
        DetectionIndex {
            v: 1,
            updated_at: String::new(),
            rows: BTreeMap::new(),
        }
    }
}

/// The detections store: the append-only transition log and its index.
#[derive(Debug, Clone)]
pub struct DetectionStore {
    jsonl: PathBuf,
    index: PathBuf,
}

impl DetectionStore {
    pub fn new(jsonl: impl Into<PathBuf>, index: impl Into<PathBuf>) -> DetectionStore {
        DetectionStore {
            jsonl: jsonl.into(),
            index: index.into(),
        }
    }

    pub fn jsonl_path(&self) -> &Path {
        &self.jsonl
    }

    pub fn index_path(&self) -> &Path {
        &self.index
    }

    /// Validate, then append one line — the `RegistryStore::append` rule,
    /// for the same reason: the file is a machine-readable contract that
    /// `jq` checks in CI, so a daemon bug must fail loudly here rather
    /// than write a record no consumer can trust.
    pub fn append(&self, record: &RegistryRecord) -> io::Result<()> {
        if let Err(violations) = validate_registry_record(record) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("detection record violates the shipped schema: {violations:?}"),
            ));
        }
        if let Some(parent) = self.jsonl.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_string(record).map_err(io::Error::other)?;
        debug_assert!(!line.contains('\n'));
        line.push('\n');
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(DETECTIONS_MODE);
        }
        let mut file = options.open(&self.jsonl)?;
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(DETECTIONS_MODE))?;
        }
        file.write_all(line.as_bytes())?;
        file.sync_data()?;
        Ok(())
    }

    /// Every record in file order. Unparsable lines are counted, not
    /// fatal: a torn write from a crash must not stop the daemon booting.
    pub fn replay(&self) -> io::Result<(Vec<RegistryRecord>, usize)> {
        let text = match std::fs::read_to_string(&self.jsonl) {
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

    /// Load the index, or a fresh empty one. An unreadable index costs
    /// the sibling data (the schema-exact records are still there), never
    /// the daemon.
    pub fn load_index(&self) -> DetectionIndex {
        let Ok(text) = std::fs::read_to_string(&self.index) else {
            return DetectionIndex::default();
        };
        match serde_json::from_str::<DetectionIndex>(&text) {
            Ok(index) => index,
            Err(e) => {
                eprintln!(
                    "punar-agentd: detection index {} could not be parsed ({e}); starting a \
                     fresh one — the schema-exact records in {} are untouched",
                    self.index.display(),
                    self.jsonl.display()
                );
                DetectionIndex::default()
            }
        }
    }

    pub fn write_index(&self, index: &DetectionIndex) -> io::Result<()> {
        if let Some(parent) = self.index.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut bytes = serde_json::to_vec(index).map_err(io::Error::other)?;
        bytes.push(b'\n');
        crate::util::write_atomic_synced(&self.index, &bytes, DETECTIONS_MODE)
    }

    /// Rewrite `detections.jsonl` keeping only the records whose
    /// `session_id` is in `keep`. Used by compaction and by purge.
    pub fn rewrite_keeping(&self, keep: &std::collections::BTreeSet<String>) -> io::Result<usize> {
        let (records, _) = self.replay()?;
        let kept: Vec<&RegistryRecord> = records
            .iter()
            .filter(|record| keep.contains(&record.session_id))
            .collect();
        let removed = records.len() - kept.len();
        if removed == 0 {
            return Ok(0);
        }
        let mut bytes = Vec::new();
        for record in kept {
            let mut line = serde_json::to_string(record).map_err(io::Error::other)?;
            line.push('\n');
            bytes.extend_from_slice(line.as_bytes());
        }
        crate::util::write_atomic_synced(&self.jsonl, &bytes, DETECTIONS_MODE)?;
        Ok(removed)
    }
}

/// Stamp the retention deadline on a cleared row.
pub fn clear_row(row: &mut DetectionIndexRow, cleared_at: &str) {
    row.cleared_at = Some(cleared_at.to_string());
    row.retention_expires_at = plus_days(cleared_at, DETECTION_RETENTION_DAYS);
}

/// Detection ids whose retention deadline has passed. Live detections
/// (no `cleared_at`) are never returned.
pub fn expired(index: &DetectionIndex, now: &str) -> Vec<String> {
    let Some(now_unix) = rfc3339_to_unix(now) else {
        return Vec::new();
    };
    index
        .rows
        .values()
        .filter(|row| {
            row.retention_expires_at
                .as_deref()
                .and_then(rfc3339_to_unix)
                .is_some_and(|deadline| deadline <= now_unix)
        })
        .map(|row| row.detection_id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::temp_dir;
    use punar_common::agent::{AgentClassification, AgentStatus};

    fn record(id: &str, status: AgentStatus) -> RegistryRecord {
        RegistryRecord {
            session_id: id.to_string(),
            agent: "foo-agent".to_string(),
            version: "unknown".to_string(),
            process_id: 2410,
            user: "punar".to_string(),
            project: "unknown".to_string(),
            environment: "host".to_string(),
            status,
            classification: AgentClassification::Unknown,
            started_at: "2026-08-25T14:29:00Z".to_string(),
        }
    }

    fn row(id: &str) -> DetectionIndexRow {
        DetectionIndexRow {
            detection_id: id.to_string(),
            signature_id: "sig_a1b2c3d4e5f6".to_string(),
            signature: "downloads-foo-agent".to_string(),
            executable: "/home/punar/Downloads/foo-agent".to_string(),
            zone: "downloads".to_string(),
            user: "punar".to_string(),
            observed_at: "2026-08-25T14:31:00Z".to_string(),
            cleared_at: None,
            retention_expires_at: None,
        }
    }

    #[test]
    fn every_persisted_line_is_a_schema_exact_ten_field_record() {
        let dir = temp_dir("detections-store");
        let store = DetectionStore::new(
            dir.join("agents/detections.jsonl"),
            dir.join("agents/detections-index.json"),
        );
        store
            .append(&record("agt_d11e0aa7c402", AgentStatus::Active))
            .unwrap();
        store
            .append(&record("agt_d11e0aa7c402", AgentStatus::Ended))
            .unwrap();

        let text = std::fs::read_to_string(store.jsonl_path()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one line per detection state change");
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
                "exactly the ten registry-record.json fields — the sibling data is in the index"
            );
            // And no path, argv or cmdline ever reached the record.
            assert!(!line.contains("/home/"), "{line}");
            assert!(!line.contains("Downloads"), "{line}");
        }
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(store.jsonl_path()).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600, "detections.jsonl is 0600 root");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_non_conformant_record_never_reaches_the_file() {
        let dir = temp_dir("detections-invalid");
        let store = DetectionStore::new(dir.join("d.jsonl"), dir.join("d-index.json"));
        let mut bad = record("nope", AgentStatus::Active);
        bad.version = String::new();
        assert!(store.append(&bad).is_err());
        assert!(!store.jsonl_path().exists(), "nothing was written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_index_round_trips_and_survives_corruption() {
        let dir = temp_dir("detections-index");
        let store = DetectionStore::new(dir.join("d.jsonl"), dir.join("d-index.json"));
        let mut index = DetectionIndex::default();
        index
            .rows
            .insert("agt_d11e0aa7c402".into(), row("agt_d11e0aa7c402"));
        index.updated_at = "2026-08-25T14:31:00Z".into();
        store.write_index(&index).unwrap();
        assert_eq!(store.load_index(), index);

        std::fs::write(store.index_path(), "{ not json").unwrap();
        assert_eq!(
            store.load_index(),
            DetectionIndex::default(),
            "a corrupt index costs the sibling data, never the daemon"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_is_seven_days_after_the_detection_clears_and_never_before() {
        let mut r = row("agt_d11e0aa7c402");
        assert!(
            expired(&index_of(&r), "2027-01-01T00:00:00Z").is_empty(),
            "a live detection is never pruned"
        );
        clear_row(&mut r, "2026-08-25T15:00:00Z");
        assert_eq!(
            r.retention_expires_at.as_deref(),
            Some("2026-09-01T15:00:00Z")
        );
        let index = index_of(&r);
        assert!(expired(&index, "2026-08-31T23:59:59Z").is_empty());
        assert_eq!(
            expired(&index, "2026-09-01T15:00:00Z"),
            vec!["agt_d11e0aa7c402".to_string()]
        );
    }

    fn index_of(row: &DetectionIndexRow) -> DetectionIndex {
        let mut index = DetectionIndex::default();
        index.rows.insert(row.detection_id.clone(), row.clone());
        index
    }

    #[test]
    fn compaction_rewrites_only_when_something_expired() {
        let dir = temp_dir("detections-compact");
        let store = DetectionStore::new(dir.join("d.jsonl"), dir.join("d-index.json"));
        store
            .append(&record("agt_aaaaaaaaaaaa", AgentStatus::Active))
            .unwrap();
        store
            .append(&record("agt_aaaaaaaaaaaa", AgentStatus::Ended))
            .unwrap();
        store
            .append(&record("agt_bbbbbbbbbbbb", AgentStatus::Active))
            .unwrap();

        let before = std::fs::read(store.jsonl_path()).unwrap();
        let keep: std::collections::BTreeSet<String> = [
            "agt_aaaaaaaaaaaa".to_string(),
            "agt_bbbbbbbbbbbb".to_string(),
        ]
        .into_iter()
        .collect();
        assert_eq!(store.rewrite_keeping(&keep).unwrap(), 0);
        assert_eq!(
            std::fs::read(store.jsonl_path()).unwrap(),
            before,
            "nothing expired, so nothing was written"
        );

        let keep: std::collections::BTreeSet<String> =
            ["agt_bbbbbbbbbbbb".to_string()].into_iter().collect();
        assert_eq!(store.rewrite_keeping(&keep).unwrap(), 2);
        let text = std::fs::read_to_string(store.jsonl_path()).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("agt_bbbbbbbbbbbb"));
        assert!(!text.contains("agt_aaaaaaaaaaaa"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
