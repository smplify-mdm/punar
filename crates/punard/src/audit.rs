//! Append-only audit log (SPEC section 53; docs/api/ipc.md section 6).
//!
//! One `punar_common::AuditEvent` JSON object per line in
//! `/var/log/punar/audit.jsonl`, created `0640 root:punar` by punard,
//! written only by punard. Every event carries **all 12 schema-required
//! fields** — the daemon fills the agent-less ones with the documented
//! sentinels (`agt_none`, `project_id: "system"`). Rotation is explicitly
//! out of M3 (target M5).
//!
//! INTERFACE NOTE (for the M3 integrate agent): the plan gives punar-common
//! an `audit` module extension written concurrently. This module uses the
//! existing `punar_common::AuditEvent` as-is; only the file writer and the
//! sentinel-filling constructor live here. If the concurrent work ships its
//! own event-builder helper, prefer it over [`build_event`].

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use punar_common::{AuditEvent, Decision, PrincipalKind};
use serde_json::Value;

use crate::timeutil::{unix_now_millis, utc_now_rfc3339};

/// Sentinel `agent_session_id` for events with no AI agent involved
/// (pattern-valid `^agt_`; contract follow-up tracked for the M4 schema
/// owner in docs/development/milestone-3.md section 10).
pub const AGENT_NONE: &str = "agt_none";

/// Sentinel `project_id` until project workspaces reach the control plane.
pub const PROJECT_SYSTEM: &str = "system";

/// `user_id` for daemon-initiated events (boot reconcile).
pub const USER_DAEMON: &str = "punard";

/// `resource` for registry-wide actions (reconcile).
pub const RESOURCE_REGISTRY: &str = "capability_registry";

static EVENT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Process-unique event id matching `^evt_[A-Za-z0-9]+$`.
pub fn new_event_id() -> String {
    let seq = EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("evt_{}x{seq}", unix_now_millis())
}

/// Build a fully-populated (all 12 fields `Some`) audit event with the M3
/// sentinel rules of docs/api/ipc.md section 6.
///
/// No secret material can flow through here by construction: every argument
/// is an identifier, decision, or outcome; any future secret-bearing field
/// must be typed `punar_common::Redacted` (SPEC sections 1.19, 53).
pub fn build_event(
    device_id: &str,
    user_id: &str,
    source: PrincipalKind,
    action: &str,
    resource: &str,
    decision: Decision,
    result: &str,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        timestamp: utc_now_rfc3339(),
        device_id: device_id.to_string(),
        user_id: Some(user_id.to_string()),
        agent_session_id: Some(AGENT_NONE.to_string()),
        project_id: Some(PROJECT_SYSTEM.to_string()),
        source,
        action: action.to_string(),
        resource: Some(resource.to_string()),
        decision,
        policy_ids: vec![crate::authz::POLICY_PERSONAL_DEFAULTS.to_string()],
        result: result.to_string(),
    }
}

/// The append-only audit file.
pub struct AuditLog {
    path: PathBuf,
    inner: Mutex<AuditInner>,
}

struct AuditInner {
    file: File,
    count: u64,
}

impl AuditLog {
    /// Open (creating if needed, mode 0640) and count existing events.
    /// `owner_gid`: best-effort `chown root:<gid>` — only meaningful when
    /// running as root; failure is ignored (tests run unprivileged, and the
    /// in-VM m3-check asserts the real modes).
    pub fn open(path: &Path, owner_gid: Option<u32>) -> io::Result<Self> {
        let count = match File::open(path) {
            Ok(f) => BufReader::new(f).lines().count() as u64,
            Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e),
        };
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o640)
            .open(path)?;
        if let Some(gid) = owner_gid {
            let _ = std::os::unix::fs::chown(path, Some(0), Some(gid));
        }
        Ok(AuditLog {
            path: path.to_path_buf(),
            inner: Mutex::new(AuditInner { file, count }),
        })
    }

    /// Append one event and flush (no per-line fsync — documented M3
    /// tradeoff, docs/development/milestone-3.md section 5).
    pub fn append(&self, event: &AuditEvent) -> io::Result<()> {
        let mut line = serde_json::to_string(event).map_err(io::Error::other)?;
        line.push('\n');
        let mut inner = self.inner.lock().unwrap();
        inner.file.write_all(line.as_bytes())?;
        inner.file.flush()?;
        inner.count += 1;
        Ok(())
    }

    /// Number of events in the file.
    pub fn count(&self) -> u64 {
        self.inner.lock().unwrap().count
    }

    /// Last `n` events, oldest→newest (docs/api/ipc.md section 5.5: newest
    /// last). Reads the whole file — fine at M3 event rates; rotation and
    /// smarter tailing land with M5.
    pub fn tail(&self, n: usize) -> io::Result<Vec<Value>> {
        // Hold the writer lock so a concurrent append cannot interleave
        // with the read.
        let _guard = self.inner.lock().unwrap();
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut events: Vec<Value> = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str(&line) {
                Ok(v) => events.push(v),
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("corrupt audit line: {e}"),
                    ));
                }
            }
        }
        let skip = events.len().saturating_sub(n);
        Ok(events.split_off(skip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn events_have_all_twelve_schema_fields() {
        let ev = build_event(
            "dev_abc123def4",
            "root",
            PrincipalKind::Human,
            "capabilities.set",
            "system.hostname",
            Decision::Allow,
            "success",
        );
        let v = serde_json::to_value(&ev).unwrap();
        let obj = v.as_object().unwrap();
        for key in [
            "event_id",
            "timestamp",
            "device_id",
            "user_id",
            "agent_session_id",
            "project_id",
            "source",
            "action",
            "resource",
            "decision",
            "policy_ids",
            "result",
        ] {
            assert!(obj.contains_key(key), "missing {key}");
        }
        assert!(obj["event_id"].as_str().unwrap().starts_with("evt_"));
        assert_eq!(obj["agent_session_id"], AGENT_NONE);
        assert_eq!(obj["project_id"], PROJECT_SYSTEM);
        assert_eq!(obj["policy_ids"], serde_json::json!(["personal-defaults"]));
        assert_eq!(obj["source"], "human");
    }

    #[test]
    fn event_ids_are_unique_and_pattern_valid() {
        let a = new_event_id();
        let b = new_event_id();
        assert_ne!(a, b);
        for id in [&a, &b] {
            let rest = id.strip_prefix("evt_").unwrap();
            assert!(!rest.is_empty());
            assert!(rest.chars().all(|c| c.is_ascii_alphanumeric()), "{id}");
        }
    }

    #[test]
    fn append_count_and_tail_round_trip() {
        let dir = std::env::temp_dir().join(format!("punard-audit-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let log = AuditLog::open(&path, None).unwrap();
        assert_eq!(log.count(), 0);

        for i in 0..5 {
            log.append(&build_event(
                "dev_abc123def4",
                "root",
                PrincipalKind::Human,
                "capabilities.set",
                "system.hostname",
                Decision::Allow,
                &format!("success-{i}"),
            ))
            .unwrap();
        }
        assert_eq!(log.count(), 5);

        let tail = log.tail(2).unwrap();
        assert_eq!(tail.len(), 2);
        // Newest last.
        assert_eq!(tail[1]["result"], "success-4");
        assert_eq!(tail[0]["result"], "success-3");

        // Reopen counts what is on disk.
        drop(log);
        let reopened = AuditLog::open(&path, None).unwrap();
        assert_eq!(reopened.count(), 5);
        let _ = fs::remove_dir_all(&dir);
    }
}
