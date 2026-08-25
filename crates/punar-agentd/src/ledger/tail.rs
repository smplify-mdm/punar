//! Source **B** of the ledger: the audit trail, read as a stream and
//! turned into Level-4 security-event *references* (milestone-8.md
//! section 4; spec sections 21.2, 53).
//!
//! # The ledger reads the audit log; it never duplicates it
//!
//! A reference is `{event_id, event_type, timestamp}` and nothing more.
//! The payload — action, resource, decision, policy ids, result — stays
//! in `/var/log/punar/audit.jsonl`, which is the single source of truth.
//! Duplicating it would create two places to redact, let the two
//! disagree, and put resource names like `security.firewall` inside a
//! per-session file the user can purge while the audit trail deliberately
//! is not purgeable.
//!
//! # Event-driven, never timed (spec 6.3)
//!
//! [`spawn_watch`] puts **one** thread into a blocking `read(2)` on an
//! `inotify` descriptor. There is no interval, no poll loop and no timer
//! anywhere: at idle the thread is parked in the kernel and the drain
//! costs nothing. Every ledger *read* additionally drains first
//! ([`AuditTail::drain`] is cheap when there is nothing new), so a missed
//! notification can never make the ledger lie to the user — the watch is
//! a freshness optimization, not the correctness mechanism.
//!
//! # Idempotence and rotation
//!
//! The tail position `(dev, ino, offset)` lives in the ledger index. When
//! the inode changes, the trail rotated (`audit.jsonl` → `audit.jsonl.1`,
//! `punar_common::audit`): the rotated file is drained from the old
//! offset to EOF *first*, then the new live file from 0, so no event is
//! lost across a rotation. Re-reading the same bytes is harmless because
//! [`punar_common::ledger::LedgerRecord::observe_security_event`] refuses
//! an `event_id` it already holds.

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use punar_common::audit::AGENT_SESSION_NONE;
use punar_common::ledger::{
    MAX_AUDIT_DRAIN_BYTES, SecurityEventRef, SecurityEventType, TailPosition,
};
use punar_common::{AuditEvent, Decision};

/// punard actions that **mutate** the system. An agent reaching for one
/// of these *is* a privilege request in the sense of spec 21.2 — the
/// ledger says so whether or not the agent declared it.
///
/// A table rather than a predicate so the mapping is reviewable in one
/// place, the way `signatures/suspected.json` is.
pub const MUTATING_ACTIONS: [&str; 4] = [
    "capabilities.set",
    "reconcile",
    "reconcile.remediate",
    "state.migrate",
];

/// Prefix form of the same idea — the whole `enroll.*` family mutates
/// the device's authority.
pub const MUTATING_ACTION_PREFIXES: [&str; 1] = ["enroll."];

/// Map one attributed audit event to a Level-4 category, or `None` when
/// it is not security-relevant.
///
/// Ordered exactly as milestone-8.md section 4.2 states it — a denial is
/// a denial first, whatever the action was:
///
/// 1. `decision == deny` on any attributed action → `denied_access`
///    (**producer exists**: punard mutations, `agents.register` denials)
/// 2. `decision == allow` on a mutating action → `privilege_request`
///    (**producer exists**)
/// 3. `action == credential.request` → `credential_request` (**M9**)
///
/// The four remaining enum values — `policy_bypass_attempt` (M9),
/// `production_access` (M12), `sensitive_resource_access` (M9/M12) and
/// `unknown_ai_execution` (the audit event exists today, but a detection
/// has no persisted session, so in M8 it attaches to no ledger; M10 owns
/// the unknown-agent ledger) — have no producer here and are reported in
/// `not_yet_observed[]` instead of being quietly absent. Rule 3's
/// `credential_request` has no producer either (punar-secrets is M9), so
/// it is named there too: five of the seven are pending, two are live.
pub fn classify(event: &AuditEvent) -> Option<SecurityEventType> {
    if event.decision == Decision::Deny {
        return Some(SecurityEventType::DeniedAccess);
    }
    if event.decision == Decision::Allow && is_mutating(&event.action) {
        return Some(SecurityEventType::PrivilegeRequest);
    }
    if event.action == "credential.request" {
        return Some(SecurityEventType::CredentialRequest);
    }
    None
}

fn is_mutating(action: &str) -> bool {
    MUTATING_ACTIONS.contains(&action)
        || MUTATING_ACTION_PREFIXES
            .iter()
            .any(|prefix| action.starts_with(prefix))
}

/// The `agent_session_id` of an event, when it names a real session
/// rather than the `agt_none` sentinel.
pub fn attributed_session(event: &AuditEvent) -> Option<&str> {
    event
        .agent_session_id
        .as_deref()
        .filter(|id| *id != AGENT_SESSION_NONE && punar_common::agent::session_id_ok(id))
}

/// One drain's worth of attributed Level-4 references, plus where to
/// resume.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainResult {
    /// `(session_id, reference)` in file order.
    pub references: Vec<(String, SecurityEventRef)>,
    pub position: TailPosition,
    /// The [`MAX_AUDIT_DRAIN_BYTES`] bound was hit; the next drain picks
    /// up where this one stopped rather than reading the rest now.
    pub bounded: bool,
}

/// The audit trail, read from a remembered offset.
#[derive(Debug, Clone)]
pub struct AuditTail {
    path: PathBuf,
}

impl AuditTail {
    pub fn new(path: impl Into<PathBuf>) -> AuditTail {
        AuditTail { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The `<name>.1` file the trail rotates to.
    fn rotated_path(&self) -> PathBuf {
        let mut os = self.path.clone().into_os_string();
        os.push(".1");
        PathBuf::from(os)
    }

    /// Read everything appended since `from`, mapping each attributed,
    /// security-relevant line to a reference.
    ///
    /// Lines that do not parse, carry `agt_none`, or map to no Level-4
    /// category are skipped. Nothing here allocates a payload: only the
    /// id, the category and the timestamp survive the function.
    pub fn drain(&self, from: TailPosition) -> DrainResult {
        let mut result = DrainResult {
            position: from,
            ..DrainResult::default()
        };
        let Ok(meta) = std::fs::metadata(&self.path) else {
            // No trail yet: nothing to drain, and the position stands.
            return result;
        };
        let (dev, ino) = ids_of(&meta);
        let mut budget = MAX_AUDIT_DRAIN_BYTES;

        let rotated = from.ino != 0 && (from.ino != ino || from.dev != dev);
        if rotated {
            // The file we were reading was renamed; finish it first so no
            // event is lost across the rotation.
            let (_, bounded) =
                self.read_from(&self.rotated_path(), from.offset, &mut budget, &mut result);
            result.bounded |= bounded;
            result.position.offset = 0;
        } else if from.offset > meta.len() {
            // Same inode, smaller file: someone truncated it. Restart.
            result.position.offset = 0;
        }

        let start = result.position.offset;
        let (consumed, bounded) = self.read_from(&self.path, start, &mut budget, &mut result);
        result.bounded |= bounded;
        result.position = TailPosition {
            dev,
            ino,
            offset: start + consumed,
        };
        result
    }

    /// Read whole lines from `offset`, appending references. Returns
    /// `(bytes consumed, hit the bound)`. A trailing partial line (a
    /// writer mid-append) is deliberately **not** consumed: the offset
    /// stops before it, and the next drain sees the complete line.
    fn read_from(
        &self,
        path: &Path,
        offset: u64,
        budget: &mut u64,
        result: &mut DrainResult,
    ) -> (u64, bool) {
        let Ok(mut file) = std::fs::File::open(path) else {
            return (0, false);
        };
        if file.seek(SeekFrom::Start(offset)).is_err() {
            return (0, false);
        }
        let mut reader = BufReader::new(file.by_ref().take(*budget));
        let mut consumed = 0u64;
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(n) => {
                    if !line.ends_with('\n') {
                        // Partial line: leave it for the next drain.
                        break;
                    }
                    consumed += n as u64;
                    *budget = budget.saturating_sub(n as u64);
                    self.ingest_line(line.trim_end(), result);
                }
                Err(_) => break,
            }
        }
        (consumed, *budget == 0)
    }

    fn ingest_line(&self, line: &str, result: &mut DrainResult) {
        if line.is_empty() {
            return;
        }
        let Ok(event) = serde_json::from_str::<AuditEvent>(line) else {
            return;
        };
        let Some(session_id) = attributed_session(&event) else {
            return;
        };
        let Some(event_type) = classify(&event) else {
            return;
        };
        // The reference is projected verbatim into
        // `security_events[].event_id`, whose schema pattern is
        // `^evt_[A-Za-z0-9]+$`. A line that does not carry a conformant
        // id is not a reference to anything a reader could look up, so it
        // is dropped here rather than poisoning a whole session's record
        // (which `LedgerRecord::validate` would then refuse to write).
        if !punar_common::ledger::event_id_ok(&event.event_id) {
            return;
        }
        result.references.push((
            session_id.to_string(),
            SecurityEventRef {
                event_id: event.event_id,
                event_type,
                timestamp: Some(event.timestamp),
            },
        ));
    }
}

#[cfg(unix)]
fn ids_of(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

// ---------------------------------------------------------------------------
// The blocking inotify watcher (spec 6.3 — event-driven, no timer)
// ---------------------------------------------------------------------------

/// Directory whose only purpose is to be written to at shutdown, so the
/// watcher's blocking `read(2)` returns and the thread can exit. It sits
/// under the (root-only) ledger directory and nothing else ever writes
/// there — the same trick the accept loop uses when it connects to its
/// own socket to wake itself.
pub const WAKE_DIR: &str = ".wake";

/// Create and immediately remove a file in the wake directory. Called at
/// shutdown; harmless at any other time.
pub fn wake(ledger_dir: &Path) {
    let dir = ledger_dir.join(WAKE_DIR);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("stop");
    let _ = std::fs::write(&path, b"");
    let _ = std::fs::remove_file(&path);
}

/// Start the watcher thread.
///
/// `on_change` runs after every wakeup; it is expected to drain and is
/// expected to be cheap when there is nothing new. `should_stop` is
/// checked first, so a [`wake`] during shutdown ends the thread.
///
/// Returns `None` when no watch could be established (no `inotify`, or a
/// path that does not exist yet) — the daemon then relies entirely on the
/// lazy catch-up drain, which is the correctness mechanism anyway, and
/// says so on stderr rather than pretending it is watching.
#[cfg(target_os = "linux")]
pub fn spawn_watch(
    audit_path: &Path,
    ledger_dir: &Path,
    should_stop: impl Fn() -> bool + Send + 'static,
    on_change: impl Fn() + Send + 'static,
) -> Option<std::thread::JoinHandle<()>> {
    use rustix::fs::inotify::{self, CreateFlags, WatchFlags};

    let wake_dir = ledger_dir.join(WAKE_DIR);
    let _ = std::fs::create_dir_all(&wake_dir);

    let fd = inotify::init(CreateFlags::empty()).ok()?;
    let mut watches = 0usize;
    // The live trail: appends and its own rename away.
    if inotify::add_watch(
        &fd,
        audit_path,
        WatchFlags::MODIFY | WatchFlags::MOVE_SELF | WatchFlags::DELETE_SELF,
    )
    .is_ok()
    {
        watches += 1;
    }
    // Its directory: rotation creates a fresh audit.jsonl.
    if let Some(parent) = audit_path.parent() {
        if inotify::add_watch(&fd, parent, WatchFlags::CREATE | WatchFlags::MOVED_TO).is_ok() {
            watches += 1;
        }
    }
    // The shutdown channel.
    if inotify::add_watch(&fd, &wake_dir, WatchFlags::CREATE).is_ok() {
        watches += 1;
    }
    if watches == 0 {
        return None;
    }

    let mut file = std::fs::File::from(fd);
    std::thread::Builder::new()
        .name("punar-agentd-ledger".to_string())
        .spawn(move || {
            // One buffer, reused: the events themselves are discarded —
            // "something changed" is the whole signal, and the drain is
            // idempotent, so there is nothing to parse.
            let mut buf = [0u8; 4096];
            loop {
                if should_stop() {
                    break;
                }
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {
                        if should_stop() {
                            break;
                        }
                        on_change();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        })
        .ok()
}

/// Non-Linux builds have no `inotify`. The daemon ships on Linux; this
/// stub exists so the workspace still builds (and the ledger's unit tests
/// still run) on a developer's macOS host, where the lazy catch-up drain
/// is the whole mechanism.
#[cfg(not(target_os = "linux"))]
pub fn spawn_watch(
    _audit_path: &Path,
    _ledger_dir: &Path,
    _should_stop: impl Fn() -> bool + Send + 'static,
    _on_change: impl Fn() + Send + 'static,
) -> Option<std::thread::JoinHandle<()>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::temp_dir;
    use punar_common::PrincipalKind;
    use punar_common::audit::AuditWriter;

    fn event(id: &str, session: &str, action: &str, decision: Decision) -> AuditEvent {
        AuditEvent {
            event_id: id.to_string(),
            timestamp: "2026-08-27T09:59:12Z".to_string(),
            device_id: "dev_test".to_string(),
            user_id: Some("punar".to_string()),
            agent_session_id: Some(session.to_string()),
            project_id: Some("atlas".to_string()),
            source: PrincipalKind::AiAgent,
            action: action.to_string(),
            resource: Some("security.firewall".to_string()),
            decision,
            policy_ids: vec!["personal-defaults".to_string()],
            result: match decision {
                Decision::Deny => "denied".to_string(),
                _ => "success".to_string(),
            },
        }
    }

    #[test]
    fn the_mapping_table_is_ordered_and_only_claims_producers_that_exist() {
        // 1. A denial is a denial first, whatever the action.
        assert_eq!(
            classify(&event("evt_1", "agt_a", "capabilities.set", Decision::Deny)),
            Some(SecurityEventType::DeniedAccess)
        );
        assert_eq!(
            classify(&event("evt_2", "agt_a", "agents.register", Decision::Deny)),
            Some(SecurityEventType::DeniedAccess)
        );
        // 2. An allowed mutation is a privilege request.
        for action in [
            "capabilities.set",
            "reconcile",
            "enroll.start",
            "enroll.sync",
        ] {
            assert_eq!(
                classify(&event("evt_3", "agt_a", action, Decision::Allow)),
                Some(SecurityEventType::PrivilegeRequest),
                "{action}"
            );
        }
        // 3. Credential requests — no producer until M9, but the arm is
        //    already here, which is why M9 needs no ledger code change.
        assert_eq!(
            classify(&event(
                "evt_4",
                "agt_a",
                "credential.request",
                Decision::Allow
            )),
            Some(SecurityEventType::CredentialRequest)
        );
        // Reads are not security events.
        for action in ["capabilities.get", "status", "agents.list", "audit.tail"] {
            assert_eq!(
                classify(&event("evt_5", "agt_a", action, Decision::Allow)),
                None,
                "{action}"
            );
        }
    }

    #[test]
    fn unattributed_events_belong_to_no_ledger() {
        let mut e = event(
            "evt_6",
            AGENT_SESSION_NONE,
            "capabilities.set",
            Decision::Deny,
        );
        assert_eq!(attributed_session(&e), None);
        e.agent_session_id = None;
        assert_eq!(attributed_session(&e), None);
        e.agent_session_id = Some("not-an-id".into());
        assert_eq!(attributed_session(&e), None);
        e.agent_session_id = Some("agt_4f21c09ab3e1".into());
        assert_eq!(attributed_session(&e), Some("agt_4f21c09ab3e1"));
    }

    #[test]
    fn draining_resumes_from_the_offset_and_keeps_only_references() {
        let dir = temp_dir("audit-tail");
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        writer
            .append(&event(
                "evt_1",
                "agt_4f21c09ab3e1",
                "capabilities.set",
                Decision::Deny,
            ))
            .unwrap();
        writer
            .append(&event(
                "evt_2",
                AGENT_SESSION_NONE,
                "capabilities.set",
                Decision::Deny,
            ))
            .unwrap();

        let tail = AuditTail::new(&path);
        let first = tail.drain(TailPosition::default());
        assert_eq!(first.references.len(), 1, "only attributed lines count");
        assert_eq!(first.references[0].0, "agt_4f21c09ab3e1");
        assert_eq!(first.references[0].1.event_id, "evt_1");
        assert_eq!(
            first.references[0].1.event_type,
            SecurityEventType::DeniedAccess
        );
        assert!(first.position.offset > 0);
        assert!(first.position.ino > 0);

        // Nothing new: a second drain is empty and the position stands.
        let second = tail.drain(first.position);
        assert!(second.references.is_empty());
        assert_eq!(second.position, first.position);

        // One more append is picked up from where we left off.
        writer
            .append(&event(
                "evt_3",
                "agt_4f21c09ab3e1",
                "enroll.start",
                Decision::Allow,
            ))
            .unwrap();
        let third = tail.drain(second.position);
        assert_eq!(third.references.len(), 1);
        assert_eq!(
            third.references[0].1.event_type,
            SecurityEventType::PrivilegeRequest
        );

        // No payload survived the read.
        let text = serde_json::to_string(&third.references).unwrap();
        assert!(!text.contains("security.firewall"), "{text}");
        assert!(!text.contains("policy_ids"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rotation_loses_no_event() {
        let dir = temp_dir("audit-rotate");
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        writer
            .append(&event(
                "evt_1",
                "agt_4f21c09ab3e1",
                "capabilities.set",
                Decision::Deny,
            ))
            .unwrap();

        let tail = AuditTail::new(&path);
        let position = tail.drain(TailPosition::default()).position;

        // One more event lands in the file we already partly read…
        writer
            .append(&event(
                "evt_2",
                "agt_4f21c09ab3e1",
                "reconcile",
                Decision::Allow,
            ))
            .unwrap();
        // …then the trail rotates and a fresh file starts.
        std::fs::rename(&path, dir.join("audit.jsonl.1")).unwrap();
        let mut fresh = AuditWriter::open(&path).unwrap();
        fresh
            .append(&event(
                "evt_3",
                "agt_4f21c09ab3e1",
                "enroll.stop",
                Decision::Allow,
            ))
            .unwrap();

        let after = tail.drain(position);
        let ids: Vec<&str> = after
            .references
            .iter()
            .map(|(_, r)| r.event_id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["evt_2", "evt_3"],
            "the tail of the rotated file first"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_partial_trailing_line_is_left_for_the_next_drain() {
        let dir = temp_dir("audit-partial");
        let path = dir.join("audit.jsonl");
        let complete = serde_json::to_string(&event(
            "evt_1",
            "agt_4f21c09ab3e1",
            "capabilities.set",
            Decision::Deny,
        ))
        .unwrap();
        let partial = serde_json::to_string(&event(
            "evt_2",
            "agt_4f21c09ab3e1",
            "capabilities.set",
            Decision::Deny,
        ))
        .unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, format!("{complete}\n{}", &partial[..20])).unwrap();

        let tail = AuditTail::new(&path);
        let first = tail.drain(TailPosition::default());
        assert_eq!(first.references.len(), 1);

        // The writer finishes the line; the next drain sees it whole.
        std::fs::write(&path, format!("{complete}\n{partial}\n")).unwrap();
        let second = tail.drain(first.position);
        assert_eq!(second.references.len(), 1);
        assert_eq!(second.references[0].1.event_id, "evt_2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_trail_is_not_an_error() {
        let tail = AuditTail::new("/nonexistent/audit.jsonl");
        let result = tail.drain(TailPosition::default());
        assert!(result.references.is_empty());
        assert_eq!(result.position, TailPosition::default());
    }
}
