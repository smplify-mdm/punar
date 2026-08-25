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
    MAX_AUDIT_DRAIN_BYTES, ResourceCategory, ResourceClass, SecurityEventRef, SecurityEventType,
    TailPosition,
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
/// The caller ([`AuditTail::ingest_line`]) has already established that
/// the event names a real agent session, so every rule below reads
/// "…**by an agent**".
///
/// Ordered as milestone-8.md section 4.2 states it — a denial is a denial
/// first, whatever the action was — with the one M9 rule that has to sit
/// **ahead** of the generic deny to exist at all:
///
/// 0. `action == approval.resolve` **and** `decision == deny` →
///    `policy_bypass_attempt` (**producer since M9**: an AI agent that
///    tries to answer an approval gate is refused by punard and audited
///    with `result: "self_approval_refused"` — docs/api/ipc.md section
///    14.5). Narrow by construction: only this one action, only when
///    refused, only when the peer was attributed to an agent session.
///    Without this rule the refusal would land as a generic
///    `denied_access` and M8's written promise ("approval gates arrive
///    with M9") would stay aspirational.
/// 1. `decision == deny` on any other attributed action → `denied_access`
///    (**producer exists**: punard mutations, `agents.register` denials,
///    and since M9 `privilege.request` from inside an agent scope)
/// 2. `decision == allow` **or** `decision == approval_required` on a
///    mutating action → `privilege_request` (**producer exists**)
///
///    The `approval_required` half is an **M9 amendment**. M8 wrote the
///    rule as "an agent reaching for a mutating action *is* a privilege
///    request … whether or not the agent declared it"
///    ([`MUTATING_ACTIONS`]), and in M8 every such reach ended in
///    `allow` or `deny`, so matching `allow` covered it. M9 inserted a
///    third outcome between them: `capabilities.set` from inside an
///    agent scope now returns `approval_required` and executes only
///    after a human resolves the gate. Matching `allow` alone would mean
///    an agent that reached for the firewall and was *gated* leaves no
///    trace in the ledger at all — the reach would be visible only if a
///    human happened to say yes. That is the lie-by-omission spec 1.22
///    forbids, and it is also the asymmetry rule 3 already avoids (a
///    gated `credential.request` is referenced whatever the gate
///    answers). The reference is to the **attempt**; whether it was
///    granted lives in the audit event the reference points at, which is
///    the whole division of labour this module is built on.
/// 3. `action == credential.request` → `credential_request`
///    (**producer since M9**: `punar-secrets`)
///
/// 4. `action == agents.scan` **and** `result == "detected"` →
///    `unknown_ai_execution` (**producer since M10**: the detection pass
///    itself). This is the rule that closes M8's open question. M8 wrote
///    that the audit event existed but attached to no ledger because a
///    detected process had no persisted session; M10 gives it one
///    ([`crate::detections`]), so the transition that produced it is
///    referenced in that ledger and the row leaves
///    [`punar_common::ledger::not_yet_observed`].
///
///    It sits **ahead** of the generic rules for the same reason rule 0
///    does: `agents.scan` is an allowed, non-mutating action, so without
///    an explicit rule it would classify as nothing at all. And only
///    `detected` matches — the matching `cleared` transition is the same
///    execution ending, not a second execution.
///
/// The two remaining enum values — `production_access` (M12) and
/// `sensitive_resource_access` (M12) — have no producer here and are
/// reported in [`punar_common::ledger::not_yet_observed`] instead of
/// being quietly absent: five of the seven are live, two are pending.
pub fn classify(event: &AuditEvent) -> Option<SecurityEventType> {
    if event.action == APPROVAL_RESOLVE_ACTION && event.decision == Decision::Deny {
        return Some(SecurityEventType::PolicyBypassAttempt);
    }
    if event.action == crate::server::ACTION_SCAN && event.result == crate::server::RESULT_DETECTED
    {
        return Some(SecurityEventType::UnknownAiExecution);
    }
    if event.decision == Decision::Deny {
        return Some(SecurityEventType::DeniedAccess);
    }
    if matches!(event.decision, Decision::Allow | Decision::ApprovalRequired)
        && is_mutating(&event.action)
    {
        return Some(SecurityEventType::PrivilegeRequest);
    }
    if event.action == CREDENTIAL_REQUEST_ACTION {
        return Some(SecurityEventType::CredentialRequest);
    }
    None
}

/// The one action whose refusal is a bypass attempt rather than an
/// ordinary denial (docs/api/ipc.md section 14.5).
pub const APPROVAL_RESOLVE_ACTION: &str = "approval.resolve";

/// The `punar-secrets` audit action that carries a credential class in
/// `resource` (docs/api/ipc.md section 16.3).
pub const CREDENTIAL_REQUEST_ACTION: &str = "credential.request";

/// The Level-3 `credential_classes` contribution of one audit event, if
/// it has one (milestone-9.md section 9.2).
///
/// M8 wired `drain_audit` for Level-4 references only, and documented an
/// `Evidence::AuditEvent` variant it never produced. This is the missing
/// door, and it is deliberately the narrowest one that can exist: an
/// **allowed** `credential.request` contributes the class it names, and
/// nothing else does. A *refused* credential contributes only the
/// Level-4 `denied_access` reference rule 1 already makes — a credential
/// that was not issued is not access, and recording it as a class the
/// agent "used" would be a lie in the user's own privacy surface.
///
/// The value is the class **name** (`github`, `aws-dev`) and never a
/// token, a token id or a hash: the broker's audit events carry the class
/// only, which is the property that makes this safe (SPEC section 53).
pub fn credential_class_of(event: &AuditEvent) -> Option<ResourceClass> {
    if event.action != CREDENTIAL_REQUEST_ACTION || event.decision != Decision::Allow {
        return None;
    }
    ResourceClass::new(
        ResourceCategory::CredentialClasses,
        event.resource.as_deref()?,
    )
    .ok()
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
    /// `(session_id, credential class)` in file order — the Level-3
    /// contribution of an allowed `credential.request`
    /// (milestone-9.md section 9.2). Kept beside the references rather
    /// than folded into them because the two land in different halves of
    /// the record: `resources.credential_classes[]` versus
    /// `security_events[]`.
    pub classes: Vec<(String, ResourceClass)>,
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
        // Level 3 first: the class contribution is independent of whether
        // the same event also produces a Level-4 reference, and an
        // allowed `credential.request` produces both.
        if let Some(class) = credential_class_of(&event) {
            result.classes.push((session_id.to_string(), class));
        }
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
        // 2b. M9's third outcome. A GATED mutation is still a reach for a
        //     privilege; recording only the approved half would hide
        //     every attempt a human said no to.
        assert_eq!(
            classify(&event(
                "evt_3g",
                "agt_a",
                "capabilities.set",
                Decision::ApprovalRequired
            )),
            Some(SecurityEventType::PrivilegeRequest)
        );
        // …and only for a MUTATING action: a gate on anything else is not
        // a privilege request invented by this table.
        assert_eq!(
            classify(&event(
                "evt_3h",
                "agt_a",
                "capabilities.get",
                Decision::ApprovalRequired
            )),
            None
        );
        // 3. Credential requests — a live producer since M9
        //    (punar-secrets).
        assert_eq!(
            classify(&event(
                "evt_4",
                "agt_a",
                "credential.request",
                Decision::Allow
            )),
            Some(SecurityEventType::CredentialRequest)
        );
        // 0. The M9 rule sits AHEAD of the generic deny, or it could
        //    never fire: an agent refused at the approval gate would land
        //    as an ordinary denied_access.
        assert_eq!(
            classify(&event("evt_7", "agt_a", "approval.resolve", Decision::Deny)),
            Some(SecurityEventType::PolicyBypassAttempt)
        );
        // Narrow by construction: the same action ALLOWED is a human
        // answering a gate, which is not a bypass attempt and (being a
        // non-mutating action) is not a ledger event at all.
        assert_eq!(
            classify(&event(
                "evt_8",
                "agt_a",
                "approval.resolve",
                Decision::Allow
            )),
            None
        );
        // A refused credential is still a denial, never a bypass.
        assert_eq!(
            classify(&event(
                "evt_9",
                "agt_a",
                "credential.request",
                Decision::Deny
            )),
            Some(SecurityEventType::DeniedAccess)
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
    fn only_an_issued_credential_contributes_a_level_3_class() {
        let mut allowed = event("evt_10", "agt_a", "credential.request", Decision::Allow);
        allowed.resource = Some("aws-dev".to_string());
        assert_eq!(
            credential_class_of(&allowed).map(|c| c.as_str().to_string()),
            Some("aws-dev".to_string()),
            "the kebab-case class id travels verbatim into the ledger"
        );

        // A REFUSED credential is not access. It keeps its Level-4
        // denied_access reference and contributes no class.
        let mut refused = allowed.clone();
        refused.decision = Decision::Deny;
        assert_eq!(credential_class_of(&refused), None);
        assert_eq!(
            classify(&refused),
            Some(SecurityEventType::DeniedAccess),
            "the denial is still recorded, just not as a class the agent used"
        );

        // Nothing else in the trail contributes a class, whatever its
        // resource looks like.
        let mut other = event("evt_11", "agt_a", "capabilities.set", Decision::Allow);
        other.resource = Some("security.firewall".to_string());
        assert_eq!(credential_class_of(&other), None);

        // A resource that is not a legal resource class is dropped rather
        // than poisoning the record: the newtype's rules are the floor.
        let mut bad = allowed.clone();
        bad.resource = Some("/home/punar/.aws/credentials".to_string());
        assert_eq!(credential_class_of(&bad), None);
        bad.resource = None;
        assert_eq!(credential_class_of(&bad), None);
    }

    #[test]
    fn a_drain_carries_the_class_and_the_reference_of_one_issuance() {
        let dir = temp_dir("audit-tail-classes");
        let path = dir.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path).unwrap();
        let mut issued = event(
            "evt_20",
            "agt_4f21c09ab3e1",
            "credential.request",
            Decision::Allow,
        );
        issued.resource = Some("github".to_string());
        writer.append(&issued).unwrap();

        let drained = AuditTail::new(&path).drain(TailPosition::default());
        assert_eq!(
            drained
                .classes
                .iter()
                .map(|(sid, class)| (sid.as_str(), class.as_str()))
                .collect::<Vec<_>>(),
            vec![("agt_4f21c09ab3e1", "github")]
        );
        assert_eq!(drained.references.len(), 1);
        assert_eq!(
            drained.references[0].1.event_type,
            SecurityEventType::CredentialRequest
        );
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
