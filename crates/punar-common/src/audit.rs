//! Audit events and the append-only JSONL audit trail (SPEC section 53).
//!
//! Milestone 3 additions on top of the M0 [`AuditEvent`] type: builder
//! helpers that emit schema-complete events, [`AuditWriter`] (append-only
//! JSONL at [`AUDIT_LOG_PATH`]), the [`tail`] reader behind the
//! `audit.tail` RPC, and [`validate_event_schema`], the Rust-side mirror of
//! `schemas/audit/audit-event.json`.
//!
//! # Field population rules (docs/api/ipc.md section 6)
//!
//! The shipped schema requires all 12 fields on every event. Fields the M3
//! daemon cannot fill from a richer context use documented sentinels:
//!
//! - `agent_session_id`: [`AGENT_SESSION_NONE`] (`"agt_none"`) — a
//!   pattern-valid sentinel meaning "no AI agent session involved".
//!   Recorded as an M4 schema follow-up: consider making agent fields
//!   conditional on `source: "ai_agent"`.
//! - `project_id`: [`PROJECT_ID_SYSTEM`] (`"system"`) — no project
//!   workspaces in the control plane until M6.
//! - `policy_ids`: `["personal-defaults"]` — the M3 built-in root-only rule;
//!   real policy ids arrive with the M4 merge.
//! - `source`: `human` for CLI-originated requests. For daemon-initiated
//!   events the plan's shorthand was "os", but `"os"` is **not** a value of
//!   the shipped `principal_kind` enum that the audit schema binds `source`
//!   to — and the schema is the contract. [`AuditActor::daemon`] therefore
//!   uses [`PrincipalKind::Service`] (`punard` is a service principal), the
//!   schema-valid encoding of "the OS did this". Flagged for the M4 schema
//!   owner alongside the `agt_none` note.
//!
//! # Durability (fsync) policy
//!
//! [`AuditWriter::append`] writes each event as **one** `write_all` of a
//! complete line to an `O_APPEND` descriptor, then calls `sync_data`
//! (fdatasync). Rationale: M3 audits only mutations, denials, and
//! reconciles — a handful of events per boot — so per-event fsync costs
//! nothing measurable, and an audit record that evaporates on power loss is
//! not an audit record. The single-write + `O_APPEND` combination also keeps
//! concurrent readers from ever observing a torn line. Revisit alongside
//! rotation (M5) if event rates grow.
//!
//! # No secrets, structurally (SPEC sections 1.19, 53)
//!
//! `AuditEvent` records identifiers, decisions, and outcomes; it has no
//! payload field. Any future secret-bearing field must be typed
//! [`crate::Redacted`], whose `Serialize`/`Debug`/`Display` emit only
//! `"[redacted]"` — the writer cannot leak what the type cannot print. The
//! tests prove the placeholder is what reaches the file.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CapabilityId, Decision, PrincipalKind};

/// The audit trail path (docs/api/ipc.md section 6). Directory
/// `/var/log/punar` is `0750 root:punar` via tmpfiles; the file is created
/// `0640` by [`AuditWriter`]; group ownership is the daemon's job.
pub const AUDIT_LOG_PATH: &str = "/var/log/punar/audit.jsonl";

/// Sentinel `agent_session_id` for events with no AI agent involved
/// (pattern-valid against `^agt_[A-Za-z0-9]+$`; see module docs).
pub const AGENT_SESSION_NONE: &str = "agt_none";

/// Sentinel `project_id` until project workspaces reach the control plane
/// (M6).
pub const PROJECT_ID_SYSTEM: &str = "system";

/// The Milestone 3 built-in authorization rule: mutations are root-only
/// until just-in-time elevation (M9).
pub const POLICY_PERSONAL_DEFAULTS: &str = "personal-defaults";

/// `user_id` for daemon-initiated events (boot reconcile).
pub const USER_ID_DAEMON: &str = "punard";

/// `resource` for registry-wide actions (`reconcile`).
pub const RESOURCE_CAPABILITY_REGISTRY: &str = "capability_registry";

/// A structured audit event, with the fields of the SPEC section 53 example.
///
/// ```json
/// {
///   "event_id": "evt_123",
///   "timestamp": "...",
///   "device_id": "dev_123",
///   "user_id": "alice@acme.com",
///   "agent_session_id": "agt_123",
///   "project_id": "atlas",
///   "source": "ai_agent",
///   "action": "credential.request",
///   "resource": "aws-dev",
///   "decision": "allow",
///   "policy_ids": ["eng-ai-v3"],
///   "result": "success"
/// }
/// ```
///
/// Type-level decisions (M0, kept in M3):
///
/// - `timestamp` is an RFC 3339 string ([`crate::time::utc_now_rfc3339`]
///   produces it; no time crate).
/// - `user_id`, `agent_session_id`, `project_id`, and `resource` stay
///   `Option` at the type level, but the shipped schema requires all 12
///   fields — the Milestone 3 builder constructors
///   ([`AuditEvent::capabilities_set`] and friends) always fill them (with
///   the documented sentinels where needed), and [`AuditWriter::append`]
///   refuses events that fail [`validate_event_schema`]. Hand-built events
///   must fill every field themselves.
/// - `result` stays a free-form string; the M3 vocabulary is
///   [`AuditOutcome`].
///
/// SPEC section 53 also rules: never log passwords, secret values, tokens,
/// private keys, prompt contents by default, or source code. `AuditEvent`
/// deliberately has no field for payload or secret material; anything secret
/// must live behind [`crate::Redacted`], which serializes as `"[redacted]"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    /// RFC 3339 timestamp string (see type docs).
    pub timestamp: String,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Kind of principal that caused the event (`"ai_agent"` in the SPEC
    /// example).
    pub source: PrincipalKind,
    /// Dotted action name, such as `credential.request`.
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    pub decision: Decision,
    #[serde(default)]
    pub policy_ids: Vec<String>,
    pub result: String,
}

// ---------------------------------------------------------------------------
// M3 vocabulary and builders (docs/api/ipc.md section 6)
// ---------------------------------------------------------------------------

/// The Milestone 3 `result` vocabulary. The schema keeps `result` a
/// free-form string; this enum is the closed set the M3 daemon emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// Mutation applied and verified.
    Success,
    /// Observed state already equaled the request (idempotent; still
    /// audited).
    Noop,
    /// Authorization denied.
    Denied,
    /// Backend apply step failed.
    Failure,
    /// Apply ran but post-apply verification did not observe the desired
    /// state.
    VerifyFailed,
    /// Reconcile found drift (report only in M3).
    DriftDetected,
    /// Reconcile found no drift.
    Clean,
}

impl AuditOutcome {
    /// All M3 outcomes.
    pub const ALL: [AuditOutcome; 7] = [
        AuditOutcome::Success,
        AuditOutcome::Noop,
        AuditOutcome::Denied,
        AuditOutcome::Failure,
        AuditOutcome::VerifyFailed,
        AuditOutcome::DriftDetected,
        AuditOutcome::Clean,
    ];

    /// The wire spelling written into `result`.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditOutcome::Success => "success",
            AuditOutcome::Noop => "noop",
            AuditOutcome::Denied => "denied",
            AuditOutcome::Failure => "failure",
            AuditOutcome::VerifyFailed => "verify_failed",
            AuditOutcome::DriftDetected => "drift_detected",
            AuditOutcome::Clean => "clean",
        }
    }
}

/// Who an audit event is attributed to: the `user_id` + `source` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditActor {
    /// Username for the peer's `SO_PEERCRED` uid (`"root"`, `"punar"`),
    /// `"uid:<n>"` when unresolvable, or [`USER_ID_DAEMON`].
    pub user_id: String,
    pub source: PrincipalKind,
}

impl AuditActor {
    /// A CLI-originated request: the resolved username of the connected
    /// peer, `source: human`.
    pub fn cli_peer(user_id: impl Into<String>) -> AuditActor {
        AuditActor {
            user_id: user_id.into(),
            source: PrincipalKind::Human,
        }
    }

    /// A CLI-originated request whose uid could not be resolved to a name:
    /// `user_id: "uid:<n>"`, `source: human`.
    pub fn cli_peer_uid(uid: u32) -> AuditActor {
        AuditActor::cli_peer(format!("uid:{uid}"))
    }

    /// A daemon-initiated event (boot reconcile): `user_id: "punard"`,
    /// `source: service`. The plan's shorthand for this attribution was
    /// "os", which is not a schema-valid `principal_kind`; `service` is the
    /// schema-conformant encoding (module docs).
    pub fn daemon() -> AuditActor {
        AuditActor {
            user_id: USER_ID_DAEMON.to_string(),
            source: PrincipalKind::Service,
        }
    }
}

/// Per-process counter for [`next_event_id`].
static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh event id: `evt_<unix-millis>x<per-process-counter>`, matching the
/// schema pattern `^evt_[A-Za-z0-9]+$`. Unique within a process; unique
/// across daemon restarts to millisecond granularity (docs/development/
/// milestone-3.md section 3).
pub fn next_event_id() -> String {
    let millis = crate::time::unix_now_millis();
    let counter = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("evt_{millis}x{counter}")
}

impl AuditEvent {
    /// Common scaffolding for the M3 builders: stamps id + timestamp and
    /// fills every schema-required field, sentinels included.
    fn m3_event(
        device_id: &str,
        actor: &AuditActor,
        action: &str,
        resource: &str,
        decision: Decision,
        result: &str,
    ) -> AuditEvent {
        AuditEvent {
            event_id: next_event_id(),
            timestamp: crate::time::utc_now_rfc3339(),
            device_id: device_id.to_string(),
            user_id: Some(actor.user_id.clone()),
            agent_session_id: Some(AGENT_SESSION_NONE.to_string()),
            project_id: Some(PROJECT_ID_SYSTEM.to_string()),
            source: actor.source,
            action: action.to_string(),
            resource: Some(resource.to_string()),
            decision,
            policy_ids: vec![POLICY_PERSONAL_DEFAULTS.to_string()],
            result: result.to_string(),
        }
    }

    /// A `capabilities.set` event (allowed path — every result: success,
    /// noop, failure, verify_failed). Denials go through
    /// [`AuditEvent::denial`].
    pub fn capabilities_set(
        device_id: &str,
        actor: &AuditActor,
        capability: &CapabilityId,
        decision: Decision,
        outcome: AuditOutcome,
    ) -> AuditEvent {
        AuditEvent::m3_event(
            device_id,
            actor,
            "capabilities.set",
            capability.as_str(),
            decision,
            outcome.as_str(),
        )
    }

    /// A `reconcile` event: `resource: "capability_registry"`,
    /// `decision: allow`, outcome [`AuditOutcome::DriftDetected`] or
    /// [`AuditOutcome::Clean`].
    pub fn reconcile(device_id: &str, actor: &AuditActor, outcome: AuditOutcome) -> AuditEvent {
        AuditEvent::m3_event(
            device_id,
            actor,
            "reconcile",
            RESOURCE_CAPABILITY_REGISTRY,
            Decision::Allow,
            outcome.as_str(),
        )
    }

    /// An authorization denial for any method (`action` is the method name
    /// verbatim, e.g. `"capabilities.set"`): `decision: deny`,
    /// `result: "denied"`. Every denial is audited (docs/api/ipc.md
    /// section 6).
    pub fn denial(device_id: &str, actor: &AuditActor, action: &str, resource: &str) -> AuditEvent {
        AuditEvent::m3_event(
            device_id,
            actor,
            action,
            resource,
            Decision::Deny,
            AuditOutcome::Denied.as_str(),
        )
    }
}

// ---------------------------------------------------------------------------
// Schema validation (Rust mirror of schemas/audit/audit-event.json)
// ---------------------------------------------------------------------------

/// Check an event against the shipped audit schema's rules: all 12 fields
/// present and non-empty, id prefixes (`evt_` / `dev_` / `agt_`), the
/// RFC 3339 timestamp pattern, and the dotted-action pattern. `source` and
/// `decision` are schema-valid by type. Returns every violation found.
///
/// [`AuditWriter::append`] runs this before writing, so a non-conformant
/// event can never reach the trail.
pub fn validate_event_schema(event: &AuditEvent) -> Result<(), Vec<String>> {
    let mut violations = Vec::new();
    if !prefixed_id_ok(&event.event_id, "evt_") {
        violations.push(format!(
            "event_id {:?} must match ^evt_[A-Za-z0-9]+$",
            event.event_id
        ));
    }
    if !crate::time::is_rfc3339_timestamp(&event.timestamp) {
        violations.push(format!(
            "timestamp {:?} must be RFC 3339 (schema pattern)",
            event.timestamp
        ));
    }
    if !prefixed_id_ok(&event.device_id, "dev_") {
        violations.push(format!(
            "device_id {:?} must match ^dev_[A-Za-z0-9]+$",
            event.device_id
        ));
    }
    match event.user_id.as_deref() {
        Some(user_id) if !user_id.is_empty() => {}
        _ => violations.push("user_id is required and must be non-empty".to_string()),
    }
    match event.agent_session_id.as_deref() {
        Some(id) if prefixed_id_ok(id, "agt_") => {}
        _ => violations.push(format!(
            "agent_session_id is required and must match ^agt_[A-Za-z0-9]+$ \
             (use {AGENT_SESSION_NONE:?} when no agent is involved)"
        )),
    }
    match event.project_id.as_deref() {
        Some(id) if !id.is_empty() => {}
        _ => violations.push(format!(
            "project_id is required and must be non-empty (use {PROJECT_ID_SYSTEM:?})"
        )),
    }
    if !action_pattern_ok(&event.action) {
        violations.push(format!(
            "action {:?} must be dotted snake_case ([a-z][a-z0-9_]* segments)",
            event.action
        ));
    }
    match event.resource.as_deref() {
        Some(resource) if !resource.is_empty() => {}
        _ => violations.push("resource is required and must be non-empty".to_string()),
    }
    for (index, policy_id) in event.policy_ids.iter().enumerate() {
        if policy_id.is_empty() {
            violations.push(format!("policy_ids[{index}] must be non-empty"));
        }
    }
    if event.result.is_empty() {
        violations.push("result must be non-empty".to_string());
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn prefixed_id_ok(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Schema pattern `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`.
fn action_pattern_ok(action: &str) -> bool {
    !action.is_empty()
        && action.split('.').all(|segment| {
            let mut bytes = segment.bytes();
            bytes.next().is_some_and(|b| b.is_ascii_lowercase())
                && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

// ---------------------------------------------------------------------------
// Writer and reader
// ---------------------------------------------------------------------------

/// Errors from [`AuditWriter`] and [`tail`].
#[derive(Debug, Error)]
pub enum AuditError {
    /// The event fails [`validate_event_schema`]; nothing was written.
    #[error("audit event violates the section 53 schema: {0:?}")]
    Schema(Vec<String>),
    #[error("audit event serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("audit log I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// Size-capped rotation threshold (docs/api/ipc.md §6, delivered in M5):
/// when the live file has reached this size at write time, it is renamed
/// to `<name>.1` (replacing any older rotated file — exactly one is kept)
/// and a fresh live file is started. `audit.tail` reads the live file
/// only, unchanged.
pub const AUDIT_ROTATE_BYTES: u64 = 8 * 1024 * 1024;

/// Append-only JSONL audit writer (see the module docs for the durability
/// policy and permission split).
///
/// Creation semantics: opens (or creates, mode `0640`) the file in append
/// mode and re-asserts `0640` on the open descriptor, so a pre-existing
/// file with looser permissions is tightened. Directory permissions and
/// `root:punar` group ownership are the daemon/tmpfiles contract, not this
/// type's.
#[derive(Debug)]
pub struct AuditWriter {
    file: File,
    path: PathBuf,
    /// Rotation threshold — [`AUDIT_ROTATE_BYTES`] in production; tests
    /// shrink it to exercise rotation without writing 8 MiB.
    rotate_bytes: u64,
}

impl AuditWriter {
    /// Open (or create, mode `0640`) the audit log for appending.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<AuditWriter> {
        let path = path.into();
        let file = Self::open_live(&path)?;
        Ok(AuditWriter {
            file,
            path,
            rotate_bytes: AUDIT_ROTATE_BYTES,
        })
    }

    /// Open/create the live file (append mode, `0640` asserted).
    fn open_live(path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o640);
        }
        let file = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o640))?;
        }
        Ok(file)
    }

    /// The path this writer appends to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The `<name>.1` path the live file rotates to.
    fn rotated_path(&self) -> PathBuf {
        let mut os = self.path.clone().into_os_string();
        os.push(".1");
        PathBuf::from(os)
    }

    /// The ipc.md §6 size-capped rotation, checked at write time: once the
    /// live file has reached the threshold, rename it to `<name>.1`
    /// (replacing any previous rotated file — one is kept, older history
    /// is discarded) and start a fresh live file. The event that triggered
    /// the check lands in the fresh file, so no single write is split
    /// across files.
    fn rotate_if_needed(&mut self) -> io::Result<()> {
        if self.file.metadata()?.len() < self.rotate_bytes {
            return Ok(());
        }
        std::fs::rename(&self.path, self.rotated_path())?;
        self.file = Self::open_live(&self.path)?;
        Ok(())
    }

    /// Validate, serialize, rotate if the live file is at the size cap,
    /// append as one line, and fdatasync. Nothing is written for
    /// schema-invalid events.
    pub fn append(&mut self, event: &AuditEvent) -> Result<(), AuditError> {
        validate_event_schema(event).map_err(AuditError::Schema)?;
        let mut line = serde_json::to_string(event)?;
        // serde_json escapes control characters inside strings, so a
        // serialized event can never contain a raw newline; the framing
        // below is therefore always one event per line.
        debug_assert!(!line.contains('\n'));
        line.push('\n');
        self.rotate_if_needed()?;
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()?;
        Ok(())
    }
}

/// Result of [`tail`]: the last events (oldest first, newest **last**, the
/// `audit.tail` wire order) plus how many trailing lines failed to parse.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuditTail {
    pub events: Vec<AuditEvent>,
    /// Lines inside the tail window that were not valid `AuditEvent` JSON
    /// (e.g. a torn write from a crash). They are skipped, not fatal —
    /// but counted, so callers can surface the corruption instead of
    /// silently hiding it.
    pub malformed_lines: usize,
}

/// Read the last `n` events from a JSONL audit log. A missing file is an
/// empty tail (the daemon creates the log at startup; before that there is
/// legitimately nothing to read). Reads the file sequentially, retaining at
/// most `n` lines in memory.
pub fn tail(path: impl AsRef<Path>, n: usize) -> io::Result<AuditTail> {
    let file = match File::open(path.as_ref()) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(AuditTail::default()),
        Err(err) => return Err(err),
    };
    let mut window: VecDeque<String> = VecDeque::with_capacity(n.min(AUDIT_TAIL_WINDOW_CAP));
    if n > 0 {
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            if window.len() == n {
                window.pop_front();
            }
            window.push_back(line);
        }
    }
    let mut result = AuditTail::default();
    for line in window {
        match serde_json::from_str::<AuditEvent>(&line) {
            Ok(event) => result.events.push(event),
            Err(_) => result.malformed_lines += 1,
        }
    }
    Ok(result)
}

/// Pre-allocation cap for the tail window (callers clamp `n` to the wire
/// maximum anyway; this only bounds the initial allocation).
const AUDIT_TAIL_WINDOW_CAP: usize = crate::ipc::AUDIT_TAIL_MAX as usize;

/// Count events (non-empty lines) in a JSONL audit log; a missing file is 0
/// (feeds `status.audit.events`).
pub fn count_events(path: impl AsRef<Path>) -> io::Result<u64> {
    let file = match File::open(path.as_ref()) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    let mut count = 0;
    for line in BufReader::new(file).lines() {
        if !line?.is_empty() {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Redacted;
    use serde_json::Value;

    // -- M0 contract tests (kept) -------------------------------------------

    fn spec_example() -> AuditEvent {
        AuditEvent {
            event_id: "evt_123".to_string(),
            timestamp: "2026-08-24T12:00:00Z".to_string(),
            device_id: "dev_123".to_string(),
            user_id: Some("alice@acme.com".to_string()),
            agent_session_id: Some("agt_123".to_string()),
            project_id: Some("atlas".to_string()),
            source: PrincipalKind::AiAgent,
            action: "credential.request".to_string(),
            resource: Some("aws-dev".to_string()),
            decision: Decision::Allow,
            policy_ids: vec!["eng-ai-v3".to_string()],
            result: "success".to_string(),
        }
    }

    #[test]
    fn serde_round_trips() {
        let event = spec_example();
        let json = serde_json::to_string(&event).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn deserializes_the_spec_section_53_example() {
        let json = r#"{
            "event_id": "evt_123",
            "timestamp": "2026-08-24T12:00:00Z",
            "device_id": "dev_123",
            "user_id": "alice@acme.com",
            "agent_session_id": "agt_123",
            "project_id": "atlas",
            "source": "ai_agent",
            "action": "credential.request",
            "resource": "aws-dev",
            "decision": "allow",
            "policy_ids": ["eng-ai-v3"],
            "result": "success"
        }"#;
        let event: AuditEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event, spec_example());
    }

    #[test]
    fn optional_fields_may_be_absent() {
        let json = r#"{
            "event_id": "evt_9",
            "timestamp": "2026-08-24T12:00:00Z",
            "device_id": "dev_123",
            "source": "service",
            "action": "reconcile.run",
            "decision": "allow",
            "result": "success"
        }"#;
        let event: AuditEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.user_id, None);
        assert_eq!(event.agent_session_id, None);
        assert_eq!(event.project_id, None);
        assert_eq!(event.resource, None);
        assert!(event.policy_ids.is_empty());

        let back: AuditEvent =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn serialized_field_names_match_the_spec() {
        let value = serde_json::to_value(spec_example()).unwrap();
        let object = value.as_object().unwrap();
        for field in [
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
            assert!(object.contains_key(field), "missing field {field:?}");
        }
        assert_eq!(object["source"], "ai_agent");
        assert_eq!(object["decision"], "allow");
    }

    // -- M3: builders vs the shipped schema ---------------------------------

    const AUDIT_SCHEMA: &str = include_str!("../../../schemas/audit/audit-event.json");
    const COMMON_DEFS: &str = include_str!("../../../schemas/common/defs.json");

    const DEVICE_ID: &str = "dev_9f3k2v8q1x";

    fn golden_set_event() -> AuditEvent {
        AuditEvent::capabilities_set(
            DEVICE_ID,
            &AuditActor::cli_peer("root"),
            &CapabilityId::new("system.hostname").unwrap(),
            Decision::Allow,
            AuditOutcome::Success,
        )
    }

    #[test]
    fn golden_builder_event_matches_the_schema_shape() {
        let schema: Value = serde_json::from_str(AUDIT_SCHEMA).unwrap();
        let defs: Value = serde_json::from_str(COMMON_DEFS).unwrap();
        let event = golden_set_event();
        assert_eq!(validate_event_schema(&event), Ok(()));

        let value = serde_json::to_value(&event).unwrap();
        let object = value.as_object().unwrap();

        // All 12 schema-required fields present, and nothing else
        // (additionalProperties: false).
        let required: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(required.len(), 12, "schema drift: required set changed");
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        for field in &required {
            assert!(
                object.contains_key(*field),
                "missing required field {field:?}"
            );
        }
        assert_eq!(object.len(), required.len(), "extra fields: {object:?}");

        // Enum-bound fields hold values from the shipped defs enums.
        let decisions = defs["$defs"]["decision"]["enum"].as_array().unwrap();
        assert!(decisions.contains(&object["decision"]));
        let principal_kinds = defs["$defs"]["principal_kind"]["enum"].as_array().unwrap();
        assert!(principal_kinds.contains(&object["source"]));

        // Field-level content rules.
        assert_eq!(object["action"], "capabilities.set");
        assert_eq!(object["resource"], "system.hostname");
        assert_eq!(object["user_id"], "root");
        assert_eq!(object["agent_session_id"], AGENT_SESSION_NONE);
        assert_eq!(object["project_id"], PROJECT_ID_SYSTEM);
        assert_eq!(
            object["policy_ids"],
            serde_json::json!([POLICY_PERSONAL_DEFAULTS])
        );
        assert_eq!(object["result"], "success");
        assert!(object["event_id"].as_str().unwrap().starts_with("evt_"));
        assert_eq!(object["device_id"], DEVICE_ID);
        assert!(crate::time::is_rfc3339_timestamp(
            object["timestamp"].as_str().unwrap()
        ));
    }

    #[test]
    fn denial_builder_produces_the_deny_shape() {
        let event = AuditEvent::denial(
            DEVICE_ID,
            &AuditActor::cli_peer("punar"),
            "capabilities.set",
            "system.hostname",
        );
        assert_eq!(validate_event_schema(&event), Ok(()));
        assert_eq!(event.decision, Decision::Deny);
        assert_eq!(event.result, "denied");
        assert_eq!(event.user_id.as_deref(), Some("punar"));
        assert_eq!(event.source, PrincipalKind::Human);
        assert_eq!(event.policy_ids, vec![POLICY_PERSONAL_DEFAULTS.to_string()]);
    }

    #[test]
    fn reconcile_builder_targets_the_registry() {
        let event = AuditEvent::reconcile(
            DEVICE_ID,
            &AuditActor::daemon(),
            AuditOutcome::DriftDetected,
        );
        assert_eq!(validate_event_schema(&event), Ok(()));
        assert_eq!(event.action, "reconcile");
        assert_eq!(
            event.resource.as_deref(),
            Some(RESOURCE_CAPABILITY_REGISTRY)
        );
        assert_eq!(event.decision, Decision::Allow);
        assert_eq!(event.result, "drift_detected");
        assert_eq!(event.user_id.as_deref(), Some(USER_ID_DAEMON));
    }

    #[test]
    fn daemon_actor_source_is_schema_valid() {
        // The plan's "os" attribution is not a principal_kind; the daemon
        // actor must serialize to a value the shipped schema accepts.
        let defs: Value = serde_json::from_str(COMMON_DEFS).unwrap();
        let kinds = defs["$defs"]["principal_kind"]["enum"].as_array().unwrap();
        let source = serde_json::to_value(AuditActor::daemon().source).unwrap();
        assert!(kinds.contains(&source), "{source} not in principal_kind");
        assert!(
            !kinds.contains(&Value::String("os".into())),
            "if the schema ever grows an \"os\" principal kind, revisit \
             AuditActor::daemon (module docs)"
        );
    }

    #[test]
    fn uid_fallback_actor_formats_as_documented() {
        let actor = AuditActor::cli_peer_uid(1001);
        assert_eq!(actor.user_id, "uid:1001");
        assert_eq!(actor.source, PrincipalKind::Human);
    }

    #[test]
    fn outcome_vocabulary_is_the_contract_set() {
        let expected = [
            "success",
            "noop",
            "denied",
            "failure",
            "verify_failed",
            "drift_detected",
            "clean",
        ];
        assert_eq!(AuditOutcome::ALL.len(), expected.len());
        for (outcome, name) in AuditOutcome::ALL.into_iter().zip(expected) {
            assert_eq!(outcome.as_str(), name);
        }
    }

    #[test]
    fn event_ids_are_pattern_valid_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let id = next_event_id();
            assert!(prefixed_id_ok(&id, "evt_"), "{id}");
            assert!(seen.insert(id), "duplicate event id");
        }
    }

    // -- validation ---------------------------------------------------------

    #[test]
    fn validation_rejects_missing_and_malformed_fields() {
        let mut event = golden_set_event();
        event.user_id = None;
        event.agent_session_id = Some("session-1".to_string()); // wrong prefix
        event.project_id = None;
        event.timestamp = "yesterday".to_string();
        event.event_id = "123".to_string();
        event.action = "Capabilities.Set".to_string();
        event.result = String::new();
        let violations = validate_event_schema(&event).unwrap_err();
        for needle in [
            "user_id",
            "agent_session_id",
            "project_id",
            "timestamp",
            "event_id",
            "action",
            "result",
        ] {
            assert!(
                violations.iter().any(|v| v.contains(needle)),
                "no violation mentions {needle}: {violations:?}"
            );
        }
    }

    // -- writer + tail ------------------------------------------------------

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_log_path(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "punar-common-audit-{tag}-{}-{}.jsonl",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn writer_appends_parseable_schema_complete_lines() {
        let path = temp_log_path("append");
        {
            let mut writer = AuditWriter::open(&path).unwrap();
            assert_eq!(writer.path(), path.as_path());
            writer.append(&golden_set_event()).unwrap();
            writer
                .append(&AuditEvent::denial(
                    DEVICE_ID,
                    &AuditActor::cli_peer("punar"),
                    "capabilities.set",
                    "system.hostname",
                ))
                .unwrap();
        }
        // Re-open appends, never truncates.
        {
            let mut writer = AuditWriter::open(&path).unwrap();
            writer
                .append(&AuditEvent::reconcile(
                    DEVICE_ID,
                    &AuditActor::daemon(),
                    AuditOutcome::Clean,
                ))
                .unwrap();
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(contents.ends_with('\n'));
        for line in &lines {
            let event: AuditEvent = serde_json::from_str(line).unwrap();
            assert_eq!(validate_event_schema(&event), Ok(()));
        }
        assert_eq!(count_events(&path).unwrap(), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn writer_enforces_0640() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_log_path("perms");
        let _writer = AuditWriter::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "created mode {mode:o}");

        // Pre-existing looser file gets tightened on open.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let _writer = AuditWriter::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "re-opened mode {mode:o}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn writer_refuses_schema_invalid_events() {
        let path = temp_log_path("refuse");
        let mut writer = AuditWriter::open(&path).unwrap();
        let mut event = golden_set_event();
        event.user_id = None;
        match writer.append(&event) {
            Err(AuditError::Schema(violations)) => {
                assert!(violations.iter().any(|v| v.contains("user_id")));
            }
            other => panic!("expected schema refusal, got {other:?}"),
        }
        assert_eq!(count_events(&path).unwrap(), 0, "nothing may be written");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tail_returns_newest_last_with_limits() {
        let path = temp_log_path("tail");
        let mut writer = AuditWriter::open(&path).unwrap();
        for index in 0..5 {
            let mut event = golden_set_event();
            event.result = format!("success{index}");
            writer.append(&event).unwrap();
        }
        let tail3 = tail(&path, 3).unwrap();
        assert_eq!(tail3.malformed_lines, 0);
        let results: Vec<&str> = tail3.events.iter().map(|e| e.result.as_str()).collect();
        assert_eq!(results, ["success2", "success3", "success4"]);

        assert_eq!(tail(&path, 100).unwrap().events.len(), 5);
        assert_eq!(tail(&path, 0).unwrap().events.len(), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tail_skips_and_counts_torn_lines() {
        let path = temp_log_path("torn");
        let mut writer = AuditWriter::open(&path).unwrap();
        writer.append(&golden_set_event()).unwrap();
        // Simulate a torn write (crash mid-line) directly in the file.
        {
            use std::io::Write as _;
            let mut raw = OpenOptions::new().append(true).open(&path).unwrap();
            raw.write_all(b"{\"event_id\":\"evt_torn\",\"time\n")
                .unwrap();
        }
        let mut writer = AuditWriter::open(&path).unwrap();
        writer.append(&golden_set_event()).unwrap();

        let result = tail(&path, 10).unwrap();
        assert_eq!(result.events.len(), 2);
        assert_eq!(result.malformed_lines, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tail_of_missing_file_is_empty() {
        let path = temp_log_path("missing");
        assert_eq!(tail(&path, 20).unwrap(), AuditTail::default());
        assert_eq!(count_events(&path).unwrap(), 0);
    }

    // -- rotation (ipc.md §6, delivered in M5) ------------------------------

    #[test]
    fn writer_rotates_at_the_threshold_keeping_one_file() {
        let path = temp_log_path("rotate");
        let rotated = {
            let mut os = path.clone().into_os_string();
            os.push(".1");
            PathBuf::from(os)
        };
        let _ = std::fs::remove_file(&rotated);

        let mut writer = AuditWriter::open(&path).unwrap();
        // Shrink the threshold so the test rotates without writing 8 MiB;
        // production keeps AUDIT_ROTATE_BYTES.
        writer.rotate_bytes = 600;
        let line_len = {
            let mut probe = serde_json::to_string(&golden_set_event()).unwrap();
            probe.push('\n');
            probe.len() as u64
        };
        // Fill past the threshold, then one more append triggers rotation.
        let mut appended = 0u64;
        while appended * line_len < 600 {
            writer.append(&golden_set_event()).unwrap();
            appended += 1;
        }
        writer.append(&golden_set_event()).unwrap();

        // Exactly one rotated file; the live file holds only the
        // triggering event (no write is split across files) and both
        // files together hold every event.
        assert!(rotated.exists(), "rotated file missing");
        assert_eq!(count_events(&path).unwrap(), 1, "fresh live file");
        assert_eq!(count_events(&rotated).unwrap(), appended);
        for file in [&path, &rotated] {
            for line in std::fs::read_to_string(file).unwrap().lines() {
                let event: AuditEvent = serde_json::from_str(line).unwrap();
                assert_eq!(validate_event_schema(&event), Ok(()));
            }
        }

        // A second rotation replaces the rotated file (one kept, older
        // discarded) rather than accumulating .2/.3/...
        let first_rotation_count = appended;
        let mut appended = 1u64; // the triggering event already in the live file
        while appended * line_len < 600 {
            writer.append(&golden_set_event()).unwrap();
            appended += 1;
        }
        writer.append(&golden_set_event()).unwrap();
        assert_eq!(count_events(&path).unwrap(), 1);
        assert_eq!(count_events(&rotated).unwrap(), appended);
        assert_ne!(
            count_events(&rotated).unwrap(),
            first_rotation_count + appended,
            "older history must be discarded, not accumulated"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&rotated);
    }

    #[test]
    fn writer_never_rotates_below_the_threshold() {
        let path = temp_log_path("norotate");
        let rotated = {
            let mut os = path.clone().into_os_string();
            os.push(".1");
            PathBuf::from(os)
        };
        let _ = std::fs::remove_file(&rotated);
        let mut writer = AuditWriter::open(&path).unwrap();
        for _ in 0..5 {
            writer.append(&golden_set_event()).unwrap();
        }
        assert!(
            !rotated.exists(),
            "rotation must not fire below AUDIT_ROTATE_BYTES"
        );
        assert_eq!(count_events(&path).unwrap(), 5);
        let _ = std::fs::remove_file(&path);
    }

    // -- redaction (SPEC sections 1.19, 53) ---------------------------------

    #[test]
    fn redacted_values_cannot_reach_the_audit_file() {
        const SECRET: &str = "tok-hunter2-XYZZY-do-not-log";
        let secret = Redacted::new(SECRET.to_string());

        // The only ways a Redacted value can flow into an AuditEvent's
        // String fields are Display/Debug/Serialize — all of which emit
        // the placeholder. (Reaching the real value takes an explicit,
        // greppable expose_secret()/into_inner() call.)
        let mut event = golden_set_event();
        event.resource = Some(format!("credential:{secret}"));
        event.result = format!("{secret:?}");

        let path = temp_log_path("redaction");
        let mut writer = AuditWriter::open(&path).unwrap();
        writer.append(&event).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(!contents.contains(SECRET), "secret leaked: {contents}");
        assert!(contents.contains(crate::REDACTED_PLACEHOLDER));

        // Serialization of a Redacted embedded in any future detail struct
        // also emits only the placeholder.
        #[derive(Serialize)]
        struct FutureSecretDetail {
            token: Redacted<String>,
        }
        let json = serde_json::to_string(&FutureSecretDetail {
            token: Redacted::new(SECRET.to_string()),
        })
        .unwrap();
        assert!(!json.contains(SECRET));
        assert_eq!(json, r#"{"token":"[redacted]"}"#);
        let _ = std::fs::remove_file(&path);
    }
}
