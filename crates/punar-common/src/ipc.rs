//! Typed local IPC contract shared by `punard` (server) and `punarctl`
//! (client).
//!
//! The binding wire contract is `docs/api/ipc.md` (NDJSON over a Unix domain
//! socket at [`SOCKET_PATH`]); this module is its typed Rust form. Spec
//! authorities: section 10 (typed capability API only), section 60 (hard
//! safety constraints), section 61 (local IPC security), section 73 (error
//! message voice).
//!
//! # Section 60 guarantee: no generic execution, by construction
//!
//! [`Method`] is a **closed** enum: the six Milestone 3 methods and nothing
//! else. There is no variant that carries a command line, a shell string, a
//! script, or an arbitrary program to run — and none will ever be added
//! (SPEC section 10 "Prohibited: RunRootShell(command)"; section 60). The
//! compile-time shape of the guarantee:
//!
//! - `Method` is not `#[non_exhaustive]`, and [`Method::name`] is an
//!   exhaustive `match` with no wildcard arm: adding a variant fails to
//!   compile until every dispatch table in this crate names it, which is the
//!   review point.
//! - Every payload a variant carries is a typed params struct whose fields
//!   are validated identifiers ([`crate::CapabilityId`]) or bounded data
//!   values — state values are *matched against a capability's declared
//!   state space* by the daemon, never interpreted as text to execute.
//! - Requests whose `method` string is not in the table (e.g. the section
//!   74.4 probes `system.exec`, `shell.run`) parse to
//!   [`ErrorCode::UnknownMethod`], not to any dispatchable value.
//!
//! # Layering
//!
//! - [`RequestEnvelope`] / [`ResponseEnvelope`]-backed [`Response`] are the
//!   raw wire frames. `punarctl debug rpc` (the 74.4 negative-test probe)
//!   sends a raw [`RequestEnvelope`] with an arbitrary method name; the
//!   server never dispatches on the raw form.
//! - [`Request`] + [`Method`] are the typed layer the server dispatches on,
//!   produced by [`Request::parse_json_line`], which maps each failure mode
//!   to the wire error codes in the order the contract requires
//!   (malformed → version → id → method → params).
//! - Result payloads travel as [`serde_json::Value`] in the envelope (the
//!   shape depends on the request method, and `punarctl --json` prints the
//!   `result` object verbatim); the typed result structs
//!   ([`StatusResult`], …) serialize into / deserialize from that value.
//!   Result structs deliberately do **not** `deny_unknown_fields`: clients
//!   must tolerate unknown result fields (contract section 3.3). Request
//!   params structs **do** deny unknown fields (strict, contract section
//!   3.1).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::approval::{
    ApprovalEnvelope, ApprovalKind, ApprovalRequest, ApprovalStatus, Grant, PolicyCitation,
    Requester, RequesterPeer,
};
use crate::audit::POLICY_PERSONAL_DEFAULTS;
use crate::{AuditEvent, CapabilityDescriptor, CapabilityId, Risk};

// ---------------------------------------------------------------------------
// Contract constants (docs/api/ipc.md sections 1–2)
// ---------------------------------------------------------------------------

/// The one supported protocol version. `v` in every envelope must equal it.
pub const PROTOCOL_VERSION: u64 = 1;

/// Daemon control socket path. Deliberately under `/run/punard` (root-owned
/// `0750 root:punar`), **not** `/run/punar` (the M1 punar-writable artifact
/// dir, where the socket could be unlinked and squatted by the unprivileged
/// user) — docs/api/ipc.md section 1.1.
pub const SOCKET_PATH: &str = "/run/punard/punard.sock";

/// Maximum bytes in one request line, excluding the terminating `\n`.
/// Longer lines are `malformed_request` and the connection closes. The
/// server must also enforce this while reading (a line whose newline never
/// arrives must not buffer unboundedly).
pub const MAX_REQUEST_LINE_BYTES: usize = 4096;

/// Envelope `id`: minimum length in characters.
pub const REQUEST_ID_MIN_CHARS: usize = 1;
/// Envelope `id`: maximum length in characters.
pub const REQUEST_ID_MAX_CHARS: usize = 64;

/// `audit.tail` default event count when `n` is omitted.
pub const AUDIT_TAIL_DEFAULT: u64 = 20;
/// `audit.tail` maximum event count; larger requests are clamped, not
/// rejected.
pub const AUDIT_TAIL_MAX: u64 = 1000;

/// Server: per-connection read-idle timeout.
pub const SERVER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Server: per-request processing timeout.
pub const SERVER_PROCESS_TIMEOUT: Duration = Duration::from_secs(10);
/// Server: response write timeout.
pub const SERVER_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Client (`punarctl`): connect timeout.
pub const CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Client (`punarctl`): whole-response timeout.
pub const CLIENT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);
/// M5 (contract sections 2, 5.9): raised per-request processing bound for
/// `enroll.start` — the pipeline contains a full reconcile pass and, on
/// TCG, nft operations are slow.
pub const ENROLL_START_PROCESS_TIMEOUT: Duration = Duration::from_secs(60);
/// M5 (contract sections 2, 7): raised client response timeout for
/// `punarctl enroll start` only, covering [`ENROLL_START_PROCESS_TIMEOUT`]
/// with margin.
pub const ENROLL_START_CLIENT_TIMEOUT: Duration = Duration::from_secs(90);

/// `punarctl` process exit codes (Plate D-014 section III; docs/api/ipc.md
/// section 7).
pub const EXIT_OK: i32 = 0;
/// Runtime/daemon error (every wire error except `denied`).
pub const EXIT_ERROR: i32 = 1;
/// Usage error (clap).
pub const EXIT_USAGE: i32 = 2;
/// Authorization denied (`denied` wire error).
pub const EXIT_DENIED: i32 = 3;
/// The call was gated: an approval was created and **nothing executed**
/// (`approval_required` wire error). Reserved since M3, real since M9.
pub const EXIT_APPROVAL_REQUIRED: i32 = 4;
/// The daemon could not be reached (connect/timeout — a transport failure,
/// so it never appears as a wire error code).
pub const EXIT_DAEMON_UNREACHABLE: i32 = 5;

// ---------------------------------------------------------------------------
// Error codes and the wire error object (contract section 4)
// ---------------------------------------------------------------------------

/// The closed set of wire error codes (docs/api/ipc.md section 4).
///
/// Mapping from the concept names used elsewhere in Punar planning to the
/// wire codes: *permission denied* → [`Denied`](ErrorCode::Denied) ·
/// *unknown capability* → [`NotFound`](ErrorCode::NotFound) · *invalid
/// state value* → [`InvalidParams`](ErrorCode::InvalidParams).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Line not valid JSON / envelope fields missing or mistyped / line over
    /// [`MAX_REQUEST_LINE_BYTES`]. The connection closes after the response.
    MalformedRequest,
    /// `v` != [`PROTOCOL_VERSION`]. `details.supported` lists `[1]`.
    UnsupportedVersion,
    /// Method not in the [`Method`] table — the permanent answer to
    /// `system.exec`, `shell.run`, and every other generic-execution probe
    /// (SPEC sections 10, 60).
    UnknownMethod,
    /// Params missing/extra/mis-shaped, unknown state value, invalid
    /// hostname/timezone syntax.
    InvalidParams,
    /// Authorization denied (M3: mutating method from a non-root peer).
    /// Always audited with `decision: "deny"`.
    Denied,
    /// `capabilities.get`/`set` on an id not in the registry.
    NotFound,
    /// Backend apply step failed. Audited with `result: "failure"`.
    ApplyFailed,
    /// Apply succeeded but re-observation did not match the desired state.
    /// Audited with `result: "verify_failed"`.
    VerifyFailed,
    /// Daemon bug or I/O error. Never carries secrets ([`crate::Redacted`]
    /// by construction for any future secret-bearing type).
    Internal,
    /// M5 (contract section 4): the request contradicts current enrollment
    /// state — `enroll.start` while already enrolled, `enroll.stop` while
    /// not enrolled. `details.state` names the current state.
    Conflict,
    /// M5 (contract section 4): the control plane did not answer during
    /// `enroll.start` (connect/call failure or timeout). Local state is
    /// untouched — enrollment is all-or-nothing. Sync failures outside
    /// `enroll.start` never surface as request errors; they queue per SPEC
    /// section 55. `details.stage` names the failing pipeline stage.
    UpstreamUnreachable,
    /// M9 (contract section 14.1): the call is **gated**. An approval was
    /// created and **nothing was executed** — this is a refusal to act, not
    /// a queued action. `details` carries `approval_id`, `expires_at`,
    /// `capability`, `resource`, `decision` (always `"approval_required"`)
    /// and `policy_ids`. Maps to [`EXIT_APPROVAL_REQUIRED`], reserved for
    /// exactly this since M3.
    ApprovalRequired,
    /// M9 (contract section 14.1): the approval passed `expires_at`, or a
    /// presented credential's TTL lapsed. Deliberately distinct from
    /// [`Conflict`](ErrorCode::Conflict), which means *already resolved*:
    /// "you were too late" and "someone already answered" are different
    /// facts and a human deserves to be told which one happened.
    Expired,
}

impl ErrorCode {
    /// All wire codes, in contract-table order.
    pub const ALL: [ErrorCode; 13] = [
        ErrorCode::MalformedRequest,
        ErrorCode::UnsupportedVersion,
        ErrorCode::UnknownMethod,
        ErrorCode::InvalidParams,
        ErrorCode::Denied,
        ErrorCode::NotFound,
        ErrorCode::ApplyFailed,
        ErrorCode::VerifyFailed,
        ErrorCode::Internal,
        ErrorCode::Conflict,
        ErrorCode::UpstreamUnreachable,
        ErrorCode::ApprovalRequired,
        ErrorCode::Expired,
    ];

    /// The wire spelling (snake_case).
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::MalformedRequest => "malformed_request",
            ErrorCode::UnsupportedVersion => "unsupported_version",
            ErrorCode::UnknownMethod => "unknown_method",
            ErrorCode::InvalidParams => "invalid_params",
            ErrorCode::Denied => "denied",
            ErrorCode::NotFound => "not_found",
            ErrorCode::ApplyFailed => "apply_failed",
            ErrorCode::VerifyFailed => "verify_failed",
            ErrorCode::Internal => "internal",
            ErrorCode::Conflict => "conflict",
            ErrorCode::UpstreamUnreachable => "upstream_unreachable",
            ErrorCode::ApprovalRequired => "approval_required",
            ErrorCode::Expired => "expired",
        }
    }

    /// Whether the server closes the connection after responding with this
    /// code (contract section 2: only framing violations do).
    pub fn closes_connection(self) -> bool {
        self == ErrorCode::MalformedRequest
    }

    /// The `punarctl` exit code this error maps to (Plate D-014 section
    /// III): [`EXIT_DENIED`] for `denied`, [`EXIT_APPROVAL_REQUIRED`] for
    /// `approval_required` — **real as of Milestone 9**, after being
    /// reserved for it since M3 — and [`EXIT_ERROR`] otherwise.
    /// [`EXIT_USAGE`] and [`EXIT_DAEMON_UNREACHABLE`] arise client-side and
    /// never from a wire error.
    pub fn suggested_exit_code(self) -> i32 {
        match self {
            ErrorCode::Denied => EXIT_DENIED,
            ErrorCode::ApprovalRequired => EXIT_APPROVAL_REQUIRED,
            _ => EXIT_ERROR,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The structured `error` object of a response (contract section 3.2).
///
/// `message` is human prose in the SPEC section 73 voice — what happened,
/// why, which policy, what the next step is; never a bare errno. `details`
/// is the optional machine layer (fields documented per code in the
/// contract's section 4 table).
///
/// Lenient on deserialize (no `deny_unknown_fields`): errors travel
/// server→client, where unknown fields must be tolerated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Error)]
#[error("{code}: {message}")]
pub struct IpcError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl IpcError {
    /// An error with no machine details.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        IpcError {
            code,
            message: message.into(),
            details: None,
        }
    }

    /// An error with a machine-readable `details` object.
    pub fn with_details(code: ErrorCode, message: impl Into<String>, details: Value) -> Self {
        IpcError {
            code,
            message: message.into(),
            details: Some(details),
        }
    }

    /// The canonical root-only denial (contract section 3.2 example; SPEC
    /// section 73 voice). `target` names what was refused (usually a
    /// capability id), `retry_command` is the full command to re-run as
    /// root. When `capability` is given it is included in
    /// `details.capability`.
    ///
    /// The message deliberately contains both "administrator" and "personal
    /// defaults" — the section 74.4 in-VM check greps for exactly those.
    ///
    /// **M9 amendment.** Since M3 this message has promised that
    /// "just-in-time elevation arrives in Milestone 9". It has arrived, so
    /// the message now names the command that exists — but only when the
    /// refusal is about a **capability**, because a grant is per-capability
    /// (SPEC section 48: no wildcard elevation). `reconcile` and the
    /// enrollment mutations have no grant to ask for and keep pointing at
    /// root, which is the honest answer for them.
    pub fn denied_needs_root(target: &str, capability: Option<&str>, retry_command: &str) -> Self {
        let mut details = json!({
            "decision": "deny",
            "policy_ids": [POLICY_PERSONAL_DEFAULTS],
        });
        if let (Some(map), Some(capability)) = (details.as_object_mut(), capability) {
            map.insert("capability".to_string(), Value::String(capability.into()));
        }
        let next = match capability {
            Some(capability) => format!(
                "Next step: re-run as root: {retry_command}\n\
                 Or ask for time-boxed privilege: \
                 punarctl privilege request --capability {capability} --reason \"<why>\""
            ),
            None => format!("Next step: re-run as root: {retry_command}"),
        };
        IpcError::with_details(
            ErrorCode::Denied,
            format!(
                "Changing {target} needs administrator privileges.\n\
                 Policy: personal defaults — an ordinary user may hold privilege for a \
                 bounded window, never permanently (SPEC section 48).\n\
                 {next}"
            ),
            details,
        )
    }

    /// The M9 gate (contract section 14.1). The call did **not** execute;
    /// an approval was created and a human has to answer it.
    ///
    /// The message is deliberately four beats in the SPEC section 73 voice —
    /// what happened, who asked, which policy said so, what to do next — and
    /// it names a next step that exists (`punarctl approvals wait`), because
    /// a gate that leaves the caller with nowhere to go is just a denial
    /// with extra words.
    pub fn approval_required(
        approval_id: &str,
        capability: &str,
        resource: &str,
        expires_at: &str,
        policy_name: &str,
        policy_id: &str,
    ) -> Self {
        IpcError::with_details(
            ErrorCode::ApprovalRequired,
            format!(
                "Changing {capability} to {resource} needs a person to approve it.\n\
                 Nothing has been changed: the request is waiting as {approval_id} \
                 and expires at {expires_at}.\n\
                 Policy: {policy_name} ({policy_id}) — AI agents may request this \
                 capability, and a human answers.\n\
                 Next step: answer it in the approval overlay, or run \
                 `punarctl approvals wait {approval_id}`."
            ),
            json!({
                "approval_id": approval_id,
                "expires_at": expires_at,
                "capability": capability,
                "resource": resource,
                "decision": "approval_required",
                "policy_ids": [policy_id],
            }),
        )
    }

    /// The M9 `expired` error (contract section 14.1): the approval lapsed
    /// before anyone answered, or an approved credential approval was
    /// presented after its expiry. **A yes is not a standing grant.**
    pub fn expired(approval_id: &str, expires_at: &str) -> Self {
        IpcError::with_details(
            ErrorCode::Expired,
            format!(
                "{approval_id} expired at {expires_at} and can no longer be used.\n\
                 Policy: personal defaults — an approval is answerable for a bounded \
                 window, so an unattended device cannot accumulate live authorizations.\n\
                 Next step: make the request again to raise a fresh approval."
            ),
            json!({ "approval_id": approval_id, "expires_at": expires_at }),
        )
    }

    /// The M5 denial for a non-root `capabilities.set` on an **org-pinned**
    /// path (contract section 5.4): the root-only rule still refuses before
    /// policy is consulted, but the citation names the pinning org source —
    /// the M3 "personal defaults" text would be a false citation on a
    /// managed path. Section 73 voice; exit code stays 3.
    pub fn denied_org_pinned(capability: &str, source_name: &str, policy_id: &str) -> Self {
        IpcError::with_details(
            ErrorCode::Denied,
            format!(
                "{capability} is managed by {source_name} ({policy_id}).\n\
                 User override: not permitted.\n\
                 Next step: ask {source_name} for an exception — a local approval \
                 cannot outrank an organization policy, and Punar will not pretend \
                 otherwise."
            ),
            json!({
                "decision": "deny",
                "policy_ids": [policy_id],
                "capability": capability,
            }),
        )
    }
}

// ---------------------------------------------------------------------------
// Request envelope (raw wire frame, contract section 3.1)
// ---------------------------------------------------------------------------

/// The raw request frame: `{"v":1,"id":"…","method":"…","params":{…}}`.
///
/// Strict (`deny_unknown_fields`): forward compatibility is carried by `v`,
/// not by ignoring fields (contract section 3.1). The server parses this and
/// immediately lifts it into the typed [`Request`]; it never dispatches on
/// the raw method string. Clients normally build [`Request`]s — the raw
/// envelope's client-side use is `punarctl debug rpc`, the hidden probe that
/// sends arbitrary method names so the section 74.4 tests can watch the
/// server answer [`ErrorCode::UnknownMethod`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    /// Protocol version; must be [`PROTOCOL_VERSION`].
    pub v: u64,
    /// Client-chosen correlation id, 1–64 characters, echoed verbatim.
    pub id: String,
    /// Dotted lowercase method name.
    pub method: String,
    /// Method-specific params; omitted when the method takes none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl RequestEnvelope {
    /// Serialize as one NDJSON line, including the terminating `\n`.
    pub fn to_json_line(&self) -> String {
        let mut line = serde_json::to_string(self)
            .expect("RequestEnvelope serialization is infallible (string/number/value fields)");
        line.push('\n');
        line
    }
}

// ---------------------------------------------------------------------------
// Method params (typed, strict — contract section 5)
// ---------------------------------------------------------------------------

/// Params for `capabilities.get`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesGetParams {
    /// The capability to describe. Typed [`CapabilityId`], so a
    /// syntactically invalid id already fails params parsing
    /// (`invalid_params`); an id that is valid but not in the registry is
    /// the server's `not_found`.
    pub capability: CapabilityId,
}

/// Params for `capabilities.set`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesSetParams {
    /// The capability to mutate.
    pub capability: CapabilityId,
    /// The requested state — **data**, validated by the daemon against the
    /// capability's `allowed_desired_states` / `state_schema` and syntax
    /// rules; never interpreted as a command (SPEC sections 10, 60).
    pub desired_state: Value,
}

/// Params for `audit.tail`. `n` defaults to [`AUDIT_TAIL_DEFAULT`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditTailParams {
    /// Requested event count. Values above [`AUDIT_TAIL_MAX`] are clamped
    /// by [`AuditTailParams::effective_n`], not rejected (contract section
    /// 5.5).
    #[serde(default = "default_audit_tail_n")]
    pub n: u64,
}

fn default_audit_tail_n() -> u64 {
    AUDIT_TAIL_DEFAULT
}

/// Params for `policy.explain` (M4, contract section 5.8). `path` is a
/// capability path from the effective document; a syntactically invalid
/// path already fails params parsing (`invalid_params`), a valid path not
/// in the document is the server's `not_found`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyExplainParams {
    pub path: CapabilityId,
}

/// Params for `enroll.start` (M5, contract section 5.9). The domain is
/// **data** — validated for domain-name syntax by the daemon
/// (`invalid_params` on failure), then handed to the control-plane
/// `org.discover` call; never interpreted as anything executable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollStartParams {
    pub org_domain: String,
}

// -- M9 approval + privilege params (contract section 14) -------------------

/// Params for `approvals.get`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalIdParams {
    pub approval_id: String,
}

/// Params for `approvals.create` (M9, contract section 14.2) — **root
/// only**. In practice there are exactly two callers: punard itself, when
/// AI authority policy gates a `capabilities.set`, and `punar-secrets`,
/// which runs as root and raises a `credential_request` on behalf of the
/// agent that asked for a class.
///
/// An unprivileged peer cannot reach this method, and that is the point: a
/// process that could mint approvals could spam the human until they stop
/// reading them. Approval fatigue is the classic attack on an approval
/// gate, so the first bound on it is the authorization rule and the second
/// is [`crate::approval::MAX_PENDING_APPROVALS`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalsCreateParams {
    pub kind: ApprovalKind,
    /// Registry capability id, or a typed method name (`credential.request`).
    pub capability: String,
    /// The concrete argument: desired state · credential class · grant window.
    pub resource: String,
    /// Requester-authored justification. Validated by the daemon
    /// ([`crate::approval::validate_reason`]) — one printable line.
    pub reason: String,
    pub risk: Risk,
    /// The human the approval is routed to.
    pub user: String,
    pub requester: Requester,
    /// Optional shorter TTL in seconds, clamped to `[15, 300]`. A requester
    /// may ask for less and never for more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    /// Optional Plate D-003 contract line; derived from
    /// `capability`/`resource` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,
    /// The requesting peer's kernel-attested credentials, when the caller
    /// terminated the connection that made the request. `punar-secrets`
    /// fills this in: it read `SO_PEERCRED` and the peer's cgroup itself
    /// (the shared rule in [`crate::principal`]), and punard cannot
    /// re-derive them for a call that arrived at a different socket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_peer: Option<RequesterPeer>,
    /// The policy that made this an approval rather than an allow or a
    /// deny. Supplied by the caller because the caller is the one that
    /// evaluated it — the broker knows whether `aws_dev: request` came from
    /// the personal defaults or from an org baseline, and punard would have
    /// to guess. Defaults to the personal-defaults citation.
    ///
    /// This is caller-supplied data on a **root-only** method, which is the
    /// whole reason it is acceptable: the only callers are punard itself
    /// and a root daemon Punar ships. An unprivileged peer cannot reach
    /// this method at all (section 14.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyCitation>,
    /// The originating typed call, recorded verbatim so a resolver sees the
    /// real request and punard re-derives execution from its own record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<ApprovalRequest>,
}

/// The two answers a human may give (contract section 14.5). Deliberately
/// **not** [`crate::Decision`]: a person answers `approved`/`denied`, which
/// are the shipped `approval.json` status values, while `Decision` is the
/// section 20 policy vocabulary and includes `approval_required` — a value
/// that would be meaningless here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveDecision {
    Approved,
    Denied,
}

impl ResolveDecision {
    /// The resulting terminal status.
    pub fn status(self) -> ApprovalStatus {
        match self {
            ResolveDecision::Approved => ApprovalStatus::Approved,
            ResolveDecision::Denied => ApprovalStatus::Denied,
        }
    }
}

/// Params for `approvals.resolve` (contract section 14.5). **Human only** —
/// enforced in the daemon at the kernel-attested cgroup, never here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalsResolveParams {
    pub approval_id: String,
    pub decision: ResolveDecision,
}

/// Params for `privilege.request` (contract section 14.8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegeRequestParams {
    /// The single capability to elevate. No wildcard exists.
    pub capability: CapabilityId,
    /// **Required.** Plate D-012: the reason travels verbatim into the
    /// audit event, so an empty one is `invalid_params`, not a default.
    pub reason: String,
    /// Grant window in minutes; defaults to
    /// [`crate::approval::GRANT_DEFAULT_MINUTES`], clamped to `[1, 60]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_minutes: Option<u64>,
}

/// Params for `privilege.revoke` (contract section 14.8): exactly one of
/// `grant_id` or `all` — neither or both is `invalid_params`, because
/// "revoke something" must never be guessed at.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegeRevokeParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<bool>,
}

impl PrivilegeRevokeParams {
    /// `Ok(Some(id))` for one grant, `Ok(None)` for all of the caller's.
    pub fn target(&self) -> Result<Option<&str>, &'static str> {
        match (self.grant_id.as_deref(), self.all) {
            (Some(id), None | Some(false)) => Ok(Some(id)),
            (None, Some(true)) => Ok(None),
            (Some(_), Some(true)) => Err("pass either grant_id or all, not both"),
            (None, None | Some(false)) => Err("pass grant_id, or all: true"),
        }
    }
}

impl Default for AuditTailParams {
    fn default() -> Self {
        AuditTailParams {
            n: AUDIT_TAIL_DEFAULT,
        }
    }
}

impl AuditTailParams {
    /// `n` with the [`AUDIT_TAIL_MAX`] clamp applied.
    pub fn effective_n(&self) -> u64 {
        self.n.min(AUDIT_TAIL_MAX)
    }
}

// ---------------------------------------------------------------------------
// The closed method table (contract section 5; SPEC sections 10, 60)
// ---------------------------------------------------------------------------

/// The complete, closed Milestone 3+4 method set.
///
/// See the module docs for the section 60 guarantee. Summary: no variant
/// carries anything executable, the enum is exhaustive-matched (adding a
/// variant is a compile error until every table names it), and unknown
/// method strings never become a `Method`. The M4 additions
/// (`policy.effective`, `policy.explain`) are **read** methods — there is
/// no write-side `policy.*` method (contract section 8): the only policy
/// mutations are `capabilities.set` and, from M5, the enrollment-managed
/// `policy.d` drop.
#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    /// `status` — daemon/device summary. Read; any connected peer.
    Status,
    /// `capabilities.list` — all registry descriptors, observed live. Read.
    CapabilitiesList,
    /// `capabilities.get` — one descriptor. Read.
    CapabilitiesGet(CapabilitiesGetParams),
    /// `capabilities.set` — mutate one capability. Root-only in M3; always
    /// audited. Since M4 the request is recorded as a User Preference layer
    /// entry and the **effective** value is applied (contract section 5.4).
    CapabilitiesSet(CapabilitiesSetParams),
    /// `audit.tail` — last `n` audit events through the daemon. Read.
    AuditTail(AuditTailParams),
    /// `reconcile` — M3 reported drift only; **since M4 it remediates per
    /// policy** (the semantic change M3 pre-announced by making the method
    /// root-only). Root-only; always audited.
    Reconcile,
    /// `policy.effective` (M4) — the merged effective document. Read.
    PolicyEffective,
    /// `policy.explain` (M4) — one effective entry for a path. Read.
    PolicyExplain(PolicyExplainParams),
    /// `enroll.start` (M5, contract section 5.9) — enroll against the
    /// (mock) control plane. Root-only; always audited; all-or-nothing.
    EnrollStart(EnrollStartParams),
    /// `enroll.status` (M5, contract section 5.10) — enrollment state.
    /// Read; never carries the device token.
    EnrollStatus,
    /// `enroll.stop` (M5, contract section 5.11) — local unenroll: remove
    /// the org layers, restore personal state. Root-only; always audited.
    EnrollStop,
    /// `approvals.list` (M9, contract section 14.2) — pending first, then
    /// recently resolved. Read; any connected peer; sweeps expiry lazily.
    ApprovalsList,
    /// `approvals.get` (M9) — one approval envelope. Read.
    ApprovalsGet(ApprovalIdParams),
    /// `approvals.create` (M9) — raise an approval. **Root only**; always
    /// audited. Boxed: this is by far the widest params object in the
    /// table, and every other method would otherwise carry its size.
    ApprovalsCreate(Box<ApprovalsCreateParams>),
    /// `approvals.resolve` (M9, contract section 14.5) — a **human** answers.
    /// May execute the recorded request. Always audited, including the
    /// refusal when the peer turns out to be an AI agent.
    ApprovalsResolve(ApprovalsResolveParams),
    /// `approvals.consume` (M9, contract section 14.7) — spend an approved
    /// `credential_request` exactly once. **Root only** (in practice
    /// `punar-secrets`); always audited.
    ApprovalsConsume(ApprovalIdParams),
    /// `privilege.request` (M9, contract section 14.8) — ask for a
    /// time-boxed grant. Refused outright for agent-attributed peers.
    PrivilegeRequest(PrivilegeRequestParams),
    /// `privilege.status` (M9) — the caller's live grants (every grant for
    /// root). Read; sweeps expiry lazily.
    PrivilegeStatus,
    /// `privilege.revoke` (M9) — hand privilege back before it lapses.
    /// Owner or root; always audited.
    PrivilegeRevoke(PrivilegeRevokeParams),
}

impl Method {
    /// Every wire method name, in contract-table order.
    pub const NAMES: [&'static str; 19] = [
        "status",
        "capabilities.list",
        "capabilities.get",
        "capabilities.set",
        "audit.tail",
        "reconcile",
        "policy.effective",
        "policy.explain",
        "enroll.start",
        "enroll.status",
        "enroll.stop",
        "approvals.list",
        "approvals.get",
        "approvals.create",
        "approvals.resolve",
        "approvals.consume",
        "privilege.request",
        "privilege.status",
        "privilege.revoke",
    ];

    /// The wire method name. Exhaustive match, no wildcard — this is the
    /// compile-time closed table (module docs).
    pub fn name(&self) -> &'static str {
        match self {
            Method::Status => "status",
            Method::CapabilitiesList => "capabilities.list",
            Method::CapabilitiesGet(_) => "capabilities.get",
            Method::CapabilitiesSet(_) => "capabilities.set",
            Method::AuditTail(_) => "audit.tail",
            Method::Reconcile => "reconcile",
            Method::PolicyEffective => "policy.effective",
            Method::PolicyExplain(_) => "policy.explain",
            Method::EnrollStart(_) => "enroll.start",
            Method::EnrollStatus => "enroll.status",
            Method::EnrollStop => "enroll.stop",
            Method::ApprovalsList => "approvals.list",
            Method::ApprovalsGet(_) => "approvals.get",
            Method::ApprovalsCreate(_) => "approvals.create",
            Method::ApprovalsResolve(_) => "approvals.resolve",
            Method::ApprovalsConsume(_) => "approvals.consume",
            Method::PrivilegeRequest(_) => "privilege.request",
            Method::PrivilegeStatus => "privilege.status",
            Method::PrivilegeRevoke(_) => "privilege.revoke",
        }
    }

    /// Whether the built-in authorization rule (`personal-defaults`)
    /// restricts this method to uid 0. Exhaustive on purpose: a new method
    /// must take an explicit authorization stance to compile. The M4
    /// `policy.*` methods are reads, open to any connected peer.
    pub fn requires_root(&self) -> bool {
        match self {
            Method::Status
            | Method::CapabilitiesList
            | Method::CapabilitiesGet(_)
            | Method::AuditTail(_)
            | Method::PolicyEffective
            | Method::PolicyExplain(_)
            | Method::EnrollStatus => false,
            Method::CapabilitiesSet(_) | Method::Reconcile => true,
            // M5 (contract section 5): enrollment mutations are root-only,
            // exactly like `capabilities.set`.
            Method::EnrollStart(_) | Method::EnrollStop => true,
            // M9 (contract section 14.2). Reads stay open. `create` and
            // `consume` are root-only: minting approvals and spending them
            // are privileged operations whose only callers are punard
            // itself and the root-run broker.
            Method::ApprovalsList | Method::ApprovalsGet(_) => false,
            Method::ApprovalsCreate(_) | Method::ApprovalsConsume(_) => true,
            // `approvals.resolve` is the one method whose rule this flag
            // cannot express, and saying `false` here would be a lie in the
            // safe direction only. It is **human only** (section 14.5):
            // root is permitted, an ordinary user is permitted for their
            // own routed approvals, and a peer inside a managed agent scope
            // is refused *whatever its uid* — because spec 60 forbids
            // bypassing AI policy enforcement, and root-ness inside an
            // agent scope buys no bypass. The daemon enforces all three
            // conditions; this flag only says "not root-only".
            Method::ApprovalsResolve(_) => false,
            // Privilege: asking and reading are open (the answer may still
            // be a refusal); revoking is checked against grant ownership in
            // the daemon, so it is not root-only either.
            Method::PrivilegeRequest(_) | Method::PrivilegeStatus | Method::PrivilegeRevoke(_) => {
                false
            }
        }
    }

    /// The method's params as a wire value (`None` for no-params methods).
    pub fn params_value(&self) -> Option<Value> {
        let params = match self {
            Method::Status
            | Method::CapabilitiesList
            | Method::Reconcile
            | Method::PolicyEffective
            | Method::EnrollStatus
            | Method::EnrollStop
            | Method::ApprovalsList
            | Method::PrivilegeStatus => return None,
            Method::CapabilitiesGet(p) => serde_json::to_value(p),
            Method::CapabilitiesSet(p) => serde_json::to_value(p),
            Method::AuditTail(p) => serde_json::to_value(p),
            Method::PolicyExplain(p) => serde_json::to_value(p),
            Method::EnrollStart(p) => serde_json::to_value(p),
            Method::ApprovalsGet(p) | Method::ApprovalsConsume(p) => serde_json::to_value(p),
            Method::ApprovalsCreate(p) => serde_json::to_value(p),
            Method::ApprovalsResolve(p) => serde_json::to_value(p),
            Method::PrivilegeRequest(p) => serde_json::to_value(p),
            Method::PrivilegeRevoke(p) => serde_json::to_value(p),
        };
        Some(params.expect("params structs serialize infallibly"))
    }

    /// Lift a wire method name + params into a typed `Method`.
    ///
    /// Errors: [`ErrorCode::UnknownMethod`] for names outside the table
    /// (including every generic-execution probe), [`ErrorCode::InvalidParams`]
    /// for missing/extra/mis-shaped params (strict: unknown params are
    /// rejected, contract section 3.1).
    pub fn from_wire(method: &str, params: Option<Value>) -> Result<Method, IpcError> {
        match method {
            "status" => Self::expect_no_params(method, params).map(|()| Method::Status),
            "capabilities.list" => {
                Self::expect_no_params(method, params).map(|()| Method::CapabilitiesList)
            }
            "reconcile" => Self::expect_no_params(method, params).map(|()| Method::Reconcile),
            "capabilities.get" => {
                Self::parse_required_params(method, params).map(Method::CapabilitiesGet)
            }
            "capabilities.set" => {
                Self::parse_required_params(method, params).map(Method::CapabilitiesSet)
            }
            "audit.tail" => match params {
                None => Ok(Method::AuditTail(AuditTailParams::default())),
                Some(value) => Self::parse_params(method, value).map(Method::AuditTail),
            },
            "policy.effective" => {
                Self::expect_no_params(method, params).map(|()| Method::PolicyEffective)
            }
            "policy.explain" => {
                Self::parse_required_params(method, params).map(Method::PolicyExplain)
            }
            "enroll.start" => Self::parse_required_params(method, params).map(Method::EnrollStart),
            "enroll.status" => {
                Self::expect_no_params(method, params).map(|()| Method::EnrollStatus)
            }
            "enroll.stop" => Self::expect_no_params(method, params).map(|()| Method::EnrollStop),
            "approvals.list" => {
                Self::expect_no_params(method, params).map(|()| Method::ApprovalsList)
            }
            "approvals.get" => {
                Self::parse_required_params(method, params).map(Method::ApprovalsGet)
            }
            "approvals.create" => Self::parse_required_params(method, params)
                .map(|p| Method::ApprovalsCreate(Box::new(p))),
            "approvals.resolve" => {
                Self::parse_required_params(method, params).map(Method::ApprovalsResolve)
            }
            "approvals.consume" => {
                Self::parse_required_params(method, params).map(Method::ApprovalsConsume)
            }
            "privilege.request" => {
                Self::parse_required_params(method, params).map(Method::PrivilegeRequest)
            }
            "privilege.status" => {
                Self::expect_no_params(method, params).map(|()| Method::PrivilegeStatus)
            }
            "privilege.revoke" => {
                Self::parse_required_params(method, params).map(Method::PrivilegeRevoke)
            }
            unknown => Err(IpcError::with_details(
                ErrorCode::UnknownMethod,
                format!(
                    "The method {unknown:?} does not exist. The Punar IPC method table is \
                     closed and typed; there is no generic execution method, by design \
                     (spec sections 10 and 60). Next step: run `punarctl --help` for the \
                     supported commands."
                ),
                json!({ "method": unknown }),
            )),
        }
    }

    fn expect_no_params(method: &str, params: Option<Value>) -> Result<(), IpcError> {
        match params {
            None => Ok(()),
            Some(Value::Object(map)) if map.is_empty() => Ok(()),
            Some(_) => Err(Self::invalid_params(
                method,
                "this method takes no parameters",
            )),
        }
    }

    fn parse_required_params<P: serde::de::DeserializeOwned>(
        method: &str,
        params: Option<Value>,
    ) -> Result<P, IpcError> {
        match params {
            None => Err(Self::invalid_params(method, "params object is required")),
            Some(value) => Self::parse_params(method, value),
        }
    }

    fn parse_params<P: serde::de::DeserializeOwned>(
        method: &str,
        value: Value,
    ) -> Result<P, IpcError> {
        serde_json::from_value(value).map_err(|err| Self::invalid_params(method, &err.to_string()))
    }

    fn invalid_params(method: &str, reason: &str) -> IpcError {
        IpcError::with_details(
            ErrorCode::InvalidParams,
            format!(
                "Invalid parameters for {method}: {reason}. Next step: run \
                 `punarctl --help` for the expected arguments."
            ),
            json!({ "reason": reason }),
        )
    }
}

// ---------------------------------------------------------------------------
// Typed request + the staged parse pipeline
// ---------------------------------------------------------------------------

/// A validated, typed request: the form the server dispatches on and the
/// form well-behaved clients build.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// Correlation id, 1–64 characters, echoed verbatim in the response.
    pub id: String,
    pub method: Method,
}

/// A request that failed the parse pipeline: the wire error to send, plus
/// the best-effort `id` to echo (`None` → `"id": null` in the response).
#[derive(Debug, Clone, PartialEq)]
pub struct RequestReject {
    pub id: Option<String>,
    pub error: IpcError,
}

impl Request {
    /// Build a typed request, validating the id length.
    pub fn new(id: impl Into<String>, method: Method) -> Result<Request, IpcError> {
        let id = id.into();
        if !id_length_ok(&id) {
            return Err(IpcError::new(
                ErrorCode::MalformedRequest,
                format!(
                    "The request id must be {REQUEST_ID_MIN_CHARS} to \
                     {REQUEST_ID_MAX_CHARS} characters."
                ),
            ));
        }
        Ok(Request { id, method })
    }

    /// The raw wire frame for this request.
    pub fn to_envelope(&self) -> RequestEnvelope {
        RequestEnvelope {
            v: PROTOCOL_VERSION,
            id: self.id.clone(),
            method: self.method.name().to_string(),
            params: self.method.params_value(),
        }
    }

    /// Serialize as one NDJSON line, including the terminating `\n`.
    pub fn to_json_line(&self) -> String {
        self.to_envelope().to_json_line()
    }

    /// Parse one request line (without its trailing `\n`) through the staged
    /// pipeline the contract's error-code table requires:
    ///
    /// 1. length → `malformed_request`
    /// 2. JSON object shape → `malformed_request` (`id` echoed best-effort)
    /// 3. `v` present and integer → `malformed_request`; wrong version →
    ///    `unsupported_version` (checked before strict field validation so
    ///    a well-formed future-version frame is answered with the version
    ///    error, not a field nitpick)
    /// 4. strict envelope fields → `malformed_request`
    /// 5. `id` length → `malformed_request`
    /// 6. method table → `unknown_method`; params → `invalid_params`
    pub fn parse_json_line(line: &str) -> Result<Request, RequestReject> {
        // 1.–5. shared envelope pipeline; 6. the punard method table.
        let envelope = parse_envelope_line(line)?;
        let method = Method::from_wire(&envelope.method, envelope.params).map_err(|error| {
            RequestReject {
                id: Some(envelope.id.clone()),
                error,
            }
        })?;
        Ok(Request {
            id: envelope.id,
            method,
        })
    }
}

/// Stages 1–5 of the request parse pipeline (length, JSON shape, version,
/// strict envelope fields, id bounds) — everything up to, but not
/// including, the method table. Extracted (M7, additively) because both
/// daemons share the envelope contract while owning distinct closed method
/// tables: `punard` finishes with [`Method::from_wire`], `punar-agentd`
/// with [`crate::agent::AgentMethod::from_wire`] (docs/api/ipc.md
/// section 10.1: "framing, envelope, versioning, timeouts … apply
/// unchanged"). Behavior of each stage is exactly what
/// [`Request::parse_json_line`] documented since M3.
pub fn parse_envelope_line(line: &str) -> Result<RequestEnvelope, RequestReject> {
    // 1. Length bound (bytes, excluding the terminator the caller strips).
    if line.len() > MAX_REQUEST_LINE_BYTES {
        return Err(RequestReject {
            id: None,
            error: IpcError::new(
                ErrorCode::MalformedRequest,
                format!(
                    "The request line exceeds the {MAX_REQUEST_LINE_BYTES}-byte limit. \
                         Next step: no Milestone 3 method needs a longer line; check the client."
                ),
            ),
        });
    }

    // 2. Generic JSON parse, so we can echo `id` even for envelopes that
    // fail strict validation.
    let value: Value = serde_json::from_str(line).map_err(|err| RequestReject {
        id: None,
        error: IpcError::new(
            ErrorCode::MalformedRequest,
            format!(
                "The request line is not valid JSON: {err}. Next step: send one \
                     JSON object per line as documented in docs/api/ipc.md."
            ),
        ),
    })?;
    let Some(object) = value.as_object() else {
        return Err(RequestReject {
            id: None,
            error: IpcError::new(
                ErrorCode::MalformedRequest,
                "The request line must be a JSON object envelope \
                     {\"v\":1,\"id\":…,\"method\":…}. Next step: see docs/api/ipc.md."
                    .to_string(),
            ),
        });
    };
    let echo_id = object
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| id_length_ok(id))
        .map(str::to_string);
    let reject = |error: IpcError| RequestReject {
        id: echo_id.clone(),
        error,
    };

    // 3. Version, before strict field checks (see doc comment).
    match object.get("v") {
        None => {
            return Err(reject(IpcError::new(
                ErrorCode::MalformedRequest,
                "The envelope field \"v\" is required and must be the integer 1.".to_string(),
            )));
        }
        Some(v) => match v.as_u64() {
            Some(version) if version == PROTOCOL_VERSION => {}
            Some(version) => {
                return Err(reject(IpcError::with_details(
                    ErrorCode::UnsupportedVersion,
                    format!(
                        "This daemon speaks Punar IPC protocol version \
                             {PROTOCOL_VERSION}; the request asked for version {version}. \
                             Next step: use the punarctl that shipped with this image."
                    ),
                    json!({ "supported": [PROTOCOL_VERSION] }),
                )));
            }
            None => {
                return Err(reject(IpcError::new(
                    ErrorCode::MalformedRequest,
                    "The envelope field \"v\" must be the integer 1.".to_string(),
                )));
            }
        },
    }

    // 4. Strict typed envelope (rejects unknown/mistyped fields).
    let envelope: RequestEnvelope = serde_json::from_value(value.clone()).map_err(|err| {
        reject(IpcError::new(
            ErrorCode::MalformedRequest,
            format!(
                "The request envelope is invalid: {err}. Next step: the \
                         envelope fields are exactly v, id, method, params \
                         (docs/api/ipc.md)."
            ),
        ))
    })?;

    // 5. Id bounds.
    if !id_length_ok(&envelope.id) {
        return Err(reject(IpcError::new(
            ErrorCode::MalformedRequest,
            format!(
                "The envelope field \"id\" must be a string of \
                     {REQUEST_ID_MIN_CHARS} to {REQUEST_ID_MAX_CHARS} characters."
            ),
        )));
    }

    // 6. (the method table) belongs to the caller.
    Ok(envelope)
}

// ---------------------------------------------------------------------------
// Framing helper (docs/api/ipc.md section 2)
// ---------------------------------------------------------------------------

/// Outcome of one bounded line read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineRead {
    /// A complete line, terminator stripped.
    Line(String),
    /// The line exceeded the caller's byte bound and was discarded; the
    /// server answers `malformed_request` and closes (section 2).
    TooLong,
    /// Clean end of stream.
    Eof,
}

/// Read one `\n`-terminated line of at most `max` bytes (terminator
/// included), never buffering more than `max` bytes of an oversized line —
/// the section 2 framing bound, which is what keeps per-connection memory
/// constant regardless of what a peer sends.
///
/// Added in M7 so `punar-agentd` frames its socket exactly as `punard`
/// does (docs/api/ipc.md section 10.1: "framing, envelope, versioning,
/// timeouts … apply unchanged"). `punard` still carries its own private
/// M3 copy of this loop, byte-for-byte identical; folding it onto this one
/// is a mechanical follow-up that touches `punard` and so stays outside
/// the M7 agentd change.
pub fn read_line_bounded<R: std::io::Read>(
    reader: &mut std::io::BufReader<R>,
    max: usize,
) -> std::io::Result<LineRead> {
    use std::io::BufRead;
    let mut line: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(LineRead::Eof)
            } else {
                // Trailing data without newline: treat as a (final) line.
                Ok(LineRead::Line(String::from_utf8_lossy(&line).into_owned()))
            };
        }
        if let Some(pos) = available.iter().position(|b| *b == b'\n') {
            if line.len() + pos + 1 > max {
                reader.consume(pos + 1);
                return Ok(LineRead::TooLong);
            }
            line.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            return Ok(LineRead::Line(String::from_utf8_lossy(&line).into_owned()));
        }
        let chunk = available.len();
        if line.len() + chunk > max {
            reader.consume(chunk);
            return Ok(LineRead::TooLong);
        }
        line.extend_from_slice(available);
        reader.consume(chunk);
    }
}

fn id_length_ok(id: &str) -> bool {
    let chars = id.chars().count();
    (REQUEST_ID_MIN_CHARS..=REQUEST_ID_MAX_CHARS).contains(&chars)
}

// ---------------------------------------------------------------------------
// Response (contract section 3.2)
// ---------------------------------------------------------------------------

/// Exactly one of `result` / `error` — enforced by construction.
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseBody {
    /// Method-specific result object (the typed result structs below
    /// serialize into / parse from this value).
    Result(Value),
    Error(IpcError),
}

/// A response frame: `{"v":1,"id":…,"result":…}` xor `{"v":1,"id":…,"error":…}`.
///
/// `id` is the request id echoed verbatim; `None` (serialized as `null`)
/// only when no id could be parsed from a malformed request. The
/// result-xor-error invariant is enforced on both serialize and deserialize
/// through a private wire shim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ResponseEnvelope", into = "ResponseEnvelope")]
pub struct Response {
    pub v: u64,
    pub id: Option<String>,
    pub body: ResponseBody,
}

/// Raw wire shape backing [`Response`]. Lenient on unknown fields
/// (server→client direction).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResponseEnvelope {
    v: u64,
    // Always serialized — `"id": null` is meaningful (unparseable request).
    id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<IpcError>,
}

impl TryFrom<ResponseEnvelope> for Response {
    type Error = String;

    fn try_from(envelope: ResponseEnvelope) -> Result<Self, String> {
        let body = match (envelope.result, envelope.error) {
            (Some(result), None) => ResponseBody::Result(result),
            (None, Some(error)) => ResponseBody::Error(error),
            (Some(_), Some(_)) => {
                return Err("a response carries exactly one of result/error, got both".into());
            }
            (None, None) => {
                return Err("a response carries exactly one of result/error, got neither".into());
            }
        };
        Ok(Response {
            v: envelope.v,
            id: envelope.id,
            body,
        })
    }
}

impl From<Response> for ResponseEnvelope {
    fn from(response: Response) -> ResponseEnvelope {
        let (result, error) = match response.body {
            ResponseBody::Result(result) => (Some(result), None),
            ResponseBody::Error(err) => (None, Some(err)),
        };
        ResponseEnvelope {
            v: response.v,
            id: response.id,
            result,
            error,
        }
    }
}

impl Response {
    /// A success response for `id` with the given result object.
    pub fn result(id: impl Into<String>, result: Value) -> Response {
        Response {
            v: PROTOCOL_VERSION,
            id: Some(id.into()),
            body: ResponseBody::Result(result),
        }
    }

    /// An error response. `id: None` serializes as `"id": null` (only for
    /// requests whose id could not be parsed).
    pub fn error(id: Option<String>, error: IpcError) -> Response {
        Response {
            v: PROTOCOL_VERSION,
            id,
            body: ResponseBody::Error(error),
        }
    }

    /// The response for a [`RequestReject`] from the parse pipeline.
    pub fn from_reject(reject: RequestReject) -> Response {
        Response::error(reject.id, reject.error)
    }

    /// Serialize as one NDJSON line, including the terminating `\n`.
    pub fn to_json_line(&self) -> String {
        let mut line = serde_json::to_string(self)
            .expect("Response serialization is infallible (string/number/value fields)");
        line.push('\n');
        line
    }

    /// Parse one response line (client side). A malformed server line is a
    /// client-local error; there is no wire code for it because the client
    /// does not answer the server.
    pub fn parse_json_line(line: &str) -> Result<Response, serde_json::Error> {
        serde_json::from_str(line)
    }
}

// ---------------------------------------------------------------------------
// Typed results (contract section 5; lenient deserialize per section 3.3)
// ---------------------------------------------------------------------------

/// Daemon mode. `personal` on an unenrolled device; `managed` while
/// enrolled (M5, contract section 5.1 — the value change the M3 contract
/// pre-announced). Design language section 8: enrollment adds
/// fields/values, it never redraws the base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Personal,
    Managed,
}

/// The `org` object of `status` / `enroll.*` results (M5, contract
/// sections 5.1, 5.9, 5.10). Absent — never `null` — on a personal device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrgInfo {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub domain: String,
}

/// The `last_sync` object of `enroll.status` (M5, contract section 5.10).
/// `result` ∈ `"success" | "unreachable" | null`; `pending` is true while
/// a report is queued (bounded latest-wins queue, SPEC section 55).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LastSync {
    pub at: Option<String>,
    pub result: Option<String>,
    pub pending: bool,
}

/// `enroll.start` result (M5, contract section 5.9). `attestation` is the
/// literal honesty label — the mock control plane answers `"simulated"`
/// and the string travels with the data everywhere enrollment state
/// appears. The device token appears in no result of any method, ever.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollStartResult {
    pub enrolled: bool,
    pub org: OrgInfo,
    pub policy_ids: Vec<String>,
    pub attestation: String,
    pub enrolled_at: String,
    pub first_sync: FirstSync,
}

/// The `first_sync` object of [`EnrollStartResult`]: per-report outcome of
/// the sync attempted inside `enroll.start` (`"success"` /
/// `"unreachable"` — failures queue per SPEC section 55, they do not fail
/// enrollment).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FirstSync {
    pub compliance: String,
    pub inventory: String,
}

/// `enroll.status` result (M5, contract section 5.10). Unenrolled:
/// `{"enrolled": false}` with the org-shaped fields absent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollStatusResult {
    pub enrolled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<OrgInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync: Option<LastSync>,
    /// M10 (milestone-10.md section 13.2): the remote-query scopes the
    /// organization asked for at enrollment, read back from
    /// `enrollment.json`. The user can therefore check every answered query
    /// against the grant themselves — SPEC section 24.2's guarantee 8, and
    /// the same array `punar-agentd` enforces, not a second copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_query_scopes: Option<Vec<String>>,
    /// M10: when the last remote query was decided, at what scope, and how.
    /// Metadata only — the full record is `punarctl privacy queries`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_query: Option<LastQuery>,
}

/// The `enroll.status` view of the most recent remote query (M10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastQuery {
    pub at: String,
    pub scope: String,
    /// `allow` | `deny` — the decision the **device** made, from local
    /// state (SPEC section 59.4).
    pub decision: String,
}

/// `enroll.stop` result (M5, contract section 5.11).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollStopResult {
    pub enrolled: bool,
    pub removed_policy_ids: Vec<String>,
}

/// `status` result (contract section 5.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusResult {
    pub protocol_version: u64,
    pub daemon_version: String,
    /// RFC 3339, daemon start.
    pub started_at: String,
    /// `dev_`-prefixed device id (generated once, persisted).
    pub device_id: String,
    pub mode: Mode,
    /// `false` until M5 enrollment.
    pub enrolled: bool,
    pub hostname: String,
    pub capabilities_total: u64,
    /// RFC 3339, most recent reconcile (boot reconcile runs before the
    /// socket opens, so this is always present).
    pub last_reconcile: String,
    pub audit: AuditStatus,
    /// M4: personal-scope compliance (SPEC section 52; contract section
    /// 5.1). Optional per contract section 3.3 — always present since M4;
    /// `Option` keeps M3-shaped payloads parseable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<ComplianceBlock>,
    /// M5 (contract section 5.1): present while enrolled, absent — never
    /// `null` — on a personal device (enrollment adds fields, never
    /// redraws).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<OrgInfo>,
}

// ---------------------------------------------------------------------------
// M4: compliance and policy result types (contract sections 5.1, 5.6–5.8)
// ---------------------------------------------------------------------------

/// SPEC section 52 compliance states, personal scope in M4 (the device
/// measured against its own effective document).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceState {
    Compliant,
    Remediating,
    NonCompliant,
    Unknown,
    Unsupported,
    Exception,
}

impl ComplianceState {
    /// The wire spelling (matches serde's snake_case rename).
    pub fn as_str(self) -> &'static str {
        match self {
            ComplianceState::Compliant => "compliant",
            ComplianceState::Remediating => "remediating",
            ComplianceState::NonCompliant => "non_compliant",
            ComplianceState::Unknown => "unknown",
            ComplianceState::Unsupported => "unsupported",
            ComplianceState::Exception => "exception",
        }
    }

    /// Badness for the `overall` fold: `non_compliant > unknown >
    /// remediating > exception > compliant` (contract section 5.1).
    /// `unsupported` is excluded from `overall` (section 52's per-row
    /// treatment) and reports the lowest severity here; [`Self::overall`]
    /// skips it entirely.
    fn severity(self) -> u8 {
        match self {
            ComplianceState::NonCompliant => 4,
            ComplianceState::Unknown => 3,
            ComplianceState::Remediating => 2,
            ComplianceState::Exception => 1,
            ComplianceState::Compliant | ComplianceState::Unsupported => 0,
        }
    }

    /// The `overall` state: worst of the per-capability states, with
    /// `unsupported` excluded. An empty iterator is `compliant` (nothing
    /// measured, nothing violated — does not occur with a non-empty
    /// registry).
    pub fn overall(states: impl IntoIterator<Item = ComplianceState>) -> ComplianceState {
        states
            .into_iter()
            .filter(|state| *state != ComplianceState::Unsupported)
            .fold(ComplianceState::Compliant, |worst, state| {
                if state.severity() > worst.severity() {
                    state
                } else {
                    worst
                }
            })
    }
}

/// One capability row of the [`ComplianceBlock`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityCompliance {
    pub capability: CapabilityId,
    pub state: ComplianceState,
}

/// The `compliance` block of `status` and `reconcile` results (contract
/// sections 5.1, 5.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceBlock {
    pub overall: ComplianceState,
    pub capabilities: Vec<CapabilityCompliance>,
    /// Monotonic in-memory counter of successful remediations since daemon
    /// start — the observable the drift demo asserts on.
    pub drift_remediated_total: u64,
    /// RFC 3339; serialized as `null` until the first remediation.
    #[serde(default)]
    pub last_remediation_at: Option<String>,
}

/// SPEC section 43 drift classification as it appears in reconcile results
/// (contract section 5.6). Personal mode classifies every capability
/// `auto_remediate`; `approval_required` behaves as `alert_only` until M9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    AutoRemediate,
    AlertOnly,
    ApprovalRequired,
}

/// Per-capability remediation outcome in a reconcile result (contract
/// section 5.6). `Suppressed` = loop protection engaged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationOutcome {
    Applied,
    None,
    ApplyFailed,
    VerifyFailed,
    AlertOnly,
    Suppressed,
}

/// The `source` object of `policy.effective` / `policy.explain` entries
/// (contract sections 5.7, 5.8). `kind` carries the `policy_source_kind`
/// enum spelling of `schemas/policy/policy-source.json` (the engine type is
/// `punar_policy::SourceKind`; the wire keeps the plain string).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicySourceRef {
    pub kind: String,
    /// Precedence rank, 1–6 ladder (lower wins).
    pub rank: u32,
    pub policy_id: String,
    /// Display name: "Personal preference" / "OS default" in personal mode.
    pub name: String,
}

/// One entry of the `policy.effective` result (contract section 5.7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyEffectiveEntry {
    pub path: String,
    pub effective_value: Value,
    pub source: PolicySourceRef,
    pub user_override_permitted: bool,
    pub compliance_state: ComplianceState,
}

/// `policy.effective` result (contract section 5.7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyEffectiveResult {
    /// RFC 3339, when the effective document was last recomputed.
    pub computed_at: String,
    pub entries: Vec<PolicyEffectiveEntry>,
}

/// `policy.explain` result (contract section 5.8): one effective entry
/// without `path` — exactly the SPEC section 40 information set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyExplainResult {
    pub effective_value: Value,
    pub source: PolicySourceRef,
    pub user_override_permitted: bool,
    pub compliance_state: ComplianceState,
}

/// The `audit` sub-object of [`StatusResult`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditStatus {
    pub path: String,
    /// Total events in the audit log.
    pub events: u64,
}

/// `capabilities.list` result (contract section 5.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilitiesListResult {
    pub capabilities: Vec<CapabilityDescriptor>,
}

/// `capabilities.get` result (contract section 5.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilitiesGetResult {
    pub descriptor: CapabilityDescriptor,
}

/// `capabilities.set` result (contract section 5.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilitiesSetResult {
    /// The descriptor as re-observed after apply + verify.
    pub descriptor: CapabilityDescriptor,
    /// `false` when the observed state already equaled the request
    /// (idempotent no-op — still audited, `result: "noop"`).
    pub changed: bool,
    /// M4: present (and `true`) only when a higher-precedence source
    /// outranks the recorded user preference, so the applied value is not
    /// the requested one. **Never emitted in personal mode** — the personal
    /// result stays byte-identical to M3 (contract section 5.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
    /// M4: the effective value that was applied when `overridden` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_state: Option<Value>,
}

/// `audit.tail` result (contract section 5.5). Events newest **last**.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditTailResult {
    pub events: Vec<AuditEvent>,
}

/// `reconcile` result (contract section 5.6). Every M3 field keeps its M3
/// meaning — `drift` / `drift_count` describe the **pre-remediation**
/// observation; the M4 fields (`classification`, `remediation`,
/// `remediated_count`, `compliance`) are additive per contract section 3.3
/// (`Option` so M3-shaped payloads still parse; always emitted since M4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconcileResult {
    /// RFC 3339.
    pub reconciled_at: String,
    /// Number of entries with `drift: true` (pre-remediation).
    pub drift_count: u64,
    pub capabilities: Vec<ReconcileEntry>,
    /// M4: number of drifts successfully remediated in this pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediated_count: Option<u64>,
    /// M4: post-pass compliance, same shape as the `status` block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<ComplianceBlock>,
}

/// One capability's drift report inside [`ReconcileResult`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconcileEntry {
    pub capability: CapabilityId,
    pub desired_state: Value,
    pub current_state: Value,
    /// `current_state != desired_state` (pre-remediation observation).
    pub drift: bool,
    /// Whether the verification mechanism itself ran successfully.
    pub verified: bool,
    /// M4: SPEC section 43 classification from the effective document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<Classification>,
    /// M4: what this pass did about the drift (contract section 5.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<RemediationOutcome>,
}

// -- M9 results (contract sections 14.2-14.8) -------------------------------

/// Result of `approvals.list`: pending first (soonest expiry first), then
/// recently resolved, newest first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalsListResult {
    pub approvals: Vec<ApprovalEnvelope>,
    /// When the lazy expiry sweep ran — the same read that produced this
    /// list (contract section 14.4). Present so a reader can tell "nothing
    /// pending" from "nobody has looked recently".
    pub checked_at: String,
}

/// Result of `approvals.consume` (contract section 14.7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalsConsumeResult {
    pub approval: ApprovalEnvelope,
    pub consumed_at: String,
}

/// Result of `privilege.status` (contract section 14.8): the caller's own
/// live grants, or every live grant for root.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivilegeStatusResult {
    pub grants: Vec<Grant>,
    pub checked_at: String,
}

/// Result of `privilege.revoke`: the grant ids that were live and are not
/// any more. Revoking nothing is a success with an empty list — idempotent,
/// because handing back privilege must never fail for lack of privilege.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivilegeRevokeResult {
    pub revoked: Vec<String>,
    pub revoked_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrincipalKind;

    // -- error codes --------------------------------------------------------

    #[test]
    fn error_codes_serialize_to_contract_names() {
        let expected = [
            "malformed_request",
            "unsupported_version",
            "unknown_method",
            "invalid_params",
            "denied",
            "not_found",
            "apply_failed",
            "verify_failed",
            "internal",
            "conflict",
            "upstream_unreachable",
            "approval_required",
            "expired",
        ];
        assert_eq!(ErrorCode::ALL.len(), expected.len());
        for (code, name) in ErrorCode::ALL.into_iter().zip(expected) {
            assert_eq!(serde_json::to_string(&code).unwrap(), format!("{name:?}"));
            assert_eq!(code.as_str(), name);
            let back: ErrorCode = serde_json::from_str(&format!("{name:?}")).unwrap();
            assert_eq!(back, code);
        }
        assert!(serde_json::from_str::<ErrorCode>("\"root_shell\"").is_err());
    }

    #[test]
    fn exit_codes_follow_plate_d014() {
        assert_eq!(ErrorCode::Denied.suggested_exit_code(), EXIT_DENIED);
        // M9: exit 4 stops being reserved and starts being reachable.
        assert_eq!(
            ErrorCode::ApprovalRequired.suggested_exit_code(),
            EXIT_APPROVAL_REQUIRED
        );
        for code in ErrorCode::ALL {
            if !matches!(code, ErrorCode::Denied | ErrorCode::ApprovalRequired) {
                assert_eq!(code.suggested_exit_code(), EXIT_ERROR, "{code}");
            }
        }
        assert!(ErrorCode::MalformedRequest.closes_connection());
        assert!(!ErrorCode::Denied.closes_connection());
    }

    #[test]
    fn denial_helper_matches_the_contract_voice() {
        let err = IpcError::denied_needs_root(
            "system.hostname",
            Some("system.hostname"),
            "sudo punarctl capabilities set system.hostname <name>",
        );
        assert_eq!(err.code, ErrorCode::Denied);
        // The 74.4 in-VM check greps for these two strings.
        assert!(err.message.contains("administrator"));
        assert!(err.message.contains("personal defaults"));
        assert!(err.message.contains("Next step"));
        // M9: the pointer that has said "Milestone 9" since M3 now names a
        // command that exists.
        assert!(
            err.message
                .contains("punarctl privilege request --capability")
        );
        assert!(!err.message.contains("Milestone 9"));
        // A refusal with no capability has no grant to offer, and says so
        // by not offering one.
        let no_cap = IpcError::denied_needs_root(
            "the capability registry (reconcile)",
            None,
            "sudo punarctl reconcile",
        );
        assert!(!no_cap.message.contains("privilege request"));
        let details = err.details.unwrap();
        assert_eq!(details["capability"], "system.hostname");
        assert_eq!(details["decision"], "deny");
        assert_eq!(details["policy_ids"], json!(["personal-defaults"]));
    }

    // -- typed request round trips ------------------------------------------

    /// One request per method variant — exhaustive over the closed table.
    fn every_method() -> Vec<Method> {
        let methods = vec![
            Method::Status,
            Method::CapabilitiesList,
            Method::CapabilitiesGet(CapabilitiesGetParams {
                capability: CapabilityId::new("security.firewall").unwrap(),
            }),
            Method::CapabilitiesSet(CapabilitiesSetParams {
                capability: CapabilityId::new("system.hostname").unwrap(),
                desired_state: json!("punar-m3"),
            }),
            Method::AuditTail(AuditTailParams { n: 50 }),
            Method::Reconcile,
            Method::PolicyEffective,
            Method::PolicyExplain(PolicyExplainParams {
                path: CapabilityId::new("security.firewall").unwrap(),
            }),
            Method::EnrollStart(EnrollStartParams {
                org_domain: "acme.com".to_string(),
            }),
            Method::EnrollStatus,
            Method::EnrollStop,
            Method::ApprovalsList,
            Method::ApprovalsGet(ApprovalIdParams {
                approval_id: "apr_7c1d9a4e".to_string(),
            }),
            Method::ApprovalsCreate(Box::new(ApprovalsCreateParams {
                kind: ApprovalKind::CapabilitySet,
                capability: "security.firewall".to_string(),
                resource: "disabled".to_string(),
                reason: "Atlas integration test".to_string(),
                risk: Risk::High,
                user: "punar".to_string(),
                requester: Requester {
                    kind: PrincipalKind::AiAgent,
                    id: "agt_4f21c09ab3e1".to_string(),
                },
                ttl: Some(60),
                contract: None,
                requester_peer: None,
                policy: None,
                request: None,
            })),
            Method::ApprovalsResolve(ApprovalsResolveParams {
                approval_id: "apr_7c1d9a4e".to_string(),
                decision: ResolveDecision::Approved,
            }),
            Method::ApprovalsConsume(ApprovalIdParams {
                approval_id: "apr_7c1d9a4e".to_string(),
            }),
            Method::PrivilegeRequest(PrivilegeRequestParams {
                capability: CapabilityId::new("time.timezone").unwrap(),
                reason: "Reproducing the Atlas net bug".to_string(),
                duration_minutes: Some(15),
            }),
            Method::PrivilegeStatus,
            Method::PrivilegeRevoke(PrivilegeRevokeParams {
                grant_id: Some("gnt_2b8e11c4".to_string()),
                all: None,
            }),
        ];
        assert_eq!(
            methods.len(),
            Method::NAMES.len(),
            "every_method() must cover the whole table"
        );
        methods
    }

    #[test]
    fn every_method_round_trips_through_the_wire() {
        for method in every_method() {
            let request = Request::new("req-1", method.clone()).unwrap();
            let line = request.to_json_line();
            assert!(line.ends_with('\n'));
            assert!(line.len() <= MAX_REQUEST_LINE_BYTES);
            let back = Request::parse_json_line(line.trim_end()).unwrap();
            assert_eq!(back.id, "req-1");
            assert_eq!(back.method, method, "round trip for {}", method.name());
        }
    }

    #[test]
    fn method_names_match_the_contract_table() {
        for (method, name) in every_method().iter().zip(Method::NAMES) {
            assert_eq!(method.name(), name);
        }
    }

    #[test]
    fn only_mutating_methods_require_root() {
        // M3: set + reconcile. M5 adds the enrollment mutations; the read
        // (`enroll.status`) stays open to any connected peer. M9 adds
        // `approvals.create`/`approvals.consume`.
        for method in every_method() {
            let expected = matches!(
                method.name(),
                "capabilities.set"
                    | "reconcile"
                    | "enroll.start"
                    | "enroll.stop"
                    // M9: minting and spending approvals are privileged.
                    // `approvals.resolve` is human-only, which is a
                    // stronger rule this flag cannot express (see
                    // `Method::requires_root`).
                    | "approvals.create"
                    | "approvals.consume"
            );
            assert_eq!(method.requires_root(), expected, "{}", method.name());
        }
    }

    #[test]
    fn no_method_name_smells_of_generic_execution() {
        // Section 60: the table must never grow an execution method. The
        // enum shape prevents the payload; this guards the naming too.
        for name in Method::NAMES {
            for forbidden in ["exec", "shell", "script", "eval", "spawn", "command"] {
                assert!(
                    !name.contains(forbidden),
                    "method {name:?} looks like generic execution"
                );
            }
        }
    }

    #[test]
    fn generic_execution_probes_get_unknown_method() {
        // The 74.4 probes, plus the spec section 10 prohibited example.
        for probe in ["system.exec", "shell.run", "run_root_shell", "debug.spawn"] {
            let line = format!(r#"{{"v":1,"id":"probe","method":"{probe}","params":{{}}}}"#);
            let reject = Request::parse_json_line(&line).unwrap_err();
            assert_eq!(reject.id.as_deref(), Some("probe"));
            assert_eq!(reject.error.code, ErrorCode::UnknownMethod, "{probe}");
            assert_eq!(reject.error.details.unwrap()["method"], probe);
        }
    }

    // -- parse pipeline: staged errors --------------------------------------

    #[test]
    fn oversize_line_is_malformed() {
        let line = format!(
            r#"{{"v":1,"id":"big","method":"status","params":{{"x":"{}"}}}}"#,
            "a".repeat(MAX_REQUEST_LINE_BYTES)
        );
        let reject = Request::parse_json_line(&line).unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::MalformedRequest);
        assert_eq!(reject.id, None);
    }

    #[test]
    fn invalid_json_is_malformed_with_null_id() {
        for line in [
            "",
            "not json",
            "{\"v\":1,",
            "[1,2,3]",
            "\"just a string\"",
            "42",
        ] {
            let reject = Request::parse_json_line(line).unwrap_err();
            assert_eq!(reject.error.code, ErrorCode::MalformedRequest, "{line:?}");
            assert_eq!(reject.id, None, "{line:?}");
        }
    }

    #[test]
    fn missing_or_mistyped_v_is_malformed() {
        for line in [
            r#"{"id":"1","method":"status"}"#,
            r#"{"v":"1","id":"1","method":"status"}"#,
            r#"{"v":1.5,"id":"1","method":"status"}"#,
            r#"{"v":-1,"id":"1","method":"status"}"#,
        ] {
            let reject = Request::parse_json_line(line).unwrap_err();
            assert_eq!(reject.error.code, ErrorCode::MalformedRequest, "{line}");
            assert_eq!(reject.id.as_deref(), Some("1"), "id still echoed: {line}");
        }
    }

    #[test]
    fn wrong_version_is_unsupported_version_with_details() {
        let reject =
            Request::parse_json_line(r#"{"v":2,"id":"up","method":"status"}"#).unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::UnsupportedVersion);
        assert_eq!(reject.id.as_deref(), Some("up"));
        assert_eq!(reject.error.details.unwrap()["supported"], json!([1]));
        // Version wins over strict field validation for well-formed frames.
        let reject =
            Request::parse_json_line(r#"{"v":2,"id":"up","method":"status","future_field":true}"#)
                .unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::UnsupportedVersion);
    }

    #[test]
    fn unknown_envelope_field_is_malformed_but_echoes_id() {
        let reject =
            Request::parse_json_line(r#"{"v":1,"id":"echo-me","method":"status","extra":true}"#)
                .unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::MalformedRequest);
        assert_eq!(reject.id.as_deref(), Some("echo-me"));
    }

    #[test]
    fn id_bounds_are_enforced() {
        let reject = Request::parse_json_line(r#"{"v":1,"id":"","method":"status"}"#).unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::MalformedRequest);
        assert_eq!(reject.id, None, "empty id is not echoed");

        let long = "x".repeat(REQUEST_ID_MAX_CHARS + 1);
        let reject =
            Request::parse_json_line(&format!(r#"{{"v":1,"id":"{long}","method":"status"}}"#))
                .unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::MalformedRequest);

        // 64 chars exactly is fine.
        let max = "x".repeat(REQUEST_ID_MAX_CHARS);
        let request =
            Request::parse_json_line(&format!(r#"{{"v":1,"id":"{max}","method":"status"}}"#))
                .unwrap();
        assert_eq!(request.id, max);

        assert!(Request::new("", Method::Status).is_err());
        assert!(Request::new(long, Method::Status).is_err());
    }

    #[test]
    fn no_params_methods_accept_absent_or_empty_params_only() {
        for method in ["status", "capabilities.list", "reconcile"] {
            let ok =
                Request::parse_json_line(&format!(r#"{{"v":1,"id":"1","method":"{method}"}}"#))
                    .unwrap();
            assert_eq!(ok.method.name(), method);
            let ok = Request::parse_json_line(&format!(
                r#"{{"v":1,"id":"1","method":"{method}","params":{{}}}}"#
            ))
            .unwrap();
            assert_eq!(ok.method.name(), method);
            let reject = Request::parse_json_line(&format!(
                r#"{{"v":1,"id":"1","method":"{method}","params":{{"x":1}}}}"#
            ))
            .unwrap_err();
            assert_eq!(reject.error.code, ErrorCode::InvalidParams, "{method}");
        }
    }

    #[test]
    fn capabilities_get_params_are_strict() {
        let reject = Request::parse_json_line(r#"{"v":1,"id":"1","method":"capabilities.get"}"#)
            .unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::InvalidParams);

        let reject = Request::parse_json_line(
            r#"{"v":1,"id":"1","method":"capabilities.get","params":{"capability":"security.firewall","extra":1}}"#,
        )
        .unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::InvalidParams);

        // Syntactically invalid capability id fails at the type boundary.
        let reject = Request::parse_json_line(
            r#"{"v":1,"id":"1","method":"capabilities.get","params":{"capability":"not a capability"}}"#,
        )
        .unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::InvalidParams);

        let request = Request::parse_json_line(
            r#"{"v":1,"id":"1","method":"capabilities.get","params":{"capability":"security.firewall"}}"#,
        )
        .unwrap();
        match request.method {
            Method::CapabilitiesGet(params) => {
                assert_eq!(params.capability.as_str(), "security.firewall");
            }
            other => panic!("wrong method: {other:?}"),
        }
    }

    #[test]
    fn capabilities_set_params_parse_typed() {
        let request = Request::parse_json_line(
            r#"{"v":1,"id":"1","method":"capabilities.set","params":{"capability":"system.hostname","desired_state":"punar-m3"}}"#,
        )
        .unwrap();
        match request.method {
            Method::CapabilitiesSet(params) => {
                assert_eq!(params.capability.as_str(), "system.hostname");
                assert_eq!(params.desired_state, json!("punar-m3"));
            }
            other => panic!("wrong method: {other:?}"),
        }

        let reject = Request::parse_json_line(
            r#"{"v":1,"id":"1","method":"capabilities.set","params":{"capability":"system.hostname"}}"#,
        )
        .unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::InvalidParams);
        assert!(reject.error.message.contains("desired_state"));
    }

    #[test]
    fn audit_tail_defaults_and_clamps() {
        let request =
            Request::parse_json_line(r#"{"v":1,"id":"1","method":"audit.tail"}"#).unwrap();
        match &request.method {
            Method::AuditTail(params) => {
                assert_eq!(params.n, AUDIT_TAIL_DEFAULT);
                assert_eq!(params.effective_n(), AUDIT_TAIL_DEFAULT);
            }
            other => panic!("wrong method: {other:?}"),
        }

        let request = Request::parse_json_line(
            r#"{"v":1,"id":"1","method":"audit.tail","params":{"n":5000}}"#,
        )
        .unwrap();
        match &request.method {
            Method::AuditTail(params) => {
                assert_eq!(params.n, 5000, "raw value preserved");
                assert_eq!(
                    params.effective_n(),
                    AUDIT_TAIL_MAX,
                    "clamped, not an error"
                );
            }
            other => panic!("wrong method: {other:?}"),
        }

        for bad in [
            r#"{"v":1,"id":"1","method":"audit.tail","params":{"n":-1}}"#,
            r#"{"v":1,"id":"1","method":"audit.tail","params":{"n":"20"}}"#,
            r#"{"v":1,"id":"1","method":"audit.tail","params":{"count":20}}"#,
        ] {
            let reject = Request::parse_json_line(bad).unwrap_err();
            assert_eq!(reject.error.code, ErrorCode::InvalidParams, "{bad}");
        }
    }

    // -- responses ----------------------------------------------------------

    #[test]
    fn success_response_round_trips() {
        let response = Response::result("req-9", json!({"protocol_version": 1}));
        let line = response.to_json_line();
        assert!(line.ends_with('\n'));
        let value: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(value["v"], 1);
        assert_eq!(value["id"], "req-9");
        assert_eq!(value["result"]["protocol_version"], 1);
        assert!(value.get("error").is_none());
        let back = Response::parse_json_line(line.trim_end()).unwrap();
        assert_eq!(back, response);
    }

    #[test]
    fn error_response_round_trips_with_null_id() {
        let response = Response::error(
            None,
            IpcError::new(
                ErrorCode::MalformedRequest,
                "The request line is not valid JSON.",
            ),
        );
        let line = response.to_json_line();
        let value: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(value["id"], Value::Null, "id must serialize as null");
        assert_eq!(value["error"]["code"], "malformed_request");
        assert!(value.get("result").is_none());
        let back = Response::parse_json_line(line.trim_end()).unwrap();
        assert_eq!(back, response);
    }

    #[test]
    fn response_must_carry_exactly_one_of_result_and_error() {
        let both = r#"{"v":1,"id":"1","result":{},"error":{"code":"internal","message":"x"}}"#;
        assert!(Response::parse_json_line(both).is_err());
        let neither = r#"{"v":1,"id":"1"}"#;
        assert!(Response::parse_json_line(neither).is_err());
    }

    #[test]
    fn contract_error_example_parses() {
        // The docs/api/ipc.md section 3.2 error example, verbatim.
        let line = r#"{"v": 1, "id": "req-1", "error": {"code": "denied", "message": "Changing system.hostname needs administrator privileges.\nPolicy: personal defaults — just-in-time elevation arrives in Milestone 9.\nNext step: re-run as root: sudo punarctl capabilities set system.hostname <name>", "details": {"capability": "system.hostname", "decision": "deny", "policy_ids": ["personal-defaults"]}}}"#;
        let response = Response::parse_json_line(line).unwrap();
        match response.body {
            ResponseBody::Error(error) => {
                assert_eq!(error.code, ErrorCode::Denied);
                assert_eq!(error.code.suggested_exit_code(), EXIT_DENIED);
            }
            other => panic!("expected error body: {other:?}"),
        }
    }

    // -- typed results ------------------------------------------------------

    #[test]
    fn status_result_parses_the_contract_example() {
        // docs/api/ipc.md section 5.1, verbatim.
        let line = r#"{"v":1,"id":"1","result":{
          "protocol_version": 1,
          "daemon_version": "0.1.0",
          "started_at": "2026-08-25T07:00:12Z",
          "device_id": "dev_9f3k2v8q1x",
          "mode": "personal",
          "enrolled": false,
          "hostname": "punar-desktop",
          "capabilities_total": 3,
          "last_reconcile": "2026-08-25T07:00:13Z",
          "audit": {"path": "/var/log/punar/audit.jsonl", "events": 42}
        }}"#;
        let response = Response::parse_json_line(line).unwrap();
        let ResponseBody::Result(result) = response.body else {
            panic!("expected result body");
        };
        let status: StatusResult = serde_json::from_value(result).unwrap();
        assert_eq!(status.protocol_version, PROTOCOL_VERSION);
        assert_eq!(status.mode, Mode::Personal);
        assert!(!status.enrolled);
        assert_eq!(status.capabilities_total, 3);
        assert_eq!(status.device_id, "dev_9f3k2v8q1x");
        assert_eq!(status.audit.path, "/var/log/punar/audit.jsonl");
        assert_eq!(status.audit.events, 42);

        // Round trip.
        let back: StatusResult =
            serde_json::from_str(&serde_json::to_string(&status).unwrap()).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn status_result_tolerates_unknown_result_fields() {
        // Contract section 3.3: adding an optional result field is not a
        // version bump; clients tolerate unknown fields.
        let mut value = serde_json::to_value(StatusResult {
            protocol_version: 1,
            daemon_version: "0.1.0".into(),
            started_at: "2026-08-25T07:00:12Z".into(),
            device_id: "dev_9f3k2v8q1x".into(),
            mode: Mode::Personal,
            enrolled: false,
            hostname: "punar-desktop".into(),
            capabilities_total: 3,
            last_reconcile: "2026-08-25T07:00:13Z".into(),
            audit: AuditStatus {
                path: "/var/log/punar/audit.jsonl".into(),
                events: 42,
            },
            compliance: None,
            org: None,
        })
        .unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("added_later".to_string(), json!({"added": "in M6+"}));
        let status: StatusResult = serde_json::from_value(value).unwrap();
        assert_eq!(status.mode, Mode::Personal);
    }

    #[test]
    fn reconcile_result_parses_the_contract_example() {
        // docs/api/ipc.md section 5.6, verbatim.
        let json = r#"{
          "reconciled_at": "2026-08-25T07:41:03Z",
          "drift_count": 1,
          "capabilities": [
            {"capability": "security.firewall", "desired_state": "enabled",
             "current_state": "disabled", "drift": true, "verified": true},
            {"capability": "system.hostname", "desired_state": "punar-m3",
             "current_state": "punar-m3", "drift": false, "verified": true},
            {"capability": "time.timezone", "desired_state": "UTC",
             "current_state": "UTC", "drift": false, "verified": true}
          ]
        }"#;
        let result: ReconcileResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.drift_count, 1);
        assert_eq!(result.capabilities.len(), 3);
        let firewall = &result.capabilities[0];
        assert_eq!(firewall.capability.as_str(), "security.firewall");
        assert!(firewall.drift);
        assert_eq!(
            result.capabilities.iter().filter(|c| c.drift).count() as u64,
            result.drift_count
        );
        let back: ReconcileResult =
            serde_json::from_str(&serde_json::to_string(&result).unwrap()).unwrap();
        assert_eq!(back, result);
    }

    #[test]
    fn capabilities_results_round_trip() {
        let descriptor: CapabilityDescriptor = serde_json::from_str(include_str!(
            "../../../schemas/capability/examples/security-firewall.json"
        ))
        .unwrap();

        let list = CapabilitiesListResult {
            capabilities: vec![descriptor.clone()],
        };
        let back: CapabilitiesListResult =
            serde_json::from_str(&serde_json::to_string(&list).unwrap()).unwrap();
        assert_eq!(back, list);

        let get = CapabilitiesGetResult {
            descriptor: descriptor.clone(),
        };
        let back: CapabilitiesGetResult =
            serde_json::from_str(&serde_json::to_string(&get).unwrap()).unwrap();
        assert_eq!(back, get);

        let set = CapabilitiesSetResult {
            descriptor,
            changed: true,
            overridden: None,
            effective_state: None,
        };
        let value = serde_json::to_value(&set).unwrap();
        assert_eq!(value["changed"], true);
        // Personal mode (contract section 5.4): the result is byte-identical
        // to M3 — the M4 override fields are omitted, not null.
        let object = value.as_object().unwrap();
        assert!(!object.contains_key("overridden"));
        assert!(!object.contains_key("effective_state"));
        let back: CapabilitiesSetResult = serde_json::from_value(value).unwrap();
        assert_eq!(back, set);
    }

    #[test]
    fn overridden_set_result_carries_the_effective_state() {
        let descriptor: CapabilityDescriptor = serde_json::from_str(include_str!(
            "../../../schemas/capability/examples/security-firewall.json"
        ))
        .unwrap();
        let set = CapabilitiesSetResult {
            descriptor,
            changed: false,
            overridden: Some(true),
            effective_state: Some(json!("enabled")),
        };
        let value = serde_json::to_value(&set).unwrap();
        assert_eq!(value["overridden"], true);
        assert_eq!(value["effective_state"], "enabled");
        let back: CapabilitiesSetResult = serde_json::from_value(value).unwrap();
        assert_eq!(back, set);
    }

    #[test]
    fn mode_spellings_are_the_contract_values() {
        // M5: `managed` joined the set (contract section 5.1); daemon and
        // CLI always ship in the same image, so the set stays closed.
        assert_eq!(
            serde_json::to_string(&Mode::Personal).unwrap(),
            "\"personal\""
        );
        assert_eq!(
            serde_json::to_string(&Mode::Managed).unwrap(),
            "\"managed\""
        );
        assert_eq!(
            serde_json::from_str::<Mode>("\"managed\"").unwrap(),
            Mode::Managed
        );
        assert!(serde_json::from_str::<Mode>("\"kiosk\"").is_err());
    }

    // -- M5 enrollment additions --------------------------------------------

    #[test]
    fn enroll_start_params_are_strict() {
        let params: EnrollStartParams =
            serde_json::from_value(json!({"org_domain": "acme.com"})).unwrap();
        assert_eq!(params.org_domain, "acme.com");
        assert!(
            serde_json::from_value::<EnrollStartParams>(json!({
                "org_domain": "acme.com", "extra": true
            }))
            .is_err(),
            "unknown params are rejected (contract section 3.1)"
        );
        assert!(serde_json::from_value::<EnrollStartParams>(json!({})).is_err());
    }

    #[test]
    fn enroll_status_and_stop_take_no_params() {
        for method in ["enroll.status", "enroll.stop"] {
            let reject = Request::parse_json_line(&format!(
                r#"{{"v":1,"id":"e","method":"{method}","params":{{"x":1}}}}"#
            ))
            .unwrap_err();
            assert_eq!(reject.error.code, ErrorCode::InvalidParams, "{method}");
        }
    }

    #[test]
    fn enroll_start_result_parses_the_contract_example() {
        let result: EnrollStartResult = serde_json::from_value(json!({
            "enrolled": true,
            "org": {"id": "acme", "name": "Acme",
                     "display_name": "Acme Engineering", "domain": "acme.com"},
            "policy_ids": ["eng-baseline-v12"],
            "attestation": "simulated",
            "enrolled_at": "2026-08-26T09:00:00Z",
            "first_sync": {"compliance": "success", "inventory": "success"}
        }))
        .unwrap();
        assert!(result.enrolled);
        assert_eq!(result.org.display_name, "Acme Engineering");
        assert_eq!(result.policy_ids, ["eng-baseline-v12"]);
        // The honesty label travels with the data (contract section 5.9).
        assert_eq!(result.attestation, "simulated");
        assert_eq!(result.first_sync.compliance, "success");
    }

    #[test]
    fn unenrolled_status_result_omits_the_org_shaped_fields() {
        // Contract section 5.10: `{"enrolled": false}`, fields absent —
        // never `null`.
        let result = EnrollStatusResult {
            enrolled: false,
            org: None,
            policy_ids: None,
            enrolled_at: None,
            attestation: None,
            last_sync: None,
            remote_query_scopes: None,
            last_query: None,
        };
        assert_eq!(
            serde_json::to_string(&result).unwrap(),
            r#"{"enrolled":false}"#
        );
        let back: EnrollStatusResult = serde_json::from_str(r#"{"enrolled":false}"#).unwrap();
        assert_eq!(back, result);
    }

    #[test]
    fn enrolled_status_result_round_trips_last_sync() {
        let result: EnrollStatusResult = serde_json::from_value(json!({
            "enrolled": true,
            "org": {"id": "acme", "name": "Acme",
                     "display_name": "Acme Engineering", "domain": "acme.com"},
            "policy_ids": ["eng-baseline-v12"],
            "enrolled_at": "2026-08-26T09:00:00Z",
            "attestation": "simulated",
            "last_sync": {"at": "2026-08-26T09:02:00Z", "result": "success",
                           "pending": false}
        }))
        .unwrap();
        let sync = result.last_sync.as_ref().unwrap();
        assert_eq!(sync.result.as_deref(), Some("success"));
        assert!(!sync.pending);
        assert_eq!(result.attestation.as_deref(), Some("simulated"));
    }

    #[test]
    fn status_result_carries_the_optional_m5_org() {
        // Enrollment adds fields, never redraws (contract section 5.1).
        let personal = serde_json::to_value(StatusResult {
            protocol_version: 1,
            daemon_version: "0.1.0".into(),
            started_at: "2026-08-25T07:00:12Z".into(),
            device_id: "dev_9f3k2v8q1x".into(),
            mode: Mode::Personal,
            enrolled: false,
            hostname: "punar".into(),
            capabilities_total: 3,
            last_reconcile: "2026-08-25T07:00:13Z".into(),
            audit: AuditStatus {
                path: "/var/log/punar/audit.jsonl".into(),
                events: 1,
            },
            compliance: None,
            org: None,
        })
        .unwrap();
        assert!(
            personal.get("org").is_none(),
            "org must be absent, never null, on a personal device"
        );

        let managed: StatusResult = serde_json::from_value(json!({
            "protocol_version": 1, "daemon_version": "0.1.0",
            "started_at": "t", "device_id": "dev_1", "mode": "managed",
            "enrolled": true, "hostname": "h", "capabilities_total": 3,
            "last_reconcile": "t",
            "audit": {"path": "p", "events": 0},
            "org": {"id": "acme", "name": "Acme",
                     "display_name": "Acme Engineering", "domain": "acme.com"}
        }))
        .unwrap();
        assert_eq!(managed.mode, Mode::Managed);
        assert_eq!(managed.org.unwrap().id, "acme");
    }

    #[test]
    fn org_pinned_denial_cites_the_pinning_source() {
        // Contract section 5.4 M5 amendment: the m5-check greps for the
        // source name, the policy id, and the section 73 next step.
        let err = IpcError::denied_org_pinned(
            "security.firewall",
            "Acme Engineering Baseline",
            "eng-baseline-v12",
        );
        assert_eq!(err.code, ErrorCode::Denied);
        assert!(err.message.contains("Acme Engineering Baseline"));
        assert!(err.message.contains("eng-baseline-v12"));
        assert!(err.message.contains("not permitted"));
        assert!(err.message.contains("Next step"));
        assert!(
            !err.message.contains("personal defaults"),
            "the false M3 citation must be gone on managed paths"
        );
        let details = err.details.unwrap();
        assert_eq!(details["policy_ids"], json!(["eng-baseline-v12"]));
        assert_eq!(details["capability"], "security.firewall");
    }

    #[test]
    fn enroll_timeout_bounds_cover_each_other() {
        // Contract section 2: the 90 s client budget must cover the 60 s
        // processing bound with margin.
        assert!(ENROLL_START_CLIENT_TIMEOUT > ENROLL_START_PROCESS_TIMEOUT);
    }

    // -- M4 typed results (contract sections 5.1, 5.6–5.8) ------------------

    #[test]
    fn policy_effective_result_parses_the_contract_example() {
        // docs/api/ipc.md section 5.7, verbatim.
        let json = r#"{
          "computed_at": "2026-08-25T09:14:02Z",
          "entries": [
            {"path": "security.firewall", "effective_value": "enabled",
             "source": {"kind": "local_user_preference", "rank": 5,
                        "policy_id": "personal-defaults",
                        "name": "Personal preference"},
             "user_override_permitted": true,
             "compliance_state": "compliant"},
            {"path": "time.timezone", "effective_value": "UTC",
             "source": {"kind": "os_secure_default", "rank": 6,
                        "policy_id": "personal-defaults",
                        "name": "OS default"},
             "user_override_permitted": true,
             "compliance_state": "compliant"}
          ]
        }"#;
        let result: PolicyEffectiveResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.entries.len(), 2);
        let firewall = &result.entries[0];
        assert_eq!(firewall.path, "security.firewall");
        assert_eq!(firewall.source.kind, "local_user_preference");
        assert_eq!(firewall.source.rank, 5);
        assert!(firewall.user_override_permitted);
        assert_eq!(firewall.compliance_state, ComplianceState::Compliant);
        let back: PolicyEffectiveResult =
            serde_json::from_str(&serde_json::to_string(&result).unwrap()).unwrap();
        assert_eq!(back, result);
    }

    #[test]
    fn policy_explain_result_parses_the_contract_example() {
        // docs/api/ipc.md section 5.8, verbatim: one entry minus `path`.
        let json = r#"{
          "effective_value": "enabled",
          "source": {"kind": "local_user_preference", "rank": 5,
                     "policy_id": "personal-defaults",
                     "name": "Personal preference"},
          "user_override_permitted": true,
          "compliance_state": "compliant"
        }"#;
        let result: PolicyExplainResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.effective_value, json!("enabled"));
        assert_eq!(result.source.policy_id, "personal-defaults");
        assert_eq!(result.source.name, "Personal preference");
        let back: PolicyExplainResult =
            serde_json::from_str(&serde_json::to_string(&result).unwrap()).unwrap();
        assert_eq!(back, result);
    }

    #[test]
    fn compliance_overall_is_the_worst_state_with_unsupported_excluded() {
        use ComplianceState::*;
        // Contract section 5.1: non_compliant > unknown > remediating >
        // exception > compliant; unsupported never drives `overall`.
        assert_eq!(ComplianceState::overall([Compliant, Compliant]), Compliant);
        assert_eq!(ComplianceState::overall([Compliant, Exception]), Exception);
        assert_eq!(
            ComplianceState::overall([Exception, Remediating]),
            Remediating
        );
        assert_eq!(ComplianceState::overall([Remediating, Unknown]), Unknown);
        assert_eq!(
            ComplianceState::overall([Unknown, NonCompliant, Compliant]),
            NonCompliant
        );
        assert_eq!(
            ComplianceState::overall([Unsupported, Compliant]),
            Compliant
        );
        assert_eq!(ComplianceState::overall([]), Compliant);
    }

    #[test]
    fn compliance_states_use_the_section_52_spellings() {
        let expected = [
            (ComplianceState::Compliant, "compliant"),
            (ComplianceState::Remediating, "remediating"),
            (ComplianceState::NonCompliant, "non_compliant"),
            (ComplianceState::Unknown, "unknown"),
            (ComplianceState::Unsupported, "unsupported"),
            (ComplianceState::Exception, "exception"),
        ];
        for (state, wire) in expected {
            assert_eq!(serde_json::to_string(&state).unwrap(), format!("{wire:?}"));
            assert_eq!(state.as_str(), wire);
            let back: ComplianceState = serde_json::from_str(&format!("{wire:?}")).unwrap();
            assert_eq!(back, state);
        }
    }

    #[test]
    fn m4_reconcile_result_round_trips_and_m3_meaning_is_kept() {
        let result = ReconcileResult {
            reconciled_at: "2026-08-25T09:14:02Z".into(),
            drift_count: 1,
            capabilities: vec![ReconcileEntry {
                capability: CapabilityId::new("security.firewall").unwrap(),
                desired_state: json!("enabled"),
                current_state: json!("disabled"),
                drift: true,
                verified: true,
                classification: Some(Classification::AutoRemediate),
                remediation: Some(RemediationOutcome::Applied),
            }],
            remediated_count: Some(1),
            compliance: Some(ComplianceBlock {
                overall: ComplianceState::Compliant,
                capabilities: vec![CapabilityCompliance {
                    capability: CapabilityId::new("security.firewall").unwrap(),
                    state: ComplianceState::Compliant,
                }],
                drift_remediated_total: 3,
                last_remediation_at: Some("2026-08-25T09:14:02Z".into()),
            }),
        };
        let value = serde_json::to_value(&result).unwrap();
        // Pre-remediation drift stays reported even though it was fixed.
        assert_eq!(value["drift_count"], 1);
        assert_eq!(value["capabilities"][0]["drift"], true);
        assert_eq!(value["capabilities"][0]["classification"], "auto_remediate");
        assert_eq!(value["capabilities"][0]["remediation"], "applied");
        assert_eq!(value["remediated_count"], 1);
        assert_eq!(value["compliance"]["overall"], "compliant");
        let back: ReconcileResult = serde_json::from_value(value).unwrap();
        assert_eq!(back, result);
    }

    #[test]
    fn remediation_outcomes_use_the_contract_spellings() {
        for (outcome, wire) in [
            (RemediationOutcome::Applied, "\"applied\""),
            (RemediationOutcome::None, "\"none\""),
            (RemediationOutcome::ApplyFailed, "\"apply_failed\""),
            (RemediationOutcome::VerifyFailed, "\"verify_failed\""),
            (RemediationOutcome::AlertOnly, "\"alert_only\""),
            (RemediationOutcome::Suppressed, "\"suppressed\""),
        ] {
            assert_eq!(serde_json::to_string(&outcome).unwrap(), wire);
            let back: RemediationOutcome = serde_json::from_str(wire).unwrap();
            assert_eq!(back, outcome);
        }
    }

    #[test]
    fn policy_methods_are_reads_with_strict_params() {
        // policy.effective takes no params.
        let reject = Request::parse_json_line(
            r#"{"v":1,"id":"1","method":"policy.effective","params":{"path":"x.y"}}"#,
        )
        .unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::InvalidParams);

        // policy.explain requires a path.
        let reject =
            Request::parse_json_line(r#"{"v":1,"id":"1","method":"policy.explain"}"#).unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::InvalidParams);
        let request = Request::parse_json_line(
            r#"{"v":1,"id":"1","method":"policy.explain","params":{"path":"security.firewall"}}"#,
        )
        .unwrap();
        match request.method {
            Method::PolicyExplain(params) => {
                assert_eq!(params.path.as_str(), "security.firewall");
            }
            other => panic!("wrong method: {other:?}"),
        }

        // There is no write-side policy method (contract section 8).
        let reject = Request::parse_json_line(
            r#"{"v":1,"id":"1","method":"policy.set","params":{"path":"security.firewall"}}"#,
        )
        .unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::UnknownMethod);
    }

    #[test]
    fn socket_path_is_the_squat_proof_directory() {
        assert_eq!(SOCKET_PATH, "/run/punard/punard.sock");
        assert!(
            !SOCKET_PATH.starts_with("/run/punar/"),
            "the socket must not live in the punar-writable M1 artifact dir"
        );
    }

    #[test]
    fn bounded_line_reader_frames_lines_and_refuses_oversize() {
        use std::io::BufReader;
        let input = b"one\ntwo\n".to_vec();
        let mut reader = BufReader::new(&input[..]);
        assert_eq!(
            read_line_bounded(&mut reader, MAX_REQUEST_LINE_BYTES).unwrap(),
            LineRead::Line("one".into())
        );
        assert_eq!(
            read_line_bounded(&mut reader, MAX_REQUEST_LINE_BYTES).unwrap(),
            LineRead::Line("two".into())
        );
        assert_eq!(
            read_line_bounded(&mut reader, MAX_REQUEST_LINE_BYTES).unwrap(),
            LineRead::Eof
        );

        // Over the bound: discarded, and the next line still frames — the
        // caller decides whether to close (section 2 says it does).
        let oversize = format!("{}\nnext\n", "x".repeat(64));
        let mut reader = BufReader::new(oversize.as_bytes());
        assert_eq!(
            read_line_bounded(&mut reader, 16).unwrap(),
            LineRead::TooLong
        );
        assert_eq!(
            read_line_bounded(&mut reader, 16).unwrap(),
            LineRead::Line("next".into())
        );

        // Trailing data without a terminator is still a line.
        let mut reader = BufReader::new(&b"tail"[..]);
        assert_eq!(
            read_line_bounded(&mut reader, 16).unwrap(),
            LineRead::Line("tail".into())
        );
    }
}
