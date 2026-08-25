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

use crate::audit::POLICY_PERSONAL_DEFAULTS;
use crate::{AuditEvent, CapabilityDescriptor, CapabilityId};

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

/// `punarctl` process exit codes (Plate D-014 section III; docs/api/ipc.md
/// section 7).
pub const EXIT_OK: i32 = 0;
/// Runtime/daemon error (every wire error except `denied`).
pub const EXIT_ERROR: i32 = 1;
/// Usage error (clap).
pub const EXIT_USAGE: i32 = 2;
/// Authorization denied (`denied` wire error).
pub const EXIT_DENIED: i32 = 3;
/// Approval required — reserved until Milestone 9.
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
}

impl ErrorCode {
    /// All wire codes, in contract-table order.
    pub const ALL: [ErrorCode; 9] = [
        ErrorCode::MalformedRequest,
        ErrorCode::UnsupportedVersion,
        ErrorCode::UnknownMethod,
        ErrorCode::InvalidParams,
        ErrorCode::Denied,
        ErrorCode::NotFound,
        ErrorCode::ApplyFailed,
        ErrorCode::VerifyFailed,
        ErrorCode::Internal,
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
        }
    }

    /// Whether the server closes the connection after responding with this
    /// code (contract section 2: only framing violations do).
    pub fn closes_connection(self) -> bool {
        self == ErrorCode::MalformedRequest
    }

    /// The `punarctl` exit code this error maps to (Plate D-014 section
    /// III): [`EXIT_DENIED`] for `denied`, [`EXIT_ERROR`] otherwise.
    /// [`EXIT_USAGE`] and [`EXIT_DAEMON_UNREACHABLE`] arise client-side and
    /// never from a wire error; [`EXIT_APPROVAL_REQUIRED`] is reserved
    /// until Milestone 9 introduces an approval flow.
    pub fn suggested_exit_code(self) -> i32 {
        match self {
            ErrorCode::Denied => EXIT_DENIED,
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

    /// The canonical Milestone 3 root-only denial (contract section 3.2
    /// example; SPEC section 73 voice). `target` names what was refused
    /// (usually a capability id), `retry_command` is the full command to
    /// re-run as root. When `capability` is given it is included in
    /// `details.capability`.
    ///
    /// The message deliberately contains both "administrator" and "personal
    /// defaults" — the section 74.4 in-VM check greps for exactly those.
    pub fn denied_needs_root(target: &str, capability: Option<&str>, retry_command: &str) -> Self {
        let mut details = json!({
            "decision": "deny",
            "policy_ids": [POLICY_PERSONAL_DEFAULTS],
        });
        if let (Some(map), Some(capability)) = (details.as_object_mut(), capability) {
            map.insert("capability".to_string(), Value::String(capability.into()));
        }
        IpcError::with_details(
            ErrorCode::Denied,
            format!(
                "Changing {target} needs administrator privileges.\n\
                 Policy: personal defaults — just-in-time elevation arrives in Milestone 9.\n\
                 Next step: re-run as root: {retry_command}"
            ),
            details,
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

/// The complete, closed Milestone 3 method set.
///
/// See the module docs for the section 60 guarantee. Summary: no variant
/// carries anything executable, the enum is exhaustive-matched (adding a
/// variant is a compile error until every table names it), and unknown
/// method strings never become a `Method`.
#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    /// `status` — daemon/device summary. Read; any connected peer.
    Status,
    /// `capabilities.list` — all registry descriptors, observed live. Read.
    CapabilitiesList,
    /// `capabilities.get` — one descriptor. Read.
    CapabilitiesGet(CapabilitiesGetParams),
    /// `capabilities.set` — mutate one capability. Root-only in M3; always
    /// audited.
    CapabilitiesSet(CapabilitiesSetParams),
    /// `audit.tail` — last `n` audit events through the daemon. Read.
    AuditTail(AuditTailParams),
    /// `reconcile` — M3: re-observe, re-verify, **report** drift (no
    /// remediation until M4). Root-only; always audited.
    Reconcile,
}

impl Method {
    /// Every wire method name, in contract-table order.
    pub const NAMES: [&'static str; 6] = [
        "status",
        "capabilities.list",
        "capabilities.get",
        "capabilities.set",
        "audit.tail",
        "reconcile",
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
        }
    }

    /// Whether the M3 authorization rule (`personal-defaults`) restricts
    /// this method to uid 0. Exhaustive on purpose: a new method must take
    /// an explicit authorization stance to compile.
    pub fn requires_root(&self) -> bool {
        match self {
            Method::Status
            | Method::CapabilitiesList
            | Method::CapabilitiesGet(_)
            | Method::AuditTail(_) => false,
            Method::CapabilitiesSet(_) | Method::Reconcile => true,
        }
    }

    /// The method's params as a wire value (`None` for no-params methods).
    pub fn params_value(&self) -> Option<Value> {
        let params = match self {
            Method::Status | Method::CapabilitiesList | Method::Reconcile => return None,
            Method::CapabilitiesGet(p) => serde_json::to_value(p),
            Method::CapabilitiesSet(p) => serde_json::to_value(p),
            Method::AuditTail(p) => serde_json::to_value(p),
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

        // 6. Method table + typed params.
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

/// Daemon mode. `personal` until enrollment lands (M5); design language
/// section 8: enrollment adds fields/values, it never redraws the base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Personal,
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
}

/// `audit.tail` result (contract section 5.5). Events newest **last**.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditTailResult {
    pub events: Vec<AuditEvent>,
}

/// `reconcile` result (contract section 5.6): M3 reports drift, never
/// remediates (remediation + policy merge are M4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconcileResult {
    /// RFC 3339.
    pub reconciled_at: String,
    /// Number of entries with `drift: true`.
    pub drift_count: u64,
    pub capabilities: Vec<ReconcileEntry>,
}

/// One capability's drift report inside [`ReconcileResult`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconcileEntry {
    pub capability: CapabilityId,
    pub desired_state: Value,
    pub current_state: Value,
    /// `current_state != desired_state`.
    pub drift: bool,
    /// Whether the verification mechanism itself ran successfully.
    pub verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for code in ErrorCode::ALL {
            if code != ErrorCode::Denied {
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
    fn only_set_and_reconcile_require_root() {
        for method in every_method() {
            let expected = matches!(method.name(), "capabilities.set" | "reconcile");
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
        })
        .unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("org".to_string(), json!({"added": "in M5"}));
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
        };
        let value = serde_json::to_value(&set).unwrap();
        assert_eq!(value["changed"], true);
        let back: CapabilitiesSetResult = serde_json::from_value(value).unwrap();
        assert_eq!(back, set);
    }

    #[test]
    fn mode_rejects_unknown_values_in_m3() {
        // M5 will add enrollment alongside a client that understands it;
        // daemon and CLI always ship in the same image.
        assert!(serde_json::from_str::<Mode>("\"managed\"").is_err());
        assert_eq!(
            serde_json::to_string(&Mode::Personal).unwrap(),
            "\"personal\""
        );
    }

    #[test]
    fn socket_path_is_the_squat_proof_directory() {
        assert_eq!(SOCKET_PATH, "/run/punard/punard.sock");
        assert!(
            !SOCKET_PATH.starts_with("/run/punar/"),
            "the socket must not live in the punar-writable M1 artifact dir"
        );
    }
}
