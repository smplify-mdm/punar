//! NDJSON-over-UDS client for the `punard` wire contract (docs/api/ipc.md).
//!
//! The client sends exactly one request per connection and closes (contract
//! section 2). It never elevates itself: the daemon is the authorization
//! point, and `sudo punarctl …` is the M3 way to run mutating verbs.
//!
//! Failure surfaces in the SPEC section 73 voice — what happened, why, what
//! the next step is; never a bare errno. Server-produced errors already
//! carry that voice in `error.message` and are printed verbatim.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Contract socket path (docs/api/ipc.md section 1).
pub const DEFAULT_SOCKET: &str = "/run/punard/punard.sock";

/// The sibling `punar-agentd` socket (contract section 10.1): `agents.*`
/// lives there, everything else stays on punard's socket. One CLI, two
/// daemons, one envelope.
pub const AGENTD_SOCKET: &str = punar_common::agent::AGENTD_SOCKET_PATH;

/// The third socket (M9, contract section 16.1): the secret broker
/// `punar-secrets`. A separate daemon per SPEC section 11.4 — a broker
/// with no state directory at all is the strongest available form of the
/// "never written to disk" promise (milestone-9.md section 3.1).
pub const SECRETS_SOCKET: &str = "/run/punar-secrets/secrets.sock";

/// Method-name prefixes that route to [`AGENTD_SOCKET`] (contract section
/// 10.5: these names auto-route, even under `debug rpc`).
///
/// M10 adds three (contract sections 17.1, 17.8, 17.9): `alerts.*` is the
/// shadow-AI alert register, and `query.answer` / `queries.list` belong to
/// the daemon that owns the data an administrator asked about — never to
/// the courier that carried the question. Routing them here is not a
/// convenience: a probe that reached punard would get `unknown_method`
/// from the wrong daemon, and "the wrong thing said no" is the kind of
/// diagnostic that costs an afternoon.
pub const AGENTD_METHOD_PREFIXES: [&str; 4] = ["agents.", "alerts.", "query.", "queries."];

/// Method-name prefix that routes to [`SECRETS_SOCKET`] (contract section
/// 16.2). `approvals.*` and `privilege.*` deliberately do **not** appear
/// here: the approval engine is punard (one store, one audit path, one
/// expiry sweep — milestone-9.md section 3.2), and the broker is a client
/// of it, not a second copy of it.
pub const CREDENTIAL_METHOD_PREFIX: &str = "credential.";

/// The one protocol version this client speaks (contract section 3.3).
pub const PROTOCOL_VERSION: u64 = 1;

/// Client-side response budget (contract section 2). Connect on a Unix
/// socket does not block meaningfully, so the contract's 5 s connect budget
/// needs no timer; reads and writes get the 15 s response budget.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// M5 (contract sections 2, 7): `enroll start` runs a full enrollment
/// pipeline server-side (60 s processing bound), so its client budget is
/// raised to 90 s — for that one verb only.
pub const ENROLL_START_TIMEOUT: Duration = Duration::from_secs(90);

/// A live Flatpak metadata inspection may contact the configured remote.
pub const APP_INSPECT_TIMEOUT: Duration = Duration::from_secs(45);
/// A first Flatpak install may fetch a platform runtime; keep the budget
/// bounded but human-sized for slow links.
pub const APP_MUTATION_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Exit codes per Plate D-014 Sect III / docs/api/ipc.md section 7.
/// 0 = success and 2 = usage (owned by clap) complete the set.
pub const EXIT_ERROR: u8 = 1;
pub const EXIT_DENIED: u8 = 3;
/// Reserved since M3, **real as of M9**: a gated call created an approval
/// and executed nothing (contract section 14.1).
pub const EXIT_APPROVAL_REQUIRED: u8 = 4;
pub const EXIT_UNREACHABLE: u8 = 5;

/// The wire code that carries exit 4 (contract section 14.1).
pub const CODE_APPROVAL_REQUIRED: &str = "approval_required";
/// The M9 code for a lapsed approval or a lapsed credential TTL — distinct
/// from `conflict`, which means *already resolved* (contract section 14.1).
pub const CODE_EXPIRED: &str = "expired";

/// Request envelope (contract section 3.1). `params` is omitted — not
/// `{}` — for methods that take none.
#[derive(Serialize)]
struct Request<'a> {
    v: u64,
    id: &'a str,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a Value>,
}

/// Response envelope (contract section 3.2). `id` may be `null` when the
/// server could not parse a correlation id out of a malformed request.
#[derive(Deserialize)]
struct Response {
    v: u64,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<WireError>,
}

/// The structured error object (contract section 4).
///
/// `details` was ignored until M9. It is kept now for exactly one reason:
/// `approval_required` (contract section 14.1) carries the `approval_id`,
/// `expires_at`, `capability`, `resource` and `policy_ids` of a request
/// that was **not executed**, and SPEC section 73 requires the surface to
/// say what is pending, who decides and how long it lasts. Everything
/// else still renders from `message` alone.
#[derive(Debug, Deserialize)]
pub struct WireError {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: Option<Value>,
}

/// Everything that can go wrong with one call, already sorted by exit code.
#[derive(Debug)]
pub enum CallError {
    /// Could not connect, or the daemon went silent after connecting.
    /// Exit 5.
    Unreachable {
        path: PathBuf,
        why: String,
        next: String,
    },
    /// The daemon answered with a structured error. Its `message` is
    /// section-73 prose and is printed verbatim. Exit 3 for `denied`,
    /// 4 for a future `approval_required`, 1 otherwise.
    Server(WireError),
    /// The daemon answered with something this client cannot read. Exit 1.
    Protocol { why: String },
}

impl CallError {
    pub fn exit_code(&self) -> u8 {
        match self {
            CallError::Unreachable { .. } => EXIT_UNREACHABLE,
            CallError::Server(err) => match err.code.as_str() {
                "denied" => EXIT_DENIED,
                CODE_APPROVAL_REQUIRED => EXIT_APPROVAL_REQUIRED,
                _ => EXIT_ERROR,
            },
            CallError::Protocol { .. } => EXIT_ERROR,
        }
    }

    /// The server error object, when the failure came from a daemon.
    pub fn server(&self) -> Option<&WireError> {
        match self {
            CallError::Server(err) => Some(err),
            _ => None,
        }
    }

    /// True for the M9 gate error (contract section 14.1) — the one error
    /// that is not a failure: the request was recorded and is waiting on a
    /// human, and nothing was executed.
    pub fn is_approval_required(&self) -> bool {
        self.server()
            .is_some_and(|e| e.code == CODE_APPROVAL_REQUIRED)
    }

    /// The stderr text. Server messages pass through verbatim; local
    /// failures are composed in the same what/why/next voice.
    pub fn message(&self) -> String {
        match self {
            CallError::Unreachable { path, why, next } => format!(
                "The Punar daemon is not reachable at {}.\nWhy: {why}.\nNext step: {next}",
                path.display()
            ),
            CallError::Server(err) => err.message.clone(),
            CallError::Protocol { why } => format!(
                "The Punar daemon answered, but punarctl could not read the response.\n\
                 Why: {why}.\n\
                 Next step: punarctl and punard ship in the same image and must match — \
                 compare punarctl --version with the running daemon."
            ),
        }
    }
}

/// One-shot IPC client bound to a socket path and the daemon behind it
/// (the daemon's unit name is what an unreachable error tells the operator
/// to check).
pub struct Client {
    pub socket: PathBuf,
    service: &'static str,
}

impl Client {
    /// The client for one daemon: `--socket` (path or daemon name) wins,
    /// then the per-daemon environment override, then the contract path.
    pub fn for_target(target: Target, flag: Option<&Path>) -> Self {
        Client {
            socket: resolve_socket(target, flag),
            service: target.service(),
        }
    }

    /// Send `method` (+ optional params) and return the raw `result` value.
    pub fn call(&self, method: &str, params: Option<Value>) -> Result<Value, CallError> {
        self.call_with_timeout(method, params, RESPONSE_TIMEOUT)
    }

    /// [`Client::call`] with an explicit response budget — used by
    /// `enroll start` ([`ENROLL_START_TIMEOUT`], contract section 2).
    pub fn call_with_timeout(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, CallError> {
        let stream = UnixStream::connect(&self.socket).map_err(|e| self.connect_error(&e))?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        let id = format!("ctl-{}", std::process::id());
        let request = Request {
            v: PROTOCOL_VERSION,
            id: &id,
            method,
            params: params.as_ref(),
        };
        let mut line = serde_json::to_string(&request).map_err(|e| CallError::Protocol {
            why: format!("the request could not be encoded ({e})"),
        })?;
        line.push('\n');

        let mut writer = &stream;
        writer
            .write_all(line.as_bytes())
            .map_err(|e| self.io_error("the request could not be sent", &e, timeout))?;

        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        let read = reader
            .read_line(&mut response_line)
            .map_err(|e| self.io_error("no response arrived", &e, timeout))?;
        if read == 0 {
            return Err(CallError::Unreachable {
                path: self.socket.clone(),
                why: "the daemon closed the connection without answering".to_string(),
                next: self.check_service(),
            });
        }

        interpret(&response_line, &id)
    }

    /// "check the service: systemctl status <unit>" — the next step for
    /// every unreachable-daemon failure, naming the daemon actually dialed.
    fn check_service(&self) -> String {
        format!("check the service: systemctl status {}", self.service)
    }

    fn connect_error(&self, error: &io::Error) -> CallError {
        let (why, next) = match error.kind() {
            io::ErrorKind::NotFound => (
                "the control socket does not exist — the daemon has not created it".to_string(),
                self.check_service(),
            ),
            io::ErrorKind::PermissionDenied => (
                "permission denied — the control socket admits root and members of \
                 group punar only (personal defaults)"
                    .to_string(),
                "re-run as root (sudo punarctl …) or from the punar session user".to_string(),
            ),
            io::ErrorKind::ConnectionRefused => (
                "nothing is listening on the control socket — the daemon is not running"
                    .to_string(),
                self.check_service(),
            ),
            _ => (format!("connecting failed ({error})"), self.check_service()),
        };
        CallError::Unreachable {
            path: self.socket.clone(),
            why,
            next,
        }
    }

    /// Post-connect I/O failures. A daemon that accepted the connection but
    /// delivers no response is still an unreachable daemon (exit 5): the
    /// distinction that matters to scripts is "no answer", not which
    /// syscall noticed.
    fn io_error(&self, what: &str, error: &io::Error, timeout: Duration) -> CallError {
        let why = match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => format!(
                "{what} — the daemon did not answer within {} seconds",
                timeout.as_secs()
            ),
            _ => format!("{what} ({error})"),
        };
        CallError::Unreachable {
            path: self.socket.clone(),
            why,
            next: self.check_service(),
        }
    }
}

/// Which daemon a call is addressed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Punard,
    Agentd,
    /// M9 (contract section 16): the secret broker.
    Secrets,
}

impl Target {
    /// The daemon that owns `method` (contract sections 10.5, 16.2).
    ///
    /// `approvals.*` and `privilege.*` route to punard — they are not
    /// listed here because punard is the fallback, and that is the point:
    /// the approval store lives with the executor of the capabilities it
    /// gates (milestone-9.md section 3.2).
    pub fn of_method(method: &str) -> Target {
        if AGENTD_METHOD_PREFIXES
            .iter()
            .any(|prefix| method.starts_with(prefix))
        {
            Target::Agentd
        } else if method.starts_with(CREDENTIAL_METHOD_PREFIX) {
            Target::Secrets
        } else {
            Target::Punard
        }
    }

    fn default_socket(self) -> PathBuf {
        match self {
            Target::Punard => PathBuf::from(DEFAULT_SOCKET),
            Target::Agentd => PathBuf::from(AGENTD_SOCKET),
            Target::Secrets => PathBuf::from(SECRETS_SOCKET),
        }
    }

    fn socket_env(self) -> &'static str {
        match self {
            Target::Punard => "PUNARD_SOCKET",
            Target::Agentd => "PUNAR_AGENTD_SOCKET",
            Target::Secrets => "PUNAR_SECRETS_SOCKET",
        }
    }

    /// The unit named in the "next step" of an unreachable-daemon error.
    fn service(self) -> &'static str {
        match self {
            Target::Punard => "punard",
            Target::Agentd => "punar-agentd",
            Target::Secrets => "punar-secrets",
        }
    }

    fn socket_from_env_or_default(self) -> PathBuf {
        std::env::var_os(self.socket_env())
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| self.default_socket())
    }
}

/// Resolve the socket for `target`: an explicit `--socket` wins, then the
/// per-daemon environment override, then the contract default.
///
/// `--socket` also accepts the three daemon **names** rather than a path
/// (`--socket agentd`, `--socket secrets`), which is how the section 74.4
/// negative probes target a sibling socket without a second flag: a path
/// with no separator that names a daemon is a name, not a path — no file
/// can be addressed as a bare `agentd` anyway (a relative socket path
/// needs at least `./`).
pub fn resolve_socket(target: Target, flag: Option<&Path>) -> PathBuf {
    match flag.and_then(|p| p.to_str()) {
        Some("agentd") => Target::Agentd.socket_from_env_or_default(),
        Some("punard") => Target::Punard.socket_from_env_or_default(),
        Some("secrets") => Target::Secrets.socket_from_env_or_default(),
        _ => match flag {
            Some(path) => path.to_path_buf(),
            None => target.socket_from_env_or_default(),
        },
    }
}

/// Decode one response line against the envelope rules (contract
/// section 3.2): `v` must be 1, exactly one of `result`/`error`, and a
/// `result` must echo our correlation id. An `error` is accepted with any
/// id — a `malformed_request` reply may carry `id: null`.
fn interpret(line: &str, expected_id: &str) -> Result<Value, CallError> {
    let response: Response =
        serde_json::from_str(line.trim_end()).map_err(|e| CallError::Protocol {
            why: format!("the response line was not a valid envelope ({e})"),
        })?;
    if response.v != PROTOCOL_VERSION {
        return Err(CallError::Protocol {
            why: format!(
                "the daemon speaks protocol v{}, this punarctl speaks v{PROTOCOL_VERSION}",
                response.v
            ),
        });
    }
    match (response.result, response.error) {
        (Some(result), None) => {
            if response.id.as_deref() == Some(expected_id) {
                Ok(result)
            } else {
                Err(CallError::Protocol {
                    why: format!(
                        "the response answered request id {:?}, not ours",
                        response.id
                    ),
                })
            }
        }
        (None, Some(error)) => Err(CallError::Server(error)),
        _ => Err(CallError::Protocol {
            why: "the response did not carry exactly one of result/error".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_omits_params_when_none() {
        let request = Request {
            v: 1,
            id: "ctl-1",
            method: "status",
            params: None,
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"v":1,"id":"ctl-1","method":"status"}"#
        );
    }

    #[test]
    fn request_carries_params_when_present() {
        let params = json!({"capability": "system.hostname", "desired_state": "punar-m3"});
        let request = Request {
            v: 1,
            id: "ctl-2",
            method: "capabilities.set",
            params: Some(&params),
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"v":1,"id":"ctl-2","method":"capabilities.set","params":{"capability":"system.hostname","desired_state":"punar-m3"}}"#
        );
    }

    #[test]
    fn interpret_accepts_a_matching_result() {
        let value = interpret(r#"{"v":1,"id":"ctl-9","result":{"ok":true}}"#, "ctl-9").unwrap();
        assert_eq!(value, json!({"ok": true}));
    }

    #[test]
    fn interpret_rejects_a_foreign_id_on_results() {
        let err = interpret(r#"{"v":1,"id":"other","result":{}}"#, "ctl-9").unwrap_err();
        assert!(matches!(err, CallError::Protocol { .. }));
        assert_eq!(err.exit_code(), EXIT_ERROR);
    }

    #[test]
    fn interpret_surfaces_server_errors_with_exit_codes() {
        let denied = interpret(
            r#"{"v":1,"id":"ctl-9","error":{"code":"denied","message":"no."}}"#,
            "ctl-9",
        )
        .unwrap_err();
        assert_eq!(denied.exit_code(), EXIT_DENIED);
        assert_eq!(denied.message(), "no.");

        let unknown = interpret(
            r#"{"v":1,"id":null,"error":{"code":"unknown_method","message":"m"}}"#,
            "ctl-9",
        )
        .unwrap_err();
        assert_eq!(unknown.exit_code(), EXIT_ERROR);

        let approval = interpret(
            r#"{"v":1,"id":"ctl-9","error":{"code":"approval_required","message":"wait"}}"#,
            "ctl-9",
        )
        .unwrap_err();
        assert_eq!(approval.exit_code(), EXIT_APPROVAL_REQUIRED);
    }

    #[test]
    fn interpret_rejects_wrong_version_and_malformed_envelopes() {
        assert!(matches!(
            interpret(r#"{"v":2,"id":"ctl-9","result":{}}"#, "ctl-9"),
            Err(CallError::Protocol { .. })
        ));
        assert!(matches!(
            interpret("not json", "ctl-9"),
            Err(CallError::Protocol { .. })
        ));
        assert!(matches!(
            interpret(r#"{"v":1,"id":"ctl-9"}"#, "ctl-9"),
            Err(CallError::Protocol { .. })
        ));
        assert!(matches!(
            interpret(
                r#"{"v":1,"id":"ctl-9","result":{},"error":{"code":"internal","message":"x"}}"#,
                "ctl-9"
            ),
            Err(CallError::Protocol { .. })
        ));
    }

    #[test]
    fn unreachable_message_is_voiced_not_an_errno() {
        let client = Client::for_target(Target::Punard, None);
        let err = client.connect_error(&io::Error::from(io::ErrorKind::PermissionDenied));
        assert_eq!(err.exit_code(), EXIT_UNREACHABLE);
        let message = err.message();
        assert!(message.contains("not reachable"));
        assert!(message.contains("group punar"));
        assert!(message.contains("Next step:"));
        assert!(!message.contains("EPERM"));
    }

    /// Routing (contract section 10.5): `agents.*` belongs to the sibling
    /// daemon, every other method to punard — and the unreachable error
    /// names the unit the operator should actually check.
    #[test]
    fn agents_methods_route_to_the_sibling_socket() {
        assert_eq!(Target::of_method("agents.list"), Target::Agentd);
        assert_eq!(Target::of_method("agents.bogus"), Target::Agentd);
        assert_eq!(Target::of_method("status"), Target::Punard);
        assert_eq!(Target::of_method("admin.query"), Target::Punard);

        let agentd = Client::for_target(Target::Agentd, None);
        assert_eq!(agentd.socket, PathBuf::from(AGENTD_SOCKET));
        let message = agentd
            .connect_error(&io::Error::from(io::ErrorKind::NotFound))
            .message();
        assert!(
            message.contains("systemctl status punar-agentd"),
            "{message}"
        );
        assert!(!message.contains("status punard\n"), "{message}");
    }

    /// M9 routing (contract section 16.2): `credential.*` belongs to the
    /// broker; `approvals.*` and `privilege.*` stay on punard, because the
    /// approval store lives with the executor of the gated capability.
    #[test]
    fn credential_methods_route_to_the_broker_and_approvals_do_not() {
        assert_eq!(Target::of_method("credential.request"), Target::Secrets);
        assert_eq!(Target::of_method("credential.classes"), Target::Secrets);
        assert_eq!(Target::of_method("credential.show"), Target::Secrets);
        assert_eq!(Target::of_method("approvals.resolve"), Target::Punard);
        assert_eq!(Target::of_method("privilege.request"), Target::Punard);
        assert_eq!(Target::of_method("secrets.dump"), Target::Punard);

        let secrets = Client::for_target(Target::Secrets, None);
        assert_eq!(secrets.socket, PathBuf::from(SECRETS_SOCKET));
        let message = secrets
            .connect_error(&io::Error::from(io::ErrorKind::NotFound))
            .message();
        assert!(
            message.contains("systemctl status punar-secrets"),
            "{message}"
        );
    }

    /// The M9 gate error is not a failure: it carries the machine data the
    /// section 73 surface needs, and it exits 4.
    #[test]
    fn approval_required_carries_its_details_and_exits_four() {
        let err = interpret(
            r#"{"v":1,"id":"ctl-9","error":{"code":"approval_required","message":"pending",
                "details":{"approval_id":"apr_7c1d9a4e","expires_at":"2026-08-25T10:05:00Z",
                "capability":"security.firewall","resource":"disabled",
                "decision":"approval_required","policy_ids":["personal-defaults"]}}}"#,
            "ctl-9",
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), EXIT_APPROVAL_REQUIRED);
        assert!(err.is_approval_required());
        let details = err.server().unwrap().details.as_ref().unwrap();
        assert_eq!(details["approval_id"], json!("apr_7c1d9a4e"));
        assert_eq!(details["decision"], json!("approval_required"));
    }

    /// An error without `details` still parses — every pre-M9 error shape
    /// is unchanged (contract section 3.3 tolerance).
    #[test]
    fn errors_without_details_still_parse() {
        let err = interpret(
            r#"{"v":1,"id":"ctl-9","error":{"code":"expired","message":"gone"}}"#,
            "ctl-9",
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), EXIT_ERROR);
        assert!(!err.is_approval_required());
        assert_eq!(err.server().unwrap().code, CODE_EXPIRED);
        assert!(err.server().unwrap().details.is_none());
    }

    /// `--socket agentd` is a daemon **name**, not a path: it is how the
    /// section 74.4 negative probes reach the sibling socket.
    #[test]
    fn the_socket_flag_accepts_a_daemon_name_or_a_path() {
        assert_eq!(
            resolve_socket(Target::Punard, Some(Path::new("agentd"))),
            PathBuf::from(AGENTD_SOCKET)
        );
        assert_eq!(
            resolve_socket(Target::Agentd, Some(Path::new("punard"))),
            PathBuf::from(DEFAULT_SOCKET)
        );
        assert_eq!(
            resolve_socket(Target::Punard, Some(Path::new("secrets"))),
            PathBuf::from(SECRETS_SOCKET)
        );
        assert_eq!(
            resolve_socket(Target::Agentd, Some(Path::new("/tmp/x.sock"))),
            PathBuf::from("/tmp/x.sock")
        );
        assert_eq!(
            resolve_socket(Target::Agentd, None),
            PathBuf::from(AGENTD_SOCKET)
        );
    }
}
