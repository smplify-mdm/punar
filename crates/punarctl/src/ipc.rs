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
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Contract socket path (docs/api/ipc.md section 1).
pub const DEFAULT_SOCKET: &str = "/run/punard/punard.sock";

/// The one protocol version this client speaks (contract section 3.3).
pub const PROTOCOL_VERSION: u64 = 1;

/// Client-side response budget (contract section 2). Connect on a Unix
/// socket does not block meaningfully, so the contract's 5 s connect budget
/// needs no timer; reads and writes get the 15 s response budget.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// Exit codes per Plate D-014 Sect III / docs/api/ipc.md section 7.
/// 0 = success and 2 = usage (owned by clap) complete the set.
pub const EXIT_ERROR: u8 = 1;
pub const EXIT_DENIED: u8 = 3;
pub const EXIT_APPROVAL_REQUIRED: u8 = 4; // reserved until Milestone 9
pub const EXIT_UNREACHABLE: u8 = 5;

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

/// The structured error object (contract section 4). `details` is machine
/// data this CLI does not render; serde ignores it.
#[derive(Debug, Deserialize)]
pub struct WireError {
    pub code: String,
    pub message: String,
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
                "approval_required" => EXIT_APPROVAL_REQUIRED,
                _ => EXIT_ERROR,
            },
            CallError::Protocol { .. } => EXIT_ERROR,
        }
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

/// One-shot IPC client bound to a socket path.
pub struct Client {
    pub socket: PathBuf,
}

impl Client {
    pub fn new(socket: PathBuf) -> Self {
        Client { socket }
    }

    /// Send `method` (+ optional params) and return the raw `result` value.
    pub fn call(&self, method: &str, params: Option<Value>) -> Result<Value, CallError> {
        let stream = UnixStream::connect(&self.socket).map_err(|e| self.connect_error(&e))?;
        let _ = stream.set_read_timeout(Some(RESPONSE_TIMEOUT));
        let _ = stream.set_write_timeout(Some(RESPONSE_TIMEOUT));

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
            .map_err(|e| self.io_error("the request could not be sent", &e))?;

        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        let read = reader
            .read_line(&mut response_line)
            .map_err(|e| self.io_error("no response arrived", &e))?;
        if read == 0 {
            return Err(CallError::Unreachable {
                path: self.socket.clone(),
                why: "the daemon closed the connection without answering".to_string(),
                next: CHECK_SERVICE.to_string(),
            });
        }

        interpret(&response_line, &id)
    }

    fn connect_error(&self, error: &io::Error) -> CallError {
        let (why, next) = match error.kind() {
            io::ErrorKind::NotFound => (
                "the control socket does not exist — the daemon has not created it".to_string(),
                CHECK_SERVICE.to_string(),
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
                CHECK_SERVICE.to_string(),
            ),
            _ => (
                format!("connecting failed ({error})"),
                CHECK_SERVICE.to_string(),
            ),
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
    fn io_error(&self, what: &str, error: &io::Error) -> CallError {
        let why = match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => format!(
                "{what} — the daemon did not answer within {} seconds",
                RESPONSE_TIMEOUT.as_secs()
            ),
            _ => format!("{what} ({error})"),
        };
        CallError::Unreachable {
            path: self.socket.clone(),
            why,
            next: CHECK_SERVICE.to_string(),
        }
    }
}

const CHECK_SERVICE: &str = "check the service: systemctl status punard";

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
        let client = Client::new(PathBuf::from("/run/punard/punard.sock"));
        let err = client.connect_error(&io::Error::from(io::ErrorKind::PermissionDenied));
        assert_eq!(err.exit_code(), EXIT_UNREACHABLE);
        let message = err.message();
        assert!(message.contains("not reachable"));
        assert!(message.contains("group punar"));
        assert!(message.contains("Next step:"));
        assert!(!message.contains("EPERM"));
    }
}
