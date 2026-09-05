//! The `punar-agentd` client used by the managed launch path
//! (docs/api/ipc.md section 10 — the sibling socket).
//!
//! One request per connection, NDJSON, `v: 1`, id echo, result XOR error —
//! all of it the shared contract in `punar_common::ipc` /
//! `punar_common::agent`, which this module *uses* rather than re-spells:
//! the request line comes from [`punar_common::agent::AgentRequest`] and
//! the response is parsed by [`punar_common::ipc::Response`]. If the
//! contract changes, this client fails to compile rather than drifting.
//!
//! Failures speak SPEC section 73 — what happened, why, and the next step.
//! Server errors already carry that voice in `error.message` and are
//! printed verbatim.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use punar_common::agent::{
    AgentMethod, AgentRequest, AgentsEndParams, AgentsEndResult, AgentsRegisterParams,
    AgentsRegisterResult,
};
use punar_common::ipc::{PROTOCOL_VERSION, Response, ResponseBody};

/// Contract socket path (`punar_common::agent::AGENTD_SOCKET_PATH`).
pub const DEFAULT_SOCKET: &str = punar_common::agent::AGENTD_SOCKET_PATH;

/// Client response budget (contract section 2, applied to the sibling
/// socket by section 10.1).
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// The authoritative production socket.  This launch boundary deliberately
/// does not honor an environment override: the invoking user controls their
/// environment before confinement, so an override could impersonate agentd.
pub fn socket_path() -> PathBuf {
    PathBuf::from(DEFAULT_SOCKET)
}

/// Everything one `agents.*` call can fail with.
#[derive(Debug)]
pub enum AgentdError {
    /// Could not connect, or the daemon went silent.
    Unreachable { path: PathBuf, why: String },
    /// The daemon answered with a structured error; `message` is already
    /// section-73 prose and is shown verbatim.
    Server { code: String, message: String },
    /// The daemon answered with something this client cannot read.
    Protocol { why: String },
}

impl AgentdError {
    /// The full operator-facing text: what happened, why, next step.
    pub fn message(&self) -> String {
        match self {
            AgentdError::Unreachable { path, why } => format!(
                "The AI agent registry is not reachable at {}.\n\
                 Why: {why}.\n\
                 A managed agent session that is not registered is a contradiction — \
                 punar-env refuses to create one, so nothing was launched (or the \
                 session that had started was stopped again).\n\
                 Next step: check the service: systemctl status punar-agentd",
                path.display()
            ),
            AgentdError::Server { message, .. } => message.clone(),
            AgentdError::Protocol { why } => format!(
                "The AI agent registry answered, but punar-env could not read the response.\n\
                 Why: {why}.\n\
                 Next step: punar-env and punar-agentd ship in the same image and must \
                 match — compare punar-env --version with the running daemon."
            ),
        }
    }
}

/// One-shot client bound to a socket path.
pub struct Client {
    socket: PathBuf,
}

impl Client {
    pub fn new(socket: PathBuf) -> Client {
        Client { socket }
    }

    /// The client for the system's fixed contract path.
    pub fn discover() -> Client {
        Client::new(socket_path())
    }

    /// `agents.register` — called once the agent process is running in its
    /// scope. The daemon verifies peer credentials and the cgroup, then
    /// **computes** the classification (ipc.md section 10.2); whatever it
    /// returns is what the launcher reports.
    pub fn register(
        &self,
        params: AgentsRegisterParams,
    ) -> Result<AgentsRegisterResult, AgentdError> {
        let value = self.call(AgentMethod::Register(Box::new(params)))?;
        serde_json::from_value(value).map_err(|e| AgentdError::Protocol {
            why: format!("the agents.register result did not parse ({e})"),
        })
    }

    /// `agents.end` — the session's owner marks it ended.
    pub fn end(&self, session_id: &str) -> Result<AgentsEndResult, AgentdError> {
        let value = self.call(AgentMethod::End(AgentsEndParams {
            session_id: session_id.to_string(),
        }))?;
        serde_json::from_value(value).map_err(|e| AgentdError::Protocol {
            why: format!("the agents.end result did not parse ({e})"),
        })
    }

    fn call(&self, method: AgentMethod) -> Result<serde_json::Value, AgentdError> {
        let stream = UnixStream::connect(&self.socket).map_err(|e| self.connect_error(&e))?;
        let _ = stream.set_read_timeout(Some(RESPONSE_TIMEOUT));
        let _ = stream.set_write_timeout(Some(RESPONSE_TIMEOUT));

        let request = AgentRequest {
            id: format!("env-{}", std::process::id()),
            method,
        };
        let line = request.to_json_line();
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
            return Err(AgentdError::Unreachable {
                path: self.socket.clone(),
                why: "the daemon closed the connection without answering".to_string(),
            });
        }
        interpret(&response_line, &request.id)
    }

    fn connect_error(&self, error: &std::io::Error) -> AgentdError {
        let why = match error.kind() {
            std::io::ErrorKind::NotFound => {
                "the registry socket does not exist — punar-agentd has not created it".to_string()
            }
            std::io::ErrorKind::PermissionDenied => {
                "permission denied — the registry socket admits root and members of group \
                 punar only"
                    .to_string()
            }
            std::io::ErrorKind::ConnectionRefused => {
                "nothing is listening on the registry socket — punar-agentd is not running"
                    .to_string()
            }
            _ => format!("connecting failed ({error})"),
        };
        AgentdError::Unreachable {
            path: self.socket.clone(),
            why,
        }
    }

    fn io_error(&self, what: &str, error: &std::io::Error) -> AgentdError {
        let why = match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => format!(
                "{what} — the daemon did not answer within {} seconds",
                RESPONSE_TIMEOUT.as_secs()
            ),
            _ => format!("{what} ({error})"),
        };
        AgentdError::Unreachable {
            path: self.socket.clone(),
            why,
        }
    }
}

/// Decode one response line against the envelope rules (contract section
/// 3.2, applied to the sibling socket by section 10.1): `v` must be 1,
/// exactly one of result/error (enforced by the shared type), and a
/// `result` must echo our correlation id.
fn interpret(line: &str, expected_id: &str) -> Result<serde_json::Value, AgentdError> {
    let response =
        Response::parse_json_line(line.trim_end()).map_err(|e| AgentdError::Protocol {
            why: format!("the response line was not a valid envelope ({e})"),
        })?;
    if response.v != PROTOCOL_VERSION {
        return Err(AgentdError::Protocol {
            why: format!(
                "the daemon speaks protocol v{}, this punar-env speaks v{PROTOCOL_VERSION}",
                response.v
            ),
        });
    }
    match response.body {
        ResponseBody::Result(result) => {
            if response.id.as_deref() == Some(expected_id) {
                Ok(result)
            } else {
                Err(AgentdError::Protocol {
                    why: format!(
                        "the response answered request id {:?}, not ours",
                        response.id
                    ),
                })
            }
        }
        ResponseBody::Error(error) => Err(AgentdError::Server {
            code: error.code.as_str().to_string(),
            message: error.message,
        }),
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! A mock agentd on a tempdir socket — the contract's own envelope,
    //! used by the client tests here and the launch lifecycle tests.

    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use serde_json::{Value, json};

    /// Every request line the mock received, in order.
    pub type Seen = Arc<Mutex<Vec<Value>>>;

    /// Start a mock daemon whose responder maps a request to
    /// `Ok(result)` / `Err(error)`. Returns the socket path and the
    /// recorded request log.
    pub fn start(responder: fn(&Value) -> Result<Value, Value>) -> (PathBuf, Seen) {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "punar-env-agentd-mock-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create mock dir");
        let path = dir.join("agentd.sock");
        let listener = UnixListener::bind(&path).expect("bind mock socket");
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let recorder = Arc::clone(&recorder);
                thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().expect("clone mock stream"));
                    let mut writer = stream;
                    let mut line = String::new();
                    while let Ok(read) = reader.read_line(&mut line) {
                        if read == 0 {
                            break;
                        }
                        let request: Value =
                            serde_json::from_str(line.trim_end()).expect("request is JSON");
                        recorder.lock().unwrap().push(request.clone());
                        let id = request["id"].clone();
                        let envelope = match responder(&request) {
                            Ok(result) => json!({"v": 1, "id": id, "result": result}),
                            Err(error) => json!({"v": 1, "id": id, "error": error}),
                        };
                        writeln!(writer, "{envelope}").expect("write response");
                        line.clear();
                    }
                });
            }
        });
        (path, seen)
    }

    /// A session row echoing the register params, classified `managed`.
    pub fn managed_session(params: &Value) -> Value {
        json!({
            "session_id": params["session_id"],
            "agent": params["agent"],
            "version": params["version"],
            "process_id": params["process_id"],
            "user": "punar",
            "project": params["project"],
            "environment": params["environment"],
            "status": "active",
            "classification": "managed",
            "started_at": "2026-08-25T09:58:40Z"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::testing;
    use super::*;
    use punar_common::agent::{AgentClassification, AuthorityRow, AuthoritySummary};
    use serde_json::{Value, json};

    fn params() -> AgentsRegisterParams {
        AgentsRegisterParams {
            session_id: "agt_4f21c09ab3e1".to_string(),
            agent: "claude-code".to_string(),
            version: "mock".to_string(),
            process_id: 2143,
            project: "atlas".to_string(),
            environment: "host".to_string(),
            authority: AuthoritySummary {
                policy_citation: "personal-defaults".to_string(),
                rows: vec![AuthorityRow {
                    zone: "filesystem.project".to_string(),
                    decision: "read_write".to_string(),
                    enforcement: "declared · M9".to_string(),
                }],
            },
        }
    }

    fn ok_responder(request: &Value) -> Result<Value, Value> {
        match request["method"].as_str().unwrap_or_default() {
            "agents.register" => {
                let p = &request["params"];
                Ok(json!({
                    "session": testing::managed_session(p),
                    "classification": "managed"
                }))
            }
            "agents.end" => {
                let mut session = testing::managed_session(&json!({
                    "session_id": request["params"]["session_id"],
                    "agent": "claude-code",
                    "version": "mock",
                    "process_id": 2143,
                    "project": "atlas",
                    "environment": "host"
                }));
                session["status"] = json!("ended");
                Ok(json!({ "session": session }))
            }
            other => Err(json!({
                "code": "unknown_method",
                "message": format!("The method {other:?} does not exist.")
            })),
        }
    }

    fn denied_responder(_request: &Value) -> Result<Value, Value> {
        Err(json!({
            "code": "denied",
            "message": "Registering an agent session needs a process you own.\n\
                        Next step: launch the agent from your own session."
        }))
    }

    #[test]
    fn register_sends_the_contract_params_and_reports_the_computed_class() {
        let (socket, seen) = testing::start(ok_responder);
        let client = Client::new(socket);
        let result = client.register(params()).expect("register succeeds");
        assert_eq!(result.classification, AgentClassification::Managed);
        assert_eq!(result.session.record.session_id, "agt_4f21c09ab3e1");
        // The daemon stamps user/started_at; the launcher never sends them.
        assert_eq!(result.session.record.user, "punar");

        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let sent = &requests[0];
        assert_eq!(sent["v"], 1);
        assert_eq!(sent["method"], "agents.register");
        let sent_params = sent["params"].as_object().expect("params object");
        let mut keys: Vec<&str> = sent_params.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "agent",
                "authority",
                "environment",
                "process_id",
                "project",
                "session_id",
                "version"
            ],
            "classification, user and started_at are the daemon's to decide"
        );
        assert_eq!(
            sent_params["authority"]["policy_citation"],
            "personal-defaults"
        );
    }

    #[test]
    fn end_marks_the_session_ended() {
        let (socket, seen) = testing::start(ok_responder);
        let client = Client::new(socket);
        let result = client.end("agt_4f21c09ab3e1").expect("end succeeds");
        assert_eq!(
            result.session.record.status,
            punar_common::agent::AgentStatus::Ended
        );
        assert_eq!(seen.lock().unwrap()[0]["method"], "agents.end");
    }

    #[test]
    fn a_server_denial_is_printed_verbatim() {
        let (socket, _seen) = testing::start(denied_responder);
        let err = Client::new(socket).register(params()).unwrap_err();
        match &err {
            AgentdError::Server { code, .. } => assert_eq!(code, "denied"),
            other => panic!("expected a server error, got {other:?}"),
        }
        assert!(err.message().contains("Next step"), "{}", err.message());
    }

    #[test]
    fn an_absent_socket_is_unreachable_in_the_section_73_voice() {
        let client = Client::new(PathBuf::from("/nonexistent/punar-agentd/agentd.sock"));
        let err = client.end("agt_1").unwrap_err();
        let message = err.message();
        assert!(message.contains("not reachable"), "{message}");
        assert!(
            message.contains("systemctl status punar-agentd"),
            "{message}"
        );
        assert!(!message.contains("ENOENT"), "{message}");
    }

    #[test]
    fn a_foreign_correlation_id_is_a_protocol_error() {
        let err = interpret(r#"{"v":1,"id":"other","result":{}}"#, "env-1").unwrap_err();
        assert!(matches!(err, AgentdError::Protocol { .. }));
        let err = interpret(r#"{"v":2,"id":"env-1","result":{}}"#, "env-1").unwrap_err();
        assert!(matches!(err, AgentdError::Protocol { .. }));
        let err = interpret("not an envelope", "env-1").unwrap_err();
        assert!(matches!(err, AgentdError::Protocol { .. }));
    }
}
