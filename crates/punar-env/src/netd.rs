//! Narrow client for the managed-launch network barrier.
//!
//! This module can ask exactly one question: has punar-netd reconciled and
//! read back the nftables rule for this exact registered session?  It has no
//! status/count fallback and the production socket cannot be redirected by an
//! environment variable controlled before confinement.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use punar_common::ipc::{PROTOCOL_VERSION, Response, ResponseBody};
use punar_common::network::{
    NetworkMethod, NetworkRequest, NetworkSessionReadyParams, NetworkSessionReadyResult,
};

pub const DEFAULT_SOCKET: &str = punar_common::network::NETD_SOCKET_PATH;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub enum NetdError {
    Unreachable { path: PathBuf, why: String },
    Server { code: String, message: String },
    Protocol { why: String },
}

impl NetdError {
    pub fn message(&self) -> String {
        match self {
            Self::Unreachable { path, why } => format!(
                "The managed-agent network barrier is not reachable at {}.\n\
                 Why: {why}.\n\
                 The adapter was not released and its scope will be stopped.\n\
                 Next step: check the service: systemctl status punar-netd",
                path.display()
            ),
            Self::Server { message, .. } => message.clone(),
            Self::Protocol { why } => format!(
                "The managed-agent network barrier answered, but punar-env could not verify its response.\n\
                 Why: {why}.\n\
                 The adapter was not released and its scope will be stopped.\n\
                 Next step: punar-env and punar-netd must come from the same Punar image."
            ),
        }
    }
}

pub struct Client {
    socket: PathBuf,
}

impl Client {
    pub fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    pub fn discover() -> Self {
        Self::new(PathBuf::from(DEFAULT_SOCKET))
    }

    pub fn session_ready(&self, session_id: &str) -> Result<NetworkSessionReadyResult, NetdError> {
        let request = NetworkRequest {
            id: format!("env-gate-{}", std::process::id()),
            method: NetworkMethod::SessionReady(NetworkSessionReadyParams {
                session_id: session_id.to_string(),
            }),
        };
        let stream = UnixStream::connect(&self.socket).map_err(|error| NetdError::Unreachable {
            path: self.socket.clone(),
            why: format!("connecting failed ({error})"),
        })?;
        let _ = stream.set_read_timeout(Some(RESPONSE_TIMEOUT));
        let _ = stream.set_write_timeout(Some(RESPONSE_TIMEOUT));
        let line = request.to_json_line();
        let mut writer = &stream;
        writer
            .write_all(line.as_bytes())
            .map_err(|error| NetdError::Unreachable {
                path: self.socket.clone(),
                why: format!("the readiness request could not be sent ({error})"),
            })?;

        let mut response_line = String::new();
        let read = BufReader::new(&stream)
            .read_line(&mut response_line)
            .map_err(|error| NetdError::Unreachable {
                path: self.socket.clone(),
                why: format!(
                    "no exact-session response arrived within {} seconds ({error})",
                    RESPONSE_TIMEOUT.as_secs()
                ),
            })?;
        if read == 0 {
            return Err(NetdError::Unreachable {
                path: self.socket.clone(),
                why: "the service closed the connection without answering".to_string(),
            });
        }
        let response = Response::parse_json_line(response_line.trim_end()).map_err(|error| {
            NetdError::Protocol {
                why: format!("the response was not a valid envelope ({error})"),
            }
        })?;
        if response.v != PROTOCOL_VERSION {
            return Err(NetdError::Protocol {
                why: format!(
                    "punar-netd speaks protocol v{}, this gate speaks v{PROTOCOL_VERSION}",
                    response.v
                ),
            });
        }
        match response.body {
            ResponseBody::Result(value) if response.id.as_deref() == Some(&request.id) => {
                let result: NetworkSessionReadyResult =
                    serde_json::from_value(value).map_err(|error| NetdError::Protocol {
                        why: format!("the session-ready result did not parse ({error})"),
                    })?;
                if result.session_id != session_id {
                    return Err(NetdError::Protocol {
                        why: format!(
                            "the response proved session {}, not requested session {session_id}",
                            result.session_id
                        ),
                    });
                }
                Ok(result)
            }
            ResponseBody::Result(_) => Err(NetdError::Protocol {
                why: "the response correlation id did not match this request".to_string(),
            }),
            ResponseBody::Error(error) => Err(NetdError::Server {
                code: error.code.as_str().to_string(),
                message: error.message,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use punar_common::network::{NetworkSessionEnforcement, NetworkSessionReadyState};
    use serde_json::{Value, json};
    use std::fs;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    static NEXT_SOCKET: AtomicU64 = AtomicU64::new(1);

    fn one_response(response: Value) -> (PathBuf, Arc<Mutex<Option<Value>>>) {
        let root = std::env::temp_dir().join(format!(
            "punar-env-netd-client-{}-{}",
            std::process::id(),
            NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let socket = root.join("netd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let seen = Arc::new(Mutex::new(None));
        let thread_seen = Arc::clone(&seen);
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let request: Value = serde_json::from_str(line.trim_end()).unwrap();
            let mut response = response;
            response["id"] = request["id"].clone();
            *thread_seen.lock().unwrap() = Some(request);
            let mut writer = &stream;
            writeln!(writer, "{}", response).unwrap();
        });
        (socket, seen)
    }

    #[test]
    fn sends_only_the_exact_session_barrier_method() {
        let (socket, seen) = one_response(json!({
            "v": 1,
            "id": "reply",
            "result": {
                "session_id": "agt_4f21c09ab3e1",
                "project": "atlas",
                "state": "ready",
                "enforcement": "nftables_cgroup_v2"
            }
        }));
        let ready = Client::new(socket)
            .session_ready("agt_4f21c09ab3e1")
            .unwrap();
        assert_eq!(ready.state, NetworkSessionReadyState::Ready);
        assert_eq!(
            ready.enforcement,
            NetworkSessionEnforcement::NftablesCgroupV2
        );
        let request = seen.lock().unwrap().clone().unwrap();
        assert_eq!(request["method"], "network.session_ready");
        assert_eq!(request["params"], json!({"session_id": "agt_4f21c09ab3e1"}));
        assert_eq!(request["params"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn count_or_generic_status_cannot_satisfy_the_barrier() {
        for result in [
            json!({"active_sessions": 1}),
            json!({"state": "ready"}),
            json!({
                "session_id": "agt_other",
                "project": "atlas",
                "state": "ready",
                "enforcement": "nftables_cgroup_v2"
            }),
        ] {
            let (socket, _) = one_response(json!({"v": 1, "id": "reply", "result": result}));
            assert!(
                Client::new(socket)
                    .session_ready("agt_4f21c09ab3e1")
                    .is_err()
            );
        }
    }
}
