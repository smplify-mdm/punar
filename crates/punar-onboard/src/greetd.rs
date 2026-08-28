//! Minimal greetd IPC client. greetd's protocol is native-endian u32 length
//! plus UTF-8 JSON; keeping the implementation here avoids a second runtime
//! or a resident greeter service.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_FRAME: usize = 64 * 1024;
const MAX_AUTH_MESSAGES: usize = 16;

#[derive(Debug, Error)]
pub enum GreetError {
    #[error("the login service is unavailable")]
    Unavailable,
    #[error("the login service returned an invalid response")]
    Protocol,
    #[error("authentication failed")]
    Authentication,
    #[error("this login needs an unsupported authentication step")]
    Unsupported,
    #[error("the desktop session could not be started")]
    Start,
}

pub fn start_session(
    socket: &Path,
    username: &str,
    mut password: Option<Zeroizing<String>>,
) -> Result<(), GreetError> {
    crate::protocol::validate_username(username).map_err(|_| GreetError::Authentication)?;
    let mut stream = UnixStream::connect(socket).map_err(|_| GreetError::Unavailable)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|_| GreetError::Unavailable)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| GreetError::Unavailable)?;

    send(
        &mut stream,
        &json!({"type": "create_session", "username": username}),
    )?;
    let mut response = receive(&mut stream)?;
    let mut answered_secret = false;

    for _ in 0..MAX_AUTH_MESSAGES {
        match response_type(&response)? {
            "success" => break,
            "error" => {
                cancel(&mut stream);
                return if response.get("error_type").and_then(Value::as_str) == Some("auth_error") {
                    Err(GreetError::Authentication)
                } else {
                    Err(GreetError::Protocol)
                };
            }
            "auth_message" => {
                let kind = response
                    .get("auth_message_type")
                    .and_then(Value::as_str)
                    .ok_or(GreetError::Protocol)?;
                match kind {
                    "info" | "error" => send(
                        &mut stream,
                        &json!({"type": "post_auth_message_response", "response": null}),
                    )?,
                    "secret" if !answered_secret => {
                        let secret = password.as_deref().ok_or(GreetError::Unsupported)?;
                        answered_secret = true;
                        send_secret_response(&mut stream, secret)?;
                    }
                    _ => {
                        cancel(&mut stream);
                        return Err(GreetError::Unsupported);
                    }
                }
                if answered_secret {
                    if let Some(secret) = password.as_mut() {
                        secret.zeroize();
                    }
                }
                response = receive(&mut stream)?;
            }
            _ => return Err(GreetError::Protocol),
        }
    }

    if response_type(&response)? != "success" {
        cancel(&mut stream);
        return Err(GreetError::Authentication);
    }
    send(
        &mut stream,
        &json!({
            "type": "start_session",
            "cmd": ["/usr/lib/punar/session.sh"],
            "env": [
                "XDG_SESSION_TYPE=wayland",
                "XDG_CURRENT_DESKTOP=Hyprland",
                "XDG_SESSION_DESKTOP=Hyprland"
            ]
        }),
    )?;
    let started = receive(&mut stream)?;
    if response_type(&started)? == "success" {
        Ok(())
    } else {
        cancel(&mut stream);
        Err(GreetError::Start)
    }
}

fn response_type(response: &Value) -> Result<&str, GreetError> {
    response
        .get("type")
        .and_then(Value::as_str)
        .ok_or(GreetError::Protocol)
}

fn cancel(stream: &mut UnixStream) {
    let _ = send(stream, &json!({"type": "cancel_session"}));
}

fn send(stream: &mut UnixStream, value: &Value) -> Result<(), GreetError> {
    let payload = serde_json::to_vec(value).map_err(|_| GreetError::Protocol)?;
    if payload.len() > MAX_FRAME {
        return Err(GreetError::Protocol);
    }
    let len: u32 = payload.len().try_into().map_err(|_| GreetError::Protocol)?;
    stream
        .write_all(&len.to_ne_bytes())
        .and_then(|_| stream.write_all(&payload))
        .map_err(map_io)
}

#[derive(Serialize)]
struct SecretResponse<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    response: &'a str,
}

fn send_secret_response(stream: &mut UnixStream, secret: &str) -> Result<(), GreetError> {
    let payload = Zeroizing::new(
        serde_json::to_vec(&SecretResponse {
            kind: "post_auth_message_response",
            response: secret,
        })
        .map_err(|_| GreetError::Protocol)?,
    );
    if payload.len() > MAX_FRAME {
        return Err(GreetError::Protocol);
    }
    let len: u32 = payload.len().try_into().map_err(|_| GreetError::Protocol)?;
    stream
        .write_all(&len.to_ne_bytes())
        .and_then(|_| stream.write_all(&payload))
        .map_err(map_io)
}

fn receive(stream: &mut UnixStream) -> Result<Value, GreetError> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).map_err(map_io)?;
    let len = u32::from_ne_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(GreetError::Protocol);
    }
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload).map_err(map_io)?;
    serde_json::from_slice(&payload).map_err(|_| GreetError::Protocol)
}

fn map_io(error: io::Error) -> GreetError {
    match error.kind() {
        io::ErrorKind::NotFound
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::TimedOut => GreetError::Unavailable,
        _ => GreetError::Protocol,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;
    use tempfile::TempDir;

    fn read_frame(stream: &mut UnixStream) -> Value {
        receive(stream).unwrap()
    }

    fn write_frame(stream: &mut UnixStream, value: Value) {
        send(stream, &value).unwrap();
    }

    #[test]
    fn password_crosses_only_the_auth_response() {
        let temp = TempDir::new().unwrap();
        let socket = temp.path().join("greetd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let create = read_frame(&mut stream);
            assert_eq!(create["username"], "alice");
            assert!(!create.to_string().contains("three amber rivers"));
            write_frame(
                &mut stream,
                json!({"type":"auth_message","auth_message_type":"secret","auth_message":"Password:"}),
            );
            let answer = read_frame(&mut stream);
            assert_eq!(answer["response"], "three amber rivers");
            write_frame(&mut stream, json!({"type":"success"}));
            let start = read_frame(&mut stream);
            assert_eq!(start["cmd"][0], "/usr/lib/punar/session.sh");
            assert!(!start.to_string().contains("three amber rivers"));
            write_frame(&mut stream, json!({"type":"success"}));
        });
        start_session(
            &socket,
            "alice",
            Some(Zeroizing::new("three amber rivers".to_string())),
        )
        .unwrap();
        server.join().unwrap();
    }

    #[test]
    fn first_session_accepts_a_passwordless_pam_success() {
        let temp = TempDir::new().unwrap();
        let socket = temp.path().join("greetd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_frame(&mut stream);
            write_frame(&mut stream, json!({"type":"success"}));
            let _ = read_frame(&mut stream);
            write_frame(&mut stream, json!({"type":"success"}));
        });
        start_session(&socket, "alice", None).unwrap();
        server.join().unwrap();
    }
}
