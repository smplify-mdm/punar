//! Deadline-bound serving for one already-admitted PIM capability channel.
//!
//! This module does not create a listener. It consumes the unnamed stream that
//! the privileged broker stamped with a fixed profile/client grant. Every
//! request and response gets its own absolute deadline, so a peer cannot keep
//! a frame alive indefinitely by sending or reading one byte at a time.

use std::cmp;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use serde_json::Value;
use thiserror::Error;

use crate::protocol::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use crate::{
    ClientGrant, FrameError, GrantedChannel, PimProtocolError, PimRequest, decode_request,
    encode_error, encode_request_error, encode_success,
};

const FRAME_DEADLINE: Duration = Duration::from_secs(10);
const READ_CHUNK_BYTES: usize = 8 * 1024;

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error(transparent)]
    Frame(#[from] FrameError),
}

/// Serve one capability channel until orderly EOF or a connection-fatal frame
/// error. The dispatcher receives the trusted broker grant and a request whose
/// method has already passed the client's least-privilege partition.
pub fn serve_granted_channel(
    granted: GrantedChannel,
    mut dispatch: impl FnMut(&ClientGrant, &PimRequest) -> Result<Value, PimProtocolError>,
) -> Result<(), ConnectionError> {
    let mut stream = UnixStream::from(granted.channel);
    serve_stream(&mut stream, &granted.grant, FRAME_DEADLINE, &mut dispatch)
}

fn serve_stream(
    stream: &mut UnixStream,
    grant: &ClientGrant,
    deadline: Duration,
    dispatch: &mut impl FnMut(&ClientGrant, &PimRequest) -> Result<Value, PimProtocolError>,
) -> Result<(), ConnectionError> {
    let mut reader = DeadlineFrameReader::default();
    loop {
        let Some(frame) = reader.read(stream, deadline)? else {
            return Ok(());
        };
        let request = match decode_request(grant.client, &frame) {
            Ok(request) => request,
            Err(failure) => {
                let Some(response) = encode_error(&failure)? else {
                    return Ok(());
                };
                write_frame(stream, &response, deadline)?;
                continue;
            }
        };
        let response = match dispatch(grant, &request) {
            Ok(result) => encode_success(&request, result)?,
            Err(error) => encode_request_error(&request, &error)?,
        };
        write_frame(stream, &response, deadline)?;
    }
}

#[derive(Default)]
struct DeadlineFrameReader {
    pending: Vec<u8>,
}

impl DeadlineFrameReader {
    fn read(
        &mut self,
        stream: &mut UnixStream,
        deadline: Duration,
    ) -> Result<Option<Vec<u8>>, FrameError> {
        let started = Instant::now();
        loop {
            if let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
                let mut frame: Vec<u8> = self.pending.drain(..=newline).collect();
                frame.pop();
                if frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                if frame.len() > MAX_REQUEST_BYTES {
                    return Err(FrameError::RequestTooLarge);
                }
                return Ok(Some(frame));
            }

            // One extra CR and its terminating LF may follow a maximum-sized
            // payload. Any other byte beyond the payload cap is fatal.
            if self.pending.len() > MAX_REQUEST_BYTES
                && !(self.pending.len() == MAX_REQUEST_BYTES + 1
                    && self.pending.last() == Some(&b'\r'))
            {
                return Err(FrameError::RequestTooLarge);
            }
            let allowance = (MAX_REQUEST_BYTES + 2).saturating_sub(self.pending.len());
            if allowance == 0 {
                return Err(FrameError::RequestTooLarge);
            }
            let remaining = remaining(deadline, started, "PIM request deadline elapsed")?;
            stream.set_read_timeout(Some(remaining))?;
            let mut chunk = [0_u8; READ_CHUNK_BYTES];
            let read_capacity = cmp::min(chunk.len(), allowance);
            let read = stream.read(&mut chunk[..read_capacity])?;
            if read == 0 {
                return if self.pending.is_empty() {
                    Ok(None)
                } else {
                    Err(FrameError::UnterminatedRequest)
                };
            }
            self.pending.extend_from_slice(&chunk[..read]);
        }
    }
}

fn write_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Duration,
) -> Result<(), FrameError> {
    if frame.len() > MAX_RESPONSE_BYTES {
        return Err(FrameError::ResponseTooLarge);
    }
    let started = Instant::now();
    write_all(stream, frame, deadline, started)?;
    write_all(stream, b"\n", deadline, started)?;
    Ok(())
}

fn write_all(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Duration,
    started: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let timeout =
            remaining(deadline, started, "PIM response deadline elapsed").map_err(frame_into_io)?;
        stream.set_write_timeout(Some(timeout))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn remaining(
    deadline: Duration,
    started: Instant,
    message: &'static str,
) -> Result<Duration, FrameError> {
    deadline
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| FrameError::Io(io::Error::new(io::ErrorKind::TimedOut, message)))
}

fn frame_into_io(error: FrameError) -> io::Error {
    match error {
        FrameError::Io(error) => error,
        other => io::Error::other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientGrant, PimClient, client_channel_pair};
    use serde_json::json;
    use std::io::{BufRead, BufReader};
    use std::thread;

    fn channel(client: PimClient) -> (UnixStream, GrantedChannel) {
        let (application, service) = client_channel_pair().unwrap();
        (
            UnixStream::from(application),
            GrantedChannel {
                grant: ClientGrant::new("grant_A1", 1000, client),
                channel: service,
            },
        )
    }

    #[test]
    fn authorized_requests_round_trip_until_orderly_eof() {
        let (mut application, granted) = channel(PimClient::Settings);
        let server = thread::spawn(move || {
            serve_granted_channel(granted, |grant, request| {
                assert_eq!(grant.profile_uid, 1000);
                assert_eq!(request.method.as_str(), "service.status");
                Ok(json!({"kind":"service_status","state":"ready"}))
            })
        });
        application
            .write_all(b"{\"v\":1,\"id\":\"r1\",\"method\":\"service.status\",\"params\":{}}\n")
            .unwrap();
        application.shutdown(std::net::Shutdown::Write).unwrap();

        let mut response = String::new();
        BufReader::new(application)
            .read_line(&mut response)
            .unwrap();
        let response: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["id"], "r1");
        assert_eq!(response["result"]["state"], "ready");
        server.join().unwrap().unwrap();
    }

    #[test]
    fn denied_safe_request_gets_error_without_reaching_dispatch() {
        let (mut application, granted) = channel(PimClient::Mail);
        let server = thread::spawn(move || {
            serve_granted_channel(granted, |_grant, request| {
                assert_eq!(request.method.as_str(), "service.status");
                Ok(json!({"kind":"service_status"}))
            })
        });
        application
            .write_all(
                b"{\"v\":1,\"id\":\"denied\",\"method\":\"events.delete\",\"params\":{}}\n\
                  {\"v\":1,\"id\":\"ok\",\"method\":\"service.status\",\"params\":{}}\n",
            )
            .unwrap();
        application.shutdown(std::net::Shutdown::Write).unwrap();

        let responses: Vec<Value> = BufReader::new(application)
            .lines()
            .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
            .collect();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["error"]["code"], "denied");
        assert_eq!(responses[1]["id"], "ok");
        server.join().unwrap().unwrap();
    }

    #[test]
    fn unsafe_correlation_closes_without_reflection() {
        let (mut application, granted) = channel(PimClient::Settings);
        let server = thread::spawn(move || {
            serve_granted_channel(granted, |_grant, _request| {
                panic!("unsafe request must not dispatch")
            })
        });
        application
            .write_all(
                b"{\"v\":1,\"id\":\"<unsafe>\",\"method\":\"service.status\",\"params\":{}}\n",
            )
            .unwrap();
        application.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reflected = Vec::new();
        application.read_to_end(&mut reflected).unwrap();
        assert!(reflected.is_empty());
        server.join().unwrap().unwrap();
    }

    #[test]
    fn partial_frame_hits_the_absolute_request_deadline() {
        let (mut application, mut service) = UnixStream::pair().unwrap();
        let grant = ClientGrant::new("grant_A1", 1000, PimClient::Settings);
        application.write_all(b"{").unwrap();
        let failure = serve_stream(
            &mut service,
            &grant,
            Duration::from_millis(50),
            &mut |_grant, _request| Ok(json!({})),
        )
        .unwrap_err();
        assert!(matches!(
            failure,
            ConnectionError::Frame(FrameError::Io(ref error))
                if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
        ));
    }

    #[test]
    fn method_level_errors_keep_valid_request_correlation() {
        let (mut application, granted) = channel(PimClient::Reminders);
        let server = thread::spawn(move || {
            serve_granted_channel(granted, |_grant, request| {
                match request.parse_params::<RequiredParams>() {
                    Ok(params) => Ok(json!({"required":params.required})),
                    Err(error) => Err(error),
                }
            })
        });
        application
            .write_all(b"{\"v\":1,\"id\":\"typed\",\"method\":\"service.status\",\"params\":{}}\n")
            .unwrap();
        application.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        BufReader::new(application)
            .read_line(&mut response)
            .unwrap();
        let response: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["id"], "typed");
        assert_eq!(response["error"]["code"], "invalid_params");
        server.join().unwrap().unwrap();
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RequiredParams {
        required: bool,
    }
}
