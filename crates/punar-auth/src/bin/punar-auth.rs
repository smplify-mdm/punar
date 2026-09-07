#![forbid(unsafe_code)]
//! The unprivileged half: relay one password to punar-authd and print one word.
//!
//! The lock surface spawns this with fixed argv and writes the candidate secret
//! on an anonymous stdin pipe — the discipline the greeter already uses for
//! account creation. The secret is never an argument, never an environment
//! variable, and never touches disk.
//!
//! It prints exactly one of `ok`, `denied`, `unavailable`, and nothing else, so
//! a surface cannot accidentally render a diagnostic as an authentication
//! result. `unavailable` is printed for every local failure too — a missing
//! socket, a refused connection, a truncated reply — because a device that could
//! not ask must never tell someone their correct password is wrong.

use std::io::{self, BufRead, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use punar_auth::protocol::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL_VERSION};
use zeroize::{Zeroize, Zeroizing};

const SOCKET: &str = "/run/punar-authd/auth.sock";

fn main() -> ExitCode {
    let verdict = run().unwrap_or("unavailable");
    let _ = writeln!(io::stdout(), "{verdict}");
    // The exit status deliberately does NOT encode the verdict: a caller reads
    // the word. Exiting non-zero on a denial would make an ordinary wrong
    // password look like a broken tool in every log that watches exit codes.
    ExitCode::SUCCESS
}

fn run() -> Option<&'static str> {
    let mut input = Zeroizing::new(Vec::with_capacity(256));
    io::stdin()
        .lock()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_until(b'\n', &mut input)
        .ok()?;
    if input.last() == Some(&b'\n') {
        input.pop();
    }
    if input.is_empty() || input.len() > MAX_REQUEST_BYTES {
        input.zeroize();
        return None;
    }

    let body = Zeroizing::new(
        serde_json::to_vec(&serde_json::json!({
            "v": PROTOCOL_VERSION,
            "password": String::from_utf8_lossy(&input).into_owned(),
        }))
        .ok()?,
    );
    input.zeroize();

    let mut stream = UnixStream::connect(PathBuf::from(SOCKET)).ok()?;
    // Generous, because the far side runs a real PAM stack whose modules may
    // deliberately delay a failure.
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok()?;

    let len = u32::try_from(body.len()).ok()?;
    stream.write_all(&len.to_le_bytes()).ok()?;
    stream.write_all(&body).ok()?;
    stream.flush().ok()?;

    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).ok()?;
    let len = u32::from_le_bytes(header) as usize;
    if len == 0 || len > MAX_RESPONSE_BYTES {
        return None;
    }
    let mut response = vec![0_u8; len];
    stream.read_exact(&mut response).ok()?;
    let parsed: serde_json::Value = serde_json::from_slice(&response).ok()?;

    // Mapped through a closed set rather than echoed: whatever the far side
    // says, this process prints one of three known words or nothing at all.
    match parsed.get("verdict").and_then(serde_json::Value::as_str) {
        Some("ok") => Some("ok"),
        Some("denied") => Some("denied"),
        _ => None,
    }
}
