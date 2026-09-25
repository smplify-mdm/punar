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
//!
//! It verifies an UNLOCK only. It used to mint an administrator ticket too
//! (`--admin`, printing `ok <ticket>`), and that is gone: its answer travels on
//! a stdout pipe, and any program running as the same person can reopen a pipe
//! through /proc/<pid>/fd and read it (F0-S4). A ticket is now asked for by
//! the process that will spend it, over punar-authd's socket, and is bound to
//! that process (docs/api/ipc.md section 23.5). The lock screen itself no
//! longer uses this relay either — it talks to the socket directly — so what
//! is left is the probe the recovery check runs.

use std::io::{self, BufRead, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use punar_auth::protocol::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL_VERSION};
use zeroize::{Zeroize, Zeroizing};

const SOCKET: &str = "/run/punar-authd/auth.sock";

fn main() -> ExitCode {
    // Not dumpable, no core file, before the password is read (F0-S4): no
    // other program of this person can open this process's /proc/<pid>/fd or
    // memory while it holds the secret. A failure here answers `unavailable`
    // rather than reading a secret into an unprotected process.
    if punar_reauth::harden().is_err() {
        let _ = writeln!(io::stdout(), "unavailable");
        return ExitCode::SUCCESS;
    }
    // A closed argv: no arguments at all. `--admin` is refused rather than
    // ignored, so a caller that still asks for a ticket learns it will not get
    // one here instead of reading an unlock verdict as a confirmation.
    if std::env::args().nth(1).is_some() {
        let _ = writeln!(io::stdout(), "unavailable");
        return ExitCode::from(2);
    }
    let verdict = run().unwrap_or_else(|| "unavailable".to_string());
    let _ = writeln!(io::stdout(), "{verdict}");
    // The exit status deliberately does NOT encode the verdict: a caller reads
    // the word. Exiting non-zero on a denial would make an ordinary wrong
    // password look like a broken tool in every log that watches exit codes.
    ExitCode::SUCCESS
}

fn run() -> Option<String> {
    // Sized for the longest line accepted, so reading never reallocates and
    // leaves an unwiped copy of the secret behind in freed memory.
    let mut input = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_BYTES + 1));
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

    #[derive(serde::Serialize)]
    struct Request<'a> {
        v: u32,
        password: &'a str,
        purpose: &'static str,
    }
    // The password is borrowed, never copied into a JSON value, and the body
    // is serialized into a wiped buffer sized so it never reallocates (JSON
    // escaping at most sextuples a byte).
    let password = std::str::from_utf8(&input).ok()?;
    let mut body = Zeroizing::new(Vec::with_capacity(input.len() * 6 + 64));
    serde_json::to_writer(
        &mut *body,
        &Request {
            v: PROTOCOL_VERSION,
            password,
            purpose: "unlock",
        },
    )
    .ok()?;
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
    let mut response = Zeroizing::new(vec![0_u8; len]);
    stream.read_exact(&mut response).ok()?;
    let parsed: serde_json::Value = serde_json::from_slice(&response).ok()?;

    // Mapped through a closed set rather than echoed: whatever the far side
    // says, this process prints one of three known words or nothing at all.
    match parsed.get("verdict").and_then(serde_json::Value::as_str) {
        Some("ok") => Some("ok".to_string()),
        Some("denied") => Some("denied".to_string()),
        _ => None,
    }
}
