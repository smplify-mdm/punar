//! One connection, one verdict, then exit.
//!
//! systemd owns the listening socket (`punar-authd.socket`, `Accept=yes`) and
//! hands each accepted connection to a fresh process on stdin/stdout. That keeps
//! the crate free of `unsafe` — an accepted connection is addressable through
//! safe std and safe rustix, while inheriting a *listening* descriptor would
//! need a raw-fd conversion `#![forbid(unsafe_code)]` refuses — and it means no
//! root process with authentication authority is resident between attempts.

use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use pam_client2::conv_mock::Conversation;
use pam_client2::{Context, Flag};
use rustix::net::sockopt::{Timeout, set_socket_timeout};
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{
    MAX_REQUEST_BYTES, PROTOCOL_VERSION, Verdict, VerifyRequest, VerifyResponse,
};

/// The stack this daemon runs. Deliberately the same file the lock surface
/// names, so faillock counts a relayed attempt exactly like a typed one and a
/// future edit to that stack applies here without anyone remembering to mirror
/// it.
const PAM_SERVICE: &str = "punar-lock";

/// Below this a uid is a system account. Nothing here has a lock screen, and a
/// service account must not be reachable through a desktop surface.
const MIN_HUMAN_UID: u32 = 1000;

/// Serve the single connection on stdin/stdout, then return.
pub fn session() -> io::Result<()> {
    let stdin = io::stdin();
    // THE IDENTITY COMES FROM THE KERNEL, and it is read before a single byte of
    // the body is parsed, so no request field can reach the code path that
    // decides who is being authenticated.
    let peer = rustix::net::sockopt::socket_peercred(&stdin)
        .map_err(|_| io::Error::other("peer credentials unavailable"))?;
    let uid = peer.uid.as_raw();

    // stdin and stdout are the same socket, so one pair of timeouts covers both
    // directions. These bound a single read; the unit's RuntimeMaxSec bounds the
    // whole transaction, because a peer dribbling one byte per interval stays
    // inside a per-read timeout indefinitely.
    let _ = set_socket_timeout(&stdin, Timeout::Recv, Some(Duration::from_secs(10)));
    let _ = set_socket_timeout(&stdin, Timeout::Send, Some(Duration::from_secs(10)));

    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let verdict = decide(uid, &mut reader);
    write_response(&mut writer, verdict)
}

/// Read one framed request and turn it into a verdict.
fn decide(uid: u32, reader: &mut dyn Read) -> Verdict {
    let mut header = [0_u8; 4];
    if reader.read_exact(&mut header).is_err() {
        return Verdict::Unavailable;
    }
    let len = u32::from_le_bytes(header) as usize;
    if len == 0 || len > MAX_REQUEST_BYTES {
        return Verdict::Denied;
    }
    let mut payload = Zeroizing::new(vec![0_u8; len]);
    if reader.read_exact(&mut payload).is_err() {
        return Verdict::Unavailable;
    }
    let request: VerifyRequest = match serde_json::from_slice(&payload) {
        Ok(request) => request,
        Err(_) => {
            payload.zeroize();
            return Verdict::Denied;
        }
    };
    payload.zeroize();
    if request.v != PROTOCOL_VERSION {
        return Verdict::Denied;
    }
    let password = Zeroizing::new(request.password);
    verify_for_uid(uid, &password)
}

/// Resolve the peer's uid to a name and run the stack for it.
///
/// Takes a uid rather than a name on purpose: the invariant "the caller cannot
/// choose who they are" is then structural, not a runtime check somebody could
/// later move or forget.
fn verify_for_uid(uid: u32, password: &str) -> Verdict {
    // Root has no lock screen and no need of this service; refusing it removes a
    // whole class of question about what a root-owned caller could ask for.
    if uid < MIN_HUMAN_UID {
        return Verdict::Denied;
    }
    // An empty secret is refused here as well as by DISALLOW_NULL_AUTHTOK below,
    // because a lock that opens on an empty string is not a lock.
    if password.is_empty() {
        return Verdict::Denied;
    }
    let Some(username) = username_for_uid(uid) else {
        // The device could not resolve its own peer. That is a fault here, not
        // a statement about the secret.
        return Verdict::Unavailable;
    };
    authenticate(&username, password)
}

/// `getent passwd <uid>`, the lookup punar-onboard already uses. NSS is what
/// knows about userdb records, and this process runs as root — precisely the
/// privilege the unprivileged caller lacked.
fn username_for_uid(uid: u32) -> Option<String> {
    let output = Command::new("/usr/bin/getent")
        .args(["passwd", &uid.to_string()])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8(output.stdout).ok()?;
    let name = line.split(':').next()?.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

fn authenticate(username: &str, password: &str) -> Verdict {
    let conversation = Conversation::with_credentials(username, password);
    let Ok(mut context) = Context::new(PAM_SERVICE, Some(username), conversation) else {
        // The stack itself could not be opened — a missing /etc/pam.d file, or a
        // module that will not load. Nothing was decided about the secret.
        return Verdict::Unavailable;
    };
    // DISALLOW_NULL_AUTHTOK: never let an empty token satisfy the stack.
    if context.authenticate(Flag::DISALLOW_NULL_AUTHTOK).is_err() {
        return Verdict::Denied;
    }
    // The account phase still matters: an expired or disabled account must not
    // open a screen just because its secret is still correct.
    if context.acct_mgmt(Flag::DISALLOW_NULL_AUTHTOK).is_err() {
        return Verdict::Denied;
    }
    Verdict::Ok
}

fn write_response(writer: &mut dyn Write, verdict: Verdict) -> io::Result<()> {
    let body = serde_json::to_vec(&VerifyResponse::new(verdict))
        .map_err(|_| io::Error::other("response serialization failed"))?;
    let len = u32::try_from(body.len()).map_err(|_| io::Error::other("response too large"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn system_uids_are_refused_before_any_lookup() {
        assert_eq!(verify_for_uid(0, "anything"), Verdict::Denied);
        assert_eq!(verify_for_uid(999, "anything"), Verdict::Denied);
    }

    #[test]
    fn an_empty_secret_is_refused() {
        assert_eq!(verify_for_uid(1000, ""), Verdict::Denied);
    }

    /// The property that must survive every later edit: for a fixed peer, the
    /// answer may vary between ok and denied, but the SECRET must never decide
    /// whether the device claims it could not ask. Both of these are refused
    /// before PAM is reached, so the test needs no stack and no account.
    #[test]
    fn the_secret_never_decides_whether_the_device_says_unavailable() {
        for secret in ["", "wrong", "another-wrong", "x".repeat(200).as_str()] {
            assert_ne!(
                verify_for_uid(0, secret),
                Verdict::Unavailable,
                "a system uid must be denied, never reported as a device fault"
            );
        }
    }

    #[test]
    fn a_truncated_frame_is_a_device_fault_and_not_a_denial() {
        // A peer that vanishes mid-request has said nothing about a password,
        // so the surface must not be able to render it as a wrong one.
        let mut short = io::Cursor::new(vec![4_u8, 0, 0]);
        assert_eq!(decide(1000, &mut short), Verdict::Unavailable);
    }

    #[test]
    fn a_malformed_or_oversized_request_is_denied_without_allocating() {
        let mut huge = io::Cursor::new((MAX_REQUEST_BYTES as u32 + 1).to_le_bytes().to_vec());
        assert_eq!(decide(1000, &mut huge), Verdict::Denied);

        let mut junk = io::Cursor::new(framed(b"not json"));
        assert_eq!(decide(1000, &mut junk), Verdict::Denied);

        let mut wrong_version = io::Cursor::new(framed(br#"{"v":99,"password":"x"}"#));
        assert_eq!(decide(1000, &mut wrong_version), Verdict::Denied);
    }

    #[test]
    fn a_username_on_the_wire_is_refused_rather_than_honoured() {
        let mut named = io::Cursor::new(framed(br#"{"v":1,"username":"root","password":"x"}"#));
        assert_eq!(decide(1000, &mut named), Verdict::Denied);
    }
}
