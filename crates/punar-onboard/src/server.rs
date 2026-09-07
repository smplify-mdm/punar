//! Pre-login-only privileged identity transactions: first-account creation and
//! one-time recovery-code redemption. Nothing here is resident.
//!
//! TWO ENTRY POINTS, ONE TRANSACTION BODY.
//!
//! [`session`] is what the image uses. systemd owns the listening socket
//! (`punar-onboardd.socket`, `Accept=yes`), hands one accepted connection to a
//! fresh process on stdin/stdout, and that process serves exactly one request
//! and exits. The socket therefore exists whenever the machine is up, while the
//! privileged code exists only for the length of a transaction.
//!
//! [`serve`] binds its own listener and is kept for tests and for any
//! non-systemd caller. It stops after the first *successful* transaction, which
//! is why it cannot be the image's entry point: recovery redemption has to stay
//! reachable for the life of the machine, not until the first person uses it.
//!
//! WHY NOT A RESIDENT DAEMON. This service can create accounts and change
//! passwords, and it holds `/var/lib/punar` and `/home` writable. Keeping a
//! process with that authority alive through every user session to answer a
//! request that arrives maybe once in a machine's life is the wrong trade.
//! Socket activation gives the reachability without the residency.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{PermissionsExt, chown};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

use crate::identity::{IdentityError, IdentityStore};
use crate::protocol::{
    CreateAccountWire, ErrorResponse, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, OpProbe,
    PROTOCOL_VERSION, RedeemRecoveryWire, RedeemedResponse, RequestOp, SuccessResponse,
    validate_timezone_name,
};

/// Bind a listener and serve until the first successful transaction.
///
/// Not what the image runs — see the module header. `punar-onboardd.socket`
/// plus [`session`] is the shipped path, because this function's stop-on-first-
/// success rule would retire the recovery door the moment anybody used it.
pub fn serve(socket_path: &Path) -> Result<(), io::Error> {
    let (greeter_uid, greeter_gid) = greeter_ids()?;
    let listener = bind_with_perms(socket_path, greeter_gid)?;
    let store = IdentityStore::production();
    store
        .materialize()
        .map_err(|_| io::Error::other("identity materialization failed"))?;

    loop {
        let (stream, _) = listener.accept()?;
        let cred = rustix::net::sockopt::socket_peercred(&stream)?;
        let uid = cred.uid.as_raw();
        if uid != greeter_uid && uid != 0 {
            continue;
        }
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        // `&UnixStream` is both Read and Write, so one connection can be handed
        // to the shared body as a reader and a writer without duplicating it.
        let (mut reader, mut writer) = (&stream, &stream);
        if handle(&store, &mut reader, &mut writer)? {
            let _ = fs::remove_file(socket_path);
            return Ok(());
        }
    }
}

/// Serve exactly one accepted connection, then exit.
///
/// The connection arrives on stdin and stdout because the socket unit sets
/// `Accept=yes`; systemd accepted it, so there is no listener here to leak and
/// nothing to unlink — systemd owns the socket file and re-arms it for the next
/// caller. Reachability therefore does not depend on this process surviving.
///
/// The peer check is the same one `serve` applies: `SO_PEERCRED`, greeter or
/// root only. A refused peer is closed without an answer, exactly as the loop
/// in `serve` drops it, so a wrong-uid caller learns nothing it did not know.
pub fn session() -> Result<(), io::Error> {
    use rustix::net::sockopt::{Timeout, set_socket_timeout};

    let (greeter_uid, _) = greeter_ids()?;
    let stdin = io::stdin();
    let cred = rustix::net::sockopt::socket_peercred(&stdin)?;
    let uid = cred.uid.as_raw();
    if uid != greeter_uid && uid != 0 {
        return Ok(());
    }
    // stdin and stdout are the same socket, so one pair of timeouts covers
    // both directions and a stalled peer cannot pin a root process open.
    set_socket_timeout(&stdin, Timeout::Recv, Some(Duration::from_secs(30)))?;
    set_socket_timeout(&stdin, Timeout::Send, Some(Duration::from_secs(5)))?;

    let store = IdentityStore::production();
    store
        .materialize()
        .map_err(|_| io::Error::other("identity materialization failed"))?;

    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    // The verdict is deliberately discarded. `serve` uses it to decide whether
    // to stop listening; a per-connection process is already stopping, and a
    // refused request is a normal outcome, not a unit failure.
    handle(&store, &mut reader, &mut writer)?;
    Ok(())
}

fn handle(
    store: &IdentityStore,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> io::Result<bool> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let len = u32::from_le_bytes(header) as usize;
    if len == 0 || len > MAX_REQUEST_BYTES {
        write_error(
            writer,
            "request_invalid",
            None,
            "The account request was not valid.",
        )?;
        return Ok(false);
    }
    let mut payload = Zeroizing::new(vec![0_u8; len]);
    reader.read_exact(&mut payload)?;
    // Choose the strict type before parsing into it. The probe tolerates
    // unknown fields; nothing after this point does.
    let op = match serde_json::from_slice::<OpProbe>(&payload) {
        Ok(probe) => probe.op.unwrap_or(RequestOp::CreateAccount),
        Err(_) => {
            payload.zeroize();
            write_error(
                writer,
                "request_invalid",
                None,
                "The account request was not valid.",
            )?;
            return Ok(false);
        }
    };

    if matches!(op, RequestOp::RedeemRecovery) {
        let result = handle_redeem(store, writer, &payload);
        payload.zeroize();
        return result;
    }

    let request: CreateAccountWire = match serde_json::from_slice(&payload) {
        Ok(request) => request,
        Err(_) => {
            payload.zeroize();
            write_error(
                writer,
                "request_invalid",
                None,
                "The account request was not valid.",
            )?;
            return Ok(false);
        }
    };
    payload.zeroize();
    if request.v != PROTOCOL_VERSION {
        write_error(
            writer,
            "version_unsupported",
            None,
            "This first-run client and service do not match.",
        )?;
        return Ok(false);
    }

    let username = request.username;
    let device_name = request.device_name;
    let timezone = request.timezone;
    if let Some(name) = timezone.as_deref() {
        if let Err(error) = validate_timezone_name(name) {
            write_error(writer, error.code, Some(error.field), error.message)?;
            return Ok(false);
        }
        if !Path::new("/usr/share/zoneinfo").join(name).is_file() {
            write_error(
                writer,
                "timezone_unknown",
                Some("timezone"),
                "That timezone is not available on this device. Choose one from the list.",
            )?;
            return Ok(false);
        }
    }
    let password = Zeroizing::new(request.password);
    let result = store.create_first_account(&username, &password, &device_name);
    drop(password);

    match result {
        Ok(created) => {
            let timezone_result = timezone.as_deref().map_or(Ok(()), |name| {
                apply_timezone(
                    name,
                    Path::new("/etc/localtime"),
                    Path::new("/usr/share/zoneinfo"),
                )
            });
            let timezone_applied = timezone_result.is_ok();
            let response = SuccessResponse {
                v: PROTOCOL_VERSION,
                ok: true,
                username: &created.username,
                hostname: &created.hostname,
                recovery_code: &created.recovery_code,
                timezone: timezone.as_deref(),
                timezone_automatic: timezone.is_none(),
                timezone_applied,
                timezone_warning: (!timezone_applied).then_some(
                    "Your account is ready, but the timezone could not be changed. You can retry in System Control.",
                ),
            };
            let body = Zeroizing::new(
                serde_json::to_vec(&response)
                    .map_err(|_| io::Error::other("response serialization failed"))?,
            );
            write_frame(writer, &body)?;
            Ok(true)
        }
        Err(error) => {
            let (code, field, message) = public_error(&error);
            write_error(writer, code, field, message)?;
            Ok(false)
        }
    }
}

fn apply_timezone(name: &str, localtime: &Path, zoneinfo: &Path) -> io::Result<()> {
    validate_timezone_name(name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.message))?;
    let source = zoneinfo.join(name);
    if !source.is_file() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "timezone"));
    }
    let parent = localtime
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "localtime"))?;
    let temporary = parent.join(format!(".punar-localtime.{}", std::process::id()));
    let _ = fs::remove_file(&temporary);
    std::os::unix::fs::symlink(&source, &temporary)?;
    if let Err(error) = fs::rename(&temporary, localtime) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

/// Redeem the one-time recovery code and set a new password.
///
/// Separate from account creation on purpose: the two share a socket and a
/// framing, and nothing else. This path creates no account, touches no
/// hostname, no timezone and no home directory, and it is reachable only on a
/// machine that already completed onboarding — there is no recovery record
/// before that.
fn handle_redeem(
    store: &IdentityStore,
    writer: &mut dyn Write,
    payload: &[u8],
) -> io::Result<bool> {
    let request: RedeemRecoveryWire = match serde_json::from_slice(payload) {
        Ok(request) => request,
        Err(_) => {
            write_error(
                writer,
                "request_invalid",
                None,
                "The recovery request was not valid.",
            )?;
            return Ok(false);
        }
    };
    if request.v != PROTOCOL_VERSION {
        write_error(
            writer,
            "version_unsupported",
            None,
            "This first-run client and service do not match.",
        )?;
        return Ok(false);
    }

    // Both secrets are owned for the length of the call and wiped after it,
    // like the creation path's password.
    let code = Zeroizing::new(request.recovery_code);
    let password = Zeroizing::new(request.password);
    let result = store.redeem_recovery(&request.username, &code, &password);
    drop(code);
    drop(password);

    match result {
        Ok(redeemed) => {
            let response = RedeemedResponse {
                v: PROTOCOL_VERSION,
                ok: true,
                username: &redeemed.username,
                password_changed: true,
            };
            let body = Zeroizing::new(
                serde_json::to_vec(&response)
                    .map_err(|_| io::Error::other("response serialization failed"))?,
            );
            write_frame(writer, &body)?;
            Ok(true)
        }
        Err(error) => {
            let (code, field, message) = public_error(&error);
            write_error(writer, code, field, message)?;
            Ok(false)
        }
    }
}

fn public_error(error: &IdentityError) -> (&'static str, Option<&'static str>, &'static str) {
    match error {
        IdentityError::Validation(validation) => {
            (validation.code, Some(validation.field), validation.message)
        }
        IdentityError::UsernameTaken => (
            "username_taken",
            Some("username"),
            "That username belongs to an account on this device. Choose another.",
        ),
        IdentityError::AlreadyComplete => (
            "already_complete",
            None,
            "This machine already has its first account. Nothing was changed.",
        ),
        IdentityError::NoUid => (
            "uid_unavailable",
            Some("username"),
            "No safe local account identifier is available. Nothing was changed.",
        ),
        IdentityError::AdmissionGroup => (
            "identity_unavailable",
            None,
            "The local identity service is incomplete. Nothing was changed; restart and try again.",
        ),
        IdentityError::Hash(_) => (
            "hash_failed",
            Some("password"),
            "The password could not be secured. Nothing was changed; try again.",
        ),
        IdentityError::Hostname => (
            "hostname_failed",
            Some("deviceName"),
            "The network name could not be applied. Nothing was changed; try again.",
        ),
        IdentityError::Home => (
            "home_failed",
            Some("username"),
            "The home folder could not be created. Nothing was changed; try again.",
        ),
        IdentityError::NoRecoveryRecord => (
            "recovery_unknown",
            Some("username"),
            "There is no recovery code on file for that account name.",
        ),
        IdentityError::RecoveryAlreadyUsed => (
            "recovery_used",
            Some("recoveryCode"),
            "That recovery code has already been used. A code works once.",
        ),
        IdentityError::RecoveryExhausted => (
            "recovery_exhausted",
            Some("recoveryCode"),
            "Too many incorrect recovery codes. This code can no longer be used.",
        ),
        // Deliberately the same shape of sentence as a wrong code, and it names
        // the remaining budget rather than the reason: a message that
        // distinguished "wrong code" from "no such account" would turn this
        // surface into an account-name oracle for anyone holding the machine.
        IdentityError::RecoveryMismatch => (
            "recovery_mismatch",
            Some("recoveryCode"),
            "That recovery code is not correct. Codes are limited; check it and try again.",
        ),
        IdentityError::Storage(_) | IdentityError::Materialize | IdentityError::Corrupt => (
            "transaction_failed",
            None,
            "Account creation did not complete. Every change was rolled back; restart and try again.",
        ),
    }
}

fn write_error(
    writer: &mut dyn Write,
    code: &'static str,
    field: Option<&'static str>,
    message: &'static str,
) -> io::Result<()> {
    let response = ErrorResponse {
        v: PROTOCOL_VERSION,
        ok: false,
        code,
        field,
        message,
        changed: false,
    };
    let body = serde_json::to_vec(&response)
        .map_err(|_| io::Error::other("response serialization failed"))?;
    write_frame(writer, &body)
}

fn write_frame(writer: &mut dyn Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response too large",
        ));
    }
    let len: u32 = body
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response too large"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

fn bind_with_perms(path: &Path, gid: u32) -> io::Result<UnixListener> {
    use rustix::net::{AddressFamily, SocketType, bind, listen, socket};

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        fs::remove_file(path)?;
    }
    let fd = socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    let addr = rustix::net::SocketAddrUnix::new(path)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    bind(&fd, &addr)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    chown(path, Some(0), Some(gid))?;
    listen(&fd, 4)?;
    Ok(UnixListener::from(fd))
}

fn greeter_ids() -> io::Result<(u32, u32)> {
    let output = Command::new("/usr/bin/getent")
        .args(["passwd", "greeter"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "greeter account"));
    }
    let line = String::from_utf8(output.stdout)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "greeter account"))?;
    let mut fields = line.trim().split(':');
    let uid = fields
        .nth(2)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "greeter uid"))?;
    let gid = fields
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "greeter gid"))?;
    Ok((uid, gid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timezone_apply_is_atomic_and_rejects_unknown_zones() {
        let root = tempfile::tempdir().unwrap();
        let zoneinfo = root.path().join("zoneinfo");
        let etc = root.path().join("etc");
        fs::create_dir_all(zoneinfo.join("Europe")).unwrap();
        fs::create_dir_all(&etc).unwrap();
        fs::write(zoneinfo.join("UTC"), b"TZif-utc").unwrap();
        fs::write(zoneinfo.join("Europe/Berlin"), b"TZif-berlin").unwrap();
        let localtime = etc.join("localtime");

        apply_timezone("UTC", &localtime, &zoneinfo).unwrap();
        assert_eq!(fs::read_link(&localtime).unwrap(), zoneinfo.join("UTC"));
        apply_timezone("Europe/Berlin", &localtime, &zoneinfo).unwrap();
        assert_eq!(
            fs::read_link(&localtime).unwrap(),
            zoneinfo.join("Europe/Berlin")
        );
        assert!(apply_timezone("Mars/Olympus", &localtime, &zoneinfo).is_err());
        assert!(apply_timezone("../shadow", &localtime, &zoneinfo).is_err());
    }

    /// Frame a request body the way both clients do.
    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    /// Unframe a response the way both clients do, so a length prefix written
    /// to the wrong handle or in the wrong order fails here rather than in a VM.
    fn unframed(raw: &[u8]) -> serde_json::Value {
        let len = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
        assert_eq!(
            raw.len(),
            4 + len,
            "response frame length disagrees with body"
        );
        serde_json::from_slice(&raw[4..]).unwrap()
    }

    // The transaction body reads and writes through two separate handles so one
    // implementation can serve both a connected UnixStream (`serve`) and a
    // systemd-accepted connection arriving on stdin/stdout (`session`). These
    // two cover that split directly: a reply has to appear on the writer, whole
    // and correctly framed, with nothing written back to the reader's side.
    //
    // Neither case reaches the store — one is refused on version, the other on
    // the length header — so `production()` here is a placeholder that is never
    // dereferenced, not a store under test.

    #[test]
    fn a_refused_version_is_answered_on_the_writer() {
        let store = IdentityStore::production();
        let request = framed(br#"{"v":99,"username":"a","password":"b","deviceName":"c"}"#);
        let mut reader = io::Cursor::new(request);
        let mut writer: Vec<u8> = Vec::new();

        let go_on = handle(&store, &mut reader, &mut writer).unwrap();

        assert!(
            !go_on,
            "a refused request must not end the transaction as a success"
        );
        let response = unframed(&writer);
        assert_eq!(response["ok"], serde_json::json!(false));
        assert_eq!(response["code"], serde_json::json!("version_unsupported"));
        assert_eq!(
            reader.position() as usize,
            reader.get_ref().len(),
            "the whole request should have been consumed from the reader"
        );
    }

    #[test]
    fn an_oversized_length_header_is_refused_without_reading_a_body() {
        let store = IdentityStore::production();
        let mut request = ((MAX_REQUEST_BYTES + 1) as u32).to_le_bytes().to_vec();
        request.extend_from_slice(b"this body must never be read");
        let mut reader = io::Cursor::new(request);
        let mut writer: Vec<u8> = Vec::new();

        let go_on = handle(&store, &mut reader, &mut writer).unwrap();

        assert!(!go_on);
        assert_eq!(
            unframed(&writer)["code"],
            serde_json::json!("request_invalid")
        );
        assert_eq!(
            reader.position(),
            4,
            "only the length header should have been consumed"
        );
    }
}
