//! Pre-login-only privileged service. It exits permanently after the first
//! successful account transaction, leaving no resident post-login daemon.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{PermissionsExt, chown};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

use crate::identity::{IdentityError, IdentityStore};
use crate::protocol::{
    CreateAccountWire, ErrorResponse, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL_VERSION,
    SuccessResponse, validate_timezone_name,
};

pub fn serve(socket_path: &Path) -> Result<(), io::Error> {
    let (greeter_uid, greeter_gid) = greeter_ids()?;
    let listener = bind_with_perms(socket_path, greeter_gid)?;
    let store = IdentityStore::production();
    store
        .materialize()
        .map_err(|_| io::Error::other("identity materialization failed"))?;

    loop {
        let (mut stream, _) = listener.accept()?;
        let cred = rustix::net::sockopt::socket_peercred(&stream)?;
        let uid = cred.uid.as_raw();
        if uid != greeter_uid && uid != 0 {
            continue;
        }
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        if handle(&store, &mut stream)? {
            let _ = fs::remove_file(socket_path);
            return Ok(());
        }
    }
}

fn handle(store: &IdentityStore, stream: &mut UnixStream) -> io::Result<bool> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    let len = u32::from_le_bytes(header) as usize;
    if len == 0 || len > MAX_REQUEST_BYTES {
        write_error(
            stream,
            "request_invalid",
            None,
            "The account request was not valid.",
        )?;
        return Ok(false);
    }
    let mut payload = Zeroizing::new(vec![0_u8; len]);
    stream.read_exact(&mut payload)?;
    let request: CreateAccountWire = match serde_json::from_slice(&payload) {
        Ok(request) => request,
        Err(_) => {
            payload.zeroize();
            write_error(
                stream,
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
            stream,
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
            write_error(stream, error.code, Some(error.field), error.message)?;
            return Ok(false);
        }
        if !Path::new("/usr/share/zoneinfo").join(name).is_file() {
            write_error(
                stream,
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
            write_frame(stream, &body)?;
            Ok(true)
        }
        Err(error) => {
            let (code, field, message) = public_error(&error);
            write_error(stream, code, field, message)?;
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
        IdentityError::Storage(_) | IdentityError::Materialize | IdentityError::Corrupt => (
            "transaction_failed",
            None,
            "Account creation did not complete. Every change was rolled back; restart and try again.",
        ),
    }
}

fn write_error(
    stream: &mut UnixStream,
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
    write_frame(stream, &body)
}

fn write_frame(stream: &mut UnixStream, body: &[u8]) -> io::Result<()> {
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
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(body)?;
    stream.flush()
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
}
