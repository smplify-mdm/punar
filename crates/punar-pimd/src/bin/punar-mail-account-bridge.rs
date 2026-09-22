//! Short-lived protected Mail account-entry surface.
//!
//! The root launch broker transfers exactly one one-use account-entry channel
//! and one verified Wayland stream to this locked service identity. The QML
//! child can reach only a private mode-0600 socket. Its password is relayed as
//! a separate bounded frame and is never placed in JSON, argv, environment,
//! logs, or the ordinary Mail capability channel.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use punar_pimd::{
    AccountEntryHelper, AccountLaunchCapabilities, OpenProtocolSetup, lock_down_current_process,
    receive_account_launch,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::net::{SocketFlags, SocketType, accept_with, sockopt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

const PROFILE_UID_ENV: &str = "PUNAR_PROFILE_UID";
const LAUNCH_FD_NAME: &str = "launch";
const QML_PROGRAM: &str = "/usr/bin/qs";
const QML_ROOT: &str = "/usr/share/punar/shell/MailAccount";
const MAX_SETUP_BYTES: usize = 8 * 1024;
const MAX_PASSWORD_BYTES: usize = 64 * 1024;
const UI_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const UI_ENTRY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
// A successful connection closes itself immediately. A rejected connection is
// deliberately left visible long enough for the person to read the provider's
// result and close the one-use surface; it cannot accept a second password.
const UI_EXIT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UiSetupFrame {
    v: u8,
    setup: OpenProtocolSetup,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct UiOutcome<'a> {
    v: u8,
    ok: bool,
    code: &'a str,
    account_id: Option<&'a str>,
}

#[derive(Debug, Error)]
enum BridgeError {
    #[error("Mail account bridge profile is invalid")]
    InvalidProfile,
    #[error("Mail account bridge activation is invalid")]
    InvalidActivation,
    #[error("Mail account bridge activation could not be read")]
    Activation(#[from] sd_listen_fds::Error),
    #[error("Mail account bridge kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
    #[error("Mail account launch was refused")]
    Launch(#[from] punar_pimd::AccountLaunchError),
    #[error("Mail account bridge process lockdown failed")]
    Lockdown(#[from] punar_pimd::ProcessSecurityError),
    #[error("Mail account entry was refused")]
    Entry(#[from] punar_pimd::AccountEntryError),
    #[error("Mail account bridge local transport failed")]
    Io(#[from] io::Error),
    #[error("Mail account interface did not connect in time")]
    UiTimeout,
    #[error("Mail account interface exited unsuccessfully")]
    UiFailure,
    #[error("Mail account interface sent an invalid frame")]
    InvalidFrame,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("punar-mail-account-bridge: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), BridgeError> {
    if env::args_os().len() != 1 {
        return Err(BridgeError::InvalidActivation);
    }
    let profile_uid = parse_profile_uid(env::var_os(PROFILE_UID_ENV))?;
    let launch_listener = select_activation_descriptor(
        sd_listen_fds::get()?
            .into_iter()
            .map(|(name, descriptor)| (name, descriptor.into_std()))
            .collect(),
    )?;

    // This is deliberately before accepting either the one-use credential
    // capability or creating a UI password field.
    lock_down_current_process()?;
    let launch_control = accept_with(&launch_listener, SocketFlags::CLOEXEC)?;
    let capabilities = receive_account_launch(launch_control, profile_uid)?;
    serve_account_ui(profile_uid, capabilities)
}

fn parse_profile_uid(value: Option<std::ffi::OsString>) -> Result<u32, BridgeError> {
    let value = value
        .and_then(|value| value.into_string().ok())
        .ok_or(BridgeError::InvalidProfile)?;
    let uid = value
        .parse::<u32>()
        .map_err(|_| BridgeError::InvalidProfile)?;
    if uid == 0 || uid.to_string() != value {
        return Err(BridgeError::InvalidProfile);
    }
    Ok(uid)
}

fn select_activation_descriptor(
    mut descriptors: Vec<(Option<String>, OwnedFd)>,
) -> Result<OwnedFd, BridgeError> {
    if descriptors.len() != 1 || descriptors[0].0.as_deref() != Some(LAUNCH_FD_NAME) {
        return Err(BridgeError::InvalidActivation);
    }
    let descriptor = descriptors.pop().expect("length checked").1;
    fcntl_setfd(&descriptor, FdFlags::CLOEXEC)?;
    if sockopt::socket_type(&descriptor)? != SocketType::SEQPACKET
        || !sockopt::socket_acceptconn(&descriptor)?
    {
        return Err(BridgeError::InvalidActivation);
    }
    Ok(descriptor)
}

fn serve_account_ui(
    profile_uid: u32,
    capabilities: AccountLaunchCapabilities,
) -> Result<(), BridgeError> {
    let runtime_dir = PathBuf::from("/run/punar-mail-account").join(profile_uid.to_string());
    verify_runtime_dir(&runtime_dir)?;
    let ui_path = runtime_dir.join("ui.sock");
    remove_stale_socket(&ui_path)?;
    let listener = UnixListener::bind(&ui_path)?;
    fs::set_permissions(&ui_path, fs::Permissions::from_mode(0o600))?;

    let mut child = launch_qml(
        profile_uid,
        &runtime_dir,
        &ui_path,
        capabilities.wayland_channel,
    )?;
    let result = accept_ui(&listener).and_then(|mut ui| {
        ui.set_read_timeout(Some(UI_ENTRY_TIMEOUT))?;
        ui.set_write_timeout(Some(UI_ENTRY_TIMEOUT))?;
        let (setup, mut password) = read_ui_entry(&mut ui)?;
        let helper = AccountEntryHelper::lock_down(capabilities.entry_channel)?;
        let outcome = helper.submit(&setup, &mut password)?;
        let frame = serde_json::to_vec(&UiOutcome {
            v: 1,
            ok: outcome.ok,
            code: account_entry_code(outcome.code),
            account_id: outcome.account_id.as_deref(),
        })
        .map_err(|_| BridgeError::InvalidFrame)?;
        ui.write_all(&frame)?;
        ui.write_all(b"\n")?;
        ui.flush()?;
        Ok(())
    });
    drop(listener);
    let _ = fs::remove_file(&ui_path);
    finish_child(&mut child, result)
}

fn read_ui_entry(
    ui: &mut UnixStream,
) -> Result<(OpenProtocolSetup, Zeroizing<Vec<u8>>), BridgeError> {
    let mut reader = BufReader::new(ui);
    let setup = read_frame(&mut reader, MAX_SETUP_BYTES)?;
    let frame: UiSetupFrame =
        serde_json::from_slice(&setup).map_err(|_| BridgeError::InvalidFrame)?;
    if frame.v != 1 {
        return Err(BridgeError::InvalidFrame);
    }
    let password = Zeroizing::new(read_frame(&mut reader, MAX_PASSWORD_BYTES)?);
    if password.is_empty()
        || password
            .iter()
            .any(|byte| *byte == 0 || *byte == b'\r' || *byte == b'\n')
    {
        return Err(BridgeError::InvalidFrame);
    }
    Ok((frame.setup, password))
}

fn read_frame(reader: &mut impl BufRead, maximum: usize) -> Result<Vec<u8>, BridgeError> {
    let mut frame = Vec::new();
    let mut bounded = Read::take(reader, (maximum + 2) as u64);
    let read = bounded.read_until(b'\n', &mut frame)?;
    if read == 0 || frame.last() != Some(&b'\n') || frame.len() > maximum + 1 {
        return Err(BridgeError::InvalidFrame);
    }
    frame.pop();
    if frame.last() == Some(&b'\r') {
        return Err(BridgeError::InvalidFrame);
    }
    Ok(frame)
}

fn account_entry_code(code: punar_pimd::AccountEntryCode) -> &'static str {
    use punar_pimd::AccountEntryCode;
    match code {
        AccountEntryCode::Connected => "connected",
        AccountEntryCode::InvalidCredentials => "invalid_credentials",
        AccountEntryCode::ProviderUnreachable => "provider_unreachable",
        AccountEntryCode::TlsValidationFailed => "tls_validation_failed",
        AccountEntryCode::InvalidConfiguration => "invalid_configuration",
        AccountEntryCode::StorageEncryptionRequired => "storage_encryption_required",
        AccountEntryCode::Internal => "internal",
    }
}

fn verify_runtime_dir(path: &Path) -> Result<(), BridgeError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BridgeError::InvalidActivation);
    }
    Ok(())
}

fn remove_stale_socket(path: &Path) -> Result<(), BridgeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path)?,
        Ok(_) => return Err(BridgeError::InvalidActivation),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn launch_qml(
    profile_uid: u32,
    runtime_dir: &Path,
    ui_path: &Path,
    wayland_channel: OwnedFd,
) -> Result<Child, BridgeError> {
    let flags = fcntl_getfd(&wayland_channel)?;
    fcntl_setfd(&wayland_channel, flags.difference(FdFlags::CLOEXEC))?;
    let raw_wayland = wayland_channel.as_raw_fd().to_string();

    let spawn = Command::new(QML_PROGRAM)
        .args(["-p", QML_ROOT])
        .env_clear()
        .env("HOME", runtime_dir)
        .env("LANG", "C.UTF-8")
        .env("PATH", "/usr/bin")
        .env("PUNAR_MAIL_ACCOUNT_SOCKET", ui_path)
        .env("PUNAR_PROFILE_UID", profile_uid.to_string())
        .env("QML_IMPORT_PATH", "/usr/share/punar/shell")
        .env("QT_QPA_PLATFORM", "wayland")
        .env("QT_QUICK_BACKEND", "software")
        .env("WAYLAND_SOCKET", raw_wayland)
        .env("XDG_DATA_DIRS", "/usr/local/share:/usr/share")
        .env("XDG_RUNTIME_DIR", runtime_dir)
        .current_dir(runtime_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn();

    fcntl_setfd(&wayland_channel, flags | FdFlags::CLOEXEC)?;
    drop(wayland_channel);
    Ok(spawn?)
}

fn accept_ui(listener: &UnixListener) -> Result<UnixStream, BridgeError> {
    let mut fds = [PollFd::new(listener, PollFlags::IN)];
    let timeout = Timespec {
        tv_sec: UI_CONNECT_TIMEOUT.as_secs().try_into().unwrap_or(i64::MAX),
        tv_nsec: UI_CONNECT_TIMEOUT.subsec_nanos().into(),
    };
    if poll(&mut fds, Some(&timeout))? == 0 {
        return Err(BridgeError::UiTimeout);
    }
    let ready = fds[0].revents();
    if ready.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
        || !ready.contains(PollFlags::IN)
    {
        return Err(BridgeError::InvalidActivation);
    }
    Ok(listener.accept()?.0)
}

fn finish_child(child: &mut Child, result: Result<(), BridgeError>) -> Result<(), BridgeError> {
    if result.is_err() {
        let _ = child.kill();
    }
    let deadline = Instant::now() + UI_EXIT_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait()?;
            return result.and(Err(BridgeError::UiFailure));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    result?;
    if status.success() {
        Ok(())
    } else {
        Err(BridgeError::UiFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::{AddressFamily, SocketAddrUnix, bind, listen, socket_with};

    fn listener(path: &Path, socket_type: SocketType) -> OwnedFd {
        let fd = socket_with(AddressFamily::UNIX, socket_type, SocketFlags::CLOEXEC, None).unwrap();
        bind(&fd, &SocketAddrUnix::new(path).unwrap()).unwrap();
        listen(&fd, 4).unwrap();
        fd
    }

    #[test]
    fn profile_and_activation_are_closed() {
        assert_eq!(parse_profile_uid(Some("1000".into())).unwrap(), 1000);
        for value in [None, Some("0".into()), Some("01000".into())] {
            assert!(parse_profile_uid(value).is_err());
        }

        let root = std::env::temp_dir().join(format!("punar-mail-account-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        assert!(
            select_activation_descriptor(vec![(
                Some(LAUNCH_FD_NAME.into()),
                listener(&root.join("launch.sock"), SocketType::SEQPACKET),
            )])
            .is_ok()
        );
        assert!(
            select_activation_descriptor(vec![(
                Some("other".into()),
                listener(&root.join("other.sock"), SocketType::SEQPACKET),
            )])
            .is_err()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn secret_frames_are_separate_bounded_and_control_free() {
        let setup = br#"{"v":1,"setup":{"identity":{"display_name":"Alice","primary_address":{"name":"Alice","address":"alice@example.com"}},"config":{"username":"alice@example.com","imap":{"host":"imap.example.com","port":993,"security":"tls"},"smtp":{"host":"smtp.example.com","port":465,"security":"tls"}}}}"#;
        let mut input = Vec::from(setup.as_slice());
        input.extend_from_slice(b"\nsecret-value\n");
        let mut cursor = std::io::Cursor::new(input);
        let (decoded, password) = read_ui_entry_stream(&mut cursor).unwrap();
        assert_eq!(decoded.config.imap.host, "imap.example.com");
        assert_eq!(&*password, b"secret-value");

        let mut bad = std::io::Cursor::new(b"{}\n\n".to_vec());
        assert!(read_ui_entry_stream(&mut bad).is_err());
    }

    fn read_ui_entry_stream(
        stream: &mut impl BufRead,
    ) -> Result<(OpenProtocolSetup, Zeroizing<Vec<u8>>), BridgeError> {
        let setup = read_frame(stream, MAX_SETUP_BYTES)?;
        let frame: UiSetupFrame =
            serde_json::from_slice(&setup).map_err(|_| BridgeError::InvalidFrame)?;
        if frame.v != 1 {
            return Err(BridgeError::InvalidFrame);
        }
        let password = Zeroizing::new(read_frame(stream, MAX_PASSWORD_BYTES)?);
        if password.is_empty()
            || password
                .iter()
                .any(|byte| *byte == 0 || *byte == b'\r' || *byte == b'\n')
        {
            return Err(BridgeError::InvalidFrame);
        }
        Ok((frame.setup, password))
    }
}
