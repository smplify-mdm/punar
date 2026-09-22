//! Locked-identity bridge between Punar Mail's QML process and `punar-pimd`.
//!
//! This binary is intentionally not a public listener.  systemd gives it one
//! root-only sequenced-packet launch socket; the root broker transfers a
//! Mail-only PIM stream plus a verified Wayland stream.  The QML child runs as
//! the same dedicated service identity and can reach only a private runtime
//! socket in a mode-0700 directory.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use punar_pimd::{MailLaunchCapabilities, lock_down_current_process, receive_mail_launch};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::net::{SocketFlags, SocketType, accept_with, sockopt};
use thiserror::Error;

const PROFILE_UID_ENV: &str = "PUNAR_PROFILE_UID";
const LAUNCH_FD_NAME: &str = "launch";
const QML_PROGRAM: &str = "/usr/bin/qs";
const QML_ROOT: &str = "/usr/share/punar/shell/Mail";
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const UI_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const UI_EXIT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Error)]
enum BridgeError {
    #[error("Mail bridge profile is invalid")]
    InvalidProfile,
    #[error("Mail bridge activation is invalid")]
    InvalidActivation,
    #[error("Mail bridge activation could not be read")]
    Activation(#[from] sd_listen_fds::Error),
    #[error("Mail bridge kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
    #[error("Mail bridge launch was refused")]
    Launch(#[from] punar_pimd::MailLaunchError),
    #[error("Mail bridge process lockdown failed")]
    Lockdown(#[from] punar_pimd::ProcessSecurityError),
    #[error("Mail bridge local transport failed")]
    Io(#[from] io::Error),
    #[error("Mail interface did not connect in time")]
    UiTimeout,
    #[error("Mail interface exited unsuccessfully")]
    UiFailure,
    #[error("Mail interface sent an invalid frame")]
    InvalidFrame,
    #[error("Mail relay worker failed")]
    Worker,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("punar-mail-bridge: {error}");
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

    lock_down_current_process()?;
    let launch_control = accept_with(&launch_listener, SocketFlags::CLOEXEC)?;
    let capabilities = receive_mail_launch(launch_control, profile_uid)?;
    serve_mail_ui(profile_uid, capabilities)
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

fn serve_mail_ui(
    profile_uid: u32,
    capabilities: MailLaunchCapabilities,
) -> Result<(), BridgeError> {
    let runtime_dir = PathBuf::from("/run/punar-mail").join(profile_uid.to_string());
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
    let result =
        accept_ui(&listener).and_then(|ui| relay(ui, UnixStream::from(capabilities.pim_channel)));
    drop(listener);
    let _ = fs::remove_file(&ui_path);
    finish_child(&mut child, result)
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
    let profile_uid = profile_uid.to_string();

    let spawn = Command::new(QML_PROGRAM)
        .args(["-p", QML_ROOT])
        .env_clear()
        .env("HOME", runtime_dir)
        .env("LANG", "C.UTF-8")
        .env("PATH", "/usr/bin")
        .env("PUNAR_MAIL_SOCKET", ui_path)
        .env("PUNAR_PROFILE_UID", profile_uid)
        .env("QML_IMPORT_PATH", "/usr/share/punar/shell")
        .env("QT_QPA_PLATFORM", "wayland")
        // The locked service deliberately has no DRM devices. Keep Qt's
        // scene graph on its software backend instead of silently widening
        // the Mail process' hardware authority.
        .env("QT_QUICK_BACKEND", "software")
        .env("WAYLAND_SOCKET", raw_wayland)
        .env("XDG_DATA_DIRS", "/usr/local/share:/usr/share")
        .env("XDG_RUNTIME_DIR", runtime_dir)
        .current_dir(runtime_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn();

    // Only the spawned QML process may retain the display capability.
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

fn relay(ui: UnixStream, pim: UnixStream) -> Result<(), BridgeError> {
    let ui_reader = ui.try_clone()?;
    let pim_writer = pim.try_clone()?;
    let request = thread::Builder::new()
        .name("punar-mail-requests".into())
        .spawn(move || relay_frames(ui_reader, pim_writer, MAX_REQUEST_BYTES))
        .map_err(|_| BridgeError::Worker)?;
    let response = thread::Builder::new()
        .name("punar-mail-responses".into())
        .spawn(move || relay_frames(pim, ui, MAX_RESPONSE_BYTES))
        .map_err(|_| BridgeError::Worker)?;

    let request = request.join().map_err(|_| BridgeError::Worker)?;
    let response = response.join().map_err(|_| BridgeError::Worker)?;
    request?;
    response?;
    Ok(())
}

fn relay_frames(
    source: UnixStream,
    mut destination: UnixStream,
    max_bytes: usize,
) -> Result<(), BridgeError> {
    let mut reader = BufReader::new(source);
    while let Some(frame) = read_frame(&mut reader, max_bytes)? {
        destination.write_all(&frame)?;
    }
    destination.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

fn read_frame(reader: &mut impl BufRead, max_bytes: usize) -> Result<Option<Vec<u8>>, BridgeError> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(BridgeError::InvalidFrame)
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |newline| newline + 1);
        if frame.len().saturating_add(take) > max_bytes.saturating_add(1) {
            return Err(BridgeError::InvalidFrame);
        }
        frame.extend_from_slice(&available[..take]);
        reader.consume(take);
        if frame.last() == Some(&b'\n') {
            return Ok(Some(frame));
        }
    }
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
        thread::sleep(Duration::from_millis(20));
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

    fn temp_root() -> PathBuf {
        let mut suffix = [0_u8; 12];
        getrandom::fill(&mut suffix).unwrap();
        let suffix = suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::env::temp_dir().join(format!("punar-mail-bridge-{suffix}"))
    }

    fn listener(path: &Path, socket_type: SocketType) -> OwnedFd {
        let fd = socket_with(AddressFamily::UNIX, socket_type, SocketFlags::CLOEXEC, None).unwrap();
        bind(&fd, &SocketAddrUnix::new(path).unwrap()).unwrap();
        listen(&fd, 4).unwrap();
        fd
    }

    #[test]
    fn profile_uid_and_activation_are_closed() {
        assert_eq!(parse_profile_uid(Some("1000".into())).unwrap(), 1000);
        for value in [None, Some("0".into()), Some("01000".into())] {
            assert!(parse_profile_uid(value).is_err());
        }

        let root = temp_root();
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
        assert!(
            select_activation_descriptor(vec![(
                Some(LAUNCH_FD_NAME.into()),
                listener(&root.join("stream.sock"), SocketType::STREAM),
            )])
            .is_err()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bounded_frame_reader_preserves_lines_and_rejects_partial_or_oversized_data() {
        let mut valid = BufReader::new(&b"one\ntwo\n"[..]);
        assert_eq!(read_frame(&mut valid, 3).unwrap().unwrap(), b"one\n");
        assert_eq!(read_frame(&mut valid, 3).unwrap().unwrap(), b"two\n");
        assert!(read_frame(&mut valid, 3).unwrap().is_none());

        let mut partial = BufReader::new(&b"partial"[..]);
        assert!(matches!(
            read_frame(&mut partial, 16),
            Err(BridgeError::InvalidFrame)
        ));
        let mut oversized = BufReader::new(&b"12345\n"[..]);
        assert!(matches!(
            read_frame(&mut oversized, 4),
            Err(BridgeError::InvalidFrame)
        ));
    }

    #[test]
    fn relay_is_bidirectional_and_closes_on_orderly_eof() {
        let (mut ui_client, ui_bridge) = UnixStream::pair().unwrap();
        let (pim_bridge, mut pim_service) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || relay(ui_bridge, pim_bridge).unwrap());

        ui_client.write_all(b"request\n").unwrap();
        let mut request = [0_u8; 8];
        std::io::Read::read_exact(&mut pim_service, &mut request).unwrap();
        assert_eq!(&request, b"request\n");
        pim_service.write_all(b"response\n").unwrap();
        let mut response = [0_u8; 9];
        std::io::Read::read_exact(&mut ui_client, &mut response).unwrap();
        assert_eq!(&response, b"response\n");

        ui_client.shutdown(std::net::Shutdown::Write).unwrap();
        pim_service.shutdown(std::net::Shutdown::Write).unwrap();
        worker.join().unwrap();
    }
}
