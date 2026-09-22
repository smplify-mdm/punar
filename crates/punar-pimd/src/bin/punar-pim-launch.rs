//! Fixed privileged broker for first-party PIM application launches.
//!
//! `punard` invokes this root-only helper with the kernel-attested caller uid
//! and pid. The helper connects to that caller's real Hyprland socket, verifies
//! the socket peer and root-owned compositor executable, activates the two
//! dormant services, and transfers unnamed capabilities. It accepts no paths,
//! commands, environment overrides, URLs, or secret material from the caller.

#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use punar_pimd::{
    ClientGrant, MailLaunch, PimClient, client_channel_pair, send_client_channel, send_mail_launch,
};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};
use thiserror::Error;

const PROC_ROOT: &str = "/proc";
const COMPOSITOR: &str = "/usr/bin/Hyprland";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const MAX_ENVIRON_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LaunchRequest {
    profile_uid: u32,
    caller_pid: i32,
}

#[derive(Debug, Error)]
enum BrokerError {
    #[error("Mail launch request is invalid")]
    InvalidRequest,
    #[error("Mail launch broker must run as root")]
    NotRoot,
    #[error("desktop session identity could not be verified")]
    SessionVerification,
    #[error("desktop session is unavailable")]
    SessionUnavailable,
    #[error("Mail services could not be activated")]
    Activation,
    #[error("Mail capability handoff failed")]
    Handoff,
    #[error("Mail broker I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("Mail broker kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("punar-pim-launch: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), BrokerError> {
    if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
        return Err(BrokerError::NotRoot);
    }
    let request = parse_request(env::args_os().collect())?;
    let wayland = connect_verified_wayland(Path::new(PROC_ROOT), request)?;
    activate_services(request.profile_uid)?;

    let pim_control = connect_seqpacket(&PathBuf::from(format!(
        "/run/punar-pimd/{}/application.sock",
        request.profile_uid
    )))?;
    let mail_control = connect_seqpacket(&PathBuf::from(format!(
        "/run/punar-mail-control/{}/launch.sock",
        request.profile_uid
    )))?;
    let (mail_endpoint, pim_endpoint) = client_channel_pair().map_err(|_| BrokerError::Handoff)?;
    let id = launch_id()?;
    send_client_channel(
        &pim_control,
        pim_endpoint,
        &ClientGrant::new(
            id.replacen("launch_", "grant_", 1),
            request.profile_uid,
            PimClient::Mail,
        ),
    )
    .map_err(|_| BrokerError::Handoff)?;
    send_mail_launch(
        &mail_control,
        mail_endpoint,
        wayland.into(),
        &MailLaunch::new(id, request.profile_uid),
    )
    .map_err(|_| BrokerError::Handoff)?;
    Ok(())
}

fn parse_request(args: Vec<std::ffi::OsString>) -> Result<LaunchRequest, BrokerError> {
    if args.len() != 4 || args[1] != "mail" {
        return Err(BrokerError::InvalidRequest);
    }
    let uid = canonical_number(&args[2])?;
    let pid = canonical_number(&args[3])?;
    let caller_pid = i32::try_from(pid).map_err(|_| BrokerError::InvalidRequest)?;
    if uid == 0 || caller_pid <= 0 {
        return Err(BrokerError::InvalidRequest);
    }
    Ok(LaunchRequest {
        profile_uid: uid,
        caller_pid,
    })
}

fn canonical_number(value: &std::ffi::OsStr) -> Result<u32, BrokerError> {
    let value = value.to_str().ok_or(BrokerError::InvalidRequest)?;
    let parsed = value
        .parse::<u32>()
        .map_err(|_| BrokerError::InvalidRequest)?;
    if parsed.to_string() != value {
        return Err(BrokerError::InvalidRequest);
    }
    Ok(parsed)
}

fn connect_verified_wayland(
    proc_root: &Path,
    request: LaunchRequest,
) -> Result<UnixStream, BrokerError> {
    verify_process_uid(proc_root, request.caller_pid, request.profile_uid)?;
    let environ = read_bounded(
        &proc_root
            .join(request.caller_pid.to_string())
            .join("environ"),
    )?;
    let display = display_from_environ(&environ, request.profile_uid)?;
    let stream = UnixStream::connect(display).map_err(|_| BrokerError::SessionUnavailable)?;
    let peer = rustix::net::sockopt::socket_peercred(&stream)?;
    if peer.uid.as_raw() != request.profile_uid {
        return Err(BrokerError::SessionVerification);
    }
    let compositor_pid = peer.pid.as_raw_nonzero().get();
    verify_compositor(
        proc_root,
        compositor_pid,
        request.profile_uid,
        Path::new(COMPOSITOR),
    )?;
    Ok(stream)
}

fn verify_process_uid(proc_root: &Path, pid: i32, expected_uid: u32) -> Result<(), BrokerError> {
    let status = read_bounded(&proc_root.join(pid.to_string()).join("status"))?;
    let text = std::str::from_utf8(&status).map_err(|_| BrokerError::SessionVerification)?;
    let real_uid = text.lines().find_map(|line| {
        line.strip_prefix("Uid:")
            .and_then(|rest| rest.split_ascii_whitespace().next())
            .and_then(|uid| uid.parse::<u32>().ok())
    });
    if real_uid != Some(expected_uid) {
        return Err(BrokerError::SessionVerification);
    }
    Ok(())
}

fn display_from_environ(environ: &[u8], uid: u32) -> Result<PathBuf, BrokerError> {
    let mut runtime = None;
    let mut display = None;
    for entry in environ.split(|byte| *byte == 0) {
        if let Some(value) = entry.strip_prefix(b"XDG_RUNTIME_DIR=") {
            runtime = std::str::from_utf8(value).ok();
        } else if let Some(value) = entry.strip_prefix(b"WAYLAND_DISPLAY=") {
            display = std::str::from_utf8(value).ok();
        }
    }
    let expected_runtime = format!("/run/user/{uid}");
    if runtime != Some(expected_runtime.as_str()) {
        return Err(BrokerError::SessionVerification);
    }
    let display = display.ok_or(BrokerError::SessionVerification)?;
    let suffix = display
        .strip_prefix("wayland-")
        .ok_or(BrokerError::SessionVerification)?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BrokerError::SessionVerification);
    }
    Ok(PathBuf::from(expected_runtime).join(display))
}

fn verify_compositor(
    proc_root: &Path,
    pid: i32,
    expected_uid: u32,
    expected_executable: &Path,
) -> Result<(), BrokerError> {
    verify_process_uid(proc_root, pid, expected_uid)?;
    let executable = fs::read_link(proc_root.join(pid.to_string()).join("exe"))?;
    if executable != expected_executable {
        return Err(BrokerError::SessionVerification);
    }
    let metadata = fs::metadata(expected_executable)?;
    if !trusted_executable_metadata(
        metadata.uid(),
        metadata.mode(),
        metadata.file_type().is_file(),
    ) {
        return Err(BrokerError::SessionVerification);
    }
    Ok(())
}

fn trusted_executable_metadata(uid: u32, mode: u32, regular: bool) -> bool {
    uid == 0 && regular && mode & 0o022 == 0
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, BrokerError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_ENVIRON_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ENVIRON_BYTES {
        return Err(BrokerError::SessionVerification);
    }
    Ok(bytes)
}

fn activate_services(uid: u32) -> Result<(), BrokerError> {
    let units = [
        format!("punar-pimd-application@{uid}.socket"),
        format!("punar-pimd-account-helper@{uid}.socket"),
        format!("punar-mail@{uid}.socket"),
    ];
    let status = Command::new(SYSTEMCTL)
        .args(["--no-ask-password", "--quiet", "start"])
        .args(units)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(BrokerError::Activation)
    }
}

fn connect_seqpacket(path: &Path) -> Result<OwnedFd, BrokerError> {
    let descriptor = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    connect(&descriptor, &SocketAddrUnix::new(path)?)?;
    Ok(descriptor)
}

fn launch_id() -> Result<String, BrokerError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| BrokerError::Handoff)?;
    Ok(format!(
        "launch_{}",
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_one_fixed_app_and_canonical_numeric_identity() {
        let parsed = parse_request(vec![
            "broker".into(),
            "mail".into(),
            "1000".into(),
            "42".into(),
        ])
        .unwrap();
        assert_eq!(parsed.profile_uid, 1000);
        assert_eq!(parsed.caller_pid, 42);
        for args in [
            vec!["broker".into()],
            vec![
                "broker".into(),
                "calendar".into(),
                "1000".into(),
                "42".into(),
            ],
            vec!["broker".into(), "mail".into(), "0".into(), "42".into()],
            vec!["broker".into(), "mail".into(), "01000".into(), "42".into()],
            vec!["broker".into(), "mail".into(), "1000".into(), "0".into()],
        ] {
            assert!(parse_request(args).is_err());
        }
    }

    #[test]
    fn wayland_path_is_derived_only_from_the_expected_runtime() {
        let valid =
            b"HOME=/home/alice\0XDG_RUNTIME_DIR=/run/user/1000\0WAYLAND_DISPLAY=wayland-1\0";
        assert_eq!(
            display_from_environ(valid, 1000).unwrap(),
            PathBuf::from("/run/user/1000/wayland-1")
        );
        for environ in [
            b"XDG_RUNTIME_DIR=/tmp\0WAYLAND_DISPLAY=wayland-1\0".as_slice(),
            b"XDG_RUNTIME_DIR=/run/user/1000\0WAYLAND_DISPLAY=/tmp/fake\0".as_slice(),
            b"XDG_RUNTIME_DIR=/run/user/1000\0WAYLAND_DISPLAY=../wayland-1\0".as_slice(),
            b"XDG_RUNTIME_DIR=/run/user/1000\0WAYLAND_DISPLAY=wayland-a\0".as_slice(),
        ] {
            assert!(display_from_environ(environ, 1000).is_err());
        }
    }

    #[test]
    fn only_root_owned_immutable_regular_compositor_is_trusted() {
        assert!(trusted_executable_metadata(0, 0o100755, true));
        assert!(!trusted_executable_metadata(1000, 0o100755, true));
        assert!(!trusted_executable_metadata(0, 0o100775, true));
        assert!(!trusted_executable_metadata(0, 0o100777, true));
        assert!(!trusted_executable_metadata(0, 0o040755, false));
    }

    #[test]
    fn process_uid_parser_rejects_cross_user_or_malformed_status() {
        let root = std::env::temp_dir().join(format!("punar-pim-launch-{}", launch_id().unwrap()));
        let proc = root.join("42");
        fs::create_dir_all(&proc).unwrap();
        fs::write(
            proc.join("status"),
            "Name:\ttest\nUid:\t1000\t1000\t1000\t1000\n",
        )
        .unwrap();
        assert!(verify_process_uid(&root, 42, 1000).is_ok());
        assert!(verify_process_uid(&root, 42, 1001).is_err());
        fs::write(proc.join("status"), "Name:\ttest\nUid:\tnot-a-number\n").unwrap();
        assert!(verify_process_uid(&root, 42, 1000).is_err());
        let _ = fs::remove_dir_all(root);
    }
}
