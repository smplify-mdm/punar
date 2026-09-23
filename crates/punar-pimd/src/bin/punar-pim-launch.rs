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
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use punar_pimd::{
    AccountHelperClaim, AccountLaunch, ClientGrant, MailLaunch, PimClient, ProviderType,
    client_channel_pair, receive_account_helper_channel, send_account_helper_claim,
    send_account_launch, send_client_channel, send_mail_launch,
};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};
use serde::Deserialize;
use serde_json::{Value, json};
use thiserror::Error;

const PROC_ROOT: &str = "/proc";
const COMPOSITOR: &str = "/usr/bin/Hyprland";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const MAX_ENVIRON_BYTES: u64 = 1024 * 1024;
const MAX_PIM_RESPONSE_BYTES: u64 = 8 * 1024;
const PIM_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchKind {
    Mail,
    AccountAdd,
    AccountManage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LaunchRequest {
    kind: LaunchKind,
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
    #[error("Mail account setup protocol failed")]
    Protocol,
    #[error("Mail broker I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("Mail broker kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
}

impl BrokerError {
    /// Stable, non-secret support codes for the privileged launch boundary.
    ///
    /// `punard` deliberately does not reflect the broker's stderr into the
    /// desktop protocol. Distinct exit codes still let diagnostics identify
    /// which closed failure class refused the launch without disclosing a
    /// process path, account value, or credential.
    fn exit_code(&self) -> u8 {
        match self {
            Self::InvalidRequest => 2,
            Self::NotRoot => 3,
            Self::SessionVerification => 4,
            Self::SessionUnavailable => 5,
            Self::Activation => 6,
            Self::Handoff => 7,
            Self::Protocol => 8,
            Self::Io(_) => 9,
            Self::Kernel(_) => 10,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("punar-pim-launch: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn run() -> Result<(), BrokerError> {
    if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
        return Err(BrokerError::NotRoot);
    }
    let request = parse_request(env::args_os().collect())?;
    let wayland = connect_verified_wayland(Path::new(PROC_ROOT), request)?;
    activate_services(request.profile_uid, request.kind)?;

    match request.kind {
        LaunchKind::Mail => launch_mail(request.profile_uid, wayland),
        LaunchKind::AccountAdd => launch_account_add(request.profile_uid, wayland),
        LaunchKind::AccountManage => launch_account_manage(request.profile_uid, wayland),
    }
}

fn launch_mail(profile_uid: u32, wayland: UnixStream) -> Result<(), BrokerError> {
    let mail_endpoint = grant_pim_channel(profile_uid, PimClient::Mail)?;
    let pim_control = connect_seqpacket(&PathBuf::from(format!(
        "/run/punar-mail-control/{profile_uid}/launch.sock"
    )))?;
    let id = launch_id()?;
    send_mail_launch(
        &pim_control,
        mail_endpoint,
        wayland.into(),
        &MailLaunch::new(id, profile_uid),
    )
    .map_err(|_| BrokerError::Handoff)?;
    Ok(())
}

fn launch_account_add(profile_uid: u32, wayland: UnixStream) -> Result<(), BrokerError> {
    let settings_endpoint = grant_pim_channel(profile_uid, PimClient::AccountConnect)?;
    let mut settings = UnixStream::from(settings_endpoint);
    settings.set_read_timeout(Some(PIM_REQUEST_TIMEOUT))?;
    settings.set_write_timeout(Some(PIM_REQUEST_TIMEOUT))?;
    let setup_id = begin_account_connect(&mut settings)?;

    let result = (|| {
        let helper_control = connect_seqpacket(&PathBuf::from(format!(
            "/run/punar-pimd/{profile_uid}/account-helper.sock"
        )))?;
        send_account_helper_claim(
            &helper_control,
            &AccountHelperClaim::new(&setup_id, profile_uid),
        )
        .map_err(|_| BrokerError::Handoff)?;
        let helper = receive_account_helper_channel(&helper_control, &setup_id, profile_uid)
            .map_err(|_| BrokerError::Handoff)?;
        let account_control = connect_seqpacket(&PathBuf::from(format!(
            "/run/punar-mail-account-control/{profile_uid}/launch.sock"
        )))?;
        send_account_launch(
            &account_control,
            helper.channel,
            wayland.into(),
            &AccountLaunch::new(launch_id()?, &setup_id, profile_uid),
        )
        .map_err(|_| BrokerError::Handoff)
    })();

    if result.is_err() {
        let _ = cancel_account_connect(&mut settings, &setup_id);
    }
    result
}

fn launch_account_manage(profile_uid: u32, wayland: UnixStream) -> Result<(), BrokerError> {
    let settings_endpoint = grant_pim_channel(profile_uid, PimClient::AccountManager)?;
    let control = connect_seqpacket(&PathBuf::from(format!(
        "/run/punar-mail-accounts-control/{profile_uid}/launch.sock"
    )))?;
    send_mail_launch(
        &control,
        settings_endpoint,
        wayland.into(),
        &MailLaunch::new(launch_id()?, profile_uid),
    )
    .map_err(|_| BrokerError::Handoff)
}

fn grant_pim_channel(profile_uid: u32, client: PimClient) -> Result<OwnedFd, BrokerError> {
    let pim_control = connect_seqpacket(&PathBuf::from(format!(
        "/run/punar-pimd/{profile_uid}/application.sock"
    )))?;
    let (application_endpoint, pim_endpoint) =
        client_channel_pair().map_err(|_| BrokerError::Handoff)?;
    let grant_id = launch_id()?.replacen("launch_", "grant_", 1);
    send_client_channel(
        &pim_control,
        pim_endpoint,
        &ClientGrant::new(grant_id, profile_uid, client),
    )
    .map_err(|_| BrokerError::Handoff)?;
    Ok(application_endpoint)
}

fn parse_request(args: Vec<std::ffi::OsString>) -> Result<LaunchRequest, BrokerError> {
    if args.len() != 4 {
        return Err(BrokerError::InvalidRequest);
    }
    let kind = match args[1].to_str() {
        Some("mail") => LaunchKind::Mail,
        Some("account-add") => LaunchKind::AccountAdd,
        Some("account-manage") => LaunchKind::AccountManage,
        _ => return Err(BrokerError::InvalidRequest),
    };
    let uid = canonical_number(&args[2])?;
    let pid = canonical_number(&args[3])?;
    let caller_pid = i32::try_from(pid).map_err(|_| BrokerError::InvalidRequest)?;
    if uid == 0 || caller_pid <= 0 {
        return Err(BrokerError::InvalidRequest);
    }
    Ok(LaunchRequest {
        kind,
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
    let display = display_through_caller_root(proc_root, request.caller_pid, &display)?;
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

fn display_through_caller_root(
    proc_root: &Path,
    caller_pid: i32,
    display: &Path,
) -> Result<PathBuf, BrokerError> {
    let caller_root = proc_root.join(caller_pid.to_string()).join("root");
    let caller_root_metadata = fs::metadata(&caller_root)?;
    let broker_root_metadata = fs::metadata("/")?;
    if !caller_root_metadata.file_type().is_dir()
        || caller_root_metadata.dev() != broker_root_metadata.dev()
        || caller_root_metadata.ino() != broker_root_metadata.ino()
    {
        return Err(BrokerError::SessionVerification);
    }
    let relative = display
        .strip_prefix("/")
        .map_err(|_| BrokerError::SessionVerification)?;
    Ok(caller_root.join(relative))
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

fn activate_services(uid: u32, kind: LaunchKind) -> Result<(), BrokerError> {
    let units = service_units(uid, kind);
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

fn service_units(uid: u32, kind: LaunchKind) -> Vec<String> {
    let mut units = vec![format!("punar-pimd-application@{uid}.socket")];
    if kind == LaunchKind::AccountAdd {
        units.push(format!("punar-pimd-account-helper@{uid}.socket"));
    }
    units.push(match kind {
        LaunchKind::Mail => format!("punar-mail@{uid}.socket"),
        LaunchKind::AccountAdd => format!("punar-mail-account@{uid}.socket"),
        LaunchKind::AccountManage => format!("punar-mail-accounts@{uid}.socket"),
    });
    units
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PimResponse {
    v: u64,
    id: String,
    method: String,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BeginConnectResult {
    kind: String,
    setup_id: String,
    provider_type: ProviderType,
    state: String,
}

fn begin_account_connect(stream: &mut UnixStream) -> Result<String, BrokerError> {
    let value = pim_call(
        stream,
        "account-connect-1",
        "accounts.begin_connect",
        json!({"provider_type": "open_protocols"}),
    )?;
    let result: BeginConnectResult =
        serde_json::from_value(value).map_err(|_| BrokerError::Protocol)?;
    if result.kind != "account_setup"
        || result.provider_type != ProviderType::OpenProtocols
        || result.state != "awaiting_credentials"
        || !valid_setup_id(&result.setup_id)
    {
        return Err(BrokerError::Protocol);
    }
    Ok(result.setup_id)
}

fn cancel_account_connect(stream: &mut UnixStream, setup_id: &str) -> Result<(), BrokerError> {
    let _ = pim_call(
        stream,
        "account-cancel-1",
        "accounts.cancel_connect",
        json!({"setup_id": setup_id}),
    )?;
    Ok(())
}

fn pim_call(
    stream: &mut UnixStream,
    id: &str,
    method: &str,
    params: Value,
) -> Result<Value, BrokerError> {
    let request = serde_json::to_vec(&json!({
        "v": 1,
        "id": id,
        "method": method,
        "params": params,
    }))
    .map_err(|_| BrokerError::Protocol)?;
    stream.write_all(&request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut frame = Vec::new();
    let mut bounded = BufReader::new(&mut *stream).take(MAX_PIM_RESPONSE_BYTES + 2);
    let read = bounded.read_until(b'\n', &mut frame)?;
    if read == 0 || frame.last() != Some(&b'\n') || frame.len() as u64 > MAX_PIM_RESPONSE_BYTES + 1
    {
        return Err(BrokerError::Protocol);
    }
    frame.pop();
    if frame.last() == Some(&b'\r') {
        frame.pop();
    }
    let response: PimResponse =
        serde_json::from_slice(&frame).map_err(|_| BrokerError::Protocol)?;
    if response.v != 1 || response.id != id || response.method != method || response.error.is_some()
    {
        return Err(BrokerError::Protocol);
    }
    response.result.ok_or(BrokerError::Protocol)
}

fn valid_setup_id(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("setup_") else {
        return false;
    };
    value.len() <= 80
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
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
    fn broker_failure_codes_are_stable_and_closed() {
        assert_eq!(BrokerError::InvalidRequest.exit_code(), 2);
        assert_eq!(BrokerError::NotRoot.exit_code(), 3);
        assert_eq!(BrokerError::SessionVerification.exit_code(), 4);
        assert_eq!(BrokerError::SessionUnavailable.exit_code(), 5);
        assert_eq!(BrokerError::Activation.exit_code(), 6);
        assert_eq!(BrokerError::Handoff.exit_code(), 7);
        assert_eq!(BrokerError::Protocol.exit_code(), 8);
        assert_eq!(BrokerError::Io(io::Error::other("test")).exit_code(), 9);
        assert_eq!(BrokerError::Kernel(rustix::io::Errno::INVAL).exit_code(), 10);
    }

    #[test]
    fn request_has_one_fixed_app_and_canonical_numeric_identity() {
        let parsed = parse_request(vec![
            "broker".into(),
            "mail".into(),
            "1000".into(),
            "42".into(),
        ])
        .unwrap();
        assert_eq!(parsed.kind, LaunchKind::Mail);
        assert_eq!(parsed.profile_uid, 1000);
        assert_eq!(parsed.caller_pid, 42);
        let account = parse_request(vec![
            "broker".into(),
            "account-add".into(),
            "1000".into(),
            "42".into(),
        ])
        .unwrap();
        assert_eq!(account.kind, LaunchKind::AccountAdd);
        let manager = parse_request(vec![
            "broker".into(),
            "account-manage".into(),
            "1000".into(),
            "42".into(),
        ])
        .unwrap();
        assert_eq!(manager.kind, LaunchKind::AccountManage);
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
            vec![
                "broker".into(),
                "account-remove".into(),
                "1000".into(),
                "42".into(),
            ],
        ] {
            assert!(parse_request(args).is_err());
        }
    }

    #[test]
    fn setup_ids_are_closed_and_bounded() {
        assert!(valid_setup_id("setup_A1"));
        assert!(!valid_setup_id("setup_"));
        assert!(!valid_setup_id("setup_a-b"));
        assert!(!valid_setup_id("other_A1"));
        assert!(!valid_setup_id(&format!("setup_{}", "a".repeat(80))));
    }

    #[test]
    fn broker_explicitly_starts_only_each_launch_entry_socket() {
        assert_eq!(
            service_units(1000, LaunchKind::Mail),
            [
                "punar-pimd-application@1000.socket",
                "punar-mail@1000.socket",
            ]
        );
        assert_eq!(
            service_units(1000, LaunchKind::AccountAdd),
            [
                "punar-pimd-application@1000.socket",
                "punar-pimd-account-helper@1000.socket",
                "punar-mail-account@1000.socket",
            ]
        );
        assert_eq!(
            service_units(1000, LaunchKind::AccountManage),
            [
                "punar-pimd-application@1000.socket",
                "punar-mail-accounts@1000.socket",
            ]
        );
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
    fn sandboxed_broker_reaches_only_the_verified_callers_root() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "punar-pim-launch-caller-root-{}",
            launch_id().unwrap()
        ));
        let proc = root.join("42");
        fs::create_dir_all(&proc).unwrap();
        symlink("/", proc.join("root")).unwrap();
        assert_eq!(
            display_through_caller_root(
                &root,
                42,
                Path::new("/run/user/1000/wayland-1")
            )
            .unwrap(),
            proc.join("root/run/user/1000/wayland-1")
        );

        fs::remove_file(proc.join("root")).unwrap();
        fs::create_dir(proc.join("root")).unwrap();
        assert!(
            display_through_caller_root(
                &root,
                42,
                Path::new("/run/user/1000/wayland-1")
            )
            .is_err()
        );
        let _ = fs::remove_dir_all(root);
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
