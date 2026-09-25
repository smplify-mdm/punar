//! punar-smplifyd — Punar's built-in Smplify device agent.
//!
//! Identity and transport, nothing else: it generates the device key, redeems
//! the enrollment code for a certificate, and carries punard's control-plane
//! calls (docs/api/ipc.md sections 5.9-5.11) to Smplify's Linux device API
//! over mutually authenticated TLS. It reads no system state beyond five
//! os-release keys and the hostname, applies nothing, decides nothing, and
//! answers only root on its own socket. punard remains the single process
//! that mutates the OS and the owner of enrollment state, audit and every
//! surface a person sees.
//!
//! systemd owns the socket (`punar-smplifyd.socket`) and starts the agent on
//! the first call, so a device that never enrolled runs none of this code;
//! the agent goes dormant again once nothing of an identity is left
//! ([`punar_smplifyd::activation`]).
//!
//! Decision record: docs/development/smplify-enrollment.md.
#![forbid(unsafe_code)]

mod device;
mod discovery;
mod http;
mod identity;
mod protocol;
mod server;
mod upstream;

use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;

use punar_smplifyd::activation::{DORMANT_EXIT_STATUS, IDLE_BEFORE_DORMANT, LISTENER_NAME};
// The report bodies and their clock live in the library half of this crate,
// so punard's tests can compose the real translation (src/lib.rs).
use punar_smplifyd::{clock, status};

const DEFAULT_SOCKET: &str = "/run/punar-smplifyd/api.sock";
const DEFAULT_STATE_DIR: &str = "/var/lib/punar-smplifyd";
const DEFAULT_DISCOVERY_DIR: &str = "/etc/punar/smplify";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") | None => run(),
        Some("version") => {
            println!("punar-smplifyd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("punar-smplifyd: unknown command {other:?} (expected: run)");
            ExitCode::from(2)
        }
    }
}

fn run() -> ExitCode {
    let state_dir = std::env::var_os("PUNAR_SMPLIFYD_STATE_DIR")
        .or_else(|| std::env::var_os("STATE_DIRECTORY"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    let discovery_dir = std::env::var_os("PUNAR_SMPLIFYD_DISCOVERY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DISCOVERY_DIR));
    let daemon = server::Daemon::new(state_dir, discovery_dir);

    let passed = sd_listen_fds::get()
        .map_err(|_| ActivationError::Environment)
        .and_then(|descriptors| {
            let descriptors: Vec<_> = descriptors
                .into_iter()
                .map(|(name, descriptor)| (name, descriptor.into_std()))
                .collect();
            if descriptors.is_empty() {
                Ok(None)
            } else {
                select_listener(descriptors).map(Some)
            }
        });
    match passed {
        // systemd's socket: dormant when nothing of an identity is left.
        Ok(Some(listener)) => match daemon.serve_listener(listener, Some(IDLE_BEFORE_DORMANT)) {
            Ok(server::Stopped::Dormant) => {
                eprintln!(
                    "punar-smplifyd: no identity is held; dormant until the next call \
                     (exit {DORMANT_EXIT_STATUS})"
                );
                ExitCode::from(DORMANT_EXIT_STATUS)
            }
            Err(error) => {
                eprintln!("punar-smplifyd: cannot serve ({})", error.kind());
                ExitCode::FAILURE
            }
        },
        // Development and tests: bind the path, serve until stopped.
        Ok(None) => {
            let socket = std::env::var_os("PUNAR_SMPLIFYD_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
            match daemon.serve(&socket) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!(
                        "punar-smplifyd: cannot serve {} ({})",
                        socket.display(),
                        error.kind()
                    );
                    ExitCode::FAILURE
                }
            }
        }
        Err(why) => {
            eprintln!("punar-smplifyd: refusing the descriptors systemd passed: {why}");
            ExitCode::FAILURE
        }
    }
}

/// Why the descriptors systemd passed are not the one listener the unit
/// declares.
#[derive(Debug, PartialEq, Eq)]
enum ActivationError {
    /// `LISTEN_PID`/`LISTEN_FDS` are set but malformed.
    Environment,
    /// Not exactly one descriptor.
    Count(usize),
    /// Not named [`LISTENER_NAME`] (`FileDescriptorName=`).
    Name(Option<String>),
    /// Not a listening Unix stream socket.
    NotAListener,
}

impl std::fmt::Display for ActivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActivationError::Environment => write!(f, "the activation environment is malformed"),
            ActivationError::Count(n) => write!(f, "{n} descriptors, not one"),
            ActivationError::Name(name) => {
                write!(f, "a descriptor named {name:?}, not {LISTENER_NAME:?}")
            }
            ActivationError::NotAListener => {
                write!(f, "the descriptor is not a listening Unix stream socket")
            }
        }
    }
}

/// The one listener `punar-smplifyd.socket` passes: named
/// [`LISTENER_NAME`], a Unix stream socket, listening. Anything else is
/// refused rather than served, since the agent answers the organization's
/// word on it. Close-on-exec, as a descriptor the agent opened itself would
/// be.
fn select_listener(
    descriptors: Vec<(Option<String>, OwnedFd)>,
) -> Result<UnixListener, ActivationError> {
    use rustix::io::{FdFlags, fcntl_setfd};
    use rustix::net::{AddressFamily, SocketType, sockopt};
    let count = descriptors.len();
    let Ok([(name, descriptor)]) = <[_; 1]>::try_from(descriptors) else {
        return Err(ActivationError::Count(count));
    };
    if name.as_deref() != Some(LISTENER_NAME) {
        return Err(ActivationError::Name(name));
    }
    let listening = fcntl_setfd(descriptor.as_fd(), FdFlags::CLOEXEC).is_ok()
        && sockopt::socket_domain(&descriptor).is_ok_and(|domain| domain == AddressFamily::UNIX)
        && sockopt::socket_type(&descriptor).is_ok_and(|kind| kind == SocketType::STREAM)
        && sockopt::socket_acceptconn(&descriptor).unwrap_or(false);
    if !listening {
        return Err(ActivationError::NotAListener);
    }
    Ok(UnixListener::from(descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, bind, listen, socket_with,
    };

    fn temp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "punar-smplifyd-activation-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("api.sock")
    }

    fn socket(path: &std::path::Path, kind: SocketType, listening: bool) -> OwnedFd {
        let descriptor =
            socket_with(AddressFamily::UNIX, kind, SocketFlags::empty(), None).unwrap();
        bind(&descriptor, &SocketAddrUnix::new(path).unwrap()).unwrap();
        if listening {
            listen(&descriptor, 8).unwrap();
        }
        descriptor
    }

    /// The one listener the socket unit declares is served; a descriptor of
    /// the wrong kind, one not listening, a misnamed one or a second one is
    /// refused.
    #[test]
    fn only_the_declared_listener_is_served() {
        let named = |descriptor| vec![(Some(LISTENER_NAME.to_string()), descriptor)];
        let good = socket(&temp_path("good"), SocketType::STREAM, true);
        assert!(select_listener(named(good)).is_ok());

        let datagram = socket(&temp_path("dgram"), SocketType::DGRAM, false);
        assert_eq!(
            select_listener(named(datagram)).unwrap_err(),
            ActivationError::NotAListener
        );
        let idle = socket(&temp_path("idle"), SocketType::STREAM, false);
        assert_eq!(
            select_listener(named(idle)).unwrap_err(),
            ActivationError::NotAListener
        );
        let misnamed = socket(&temp_path("misnamed"), SocketType::STREAM, true);
        assert_eq!(
            select_listener(vec![(Some("other".into()), misnamed)]).unwrap_err(),
            ActivationError::Name(Some("other".into()))
        );
        let one = socket(&temp_path("one"), SocketType::STREAM, true);
        let two = socket(&temp_path("two"), SocketType::STREAM, true);
        assert_eq!(
            select_listener(vec![
                (Some(LISTENER_NAME.to_string()), one),
                (Some(LISTENER_NAME.to_string()), two),
            ])
            .unwrap_err(),
            ActivationError::Count(2)
        );
    }
}
