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
//! Decision record: docs/development/smplify-enrollment.md.
mod device;
mod discovery;
mod http;
mod identity;
mod protocol;
mod server;
mod upstream;

use std::path::PathBuf;
use std::process::ExitCode;

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
    let socket = std::env::var_os("PUNAR_SMPLIFYD_SOCKET")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("RUNTIME_DIRECTORY").map(|d| PathBuf::from(d).join("api.sock"))
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
    let state_dir = std::env::var_os("PUNAR_SMPLIFYD_STATE_DIR")
        .or_else(|| std::env::var_os("STATE_DIRECTORY"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    let discovery_dir = std::env::var_os("PUNAR_SMPLIFYD_DISCOVERY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DISCOVERY_DIR));
    let daemon = server::Daemon::new(state_dir, discovery_dir);
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
