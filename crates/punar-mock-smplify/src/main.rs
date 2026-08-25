//! `punar-mock-smplify` — **dev/CI mock — not a product component.**
//!
//! Started only by `m5-check.sh` (the unit is never enabled); serves the
//! staged Acme fixtures over a root-only UDS and records what it receives
//! under the state directory. See the crate docs and
//! docs/development/milestone-5.md section 4.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use punar_mock_smplify::config::MockConfig;
use punar_mock_smplify::server::MockServer;

/// dev/CI mock — not a product component.
///
/// In-VM mock Smplify control plane for the Milestone 5 checks: serves the
/// Acme fixture organization over a root-only Unix socket (NDJSON,
/// docs/api/ipc.md framing) and persists everything it receives so m5-check
/// can assert the received side. Never enabled as a service; started and
/// stopped only by m5-check. Attestation is simulated; the token check
/// stands in for production mTLS device auth.
#[derive(Parser)]
#[command(name = "punar-mock-smplify", version)]
struct Cli {
    /// Unix socket path (chmod 0600 root before listen). Default:
    /// /run/punar-mock-smplify/api.sock; env override PUNAR_MOCK_SMPLIFY_SOCKET.
    #[arg(long, value_name = "PATH", help_heading = "Paths")]
    socket: Option<PathBuf>,

    /// Fixture directory holding org.json + policy-source + desired-state,
    /// served verbatim. Default: /usr/share/punar/fixtures/acme; env
    /// override PUNAR_MOCK_SMPLIFY_FIXTURES.
    #[arg(long, value_name = "DIR", help_heading = "Paths")]
    fixtures: Option<PathBuf>,

    /// State directory for devices.json and received-*.jsonl. Default:
    /// /var/lib/punar-mock-smplify; env override PUNAR_MOCK_SMPLIFY_STATE_DIR.
    #[arg(long, value_name = "DIR", help_heading = "Paths")]
    state_dir: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cfg = MockConfig::resolve(cli.socket, cli.fixtures, cli.state_dir);

    let server = match MockServer::new(cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("punar-mock-smplify: startup failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let fixtures = server.fixtures().clone();
    let known_devices = server.device_count();

    let handle = match server.spawn() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("punar-mock-smplify: could not bind the socket: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "punar-mock-smplify: dev/CI mock — not a product component; listening on {} \
         (organization {:?}, domain {}, {} policy file(s), {} known device(s))",
        handle.socket_path().display(),
        fixtures.org_id,
        fixtures.domain,
        fixtures.policies.len(),
        known_devices,
    );

    // Graceful shutdown on SIGTERM/SIGINT (systemctl stop from m5-check):
    // stop accepting, close and remove the socket, exit 0. Received state
    // stays on disk deliberately.
    let mut signals = match signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("punar-mock-smplify: could not install signal handlers: {e}");
            handle.stop();
            return ExitCode::FAILURE;
        }
    };
    let signal = signals.forever().next();
    eprintln!("punar-mock-smplify: received signal {signal:?}, shutting down");
    handle.stop();
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    /// clap's self-check: argument definitions are internally consistent
    /// and `--version` can be answered.
    #[test]
    fn cli_definition_is_well_formed() {
        Cli::command().debug_assert();
        assert!(Cli::command().get_version().is_some());
    }

    /// The dev/CI banner is the first thing `--help` says (milestone-5.md
    /// section 4.1: "--help and startup log both say it").
    #[test]
    fn help_carries_the_dev_ci_banner() {
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains("dev/CI mock — not a product component"),
            "--help must carry the dev/CI banner, got:\n{help}"
        );
    }
}
