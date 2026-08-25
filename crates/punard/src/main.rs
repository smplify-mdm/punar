//! `punard` — Punar privileged local control-plane daemon (SPEC section
//! 11.1), Milestone 3 build: UDS NDJSON server, capability registry, audit.
//!
//! Architectural rules that bind this binary (SPEC sections 1, 10, 60):
//! privileged changes go through typed capability APIs, and there is never a
//! generic root-command RPC.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use punard::backends::firewall::FirewallBackend;
use punard::backends::hostname::HostnameBackend;
use punard::backends::timezone::TimezoneBackend;
use punard::capability::Registry;
use punard::server::{Daemon, DaemonConfig};

#[derive(Parser)]
#[command(
    name = "punard",
    version,
    about = "Punar privileged local control-plane daemon (SPEC section 11.1)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon (started by punard.service as root).
    Run(RunArgs),
    /// Validate punard configuration without starting the daemon (stub).
    CheckConfig,
}

#[derive(clap::Args)]
struct RunArgs {
    /// Unix socket path (docs/api/ipc.md section 1).
    #[arg(long, default_value = punar_common::ipc::SOCKET_PATH)]
    socket: PathBuf,

    /// State directory holding desired.json and device-id.
    #[arg(long, default_value = "/var/lib/punar")]
    state_dir: PathBuf,

    /// Audit log file (append-only JSONL).
    #[arg(long, default_value = punar_common::audit::AUDIT_LOG_PATH)]
    audit_file: PathBuf,

    /// Group granted read access to the socket.
    #[arg(long, default_value = "punar")]
    group: String,

    /// nft binary (fixed argv — never a shell).
    #[arg(long, default_value = "/usr/bin/nft")]
    nft_bin: PathBuf,

    /// Vendored punar-base nftables ruleset.
    #[arg(long, default_value = "/usr/share/punar/nftables/punar-base.nft")]
    ruleset: PathBuf,
}

fn build_registry(args: &RunArgs) -> Registry {
    Registry::new(vec![
        Box::new(FirewallBackend::new(
            args.nft_bin.clone(),
            args.ruleset.clone(),
        )),
        Box::new(HostnameBackend::new(
            PathBuf::from("/etc/hostname"),
            PathBuf::from("/proc/sys/kernel/hostname"),
        )),
        Box::new(TimezoneBackend::new(
            PathBuf::from("/etc/localtime"),
            PathBuf::from("/usr/share/zoneinfo"),
        )),
    ])
}

fn run(args: RunArgs) -> ExitCode {
    let registry = build_registry(&args);
    let cfg = DaemonConfig::new(args.socket, args.state_dir, args.audit_file);
    let cfg = DaemonConfig {
        group: args.group,
        ..cfg
    };

    let daemon = match Daemon::new(cfg, registry) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("punard: startup failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    daemon.boot_reconcile();

    let handle = match daemon.spawn() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("punard: could not bind the control socket: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "punard: listening on {} (protocol v1)",
        handle.socket_path().display()
    );

    // Graceful shutdown on SIGTERM/SIGINT: stop accepting, close the
    // socket, remove the socket file, exit 0.
    let mut signals = match signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("punard: could not install signal handlers: {e}");
            handle.stop();
            return ExitCode::FAILURE;
        }
    };
    let signal = signals.forever().next();
    eprintln!("punard: received signal {signal:?}, shutting down");
    handle.stop();
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Run(args)) => run(args),
        Some(Command::CheckConfig) => {
            eprintln!(
                "punard check-config: not implemented in Milestone 3; no configuration was validated"
            );
            ExitCode::FAILURE
        }
        None => {
            eprintln!("punard: no command given; the service runs `punard run` (see --help)");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    /// clap's self-check: asserts the argument definitions are internally
    /// consistent (unique names, valid requirements), and that `--version`
    /// can be answered.
    #[test]
    fn cli_definition_is_well_formed() {
        Cli::command().debug_assert();
        assert!(Cli::command().get_version().is_some());
    }
}
