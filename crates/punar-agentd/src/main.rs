//! `punar-agentd` — the AI Agent Registry service (SPEC section 11.3),
//! Milestone 7 build.
//!
//! Architectural rules that bind this binary (SPEC sections 10, 60): the
//! `agents.*` method table is closed and typed, there is no generic
//! execution RPC, and nothing on this socket accepts a command line.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use punar_agentd::server::{AgentdConfig, Daemon};

#[derive(Parser)]
#[command(
    name = "punar-agentd",
    version,
    about = "Punar AI Agent Registry service (SPEC section 11.3)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon (started by punar-agentd.service as root).
    Run(RunArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// Unix socket path (docs/api/ipc.md section 10.1).
    #[arg(long, default_value = punar_common::agent::AGENTD_SOCKET_PATH)]
    socket: PathBuf,

    /// State directory. Holds the registry's `agents/` subdirectory; also
    /// where punard's `device-id` and `enrollment.json` are read from.
    #[arg(long, default_value = "/var/lib/punar")]
    state_dir: PathBuf,

    /// Registry transition log (append-only JSONL, one schema-exact
    /// registry record per line).
    #[arg(long, default_value = punar_common::agent::REGISTRY_JSONL_PATH)]
    registry_file: PathBuf,

    /// Audit log — the same trail punard appends to (docs/api/ipc.md
    /// section 10.4).
    #[arg(long, default_value = punar_common::audit::AUDIT_LOG_PATH)]
    audit_file: PathBuf,

    /// Staged agent-definition documents (spec section 26 adapters).
    #[arg(long, default_value = punar_common::agent::ADAPTERS_DIR)]
    adapters_dir: PathBuf,

    /// Suspected-signature heuristic input (spec section 23).
    #[arg(long, default_value = punar_common::agent::SUSPECTED_SIGNATURES_PATH)]
    signatures_file: PathBuf,

    /// AI-panel summary file (docs/api/ipc.md section 11).
    #[arg(long, default_value = punar_common::agent::AGENTS_SUMMARY_PATH)]
    agents_file: PathBuf,

    /// punard's shell summary file, read for the enrollment flag behind
    /// the policy citation (docs/api/ipc.md sections 9, 10.3).
    #[arg(long, default_value = "/run/punar/status.json")]
    status_file: PathBuf,

    /// Group granted access to the socket.
    #[arg(long, default_value = "punar")]
    group: String,
}

fn run(args: RunArgs) -> ExitCode {
    let base = AgentdConfig::production();
    let cfg = AgentdConfig {
        socket_path: args.socket,
        state_dir: args.state_dir,
        registry_path: args.registry_file,
        audit_path: args.audit_file,
        adapters_dir: args.adapters_dir,
        suspected_path: args.signatures_file,
        agents_file: args.agents_file,
        status_file: args.status_file,
        group: args.group,
        ..base
    };

    let daemon = match Daemon::new(cfg) {
        Ok(daemon) => daemon,
        Err(e) => {
            eprintln!("punar-agentd: startup failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let handle = match daemon.spawn() {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("punar-agentd: could not bind the registry socket: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "punar-agentd: listening on {} (protocol v1)",
        handle.socket_path().display()
    );

    // Graceful shutdown on SIGTERM/SIGINT: stop accepting, close the
    // socket, remove the socket file, exit 0 — the punard pattern.
    let mut signals = match signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ]) {
        Ok(signals) => signals,
        Err(e) => {
            eprintln!("punar-agentd: could not install signal handlers: {e}");
            handle.stop();
            return ExitCode::FAILURE;
        }
    };
    let signal = signals.forever().next();
    eprintln!("punar-agentd: received signal {signal:?}, shutting down");
    handle.stop();
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Run(args)) => run(args),
        None => {
            eprintln!(
                "punar-agentd: no command given; the service runs `punar-agentd run` (see --help)"
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    /// clap's self-check: the argument definitions are internally
    /// consistent and `--version` can be answered.
    #[test]
    fn cli_definition_is_well_formed() {
        Cli::command().debug_assert();
        assert!(Cli::command().get_version().is_some());
    }
}
