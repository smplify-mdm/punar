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

// `RunArgs` is large by design — every production path punard touches is an
// injectable flag, which is what lets the in-VM checks and the host tests
// point the daemon at a tempdir. clap's derive needs the args inline in the
// variant (a `Box<RunArgs>` does not implement `Args`), and this enum is
// constructed exactly once per process.
#[allow(clippy::large_enum_variant)]
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

    /// State directory holding device-id, the layer stores
    /// (preferences.json, os-defaults.json), and policy.d.
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

    /// M5 control-plane socket (the dev/CI mock's root-only UDS). When
    /// omitted, the PUNAR_CONTROL_PLANE_SOCKET environment variable is
    /// consulted, then the compiled default
    /// (docs/development/milestone-5.md section 4.2).
    #[arg(long, value_name = "PATH")]
    control_plane_socket: Option<PathBuf>,

    /// M5 shell summary file (docs/api/ipc.md section 9).
    #[arg(long, default_value = punard::enroll::DEFAULT_STATUS_FILE)]
    status_file: PathBuf,

    /// M9 approval summary the shell watches (docs/api/ipc.md section 15).
    /// Inside the **root-owned** `/run/punard`, deliberately not beside
    /// `status.json` in the user-writable `/run/punar`: this is the file
    /// that tells a human what they are about to authorize, and a file a
    /// local process can substitute is a spoofing primitive.
    #[arg(long, default_value = punar_common::approval::APPROVALS_SUMMARY_FILE)]
    approvals_file: PathBuf,

    /// M9 AI authority document (SPEC section 20). A missing or unreadable
    /// file falls back to the compiled-in personal defaults — the same
    /// bytes the image installs here.
    #[arg(long, default_value = punar_common::aipolicy::AI_DEFAULTS_FILE)]
    ai_defaults_file: PathBuf,

    /// M9: the uid an agent-raised approval is routed to (the session
    /// user). Not a presence check — see `Inner::console_user`.
    #[arg(long, default_value_t = punard::server::DEFAULT_CONSOLE_UID)]
    console_uid: u32,
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
    // Control-plane endpoint precedence: flag, then environment override,
    // then the compiled default (milestone-5.md section 4.2 — the env
    // seam is how host tests point punard at a temp socket).
    let control_plane_socket = args
        .control_plane_socket
        .or_else(|| {
            std::env::var_os(punard::enroll::CONTROL_PLANE_SOCKET_ENV)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(punard::enroll::DEFAULT_CONTROL_PLANE_SOCKET));
    let cfg = DaemonConfig::new(args.socket, args.state_dir, args.audit_file);
    let cfg = DaemonConfig {
        group: args.group,
        control_plane_socket,
        status_file: args.status_file,
        approvals_file: args.approvals_file,
        ai_defaults_file: args.ai_defaults_file,
        console_uid: args.console_uid,
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
