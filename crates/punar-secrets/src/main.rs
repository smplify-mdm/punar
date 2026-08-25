//! `punar-secrets` — the credential broker service (SPEC section 11.4),
//! Milestone 9 build.
//!
//! Architectural rules that bind this binary (SPEC sections 10, 29, 53,
//! 60): the `credential.*` method table is closed and typed, nothing on
//! this socket accepts a command line, no credential value is ever written
//! to disk by Punar, and there is no method that can return an issued token
//! a second time.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use punar_secrets::server::{Daemon, SecretsConfig};

#[derive(Parser)]
#[command(
    name = "punar-secrets",
    version,
    about = "Punar short-lived credential broker (SPEC sections 11.4, 29)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon (started by punar-secrets.service as root).
    Run(RunArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// Unix socket path (docs/api/ipc.md section 16.1).
    #[arg(long, default_value = punar_secrets::protocol::SECRETS_SOCKET_PATH)]
    socket: PathBuf,

    /// Credential class catalog — data, not code (milestone-9.md 6.1).
    #[arg(long, default_value = punar_secrets::protocol::CLASSES_PATH)]
    classes: PathBuf,

    /// The shipped AI authority document (spec section 20).
    #[arg(long, default_value = punar_secrets::protocol::AI_DEFAULTS_PATH)]
    ai_defaults: PathBuf,

    /// Organization AI authority layers, when a device has any.
    #[arg(long, default_value = punar_secrets::protocol::AI_POLICY_DIR)]
    ai_policy_dir: PathBuf,

    /// Audit log — the same trail punard and punar-agentd append to
    /// (docs/api/ipc.md section 10.4). The broker's only disk writes.
    #[arg(long, default_value = punar_common::audit::AUDIT_LOG_PATH)]
    audit_file: PathBuf,

    /// punard's state directory, read for the device id. Never written.
    #[arg(long, default_value = "/var/lib/punar")]
    state_dir: PathBuf,

    /// punard's socket — the approval engine (docs/api/ipc.md section 14).
    #[arg(long, default_value = punar_common::ipc::SOCKET_PATH)]
    punard_socket: PathBuf,

    /// Group granted access to the socket.
    #[arg(long, default_value = "punar")]
    group: String,
}

fn run(args: RunArgs) -> ExitCode {
    let base = SecretsConfig::production();
    let cfg = SecretsConfig {
        socket_path: args.socket,
        classes_path: args.classes,
        ai_defaults_path: args.ai_defaults,
        ai_policy_dir: args.ai_policy_dir,
        audit_path: args.audit_file,
        state_dir: args.state_dir,
        punard_socket: args.punard_socket,
        group: args.group,
        ..base
    };

    let daemon = match Daemon::new(cfg) {
        Ok(daemon) => daemon,
        Err(e) => {
            eprintln!("punar-secrets: startup failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let handle = match daemon.spawn() {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("punar-secrets: could not bind the broker socket: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "punar-secrets: listening on {} (protocol v1, provider mock — SIMULATED)",
        handle.socket_path().display()
    );

    // Graceful shutdown on SIGTERM/SIGINT: stop accepting, close the
    // socket, remove the socket file, exit 0 — the punard pattern. Every
    // live credential dies with the process, by design.
    let mut signals = match signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ]) {
        Ok(signals) => signals,
        Err(e) => {
            eprintln!("punar-secrets: could not install signal handlers: {e}");
            handle.stop();
            return ExitCode::FAILURE;
        }
    };
    let signal = signals.forever().next();
    eprintln!("punar-secrets: received signal {signal:?}, shutting down");
    handle.stop();
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Run(args)) => run(args),
        None => {
            eprintln!(
                "punar-secrets: no command given; the service runs `punar-secrets run` \
                 (see --help)"
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

    /// There is no flag that takes a token: `/proc/<pid>/cmdline` is
    /// world-readable, so a `--token` argument would publish every secret
    /// it was given (ipc.md section 16.4). This test exists so that adding
    /// one fails CI.
    #[test]
    fn no_argument_anywhere_accepts_a_credential_value() {
        fn walk(command: &clap::Command) {
            for arg in command.get_arguments() {
                let name = arg.get_id().to_string();
                assert!(
                    !name.contains("token") && !name.contains("secret") && !name.contains("value"),
                    "argument {name:?} looks like it carries a credential value; \
                     secrets reach Punar on stdin, never on argv"
                );
            }
            for sub in command.get_subcommands() {
                walk(sub);
            }
        }
        walk(&Cli::command());
    }
}
