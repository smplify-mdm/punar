//! `punard` — Punar's primary privileged local control-plane daemon.
//!
//! **Milestone 0 status: CLI skeleton only.** The daemon proper is a
//! Milestone 3 deliverable (SPEC section 76); running it today exits with a
//! clear error rather than pretending to serve.
//!
//! Future scope, per SPEC section 11.1, is responsibility for:
//!
//! - device identity;
//! - enrollment;
//! - desired-state receipt;
//! - state reconciliation;
//! - capability registry;
//! - compliance;
//! - inventory;
//! - drift detection;
//! - local policy;
//! - local IPC;
//! - update orchestration;
//! - audit events;
//! - Smplify communication;
//! - AI inventory coordination;
//! - privacy-aware remote query execution.
//!
//! Architectural rules that bind this binary from day one (SPEC sections 1
//! and 10): privileged changes go through typed capability APIs, and there is
//! never a generic root-command RPC.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "punard",
    version,
    about = "Punar privileged local control-plane daemon (Milestone 0 skeleton)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Validate punard configuration without starting the daemon (stub).
    CheckConfig,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::CheckConfig) => {
            eprintln!(
                "punard check-config: not implemented until Milestone 3 (punard + punarctl); no configuration was validated"
            );
            ExitCode::FAILURE
        }
        None => {
            eprintln!("punard: daemon not implemented (Milestone 3)");
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
