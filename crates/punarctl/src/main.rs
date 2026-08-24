//! `punarctl` — the Punar control CLI (SPEC section 11.2).
//!
//! Milestone 0 status: the full SPEC section 11.2 command surface parses,
//! but every command prints a one-line "not implemented until Milestone N"
//! notice (per the SPEC section 76 milestone plan) and exits nonzero. The
//! CLI surface is real from day one; behavior lands milestone by milestone,
//! always through the same typed capability APIs as the graphical UX (SPEC
//! section 10).

#![forbid(unsafe_code)]

use std::fmt;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use punar_common::CapabilityId;

/// A SPEC section 76 milestone that will make a stubbed command real.
struct Milestone {
    number: u8,
    name: &'static str,
}

impl fmt::Display for Milestone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Milestone {} ({})", self.number, self.name)
    }
}

/// Milestone 3 — `punard` + `punarctl`: daemon, typed IPC, capability
/// registry, CLI, and audit. Update orchestration is a `punard`
/// responsibility (SPEC section 11.1), so `update status` maps here too.
const M3_DAEMON: Milestone = Milestone {
    number: 3,
    name: "punard + punarctl",
};
/// Milestone 4 — declarative desired state: preference/policy merge,
/// reconciliation, explain.
const M4_DESIRED_STATE: Milestone = Milestone {
    number: 4,
    name: "declarative desired state",
};
/// Milestone 5 — mock Smplify enrollment: policy, compliance, inventory.
const M5_ENROLLMENT: Milestone = Milestone {
    number: 5,
    name: "mock Smplify enrollment",
};
/// Milestone 7 — AI Agent Registry.
const M7_AGENT_REGISTRY: Milestone = Milestone {
    number: 7,
    name: "AI Agent Registry",
};
/// Milestone 8 — AI Access Ledger.
const M8_ACCESS_LEDGER: Milestone = Milestone {
    number: 8,
    name: "AI Access Ledger",
};
/// Milestone 12 — network privacy prototype: observability, relay.
const M12_NETWORK_PRIVACY: Milestone = Milestone {
    number: 12,
    name: "network privacy prototype",
};

#[derive(Parser)]
#[command(
    name = "punarctl",
    version,
    about = "Control CLI for the Punar local control plane (stubbed until later milestones)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show daemon and device status.
    Status,
    /// List capabilities from the capability registry.
    Capabilities,
    /// Show compliance state against organization policy.
    Compliance,
    /// Inspect effective policy.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Inspect the AI Agent Registry and Access Ledger.
    Agents {
        #[command(subcommand)]
        command: AgentsCommand,
    },
    /// Inspect local network privacy state.
    Privacy {
        #[command(subcommand)]
        command: PrivacyCommand,
    },
    /// Inspect private relay state.
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    /// Inspect the local audit log.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Run a reconciliation pass against desired state.
    Reconcile,
    /// Inspect update orchestration state.
    Update {
        #[command(subcommand)]
        command: UpdateCommand,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Show the effective merged policy.
    Effective,
    /// Explain the effective value and winning source for one capability.
    Explain {
        /// Dotted capability path, like `security.firewall`.
        capability: CapabilityId,
    },
}

#[derive(Subcommand)]
enum AgentsCommand {
    /// List registered AI agents.
    List,
    /// Inspect one AI agent session.
    Inspect {
        /// Agent session id, like `agt_123`.
        id: String,
    },
    /// Show what an AI agent has actually accessed (Access Ledger).
    Access {
        /// Agent session id, like `agt_123`.
        id: String,
    },
}

#[derive(Subcommand)]
enum PrivacyCommand {
    /// Show current network connections and their privacy handling.
    Connections,
}

#[derive(Subcommand)]
enum RelayCommand {
    /// Show private relay status.
    Status,
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Tail recent audit events.
    Tail,
}

#[derive(Subcommand)]
enum UpdateCommand {
    /// Show current/desired version, channel, health, and rollback state.
    Status,
}

/// Print the one-line stub notice for `invocation` and exit nonzero.
fn stub(invocation: &str, milestone: &Milestone) -> ExitCode {
    eprintln!("punarctl {invocation}: not implemented until {milestone}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Status => stub("status", &M3_DAEMON),
        Command::Capabilities => stub("capabilities", &M3_DAEMON),
        Command::Compliance => stub("compliance", &M5_ENROLLMENT),
        Command::Policy { command } => match command {
            PolicyCommand::Effective => stub("policy effective", &M4_DESIRED_STATE),
            PolicyCommand::Explain { capability } => {
                stub(&format!("policy explain {capability}"), &M4_DESIRED_STATE)
            }
        },
        Command::Agents { command } => match command {
            AgentsCommand::List => stub("agents list", &M7_AGENT_REGISTRY),
            AgentsCommand::Inspect { id } => {
                stub(&format!("agents inspect {id}"), &M7_AGENT_REGISTRY)
            }
            AgentsCommand::Access { id } => stub(&format!("agents access {id}"), &M8_ACCESS_LEDGER),
        },
        Command::Privacy { command } => match command {
            PrivacyCommand::Connections => stub("privacy connections", &M12_NETWORK_PRIVACY),
        },
        Command::Relay { command } => match command {
            RelayCommand::Status => stub("relay status", &M12_NETWORK_PRIVACY),
        },
        Command::Audit { command } => match command {
            AuditCommand::Tail => stub("audit tail", &M3_DAEMON),
        },
        Command::Reconcile => stub("reconcile", &M4_DESIRED_STATE),
        Command::Update { command } => match command {
            UpdateCommand::Status => stub("update status", &M3_DAEMON),
        },
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::Cli;

    /// clap's self-check: asserts the argument definitions are internally
    /// consistent, and that `--version` can be answered.
    #[test]
    fn cli_definition_is_well_formed() {
        Cli::command().debug_assert();
        assert!(Cli::command().get_version().is_some());
    }

    /// Every SPEC section 11.2 example invocation must parse.
    #[test]
    fn spec_section_11_2_examples_parse() {
        let examples: &[&[&str]] = &[
            &["punarctl", "status"],
            &["punarctl", "capabilities"],
            &["punarctl", "compliance"],
            &["punarctl", "policy", "effective"],
            &["punarctl", "policy", "explain", "security.firewall"],
            &["punarctl", "agents", "list"],
            &["punarctl", "agents", "inspect", "agt_123"],
            &["punarctl", "agents", "access", "agt_123"],
            &["punarctl", "privacy", "connections"],
            &["punarctl", "relay", "status"],
            &["punarctl", "audit", "tail"],
            &["punarctl", "reconcile"],
            &["punarctl", "update", "status"],
        ];
        for example in examples {
            assert!(
                Cli::try_parse_from(example.iter()).is_ok(),
                "failed to parse {example:?}"
            );
        }
    }

    /// `policy explain` validates its capability argument via
    /// `punar_common::CapabilityId`.
    #[test]
    fn policy_explain_rejects_invalid_capability_ids() {
        assert!(Cli::try_parse_from(["punarctl", "policy", "explain", "firewall"]).is_err());
        assert!(
            Cli::try_parse_from(["punarctl", "policy", "explain", "not a capability"]).is_err()
        );
    }
}
