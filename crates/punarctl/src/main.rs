//! `punarctl` — the Punar control CLI (SPEC section 11.2).
//!
//! Milestone 3: the daemon-backed verbs are real. `status`, `capabilities`
//! (bare list, `get`, `set`), `audit tail`, and `reconcile` speak the typed
//! NDJSON IPC contract (`docs/api/ipc.md`) to `punard` over its Unix socket
//! and render in the Plate D-014 output grammar
//! (`docs/design/mockups/cli-grammar.html`) — or, with the global `--json`
//! flag, print the IPC `result` object verbatim (capability-registry field
//! names unchanged). `policy effective` / `policy explain` answer honestly
//! that no policy engine is loaded until Milestone 4. Every other SPEC
//! section 11.2 verb keeps a milestone-labeled stub.
//!
//! The CLI never elevates itself; the daemon is the authorization point
//! (`sudo punarctl …` is the M3 way to run mutating verbs), and a denial
//! prints the server's SPEC section 73 message verbatim — who may act, why
//! this was refused, which policy, and the next step. Never an errno.
//!
//! Exit codes (Plate D-014 Sect III): 0 success · 1 runtime/daemon error ·
//! 2 usage (clap) · 3 denied · 4 approval_required (reserved for
//! Milestone 9) · 5 daemon unreachable.

#![forbid(unsafe_code)]

mod fmt;
mod ipc;
mod model;
mod views;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use punar_common::CapabilityId;
use serde_json::{Value, json};

use crate::fmt::Style;
use crate::ipc::{CallError, Client, DEFAULT_SOCKET};

/// A SPEC section 76 milestone that will make a stubbed command real.
struct Milestone {
    number: u8,
    name: &'static str,
}

impl std::fmt::Display for Milestone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Milestone {} ({})", self.number, self.name)
    }
}

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
    about = "Control CLI for the Punar local control plane"
)]
struct Cli {
    /// Print the raw typed IPC result as JSON instead of the human output.
    #[arg(long, global = true)]
    json: bool,

    /// Path to the punard control socket
    /// (default /run/punard/punard.sock; env PUNARD_SOCKET).
    #[arg(long, global = true, value_name = "PATH")]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show daemon and device status.
    Status,
    /// List capabilities from the capability registry.
    Capabilities {
        #[command(subcommand)]
        command: Option<CapabilitiesCommand>,
    },
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
    /// Re-observe every capability and report drift (Milestone 3 reports
    /// only; remediation arrives in Milestone 4).
    Reconcile,
    /// Inspect update orchestration state.
    Update {
        #[command(subcommand)]
        command: UpdateCommand,
    },
    /// Test probe (SPEC section 74.4): send a raw method name to the
    /// daemon. Adds no server capability — the daemon's closed method
    /// table is the enforcement point.
    #[command(hide = true)]
    Debug {
        #[command(subcommand)]
        command: DebugCommand,
    },
}

#[derive(Subcommand)]
enum CapabilitiesCommand {
    /// Inspect one capability descriptor.
    Get {
        /// Dotted capability path, like `security.firewall`.
        capability: CapabilityId,
    },
    /// Set the desired state of one capability (root only in Milestone 3).
    Set {
        /// Dotted capability path, like `security.firewall`.
        capability: CapabilityId,
        /// Desired state value, like `enabled`. Sent as a string; the
        /// daemon validates it against the capability's allowed states.
        desired_state: String,
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
    /// Tail recent audit events (newest last).
    Tail {
        /// Number of events to show; the daemon caps requests at 1000.
        #[arg(short = 'n', long = "lines", default_value_t = 20)]
        n: u64,
    },
}

#[derive(Subcommand)]
enum UpdateCommand {
    /// Show current/desired version, channel, health, and rollback state.
    Status,
}

#[derive(Subcommand)]
enum DebugCommand {
    /// Send `method` with no params and print the raw response.
    Rpc { method: String },
}

/// Print the one-line stub notice for `invocation` and exit nonzero.
fn stub(invocation: &str, milestone: &Milestone) -> ExitCode {
    eprintln!("punarctl {invocation}: not implemented until {milestone}");
    ExitCode::FAILURE
}

/// Socket path resolution: `--socket` flag, then `PUNARD_SOCKET`, then the
/// contract default.
fn resolve_socket(flag: Option<PathBuf>) -> PathBuf {
    flag.or_else(|| {
        std::env::var_os("PUNARD_SOCKET")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    })
    .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

/// The masthead context hostname for verbs whose result carries none.
/// punarctl always runs on the machine it controls, so the kernel's
/// spelling is authoritative; fall back quietly on non-Linux dev hosts.
fn local_hostname() -> String {
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let name = contents.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    std::env::var("HOSTNAME")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

fn fail(error: &CallError) -> ExitCode {
    eprintln!("{}", error.message());
    ExitCode::from(error.exit_code())
}

/// Run one IPC call and print either the verbatim JSON result or the
/// rendered human view. The human table and the JSON are two renderers
/// over one result — they can never disagree.
fn rpc(
    client: &Client,
    json: bool,
    method: &str,
    params: Option<Value>,
    render: impl FnOnce(&Value) -> Result<String, String>,
) -> ExitCode {
    match client.call(method, params) {
        Ok(result) => {
            if json {
                match serde_json::to_string(&result) {
                    Ok(line) => {
                        println!("{line}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => fail(&CallError::Protocol {
                        why: format!("the result could not be re-encoded ({e})"),
                    }),
                }
            } else {
                match render(&result) {
                    Ok(text) => {
                        print!("{text}");
                        ExitCode::SUCCESS
                    }
                    Err(why) => fail(&CallError::Protocol { why }),
                }
            }
        }
        Err(error) => fail(&error),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let style = Style::detect();
    let client = Client::new(resolve_socket(cli.socket));
    let json = cli.json;

    match cli.command {
        Command::Status => rpc(&client, json, "status", None, |v| views::status(&style, v)),
        Command::Capabilities { command } => match command {
            None => {
                let hostname = local_hostname();
                rpc(&client, json, "capabilities.list", None, |v| {
                    views::capabilities(&style, v, &hostname)
                })
            }
            Some(CapabilitiesCommand::Get { capability }) => {
                let hostname = local_hostname();
                rpc(
                    &client,
                    json,
                    "capabilities.get",
                    Some(json!({"capability": capability.as_str()})),
                    |v| views::capability(&style, v, &hostname),
                )
            }
            Some(CapabilitiesCommand::Set {
                capability,
                desired_state,
            }) => {
                let hostname = local_hostname();
                rpc(
                    &client,
                    json,
                    "capabilities.set",
                    Some(json!({
                        "capability": capability.as_str(),
                        "desired_state": desired_state,
                    })),
                    |v| views::set(&style, v, &hostname),
                )
            }
        },
        Command::Audit { command } => match command {
            AuditCommand::Tail { n } => {
                let hostname = local_hostname();
                rpc(&client, json, "audit.tail", Some(json!({"n": n})), |v| {
                    views::audit(&style, v, &hostname)
                })
            }
        },
        Command::Reconcile => {
            let hostname = local_hostname();
            rpc(&client, json, "reconcile", None, |v| {
                views::reconcile(&style, v, &hostname)
            })
        }
        Command::Policy { command } => match command {
            // Honest Milestone 3 answers: no policy engine is loaded until
            // Milestone 4, and these verbs say so in the designed voice
            // instead of pretending. Local-only — this truth does not need
            // the daemon. The JSON spelling is punarctl's own (there is no
            // policy.* IPC method yet).
            PolicyCommand::Effective => {
                if json {
                    println!(
                        "{}",
                        json!({
                            "policy_loaded": false,
                            "available_in_milestone": 4,
                            "mode": "personal",
                            "policy_ids": ["personal-defaults"],
                        })
                    );
                } else {
                    print!("{}", views::policy_effective(&style, &local_hostname()));
                }
                ExitCode::SUCCESS
            }
            PolicyCommand::Explain { capability } => {
                if json {
                    println!(
                        "{}",
                        json!({
                            "policy_loaded": false,
                            "available_in_milestone": 4,
                            "mode": "personal",
                            "policy_ids": ["personal-defaults"],
                            "capability": capability.as_str(),
                            "user_override": "permitted",
                        })
                    );
                } else {
                    print!("{}", views::policy_explain(&style, capability.as_str()));
                }
                ExitCode::SUCCESS
            }
        },
        Command::Debug { command } => match command {
            DebugCommand::Rpc { method } => match client.call(&method, None) {
                Ok(result) => {
                    println!("{result}");
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error),
            },
        },
        Command::Compliance => stub("compliance", &M5_ENROLLMENT),
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
        Command::Update { command } => match command {
            UpdateCommand::Status => {
                // Retargeted while touched (M3 plan section 10): update
                // orchestration is a punard responsibility (SPEC section
                // 11.1), but no SPEC section 76 milestone schedules it —
                // an honest stub beats a wrong label.
                eprintln!(
                    "punarctl update status: not implemented — update orchestration \
                     (SPEC section 11.1) is not scheduled by the SPEC section 76 \
                     milestone plan; this stub stays until a milestone claims it"
                );
                ExitCode::FAILURE
            }
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

    /// Every SPEC section 11.2 example invocation must parse, plus the
    /// Milestone 3 additions (capabilities get/set, audit tail -n, the
    /// hidden debug probe, global --json/--socket).
    #[test]
    fn command_surface_parses() {
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
            &["punarctl", "capabilities", "get", "security.firewall"],
            &[
                "punarctl",
                "capabilities",
                "set",
                "system.hostname",
                "punar-m3",
            ],
            &["punarctl", "audit", "tail", "-n", "20"],
            &["punarctl", "debug", "rpc", "system.exec"],
            &["punarctl", "--json", "status"],
            &["punarctl", "status", "--json"],
            &[
                "punarctl",
                "--socket",
                "/tmp/x.sock",
                "--json",
                "capabilities",
            ],
        ];
        for example in examples {
            assert!(
                Cli::try_parse_from(example.iter()).is_ok(),
                "failed to parse {example:?}"
            );
        }
    }

    /// Capability arguments are validated via `punar_common::CapabilityId`
    /// (usage errors exit 2 through clap).
    #[test]
    fn capability_arguments_reject_invalid_ids() {
        for example in [
            ["punarctl", "policy", "explain", "firewall"].as_slice(),
            ["punarctl", "capabilities", "get", "not a capability"].as_slice(),
            ["punarctl", "capabilities", "set", "firewall", "enabled"].as_slice(),
        ] {
            assert!(Cli::try_parse_from(example.iter()).is_err(), "{example:?}");
        }
    }

    /// `audit tail` defaults to 20 events (docs/api/ipc.md section 5.5).
    #[test]
    fn audit_tail_defaults_to_twenty() {
        let cli = Cli::try_parse_from(["punarctl", "audit", "tail"]).unwrap();
        match cli.command {
            super::Command::Audit {
                command: super::AuditCommand::Tail { n },
            } => assert_eq!(n, 20),
            _ => panic!("parsed into the wrong command"),
        }
    }
}
