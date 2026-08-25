//! `punarctl` — the Punar control CLI (SPEC section 11.2).
//!
//! Milestones 3–4: the daemon-backed verbs are real. `status`,
//! `capabilities` (bare list, `get`, `set`), `audit tail`, `reconcile`,
//! and — since Milestone 4 — `policy effective` / `policy explain` speak
//! the typed NDJSON IPC contract (`docs/api/ipc.md`) to `punard` over its
//! Unix socket and render in the Plate D-014 output grammar
//! (`docs/design/mockups/cli-grammar.html`) — or, with the global `--json`
//! flag, print the IPC `result` object verbatim (capability-registry field
//! names unchanged). The policy verbs render the SPEC section 39 layered
//! merge (contract sections 5.7/5.8) in the SPEC section 40 layout, and
//! `status` renders the SPEC section 52 compliance block.
//!
//! Milestone 7 adds `agents list` / `agents inspect <id>`, the AI Agent
//! Registry surface (SPEC sections 19/20/22/23). Those verbs speak the
//! same envelope to a **second** daemon — `punar-agentd` on its own socket
//! (contract section 10) — and render Plate D-005's rail and detail in
//! terminal grammar: classification words colored (managed calm, unknown
//! in the red voice), authority rows carrying their enforcement
//! milestone, detection always spelled *suspected*, and the Access Ledger
//! named as the Milestone 8 work it still is. Every other SPEC section
//! 11.2 verb keeps a milestone-labeled stub.
//!
//! Milestone 8 makes the AI Access Ledger real: `agents access <id>`
//! (contract section 12.2) renders SPEC section 21's "what did it access?"
//! register — Level-3 resource summaries with their counts, Level-4
//! security events as audit references, and an explicit
//! `NOT YET OBSERVED · MILESTONE n` row for every category no mediation
//! point observes yet (SPEC section 1.22). `agents inspect` grows the same
//! register beneath its authority block. The new `privacy` verbs are the
//! section 24.2 half of the milestone: `privacy ledger` answers "what has
//! this device recorded about me?", and `privacy purge` deletes it — a
//! right no policy withholds for one's own sessions, because in Milestone
//! 8 no organization can read the data either.
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

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgGroup, Parser, Subcommand};
use punar_common::CapabilityId;
use serde_json::{Value, json};

use crate::fmt::Style;
use crate::ipc::{CallError, Client, Target};

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

    /// Path to the control socket, or the daemon name `punard` /
    /// `agentd` (defaults: /run/punard/punard.sock, and
    /// /run/punar-agentd/agentd.sock for the `agents.*` verbs; env
    /// PUNARD_SOCKET / PUNAR_AGENTD_SOCKET).
    #[arg(long, global = true, value_name = "PATH")]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show daemon and device status.
    Status,
    /// Enroll this device with an organization, or inspect/stop the
    /// enrollment (Milestone 5 — against the dev/CI mock control plane).
    Enroll {
        #[command(subcommand)]
        command: EnrollCommand,
    },
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
    /// Inspect the AI Agent Registry (Milestone 7) and, from Milestone 8,
    /// the AI Access Ledger. Routed to punar-agentd's socket.
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
    /// Re-observe every capability, remediate drift per the effective
    /// policy (SPEC section 42; Milestone 4), and report the outcome.
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
    /// Show the effective merged policy (SPEC section 39 layered merge).
    Effective,
    /// Explain the effective value, winning source, override permission,
    /// and compliance for one capability path (SPEC section 40).
    Explain {
        /// Dotted capability path, like `security.firewall`.
        path: CapabilityId,
    },
}

#[derive(Subcommand)]
enum AgentsCommand {
    /// List AI agent sessions and suspected AI activity.
    List,
    /// Inspect one AI agent session or detection.
    Inspect {
        /// Agent session id, like `agt_123`.
        id: String,
    },
    /// Show what an AI agent has actually accessed (Access Ledger).
    Access {
        /// Agent session id, like `agt_123`.
        id: String,
    },
    /// Force one detection pass now and print the refreshed registry.
    ///
    /// Hidden on purpose: the advertised Milestone 7 surface is `list` and
    /// `inspect` (milestone-7.md section 9), and `list` already refreshes
    /// a stale view by itself (contract section 10.2). This verb exists so
    /// the in-VM exercise — and anyone debugging detection — can ask for a
    /// pass *now* without a raw `debug rpc`.
    #[command(hide = true)]
    Scan,
}

#[derive(Subcommand)]
enum PrivacyCommand {
    /// Show what this device has recorded about AI agent sessions —
    /// and, just as loudly, what it never records (SPEC section 24.2).
    Ledger {
        /// One session id, like `agt_123`. Omitted, the whole device is
        /// summarized.
        #[arg(value_name = "ID")]
        id: Option<String>,
        /// The same thing, spelled as a flag for symmetry with `purge`.
        #[arg(long, value_name = "ID", conflicts_with = "id")]
        session: Option<String>,
    },
    /// Delete the local AI access ledger. Your own sessions are always
    /// yours to delete; the audit trail is a separate record and is not
    /// touched (SPEC sections 24.2, 53).
    #[command(group(ArgGroup::new("scope").required(true)))]
    Purge {
        /// One session id, like `agt_123`.
        #[arg(long, value_name = "ID", group = "scope")]
        session: Option<String>,
        /// Every session you own (root: every session on the device).
        #[arg(long, group = "scope")]
        all: bool,
        /// Skip the interactive confirmation.
        #[arg(long)]
        yes: bool,
    },
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

#[derive(Subcommand)]
enum EnrollCommand {
    /// Enroll with the organization at <domain> (root only; explicit by
    /// design — enrollment is never automatic, SPEC section 24).
    Start {
        /// Organization domain, like `acme.com`.
        domain: String,
    },
    /// Show enrollment state (never the device token).
    Status,
    /// Unenroll: remove the org policy layers and restore personal state
    /// (root only; local — the org keeps what it already received).
    Stop {
        /// Skip the interactive confirmation.
        #[arg(long)]
        yes: bool,
    },
}

/// Print the one-line stub notice for `invocation` and exit nonzero.
fn stub(invocation: &str, milestone: &Milestone) -> ExitCode {
    eprintln!("punarctl {invocation}: not implemented until {milestone}");
    ExitCode::FAILURE
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

/// Print a result object as one JSON line (the `--json` contract: the IPC
/// `result` verbatim).
fn print_json(result: &Value) -> ExitCode {
    match serde_json::to_string(result) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&CallError::Protocol {
            why: format!("the result could not be re-encoded ({e})"),
        }),
    }
}

/// Render a successful result with `render`, or print it verbatim in
/// `--json` mode.
fn render_or_json(
    json: bool,
    result: &Value,
    render: impl FnOnce(&Value) -> Result<String, String>,
) -> ExitCode {
    if json {
        return print_json(result);
    }
    match render(result) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(why) => fail(&CallError::Protocol { why }),
    }
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
        Ok(result) => render_or_json(json, &result, render),
        Err(error) => fail(&error),
    }
}

/// Fetch one `agents.access` result per listed session, best effort.
///
/// `privacy ledger` is a composed view (the `status` → `enroll.status`
/// precedent): the fingerprint on an `agents.list` row carries counts but
/// no retention date, and the retention date is half of what the section
/// 24.2 question asks. A session this user may not read simply has no
/// entry here — the row then renders from its counts and says why, rather
/// than the whole command failing on someone else's data.
fn collect_ledgers(agents: &Client, list: &Value) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let Some(sessions) = list.get("sessions").and_then(Value::as_array) else {
        return out;
    };
    for session in sessions {
        let Some(id) = session.get("session_id").and_then(Value::as_str) else {
            continue;
        };
        if let Ok(access) = agents.call("agents.access", Some(json!({ "session_id": id }))) {
            out.push((id.to_string(), access));
        }
    }
    out
}

/// `privacy ledger --json` for the device-wide view.
///
/// Every other `--json` in this CLI is one IPC `result` verbatim. This one
/// cannot be: the view is composed from `agents.list` plus one
/// `agents.access` per session, so the document names itself as a composed
/// local view and carries both parts unmodified. Nothing is summarized
/// away — a consumer that wants the wire objects has them.
fn privacy_ledger_json(list: &Value, accesses: &[(String, Value)]) -> Value {
    let ledgers: Vec<Value> = accesses
        .iter()
        .map(|(id, access)| json!({"session_id": id, "access": access}))
        .collect();
    json!({
        "source": "punarctl privacy ledger (composed locally from agents.list + agents.access)",
        "registry": list,
        "ledgers": ledgers,
        "readable": ledgers.len(),
        "storage_path": "/var/lib/punar/agents/ledger",
        "local_only": true,
        "remote_query": {"available": false, "milestone": "M10"},
        "audit_trail_separate": true,
        "purge_command": "punarctl privacy purge --session <id>"
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let style = Style::detect();
    // Two daemons, one CLI: `agents.*` speaks to punar-agentd (contract
    // section 10.5), everything else to punard. An explicit --socket wins
    // for whichever verb it is passed to.
    let socket = cli.socket.clone();
    let client = Client::for_target(Target::Punard, socket.as_deref());
    let json = cli.json;

    match cli.command {
        Command::Status => match client.call("status", None) {
            // The human view's org row cites the policy ids, which live in
            // `enroll.status` (contract section 7) — a second read, fetched
            // only when the device is enrolled; the row degrades to the
            // org domain if it fails. `--json` prints the status result
            // verbatim, untouched.
            Ok(result) => render_or_json(json, &result, |v| {
                let policy_ids: Vec<String> =
                    if v.get("enrolled").and_then(Value::as_bool) == Some(true) {
                        client
                            .call("enroll.status", None)
                            .ok()
                            .and_then(|s| s.get("policy_ids").cloned())
                            .and_then(|ids| serde_json::from_value(ids).ok())
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                views::status(&style, v, &policy_ids)
            }),
            Err(error) => fail(&error),
        },
        Command::Enroll { command } => {
            let hostname = local_hostname();
            match command {
                EnrollCommand::Start { domain } => {
                    // 90 s client budget for this one verb (contract
                    // section 2): the pipeline runs a full reconcile pass
                    // server-side.
                    match client.call_with_timeout(
                        "enroll.start",
                        Some(json!({ "org_domain": domain })),
                        crate::ipc::ENROLL_START_TIMEOUT,
                    ) {
                        Ok(result) => render_or_json(json, &result, |v| {
                            views::enroll_start(&style, v, &hostname)
                        }),
                        Err(error) => fail(&error),
                    }
                }
                EnrollCommand::Status => rpc(&client, json, "enroll.status", None, |v| {
                    views::enroll_status(&style, v, &hostname)
                }),
                EnrollCommand::Stop { yes } => {
                    // Interactive confirmation (D-014: destructive verbs
                    // confirm): prompted only on a TTY without --yes;
                    // scripts and --json calls are deliberate already.
                    if !yes && !json && std::io::stdin().is_terminal() {
                        eprint!(
                            "Unenroll from the organization? Org policy layers are removed \
                             and all sync stops. Type yes to continue: "
                        );
                        let mut answer = String::new();
                        let _ = std::io::stdin().read_line(&mut answer);
                        if answer.trim() != "yes" {
                            eprintln!("Unenroll aborted — nothing was changed.");
                            return ExitCode::FAILURE;
                        }
                    }
                    rpc(&client, json, "enroll.stop", None, |v| {
                        views::enroll_stop(&style, v, &hostname)
                    })
                }
            }
        }
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
                match client.call(
                    "capabilities.set",
                    Some(json!({
                        "capability": capability.as_str(),
                        "desired_state": desired_state,
                    })),
                ) {
                    Ok(result) => render_or_json(json, &result, |v| {
                        // M5 (contract section 5.4): an overridden set
                        // renders the "Recorded, not applied" verdict
                        // citing the pinning source — fetched via
                        // `policy.explain` (the set result deliberately
                        // stays M4-shaped). Best-effort: without it the
                        // verdict still states the override.
                        let pinning: Option<model::PolicyExplain> =
                            if v.get("overridden").and_then(Value::as_bool) == Some(true) {
                                client
                                    .call(
                                        "policy.explain",
                                        Some(json!({ "path": capability.as_str() })),
                                    )
                                    .ok()
                                    .and_then(|e| serde_json::from_value(e).ok())
                            } else {
                                None
                            };
                        views::set(&style, v, &hostname, pinning.as_ref())
                    }),
                    Err(error) => fail(&error),
                }
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
            // Milestone 4: the policy verbs are daemon-backed (contract
            // sections 5.7/5.8) — the effective document is the SPEC
            // section 39 layered merge computed by punard; the M3 "no
            // policy engine yet" local answer is retired.
            PolicyCommand::Effective => {
                let hostname = local_hostname();
                rpc(&client, json, "policy.effective", None, |v| {
                    views::policy_effective(&style, v, &hostname)
                })
            }
            PolicyCommand::Explain { path } => rpc(
                &client,
                json,
                "policy.explain",
                Some(json!({"path": path.as_str()})),
                |v| views::policy_explain(&style, v, path.as_str()),
            ),
        },
        Command::Debug { command } => match command {
            DebugCommand::Rpc { method } => {
                // The probe follows the same routing as the real verbs, so
                // a negative probe reaches the daemon that owns the name
                // (contract section 10.5) — `--socket agentd` forces it.
                let probe = Client::for_target(Target::of_method(&method), socket.as_deref());
                match probe.call(&method, None) {
                    Ok(result) => {
                        println!("{result}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => fail(&error),
                }
            }
        },
        Command::Compliance => stub("compliance", &M5_ENROLLMENT),
        Command::Agents { command } => {
            let agents = Client::for_target(Target::Agentd, socket.as_deref());
            match command {
                AgentsCommand::List => {
                    let hostname = local_hostname();
                    rpc(&agents, json, "agents.list", None, |v| {
                        views::agents_list(&style, v, &hostname)
                    })
                }
                AgentsCommand::Inspect { id } => {
                    match agents.call("agents.get", Some(json!({ "session_id": id.clone() }))) {
                        // The ledger register is a second read (contract
                        // section 12.2) — the `status` → `enroll.status`
                        // precedent, and for the same reason: one result
                        // object per method, composed by the renderer.
                        // `--json` stays the `agents.get` result verbatim.
                        Ok(result) => render_or_json(json, &result, |v| {
                            let suspected = v["session"].get("suspected").and_then(Value::as_bool)
                                == Some(true);
                            let ledger = if suspected {
                                // A detection has no persisted session and so
                                // no ledger to ask for (milestone-8.md §3.1).
                                None
                            } else {
                                Some(
                                    agents
                                        .call("agents.access", Some(json!({ "session_id": id })))
                                        .map_err(|error| error.message()),
                                )
                            };
                            let ledger = ledger.as_ref().map(|r| r.as_ref().map_err(String::clone));
                            views::agent_inspect(&style, v, ledger)
                        }),
                        Err(error) => fail(&error),
                    }
                }
                AgentsCommand::Scan => {
                    let hostname = local_hostname();
                    rpc(&agents, json, "agents.scan", None, |v| {
                        views::agents_list(&style, v, &hostname)
                    })
                }
                // SPEC section 11.2's reserved verb, real since M8. The
                // ledger is personal data: the daemon admits the session
                // owner or root and answers `denied` (exit 3) otherwise.
                AgentsCommand::Access { id } => rpc(
                    &agents,
                    json,
                    "agents.access",
                    Some(json!({ "session_id": id })),
                    |v| views::agent_access(&style, v),
                ),
            }
        }
        Command::Privacy { command } => {
            let agents = Client::for_target(Target::Agentd, socket.as_deref());
            match command {
                PrivacyCommand::Ledger { id, session } => {
                    let hostname = local_hostname();
                    match id.or(session) {
                        // One session: a single call, so `--json` is the
                        // `agents.access` result verbatim.
                        Some(id) => rpc(
                            &agents,
                            json,
                            "agents.access",
                            Some(json!({ "session_id": id })),
                            |v| views::privacy_ledger_session(&style, v, &hostname),
                        ),
                        // The device-wide view is composed from two
                        // methods, so its `--json` is a composed local
                        // document and says so in its own `source` field.
                        None => match agents.call("agents.list", None) {
                            Ok(list) => {
                                let accesses = collect_ledgers(&agents, &list);
                                if json {
                                    print_json(&privacy_ledger_json(&list, &accesses))
                                } else {
                                    match views::privacy_ledger(&style, &list, &accesses, &hostname)
                                    {
                                        Ok(text) => {
                                            print!("{text}");
                                            ExitCode::SUCCESS
                                        }
                                        Err(why) => fail(&CallError::Protocol { why }),
                                    }
                                }
                            }
                            Err(error) => fail(&error),
                        },
                    }
                }
                PrivacyCommand::Purge { session, all, yes } => {
                    let hostname = local_hostname();
                    let (params, scope) = match (&session, all) {
                        (Some(id), false) => (json!({ "session_id": id }), format!("session {id}")),
                        (None, true) => (
                            json!({ "all": true }),
                            "every session you own (root: every session on this device)"
                                .to_string(),
                        ),
                        // clap's required group makes both other shapes
                        // unreachable; the daemon rejects them too
                        // (invalid_params, contract section 12.3).
                        _ => {
                            eprintln!(
                                "punarctl privacy purge: choose exactly one scope.\n\
                                 Next step: punarctl privacy purge --session <id>, or \
                                 punarctl privacy purge --all"
                            );
                            return ExitCode::from(2);
                        }
                    };
                    // Destructive verb: confirm on a TTY unless --yes (the
                    // `enroll stop` precedent). Deletion is real — the
                    // file is unlinked and a tombstone floors re-ingestion.
                    if !yes && !json && std::io::stdin().is_terminal() {
                        eprint!(
                            "Delete the local AI access ledger for {scope}? This cannot be \
                             undone. The audit trail is a separate record and is not \
                             deleted. Type yes to continue: "
                        );
                        let mut answer = String::new();
                        let _ = std::io::stdin().read_line(&mut answer);
                        if answer.trim() != "yes" {
                            eprintln!("Purge aborted — nothing was deleted.");
                            return ExitCode::FAILURE;
                        }
                    }
                    rpc(&agents, json, "ledger.purge", Some(params), |v| {
                        views::privacy_purge(&style, v, &hostname, &scope)
                    })
                }
                PrivacyCommand::Connections => {
                    // Reserved honestly: the verb is in SPEC section 11.2,
                    // and nothing on this device observes network
                    // destinations until punar-netd (M12). Naming the
                    // milestone beats a silent absence.
                    eprintln!("{}", views::privacy_connections_notice());
                    ExitCode::FAILURE
                }
            }
        }
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
            &["punarctl", "agents", "scan"],
            &["punarctl", "agents", "inspect", "agt_123"],
            &["punarctl", "agents", "access", "agt_123"],
            &["punarctl", "privacy", "connections"],
            &["punarctl", "privacy", "ledger"],
            &["punarctl", "privacy", "ledger", "agt_123"],
            &["punarctl", "privacy", "ledger", "--session", "agt_123"],
            &["punarctl", "--json", "privacy", "ledger"],
            &["punarctl", "privacy", "purge", "--session", "agt_123"],
            &[
                "punarctl",
                "privacy",
                "purge",
                "--session",
                "agt_123",
                "--yes",
            ],
            &["punarctl", "privacy", "purge", "--all", "--yes"],
            // The exact argv the AI panel hands `execDetached` (fixed
            // argv, never a shell string): shell/punar-shell/AiPanel.
            &["punarctl", "agents", "access", "agt_123", "--json"],
            &[
                "punarctl",
                "privacy",
                "purge",
                "--session",
                "agt_123",
                "--yes",
            ],
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
            &["punarctl", "enroll", "start", "acme.com"],
            &["punarctl", "enroll", "status"],
            &["punarctl", "enroll", "stop"],
            &["punarctl", "enroll", "stop", "--yes"],
            &["punarctl", "--json", "enroll", "start", "acme.com"],
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

    /// `privacy purge` is destructive, so clap — not the daemon — makes
    /// the scope explicit: exactly one of `--session` / `--all`, never
    /// both, never neither. A usage error exits 2 before any IPC happens.
    #[test]
    fn privacy_purge_requires_exactly_one_scope() {
        for example in [
            ["punarctl", "privacy", "purge"].as_slice(),
            ["punarctl", "privacy", "purge", "--yes"].as_slice(),
            [
                "punarctl",
                "privacy",
                "purge",
                "--session",
                "agt_1",
                "--all",
            ]
            .as_slice(),
        ] {
            assert!(Cli::try_parse_from(example.iter()).is_err(), "{example:?}");
        }
    }

    /// `privacy ledger` takes the id positionally or as `--session`, but
    /// never twice.
    #[test]
    fn privacy_ledger_rejects_two_spellings_of_one_id() {
        assert!(
            Cli::try_parse_from(
                [
                    "punarctl",
                    "privacy",
                    "ledger",
                    "agt_1",
                    "--session",
                    "agt_2"
                ]
                .iter()
            )
            .is_err()
        );
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
