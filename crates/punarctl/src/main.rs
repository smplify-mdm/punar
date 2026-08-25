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
//! Milestone 9 completes the exit-code table and adds the three verb
//! families of the approval milestone. `approvals list/get/resolve/wait`
//! is the human half of the SPEC section 28 gate — and `resolve` is
//! human-only in the daemon, so Plate D-014 register 05's `[A]`/`[D]`
//! affordance is drawn only for a peer eligible to use it. `privilege
//! request/status/revoke` is Plate D-012's just-in-time elevation: a
//! required reason, a duration in minutes, a grant that counts itself
//! down, and no permanent local administrator anywhere behind it.
//! `secrets list/get/validate/revoke` speaks to a **third** daemon,
//! `punar-secrets`, over its own socket (contract section 16), and it is
//! where the section 53 rule becomes structural: the issued value is
//! written **bare to stdout and nowhere else**, the card explaining it
//! goes to stderr so `TOKEN=$(punarctl secrets get aws-dev)` works, and
//! a token is never accepted on argv — `validate` and `revoke` read it
//! from stdin, because `/proc/<pid>/cmdline` is world-readable.
//!
//! Exit codes (Plate D-014 Sect III), now complete: 0 success · 1
//! runtime/daemon error · 2 usage (clap) · 3 denied · **4
//! approval_required, real as of Milestone 9** · 5 daemon unreachable.

#![forbid(unsafe_code)]

mod fmt;
mod ipc;
mod model;
mod peer;
mod views;
mod watch;

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{ArgGroup, Parser, Subcommand};
use punar_common::{CapabilityId, Redacted};
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
    /// Answer the approval gates this device is holding (Milestone 9,
    /// SPEC section 28). An approval is a gate, not a notification: the
    /// capability does not execute until a human resolves it.
    Approvals {
        #[command(subcommand)]
        command: ApprovalsCommand,
    },
    /// Ask for time-boxed privilege, and see or drop what you hold
    /// (Milestone 9, SPEC section 48). There is no permanent local
    /// administrator on this device — there is a reason, a grant, and a
    /// clock.
    Privilege {
        #[command(subcommand)]
        command: PrivilegeCommand,
    },
    /// Short-lived credentials from the local secret broker (Milestone
    /// 9, SPEC section 29). Routed to punar-secrets on its own socket.
    Secrets {
        #[command(subcommand)]
        command: SecretsCommand,
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
enum ApprovalsCommand {
    /// List approvals — pending first, then recently resolved.
    List,
    /// Show one approval as its full contract card.
    Get {
        /// Approval id, like `apr_7c1d9a4e`.
        approval_id: String,
    },
    /// Answer one approval. Human-only in the daemon (contract section
    /// 14.5): an AI agent may resolve nothing, ever, including a
    /// human's request.
    Resolve {
        /// Approval id, like `apr_7c1d9a4e`.
        approval_id: String,
        /// The decision. There is no default — a gate is answered
        /// deliberately or not at all.
        #[arg(long, value_parser = ["approved", "denied"])]
        decision: String,
    },
    /// Wait for one approval to be answered (Plate D-014 register 05).
    ///
    /// Event-driven: an inotify watch supplies the wake, the socket
    /// supplies the truth. The wait is bounded by the approval's own
    /// expiry, so it can never outlast the request it is watching.
    Wait {
        /// Approval id, like `apr_7c1d9a4e`.
        approval_id: String,
        /// Give up after this many seconds and exit 4. Capped by the
        /// approval's `expires_at` either way.
        #[arg(long, default_value_t = 300, value_name = "SECONDS")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
enum PrivilegeCommand {
    /// Request time-boxed privilege for one capability (Plate D-012).
    /// Creates an approval and returns exit 4 — nothing is elevated
    /// until it is answered.
    Request {
        /// Dotted capability path, like `time.timezone`. One capability
        /// per grant: no wildcard, no `--all`.
        #[arg(long)]
        capability: CapabilityId,
        /// Why you need it. Required — it travels verbatim into the
        /// audit event (Plate D-012 Sect I.02).
        #[arg(long)]
        reason: String,
        /// Grant window in MINUTES (SPEC section 48: "Approved for 15
        /// minutes"). A policy value, not a constant.
        #[arg(long, default_value_t = 15, value_name = "MINUTES")]
        duration: u64,
    },
    /// Show the grants you hold right now, and what is left of each.
    Status,
    /// Drop a grant early. Privilege is never invisible and never
    /// permanent.
    Revoke {
        /// Grant id, like `gnt_2b8e11c4`. Omitted, the single grant you
        /// hold is revoked; ambiguity is a usage error, never a guess.
        grant_id: Option<String>,
        /// Every grant you hold.
        #[arg(long, conflicts_with = "grant_id")]
        all: bool,
    },
}

#[derive(Subcommand)]
enum SecretsCommand {
    /// List credential classes and their effective decision. Never
    /// values: after issuance the broker holds only a hash.
    List,
    /// Request a short-lived credential. The VALUE goes to stdout, bare;
    /// the card goes to stderr.
    Get {
        /// Credential class, kebab-case on the wire — `github`,
        /// `aws-dev`, `aws-prod` (SPEC section 29).
        credential: String,
        /// Requested lifetime in seconds. Clamped by the class.
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
    },
    /// Check a credential. The value is read from STDIN — there is no
    /// `--token` flag and there never will be, because
    /// `/proc/<pid>/cmdline` is world-readable.
    Validate {
        /// Credential class the value claims to belong to.
        #[arg(long)]
        class: String,
    },
    /// Revoke a credential immediately. The value is read from STDIN.
    Revoke,
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

// ---------------------------------------------------------------------
// Milestone 9 helpers
// ---------------------------------------------------------------------

/// The approval summary file (contract section 15). Read here only as a
/// **wake source** for `approvals wait`; every verdict comes from the
/// socket. It is `0640 root:punar` inside the root-owned `/run/punard`
/// on purpose — the file that tells a human what they are about to
/// authorize must not sit in a user-writable directory.
const APPROVALS_SUMMARY: &str = "/run/punard/approvals.json";

/// The redraw cadence of `approvals wait`'s countdown. One second, and
/// only while a human is being asked something.
const COUNTDOWN_TICK: Duration = Duration::from_secs(1);

/// `punarctl approvals wait` exit code for an approval that outlived the
/// wait without being answered (contract section 14.1 / milestone-9.md
/// section 10): still pending is still `approval_required`.
const EXIT_STILL_PENDING: u8 = ipc::EXIT_APPROVAL_REQUIRED;

/// Render the **exit 4** surface for a gated call (contract section
/// 14.1). Not a failure report: the request is alive, recorded, and
/// waiting on a human, and nothing was executed.
///
/// Human mode gets the section 73 card on stderr; `--json` gets the
/// error envelope as one line on stderr, so a script can lift the
/// `approval_id` out without parsing prose. Either way stdout stays
/// empty — there is no result to pipe, because nothing ran.
fn approval_required_exit(
    style: &Style,
    error: &CallError,
    hostname: &str,
    json: bool,
) -> ExitCode {
    let Some(err) = error.server() else {
        return fail(error);
    };
    if json {
        let line = json!({"error": {
            "code": err.code,
            "message": err.message,
            "details": err.details.clone().unwrap_or(Value::Null),
        }});
        eprintln!("{line}");
    } else {
        eprint!(
            "{}",
            views::approval_required(style, &err.message, err.details.as_ref(), hostname)
        );
    }
    ExitCode::from(ipc::EXIT_APPROVAL_REQUIRED)
}

/// One call whose `approval_required` is an outcome rather than a
/// failure: `capabilities.set`, `credential.request`, `privilege.request`
/// all take this path.
fn rpc_gated(
    client: &Client,
    style: &Style,
    json: bool,
    hostname: &str,
    method: &str,
    params: Option<Value>,
    render: impl FnOnce(&Value) -> Result<String, String>,
) -> ExitCode {
    match client.call(method, params) {
        Ok(result) => render_or_json(json, &result, render),
        Err(error) if error.is_approval_required() => {
            approval_required_exit(style, &error, hostname, json)
        }
        Err(error) => fail(&error),
    }
}

/// The routed user of an approval envelope — the input to the display
/// eligibility test (contract section 14.5).
fn routed_user(envelope: &Value) -> String {
    envelope
        .pointer("/approval/user")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// The status of an approval envelope.
fn approval_status(envelope: &Value) -> String {
    envelope
        .pointer("/approval/status")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// `expires_at` of an approval envelope, as a unix second.
fn approval_deadline(envelope: &Value) -> Option<u64> {
    let stamp = envelope.pointer("/approval/expires_at")?.as_str()?;
    punar_common::time::unix_seconds_from_rfc3339(stamp)
}

/// Render (or dump) a result, returning `Err(code)` only when the render
/// itself failed — so a caller that owns the exit code (`approvals wait`
/// maps the *status* to the code) keeps it, and a broken renderer still
/// reports itself instead of being masked by a success.
fn emit(
    json: bool,
    result: &Value,
    render: impl FnOnce(&Value) -> Result<String, String>,
) -> Result<(), ExitCode> {
    if json {
        return match serde_json::to_string(result) {
            Ok(line) => {
                println!("{line}");
                Ok(())
            }
            Err(e) => Err(fail(&CallError::Protocol {
                why: format!("the result could not be re-encoded ({e})"),
            })),
        };
    }
    match render(result) {
        Ok(text) => {
            print!("{text}");
            Ok(())
        }
        Err(why) => Err(fail(&CallError::Protocol { why })),
    }
}

/// Exit code for a terminal approval status (milestone-9.md section 10):
/// 0 approved · 3 denied · 1 expired.
fn wait_exit(status: &str) -> ExitCode {
    match status {
        "approved" => ExitCode::SUCCESS,
        "denied" => ExitCode::from(ipc::EXIT_DENIED),
        _ => ExitCode::FAILURE,
    }
}

/// `punarctl approvals wait <apr_id>` — Plate D-014 register 05.
///
/// Watch for the wake, socket for the truth: an inotify watch on the
/// summary file's directory says *something changed*, and one
/// authoritative `approvals.get` says *what*. The 1 Hz tick is the
/// countdown's own redraw and spends no IPC.
///
/// The wait cannot outlast the request: the deadline is
/// `min(--timeout, expires_at)`, and an approval lives at most 300 s.
fn approvals_wait(
    client: &Client,
    style: &Style,
    json: bool,
    hostname: &str,
    approval_id: &str,
    timeout: u64,
) -> ExitCode {
    let params = json!({ "approval_id": approval_id });
    let mut current = match client.call("approvals.get", Some(params.clone())) {
        Ok(v) => v,
        Err(error) => return fail(&error),
    };

    // Already answered: print the verdict and leave. A wait on a settled
    // approval is a read, not a wait.
    let status = approval_status(&current);
    if status != "pending" {
        let eligible = peer::may_resolve(&routed_user(&current));
        if let Err(code) = emit(json, &current, |v| {
            views::approval_wait(style, v, hostname, eligible)
        }) {
            return code;
        }
        return wait_exit(&status);
    }

    let eligible = peer::may_resolve(&routed_user(&current));
    if !json {
        match views::approval_wait(style, &current, hostname, eligible) {
            Ok(card) => print!("{card}"),
            Err(why) => return fail(&CallError::Protocol { why }),
        }
    }

    // The deadline: the caller's patience, floored by the approval's own
    // expiry. A one-second grace lets the daemon's lazy sweep observe the
    // lapse on our final read, so the last word is still the daemon's.
    let started = Instant::now();
    let patience = Duration::from_secs(timeout);
    let hard_stop = approval_deadline(&current).map(|deadline| {
        let now = (punar_common::time::unix_now_millis() / 1000) as u64;
        Duration::from_secs(deadline.saturating_sub(now) + 1)
    });
    let budget = match hard_stop {
        Some(stop) => patience.min(stop),
        None => patience,
    };

    // The wake source. A machine where the summary directory cannot be
    // watched (no punard, or no read permission) degrades to a slower
    // re-check rather than failing — a missing summary file is a calm
    // state, not an error surface.
    let watch = watch::DirWatch::on(Path::new(APPROVALS_SUMMARY)).ok();
    let mut since_recheck = Duration::ZERO;
    let live = std::io::stderr().is_terminal();

    loop {
        let elapsed = started.elapsed();
        if elapsed >= budget {
            break;
        }
        let tick = COUNTDOWN_TICK.min(budget - elapsed);
        let woken = match &watch {
            Some(w) => w.wait(tick).unwrap_or(false),
            None => {
                std::thread::sleep(tick);
                since_recheck += tick;
                let due = since_recheck >= watch::FALLBACK_RECHECK;
                if due {
                    since_recheck = Duration::ZERO;
                }
                due
            }
        };

        // The countdown, redrawn in place — only for a human at a
        // terminal, so a script or a CI log never sees carriage returns.
        if live && !json {
            let left = approval_deadline(&current)
                .map(|d| d as i64 - (punar_common::time::unix_now_millis() / 1000) as i64)
                .unwrap_or(0);
            let mut err = std::io::stderr();
            let _ = write!(err, "\r  Expires in {}   ", views::countdown(left));
            let _ = err.flush();
        }

        if !woken {
            continue;
        }
        // Something changed. Ask the authority.
        current = match client.call("approvals.get", Some(params.clone())) {
            Ok(v) => v,
            Err(error) => {
                if live && !json {
                    eprintln!();
                }
                return fail(&error);
            }
        };
        let status = approval_status(&current);
        if status != "pending" {
            if live && !json {
                eprintln!();
            }
            if let Err(code) = emit(json, &current, |v| {
                views::approval_wait(style, v, hostname, eligible)
            }) {
                return code;
            }
            return wait_exit(&status);
        }
    }

    // The budget ran out. One last authoritative read: the daemon sweeps
    // expiry lazily on every read, so this call is what turns a lapsed
    // approval into a recorded `expired` rather than a silent one.
    if live && !json {
        eprintln!();
    }
    match client.call("approvals.get", Some(params)) {
        Ok(final_state) => {
            let status = approval_status(&final_state);
            if let Err(code) = emit(json, &final_state, |v| {
                views::approval_wait(style, v, hostname, eligible)
            }) {
                return code;
            }
            if status == "pending" {
                if !json {
                    eprintln!(
                        "Still pending after {timeout}s — nothing has been executed.\n\
                         Next step: answer it in the approval overlay, or run \
                         punarctl approvals wait {approval_id} again."
                    );
                }
                return ExitCode::from(EXIT_STILL_PENDING);
            }
            wait_exit(&status)
        }
        Err(error) => fail(&error),
    }
}

/// Read one credential value from **stdin**.
///
/// Secrets are never accepted on argv: `/proc/<pid>/cmdline` is
/// world-readable, so a `--token` flag does not exist and must never be
/// added (contract section 16.4). The value is wrapped in
/// [`Redacted`] the moment it exists, so no stray `{:?}` anywhere
/// downstream can print it.
fn token_from_stdin(verb: &str) -> Result<Redacted<String>, ExitCode> {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        eprintln!(
            "punarctl secrets {verb}: the credential value could not be read from \
             standard input.\n\
             Why: the value must arrive on stdin — Punar never accepts a secret on \
             argv, because /proc/<pid>/cmdline is world-readable.\n\
             Next step: printf %s \"$TOKEN\" | punarctl secrets {verb} …"
        );
        return Err(ExitCode::from(2));
    }
    let value = raw.trim().to_string();
    if value.is_empty() {
        eprintln!(
            "punarctl secrets {verb}: no credential value arrived on standard input.\n\
             Why: the value is read from stdin by design — there is no --token flag, \
             because /proc/<pid>/cmdline is world-readable.\n\
             Next step: printf %s \"$TOKEN\" | punarctl secrets {verb} …"
        );
        return Err(ExitCode::from(2));
    }
    Ok(Redacted::new(value))
}

/// `punarctl secrets get <class>` — issuance, and the one place in Punar
/// where a secret reaches a file descriptor.
///
/// The value goes to **stdout, bare, with no masthead**; the human card
/// goes to **stderr**. That split is the whole design:
/// `TOKEN=$(punarctl secrets get aws-dev)` captures the value and only
/// the value, and prose can never contaminate it. `--json` serializes
/// the value on stdout — the one place Punar ever serializes a secret,
/// documented in contract section 16.4, and never persisted by Punar.
///
/// The honest leak surface, stated where it lives: the caller may
/// redirect stdout to a file. Punar cannot prevent that and does not
/// claim to. The promise is exactly **Punar never writes it**.
fn secrets_get(
    broker: &Client,
    style: &Style,
    json: bool,
    hostname: &str,
    credential: &str,
    ttl: Option<u64>,
) -> ExitCode {
    let mut params = json!({ "credential": credential });
    if let Some(ttl) = ttl {
        params["ttl"] = json!(ttl);
    }
    match broker.call("credential.request", Some(params)) {
        Ok(result) => {
            if json {
                return print_json(&result);
            }
            // Lift the value out into a Redacted before anything else
            // touches the result, and render the card first: a card that
            // cannot be rendered must not emit a value into a stream the
            // caller may already be capturing.
            let Some(value) = result.get("value").and_then(Value::as_str) else {
                return fail(&CallError::Protocol {
                    why: "the broker answered without a credential value".to_string(),
                });
            };
            let value = Redacted::new(value.to_string());
            match views::secrets_card(style, &result, hostname) {
                Ok(card) => eprint!("{card}"),
                Err(why) => return fail(&CallError::Protocol { why }),
            }
            println!("{}", value.expose_secret());
            ExitCode::SUCCESS
        }
        Err(error) if error.is_approval_required() => {
            approval_required_exit(style, &error, hostname, json)
        }
        Err(error) => fail(&error),
    }
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
                    // M9 (contract section 14.1): an agent-originated
                    // mutation the AI policy gates answers
                    // `approval_required` and executes NOTHING. Exit 4,
                    // reserved since M3, is real from here.
                    Err(error) if error.is_approval_required() => {
                        approval_required_exit(&style, &error, &hostname, json)
                    }
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
        // M9 (contract section 14): the approval gate, from the human
        // side. `resolve` is human-only in the daemon, and this CLI never
        // pretends otherwise — the affordance on a card is drawn only for
        // a peer eligible to use it, and the daemon re-checks regardless.
        Command::Approvals { command } => {
            let hostname = local_hostname();
            match command {
                ApprovalsCommand::List => rpc(&client, json, "approvals.list", None, |v| {
                    views::approvals_list(&style, v, &hostname)
                }),
                ApprovalsCommand::Get { approval_id } => {
                    match client.call("approvals.get", Some(json!({ "approval_id": approval_id })))
                    {
                        Ok(result) => render_or_json(json, &result, |v| {
                            let eligible = peer::may_resolve(&routed_user(v));
                            views::approval_get(&style, v, &hostname, eligible)
                        }),
                        Err(error) => fail(&error),
                    }
                }
                ApprovalsCommand::Resolve {
                    approval_id,
                    decision,
                } => rpc(
                    &client,
                    json,
                    "approvals.resolve",
                    Some(json!({"approval_id": approval_id, "decision": decision})),
                    |v| views::approval_resolved(&style, v, &hostname),
                ),
                ApprovalsCommand::Wait {
                    approval_id,
                    timeout,
                } => approvals_wait(&client, &style, json, &hostname, &approval_id, timeout),
            }
        }
        // M9 (contract section 14.8, Plate D-012): privilege you ask for,
        // with a reason, for a while.
        Command::Privilege { command } => {
            let hostname = local_hostname();
            match command {
                PrivilegeCommand::Request {
                    capability,
                    reason,
                    duration,
                } => {
                    // Validated here as well as in the daemon, because a
                    // usage error deserves an exit 2 and a sentence, not
                    // a round trip. The rules are the contract's
                    // (section 14.4): one line, printable, ≤ 512 bytes.
                    let reason = reason.trim();
                    if reason.is_empty() {
                        eprintln!(
                            "punarctl privilege request: --reason is required.\n\
                             Why: the reason travels verbatim into the audit event — an \
                             elevation with no stated purpose is not auditable.\n\
                             Next step: punarctl privilege request --capability {} \
                             --reason \"<why you need it>\"",
                            capability.as_str()
                        );
                        return ExitCode::from(2);
                    }
                    if reason.len() > 512 || reason.chars().any(char::is_control) {
                        eprintln!(
                            "punarctl privilege request: --reason must be one line of at \
                             most 512 bytes.\n\
                             Why: it is displayed on the approval surface and written to \
                             the audit event verbatim; control characters and newlines \
                             would let a request draw something it is not.\n\
                             Next step: shorten the reason to a single sentence."
                        );
                        return ExitCode::from(2);
                    }
                    if !(1..=60).contains(&duration) {
                        eprintln!(
                            "punarctl privilege request: --duration is in minutes, from 1 \
                             to 60.\n\
                             Why: privilege is time-boxed by design — there is no \
                             permanent local administrator on this device.\n\
                             Next step: punarctl privilege request --capability {} \
                             --reason \"…\" --duration 15",
                            capability.as_str()
                        );
                        return ExitCode::from(2);
                    }
                    rpc_gated(
                        &client,
                        &style,
                        json,
                        &hostname,
                        "privilege.request",
                        Some(json!({
                            "capability": capability.as_str(),
                            "reason": reason,
                            "duration_minutes": duration,
                        })),
                        // A daemon that answers with a record rather than
                        // the gate error still renders — the card is the
                        // same card either way.
                        |v| views::approval_get(&style, v, &hostname, true),
                    )
                }
                PrivilegeCommand::Status => rpc(&client, json, "privilege.status", None, |v| {
                    views::privilege_status(&style, v, &hostname)
                }),
                PrivilegeCommand::Revoke { grant_id, all } => {
                    let (params, scope) = match (grant_id, all) {
                        (Some(id), _) => (json!({ "grant_id": id.clone() }), format!("grant {id}")),
                        (None, true) => {
                            (json!({ "all": true }), "every grant you hold".to_string())
                        }
                        // No id and no --all: resolve the single grant if
                        // there is exactly one, and refuse to guess
                        // otherwise. Revoking the wrong grant is cheap to
                        // undo and expensive to notice.
                        (None, false) => match client.call("privilege.status", None) {
                            Ok(status) => {
                                let grants: Vec<String> = status
                                    .get("grants")
                                    .and_then(Value::as_array)
                                    .map(|g| {
                                        g.iter()
                                            .filter_map(|e| e.get("grant_id"))
                                            .filter_map(Value::as_str)
                                            .map(str::to_string)
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                match grants.len() {
                                    1 => (
                                        json!({ "grant_id": grants[0].clone() }),
                                        format!("grant {}", grants[0]),
                                    ),
                                    0 => {
                                        eprintln!(
                                            "punarctl privilege revoke: you hold no grants.\n\
                                             Why: there is nothing elevated to drop.\n\
                                             Next step: punarctl privilege status"
                                        );
                                        return ExitCode::from(2);
                                    }
                                    n => {
                                        eprintln!(
                                            "punarctl privilege revoke: you hold {n} grants, \
                                             so this is ambiguous.\n\
                                             Why: Punar does not guess which privilege to \
                                             drop.\n\
                                             Next step: punarctl privilege revoke {} — or \
                                             --all",
                                            grants.join(" | ")
                                        );
                                        return ExitCode::from(2);
                                    }
                                }
                            }
                            Err(error) => return fail(&error),
                        },
                    };
                    rpc(&client, json, "privilege.revoke", Some(params), |v| {
                        views::privilege_revoked(&style, v, &hostname, &scope)
                    })
                }
            }
        }
        // M9 (contract section 16): the third daemon. Class ids are
        // kebab-case on the wire and in the ledger; values never appear
        // anywhere but stdout, once.
        Command::Secrets { command } => {
            let broker = Client::for_target(Target::Secrets, socket.as_deref());
            let hostname = local_hostname();
            match command {
                SecretsCommand::List => rpc(&broker, json, "credential.classes", None, |v| {
                    views::secrets_list(&style, v, &hostname)
                }),
                SecretsCommand::Get { credential, ttl } => {
                    secrets_get(&broker, &style, json, &hostname, &credential, ttl)
                }
                SecretsCommand::Validate { class } => match token_from_stdin("validate") {
                    Ok(token) => {
                        match broker.call(
                            "credential.validate",
                            Some(json!({"credential": class, "value": token.expose_secret()})),
                        ) {
                            Ok(result) => render_or_json(json, &result, |v| {
                                views::secrets_validate(&style, v, &hostname)
                            }),
                            // `expired` and `not_found` are verdicts, not
                            // malfunctions (contract section 16.5). The
                            // word INVALID comes from the wire code so it
                            // never depends on the daemon's prose; the
                            // daemon's own sentence still prints verbatim.
                            Err(error)
                                if error.server().is_some_and(|e| {
                                    e.code == ipc::CODE_EXPIRED || e.code == "not_found"
                                }) =>
                            {
                                let err = error.server().expect("checked above");
                                if json {
                                    eprintln!(
                                        "{}",
                                        json!({"error": {"code": err.code,
                                                         "message": err.message}})
                                    );
                                } else {
                                    eprint!(
                                        "{}",
                                        views::secrets_invalid(
                                            &style,
                                            &err.code,
                                            &err.message,
                                            &hostname
                                        )
                                    );
                                }
                                ExitCode::FAILURE
                            }
                            Err(error) => fail(&error),
                        }
                    }
                    Err(code) => code,
                },
                SecretsCommand::Revoke => match token_from_stdin("revoke") {
                    Ok(token) => rpc(
                        &broker,
                        json,
                        "credential.revoke",
                        Some(json!({ "value": token.expose_secret() })),
                        |v| views::secrets_revoked(&style, v, &hostname),
                    ),
                    Err(code) => code,
                },
            }
        }
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
            // M9 — the approval gate, JIT privilege, the broker.
            &["punarctl", "approvals", "list"],
            &["punarctl", "--json", "approvals", "list"],
            &["punarctl", "approvals", "get", "apr_7c1d9a4e"],
            &[
                "punarctl",
                "approvals",
                "resolve",
                "apr_7c1d9a4e",
                "--decision",
                "approved",
            ],
            &[
                "punarctl",
                "approvals",
                "resolve",
                "apr_7c1d9a4e",
                "--decision",
                "denied",
            ],
            &["punarctl", "approvals", "wait", "apr_7c1d9a4e"],
            &[
                "punarctl",
                "approvals",
                "wait",
                "apr_7c1d9a4e",
                "--timeout",
                "60",
            ],
            // The exact argv the D-003 overlay hands `execDetached`
            // (fixed argv, never a shell string):
            // shell/punar-shell/Approval/ApprovalOverlay.qml.
            &[
                "punarctl",
                "approvals",
                "resolve",
                "apr_7c1d9a4e",
                "--decision",
                "approved",
            ],
            &["punarctl", "privilege", "status"],
            &[
                "punarctl",
                "privilege",
                "request",
                "--capability",
                "time.timezone",
                "--reason",
                "Reproducing the Atlas net bug",
            ],
            &[
                "punarctl",
                "privilege",
                "request",
                "--capability",
                "time.timezone",
                "--reason",
                "why",
                "--duration",
                "15",
            ],
            &["punarctl", "privilege", "revoke"],
            &["punarctl", "privilege", "revoke", "gnt_2b8e11c4"],
            &["punarctl", "privilege", "revoke", "--all"],
            // The bar chip's revoke argv: shell/punar-shell/Bar/Bar.qml.
            &["punarctl", "privilege", "revoke", "gnt_2b8e11c4"],
            &["punarctl", "secrets", "list"],
            &["punarctl", "secrets", "get", "aws-dev"],
            &["punarctl", "secrets", "get", "github", "--ttl", "5"],
            &["punarctl", "secrets", "validate", "--class", "github"],
            &["punarctl", "secrets", "revoke"],
            &["punarctl", "--socket", "secrets", "debug", "rpc", "status"],
            &["punarctl", "debug", "rpc", "credential.show"],
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

    /// A gate is answered deliberately or not at all: `--decision` is
    /// required and takes exactly the two words the contract defines
    /// (section 14.5). There is no default and no third option.
    #[test]
    fn approvals_resolve_requires_one_of_two_explicit_decisions() {
        for example in [
            ["punarctl", "approvals", "resolve", "apr_1"].as_slice(),
            [
                "punarctl",
                "approvals",
                "resolve",
                "apr_1",
                "--decision",
                "maybe",
            ]
            .as_slice(),
            [
                "punarctl",
                "approvals",
                "resolve",
                "apr_1",
                "--decision",
                "approve",
            ]
            .as_slice(),
            ["punarctl", "approvals", "resolve", "--decision", "approved"].as_slice(),
        ] {
            assert!(Cli::try_parse_from(example.iter()).is_err(), "{example:?}");
        }
    }

    /// **Secrets are never accepted on argv** (contract section 16.4):
    /// `/proc/<pid>/cmdline` is world-readable, so a `--token` flag does
    /// not exist and must never be added. This test is the guard rail —
    /// adding the flag makes it fail.
    #[test]
    fn secrets_verbs_have_no_token_flag() {
        for example in [
            ["punarctl", "secrets", "validate", "--token", "x"].as_slice(),
            [
                "punarctl", "secrets", "validate", "--class", "github", "--token", "x",
            ]
            .as_slice(),
            ["punarctl", "secrets", "revoke", "--token", "x"].as_slice(),
            ["punarctl", "secrets", "revoke", "--value", "x"].as_slice(),
            ["punarctl", "secrets", "get", "aws-dev", "--token", "x"].as_slice(),
            // Nor a --project: the broker has no unforgeable project
            // mediation point, and a requester-supplied one would put
            // forgeable data in a tamper-evident record (section 16.3).
            [
                "punarctl",
                "secrets",
                "get",
                "aws-dev",
                "--project",
                "atlas",
            ]
            .as_slice(),
        ] {
            assert!(Cli::try_parse_from(example.iter()).is_err(), "{example:?}");
        }
    }

    /// `secrets validate` names the class it is checking against; the
    /// value comes from stdin, never from the command line.
    #[test]
    fn secrets_validate_requires_a_class() {
        assert!(Cli::try_parse_from(["punarctl", "secrets", "validate"].iter()).is_err());
    }

    /// Plate D-012: Authorize stays unfilled until a reason exists, and
    /// the capability is named explicitly — one capability per grant, no
    /// wildcard, no `--all` grant.
    #[test]
    fn privilege_request_requires_a_capability_and_a_reason() {
        for example in [
            ["punarctl", "privilege", "request"].as_slice(),
            [
                "punarctl",
                "privilege",
                "request",
                "--capability",
                "time.timezone",
            ]
            .as_slice(),
            ["punarctl", "privilege", "request", "--reason", "why"].as_slice(),
            // Not a capability id — rejected by clap before any IPC.
            [
                "punarctl",
                "privilege",
                "request",
                "--capability",
                "timezone",
                "--reason",
                "w",
            ]
            .as_slice(),
            // There is no wildcard grant.
            ["punarctl", "privilege", "request", "--all", "--reason", "w"].as_slice(),
        ] {
            assert!(Cli::try_parse_from(example.iter()).is_err(), "{example:?}");
        }
    }

    /// SPEC section 48: "Approved for 15 minutes." The default is that
    /// number, in minutes, and it is a policy value rather than a
    /// constant buried in a call site.
    #[test]
    fn privilege_request_defaults_to_fifteen_minutes() {
        let cli = Cli::try_parse_from(
            [
                "punarctl",
                "privilege",
                "request",
                "--capability",
                "time.timezone",
                "--reason",
                "why",
            ]
            .iter(),
        )
        .unwrap();
        match cli.command {
            super::Command::Privilege {
                command: super::PrivilegeCommand::Request { duration, .. },
            } => assert_eq!(duration, 15),
            _ => panic!("parsed into the wrong command"),
        }
    }

    /// One grant or all of them, never both spellings at once.
    #[test]
    fn privilege_revoke_rejects_an_id_and_all_together() {
        assert!(
            Cli::try_parse_from(["punarctl", "privilege", "revoke", "gnt_1", "--all"].iter())
                .is_err()
        );
    }

    /// `approvals wait` is bounded by default — a wait with no ceiling
    /// is a hang, and the ceiling matches the approval TTL (300 s).
    #[test]
    fn approvals_wait_defaults_to_the_approval_ttl() {
        let cli = Cli::try_parse_from(["punarctl", "approvals", "wait", "apr_1"].iter()).unwrap();
        match cli.command {
            super::Command::Approvals {
                command: super::ApprovalsCommand::Wait { timeout, .. },
            } => assert_eq!(timeout, 300),
            _ => panic!("parsed into the wrong command"),
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
