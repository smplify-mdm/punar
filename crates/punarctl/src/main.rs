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

use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::{Duration, Instant};

use clap::{ArgGroup, Parser, Subcommand};
#[cfg(target_os = "linux")]
use punar_common::install::{
    InstallApplyParams, InstallAwaiting, InstallEncryption, InstallOverallState, InstallPlanParams,
    InstallPlanResult, InstallRecoveryAckParams, InstallRecoveryMode, InstallSeedParams,
    InstallStatusResult, InstallTargetsResult,
};
use punar_common::{CapabilityId, Redacted};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::fmt::Style;
use crate::ipc::{CallError, Client, Target};

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

    /// Path to a control socket, or `punard`, `agentd`, `secrets`, or `netd`.
    /// Without this flag each method uses its owning daemon and environment
    /// override (PUNARD_SOCKET / PUNAR_AGENTD_SOCKET /
    /// PUNAR_SECRETS_SOCKET / PUNAR_NETD_SOCKET).
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
    /// Find, inspect, install, open, or remove curated applications.
    App {
        #[command(subcommand)]
        command: AppCommand,
    },
    /// Show whether tracked settings still match, and what was put back.
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
    /// Inspect or apply per-project network policy.
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
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
enum AppCommand {
    /// Search the local signed application catalog.
    Search {
        /// App name, category, or purpose.
        query: String,
    },
    /// Inspect the exact source, trust disclosure, and live permissions.
    Show {
        /// Catalog id, such as `spotify`.
        id: String,
    },
    /// List catalog apps and native installation state.
    List,
    /// Install the pinned native package for this architecture.
    Install {
        /// Catalog id, such as `spotify`.
        id: String,
        /// Skip the interactive confirmation.
        #[arg(long)]
        yes: bool,
        /// Digest from a Command Center card. Hidden because ordinary CLI
        /// use obtains it from the card it prints immediately beforehand.
        #[arg(long, hide = true, value_name = "SHA256")]
        confirm_metadata_sha256: Option<String>,
    },
    /// Open an installed native app, or its curated web-app fallback.
    Open {
        /// Catalog id, such as `spotify`.
        id: String,
        /// Custom URI delivered by the desktop handler. Ordinary users do
        /// not type this; browsers supply it for flows such as OAuth.
        #[arg(value_name = "URI")]
        uris: Vec<String>,
    },
    /// Supervise one native vendor process behind its filtered desktop bus.
    /// This is an implementation detail of `app open`: the public command
    /// returns immediately while this child owns the proxy for the life of
    /// the application.
    #[command(name = "run-vendor", hide = true)]
    RunVendor { id: String },
    /// Remove the native package. Per-user application data is preserved.
    Remove {
        /// Catalog id, such as `spotify`.
        id: String,
        /// Skip the interactive confirmation.
        #[arg(long)]
        yes: bool,
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
    /// The shadow-AI alert register: one card per signature, never per
    /// scan and never per process (milestone-10.md section 5.2).
    Alerts {
        #[command(subcommand)]
        command: Option<AlertsCommand>,
        /// Include cards already filed. Dismissal files, it never
        /// destroys, so they are still here.
        #[arg(long)]
        all: bool,
    },
    /// Force one detection pass now and print the refreshed registry.
    ///
    /// Hidden on purpose: the advertised surface is `list`, `inspect` and
    /// `alerts`, and since M10 the pass runs on a timer by itself
    /// (`punar-agentd-scan.timer`, every 4 minutes). This verb exists so
    /// the timer unit — and anyone debugging detection — can ask for a
    /// pass *now* without a raw `debug rpc`.
    #[command(hide = true)]
    Scan {
        /// What asked for this pass. It travels into the audit event, so
        /// a detection produced by the timer is distinguishable from one
        /// produced by a typed command (milestone-10.md section 3.4).
        /// Absent means `manual` — never an assumed timer.
        #[arg(long, value_parser = ["manual", "timer", "register", "enroll"])]
        trigger: Option<String>,
    },
}

#[derive(Subcommand)]
enum AlertsCommand {
    /// File one card. It is never deleted: the alert stays in the
    /// register with its dismissal time, and suppression does not move.
    Dismiss {
        /// Alert id, like `alr_7c1d9a4e`.
        alert_id: String,
    },
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
    /// Show every question an administrator asked about this device, what
    /// scope it was asked at, and what this device decided (SPEC sections
    /// 24.2, 51.1).
    ///
    /// Readable by any peer the agentd socket admits — withholding the log
    /// of who asked about you *from you* would invert the promise this
    /// command exists to keep. On a personal device it prints one calm
    /// sentence and exits 0: there is no remote-query path here.
    Queries {
        /// Only queries decided at or after this RFC 3339 timestamp.
        #[arg(long, value_name = "RFC3339")]
        since: Option<String>,
    },
    /// Show current network connections and their privacy handling.
    Connections,
}

#[derive(Subcommand)]
enum NetworkCommand {
    /// Show enforcement capability and privacy-observation boundaries.
    Status,
    /// List the closed set of policy zones known to this device.
    Zones,
    /// Show the effective network policy for one active managed project.
    Policy {
        /// Project id from `punarctl agents list`.
        project: String,
    },
    /// Explain one effective project/zone decision and its policy sources.
    Explain {
        /// Project id from `punarctl agents list`.
        project: String,
        /// Zone id from `punarctl network zones`.
        zone: String,
    },
    /// Reconcile active managed sessions into the kernel nftables table.
    Apply {
        /// Optional project citation for the audited apply trigger. The daemon
        /// always reconciles all live sessions atomically.
        project: Option<String>,
    },
}

#[derive(Subcommand)]
enum RelayCommand {
    /// Show the selected route model and whether it is simulated.
    Status,
    /// Select direct routing or the explicitly simulated private-relay model.
    Set {
        #[arg(value_parser = ["direct", "private_relay"])]
        mode: String,
    },
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
    /// Send `method` and print the raw response.
    Rpc {
        method: String,
        /// A JSON object of params, verbatim. Exists so a negative probe
        /// can be *specific* — "this well-formed question was refused" is
        /// a different claim from "a request with no params was rejected"
        /// — and so the in-VM exercise can drive the dev/CI control plane
        /// over `--socket <path>` without a second client binary in the
        /// image (milestone-10.md section 16, groups 7-13).
        #[arg(long, value_name = "JSON")]
        params: Option<String>,
    },
    /// Exercise the attended encrypted installer against the exact disposable
    /// VM target. This command has no caller-controlled disk or secret input,
    /// is live-only, and additionally requires the dedicated CI virtio port.
    #[cfg(target_os = "linux")]
    #[command(name = "installer-apply-proof", hide = true)]
    InstallerApplyProof,
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

fn inspect_app(client: &Client, id: &str) -> Result<Value, CallError> {
    client.call_with_timeout(
        "apps.catalog",
        Some(json!({ "id": id })),
        crate::ipc::APP_INSPECT_TIMEOUT,
    )
}

fn app_install(
    client: &Client,
    style: &Style,
    json_output: bool,
    id: &str,
    yes: bool,
    confirmed: Option<String>,
) -> ExitCode {
    let detail = match inspect_app(client, id) {
        Ok(value) => value,
        Err(error) => return fail(&error),
    };
    let app = match detail.get("app") {
        Some(app) => app,
        None => {
            return fail(&CallError::Protocol {
                why: "apps.catalog returned no app object".to_string(),
            });
        }
    };
    let source = app.get("source").and_then(Value::as_str);
    if !matches!(source, Some("flatpak" | "vendor_deb")) {
        eprintln!(
            "{} has no native package for this architecture. Next step: `punarctl app open {id}` opens its curated web app.",
            app.get("name").and_then(Value::as_str).unwrap_or(id)
        );
        return ExitCode::FAILURE;
    }
    let shown_digest = match source {
        Some("flatpak") => app
            .pointer("/inspection/metadata_sha256")
            .and_then(Value::as_str),
        Some("vendor_deb") => app
            .pointer("/inspection/package_sha256")
            .and_then(Value::as_str),
        _ => None,
    };
    let digest = match (confirmed, shown_digest) {
        (Some(value), Some(shown)) if value == shown => value,
        (Some(_), Some(_)) => {
            eprintln!(
                "The app card is stale: its metadata digest changed. Nothing was installed. Next step: reopen the card and retry."
            );
            return ExitCode::FAILURE;
        }
        (None, Some(value)) => value.to_string(),
        _ => {
            eprintln!(
                "The app source was not verified, so Punar will not install it. Next step: check the Flatpak remote and inspect the app again."
            );
            return ExitCode::FAILURE;
        }
    };

    if !json_output {
        match views::app_detail(style, &detail, &local_hostname()) {
            Ok(card) => print!("{card}"),
            Err(why) => return fail(&CallError::Protocol { why }),
        }
    }
    if !yes && !json_output && std::io::stdin().is_terminal() {
        eprint!("Install this exact verified version? Type yes to continue: ");
        let mut answer = String::new();
        let _ = std::io::stdin().read_line(&mut answer);
        if answer.trim() != "yes" {
            eprintln!("Install aborted — nothing was changed.");
            return ExitCode::FAILURE;
        }
    }
    match client.call_with_timeout(
        "apps.install",
        Some(json!({
            "id": id,
            "confirm_metadata_sha256": digest,
        })),
        crate::ipc::APP_MUTATION_TIMEOUT,
    ) {
        Ok(result) => render_or_json(json_output, &result, |v| {
            views::app_mutation(style, v, &local_hostname(), "installed")
        }),
        Err(error) => fail(&error),
    }
}

fn app_remove(client: &Client, style: &Style, json_output: bool, id: &str, yes: bool) -> ExitCode {
    if !yes && !json_output && std::io::stdin().is_terminal() {
        eprint!("Remove {id}? Type yes to continue: ");
        let mut answer = String::new();
        let _ = std::io::stdin().read_line(&mut answer);
        if answer.trim() != "yes" {
            eprintln!("Removal aborted — nothing was changed.");
            return ExitCode::FAILURE;
        }
    }
    match client.call_with_timeout(
        "apps.remove",
        Some(json!({ "id": id })),
        crate::ipc::APP_MUTATION_TIMEOUT,
    ) {
        Ok(result) => render_or_json(json_output, &result, |v| {
            views::app_mutation(style, v, &local_hostname(), "removed")
        }),
        Err(error) => fail(&error),
    }
}

fn app_open(client: &Client, id: &str, uris: &[String]) -> ExitCode {
    let detail = match inspect_app(client, id) {
        Ok(value) => value,
        Err(error) => return fail(&error),
    };
    let Some(app) = detail.get("app") else {
        return fail(&CallError::Protocol {
            why: "apps.catalog returned no app object".to_string(),
        });
    };
    let mut command = match app.get("source").and_then(Value::as_str) {
        Some("web") => {
            if !uris.is_empty() {
                return fail(&CallError::Protocol {
                    why: "a web-app launcher cannot receive a native callback URI".to_string(),
                });
            }
            let Some(url) = app.get("url").and_then(Value::as_str) else {
                return fail(&CallError::Protocol {
                    why: "the curated web app has no URL".to_string(),
                });
            };
            if app.get("browser").and_then(Value::as_str) != Some("chromium")
                || !url.starts_with("https://")
            {
                return fail(&CallError::Protocol {
                    why: "the curated web-app launch contract is invalid".to_string(),
                });
            }
            let mut command = std::process::Command::new("/usr/bin/chromium");
            command
                .arg(format!("--app={url}"))
                .arg(format!("--class=punar-webapp-{id}"))
                .arg("--ozone-platform-hint=auto");
            command
        }
        Some("flatpak") => {
            if !uris.is_empty() {
                return fail(&CallError::Protocol {
                    why: "Punar does not proxy callback URIs into Flatpak launchers".to_string(),
                });
            }
            if app.get("installed").and_then(Value::as_bool) != Some(true) {
                eprintln!(
                    "{} is not installed. Next step: `punarctl app install {id}`.",
                    app.get("name").and_then(Value::as_str).unwrap_or(id)
                );
                return ExitCode::FAILURE;
            }
            let Some(app_id) = app.get("app_id").and_then(Value::as_str) else {
                return fail(&CallError::Protocol {
                    why: "the curated Flatpak has no application id".to_string(),
                });
            };
            let mut command = std::process::Command::new("/usr/bin/flatpak");
            command.args(["run", "--system", app_id]);
            command
        }
        Some("vendor_deb") => {
            if let Err(why) = spawn_vendor_supervisor(id, uris) {
                eprintln!(
                    "The application could not start.\nWhy: {why}.\nNext step: reinstall it from the application library."
                );
                return ExitCode::FAILURE;
            }
            return ExitCode::SUCCESS;
        }
        _ => {
            return fail(&CallError::Protocol {
                why: "the application source is not supported by this client".to_string(),
            });
        }
    };
    match command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "The application could not start.\nWhy: {error}.\nNext step: inspect it with `punarctl app show {id}`."
            );
            ExitCode::FAILURE
        }
    }
}

fn spawn_vendor_supervisor(id: &str, uris: &[String]) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate the Punar application supervisor: {error}"))?;
    let mut command = vendor_supervisor_command(&executable, id);
    let payload = Zeroizing::new(
        serde_json::to_vec(uris)
            .map_err(|error| format!("could not encode the application callback: {error}"))?,
    );
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("could not start the Punar application supervisor: {error}"))?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| "the application supervisor has no private input channel".to_string())
        .and_then(|mut input| {
            input.write_all(&payload).map_err(|error| {
                format!("could not deliver the application callback privately: {error}")
            })
        });
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    Ok(())
}

fn vendor_supervisor_command(executable: &Path, id: &str) -> std::process::Command {
    let mut command = std::process::Command::new(executable);
    // OAuth callbacks travel through the anonymous stdin pipe below. Keeping
    // them out of this long-lived process's argv prevents disclosure through
    // /proc/$pid/cmdline while the application remains open.
    command.args(["app", "run-vendor", id]);
    command
}

fn app_run_vendor(client: &Client, id: &str) -> ExitCode {
    let uris = match read_vendor_supervisor_uris() {
        Ok(value) => value,
        Err(why) => {
            eprintln!("punarctl: vendor application supervisor: {why}");
            return ExitCode::FAILURE;
        }
    };
    let detail = match inspect_app(client, id) {
        Ok(value) => value,
        Err(error) => return fail(&error),
    };
    let Some(app) = detail.get("app") else {
        return fail(&CallError::Protocol {
            why: "apps.catalog returned no app object".to_string(),
        });
    };
    if app.get("source").and_then(Value::as_str) != Some("vendor_deb") {
        return fail(&CallError::Protocol {
            why: "the private supervisor accepts only verified vendor applications".to_string(),
        });
    }
    match supervise_vendor_app(app, id, &uris) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("punarctl: vendor application supervisor: {why}");
            ExitCode::FAILURE
        }
    }
}

const VENDOR_SUPERVISOR_PAYLOAD_LIMIT: u64 = 8 * 8192 + 1024;

fn read_vendor_supervisor_uris() -> Result<Zeroizing<Vec<String>>, String> {
    let mut payload = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(VENDOR_SUPERVISOR_PAYLOAD_LIMIT + 1)
        .read_to_end(&mut payload)
        .map_err(|error| format!("could not read the private application callback: {error}"))?;
    if payload.len() as u64 > VENDOR_SUPERVISOR_PAYLOAD_LIMIT {
        return Err("the private application callback is oversized".to_string());
    }
    let uris = serde_json::from_slice::<Vec<String>>(&payload)
        .map_err(|_| "the private application callback is malformed".to_string())?;
    Ok(Zeroizing::new(uris))
}

fn vendor_app_command(
    app: &Value,
    id: &str,
    uris: &[String],
    filtered_bus: &Path,
) -> Result<std::process::Command, String> {
    if app.get("installed").and_then(Value::as_bool) != Some(true) {
        return Err(format!(
            "{} is not installed",
            app.get("name").and_then(Value::as_str).unwrap_or(id)
        ));
    }
    if id.is_empty()
        || id.len() > 64
        || !id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || (index > 0 && byte == b'-')
        })
    {
        return Err("the catalog id is unsafe".to_string());
    }
    let executable = app
        .get("launch_executable")
        .and_then(Value::as_str)
        .ok_or_else(|| "the verified native package has no launcher".to_string())?;
    let app_root = PathBuf::from(format!("/var/lib/punar-apps/{id}/current"));
    let executable_path = Path::new(executable);
    if !executable_path.is_absolute()
        || !executable_path.starts_with(app_root.join("usr/lib"))
        || !executable_path.is_file()
    {
        return Err("the installed launcher path is outside its application payload".to_string());
    }
    let relative_executable = executable_path
        .strip_prefix(&app_root)
        .map_err(|_| "the installed launcher path is invalid".to_string())?;
    let sandbox_executable = Path::new("/app").join(relative_executable);
    let callback_uris = validated_vendor_callback_uris(app, uris)?;

    let host_home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "HOME is not an absolute path".to_string())?;
    let app_home = host_home
        .join(".local/share/punar-apps")
        .join(id)
        .join("home");
    for relative in [".config", ".cache", ".local/share", "Downloads"] {
        std::fs::create_dir_all(app_home.join(relative))
            .map_err(|error| format!("could not prepare the isolated app home: {error}"))?;
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| valid_runtime_dir(path))
        .ok_or_else(|| "the desktop runtime directory is unavailable".to_string())?;
    // Electron forwards a deep link to the already-running instance through
    // its process-singleton socket. Chromium commonly places that socket in
    // /tmp, so a fresh private tmpfs for every invocation strands OAuth
    // callbacks in the second process. Share one *app-specific, session-only*
    // directory across invocations instead: it lives below /run/user, is
    // removed at logout, and remains invisible to every other vendor app.
    let app_runtime_tmp = vendor_runtime_tmp(&runtime, id);
    std::fs::create_dir_all(&app_runtime_tmp)
        .map_err(|error| format!("could not prepare the isolated app runtime: {error}"))?;
    std::fs::set_permissions(&app_runtime_tmp, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not protect the isolated app runtime: {error}"))?;
    let wayland_display = std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-0".into());
    if wayland_display.is_empty()
        || !wayland_display
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("the Wayland display name is unsafe".to_string());
    }

    let mut command = std::process::Command::new("/usr/bin/bwrap");
    command.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/bin",
        "/bin",
        "--ro-bind-try",
        "/sbin",
        "/sbin",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind",
        "/etc",
        "/etc",
        "--ro-bind",
        "/sys",
        "/sys",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--dir",
        "/run",
        "--dir",
        "/run/user",
    ]);
    append_vendor_open_bridge(&mut command);
    append_resolver_mount(&mut command, Path::new("/run/systemd/resolve"));
    command
        .arg("--bind")
        .arg(&app_runtime_tmp)
        .arg("/tmp")
        .arg("--dir")
        .arg("/home")
        .arg("--bind")
        .arg(&app_home)
        .arg("/home/punar")
        .arg("--ro-bind")
        .arg(&app_root)
        .arg("/app")
        .args([
            "--setenv",
            "HOME",
            "/home/punar",
            "--setenv",
            "XDG_CONFIG_HOME",
            "/home/punar/.config",
            "--setenv",
            "XDG_CACHE_HOME",
            "/home/punar/.cache",
            "--setenv",
            "XDG_DATA_HOME",
            "/home/punar/.local/share",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "XDG_SESSION_TYPE",
            "wayland",
            "--setenv",
            "XDG_CURRENT_DESKTOP",
            "Hyprland",
            "--setenv",
            "QT_QPA_PLATFORM",
            "wayland",
        ])
        .arg("--setenv")
        .arg("XDG_RUNTIME_DIR")
        .arg(&runtime)
        .arg("--setenv")
        .arg("WAYLAND_DISPLAY")
        .arg(&wayland_display);
    command.arg("--dir").arg(&runtime);
    let runtime_paths = [
        runtime.join(&wayland_display),
        runtime.join("pulse"),
        runtime.join("pipewire-0"),
        runtime.join("pipewire-0-manager"),
    ];
    for path in runtime_paths.iter().filter(|path| path.exists()) {
        command.arg("--bind").arg(path).arg(path);
    }
    append_filtered_session_bus_mount(&mut command, filtered_bus);
    for key in ["LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(key) {
            command.arg("--setenv").arg(key).arg(value);
        }
    }
    if let Ok(entries) = std::fs::read_dir("/dev/dri") {
        command.args(["--dir", "/dev/dri"]);
        for path in entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("renderD"))
            })
        {
            command.arg("--dev-bind").arg(&path).arg(&path);
        }
    }
    command
        .arg("--chdir")
        .arg("/home/punar")
        .arg("--")
        .arg(sandbox_executable)
        .arg("--no-sandbox");
    command.args(callback_uris);
    Ok(command)
}

fn append_vendor_open_bridge(command: &mut std::process::Command) {
    command.args([
        "--ro-bind",
        "/usr/lib/punar/vendor-sandbox-bin/xdg-open",
        "/usr/bin/xdg-open",
    ]);
}

fn append_filtered_session_bus_mount(command: &mut std::process::Command, filtered_bus: &Path) {
    const SANDBOX_BUS: &str = "/run/punar-session-bus";
    command
        .arg("--bind")
        .arg(filtered_bus)
        .arg(SANDBOX_BUS)
        .arg("--setenv")
        .arg("DBUS_SESSION_BUS_ADDRESS")
        .arg(format!("unix:path={SANDBOX_BUS}"));
}

fn filtered_bus_proxy_command(
    real_bus: &Path,
    filtered_bus: &Path,
    ready_fd: i32,
) -> std::process::Command {
    let mut command = std::process::Command::new("/usr/bin/xdg-dbus-proxy");
    command
        .arg(format!("--fd={ready_fd}"))
        .arg(format!("unix:path={}", real_bus.display()))
        .arg(filtered_bus)
        .args([
            "--filter",
            "--call=org.freedesktop.portal.*=*",
            "--broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*",
            "--talk=org.freedesktop.Notifications",
        ]);
    command
}

/// Keep the real user bus outside the vendor mount namespace. A filtered
/// xdg-dbus-proxy exposes only the freedesktop desktop portal and notification
/// service: binding `/run/user/$UID/bus` directly would also expose the user
/// systemd manager and turn a nominal application sandbox into an execution
/// trampoline back onto the host.
#[cfg(target_os = "linux")]
fn supervise_vendor_app(app: &Value, id: &str, uris: &[String]) -> Result<(), String> {
    use std::os::unix::fs::FileTypeExt;

    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| valid_runtime_dir(path))
        .ok_or_else(|| "the desktop runtime directory is unavailable".to_string())?;
    let real_bus = runtime.join("bus");
    let bus_metadata = std::fs::symlink_metadata(&real_bus)
        .map_err(|error| format!("the desktop session bus is unavailable: {error}"))?;
    if !bus_metadata.file_type().is_socket() {
        return Err("the desktop session bus is not a direct Unix socket".to_string());
    }

    let app_runtime = runtime.join("punar-apps").join(id);
    std::fs::create_dir_all(&app_runtime)
        .map_err(|error| format!("could not prepare the isolated app runtime: {error}"))?;
    std::fs::set_permissions(&app_runtime, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not protect the isolated app runtime: {error}"))?;
    let filtered_bus = app_runtime.join(format!("bus-{}", std::process::id()));
    if std::fs::symlink_metadata(&filtered_bus).is_ok() {
        return Err("the private desktop bus path already exists".to_string());
    }

    let (mut ready_reader, ready_writer) = UnixStream::pair()
        .map_err(|error| format!("could not create the desktop-bus readiness channel: {error}"))?;
    // std creates both descriptors close-on-exec. Only the proxy endpoint is
    // inherited by the one child that consumes --fd; the supervisor endpoint
    // cannot leak into either the proxy or the vendor application.
    rustix::io::fcntl_setfd(ready_writer.as_fd(), rustix::io::FdFlags::empty())
        .map_err(|error| format!("could not pass the desktop-bus readiness channel: {error}"))?;
    let ready_fd = ready_writer.as_raw_fd();
    let mut proxy = filtered_bus_proxy_command(&real_bus, &filtered_bus, ready_fd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("could not start the filtered desktop bus: {error}"))?;
    drop(ready_writer);

    let outcome = (|| {
        ready_reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| format!("could not bound the desktop-bus startup wait: {error}"))?;
        let mut ready = [0_u8; 1];
        ready_reader
            .read_exact(&mut ready)
            .map_err(|error| format!("the filtered desktop bus did not become ready: {error}"))?;
        if ready != *b"x" {
            return Err("the filtered desktop bus returned an invalid readiness marker".into());
        }
        let metadata = std::fs::symlink_metadata(&filtered_bus)
            .map_err(|error| format!("the filtered desktop bus socket is missing: {error}"))?;
        if !metadata.file_type().is_socket() {
            return Err("the filtered desktop bus path is not a Unix socket".into());
        }

        let mut command = vendor_app_command(app, id, uris, &filtered_bus)?;
        let status = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("could not enter the application sandbox: {error}"))?;
        if !status.success() {
            return Err(format!("the isolated application exited with {status}"));
        }
        Ok(())
    })();

    // Closing the peer of xdg-dbus-proxy's --fd channel is its explicit
    // lifetime signal. Bound the reap too: a broken proxy cannot leave a
    // resident process behind after the application closes.
    drop(ready_reader);
    for _ in 0..100 {
        match proxy.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => break,
        }
    }
    if proxy.try_wait().ok().flatten().is_none() {
        let _ = proxy.kill();
        let _ = proxy.wait();
    }
    let _ = std::fs::remove_file(&filtered_bus);
    outcome
}

#[cfg(not(target_os = "linux"))]
fn supervise_vendor_app(_app: &Value, _id: &str, _uris: &[String]) -> Result<(), String> {
    Err("verified vendor applications are available only on Linux".to_string())
}

fn vendor_runtime_tmp(runtime: &Path, id: &str) -> PathBuf {
    runtime.join("punar-apps").join(id).join("tmp")
}

/// Accept only custom schemes declared by the signed catalog record. The URI
/// is passed as one argv item after bwrap's `--` separator; it is never a
/// shell string, daemon request, log field, or environment variable because
/// OAuth callbacks can contain credentials.
fn validated_vendor_callback_uris<'a>(
    app: &Value,
    uris: &'a [String],
) -> Result<Vec<&'a str>, String> {
    if uris.len() > 8 {
        return Err("too many callback URIs were supplied".to_string());
    }
    let allowed: Vec<&str> = app
        .get("uri_schemes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut validated = Vec::with_capacity(uris.len());
    for uri in uris {
        if uri.is_empty() || uri.len() > 8192 || uri.chars().any(char::is_control) {
            return Err("the callback URI is empty, oversized, or contains controls".to_string());
        }
        let (scheme, rest) = uri
            .split_once(':')
            .ok_or_else(|| "the callback is not an absolute URI".to_string())?;
        if rest.is_empty()
            || !allowed
                .iter()
                .any(|candidate| scheme.eq_ignore_ascii_case(candidate))
        {
            return Err("the callback URI scheme is not owned by this catalog app".to_string());
        }
        validated.push(uri.as_str());
    }
    Ok(validated)
}

/// Keep the app's network view useful without exposing the host runtime tree.
/// systemd-resolved makes `/etc/resolv.conf` a symlink into this directory;
/// the otherwise-empty sandbox `/run` would leave that link dangling and make
/// every hostname lookup fail. Only the resolver directory is shared, and it
/// is mounted read-only.
fn append_resolver_mount(command: &mut std::process::Command, resolver_dir: &Path) {
    if resolver_dir.is_dir() {
        command
            .args(["--dir", "/run/systemd"])
            .arg("--ro-bind")
            .arg(resolver_dir)
            .arg("/run/systemd/resolve");
    }
}

fn valid_runtime_dir(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    let Some(uid) = value.strip_prefix("/run/user/") else {
        return false;
    };
    !uid.is_empty() && uid.bytes().all(|byte| byte.is_ascii_digit()) && path.is_dir()
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
fn privacy_ledger_json(
    list: &Value,
    accesses: &[(String, Value)],
    queries: Option<&Value>,
) -> Value {
    let ledgers: Vec<Value> = accesses
        .iter()
        .map(|(id, access)| json!({"session_id": id, "access": access}))
        .collect();
    // M10: the `remote_query` block was `{"available": false, "milestone":
    // "M10"}` in M8, by design and with the milestone named. It now carries
    // the live log — or, when the daemon could not answer, says exactly
    // that. "Not read" and "none" are different, and a consumer must be
    // able to tell them apart.
    let remote_query = match queries {
        Some(queries) => json!({
            "available": true,
            "log": queries,
            "command": "punarctl privacy queries",
        }),
        None => json!({
            "available": true,
            "log": Value::Null,
            "read": false,
            "reason": "punar-agentd did not answer queries.list",
            "command": "punarctl privacy queries",
        }),
    };
    json!({
        "source": "punarctl privacy ledger (composed locally from agents.list + agents.access)",
        "registry": list,
        "ledgers": ledgers,
        "readable": ledgers.len(),
        "storage_path": "/var/lib/punar/agents/ledger",
        "local_only": true,
        "remote_query": remote_query,
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

#[cfg(target_os = "linux")]
const INSTALL_APPLY_PROOF_PORT: &str = "/dev/virtio-ports/punar.install-apply-proof";
#[cfg(target_os = "linux")]
const INSTALL_APPLY_PROOF_SERIAL: &str = "PUNAR-CI-TARGET";
#[cfg(target_os = "linux")]
const INSTALL_APPLY_PROOF_BYTES: u64 = 128 * 1024 * 1024 * 1024;
#[cfg(target_os = "linux")]
const INSTALL_APPLY_PROOF_PASSPHRASE: &[u8] = b"punar-ci-only-vm-passphrase";

#[cfg(target_os = "linux")]
fn sealed_install_proof_memfd(name: &str, value: &[u8]) -> Result<std::fs::File, String> {
    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};

    let owned = memfd_create(name, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
        .map_err(|error| format!("could not allocate sealed anonymous memory ({error})"))?;
    let mut file = std::fs::File::from(owned);
    file.write_all(value)
        .map_err(|error| format!("could not populate sealed anonymous memory ({error})"))?;
    fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )
    .map_err(|error| format!("could not seal anonymous memory ({error})"))?;
    Ok(file)
}

/// Resolve the two challenged recovery groups without ever returning the
/// complete recovery key or placing a group in a diagnostic string.
#[cfg(target_os = "linux")]
fn install_proof_recovery_confirmation(
    recovery_key: &str,
    challenge: &str,
) -> Result<Zeroizing<String>, String> {
    let groups = recovery_key.trim().split('-').collect::<Vec<_>>();
    if groups.len() != 8 || groups.iter().any(|group| group.is_empty()) {
        return Err("the recovery disclosure did not contain eight groups".into());
    }
    let positions = challenge
        .split_ascii_whitespace()
        .map(str::parse::<usize>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "the recovery disclosure challenge was malformed".to_string())?;
    if positions.len() != 2
        || positions[0] == positions[1]
        || positions.iter().any(|position| !(1..=8).contains(position))
    {
        return Err("the recovery disclosure challenge was out of bounds".into());
    }
    Ok(Zeroizing::new(format!(
        "{} {}",
        groups[positions[0] - 1],
        groups[positions[1] - 1]
    )))
}

#[cfg(target_os = "linux")]
fn join_installer_apply_proof(
    apply: std::thread::JoinHandle<Result<Value, CallError>>,
) -> Result<Value, String> {
    apply
        .join()
        .map_err(|_| "the installer apply client thread terminated unexpectedly".to_string())?
        .map_err(|error| error.message())
}

/// Read one line from the private recovery socket while keeping the VM proof
/// observable. Only the public phase/state vocabulary is emitted; recovery
/// material, descriptor numbers, disk paths and failure details never become
/// progress output. If install.apply exits first, join it immediately so the
/// daemon's exact typed failure is surfaced instead of being hidden behind a
/// long socket timeout.
#[cfg(target_os = "linux")]
fn read_installer_proof_disclosure_line(
    disclosure: &mut BufReader<UnixStream>,
    line: &mut String,
    description: &str,
    client: &Client,
    apply: &mut Option<std::thread::JoinHandle<Result<Value, CallError>>>,
    deadline: Instant,
    last_progress: &mut Option<String>,
) -> Result<(), String> {
    loop {
        match disclosure.read_line(line) {
            Ok(0) => {
                if apply.as_ref().is_some_and(|handle| handle.is_finished()) {
                    let result = join_installer_apply_proof(
                        apply.take().expect("the finished apply handle is present"),
                    );
                    return match result {
                        Err(error) => Err(error),
                        Ok(_) => Err(format!(
                            "install.apply ended before {description} was disclosed"
                        )),
                    };
                }
                return Err(format!(
                    "the recovery disclosure channel closed before {description}"
                ));
            }
            Ok(_) => return Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                if apply.as_ref().is_some_and(|handle| handle.is_finished()) {
                    let result = join_installer_apply_proof(
                        apply.take().expect("the finished apply handle is present"),
                    );
                    return match result {
                        Err(error) => Err(error),
                        Ok(_) => Err(format!(
                            "install.apply ended before {description} was disclosed"
                        )),
                    };
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "install.apply did not disclose {description} within 25 minutes"
                    ));
                }

                let status: InstallStatusResult = serde_json::from_value(
                    client
                        .call("install.status", None)
                        .map_err(|error| error.message())?,
                )
                .map_err(|error| format!("install.status returned an invalid result ({error})"))?;
                if status.state == InstallOverallState::Failed {
                    let failure = status
                        .failure
                        .as_ref()
                        .map(|failure| failure.message.as_str())
                        .unwrap_or("the daemon did not publish a failure reason");
                    return Err(format!(
                        "install.apply failed before {description}: {failure}"
                    ));
                }
                let marker = format!(
                    "PUNAR_INSTALL_APPLY_PROGRESS phase={} state={}",
                    status
                        .phase
                        .map(|phase| format!("{phase:?}").to_ascii_lowercase())
                        .unwrap_or_else(|| "none".into()),
                    format!("{:?}", status.state).to_ascii_lowercase()
                );
                if last_progress.as_deref() != Some(marker.as_str()) {
                    let mut stdout = std::io::stdout().lock();
                    writeln!(stdout, "{marker}")
                        .and_then(|()| stdout.flush())
                        .map_err(|error| {
                            format!("could not publish installer progress ({error})")
                        })?;
                    *last_progress = Some(marker);
                }
            }
            Err(error) => {
                return Err(format!(
                    "could not read {description} from the recovery disclosure ({error})"
                ));
            }
        }
    }
}

/// The destructive VM gate deliberately has no caller-controlled disk,
/// passphrase or recovery material. It can run only as root in the live image
/// while QEMU presents the named proof port; the daemon still revalidates the
/// disk identity and consumes the secrets through its production descriptor
/// boundary.
#[cfg(target_os = "linux")]
fn run_installer_apply_proof(socket: Option<&Path>) -> Result<String, String> {
    use std::os::unix::fs::FileTypeExt;

    if rustix::process::getuid().as_raw() != 0 {
        return Err("the installer apply proof must run as root".into());
    }
    let port = Path::new(INSTALL_APPLY_PROOF_PORT);
    let metadata = port
        .metadata()
        .map_err(|_| "the dedicated installer apply proof port is absent".to_string())?;
    if !metadata.file_type().is_char_device() {
        return Err("the installer apply proof endpoint is not a character device".into());
    }
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .map_err(|error| format!("could not read the live kernel command line ({error})"))?;
    if !cmdline
        .split_ascii_whitespace()
        .any(|token| token == "punar.live=1")
    {
        return Err("the installer apply proof is available only in the live environment".into());
    }

    let client = Client::for_target(Target::Punard, socket);
    let mut target_result = None;
    for attempt in 0..120 {
        match client.call("install.targets", None) {
            Ok(result) => {
                target_result = Some(result);
                break;
            }
            Err(CallError::Unreachable { .. }) if attempt != 119 => {
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(error) => return Err(error.message()),
        }
    }
    let targets: InstallTargetsResult = serde_json::from_value(
        target_result
            .ok_or_else(|| "punard did not become reachable within 30 seconds".to_string())?,
    )
    .map_err(|error| format!("install.targets returned an invalid result ({error})"))?;
    let [target] = targets.targets.as_slice() else {
        return Err("the apply proof requires exactly one eligible disposable target".into());
    };
    if target.serial.as_deref() != Some(INSTALL_APPLY_PROOF_SERIAL)
        || target.size_bytes != INSTALL_APPLY_PROOF_BYTES
        || !target.eligible
        || !target.partitions.is_empty()
    {
        return Err("the only target is not the exact blank CI disk".into());
    }

    let plan_params = InstallPlanParams {
        disk: target.device.clone(),
        keymap: "us".into(),
        encryption: InstallEncryption::Luks2,
        recovery_mode: InstallRecoveryMode::PersonalCopy,
    };
    let plan: InstallPlanResult = serde_json::from_value(
        client
            .call(
                "install.plan",
                Some(serde_json::to_value(&plan_params).map_err(|error| error.to_string())?),
            )
            .map_err(|error| error.message())?,
    )
    .map_err(|error| format!("install.plan returned an invalid result ({error})"))?;
    if plan.plan.disk.device != target.device
        || plan.plan.disk.serial != INSTALL_APPLY_PROOF_SERIAL
        || plan.plan.encryption != InstallEncryption::Luks2
        || plan.plan.recovery_mode != InstallRecoveryMode::PersonalCopy
    {
        return Err("the confirmed plan is not bound to the encrypted CI target".into());
    }

    let passphrase = sealed_install_proof_memfd(
        "punar-installer-ci-passphrase",
        INSTALL_APPLY_PROOF_PASSPHRASE,
    )?;
    let (recovery_writer, recovery_reader) = UnixStream::pair()
        .map_err(|error| format!("could not create the recovery disclosure channel ({error})"))?;
    recovery_reader
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|error| format!("could not bound the recovery disclosure wait ({error})"))?;

    let apply_params = InstallApplyParams {
        plan_token: plan.plan_token.clone(),
        disk: target.device.clone(),
        passphrase_fd: Some(
            u32::try_from(passphrase.as_raw_fd())
                .map_err(|_| "the passphrase descriptor was out of range".to_string())?,
        ),
        recovery_output_fd: Some(
            u32::try_from(recovery_writer.as_raw_fd())
                .map_err(|_| "the recovery descriptor was out of range".to_string())?,
        ),
        keymap: "us".into(),
        seed: InstallSeedParams {
            locale: "C.UTF-8".into(),
        },
        oobe_answers_fd: None,
        unattended: false,
    };
    let apply_value = serde_json::to_value(&apply_params).map_err(|error| error.to_string())?;
    let apply_socket = socket.map(Path::to_path_buf);
    let mut apply = Some(std::thread::spawn(move || {
        // These owners must live for exactly as long as the daemon call may
        // duplicate their descriptors. Moving the recovery writer here also
        // guarantees EOF at the reader if install.apply returns early.
        let _passphrase_guard = passphrase;
        let _recovery_writer_guard = recovery_writer;
        let apply_client = Client::for_target(Target::Punard, apply_socket.as_deref());
        apply_client.call_with_timeout(
            "install.apply",
            Some(apply_value),
            Duration::from_secs(60 * 60),
        )
    }));

    let mut disclosure = BufReader::new(recovery_reader);
    let mut header = String::new();
    let mut recovery_key = Zeroizing::new(String::new());
    let mut challenge = String::new();
    let disclosure_deadline = Instant::now() + Duration::from_secs(25 * 60);
    let mut last_progress = None;
    read_installer_proof_disclosure_line(
        &mut disclosure,
        &mut header,
        "the recovery protocol header",
        &client,
        &mut apply,
        disclosure_deadline,
        &mut last_progress,
    )?;
    read_installer_proof_disclosure_line(
        &mut disclosure,
        &mut recovery_key,
        "the recovery key",
        &client,
        &mut apply,
        disclosure_deadline,
        &mut last_progress,
    )?;
    read_installer_proof_disclosure_line(
        &mut disclosure,
        &mut challenge,
        "the recovery challenge",
        &client,
        &mut apply,
        disclosure_deadline,
        &mut last_progress,
    )?;
    if header.trim_end() != "PUNAR-RECOVERY-V1" {
        return Err("the recovery disclosure protocol version was invalid".into());
    }
    let confirmation = install_proof_recovery_confirmation(&recovery_key, &challenge)?;

    let mut awaiting = false;
    for _ in 0..100 {
        let status: InstallStatusResult = serde_json::from_value(
            client
                .call("install.status", None)
                .map_err(|error| error.message())?,
        )
        .map_err(|error| format!("install.status returned an invalid result ({error})"))?;
        if status.state == InstallOverallState::Awaiting
            && status.awaiting == Some(InstallAwaiting::RecoveryKeyAck)
        {
            awaiting = true;
            break;
        }
        if status.state == InstallOverallState::Failed {
            return Err("the installation failed before recovery acknowledgement".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !awaiting {
        return Err("the installer did not publish its recovery acknowledgement gate".into());
    }

    let groups = sealed_install_proof_memfd(
        "punar-installer-ci-recovery-confirmation",
        confirmation.as_bytes(),
    )?;
    let ack = InstallRecoveryAckParams {
        plan_token: plan.plan_token.clone(),
        groups_fd: u32::try_from(groups.as_raw_fd())
            .map_err(|_| "the recovery confirmation descriptor was out of range".to_string())?,
    };
    client
        .call(
            "install.recovery_ack",
            Some(serde_json::to_value(ack).map_err(|error| error.to_string())?),
        )
        .map_err(|error| error.message())?;

    let result = join_installer_apply_proof(
        apply
            .take()
            .ok_or_else(|| "the installer apply client thread ended too early".to_string())?,
    )?;
    let status: InstallStatusResult = serde_json::from_value(result)
        .map_err(|error| format!("install.apply returned an invalid status ({error})"))?;
    if status.state != InstallOverallState::Succeeded
        || status.plan_token.as_deref() != Some(plan.plan_token.as_str())
        || status.disk.as_deref() != Some(target.device.as_str())
    {
        return Err("install.apply did not finish with the confirmed disk and plan".into());
    }
    Ok(plan.plan_token)
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
        Command::App { command } => match command {
            AppCommand::Search { query } => {
                let hostname = local_hostname();
                match client.call_with_timeout(
                    "apps.catalog",
                    Some(json!({ "query": query })),
                    crate::ipc::APP_INSPECT_TIMEOUT,
                ) {
                    Ok(result) => {
                        render_or_json(json, &result, |v| views::apps(&style, v, &hostname))
                    }
                    Err(error) => fail(&error),
                }
            }
            AppCommand::Show { id } => {
                let hostname = local_hostname();
                match inspect_app(&client, &id) {
                    Ok(result) => {
                        render_or_json(json, &result, |v| views::app_detail(&style, v, &hostname))
                    }
                    Err(error) => fail(&error),
                }
            }
            AppCommand::List => {
                let hostname = local_hostname();
                rpc(&client, json, "apps.list", None, |v| {
                    views::apps(&style, v, &hostname)
                })
            }
            AppCommand::Install {
                id,
                yes,
                confirm_metadata_sha256,
            } => app_install(&client, &style, json, &id, yes, confirm_metadata_sha256),
            AppCommand::Open { id, uris } => app_open(&client, &id, &uris),
            AppCommand::RunVendor { id } => app_run_vendor(&client, &id),
            AppCommand::Remove { id, yes } => app_remove(&client, &style, json, &id, yes),
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
            DebugCommand::Rpc { method, params } => {
                // The probe follows the same routing as the real verbs, so
                // a negative probe reaches the daemon that owns the name
                // (contract section 10.5) — `--socket agentd` forces it.
                let probe = Client::for_target(Target::of_method(&method), socket.as_deref());
                let params = match params.as_deref().map(serde_json::from_str::<Value>) {
                    None => None,
                    Some(Ok(value)) => Some(value),
                    Some(Err(why)) => {
                        // Refused here rather than sent as a string: a
                        // daemon answering `invalid_params` to a typo in
                        // the probe would look like a daemon refusing the
                        // method, and a probe that lies about which thing
                        // said no is worse than no probe.
                        eprintln!("punarctl: --params is not valid JSON: {why}");
                        return ExitCode::from(2);
                    }
                };
                match probe.call(&method, params) {
                    Ok(result) => {
                        println!("{result}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => fail(&error),
                }
            }
            #[cfg(target_os = "linux")]
            DebugCommand::InstallerApplyProof => match run_installer_apply_proof(socket.as_deref())
            {
                Ok(plan_token) => {
                    println!("PUNAR_INSTALL_APPLY_OK plan_token={plan_token}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    // This hidden command's stdout is the VM proof protocol;
                    // send both terminal states to the dedicated virtio port.
                    println!("PUNAR_INSTALL_APPLY_FAIL {error}");
                    ExitCode::FAILURE
                }
            },
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
        // Real since 2026-08-26: it renders the block `status` already
        // returns. It used to print "not implemented until Milestone 5 (mock
        // Smplify enrollment)" to stderr and exit non-zero — a nag naming a
        // product the person may never want, for a reading the daemon was
        // already computing and already showing under `status`. The verb is a
        // SPEC section 11.2 example and command_surface_parses asserts every
        // section 11.2 example parses, so it is made real, not deleted.
        Command::Compliance => match client.call("status", None) {
            Ok(result) => render_or_json(json, &result, |v| views::compliance(&style, v)),
            Err(error) => fail(&error),
        },
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
                            // M10 closed M8's open question: a detection has
                            // a persisted record and a bounded ledger
                            // (milestone-10.md section 6), so the follow-up
                            // runs for detections too. The register that
                            // comes back is strictly smaller than a managed
                            // one, and says why for every empty category.
                            let ledger = Some(
                                agents
                                    .call("agents.access", Some(json!({ "session_id": id })))
                                    .map_err(|error| error.message()),
                            );
                            let ledger = ledger.as_ref().map(|r| r.as_ref().map_err(String::clone));
                            views::agent_inspect(&style, v, ledger)
                        }),
                        Err(error) => fail(&error),
                    }
                }
                AgentsCommand::Scan { trigger } => {
                    let hostname = local_hostname();
                    // Absent means `manual`, and the daemon decides that,
                    // not this process: a CLI that filled in a default
                    // trigger could label a typed command as a timer.
                    let params = trigger.map(|t| json!({ "trigger": t }));
                    rpc(&agents, json, "agents.scan", params, |v| {
                        views::agents_list(&style, v, &hostname)
                    })
                }
                AgentsCommand::Alerts { command, all } => match command {
                    Some(AlertsCommand::Dismiss { alert_id }) => rpc(
                        &agents,
                        json,
                        "alerts.dismiss",
                        Some(json!({ "alert_id": alert_id })),
                        |v| views::agent_alert_dismissed(&style, v),
                    ),
                    None => {
                        let hostname = local_hostname();
                        rpc(
                            &agents,
                            json,
                            "alerts.list",
                            Some(json!({ "include_dismissed": all })),
                            |v| views::agents_alerts(&style, v, &hostname),
                        )
                    }
                },
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
                                // M10: the `REMOTE QUERY` footer line M8
                                // wrote as a placeholder goes live. Best
                                // effort — a daemon that cannot answer
                                // `queries.list` leaves the row on its
                                // honest static sentence rather than on a
                                // fabricated zero.
                                let queries = agents.call("queries.list", None).ok();
                                if json {
                                    print_json(&privacy_ledger_json(
                                        &list,
                                        &accesses,
                                        queries.as_ref(),
                                    ))
                                } else {
                                    match views::privacy_ledger(
                                        &style,
                                        &list,
                                        &accesses,
                                        &hostname,
                                        queries.as_ref(),
                                    ) {
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
                PrivacyCommand::Queries { since } => {
                    let hostname = local_hostname();
                    let params = since.as_ref().map(|since| json!({ "since": since }));
                    rpc(&agents, json, "queries.list", params, |v| {
                        views::privacy_queries(&style, v, &hostname)
                    })
                }
                PrivacyCommand::Connections => {
                    let netd = Client::for_target(Target::Netd, socket.as_deref());
                    let hostname = local_hostname();
                    rpc(&netd, json, "network.connections", None, |v| {
                        views::privacy_connections(&style, v, &hostname)
                    })
                }
            }
        }
        Command::Network { command } => {
            let netd = Client::for_target(Target::Netd, socket.as_deref());
            let hostname = local_hostname();
            match command {
                NetworkCommand::Status => rpc(&netd, json, "network.status", None, |v| {
                    views::network_status(&style, v, &hostname)
                }),
                NetworkCommand::Zones => rpc(&netd, json, "network.zones", None, |v| {
                    views::network_zones(&style, v, &hostname)
                }),
                NetworkCommand::Policy { project } => rpc(
                    &netd,
                    json,
                    "network.policy",
                    Some(json!({"project": project})),
                    |v| views::network_policy(&style, v, &hostname),
                ),
                NetworkCommand::Explain { project, zone } => rpc(
                    &netd,
                    json,
                    "network.explain",
                    Some(json!({"project": project, "zone": zone})),
                    |v| views::network_explain(&style, v, &hostname),
                ),
                NetworkCommand::Apply { project } => {
                    let params = project.map(|project| json!({"project": project}));
                    rpc(&netd, json, "network.apply", params, |v| {
                        views::network_apply(&style, v, &hostname)
                    })
                }
            }
        }
        Command::Relay { command } => {
            let netd = Client::for_target(Target::Netd, socket.as_deref());
            let hostname = local_hostname();
            match command {
                RelayCommand::Status => rpc(&netd, json, "relay.status", None, |v| {
                    views::relay_status(&style, v, &hostname)
                }),
                RelayCommand::Set { mode } => {
                    rpc(&netd, json, "relay.set", Some(json!({"mode": mode})), |v| {
                        views::relay_status(&style, v, &hostname)
                    })
                }
            }
        }
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
    use std::ffi::OsStr;
    use std::path::Path;

    use clap::{CommandFactory, Parser};

    #[cfg(target_os = "linux")]
    use super::install_proof_recovery_confirmation;
    use super::{
        Cli, append_filtered_session_bus_mount, append_resolver_mount, append_vendor_open_bridge,
        filtered_bus_proxy_command, validated_vendor_callback_uris, vendor_runtime_tmp,
        vendor_supervisor_command,
    };
    use serde_json::json;

    #[test]
    fn vendor_sandbox_mounts_system_resolver_read_only() {
        // `/` is a portable, existing directory; the helper's destination is
        // fixed, so this verifies the exact bwrap shape without assuming the
        // test host itself runs systemd-resolved.
        let mut command = std::process::Command::new("/usr/bin/bwrap");
        append_resolver_mount(&mut command, Path::new("/"));
        let args: Vec<&OsStr> = command.get_args().collect();

        assert_eq!(
            args,
            [
                OsStr::new("--dir"),
                OsStr::new("/run/systemd"),
                OsStr::new("--ro-bind"),
                OsStr::new("/"),
                OsStr::new("/run/systemd/resolve"),
            ]
        );
    }

    #[test]
    fn vendor_sandbox_uses_the_portal_bridge_and_not_the_real_user_bus() {
        let mut command = std::process::Command::new("/usr/bin/bwrap");
        append_vendor_open_bridge(&mut command);
        append_filtered_session_bus_mount(&mut command, Path::new("/run/private/bus"));
        let args: Vec<&OsStr> = command.get_args().collect();
        assert_eq!(
            args,
            [
                OsStr::new("--ro-bind"),
                OsStr::new("/usr/lib/punar/vendor-sandbox-bin/xdg-open"),
                OsStr::new("/usr/bin/xdg-open"),
                OsStr::new("--bind"),
                OsStr::new("/run/private/bus"),
                OsStr::new("/run/punar-session-bus"),
                OsStr::new("--setenv"),
                OsStr::new("DBUS_SESSION_BUS_ADDRESS"),
                OsStr::new("unix:path=/run/punar-session-bus"),
            ]
        );
    }

    #[test]
    fn vendor_bus_proxy_admits_portals_without_the_user_service_manager() {
        let command = filtered_bus_proxy_command(
            Path::new("/run/user/1000/bus"),
            Path::new("/run/private/bus"),
            17,
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();
        assert!(args.iter().any(|arg| arg == "--filter"));
        assert!(
            args.iter()
                .any(|arg| arg == "--call=org.freedesktop.portal.*=*")
        );
        assert!(
            args.iter()
                .all(|arg| !arg.contains("org.freedesktop.systemd1"))
        );
    }

    #[test]
    fn vendor_supervisor_argv_never_carries_an_oauth_callback() {
        let command = vendor_supervisor_command(Path::new("/usr/bin/punarctl"), "claude-desktop");
        let args: Vec<&OsStr> = command.get_args().collect();
        assert_eq!(
            args,
            [
                OsStr::new("app"),
                OsStr::new("run-vendor"),
                OsStr::new("claude-desktop"),
            ]
        );
    }

    #[test]
    fn vendor_callback_accepts_only_the_signed_catalog_scheme() {
        let app = json!({"uri_schemes": ["claude"]});
        let good = vec!["claude://claude.ai/auth/callback?code=redacted&state=opaque".to_string()];
        assert_eq!(
            validated_vendor_callback_uris(&app, &good).unwrap(),
            [good[0].as_str()]
        );

        for rejected in [
            "https://claude.ai/auth/callback",
            "file:///etc/passwd",
            "claude:",
            "claude://callback\nsecond-argument",
        ] {
            assert!(
                validated_vendor_callback_uris(&app, &[rejected.to_string()]).is_err(),
                "accepted unsafe callback {rejected:?}"
            );
        }
        assert!(validated_vendor_callback_uris(&json!({"uri_schemes": []}), &good).is_err());
    }

    #[test]
    fn vendor_runtime_tmp_is_stable_per_app_and_separate_between_apps() {
        let runtime = Path::new("/run/user/1000");
        let first = vendor_runtime_tmp(runtime, "claude-desktop");
        let second = vendor_runtime_tmp(runtime, "claude-desktop");
        let other = vendor_runtime_tmp(runtime, "slack");
        assert_eq!(
            first,
            Path::new("/run/user/1000/punar-apps/claude-desktop/tmp")
        );
        assert_eq!(
            first, second,
            "a callback launch must see the first instance runtime"
        );
        assert_ne!(first, other, "vendor apps must not share temporary state");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installer_proof_selects_only_the_challenged_recovery_groups() {
        let selected = install_proof_recovery_confirmation(
            "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH\n",
            "2 7\n",
        )
        .unwrap();
        assert_eq!(selected.as_str(), "BBBB GGGG");

        for invalid in ["2 2", "0 7", "2 9", "two seven", "2"] {
            assert!(
                install_proof_recovery_confirmation(
                    "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH",
                    invalid,
                )
                .is_err(),
                "accepted invalid challenge {invalid:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installer_apply_proof_accepts_no_caller_controlled_target_or_secret() {
        assert!(Cli::try_parse_from(["punarctl", "debug", "installer-apply-proof"]).is_ok());
        for forbidden in [
            ["punarctl", "debug", "installer-apply-proof", "/dev/vda"],
            ["punarctl", "debug", "installer-apply-proof", "--passphrase"],
        ] {
            assert!(Cli::try_parse_from(forbidden).is_err());
        }
    }

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
            &["punarctl", "app", "search", "spotify"],
            &["punarctl", "app", "show", "spotify"],
            &["punarctl", "app", "list"],
            &["punarctl", "app", "install", "spotify"],
            &["punarctl", "app", "install", "spotify", "--yes"],
            &[
                "punarctl",
                "app",
                "install",
                "spotify",
                "--confirm-metadata-sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ],
            &["punarctl", "app", "open", "spotify"],
            &[
                "punarctl",
                "app",
                "open",
                "claude-desktop",
                "claude://claude.ai/auth/callback?code=redacted&state=opaque",
            ],
            &["punarctl", "app", "run-vendor", "claude-desktop"],
            &["punarctl", "app", "remove", "spotify", "--yes"],
            &["punarctl", "capabilities"],
            &["punarctl", "compliance"],
            &["punarctl", "policy", "effective"],
            &["punarctl", "policy", "explain", "security.firewall"],
            &["punarctl", "agents", "list"],
            &["punarctl", "agents", "scan"],
            &["punarctl", "agents", "inspect", "agt_123"],
            &["punarctl", "agents", "access", "agt_123"],
            &["punarctl", "privacy", "connections"],
            &["punarctl", "privacy", "queries"],
            &["punarctl", "--json", "privacy", "queries"],
            &[
                "punarctl",
                "privacy",
                "queries",
                "--since",
                "2026-08-25T00:00:00Z",
            ],
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
