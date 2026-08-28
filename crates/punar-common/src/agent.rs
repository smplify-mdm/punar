//! Typed wire contract for the `punar-agentd` socket (`agents.*`) and the
//! AI Agent Registry record types shared by `punar-agentd`, `punar-env`,
//! and `punarctl`.
//!
//! Binding contracts: `docs/api/ipc.md` sections 10–11 (the sibling-socket
//! wire contract and the `/run/punar/agents.json` side contract),
//! `schemas/ai-agent/registry-record.json` (the ten-field record — every
//! persisted registry line conforms exactly), and
//! `docs/development/milestone-7.md`. Spec authorities: sections 18–19
//! (registry + classifications), 22 (attribution), 23 (shadow AI —
//! *suspected*, never certain), 60/61 (closed method table, local IPC
//! security).
//!
//! # Section 60 again, on the second socket
//!
//! [`AgentMethod`] is a **closed** enum, exactly like
//! [`crate::ipc::Method`]: five M7 methods, the two M8 ledger methods and
//! the two M10 alert methods, no variant that carries a command line or
//! program. "Closed" means *exhaustively dispatched and reviewed*, not
//! *frozen*: a milestone may add a typed method, and adding one fails to
//! compile until every dispatch table names it — which is the section 60
//! review point. What will never be added is a variant that carries
//! something executable.
//!
//! `admin.*` and `ledger.export`/`ledger.query` (which do **not** exist —
//! there is no upload path at all) stay **reserved**: they answer
//! [`ErrorCode::UnknownMethod`], said honestly in the error prose.
//!
//! # Layering
//!
//! Envelope, framing, error codes, and timeouts are `punar-common::ipc`,
//! verbatim (`docs/api/ipc.md` section 10.1). This module adds only the
//! agentd method table and the typed params/results — the same split
//! `ipc::Method` has for punard.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ipc::{ErrorCode, IpcError, RequestEnvelope, RequestReject, parse_envelope_line};

// ---------------------------------------------------------------------------
// Contract paths and constants (docs/api/ipc.md sections 10.1, 11)
// ---------------------------------------------------------------------------

/// The agentd control socket (docs/api/ipc.md section 10.1). Lives in the
/// root-owned `/run/punar-agentd` for the same impostor argument as
/// section 1.1; `0660 root:punar`.
pub const AGENTD_SOCKET_PATH: &str = "/run/punar-agentd/agentd.sock";

/// Append-only registry persistence, one schema-exact
/// `registry-record.json` line per lifecycle transition
/// (`0640 root:root`; milestone-7.md section 4.1).
pub const REGISTRY_JSONL_PATH: &str = "/var/lib/punar/agents/registry.jsonl";

/// The world-readable AI-panel summary file (docs/api/ipc.md section 11)
/// — display data only, the `status.json` pattern.
pub const AGENTS_SUMMARY_PATH: &str = "/run/punar/agents.json";

/// Staged adapter definitions (`agent-definition.json`-valid documents;
/// milestone-7.md section 5.4).
pub const ADAPTERS_DIR: &str = "/usr/share/punar/agents/adapters";

/// Suspected-signature heuristic input (milestone-7.md section 7.1).
pub const SUSPECTED_SIGNATURES_PATH: &str = "/usr/share/punar/agents/signatures/suspected.json";

/// `agents.list` triggers a detection pass first when the last pass is
/// older than this (docs/api/ipc.md section 10.2 — on-demand freshness;
/// **no timers**, spec section 6.3).
pub const SCAN_STALE_AFTER_SECS: u64 = 30;

/// Version field of `/run/punar/agents.json` (section 11).
pub const AGENTS_SUMMARY_VERSION: u32 = 1;

// -- Milestone 10 (docs/api/ipc.md sections 17, 20; milestone-10.md) --------

/// The local shadow-AI **alert** state file (milestone-10.md section 5.3;
/// proposed `docs/api/ipc.md` section 20).
///
/// `0640 root:punar` in the **root-owned** `/run/punar-agentd`, never in
/// the world-readable `/run/punar`: a forged card reading *"Unknown AI
/// activity suspected · your-bank-helper"* with an `Inspect` action is a
/// phishing primitive, and M9 already moved `approvals.json` out of
/// `/run/punar` for exactly this reason. Display data whose authority is
/// the socket; consumers fail closed (missing or unparsable ⇒ **no**
/// alert, never a placeholder alert).
pub const ALERTS_RUNTIME_PATH: &str = "/run/punar-agentd/alerts.json";

/// Version field of `/run/punar-agentd/alerts.json`.
pub const ALERTS_FILE_VERSION: u32 = 1;

/// Append-only detection persistence: one schema-exact
/// `registry-record.json` line per detection **state change**
/// (`0600 root:root`; milestone-10.md section 6.4). This is the file that
/// closes M8's open question — a detected unmanaged process now has a
/// persisted record, and therefore a ledger.
pub const DETECTIONS_JSONL_PATH: &str = "/var/lib/punar/agents/detections.jsonl";

/// The sibling index for everything `registry-record.json` cannot hold
/// (`signature_id`, the matched signature name, the executable path, the
/// zone class, `cleared_at`). Third application of the M8 Decision-0 law:
/// a shipped schema never grows a property to suit a later milestone.
pub const DETECTIONS_INDEX_PATH: &str = "/var/lib/punar/agents/detections-index.json";

/// The periodic detection cadence (`punar-agentd-scan.timer`), stated on
/// every surface that claims continuous detection: an exact multiple of
/// the 120 s reconcile timer so systemd **coalesces** the two wakeups
/// (milestone-10.md decision 2).
pub const SCAN_PERIOD_SECS: u64 = 240;

/// How long an alert stays suppressed after its last live detection
/// clears (milestone-10.md section 5.2). A crash-looping agent yields one
/// alert a day; a genuinely new appearance next week yields a fresh one.
pub const ALERT_QUIET_WINDOW_SECS: u64 = 24 * 60 * 60;

/// How many alert records are retained (live, cleared and filed together)
/// before the oldest **non-live** one is evicted. Dismissal files rather
/// than destroys (D-009 Sect I register 03), so the register has to be
/// bounded somewhere; a live alert is never evicted.
pub const MAX_RETAINED_ALERTS: usize = 64;

/// What asked for a detection pass (milestone-10.md section 3.4). It
/// travels into the `agents.scan` audit event's `resource` field so a
/// check can prove a detection came from the **timer** and not from a
/// command a check script typed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanTrigger {
    /// A human ran `punarctl agents scan` (the default: an unlabelled
    /// request is a typed one, never a claimed timer).
    #[default]
    Manual,
    /// `punar-agentd-scan.timer` → `punarctl agents scan --trigger timer`.
    Timer,
    /// A managed session registered, or a session was reaped.
    Register,
    /// An enrollment transition completed (punard → agentd).
    Enroll,
}

impl ScanTrigger {
    pub const ALL: [ScanTrigger; 4] = [
        ScanTrigger::Manual,
        ScanTrigger::Timer,
        ScanTrigger::Register,
        ScanTrigger::Enroll,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ScanTrigger::Manual => "manual",
            ScanTrigger::Timer => "timer",
            ScanTrigger::Register => "register",
            ScanTrigger::Enroll => "enroll",
        }
    }
}

impl std::fmt::Display for ScanTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `agents.scan` params. Optional on the wire — M7 sent none, and an
/// absent `trigger` is [`ScanTrigger::Manual`], never an assumed timer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentsScanParams {
    #[serde(default)]
    pub trigger: ScanTrigger,
}

/// Display state of one alert card (milestone-10.md sections 5.2, 5.4).
///
/// `dismissed` is a **display** state, not a suppression state: filing a
/// card never changes what will or will not be raised, because a
/// signature was never going to be raised twice anyway. That is why M10
/// has no snooze, no per-alert mute and no user-facing suppression
/// setting to explain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    /// At least one detection of this signature is live and the card
    /// stands.
    Live,
    /// The last live detection cleared; the 24 h quiet window is running.
    Cleared,
    /// The user filed the card. It stays in the register and in the
    /// detection record — dismissal never destroys.
    Dismissed,
}

impl AlertState {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertState::Live => "live",
            AlertState::Cleared => "cleared",
            AlertState::Dismissed => "dismissed",
        }
    }
}

/// One alert as `/run/punar-agentd/alerts.json` carries it — **exactly**
/// the milestone-10.md section 5.3 field list and nothing else.
///
/// What is absent is the contract: no pid, no cgroup path, no `comm`, no
/// command line, no argv, no environment, no hash of anything secret. The
/// one path present is the single matched executable — the datum D-009's
/// card is built around, and one the same user can already print with
/// `punarctl agents list`. Spec 24.2 is the rule: the card may not tell
/// the user *less* than they can already read, and it may not carry more
/// than the surface it mirrors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRow {
    /// `alr_`-prefixed, stable for the life of this alert.
    pub alert_id: String,
    /// The **anti-nag key** — `sig_` + 12 hex (milestone-10.md 4.2).
    pub signature_id: String,
    pub agent: String,
    /// The matched executable path.
    pub executable: String,
    pub owner: String,
    pub first_seen: String,
    /// Last sighting **as of the last alert-set change**. Liveness is
    /// in-memory state served by `alerts.list`; the file is a change log,
    /// exactly as `agents.json`'s `scanned_at` is (milestone-10.md 3.4).
    pub last_seen: String,
    /// How many live detections currently carry this signature.
    pub live: u64,
    /// The most recent `detection_id` of this signature.
    pub detection_id: String,
    /// The matched signature's **name** (`unmanaged-path-agentlike`), the
    /// reviewable rule in the data file — not the `sig_` identity above.
    pub signature: String,
    /// `personal-defaults`, or the org policy id when enrolled.
    pub policy_citation: String,
    pub state: AlertState,
}

/// The whole `/run/punar-agentd/alerts.json` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertsFile {
    pub v: u32,
    pub updated_at: String,
    pub alerts: Vec<AlertRow>,
}

/// One alert as the **socket** returns it: the file's row plus the
/// lifecycle timestamps the display file has no reason to carry. The
/// socket is the authority; the file is display data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListedAlert {
    #[serde(flatten)]
    pub row: AlertRow,
    pub raised_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dismissed_at: Option<String>,
    /// When the anti-nag window expires and a fresh sighting of this
    /// signature would raise a new card. Absent while the alert is live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet_until: Option<String>,
}

/// `alerts.list` params.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertsListParams {
    /// Filed cards are listed too when asked for — "I clicked it away and
    /// now I cannot find it" has an answer (milestone-10.md 5.4).
    #[serde(default)]
    pub include_dismissed: bool,
}

/// `alerts.list` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertsListResult {
    pub alerts: Vec<ListedAlert>,
    /// The anti-nag window, so a renderer states the rule rather than
    /// hard-coding it.
    pub quiet_window_secs: u64,
}

/// `alerts.dismiss` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertsDismissParams {
    pub alert_id: String,
}

/// `alerts.dismiss` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertsDismissResult {
    pub dismissed: bool,
    pub alert_id: String,
    pub dismissed_at: String,
    /// Always `false` in M10 and stated on the surface: filing a card
    /// changes nothing about what will be raised.
    pub suppression_changed: bool,
}

/// Whether a string is a well-formed alert id (`^alr_[a-f0-9]{12}$`).
pub fn alert_id_ok(value: &str) -> bool {
    value
        .strip_prefix("alr_")
        .is_some_and(|rest| rest.len() == 12 && rest.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Whether a string is a well-formed signature identity
/// (`^sig_[a-f0-9]{12}$`, milestone-10.md section 4.2).
pub fn signature_identity_ok(value: &str) -> bool {
    value
        .strip_prefix("sig_")
        .is_some_and(|rest| rest.len() == 12 && rest.chars().all(|c| c.is_ascii_hexdigit()))
}

// ---------------------------------------------------------------------------
// Registry record (schemas/ai-agent/registry-record.json — exact)
// ---------------------------------------------------------------------------

/// Session lifecycle status. The shipped schema listed only `active` and
/// pre-authorized the additive widening in its own description
/// ("additional lifecycle values (e.g. for ended sessions) will be added
/// additively to this enum"); M7 adds `ended` (milestone-7.md section
/// 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Active,
    Ended,
}

impl AgentStatus {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            AgentStatus::Active => "active",
            AgentStatus::Ended => "ended",
        }
    }
}

/// Registry classification (spec section 19.1;
/// `schemas/common/defs.json#/$defs/agent_classification`): `managed` is
/// *proven* by the launch scope cgroup, `observed` is a known agent
/// outside the managed runtime, `unknown` covers the spec's UNKNOWN /
/// SUSPECTED class — every rendering of `unknown` says *suspected*, never
/// certain (spec section 23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentClassification {
    Managed,
    Observed,
    Unknown,
}

impl AgentClassification {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            AgentClassification::Managed => "managed",
            AgentClassification::Observed => "observed",
            AgentClassification::Unknown => "unknown",
        }
    }
}

/// One AI agent session — exactly the ten fields of
/// `schemas/ai-agent/registry-record.json`, in schema order. Strict on
/// deserialize: a registry line with extra fields is a broken line, not a
/// lenient read (the persistence file is ours alone).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryRecord {
    /// `agt_`-prefixed session id (spec sections 19.2, 22).
    pub session_id: String,
    /// Agent product name, e.g. `claude-code`.
    pub agent: String,
    /// Free-form agent version (`"mock"` for the CI stand-in, `"unknown"`
    /// when no version could be probed).
    pub version: String,
    /// OS pid of the session's root process.
    pub process_id: u32,
    /// The human who started the agent — stamped by the daemon from peer
    /// credentials, never trusted from params (ipc.md section 10.2).
    pub user: String,
    /// Project the session belongs to (`"unknown"` sentinel for
    /// detections; milestone-7.md section 4.4).
    pub project: String,
    /// Environment instance (`punar-env-<project>` when the M6 container
    /// runs, else the `"host"` sentinel).
    pub environment: String,
    pub status: AgentStatus,
    pub classification: AgentClassification,
    /// RFC 3339, daemon-stamped.
    pub started_at: String,
}

/// `^agt_[A-Za-z0-9]+$` — the `common/defs.json` `agent_session_id`
/// pattern (also what `agents.register` asserts, ipc.md section 10.2).
pub fn session_id_ok(id: &str) -> bool {
    id.strip_prefix("agt_")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Schema pattern for the `agent` field:
/// `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`.
pub fn agent_name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    let inner_ok =
        |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-');
    let edge_ok = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    match b {
        [] => false,
        [only] => edge_ok(only),
        [first, mid @ .., last] => edge_ok(first) && edge_ok(last) && mid.iter().all(inner_ok),
    }
}

/// Longest `AuthoritySummary` string this daemon will store, and the
/// largest number of rows. Generous for a display block, far too small to
/// be a payload.
pub const AUTHORITY_FIELD_MAX_BYTES: usize = 128;
/// Row cap for [`validate_authority_summary`].
pub const AUTHORITY_MAX_ROWS: usize = 32;

/// Validate the authority block a launcher hands to `agents.register`.
///
/// # Why a display block needs a validator
///
/// [`AuthoritySummary`] is not derived by this daemon. It is supplied by
/// the caller of `agents.register` — a peer that only has to own the
/// process it is registering and either be inside its own agent scope or
/// match a known-agent signature, both of which an unprivileged local
/// process can arrange. Through M7-M9 that was tolerable: the block was
/// display data, rendered to the person whose machine it described.
///
/// Milestone 10 changed what it is. The `authority` query scope exports
/// these rows **off the device**, to an administrator who is told they are
/// reading "the org's own policy, read back" (milestone-10.md section
/// 8.1). Unvalidated, the three strings are a channel through which a
/// local unprivileged process chooses what its organization believes: it
/// can spell an `enforcement` of `enforced` over something merely
/// declared, and it can carry a file path, a prompt or a terminal escape
/// out through a surface documented as carrying zone classes and decision
/// words.
///
/// This function closes the second half — bounded, single-line, printable,
/// the M9 `approval::validate_reason` rule. It cannot close the first
/// half, because nothing on this device measures the rows; that is why
/// the export labels them `declared by the local launcher · not verified
/// by this device`, exactly as the requesting admin's identity is labelled
/// (milestone-10.md section 9.1). Spec 1.22: an administrator must not be
/// told something is verified when it is asserted.
pub fn validate_authority_summary(authority: &AuthoritySummary) -> Result<(), Vec<String>> {
    fn check(violations: &mut Vec<String>, name: &str, value: &str) {
        if value.trim().is_empty() {
            violations.push(format!("{name} must not be blank"));
        } else if value.len() > AUTHORITY_FIELD_MAX_BYTES {
            violations.push(format!(
                "{name} must be at most {AUTHORITY_FIELD_MAX_BYTES} bytes; this one is {}",
                value.len()
            ));
        } else if let Some(c) = value.chars().find(|c| c.is_control()) {
            violations.push(format!(
                "{name} must be a single line of printable text; found {c:?}"
            ));
        }
    }

    let mut violations = Vec::new();
    check(
        &mut violations,
        "policy_citation",
        &authority.policy_citation,
    );
    if authority.rows.len() > AUTHORITY_MAX_ROWS {
        violations.push(format!(
            "authority.rows must hold at most {AUTHORITY_MAX_ROWS} rows; this one holds {}",
            authority.rows.len()
        ));
    }
    for (index, row) in authority.rows.iter().enumerate() {
        check(
            &mut violations,
            &format!("authority.rows[{index}].zone"),
            &row.zone,
        );
        check(
            &mut violations,
            &format!("authority.rows[{index}].decision"),
            &row.decision,
        );
        check(
            &mut violations,
            &format!("authority.rows[{index}].enforcement"),
            &row.enforcement,
        );
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// The honesty label the `authority` query scope carries beside the rows
/// [`validate_authority_summary`] guards (milestone-10.md section 9.1's
/// discipline, applied to the other asserted identity in the answer).
pub const AUTHORITY_SOURCE_LABEL: &str =
    "declared by the local launcher · not verified by this device";

/// Validate a record against the registry-record schema contract (the
/// Rust-side mirror, the [`crate::audit::validate_event_schema`] pattern):
/// pattern-checked ids/names, non-empty strings, RFC 3339 shape. Enum
/// fields are schema-valid by type. Returns every violation found.
/// Persistence refuses records that fail this — a non-conformant line can
/// never reach `registry.jsonl`.
pub fn validate_registry_record(record: &RegistryRecord) -> Result<(), Vec<String>> {
    let mut violations = Vec::new();
    if !session_id_ok(&record.session_id) {
        violations.push(format!(
            "session_id {:?} must match ^agt_[A-Za-z0-9]+$",
            record.session_id
        ));
    }
    if !agent_name_ok(&record.agent) {
        violations.push(format!(
            "agent {:?} must match ^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$",
            record.agent
        ));
    }
    if record.version.is_empty() {
        violations.push("version must be non-empty".to_string());
    }
    if record.process_id == 0 {
        violations.push("process_id must be >= 1".to_string());
    }
    if record.user.is_empty() {
        violations.push("user must be non-empty".to_string());
    }
    if record.project.is_empty() {
        violations.push("project must be non-empty".to_string());
    }
    if record.environment.is_empty() {
        violations.push("environment must be non-empty".to_string());
    }
    if !crate::time::is_rfc3339_timestamp(&record.started_at) {
        violations.push(format!(
            "started_at {:?} must be RFC 3339 (schema pattern)",
            record.started_at
        ));
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

// ---------------------------------------------------------------------------
// Authority display summary (ipc.md section 10.3 — display-level in M7)
// ---------------------------------------------------------------------------

/// One authority row as displayed at launch: a zone, a spec-section-20
/// decision word, and the enforcement label. All display strings — M7
/// authority is **display-level only** and every rendering carries its
/// `declared · M9/M12` label (spec section 1.22); enforcement arrives in
/// M9 (credentials/approvals) and M12 (network).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRow {
    /// E.g. `filesystem.project`, `network.internet`.
    pub zone: String,
    /// Spec section 20 decision word (`read_write`, `allow`, …) as
    /// displayed.
    pub decision: String,
    /// The honesty label, e.g. `declared · M9`.
    pub enforcement: String,
}

/// The authority summary the launcher displayed (spec section 27 step 10),
/// carried to agentd so the panel and `punarctl agents inspect` render the
/// same block. Stored in memory and `agents.json` only — never in
/// `registry.jsonl` (the record schema is exact).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySummary {
    /// `"personal-defaults"` on an unenrolled device, the org policy id
    /// (hero demo: `"eng-ai-v3"`) while enrolled — sourced from
    /// `/run/punar/status.json` (ipc.md section 10.3).
    pub policy_citation: String,
    #[serde(default)]
    pub rows: Vec<AuthorityRow>,
}

// ---------------------------------------------------------------------------
// Method params (ipc.md section 10.2; strict — unknown params rejected)
// ---------------------------------------------------------------------------

/// `agents.get` params.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentsGetParams {
    pub session_id: String,
}

/// `agents.end` params.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentsEndParams {
    pub session_id: String,
}

/// `agents.register` params — the facts the launcher owns. `user`,
/// `started_at`, and `classification` are **absent by design**: the
/// daemon stamps the first two from peer credentials and computes the
/// third from the cgroup (ipc.md section 10.2 — attribution is checked,
/// never trusted from params).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentsRegisterParams {
    pub session_id: String,
    pub agent: String,
    pub version: String,
    pub process_id: u32,
    pub project: String,
    pub environment: String,
    pub authority: AuthoritySummary,
}

/// `agents.access` params — the M8 AI Access Ledger read
/// (docs/api/ipc.md section 12.2). Authorization is **owner or root**:
/// a ledger is personal data about one user's session, which is stricter
/// than `agents.list` and is the local half of spec section 24.1's "RBAC
/// applies".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentsAccessParams {
    pub session_id: String,
}

/// `ledger.purge` params (docs/api/ipc.md section 12.3): **exactly one**
/// of `session_id` or `all`. Neither, or both, is `invalid_params` —
/// deleting data is never inferred from an ambiguous request.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerPurgeParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<bool>,
}

impl LedgerPurgeParams {
    /// The scope the params name, or `None` when they name neither or
    /// both.
    pub fn scope(&self) -> Option<PurgeScope> {
        match (self.session_id.as_deref(), self.all) {
            (Some(id), None | Some(false)) if !id.is_empty() => {
                Some(PurgeScope::Session(id.to_string()))
            }
            (None, Some(true)) => Some(PurgeScope::CallersOwn),
            _ => None,
        }
    }
}

/// What a purge covers. `CallersOwn` scopes to the **calling uid's** own
/// sessions for a non-root peer, and to every session for root
/// (docs/api/ipc.md section 12.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurgeScope {
    Session(String),
    CallersOwn,
}

// ---------------------------------------------------------------------------
// The closed agentd method table
// ---------------------------------------------------------------------------

/// The complete M7 `punar-agentd` method surface (ipc.md section 10.2) —
/// closed, like [`crate::ipc::Method`]: no `#[non_exhaustive]`,
/// exhaustive dispatch, no variant carrying anything executable.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentMethod {
    /// `agents.list` — sessions this boot + current detections; may
    /// trigger a staleness-gated scan first.
    List,
    /// `agents.get` — one session/detection by id.
    Get(AgentsGetParams),
    /// `agents.register` — the managed-launch registration (peer-cred +
    /// cgroup verified server-side).
    Register(Box<AgentsRegisterParams>),
    /// `agents.end` — owner/root marks a session ended.
    End(AgentsEndParams),
    /// `agents.scan` — force one detection pass now. M10 carries the
    /// **trigger** into the audit event so a detection produced by the
    /// timer is distinguishable from one produced by a typed command
    /// (milestone-10.md section 3.4).
    Scan(AgentsScanParams),
    /// `alerts.list` — the shadow-AI alert register (M10, spec sections
    /// 12.1, 73). Readable by any peer the socket admitted: withholding
    /// it from the user would violate spec 24.2, since from M10 onward an
    /// authorized administrator can query the same fact.
    AlertsList(AlertsListParams),
    /// `alerts.dismiss` — file one card. Owner of the detection, or
    /// root. It **never** deletes and never changes suppression.
    AlertsDismiss(AlertsDismissParams),
    /// `agents.access` — the AI Access Ledger for one session (M8, spec
    /// section 21). Owner or root; drains the audit tail and samples the
    /// scope cgroup first so a read never shows a stale answer.
    Access(AgentsAccessParams),
    /// `ledger.purge` — the user deletes their own ledger (M8, spec
    /// section 24.2). Owner or root, always audited, and it does **not**
    /// touch the audit trail.
    Purge(LedgerPurgeParams),
    /// `query.answer` — one administrator question the device **fetched**
    /// (M10, spec sections 24.1, 51). **Root peer only**: the only caller
    /// is `punard`, the courier. The data owner re-evaluates
    /// authorization from local state and never from the request, and a
    /// refusal comes back as a *successful result* carrying
    /// `authorization_decision: "deny"` — never an error frame, because a
    /// courier that receives an error has no decision to relay.
    QueryAnswer(Box<crate::query::PendingQuery>),
    /// `queries.list` — the local record of every question an
    /// administrator asked about this device. Readable by **any admitted
    /// peer**: withholding it from the user would violate spec 24.2.
    QueriesList(crate::query::QueriesListParams),
}

/// Reserved method-name prefixes/names that deserve a *specific* honest
/// `unknown_method` answer (ipc.md section 10.2): the M8 ledger read and
/// the M10 admin surface.
const RESERVED_ADMIN_PREFIX: &str = "admin.";
/// `ledger.export` / `ledger.query` are not "not yet" — there is **no**
/// upload or remote-query path in M8 at all (spec section 24; the
/// authorized administrator query is Milestone 10).
const RESERVED_LEDGER_PREFIX: &str = "ledger.";

impl AgentMethod {
    /// All wire method names, contract-table order.
    pub const NAMES: [&'static str; 11] = [
        "agents.list",
        "agents.get",
        "agents.register",
        "agents.end",
        "agents.scan",
        "agents.access",
        "ledger.purge",
        "alerts.list",
        "alerts.dismiss",
        "query.answer",
        "queries.list",
    ];

    /// The wire method name.
    pub fn name(&self) -> &'static str {
        // Exhaustive: adding a variant fails to compile until every
        // dispatch table names it (the section 60 review point).
        match self {
            AgentMethod::List => "agents.list",
            AgentMethod::Get(_) => "agents.get",
            AgentMethod::Register(_) => "agents.register",
            AgentMethod::End(_) => "agents.end",
            AgentMethod::Scan(_) => "agents.scan",
            AgentMethod::Access(_) => "agents.access",
            AgentMethod::Purge(_) => "ledger.purge",
            AgentMethod::AlertsList(_) => "alerts.list",
            AgentMethod::AlertsDismiss(_) => "alerts.dismiss",
            AgentMethod::QueryAnswer(_) => "query.answer",
            AgentMethod::QueriesList(_) => "queries.list",
        }
    }

    /// The `params` value for the wire envelope.
    pub fn params_value(&self) -> Option<Value> {
        let params = match self {
            AgentMethod::List => return None,
            AgentMethod::Scan(p) => serde_json::to_value(p),
            AgentMethod::Get(p) => serde_json::to_value(p),
            AgentMethod::Register(p) => serde_json::to_value(p),
            AgentMethod::End(p) => serde_json::to_value(p),
            AgentMethod::Access(p) => serde_json::to_value(p),
            AgentMethod::Purge(p) => serde_json::to_value(p),
            AgentMethod::AlertsList(p) => serde_json::to_value(p),
            AgentMethod::AlertsDismiss(p) => serde_json::to_value(p),
            AgentMethod::QueryAnswer(p) => serde_json::to_value(p),
            AgentMethod::QueriesList(p) => serde_json::to_value(p),
        };
        Some(params.expect("params structs serialize infallibly"))
    }

    /// Lift a wire method name + params into a typed [`AgentMethod`].
    ///
    /// Errors: [`ErrorCode::UnknownMethod`] for names outside the table —
    /// with reserved-name honesty for `agents.access` (M8) and `admin.*`
    /// (M10) — and [`ErrorCode::InvalidParams`] for missing/extra/
    /// mis-shaped params.
    pub fn from_wire(method: &str, params: Option<Value>) -> Result<AgentMethod, IpcError> {
        match method {
            "agents.list" => Self::expect_no_params(method, params).map(|()| AgentMethod::List),
            // M7 sent `agents.scan` with no params and still may: an
            // absent `trigger` is `manual`, never an assumed timer.
            "agents.scan" => Self::parse_optional_params(method, params).map(AgentMethod::Scan),
            "alerts.list" => {
                Self::parse_optional_params(method, params).map(AgentMethod::AlertsList)
            }
            "alerts.dismiss" => {
                Self::parse_required_params(method, params).map(AgentMethod::AlertsDismiss)
            }
            "agents.get" => Self::parse_required_params(method, params).map(AgentMethod::Get),
            "agents.end" => Self::parse_required_params(method, params).map(AgentMethod::End),
            "agents.register" => Self::parse_required_params(method, params)
                .map(|p| AgentMethod::Register(Box::new(p))),
            "agents.access" => Self::parse_required_params(method, params).map(AgentMethod::Access),
            // The question is required and strict: an administrator query
            // with a missing or mis-shaped field is refused as invalid,
            // never answered best-effort.
            "query.answer" => Self::parse_required_params(method, params)
                .map(|p| AgentMethod::QueryAnswer(Box::new(p))),
            // The user's own log: no params needed to read your own
            // record of who asked about you.
            "queries.list" => {
                Self::parse_optional_params(method, params).map(AgentMethod::QueriesList)
            }
            "ledger.purge" => {
                let parsed: LedgerPurgeParams = Self::parse_required_params(method, params)?;
                if parsed.scope().is_none() {
                    return Err(Self::invalid_params(
                        method,
                        "name exactly one of session_id or all:true — deleting data is \
                         never inferred from an ambiguous request",
                    ));
                }
                Ok(AgentMethod::Purge(parsed))
            }
            unknown if unknown.starts_with(RESERVED_LEDGER_PREFIX) => Err(IpcError::with_details(
                ErrorCode::UnknownMethod,
                format!(
                    "The method {unknown:?} does not exist. The AI Access Ledger stays on \
                     this device: there is no export method and no upload path, by design \
                     (spec section 24). Since Milestone 10 one thing can leave — the \
                     answer to a question the device itself FETCHED, at a scope the \
                     organization was granted, decided here and recorded in \
                     `punarctl privacy queries`. That is `query.answer`, and it is not a \
                     ledger export: nothing streams, nothing uploads continuously, and no \
                     administrator can pull. Next step: `punarctl privacy ledger` shows \
                     what is recorded, `punarctl privacy purge` deletes it."
                ),
                json!({ "method": unknown, "reason": "no export or upload path exists" }),
            )),
            unknown if unknown.starts_with(RESERVED_ADMIN_PREFIX) => Err(IpcError::with_details(
                ErrorCode::UnknownMethod,
                format!(
                    "The method {unknown:?} does not exist on this socket. admin.* names \
                     belong to the CONTROL PLANE, not to the device: an administrator \
                     asks the organization, the organization holds the question, and this \
                     device fetches it and decides for itself (spec sections 24.1, 59.4). \
                     Nothing listens here for an administrator. Next step: \
                     `punarctl privacy queries` shows every question that reached this \
                     device and what was decided."
                ),
                json!({ "method": unknown, "belongs_to": "control-plane" }),
            )),
            unknown => Err(IpcError::with_details(
                ErrorCode::UnknownMethod,
                format!(
                    "The method {unknown:?} does not exist. The punar-agentd IPC method \
                     table is closed and typed; there is no generic execution method, by \
                     design (spec sections 10 and 60). Next step: run `punarctl --help` \
                     for the supported commands."
                ),
                json!({ "method": unknown }),
            )),
        }
    }

    fn expect_no_params(method: &str, params: Option<Value>) -> Result<(), IpcError> {
        match params {
            None => Ok(()),
            Some(Value::Object(map)) if map.is_empty() => Ok(()),
            Some(_) => Err(Self::invalid_params(
                method,
                "this method takes no parameters",
            )),
        }
    }

    /// Params that may be omitted entirely: `None` (or `{}`) yields the
    /// type's `Default`. Used only where every field has a **safe**
    /// default — `agents.scan`'s `manual` trigger and `alerts.list`'s
    /// "live cards only".
    fn parse_optional_params<P: serde::de::DeserializeOwned + Default>(
        method: &str,
        params: Option<Value>,
    ) -> Result<P, IpcError> {
        match params {
            None => Ok(P::default()),
            Some(value) => serde_json::from_value(value)
                .map_err(|err| Self::invalid_params(method, &err.to_string())),
        }
    }

    fn parse_required_params<P: serde::de::DeserializeOwned>(
        method: &str,
        params: Option<Value>,
    ) -> Result<P, IpcError> {
        match params {
            None => Err(Self::invalid_params(method, "params object is required")),
            Some(value) => serde_json::from_value(value)
                .map_err(|err| Self::invalid_params(method, &err.to_string())),
        }
    }

    fn invalid_params(method: &str, reason: &str) -> IpcError {
        IpcError::with_details(
            ErrorCode::InvalidParams,
            format!(
                "Invalid parameters for {method}: {reason}. Next step: run \
                 `punarctl --help` for the expected arguments."
            ),
            json!({ "reason": reason }),
        )
    }
}

/// A validated, typed agentd request — the [`crate::ipc::Request`] shape
/// for the sibling socket.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentRequest {
    pub id: String,
    pub method: AgentMethod,
}

impl AgentRequest {
    /// The raw wire frame for this request.
    pub fn to_envelope(&self) -> RequestEnvelope {
        RequestEnvelope {
            v: crate::ipc::PROTOCOL_VERSION,
            id: self.id.clone(),
            method: self.method.name().to_string(),
            params: self.method.params_value(),
        }
    }

    /// Serialize as one NDJSON line, including the terminating `\n`.
    pub fn to_json_line(&self) -> String {
        self.to_envelope().to_json_line()
    }

    /// Parse one request line: the shared stages 1–5
    /// ([`parse_envelope_line`]) plus the agentd method table.
    pub fn parse_json_line(line: &str) -> Result<AgentRequest, RequestReject> {
        let envelope = parse_envelope_line(line)?;
        let method =
            AgentMethod::from_wire(&envelope.method, envelope.params).map_err(|error| {
                RequestReject {
                    id: Some(envelope.id.clone()),
                    error,
                }
            })?;
        Ok(AgentRequest {
            id: envelope.id,
            method,
        })
    }
}

// ---------------------------------------------------------------------------
// Typed results (ipc.md section 10.2; lenient deserialize per section 3.3)
// ---------------------------------------------------------------------------

/// One row of the `agents.list` / `agents.get` / `agents.register` result
/// shapes: the ten record fields plus the optional extras — detection
/// extras (`suspected`/`executable`/`signature_id`) on detections,
/// `scope_unit`/`authority` on managed sessions in `agents.get`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRow {
    #[serde(flatten)]
    pub record: RegistryRecord,
    /// Always `true` on detection rows (spec section 23 — the honesty
    /// label travels in the data); absent on registered sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_id: Option<String>,
    /// `punar-agent-<id>.scope` (managed sessions, `agents.get`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<AuthoritySummary>,
}

impl SessionRow {
    /// A bare row carrying only the record fields.
    pub fn from_record(record: RegistryRecord) -> SessionRow {
        SessionRow {
            record,
            suspected: None,
            executable: None,
            signature_id: None,
            scope_unit: None,
            authority: None,
        }
    }
}

/// One `agents.list` session row: the ten record fields plus the M8
/// **counts-only** ledger fingerprint (docs/api/ipc.md section 12.4).
///
/// Deliberately *not* [`SessionRow`]: `scope_unit` and `authority` are
/// `agents.get` detail and stay out of the list. And deliberately counts
/// only — no class names, no `evt_` ids, no zones. Identifiers require
/// `agents.access` and its ownership check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListedSession {
    #[serde(flatten)]
    pub record: RegistryRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger: Option<crate::ledger::LedgerFingerprint>,
}

impl ListedSession {
    /// A row with no ledger yet (a session registered before the ledger
    /// recorded anything, or a record that could not be read).
    pub fn bare(record: RegistryRecord) -> ListedSession {
        ListedSession {
            record,
            ledger: None,
        }
    }
}

/// `agents.list` / `agents.scan` result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentsListResult {
    /// RFC 3339 time of the most recent **change** to the detection set.
    ///
    /// M10 amendment (milestone-10.md section 3.4): a pass that changes
    /// nothing writes nothing, so this stamp — the one `agents.json`
    /// carries — means *the view as of the last change*. Liveness is
    /// [`AgentsListResult::last_scan_at`] below, which is in-memory state
    /// the socket serves and no file records.
    pub scanned_at: String,
    /// When the last detection pass actually ran, whether or not it
    /// changed anything. In-memory only: the socket is the authority, the
    /// file is a change log.
    #[serde(default)]
    pub last_scan_at: String,
    /// What asked for that pass.
    #[serde(default)]
    pub last_scan_trigger: ScanTrigger,
    /// `agents.scan` only: whether this pass changed the detection set.
    /// Absent on `agents.list`, which did not necessarily run one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    /// Sessions this boot (active + ended) — the ten record fields each,
    /// plus the ledger fingerprint when one exists.
    pub sessions: Vec<ListedSession>,
    /// Current point-in-time detections (memory + `agents.json` only,
    /// never persisted; milestone-7.md section 4.4). Detections carry
    /// **no** ledger field: an unregistered process has no persisted
    /// session and therefore no ledger in M8 (Milestone 10 owns that).
    pub detections: Vec<SessionRow>,
}

/// `agents.get` result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentsGetResult {
    pub session: SessionRow,
}

/// `agents.register` result: the accepted row plus the classification the
/// daemon **computed** (`managed`, or the honest `observed` downgrade the
/// launcher must surface).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentsRegisterResult {
    pub session: SessionRow,
    pub classification: AgentClassification,
}

/// `agents.end` result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentsEndResult {
    pub session: SessionRow,
}

// ---------------------------------------------------------------------------
// /run/punar/agents.json (ipc.md section 11 — summary only, no secrets)
// ---------------------------------------------------------------------------

/// Per-classification counts for the panel masthead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentsSummaryCounts {
    pub managed: u64,
    pub observed: u64,
    pub unknown: u64,
}

/// One session in the summary file — **no pid**, no cmdline, no secrets:
/// exactly what the panel renders (ipc.md section 11).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SummarySession {
    pub session_id: String,
    pub agent: String,
    pub project: String,
    pub environment: String,
    pub classification: AgentClassification,
    pub status: AgentStatus,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<AuthoritySummary>,
}

/// One detection in the summary file. `suspected` is always `true` —
/// every surface says *suspected AI*, never *AI* (spec section 23).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SummaryDetection {
    pub session_id: String,
    pub agent: String,
    pub classification: AgentClassification,
    pub suspected: bool,
    pub executable: String,
    pub observed_at: String,
}

/// The whole `/run/punar/agents.json` document. Non-authoritative by
/// design (`/run/punar` is user-writable — display data for that user's
/// own session; anything trusted stays on the socket). Consumers fail
/// closed: missing/unparsable → the calm empty panel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentsSummary {
    pub v: u32,
    pub scanned_at: String,
    /// `"personal-defaults"` or the org policy id (section 10.3).
    pub policy_citation: String,
    pub counts: AgentsSummaryCounts,
    pub sessions: Vec<SummarySession>,
    pub detections: Vec<SummaryDetection>,
    pub ts: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_19_2_record() -> RegistryRecord {
        RegistryRecord {
            session_id: "agt_123".into(),
            agent: "claude-code".into(),
            version: "x.y.z".into(),
            process_id: 18422,
            user: "alice@acme.com".into(),
            project: "atlas".into(),
            environment: "atlas-dev-42".into(),
            status: AgentStatus::Active,
            classification: AgentClassification::Managed,
            started_at: "2026-08-24T09:15:00Z".into(),
        }
    }

    #[test]
    fn record_round_trips_the_fixture_exactly() {
        // fixtures/agents/claude-code.registry-record.json, verbatim.
        let fixture = serde_json::json!({
            "session_id": "agt_123",
            "agent": "claude-code",
            "version": "x.y.z",
            "process_id": 18422,
            "user": "alice@acme.com",
            "project": "atlas",
            "environment": "atlas-dev-42",
            "status": "active",
            "classification": "managed",
            "started_at": "2026-08-24T09:15:00Z"
        });
        let parsed: RegistryRecord = serde_json::from_value(fixture.clone()).unwrap();
        assert_eq!(parsed, spec_19_2_record());
        assert_eq!(serde_json::to_value(&parsed).unwrap(), fixture);
    }

    #[test]
    fn record_serializes_exactly_the_ten_schema_fields() {
        let value = serde_json::to_value(spec_19_2_record()).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected = vec![
            "session_id",
            "agent",
            "version",
            "process_id",
            "user",
            "project",
            "environment",
            "status",
            "classification",
            "started_at",
        ];
        let mut got = keys.clone();
        got.sort_unstable();
        expected.sort_unstable();
        assert_eq!(got, expected);
    }

    #[test]
    fn record_rejects_unknown_fields() {
        let mut value = serde_json::to_value(spec_19_2_record()).unwrap();
        value["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<RegistryRecord>(value).is_err());
    }

    #[test]
    fn ended_status_widens_additively() {
        let mut record = spec_19_2_record();
        record.status = AgentStatus::Ended;
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["status"], "ended");
        let back: RegistryRecord = serde_json::from_value(value).unwrap();
        assert_eq!(back.status, AgentStatus::Ended);
    }

    #[test]
    fn validation_accepts_the_spec_record_and_reports_violations() {
        assert!(validate_registry_record(&spec_19_2_record()).is_ok());
        let broken = RegistryRecord {
            session_id: "sess-1".into(),
            agent: "-Bad-".into(),
            version: String::new(),
            process_id: 0,
            user: String::new(),
            project: String::new(),
            environment: String::new(),
            status: AgentStatus::Active,
            classification: AgentClassification::Unknown,
            started_at: "yesterday".into(),
        };
        let violations = validate_registry_record(&broken).unwrap_err();
        assert_eq!(violations.len(), 8, "{violations:?}");
    }

    #[test]
    fn session_id_pattern_matches_the_schema() {
        for ok in ["agt_123", "agt_4f21c09ab3e1", "agt_ABC9"] {
            assert!(session_id_ok(ok), "{ok}");
        }
        for bad in ["agt_", "agt-123", "sess_1", "", "agt_12 3", "agt_x!"] {
            assert!(!session_id_ok(bad), "{bad}");
        }
    }

    #[test]
    fn agent_name_pattern_matches_the_schema() {
        for ok in ["claude-code", "codex", "a", "foo.bar_1", "9lives"] {
            assert!(agent_name_ok(ok), "{ok}");
        }
        for bad in ["", "-lead", "trail-", "Upper", "has space", ".dot"] {
            assert!(!agent_name_ok(bad), "{bad}");
        }
    }

    #[test]
    fn method_table_is_closed_and_named() {
        for name in AgentMethod::NAMES {
            // Every listed name parses (with minimal params) or fails only
            // on params, never as unknown_method.
            let err = AgentMethod::from_wire(name, None).err();
            if let Some(err) = err {
                assert_eq!(err.code, ErrorCode::InvalidParams, "{name}");
            }
        }
        for probe in ["system.exec", "shell.run", "capabilities.set", "status"] {
            let err = AgentMethod::from_wire(probe, None).unwrap_err();
            assert_eq!(err.code, ErrorCode::UnknownMethod, "{probe}");
        }
    }

    /// M7/M8 asserted that `admin.*` was "reserved for Milestone 10".
    /// M10 shipped, so the honest answer is no longer a promise about a
    /// milestone but the invariant that milestone established: an
    /// administrator's question never arrives at this socket at all —
    /// the device fetches it from the control plane and decides it
    /// itself (milestone-10.md laws 1 and 2).
    #[test]
    fn reserved_names_answer_unknown_method_honestly() {
        let err = AgentMethod::from_wire("admin.query", None).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnknownMethod);
        assert!(err.message.contains("CONTROL PLANE"), "{}", err.message);
        assert!(
            err.message.contains("Nothing listens here"),
            "{}",
            err.message
        );
        assert!(
            err.message.contains("punarctl privacy queries"),
            "{}",
            err.message
        );
        assert!(
            !err.message.contains("reserved"),
            "a fulfilled reservation must stop advertising itself: {}",
            err.message
        );
    }

    /// The two remote-query methods are in the table, typed, and strict.
    /// `query.answer` requires its params — an administrator query with a
    /// missing field is refused as invalid, never answered best-effort —
    /// and `queries.list` needs none, because reading your own record of
    /// who asked about you takes no argument (spec 24.2).
    #[test]
    fn the_remote_query_methods_are_typed_and_strict() {
        let answer = AgentMethod::from_wire(
            "query.answer",
            Some(json!({
                "query_id": "qry_1",
                "requesting_admin": "cio@acme.com",
                "organization": "acme.com",
                "requested_scope": "inventory",
                "received_at": "2026-08-25T14:02:09Z",
            })),
        )
        .unwrap();
        assert_eq!(answer.name(), "query.answer");

        assert_eq!(
            AgentMethod::from_wire("query.answer", None)
                .unwrap_err()
                .code,
            ErrorCode::InvalidParams
        );
        // Nothing executable, and nothing undeclared, may ride along.
        assert_eq!(
            AgentMethod::from_wire(
                "query.answer",
                Some(json!({
                    "query_id": "qry_1",
                    "requesting_admin": "cio@acme.com",
                    "organization": "acme.com",
                    "requested_scope": "inventory",
                    "received_at": "2026-08-25T14:02:09Z",
                    "command": "/bin/sh",
                })),
            )
            .unwrap_err()
            .code,
            ErrorCode::InvalidParams
        );

        assert_eq!(
            AgentMethod::from_wire("queries.list", None).unwrap().name(),
            "queries.list"
        );
        assert_eq!(
            AgentMethod::from_wire("queries.list", Some(json!({ "limit": 5 })))
                .unwrap()
                .name(),
            "queries.list"
        );
    }

    /// There is no upload path in M8, and the refusal says so rather
    /// than promising a later one (spec sections 1.22, 24).
    #[test]
    fn there_is_no_ledger_export_or_query_method() {
        for probe in [
            "ledger.export",
            "ledger.query",
            "ledger.upload",
            "ledger.bogus",
        ] {
            let err = AgentMethod::from_wire(probe, None).unwrap_err();
            assert_eq!(err.code, ErrorCode::UnknownMethod, "{probe}");
            assert!(
                err.message.contains("stays on this device"),
                "{probe}: {}",
                err.message
            );
        }
    }

    #[test]
    fn the_ledger_methods_are_in_the_table_and_typed() {
        let access = AgentMethod::from_wire(
            "agents.access",
            Some(json!({ "session_id": "agt_4f21c09ab3e1" })),
        )
        .unwrap();
        assert_eq!(access.name(), "agents.access");

        // Exactly one scope, always.
        let one = AgentMethod::from_wire("ledger.purge", Some(json!({ "all": true }))).unwrap();
        assert_eq!(one.name(), "ledger.purge");
        for ambiguous in [
            json!({}),
            json!({ "session_id": "agt_1", "all": true }),
            json!({ "all": false }),
        ] {
            let err = AgentMethod::from_wire("ledger.purge", Some(ambiguous.clone())).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidParams, "{ambiguous}");
        }
    }

    #[test]
    fn purge_scope_reads_exactly_one_of_the_two_forms() {
        assert_eq!(
            LedgerPurgeParams {
                session_id: Some("agt_1".into()),
                all: None
            }
            .scope(),
            Some(PurgeScope::Session("agt_1".into()))
        );
        assert_eq!(
            LedgerPurgeParams {
                session_id: None,
                all: Some(true)
            }
            .scope(),
            Some(PurgeScope::CallersOwn)
        );
        assert_eq!(LedgerPurgeParams::default().scope(), None);
    }

    #[test]
    fn register_params_reject_daemon_stamped_fields() {
        // `user`, `started_at`, `classification` are computed/stamped by
        // the daemon — a launcher that sends them is broken, not humored.
        for (field, value) in [
            ("user", serde_json::json!("mallory")),
            ("started_at", serde_json::json!("2026-01-01T00:00:00Z")),
            ("classification", serde_json::json!("managed")),
        ] {
            let mut params = serde_json::json!({
                "session_id": "agt_4f21c09ab3e1",
                "agent": "claude-code",
                "version": "mock",
                "process_id": 2143,
                "project": "atlas",
                "environment": "host",
                "authority": {"policy_citation": "personal-defaults", "rows": []}
            });
            params[field] = value;
            let err = AgentMethod::from_wire("agents.register", Some(params)).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidParams, "{field}");
        }
    }

    #[test]
    fn agent_request_round_trips_over_the_shared_envelope() {
        let request = AgentRequest {
            id: "7".into(),
            method: AgentMethod::Get(AgentsGetParams {
                session_id: "agt_123".into(),
            }),
        };
        let line = request.to_json_line();
        assert!(line.ends_with('\n'));
        let parsed = AgentRequest::parse_json_line(line.trim_end()).unwrap();
        assert_eq!(parsed, request);
    }

    #[test]
    fn shared_envelope_stages_still_apply() {
        // Wrong version → unsupported_version, from the shared pipeline.
        let reject = AgentRequest::parse_json_line(r#"{"v":2,"id":"1","method":"agents.list"}"#)
            .unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::UnsupportedVersion);
        // Not JSON → malformed_request.
        let reject = AgentRequest::parse_json_line("not json").unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::MalformedRequest);
    }

    #[test]
    fn list_result_shape_matches_the_contract_example() {
        let result = AgentsListResult {
            last_scan_at: "2026-08-27T10:00:00Z".into(),
            last_scan_trigger: ScanTrigger::Timer,
            changed: None,
            scanned_at: "2026-08-27T10:00:02Z".into(),
            sessions: vec![ListedSession {
                record: spec_19_2_record(),
                ledger: Some(crate::ledger::LedgerFingerprint {
                    counts: crate::ledger::LedgerCounts {
                        resources: 5,
                        process_classes: 3,
                        security_events: 1,
                    },
                    updated_at: "2026-08-27T10:00:02Z".into(),
                }),
            }],
            detections: vec![SessionRow {
                suspected: Some(true),
                executable: Some("/home/punar/Downloads/foo-agent".into()),
                signature_id: Some("downloads-foo-agent".into()),
                ..SessionRow::from_record(RegistryRecord {
                    session_id: "agt_d11e0aa7c402".into(),
                    agent: "foo-agent".into(),
                    version: "unknown".into(),
                    process_id: 2410,
                    user: "punar".into(),
                    project: "unknown".into(),
                    environment: "host".into(),
                    status: AgentStatus::Active,
                    classification: AgentClassification::Unknown,
                    started_at: "2026-08-27T09:59:55Z".into(),
                })
            }],
        };
        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(value["sessions"][0]["session_id"], "agt_123");
        // The fingerprint is counts only (section 12.4).
        assert_eq!(value["sessions"][0]["ledger"]["process_classes"], 3);
        assert_eq!(value["sessions"][0]["ledger"]["security_events"], 1);
        assert!(value["detections"][0].get("ledger").is_none());
        let detection = &value["detections"][0];
        assert_eq!(detection["suspected"], true);
        assert_eq!(detection["signature_id"], "downloads-foo-agent");
        assert_eq!(detection["classification"], "unknown");
        // Flattened: record fields sit at the top level of the row.
        assert_eq!(detection["version"], "unknown");
        assert!(detection.get("record").is_none());
        // Absent extras stay absent, not null.
        assert!(detection.get("scope_unit").is_none());
    }

    // -- the shipped schema is the contract (the audit.rs precedent) ------

    const REGISTRY_RECORD_SCHEMA: &str =
        include_str!("../../../schemas/ai-agent/registry-record.json");
    const COMMON_DEFS: &str = include_str!("../../../schemas/common/defs.json");

    /// [`RegistryRecord`] and the shipped schema must not drift apart: the
    /// persisted registry log is read by `punarctl`, the panel, and CI's
    /// `jq` validation, so the Rust type is only as good as its agreement
    /// with the JSON contract.
    #[test]
    fn the_record_type_matches_the_shipped_schema() {
        let schema: Value = serde_json::from_str(REGISTRY_RECORD_SCHEMA).unwrap();
        let defs: Value = serde_json::from_str(COMMON_DEFS).unwrap();

        // Same field set, required-ness included, and nothing extra.
        let mut required: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        required.sort_unstable();
        let value = serde_json::to_value(spec_19_2_record()).unwrap();
        let mut serialized: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        serialized.sort_unstable();
        assert_eq!(serialized, required, "schema drift: field set changed");
        assert_eq!(schema["additionalProperties"], Value::Bool(false));

        // The status enum carries the M7 widening the schema's own
        // description pre-authorized — and nothing more.
        let statuses: Vec<&str> = schema["properties"]["status"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            statuses,
            vec![AgentStatus::Active.as_str(), AgentStatus::Ended.as_str()]
        );

        // Classification is the shared enum in common/defs.json, so the
        // three variants are pinned there, not restated here.
        let classifications: Vec<&str> = defs["$defs"]["agent_classification"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            classifications,
            vec![
                AgentClassification::Managed.as_str(),
                AgentClassification::Observed.as_str(),
                AgentClassification::Unknown.as_str(),
            ]
        );
    }

    // -- Milestone 10 ---------------------------------------------------

    /// `agents.scan` kept its M7 shape on the wire: no params is still
    /// valid, and it means `manual` — never an assumed timer.
    #[test]
    fn an_unlabelled_scan_is_manual_and_a_labelled_one_is_not() {
        assert_eq!(
            AgentMethod::from_wire("agents.scan", None).unwrap(),
            AgentMethod::Scan(AgentsScanParams {
                trigger: ScanTrigger::Manual
            })
        );
        assert_eq!(
            AgentMethod::from_wire("agents.scan", Some(json!({}))).unwrap(),
            AgentMethod::Scan(AgentsScanParams {
                trigger: ScanTrigger::Manual
            })
        );
        for trigger in ScanTrigger::ALL {
            let parsed =
                AgentMethod::from_wire("agents.scan", Some(json!({"trigger": trigger.as_str()})))
                    .unwrap();
            assert_eq!(parsed, AgentMethod::Scan(AgentsScanParams { trigger }));
            // And it round-trips through the envelope the CLI sends.
            let request = AgentRequest {
                id: "t1".into(),
                method: parsed,
            };
            let back = AgentRequest::parse_json_line(&request.to_json_line()).unwrap();
            assert_eq!(back.method, request.method);
        }
        // A trigger nobody defined is refused, not coerced to `manual`:
        // the audit trail must never carry a word the enum does not have.
        assert_eq!(
            AgentMethod::from_wire("agents.scan", Some(json!({"trigger": "cron"})))
                .unwrap_err()
                .code,
            ErrorCode::InvalidParams
        );
    }

    #[test]
    fn the_alert_methods_are_in_the_closed_table() {
        assert!(AgentMethod::NAMES.contains(&"alerts.list"));
        assert!(AgentMethod::NAMES.contains(&"alerts.dismiss"));
        assert_eq!(
            AgentMethod::from_wire("alerts.list", None).unwrap(),
            AgentMethod::AlertsList(AlertsListParams {
                include_dismissed: false
            })
        );
        assert_eq!(
            AgentMethod::from_wire("alerts.list", Some(json!({"include_dismissed": true})))
                .unwrap()
                .name(),
            "alerts.list"
        );
        // Dismissal names its target explicitly — never "the current one".
        assert_eq!(
            AgentMethod::from_wire("alerts.dismiss", None)
                .unwrap_err()
                .code,
            ErrorCode::InvalidParams
        );
        assert_eq!(
            AgentMethod::from_wire("alerts.bogus", None)
                .unwrap_err()
                .code,
            ErrorCode::UnknownMethod
        );
        // Every name in the table parses, and no name carries a program.
        for name in AgentMethod::NAMES {
            let refusal = AgentMethod::from_wire(name, None);
            assert!(
                refusal.is_ok() || refusal.unwrap_err().code == ErrorCode::InvalidParams,
                "{name} must be known, whatever its params"
            );
        }
    }

    /// The `alerts.json` side contract (milestone-10.md section 5.3):
    /// exactly twelve fields, and none of them can hold a pid, an argv or
    /// a `comm` — there is nowhere to put one.
    #[test]
    fn the_alert_row_is_exactly_the_documented_field_list() {
        let file = AlertsFile {
            v: ALERTS_FILE_VERSION,
            updated_at: "2026-08-25T14:31:00Z".into(),
            alerts: vec![AlertRow {
                alert_id: "alr_a1b2c3d4e5f6".into(),
                signature_id: "sig_0f1e2d3c4b5a".into(),
                agent: "foo-agent".into(),
                executable: "/home/punar/Downloads/foo-agent".into(),
                owner: "punar".into(),
                first_seen: "2026-08-25T14:31:00Z".into(),
                last_seen: "2026-08-25T14:31:00Z".into(),
                live: 1,
                detection_id: "agt_d11e0aa7c402".into(),
                signature: "unmanaged-path-agentlike".into(),
                policy_citation: "personal-defaults".into(),
                state: AlertState::Live,
            }],
        };
        let value: Value = serde_json::to_value(&file).unwrap();
        let mut keys: Vec<&str> = value["alerts"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "agent",
                "alert_id",
                "detection_id",
                "executable",
                "first_seen",
                "last_seen",
                "live",
                "owner",
                "policy_citation",
                "signature",
                "signature_id",
                "state",
            ]
        );
        assert_eq!(value["alerts"][0]["state"], "live");
        // Consumers fail closed on an unparsable file, so the shape has
        // to round-trip exactly.
        let back: AlertsFile = serde_json::from_value(value).unwrap();
        assert_eq!(back, file);
    }

    #[test]
    fn identity_shapes_are_checkable() {
        assert!(alert_id_ok("alr_a1b2c3d4e5f6"));
        assert!(!alert_id_ok("alr_short"));
        assert!(!alert_id_ok("agt_a1b2c3d4e5f6"));
        assert!(signature_identity_ok("sig_0f1e2d3c4b5a"));
        assert!(!signature_identity_ok("sig_0f1e2d3c4b5"));
        assert!(!signature_identity_ok("downloads-foo-agent"));
        // The M7 wire field keeps its M7 meaning: a rule *name*, which is
        // deliberately not a `sig_` identity.
        assert!(!signature_identity_ok("unmanaged-path-agentlike"));
    }

    #[test]
    fn summary_file_carries_no_process_ids() {
        let summary = AgentsSummary {
            v: AGENTS_SUMMARY_VERSION,
            scanned_at: "2026-08-27T10:00:02Z".into(),
            policy_citation: "personal-defaults".into(),
            counts: AgentsSummaryCounts {
                managed: 1,
                observed: 0,
                unknown: 1,
            },
            sessions: vec![SummarySession {
                session_id: "agt_4f21c09ab3e1".into(),
                agent: "claude-code".into(),
                project: "atlas".into(),
                environment: "punar-env-atlas".into(),
                classification: AgentClassification::Managed,
                status: AgentStatus::Active,
                started_at: "2026-08-27T09:58:40Z".into(),
                authority: Some(AuthoritySummary {
                    policy_citation: "personal-defaults".into(),
                    rows: vec![AuthorityRow {
                        zone: "filesystem.project".into(),
                        decision: "read_write".into(),
                        enforcement: "declared · M9".into(),
                    }],
                }),
            }],
            detections: vec![SummaryDetection {
                session_id: "agt_d11e0aa7c402".into(),
                agent: "foo-agent".into(),
                classification: AgentClassification::Unknown,
                suspected: true,
                executable: "/home/punar/Downloads/foo-agent".into(),
                observed_at: "2026-08-27T09:59:55Z".into(),
            }],
            ts: "2026-08-27T10:00:02Z".into(),
        };
        let text = serde_json::to_string(&summary).unwrap();
        // Summary only (ipc.md section 11): no pids, no cmdlines.
        assert!(!text.contains("process_id"), "{text}");
        assert!(!text.contains("cmdline"), "{text}");
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["counts"]["unknown"], 1);
        assert_eq!(value["detections"][0]["suspected"], true);
    }
}
