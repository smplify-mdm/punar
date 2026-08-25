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
//! [`crate::ipc::Method`]: five M7 methods plus the two M8 ledger
//! methods, no variant that carries a command line or program, and none
//! will ever be added. `admin.*` (M10) and `ledger.export`/`ledger.query`
//! (which do **not** exist — M8 has no upload path at all) are
//! **reserved**: they answer [`ErrorCode::UnknownMethod`] — said honestly
//! in the error prose.
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
    /// `agents.scan` — force one detection pass now.
    Scan,
    /// `agents.access` — the AI Access Ledger for one session (M8, spec
    /// section 21). Owner or root; drains the audit tail and samples the
    /// scope cgroup first so a read never shows a stale answer.
    Access(AgentsAccessParams),
    /// `ledger.purge` — the user deletes their own ledger (M8, spec
    /// section 24.2). Owner or root, always audited, and it does **not**
    /// touch the audit trail.
    Purge(LedgerPurgeParams),
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
    pub const NAMES: [&'static str; 7] = [
        "agents.list",
        "agents.get",
        "agents.register",
        "agents.end",
        "agents.scan",
        "agents.access",
        "ledger.purge",
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
            AgentMethod::Scan => "agents.scan",
            AgentMethod::Access(_) => "agents.access",
            AgentMethod::Purge(_) => "ledger.purge",
        }
    }

    /// The `params` value for the wire envelope.
    pub fn params_value(&self) -> Option<Value> {
        let params = match self {
            AgentMethod::List | AgentMethod::Scan => return None,
            AgentMethod::Get(p) => serde_json::to_value(p),
            AgentMethod::Register(p) => serde_json::to_value(p),
            AgentMethod::End(p) => serde_json::to_value(p),
            AgentMethod::Access(p) => serde_json::to_value(p),
            AgentMethod::Purge(p) => serde_json::to_value(p),
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
            "agents.scan" => Self::expect_no_params(method, params).map(|()| AgentMethod::Scan),
            "agents.get" => Self::parse_required_params(method, params).map(AgentMethod::Get),
            "agents.end" => Self::parse_required_params(method, params).map(AgentMethod::End),
            "agents.register" => Self::parse_required_params(method, params)
                .map(|p| AgentMethod::Register(Box::new(p))),
            "agents.access" => Self::parse_required_params(method, params).map(AgentMethod::Access),
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
                     this device: there is no export, upload, or remote-query method, by \
                     design (spec section 24). Next step: `punarctl privacy ledger` shows \
                     what is recorded, `punarctl privacy purge` deletes it."
                ),
                json!({ "method": unknown, "reason": "no upload path exists" }),
            )),
            unknown if unknown.starts_with(RESERVED_ADMIN_PREFIX) => Err(IpcError::with_details(
                ErrorCode::UnknownMethod,
                format!(
                    "The method {unknown:?} does not exist; admin.* names are reserved \
                     for the Milestone 10 shadow-AI detection MVP. Next step: run \
                     `punarctl --help` for the supported commands."
                ),
                json!({ "method": unknown, "reserved_for": "milestone-10" }),
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
    /// RFC 3339 time of the most recent detection pass.
    pub scanned_at: String,
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

    #[test]
    fn reserved_names_answer_unknown_method_honestly() {
        let err = AgentMethod::from_wire("admin.query", None).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnknownMethod);
        assert!(err.message.contains("Milestone 10"), "{}", err.message);
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
