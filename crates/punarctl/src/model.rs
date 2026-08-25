//! Client-side views of the IPC result shapes (docs/api/ipc.md section 5).
//!
//! Deliberately tolerant: the contract says clients must accept unknown
//! `result` fields (serde's default), and these structs also keep
//! enum-like values (`decision`, `source`, states) as plain strings so a
//! newer daemon never breaks an older CLI's rendering. `--json` bypasses
//! all of this and prints the raw result verbatim; only the human views
//! parse.

use serde::Deserialize;
use serde_json::Value;

/// `status` result (contract section 5.1).
#[derive(Deserialize)]
pub struct Status {
    pub protocol_version: u64,
    pub daemon_version: String,
    #[serde(default)]
    pub started_at: Option<String>,
    pub device_id: String,
    pub mode: String,
    pub enrolled: bool,
    pub hostname: String,
    pub capabilities_total: u64,
    #[serde(default)]
    pub last_reconcile: Option<String>,
    #[serde(default)]
    pub audit: Option<AuditFile>,
    /// M4 addition (contract section 5.1) — optional so an M3-shaped
    /// result still renders (contract 3.3 tolerance).
    #[serde(default)]
    pub compliance: Option<Compliance>,
    /// M5 addition (contract section 5.1) — present while enrolled,
    /// absent on a personal device (enrollment adds fields, never
    /// redraws).
    #[serde(default)]
    pub org: Option<Org>,
}

/// The `org` object of `status` / `enroll.*` results (contract sections
/// 5.1, 5.9, 5.10).
#[derive(Deserialize)]
pub struct Org {
    #[allow(dead_code)]
    pub id: String,
    #[allow(dead_code)]
    pub name: String,
    pub display_name: String,
    pub domain: String,
}

#[derive(Deserialize)]
pub struct AuditFile {
    pub path: String,
    pub events: u64,
}

/// The `status.compliance` block (contract section 5.1, M4): SPEC
/// section 52 states in personal scope — the device measured against its
/// own effective document.
#[derive(Deserialize)]
pub struct Compliance {
    pub overall: String,
    pub capabilities: Vec<ComplianceCapability>,
    #[serde(default)]
    pub drift_remediated_total: u64,
    #[serde(default)]
    pub last_remediation_at: Option<String>,
}

#[derive(Deserialize)]
pub struct ComplianceCapability {
    pub capability: String,
    pub state: String,
}

/// `capabilities.list` result (contract section 5.2).
#[derive(Deserialize)]
pub struct CapabilityList {
    pub capabilities: Vec<Descriptor>,
}

/// One `schemas/capability/capability-descriptor.json` document, field
/// names verbatim. State values are capability-specific JSON (the schema's
/// `state_value` convention) — consumers must not assume string.
#[derive(Deserialize)]
pub struct Descriptor {
    pub capability: String,
    pub supported: bool,
    pub current_state: Value,
    pub desired_state: Value,
    pub mutable: bool,
    pub requires_reboot: bool,
    pub risk: String,
    pub managed_by: String,
    pub verification: String,
    #[serde(default)]
    pub allowed_desired_states: Option<Vec<Value>>,
    #[serde(default)]
    pub privilege_required: Option<String>,
    #[serde(default)]
    pub approval_requirement: Option<String>,
    #[serde(default)]
    pub audit_category: Option<String>,
}

/// `capabilities.get` result (contract section 5.3).
#[derive(Deserialize)]
pub struct CapabilityGet {
    pub descriptor: Descriptor,
}

/// `capabilities.set` result (contract section 5.4).
#[derive(Deserialize)]
pub struct CapabilitySet {
    pub descriptor: Descriptor,
    pub changed: bool,
    /// M4/M5 (contract section 5.4): present (and `true`) only when a
    /// higher-precedence source outranks the recorded preference —
    /// recorded-but-overridden, not forbidden.
    #[serde(default)]
    pub overridden: Option<bool>,
    /// The effective value that was applied when `overridden` is set.
    #[serde(default)]
    pub effective_state: Option<Value>,
}

/// `enroll.start` result (contract section 5.9).
#[derive(Deserialize)]
pub struct EnrollStart {
    #[allow(dead_code)]
    pub enrolled: bool,
    pub org: Org,
    pub policy_ids: Vec<String>,
    /// The honesty label — `"simulated"` from the mock control plane,
    /// rendered loud by design.
    pub attestation: String,
    #[serde(default)]
    pub enrolled_at: Option<String>,
    #[serde(default)]
    pub first_sync: Option<FirstSync>,
}

/// The `first_sync` object of [`EnrollStart`].
#[derive(Deserialize)]
pub struct FirstSync {
    pub compliance: String,
    pub inventory: String,
}

/// `enroll.status` result (contract section 5.10). Unenrolled:
/// `{"enrolled": false}` with everything else absent.
#[derive(Deserialize)]
pub struct EnrollStatus {
    pub enrolled: bool,
    #[serde(default)]
    pub org: Option<Org>,
    #[serde(default)]
    pub policy_ids: Option<Vec<String>>,
    #[serde(default)]
    pub enrolled_at: Option<String>,
    #[serde(default)]
    pub attestation: Option<String>,
    #[serde(default)]
    pub last_sync: Option<LastSync>,
}

/// The `last_sync` object of [`EnrollStatus`].
#[derive(Deserialize)]
pub struct LastSync {
    #[serde(default)]
    pub at: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub pending: bool,
}

/// `enroll.stop` result (contract section 5.11).
#[derive(Deserialize)]
pub struct EnrollStop {
    #[allow(dead_code)]
    pub enrolled: bool,
    pub removed_policy_ids: Vec<String>,
}

/// `audit.tail` result (contract section 5.5). Events are
/// schema-conformant `AuditEvent` objects; the human view only renders a
/// subset of fields and tolerates anything extra.
#[derive(Deserialize)]
pub struct AuditTail {
    pub events: Vec<AuditEventView>,
}

#[derive(Deserialize)]
pub struct AuditEventView {
    #[serde(default)]
    pub event_id: String,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub decision: String,
    #[serde(default)]
    pub result: String,
}

/// `reconcile` result (contract section 5.6). The M4 fields are optional
/// so an M3-shaped result (report-only, no remediation) still renders —
/// `remediated_count` present is the marker that the daemon remediates.
#[derive(Deserialize)]
pub struct Reconcile {
    #[serde(default)]
    pub reconciled_at: Option<String>,
    pub drift_count: u64,
    pub capabilities: Vec<ReconcileEntry>,
    #[serde(default)]
    pub remediated_count: Option<u64>,
}

#[derive(Deserialize)]
pub struct ReconcileEntry {
    pub capability: String,
    pub desired_state: Value,
    pub current_state: Value,
    pub drift: bool,
    #[serde(default = "default_true")]
    pub verified: bool,
    /// M4 (contract section 5.6): SPEC section 43 classification —
    /// `auto_remediate | alert_only | approval_required`.
    #[serde(default)]
    pub classification: Option<String>,
    /// M4 (contract section 5.6): `applied | none | apply_failed |
    /// verify_failed | alert_only | suppressed`.
    #[serde(default)]
    pub remediation: Option<String>,
}

fn default_true() -> bool {
    true
}

/// `policy.effective` result (contract section 5.7, M4).
#[derive(Deserialize)]
pub struct PolicyEffective {
    #[serde(default)]
    pub computed_at: Option<String>,
    pub entries: Vec<PolicyEntry>,
}

/// One effective-document entry: a path plus the section 40 information
/// set (`policy.explain` returns the same body without the path).
#[derive(Deserialize)]
pub struct PolicyEntry {
    pub path: String,
    #[serde(flatten)]
    pub explain: PolicyExplain,
}

/// `policy.explain` result (contract section 5.8, M4) — exactly the SPEC
/// section 40 information set.
#[derive(Deserialize)]
pub struct PolicyExplain {
    pub effective_value: Value,
    pub source: PolicySource,
    pub user_override_permitted: bool,
    pub compliance_state: String,
}

/// The winning source: `kind`/`rank` are the `policy_source_kind` enum
/// and precedence ranks of `schemas/policy/policy-source.json` (lower
/// wins); `name` is the human spelling ("Personal preference" /
/// "OS default" in personal mode).
#[derive(Deserialize)]
pub struct PolicySource {
    /// Machine layer of the wire contract: the human views render `name`
    /// and `policy_id` (spec 40 shows names, not enum values); `kind` and
    /// `rank` are parsed so the client pins the contract shape (tests
    /// assert them) and stay available to future renderers.
    #[allow(dead_code)]
    pub kind: String,
    #[allow(dead_code)]
    pub rank: u64,
    pub policy_id: String,
    pub name: String,
}

// ---------------------------------------------------------------------------
// M7 agent registry views (contract section 10.2 — the punar-agentd socket)
// ---------------------------------------------------------------------------

/// `agents.list` / `agents.scan` result (contract section 10.2).
#[derive(Deserialize)]
pub struct AgentsList {
    /// The view as of the last **change** — a pass that changes nothing
    /// rewrites nothing (milestone-10.md section 3.4), so this does not
    /// advance every four minutes and is not meant to.
    pub scanned_at: String,
    /// M10 liveness, in-memory and served only by the socket: when a pass
    /// last actually ran, and what asked for it.
    #[serde(default)]
    pub last_scan_at: Option<String>,
    #[serde(default)]
    pub last_scan_trigger: Option<String>,
    #[serde(default)]
    pub sessions: Vec<AgentRow>,
    /// Point-in-time detections — heuristic, never certain (SPEC section
    /// 23). Every one carries `suspected: true` in the data itself.
    #[serde(default)]
    pub detections: Vec<AgentRow>,
}

/// `agents.get` result (contract section 10.2).
#[derive(Deserialize)]
pub struct AgentGet {
    pub session: AgentRow,
}

/// One registry row: the ten `schemas/ai-agent/registry-record.json`
/// fields plus the optional detection and managed-session extras. Tolerant
/// like every other model here — `version`/`environment` default so a row
/// still renders if a future daemon omits one.
#[derive(Deserialize, Clone)]
pub struct AgentRow {
    pub session_id: String,
    pub agent: String,
    #[serde(default)]
    pub version: String,
    pub user: String,
    pub project: String,
    #[serde(default)]
    pub environment: String,
    pub status: String,
    /// `managed` · `observed` · `unknown` (SPEC section 19.1).
    pub classification: String,
    pub started_at: String,
    /// Always `true` on detections; absent on registered sessions.
    #[serde(default)]
    pub suspected: bool,
    #[serde(default)]
    pub executable: Option<String>,
    #[serde(default)]
    pub signature_id: Option<String>,
    #[serde(default)]
    pub scope_unit: Option<String>,
    /// The display-level authority summary captured at launch (contract
    /// section 10.3) — present for managed sessions in `agents.get`.
    #[serde(default)]
    pub authority: Option<AgentAuthority>,
    /// The M8 counts-only ledger fingerprint (contract section 12.4).
    /// Absent on detections by design: an unregistered process has no
    /// persisted session and therefore no ledger until Milestone 10.
    #[serde(default)]
    pub ledger: Option<LedgerFingerprint>,
}

/// The authority block: named policy source + the declared rows, each
/// carrying the milestone that will enforce it (M7 enforces none).
#[derive(Deserialize, Clone)]
pub struct AgentAuthority {
    pub policy_citation: String,
    #[serde(default)]
    pub rows: Vec<AgentAuthorityRow>,
}

#[derive(Deserialize, Clone)]
pub struct AgentAuthorityRow {
    pub zone: String,
    pub decision: String,
    #[serde(default)]
    pub enforcement: String,
}

// ---------------------------------------------------------------------------
// M8 AI Access Ledger (contract sections 12–13 — the punar-agentd socket)
// ---------------------------------------------------------------------------

/// `agents.access` result (contract section 12.2): the schema-exact
/// `summary` document plus the sibling fields the schema deliberately
/// cannot hold — counts, first/last seen, the honest not-yet-observed
/// rows, retention and the privacy statement.
///
/// Everything but `summary` defaults, so a daemon that answers with the
/// bare document still renders: the view then simply has no counts to
/// print and says nothing it cannot prove.
#[derive(Deserialize)]
pub struct LedgerAccess {
    pub summary: LedgerSummary,
    #[serde(default)]
    pub detail: Option<LedgerDetail>,
    #[serde(default)]
    pub not_yet_observed: Vec<NotYetObserved>,
    #[serde(default)]
    pub retention: Option<LedgerRetention>,
    #[serde(default)]
    pub privacy: Option<LedgerPrivacy>,
    /// Set when the user purged this session's ledger (section 12.2): the
    /// resources are empty *because they were deleted*, and every surface
    /// must say `purged`, never `nothing recorded`.
    #[serde(default)]
    pub purged_at: Option<String>,
}

/// The `schemas/ai-agent/ledger-summary.json` document, unchanged by M8.
#[derive(Deserialize)]
pub struct LedgerSummary {
    pub session_id: String,
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub generated_at: String,
    #[serde(default)]
    pub resources: LedgerResources,
    #[serde(default)]
    pub security_events: Vec<LedgerEvent>,
}

/// The six resource categories, verbatim from the schema. They are the
/// closed vocabulary: there is no seventh, and a category with no owned
/// mediation point is an **empty array plus a `not_yet_observed` row**,
/// never a silent absence (spec section 1.22).
#[derive(Deserialize, Default)]
pub struct LedgerResources {
    #[serde(default)]
    pub repositories: Vec<String>,
    #[serde(default)]
    pub directory_zones: Vec<String>,
    #[serde(default)]
    pub network_destinations: Vec<String>,
    #[serde(default)]
    pub mcp_servers: Vec<String>,
    #[serde(default)]
    pub credential_classes: Vec<String>,
    #[serde(default)]
    pub process_classes: Vec<String>,
}

impl LedgerResources {
    /// The categories in the Plate D-005 reading order, each with the label
    /// every surface prints for it. Observed categories come first; the
    /// three with no producer in M8 keep their place at the bottom so the
    /// M8/M12 boundary sits where the plate draws it.
    pub fn categories(&self) -> [(&'static str, &'static str, &[String]); 6] {
        [
            ("repositories", "Repositories", &self.repositories),
            ("directory_zones", "Directory zones", &self.directory_zones),
            ("process_classes", "Processes", &self.process_classes),
            (
                "network_destinations",
                "Network destinations",
                &self.network_destinations,
            ),
            ("mcp_servers", "MCP servers", &self.mcp_servers),
            (
                "credential_classes",
                "Credential classes",
                &self.credential_classes,
            ),
        ]
    }

    /// Distinct resource classes recorded across every category — the one
    /// number `privacy ledger` reports as "what is recorded".
    pub fn total(&self) -> usize {
        self.categories().iter().map(|(_, _, v)| v.len()).sum()
    }
}

/// A Level-4 security event **reference** (contract section 12.2). The
/// payload stays in `/var/log/punar/audit.jsonl` — one source of truth
/// (spec section 53), one place to redact, and nothing the ledger could
/// contradict.
#[derive(Deserialize)]
pub struct LedgerEvent {
    pub event_id: String,
    #[serde(default)]
    pub event_type: String,
    #[serde(default)]
    pub timestamp: String,
}

/// The counted aggregate behind the document (contract section 12.2).
#[derive(Deserialize)]
pub struct LedgerDetail {
    #[serde(default)]
    pub status: String,
    /// The scope cgroup's `pids.peak` — peak **concurrent** pids, never a
    /// spawn total.
    #[serde(default)]
    pub process_peak: Option<u64>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub entries: Vec<LedgerEntry>,
}

impl LedgerDetail {
    /// The count recorded for one `(category, resource_class)` pair, if the
    /// daemon sent the aggregate at all.
    pub fn count_of(&self, category: &str, resource_class: &str) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.category == category && e.resource_class == resource_class)
            .map(|e| e.count)
    }
}

/// One aggregate entry. `count` for `process_classes` is distinct
/// `(pid, starttime)` pairs observed **alive at a sampling point** — not a
/// spawn count, and every renderer carries that qualifier.
#[derive(Deserialize)]
pub struct LedgerEntry {
    pub category: String,
    pub resource_class: String,
    #[serde(default)]
    pub count: u64,
    #[serde(default)]
    pub first_seen: String,
    #[serde(default)]
    pub last_seen: String,
    /// `cgroup_scope` · `audit_event` · `workspace_bind` ·
    /// `adapter_metadata` — the mediation point that proved the entry.
    #[serde(default)]
    pub evidence: String,
}

/// An honest empty: the category exists, nothing observes it yet, and the
/// milestone that will is named (contract section 12.2; spec section 1.22).
#[derive(Deserialize)]
pub struct NotYetObserved {
    #[serde(default)]
    pub level: u8,
    pub category: String,
    #[serde(default)]
    pub milestone: String,
    #[serde(default)]
    pub reason: String,
}

/// `{days, active}` while the session runs; `{days, expires_at}` once it
/// has ended (contract section 12.2).
#[derive(Deserialize)]
pub struct LedgerRetention {
    #[serde(default)]
    pub days: u32,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// The section 24.2 guarantee, carried in the result so every renderer
/// says the same words rather than each inventing its own.
#[derive(Deserialize)]
pub struct LedgerPrivacy {
    #[serde(default)]
    pub local_only: bool,
    #[serde(default)]
    pub purge_command: String,
    #[serde(default)]
    pub never_recorded: Vec<String>,
    #[serde(default)]
    pub audit_trail_separate: bool,
}

/// `ledger.purge` result (contract section 12.3).
#[derive(Deserialize)]
pub struct LedgerPurge {
    #[serde(default)]
    pub purged: u64,
    #[serde(default)]
    pub resource_classes: u64,
    #[serde(default)]
    pub security_events: u64,
    #[serde(default)]
    pub purged_at: String,
}

/// The counts-only ledger fingerprint on an `agents.list` row (contract
/// section 12.4). **No** class names, **no** `evt_` ids, **no** zones —
/// identifiers require `agents.access` and its ownership check.
#[derive(Deserialize, Clone)]
pub struct LedgerFingerprint {
    #[serde(default)]
    pub resources: u64,
    #[serde(default)]
    pub process_classes: u64,
    #[serde(default)]
    pub security_events: u64,
    #[serde(default)]
    pub updated_at: String,
}

// ---------------------------------------------------------------------
// Milestone 9 — approvals, privilege grants, credential classes
// (contract sections 14, 16).
// ---------------------------------------------------------------------

/// The spec section 28 approval **document** — the member of the envelope
/// that validates against `schemas/audit/approval.json` as-is (contract
/// section 14.3). Nothing M9 added lives in here: `kind`, `execution`,
/// `consumed_at` and the rest are siblings, and `status` never leaves the
/// shipped `pending | approved | denied | expired` enum.
#[derive(Deserialize)]
pub struct ApprovalDoc {
    pub approval_id: String,
    #[serde(default)]
    pub requester: Requester,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub capability: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub risk: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub expires_at: String,
}

/// `approval.requester` — who asked. `type` is `ai_agent` or `user`; the
/// field is spelled `type` on the wire, which is a Rust keyword.
#[derive(Deserialize, Default)]
pub struct Requester {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub id: String,
    /// Display-grade, from the registry — present on the summary file's
    /// rows, absent from the schema document.
    #[serde(default)]
    pub agent_name: String,
}

/// The `approvals.get` / `approvals.resolve` / `approvals.consume`
/// envelope (contract section 14.3). Every sibling defaults, so a daemon
/// that answers with the bare document still renders and the view simply
/// prints nothing it cannot prove.
#[derive(Deserialize)]
pub struct ApprovalEnvelope {
    pub approval: ApprovalDoc,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub contract: String,
    #[serde(default)]
    pub policy: Option<ApprovalPolicy>,
    #[serde(default)]
    pub resolved_at: Option<String>,
    #[serde(default)]
    pub resolved_by: Option<ResolvedBy>,
    #[serde(default)]
    pub consumed_at: Option<String>,
    #[serde(default)]
    pub execution: Option<ApprovalExecution>,
}

/// The policy citation an approval carries (`{name, policy_id}`).
/// Personal mode cites the personal defaults; an org name appears only
/// while enrolled (DESIGN_LANGUAGE section 8).
#[derive(Deserialize)]
pub struct ApprovalPolicy {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub policy_id: String,
}

/// Who answered, recorded in full so that an attribution escape is
/// visible after the fact even where it is not preventable (contract
/// section 14.5).
#[derive(Deserialize)]
pub struct ResolvedBy {
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub pid: Option<u32>,
}

/// What ran on `resolve(approved)`, and the **pointer into the audit
/// trail** (contract section 14.3). The direction is deliberate:
/// approval → event, exactly as Plate D-003 prints it ("audit evt_501").
#[derive(Deserialize)]
pub struct ApprovalExecution {
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub changed: Option<bool>,
    #[serde(default)]
    pub audit_event_id: Option<String>,
    #[serde(default)]
    pub grant_id: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// `approvals.list` result.
#[derive(Deserialize)]
pub struct ApprovalsList {
    #[serde(default)]
    pub approvals: Vec<ApprovalEnvelope>,
    #[serde(default)]
    pub checked_at: String,
}

/// One live just-in-time privilege grant (contract section 14.8).
#[derive(Deserialize)]
pub struct Grant {
    pub grant_id: String,
    #[serde(default)]
    pub capability: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub granted_at: String,
    #[serde(default)]
    pub expires_at: String,
}

/// `privilege.status` result.
#[derive(Deserialize)]
pub struct PrivilegeStatus {
    #[serde(default)]
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub checked_at: String,
}

/// `privilege.revoke` result. The shape is deliberately tolerant: the
/// view reports whichever count the daemon spells.
#[derive(Deserialize)]
pub struct PrivilegeRevoke {
    #[serde(default)]
    pub revoked: Vec<String>,
    #[serde(default)]
    pub revoked_count: Option<u64>,
    #[serde(default)]
    pub revoked_at: String,
}

/// One credential class (contract section 16.3). Class ids are
/// **kebab-case** on the wire, in audit `resource` and in the M8 ledger
/// (`github`, `aws-dev`, `aws-prod`); the snake_case `policy_key` is the
/// declared mapping into the section 20 policy document, never a guess.
#[derive(Deserialize)]
pub struct CredentialClass {
    pub credential: String,
    #[serde(default)]
    pub decision: String,
    #[serde(default)]
    pub policy_key: String,
    #[serde(default)]
    pub default_ttl: Option<u64>,
    #[serde(default)]
    pub max_ttl: Option<u64>,
    #[serde(default)]
    pub provider: String,
}

/// `credential.classes` result — classes and their effective decision.
/// **Never values**: after issuance the broker holds only
/// `sha256(token)`, so there is no method that could list one.
#[derive(Deserialize)]
pub struct CredentialClasses {
    #[serde(default, alias = "credentials")]
    pub classes: Vec<CredentialClass>,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub checked_at: String,
}

/// The issuance receipt for the human card (contract section 16.3). The
/// **value is not in this struct on purpose**: it is lifted out of the
/// raw result into a [`punar_common::Redacted`] and written once to fd 1
/// (see `main::secrets_get`), so no derived `Debug` here can ever print
/// it.
#[derive(Deserialize)]
pub struct CredentialIssued {
    #[serde(default)]
    pub credential: String,
    #[serde(default)]
    pub expires_at: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub agent_session_id: String,
}

/// `credential.validate` result.
#[derive(Deserialize)]
pub struct CredentialValidate {
    #[serde(default)]
    pub valid: bool,
    #[serde(default)]
    pub credential: String,
    #[serde(default)]
    pub expires_at: String,
}

/// `credential.revoke` result.
#[derive(Deserialize)]
pub struct CredentialRevoke {
    #[serde(default)]
    pub credential: String,
    #[serde(default)]
    pub revoked: Option<bool>,
    #[serde(default)]
    pub revoked_at: String,
}

/// Display spelling of a capability state value: strings render bare
/// (`enabled`), anything else as compact JSON.
pub fn state_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn status_tolerates_unknown_and_missing_optional_fields() {
        let status: Status = serde_json::from_value(json!({
            "protocol_version": 1,
            "daemon_version": "0.1.0",
            "device_id": "dev_9f3k2v8q1x",
            "mode": "personal",
            "enrolled": false,
            "hostname": "punar-m3",
            "capabilities_total": 3,
            "added_by_a_future_milestone": {"ok": true}
        }))
        .unwrap();
        assert_eq!(status.capabilities_total, 3);
        assert!(status.started_at.is_none());
        assert!(status.audit.is_none());
        // An M3-shaped status (no compliance block) must still parse —
        // contract section 3.3 tolerance.
        assert!(status.compliance.is_none());
    }

    #[test]
    fn status_parses_the_m4_compliance_block() {
        let status: Status = serde_json::from_value(json!({
            "protocol_version": 1,
            "daemon_version": "0.2.0",
            "device_id": "dev_9f3k2v8q1x",
            "mode": "personal",
            "enrolled": false,
            "hostname": "punar-m4",
            "capabilities_total": 3,
            "compliance": {
                "overall": "compliant",
                "capabilities": [
                    {"capability": "security.firewall", "state": "compliant"},
                    {"capability": "time.timezone", "state": "remediating"}
                ],
                "drift_remediated_total": 2,
                "last_remediation_at": "2026-08-25T09:14:02Z"
            }
        }))
        .unwrap();
        let compliance = status.compliance.unwrap();
        assert_eq!(compliance.overall, "compliant");
        assert_eq!(compliance.capabilities.len(), 2);
        assert_eq!(compliance.capabilities[1].state, "remediating");
        assert_eq!(compliance.drift_remediated_total, 2);
        assert_eq!(
            compliance.last_remediation_at.as_deref(),
            Some("2026-08-25T09:14:02Z")
        );
    }

    #[test]
    fn policy_effective_parses_the_contract_example_entry() {
        let doc: PolicyEffective = serde_json::from_value(json!({
            "computed_at": "2026-08-25T09:14:02Z",
            "entries": [
                {"path": "time.timezone", "effective_value": "UTC",
                 "source": {"kind": "os_secure_default", "rank": 6,
                            "policy_id": "personal-defaults",
                            "name": "OS default"},
                 "user_override_permitted": true,
                 "compliance_state": "compliant"}
            ]
        }))
        .unwrap();
        assert_eq!(doc.entries.len(), 1);
        let entry = &doc.entries[0];
        assert_eq!(entry.path, "time.timezone");
        assert_eq!(entry.explain.source.kind, "os_secure_default");
        assert_eq!(entry.explain.source.rank, 6);
        assert!(entry.explain.user_override_permitted);
    }

    #[test]
    fn policy_explain_is_an_entry_without_the_path() {
        let explain: PolicyExplain = serde_json::from_value(json!({
            "effective_value": "enabled",
            "source": {"kind": "local_user_preference", "rank": 5,
                       "policy_id": "personal-defaults",
                       "name": "Personal preference"},
            "user_override_permitted": true,
            "compliance_state": "compliant"
        }))
        .unwrap();
        assert_eq!(state_str(&explain.effective_value), "enabled");
        assert_eq!(explain.source.name, "Personal preference");
        assert_eq!(explain.compliance_state, "compliant");
    }

    #[test]
    fn descriptor_parses_the_schema_shape() {
        let descriptor: Descriptor = serde_json::from_value(json!({
            "capability": "security.firewall",
            "supported": true,
            "current_state": "enabled",
            "desired_state": "enabled",
            "mutable": true,
            "requires_reboot": false,
            "risk": "high",
            "managed_by": "local",
            "verification": "nftables",
            "allowed_desired_states": ["enabled", "disabled"],
            "privilege_required": "root",
            "approval_requirement": "allow",
            "audit_category": "security",
            "state_schema": {"enum": ["enabled", "disabled"]}
        }))
        .unwrap();
        assert_eq!(descriptor.capability, "security.firewall");
        assert_eq!(descriptor.allowed_desired_states.unwrap().len(), 2);
    }

    #[test]
    fn reconcile_verified_defaults_to_true() {
        let entry: ReconcileEntry = serde_json::from_value(json!({
            "capability": "time.timezone",
            "desired_state": "UTC",
            "current_state": "UTC",
            "drift": false
        }))
        .unwrap();
        assert!(entry.verified);
        // M3-shaped entry: no M4 remediation fields.
        assert!(entry.classification.is_none());
        assert!(entry.remediation.is_none());
    }

    #[test]
    fn reconcile_parses_the_m4_remediation_fields() {
        let report: Reconcile = serde_json::from_value(json!({
            "reconciled_at": "2026-08-25T09:14:02Z",
            "drift_count": 1,
            "remediated_count": 1,
            "compliance": {"overall": "compliant", "capabilities": [],
                           "drift_remediated_total": 1},
            "capabilities": [
                {"capability": "security.firewall", "desired_state": "enabled",
                 "current_state": "disabled", "drift": true, "verified": true,
                 "classification": "auto_remediate", "remediation": "applied"}
            ]
        }))
        .unwrap();
        assert_eq!(report.remediated_count, Some(1));
        let entry = &report.capabilities[0];
        assert_eq!(entry.classification.as_deref(), Some("auto_remediate"));
        assert_eq!(entry.remediation.as_deref(), Some("applied"));
    }

    #[test]
    fn state_str_keeps_strings_bare_and_json_for_the_rest() {
        assert_eq!(state_str(&json!("enabled")), "enabled");
        assert_eq!(state_str(&json!(true)), "true");
        assert_eq!(state_str(&json!({"a": 1})), r#"{"a":1}"#);
    }
}

// ---------------------------------------------------------------------------
// M10 — the remote-query log (contract section 13.1's `queries.list`;
// docs/development/milestone-10.md section 10.3). SPEC section 24.2: the
// employee never has less visibility than the administrator, so this is
// readable by any peer the agentd socket admits, not by root alone.
// ---------------------------------------------------------------------------

/// `alerts.list` result (contract section 17.1) — the shadow-AI alert
/// register. One card per signature, never per scan and never per
/// process.
#[derive(Deserialize)]
pub struct AlertsList {
    #[serde(default)]
    pub alerts: Vec<AlertRow>,
    /// The anti-nag window in seconds, from the daemon that enforces it,
    /// so the renderer states the rule rather than hard-coding it.
    #[serde(default)]
    pub quiet_window_secs: u64,
}

/// One alert card, in the `alerts.json` field list (milestone-10.md
/// section 5.3). Tolerant like every other model here.
#[derive(Deserialize)]
pub struct AlertRow {
    #[serde(default)]
    pub alert_id: String,
    /// The M10 `sig_` identity — one thing seen, however often it
    /// restarts.
    #[serde(default)]
    pub signature_id: String,
    /// The matched rule's **name**, the reviewable line in the data file.
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub executable: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub first_seen: String,
    #[serde(default)]
    pub last_seen: String,
    /// How many live detections currently carry this signature — a
    /// count, not a flag: a crash-looping agent is one card and several
    /// processes.
    #[serde(default)]
    pub live: u64,
    #[serde(default)]
    pub detection_id: String,
    #[serde(default)]
    pub policy_citation: String,
    /// `live` · `cleared` · `dismissed`.
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub raised_at: String,
    #[serde(default)]
    pub cleared_at: Option<String>,
    #[serde(default)]
    pub dismissed_at: Option<String>,
    /// When a fresh sighting of this signature would raise a new card.
    #[serde(default)]
    pub quiet_until: Option<String>,
}

/// `alerts.dismiss` result.
#[derive(Deserialize)]
pub struct AlertDismissed {
    #[serde(default)]
    pub alert_id: String,
    #[serde(default)]
    pub dismissed_at: String,
    /// Always `false`: filing a card moves no suppression state, because
    /// there is none to move (milestone-10.md section 5.2).
    #[serde(default)]
    pub suppression_changed: bool,
}

/// `queries.list` result. Everything the surface prints comes from the
/// daemon — the granted scopes, the never-answered list and the storage
/// facts included — so the CLI invents nothing and the two cannot drift.
#[derive(Deserialize)]
pub struct QueriesList {
    #[serde(default)]
    pub queries: Vec<QueryRow>,
    #[serde(default)]
    pub enrolled: bool,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub policy_citation: Option<String>,
    /// The same array `punar-agentd` enforces, so the user can check every
    /// answer against it themselves (SPEC 24.2 guarantee 8).
    #[serde(default)]
    pub granted_scopes: Vec<String>,
    /// Always `false` in M10: there is no IdP, and every rendering of a
    /// requesting admin says so.
    #[serde(default)]
    pub admin_identity_verified: bool,
    #[serde(default)]
    pub never_answered: Vec<String>,
    #[serde(default)]
    pub storage: Option<QueryLogStorage>,
}

/// One line of `/var/lib/punar/agents/queries.jsonl` — the six SPEC 51.1
/// fields plus the granted scope and the result shape.
#[derive(Deserialize)]
pub struct QueryRow {
    #[serde(default)]
    pub query_id: String,
    #[serde(default)]
    pub received_at: String,
    #[serde(default)]
    pub answered_at: String,
    #[serde(default)]
    pub requesting_admin: String,
    #[serde(default)]
    pub requested_scope: String,
    #[serde(default)]
    pub granted_scope: Option<String>,
    #[serde(default)]
    pub authorization_decision: String,
    #[serde(default)]
    pub refusal_reason: Option<String>,
    #[serde(default)]
    pub result_category: String,
    #[serde(default)]
    pub record_counts: QueryRecordCounts,
    #[serde(default)]
    pub audit_event_id: Option<String>,
}

/// The *shape* of what left the device — never a second copy of the
/// contents (milestone-10.md section 10.1).
#[derive(Default, Deserialize)]
pub struct QueryRecordCounts {
    #[serde(default)]
    pub sessions: u64,
    #[serde(default)]
    pub detections: u64,
    #[serde(default)]
    pub security_events: u64,
}

/// Where the query log lives and how long it is kept, as the daemon
/// reports it.
#[derive(Deserialize)]
pub struct QueryLogStorage {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub retention_days: u32,
    /// The boundary: this log records what the **organization** did, so a
    /// purge of the user's own data does not remove it.
    #[serde(default)]
    pub purged_by_privacy_purge: bool,
}
