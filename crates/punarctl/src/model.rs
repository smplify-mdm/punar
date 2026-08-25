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
