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
}

#[derive(Deserialize)]
pub struct AuditFile {
    pub path: String,
    pub events: u64,
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

/// `reconcile` result (contract section 5.6).
#[derive(Deserialize)]
pub struct Reconcile {
    #[serde(default)]
    pub reconciled_at: Option<String>,
    pub drift_count: u64,
    pub capabilities: Vec<ReconcileEntry>,
}

#[derive(Deserialize)]
pub struct ReconcileEntry {
    pub capability: String,
    pub desired_state: Value,
    pub current_state: Value,
    pub drift: bool,
    #[serde(default = "default_true")]
    pub verified: bool,
}

fn default_true() -> bool {
    true
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
    }

    #[test]
    fn state_str_keeps_strings_bare_and_json_for_the_rest() {
        assert_eq!(state_str(&json!("enabled")), "enabled");
        assert_eq!(state_str(&json!(true)), "true");
        assert_eq!(state_str(&json!({"a": 1})), r#"{"a":1}"#);
    }
}
