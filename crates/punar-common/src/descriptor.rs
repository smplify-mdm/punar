//! Capability registry descriptor — the typed form of
//! `schemas/capability/capability-descriptor.json` (SPEC section 41).
//!
//! `punard` serializes these into `capabilities.list` / `capabilities.get` /
//! `capabilities.set` results; `punarctl` renders them (and `--json` prints
//! the wire object verbatim). Field names match the schema exactly —
//! machine-emitted runtime records are snake_case.
//!
//! State values (`current_state`, `desired_state`, `allowed_desired_states`
//! items) are [`serde_json::Value`]: the schema's `state_value` def is
//! deliberately open ("Consumers must not assume string") because the value
//! space is capability-specific and authoritatively described by
//! `state_schema`. State values are **data** matched against a capability's
//! declared state space — never text that gets executed (SPEC sections 10,
//! 60).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::CapabilityId;

/// Risk level of mutating a capability (SPEC sections 28, 41;
/// `schemas/common/defs.json#/$defs/risk`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    /// All risk levels, low to high.
    pub const ALL: [Risk; 3] = [Risk::Low, Risk::Medium, Risk::High];

    /// The wire spelling (`"low"` / `"medium"` / `"high"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }
}

/// One entry in the capability registry, exactly per
/// `schemas/capability/capability-descriptor.json`.
///
/// The first nine fields are schema-required; the rest are optional and are
/// omitted (not `null`) when absent, which is what the schema expects.
///
/// Serde note: descriptors travel server→client inside IPC results, and the
/// wire contract (docs/api/ipc.md section 3.3) requires clients to tolerate
/// unknown *result* fields — so this type does **not** use
/// `deny_unknown_fields`. Strictness on emit comes from construction: a
/// typed struct cannot serialize fields it does not have, which is how the
/// schema's `additionalProperties: false` is honored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityDescriptor {
    /// Dotted capability id, e.g. `security.firewall`.
    pub capability: CapabilityId,
    /// Whether the capability is supported on this device/build.
    pub supported: bool,
    /// Observed, normalized actual state (observed live at request time in
    /// M3 — never cached).
    pub current_state: Value,
    /// Desired state as resolved from desired-state sources.
    pub desired_state: Value,
    /// Whether the state can be changed on this device.
    pub mutable: bool,
    /// Whether applying a change requires a reboot.
    pub requires_reboot: bool,
    /// Risk level of mutating this capability.
    pub risk: Risk,
    /// Management authority (`"local"` in personal mode; `"smplify"` only
    /// after enrollment, M5+).
    pub managed_by: String,
    /// Verification mechanism used after apply (e.g. `"nftables"`).
    pub verification: String,
    /// JSON Schema for the state value space (SPEC section 41 "must
    /// describe schema").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_schema: Option<Value>,
    /// Enumerated acceptable desired states, where enumerable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_desired_states: Option<Vec<Value>>,
    /// Privilege level required to mutate (`"root"` for all M3 capabilities).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privilege_required: Option<String>,
    /// Approval requirement, expressed with the shared decision enum
    /// (`allow` = no approval gate; approvals arrive M9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_requirement: Option<crate::Decision>,
    /// Category attached to audit events for this capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_category: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decision;

    /// The shipped shape-reference example for the descriptor schema.
    const GOLDEN: &str =
        include_str!("../../../schemas/capability/examples/security-firewall.json");

    fn m3_firewall_descriptor() -> CapabilityDescriptor {
        CapabilityDescriptor {
            capability: CapabilityId::new("security.firewall").unwrap(),
            supported: true,
            current_state: Value::String("enabled".into()),
            desired_state: Value::String("enabled".into()),
            mutable: true,
            requires_reboot: false,
            risk: Risk::High,
            managed_by: "local".to_string(),
            verification: "nftables".to_string(),
            state_schema: Some(serde_json::json!({"enum": ["enabled", "disabled"]})),
            allowed_desired_states: Some(vec![
                Value::String("enabled".into()),
                Value::String("disabled".into()),
            ]),
            privilege_required: Some("root".to_string()),
            approval_requirement: Some(Decision::Allow),
            audit_category: Some("security".to_string()),
        }
    }

    #[test]
    fn golden_schema_example_deserializes_and_round_trips() {
        let descriptor: CapabilityDescriptor = serde_json::from_str(GOLDEN).unwrap();
        assert_eq!(descriptor.capability.as_str(), "security.firewall");
        assert_eq!(descriptor.risk, Risk::High);
        assert_eq!(descriptor.managed_by, "smplify");
        assert_eq!(descriptor.current_state, Value::String("enabled".into()));
        assert_eq!(descriptor.state_schema, None);

        // Value-level round trip: optional fields absent in the golden file
        // must stay absent (omitted, not null) on re-serialization.
        let golden_value: Value = serde_json::from_str(GOLDEN).unwrap();
        let reserialized = serde_json::to_value(&descriptor).unwrap();
        assert_eq!(reserialized, golden_value);
    }

    #[test]
    fn full_m3_descriptor_round_trips() {
        let descriptor = m3_firewall_descriptor();
        let json = serde_json::to_string(&descriptor).unwrap();
        let back: CapabilityDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(descriptor, back);
    }

    #[test]
    fn serialized_field_names_match_the_schema() {
        let value = serde_json::to_value(m3_firewall_descriptor()).unwrap();
        let object = value.as_object().unwrap();
        let schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/capability/capability-descriptor.json"
        ))
        .unwrap();

        // Every schema-required field is present.
        for required in schema["required"].as_array().unwrap() {
            let name = required.as_str().unwrap();
            assert!(object.contains_key(name), "missing required field {name:?}");
        }
        // Every emitted field is a schema property (additionalProperties:
        // false on the shipped contract).
        let properties = schema["properties"].as_object().unwrap();
        for key in object.keys() {
            assert!(properties.contains_key(key), "field {key:?} not in schema");
        }
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
    }

    #[test]
    fn optional_fields_are_omitted_when_none() {
        let descriptor: CapabilityDescriptor = serde_json::from_str(GOLDEN).unwrap();
        let value = serde_json::to_value(&descriptor).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 9, "only the required fields: {object:?}");
        for absent in [
            "state_schema",
            "allowed_desired_states",
            "privilege_required",
            "approval_requirement",
            "audit_category",
        ] {
            assert!(!object.contains_key(absent), "{absent:?} should be omitted");
        }
    }

    #[test]
    fn risk_serializes_to_defs_enum_values() {
        let defs: Value =
            serde_json::from_str(include_str!("../../../schemas/common/defs.json")).unwrap();
        let allowed = defs["$defs"]["risk"]["enum"].as_array().unwrap();
        for risk in Risk::ALL {
            let wire = serde_json::to_value(risk).unwrap();
            assert!(allowed.contains(&wire), "{wire} not in schema risk enum");
            assert_eq!(wire, Value::String(risk.as_str().into()));
        }
        assert!(serde_json::from_str::<Risk>("\"critical\"").is_err());
    }

    #[test]
    fn descriptor_tolerates_unknown_result_fields() {
        // Wire contract section 3.3: clients tolerate unknown fields in
        // results. A newer daemon may add descriptor fields under v1.
        let mut value: Value = serde_json::from_str(GOLDEN).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("added_in_a_future_milestone".to_string(), Value::Bool(true));
        let descriptor: CapabilityDescriptor = serde_json::from_value(value).unwrap();
        assert_eq!(descriptor.capability.as_str(), "security.firewall");
    }
}
