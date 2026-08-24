use serde::{Deserialize, Serialize};

use crate::{Decision, PrincipalKind};

/// A structured audit event, with the fields of the SPEC section 53 example.
///
/// ```json
/// {
///   "event_id": "evt_123",
///   "timestamp": "...",
///   "device_id": "dev_123",
///   "user_id": "alice@acme.com",
///   "agent_session_id": "agt_123",
///   "project_id": "atlas",
///   "source": "ai_agent",
///   "action": "credential.request",
///   "resource": "aws-dev",
///   "decision": "allow",
///   "policy_ids": ["eng-ai-v3"],
///   "result": "success"
/// }
/// ```
///
/// Milestone 0 decisions, to be revisited when `punard` emits real events
/// (Milestone 3):
///
/// - `timestamp` is an RFC 3339 string rather than a typed time value, so
///   Milestone 0 carries no clock/time dependency;
/// - `user_id`, `agent_session_id`, `project_id`, and `resource` are
///   optional: not every event has a human, an agent session, a project, or
///   a target resource;
/// - `result` stays a free-form string (`"success"` in the SPEC example);
///   the SPEC does not enumerate result values yet.
///
/// SPEC section 53 also rules: never log passwords, secret values, tokens,
/// private keys, prompt contents by default, or source code. `AuditEvent`
/// deliberately has no field for payload or secret material; anything secret
/// must live behind [`crate::Redacted`], which serializes as `"[redacted]"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    /// RFC 3339 timestamp string (see type docs).
    pub timestamp: String,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Kind of principal that caused the event (`"ai_agent"` in the SPEC
    /// example).
    pub source: PrincipalKind,
    /// Dotted action name, such as `credential.request`.
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    pub decision: Decision,
    #[serde(default)]
    pub policy_ids: Vec<String>,
    pub result: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_example() -> AuditEvent {
        AuditEvent {
            event_id: "evt_123".to_string(),
            timestamp: "2026-08-24T12:00:00Z".to_string(),
            device_id: "dev_123".to_string(),
            user_id: Some("alice@acme.com".to_string()),
            agent_session_id: Some("agt_123".to_string()),
            project_id: Some("atlas".to_string()),
            source: PrincipalKind::AiAgent,
            action: "credential.request".to_string(),
            resource: Some("aws-dev".to_string()),
            decision: Decision::Allow,
            policy_ids: vec!["eng-ai-v3".to_string()],
            result: "success".to_string(),
        }
    }

    #[test]
    fn serde_round_trips() {
        let event = spec_example();
        let json = serde_json::to_string(&event).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn deserializes_the_spec_section_53_example() {
        let json = r#"{
            "event_id": "evt_123",
            "timestamp": "2026-08-24T12:00:00Z",
            "device_id": "dev_123",
            "user_id": "alice@acme.com",
            "agent_session_id": "agt_123",
            "project_id": "atlas",
            "source": "ai_agent",
            "action": "credential.request",
            "resource": "aws-dev",
            "decision": "allow",
            "policy_ids": ["eng-ai-v3"],
            "result": "success"
        }"#;
        let event: AuditEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event, spec_example());
    }

    #[test]
    fn optional_fields_may_be_absent() {
        let json = r#"{
            "event_id": "evt_9",
            "timestamp": "2026-08-24T12:00:00Z",
            "device_id": "dev_123",
            "source": "service",
            "action": "reconcile.run",
            "decision": "allow",
            "result": "success"
        }"#;
        let event: AuditEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.user_id, None);
        assert_eq!(event.agent_session_id, None);
        assert_eq!(event.project_id, None);
        assert_eq!(event.resource, None);
        assert!(event.policy_ids.is_empty());

        let back: AuditEvent =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn serialized_field_names_match_the_spec() {
        let value = serde_json::to_value(spec_example()).unwrap();
        let object = value.as_object().unwrap();
        for field in [
            "event_id",
            "timestamp",
            "device_id",
            "user_id",
            "agent_session_id",
            "project_id",
            "source",
            "action",
            "resource",
            "decision",
            "policy_ids",
            "result",
        ] {
            assert!(object.contains_key(field), "missing field {field:?}");
        }
        assert_eq!(object["source"], "ai_agent");
        assert_eq!(object["decision"], "allow");
    }
}
