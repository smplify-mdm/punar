use serde::{Deserialize, Serialize};

/// Identity types recognized by Punar as first-class principals.
///
/// SPEC section 18 ("AI-Native Architecture") lists these identity types:
/// Device, Human, Organization, Project, Application, AI Agent, Service.
///
/// Serialized in `snake_case`; `AiAgent` serializes as `"ai_agent"`, which is
/// the spelling the SPEC section 53 audit example uses for `source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Device,
    Human,
    Organization,
    Project,
    Application,
    AiAgent,
    Service,
}

impl PrincipalKind {
    /// All principal kinds, in SPEC section 18 order.
    pub const ALL: [PrincipalKind; 7] = [
        PrincipalKind::Device,
        PrincipalKind::Human,
        PrincipalKind::Organization,
        PrincipalKind::Project,
        PrincipalKind::Application,
        PrincipalKind::AiAgent,
        PrincipalKind::Service,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_to_expected_snake_case_names() {
        let expected = [
            (PrincipalKind::Device, "\"device\""),
            (PrincipalKind::Human, "\"human\""),
            (PrincipalKind::Organization, "\"organization\""),
            (PrincipalKind::Project, "\"project\""),
            (PrincipalKind::Application, "\"application\""),
            (PrincipalKind::AiAgent, "\"ai_agent\""),
            (PrincipalKind::Service, "\"service\""),
        ];
        for (kind, json) in expected {
            assert_eq!(serde_json::to_string(&kind).unwrap(), json);
        }
    }

    #[test]
    fn serde_round_trips_every_variant() {
        for kind in PrincipalKind::ALL {
            let json = serde_json::to_string(&kind).unwrap();
            let back: PrincipalKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn unknown_principal_kind_is_rejected() {
        assert!(serde_json::from_str::<PrincipalKind>("\"robot\"").is_err());
    }
}
