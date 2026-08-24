use serde::{Deserialize, Serialize};

/// Authorization decision values, per SPEC section 20 ("AI Authority Model").
///
/// The SPEC defines exactly three decision values: `allow`, `deny`,
/// `approval_required`. Serialized in `snake_case` to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    ApprovalRequired,
}

impl Decision {
    /// All decision values, in SPEC section 20 order.
    pub const ALL: [Decision; 3] = [Decision::Allow, Decision::Deny, Decision::ApprovalRequired];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_to_spec_names() {
        assert_eq!(
            serde_json::to_string(&Decision::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(serde_json::to_string(&Decision::Deny).unwrap(), "\"deny\"");
        assert_eq!(
            serde_json::to_string(&Decision::ApprovalRequired).unwrap(),
            "\"approval_required\""
        );
    }

    #[test]
    fn serde_round_trips_every_variant() {
        for decision in Decision::ALL {
            let json = serde_json::to_string(&decision).unwrap();
            let back: Decision = serde_json::from_str(&json).unwrap();
            assert_eq!(decision, back);
        }
    }

    #[test]
    fn unknown_decision_is_rejected() {
        assert!(serde_json::from_str::<Decision>("\"maybe\"").is_err());
    }
}
