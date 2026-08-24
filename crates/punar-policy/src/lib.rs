//! Policy source precedence and merge logic.
//!
//! SPEC section 39 ("State Sources and Precedence") defines the precedence
//! chain and instructs: "Encode and test." This crate delivers exactly that
//! for Milestone 0: the [`PolicySource`] ordering and the [`resolve`]
//! function that picks the effective value for one setting. Loading real
//! policy documents, schemas, and reconciliation arrive in Milestones 4–5.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Where a value for a setting came from, ordered by SPEC section 39
/// precedence:
///
/// ```text
/// Hard OS Safety Constraint
///         >
/// Organization Mandatory Policy
///         >
/// Organization Role Policy
///         >
/// Temporary Approved Exception
///         >
/// User Preference
///         >
/// OS Default
/// ```
///
/// Variants are declared lowest-precedence first so the derived [`Ord`]
/// agrees with the chain: `a > b` means source `a` beats source `b`. A unit
/// test pins the full ordering against the SPEC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySource {
    OsDefault,
    UserPreference,
    TemporaryApprovedException,
    OrganizationRole,
    OrganizationMandatory,
    HardOsSafetyConstraint,
}

impl PolicySource {
    /// All sources, highest precedence first (SPEC section 39 order).
    pub const IN_PRECEDENCE_ORDER: [PolicySource; 6] = [
        PolicySource::HardOsSafetyConstraint,
        PolicySource::OrganizationMandatory,
        PolicySource::OrganizationRole,
        PolicySource::TemporaryApprovedException,
        PolicySource::UserPreference,
        PolicySource::OsDefault,
    ];
}

/// The effective value for one setting, plus the source that won.
///
/// Feeds `punarctl policy explain` (SPEC section 40): explaining a setting
/// requires knowing both the value and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolved<V> {
    pub value: V,
    pub source: PolicySource,
}

/// Merge the `(source, value)` entries for **one** setting into its effective
/// value and winning source.
///
/// Rules:
///
/// - the entry whose source has the highest SPEC section 39 precedence wins;
/// - if several entries share the highest-precedence source, the first such
///   entry wins (callers that can produce duplicates must order them; the
///   real policy loader in Milestone 4 is expected to reject duplicates
///   instead);
/// - no entries means no opinion: `None`. Even the OS default is an entry,
///   not something this function invents.
///
/// Returns `None` only for an empty input.
pub fn resolve<V>(entries: impl IntoIterator<Item = (PolicySource, V)>) -> Option<Resolved<V>> {
    entries
        .into_iter()
        .fold(None, |best: Option<Resolved<V>>, (source, value)| {
            match best {
                // Strictly-greater keeps the first entry on ties.
                Some(current) if source > current.source => Some(Resolved { value, source }),
                Some(current) => Some(current),
                None => Some(Resolved { value, source }),
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_matches_spec_section_39_chain() {
        assert!(PolicySource::HardOsSafetyConstraint > PolicySource::OrganizationMandatory);
        assert!(PolicySource::OrganizationMandatory > PolicySource::OrganizationRole);
        assert!(PolicySource::OrganizationRole > PolicySource::TemporaryApprovedException);
        assert!(PolicySource::TemporaryApprovedException > PolicySource::UserPreference);
        assert!(PolicySource::UserPreference > PolicySource::OsDefault);
    }

    #[test]
    fn in_precedence_order_is_strictly_descending() {
        let order = PolicySource::IN_PRECEDENCE_ORDER;
        for pair in order.windows(2) {
            assert!(pair[0] > pair[1], "{:?} should beat {:?}", pair[0], pair[1]);
        }
    }

    /// SPEC section 43 firewall example: the organization mandates the
    /// firewall enabled, the user prefers it disabled. Effective state is
    /// enabled, and the winner is the organization mandatory policy.
    #[test]
    fn firewall_org_mandate_beats_user_preference() {
        let effective = resolve([
            (PolicySource::OsDefault, true),
            (PolicySource::UserPreference, false),
            (PolicySource::OrganizationMandatory, true),
        ])
        .unwrap();
        assert!(effective.value, "effective firewall state must be enabled");
        assert_eq!(effective.source, PolicySource::OrganizationMandatory);
    }

    #[test]
    fn hard_os_safety_constraint_beats_everything() {
        let effective = resolve([
            (PolicySource::OrganizationMandatory, "org"),
            (PolicySource::HardOsSafetyConstraint, "hard"),
            (PolicySource::OrganizationRole, "role"),
            (PolicySource::TemporaryApprovedException, "exception"),
            (PolicySource::UserPreference, "user"),
            (PolicySource::OsDefault, "default"),
        ])
        .unwrap();
        assert_eq!(effective.value, "hard");
        assert_eq!(effective.source, PolicySource::HardOsSafetyConstraint);
    }

    #[test]
    fn temporary_approved_exception_beats_user_preference() {
        let effective = resolve([
            (PolicySource::UserPreference, "user"),
            (PolicySource::TemporaryApprovedException, "exception"),
        ])
        .unwrap();
        assert_eq!(effective.value, "exception");
        assert_eq!(effective.source, PolicySource::TemporaryApprovedException);
    }

    #[test]
    fn organization_role_yields_to_organization_mandatory() {
        let effective = resolve([
            (PolicySource::OrganizationRole, "role"),
            (PolicySource::OrganizationMandatory, "mandatory"),
        ])
        .unwrap();
        assert_eq!(effective.value, "mandatory");
        assert_eq!(effective.source, PolicySource::OrganizationMandatory);
    }

    #[test]
    fn user_preference_wins_when_nothing_above_it_speaks() {
        let effective = resolve([
            (PolicySource::OsDefault, "default"),
            (PolicySource::UserPreference, "user"),
        ])
        .unwrap();
        assert_eq!(effective.value, "user");
        assert_eq!(effective.source, PolicySource::UserPreference);
    }

    #[test]
    fn os_default_wins_alone() {
        let effective = resolve([(PolicySource::OsDefault, 42)]).unwrap();
        assert_eq!(effective.value, 42);
        assert_eq!(effective.source, PolicySource::OsDefault);
    }

    #[test]
    fn empty_input_resolves_to_none() {
        assert_eq!(resolve(Vec::<(PolicySource, bool)>::new()), None);
    }

    #[test]
    fn winner_does_not_depend_on_entry_order() {
        let forward = resolve([
            (PolicySource::UserPreference, "user"),
            (PolicySource::OrganizationMandatory, "org"),
            (PolicySource::OsDefault, "default"),
        ])
        .unwrap();
        let reversed = resolve([
            (PolicySource::OsDefault, "default"),
            (PolicySource::OrganizationMandatory, "org"),
            (PolicySource::UserPreference, "user"),
        ])
        .unwrap();
        assert_eq!(forward, reversed);
    }

    #[test]
    fn first_entry_wins_a_tie_between_equal_sources() {
        let effective = resolve([
            (PolicySource::UserPreference, "first"),
            (PolicySource::UserPreference, "second"),
        ])
        .unwrap();
        assert_eq!(effective.value, "first");
        assert_eq!(effective.source, PolicySource::UserPreference);
    }

    #[test]
    fn policy_source_serde_round_trips_in_snake_case() {
        let expected = [
            (
                PolicySource::HardOsSafetyConstraint,
                "\"hard_os_safety_constraint\"",
            ),
            (
                PolicySource::OrganizationMandatory,
                "\"organization_mandatory\"",
            ),
            (PolicySource::OrganizationRole, "\"organization_role\""),
            (
                PolicySource::TemporaryApprovedException,
                "\"temporary_approved_exception\"",
            ),
            (PolicySource::UserPreference, "\"user_preference\""),
            (PolicySource::OsDefault, "\"os_default\""),
        ];
        for (source, json) in expected {
            assert_eq!(serde_json::to_string(&source).unwrap(), json);
            let back: PolicySource = serde_json::from_str(json).unwrap();
            assert_eq!(source, back);
        }
    }
}
