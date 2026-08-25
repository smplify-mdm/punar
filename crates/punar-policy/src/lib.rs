//! Policy source precedence and merge logic.
//!
//! SPEC section 39 ("State Sources and Precedence") defines the precedence
//! chain and instructs: "Encode and test." Milestone 0 delivered the
//! [`PolicySource`] ordering and the [`resolve`] function that picks the
//! effective value for one setting. Milestone 4 adds the document layer on
//! top (docs/development/milestone-4.md section 3.2): [`SourceKind`] (the
//! seven-value `policy_source_kind` enum of
//! `schemas/policy/policy-source.json`), [`Provenance`], [`Classification`]
//! (SPEC section 43 drift classes), and [`merge`], which folds provenance-
//! tagged layer entries into an effective document per path via [`resolve`].
//! Loading real policy files stays in `punard` (the store owner); this crate
//! stays pure logic + serde.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

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

// ---------------------------------------------------------------------------
// Milestone 4: provenance, classification, and the document merge
// (docs/development/milestone-4.md section 3.2)
// ---------------------------------------------------------------------------

/// The seven state sources of SPEC section 39, spelled exactly as the
/// `policy_source_kind` enum of `schemas/policy/policy-source.json`
/// (snake_case on the wire; a test pins every string).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    OsHardSafetyConstraint,
    OrganizationBaseline,
    OrganizationRolePolicy,
    TemporaryApprovedException,
    LocalUserPreference,
    OsSecureDefault,
    DeviceSpecificOverride,
}

impl SourceKind {
    /// All source kinds, ladder order first (rank 1..6), then the rung-less
    /// `device_specific_override`.
    pub const ALL: [SourceKind; 7] = [
        SourceKind::OsHardSafetyConstraint,
        SourceKind::OrganizationBaseline,
        SourceKind::OrganizationRolePolicy,
        SourceKind::TemporaryApprovedException,
        SourceKind::LocalUserPreference,
        SourceKind::OsSecureDefault,
        SourceKind::DeviceSpecificOverride,
    ];

    /// The schema spelling (matches serde's snake_case rename).
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::OsHardSafetyConstraint => "os_hard_safety_constraint",
            SourceKind::OrganizationBaseline => "organization_baseline",
            SourceKind::OrganizationRolePolicy => "organization_role_policy",
            SourceKind::TemporaryApprovedException => "temporary_approved_exception",
            SourceKind::LocalUserPreference => "local_user_preference",
            SourceKind::OsSecureDefault => "os_secure_default",
            SourceKind::DeviceSpecificOverride => "device_specific_override",
        }
    }

    /// The fixed precedence rank of the six laddered kinds, per the
    /// documented rank table of `schemas/policy/policy-source.json`
    /// (1 = hard OS safety constraint … 6 = OS default; **lower wins**).
    /// `device_specific_override` has no fixed rung — the schema stores its
    /// rank as data — so it returns `None`, and loaders must take the
    /// stored `precedence_rank` instead.
    pub const fn fixed_rank(self) -> Option<u32> {
        match self {
            SourceKind::OsHardSafetyConstraint => Some(1),
            SourceKind::OrganizationBaseline => Some(2),
            SourceKind::OrganizationRolePolicy => Some(3),
            SourceKind::TemporaryApprovedException => Some(4),
            SourceKind::LocalUserPreference => Some(5),
            SourceKind::OsSecureDefault => Some(6),
            SourceKind::DeviceSpecificOverride => None,
        }
    }
}

/// The lowest (numerically) rank a user may override: rank 5 (their own
/// preference) and rank 6 (the OS default) are overridable; anything that
/// wins with a better rank pins the value (SPEC sections 39, 40).
pub const USER_OVERRIDE_MIN_RANK: u32 = 5;

/// Map a stored precedence rank onto the [`PolicySource`] ladder,
/// positionally: rank 1 behaves as the hard OS safety constraint rung,
/// rank 2 as organization-mandatory, … rank 6 (and anything below the
/// ladder) as the OS default rung. This is how `device_specific_override`
/// — whose rank is stored data, not schema-fixed — joins the merge.
pub fn policy_source_for_rank(rank: u32) -> PolicySource {
    match rank {
        0 | 1 => PolicySource::HardOsSafetyConstraint,
        2 => PolicySource::OrganizationMandatory,
        3 => PolicySource::OrganizationRole,
        4 => PolicySource::TemporaryApprovedException,
        5 => PolicySource::UserPreference,
        _ => PolicySource::OsDefault,
    }
}

/// Where an effective value came from — the explainability payload of
/// SPEC section 40 (`Source:` / `Policy:` lines) and the `source` object of
/// the `policy.effective` / `policy.explain` IPC results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub kind: SourceKind,
    /// Precedence rank (lower wins). Equals `kind.fixed_rank()` for the six
    /// laddered kinds; stored data for `device_specific_override`.
    pub rank: u32,
    /// Stable policy id, e.g. `personal-defaults` or `eng-baseline-v12`.
    pub policy_id: String,
    /// Human-readable source name, e.g. "Personal preference", "OS
    /// default", "Acme Engineering Baseline".
    pub source_name: String,
}

impl Provenance {
    /// The ladder rung this provenance merges at (see
    /// [`policy_source_for_rank`]).
    pub fn policy_source(&self) -> PolicySource {
        policy_source_for_rank(self.rank)
    }
}

/// SPEC section 43 drift classification — data in the effective document
/// (step 3 "classify"). Personal mode defaults every capability to
/// [`Classification::AutoRemediate`]; `approval_required` behaves as
/// `alert_only` until Milestone 9 delivers approvals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    AutoRemediate,
    AlertOnly,
    ApprovalRequired,
}

impl Classification {
    /// The wire spelling (matches serde's snake_case rename).
    pub fn as_str(self) -> &'static str {
        match self {
            Classification::AutoRemediate => "auto_remediate",
            Classification::AlertOnly => "alert_only",
            Classification::ApprovalRequired => "approval_required",
        }
    }
}

/// One layer's opinion about one path: the value plus where it came from
/// and how drift from it is classified.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayerValue<V> {
    pub value: V,
    pub provenance: Provenance,
    pub classification: Classification,
}

/// The winning entry for one path after the merge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EffectiveEntry<V> {
    pub value: V,
    pub provenance: Provenance,
    pub classification: Classification,
    /// `true` iff the winning rank is ≥ [`USER_OVERRIDE_MIN_RANK`]: a user
    /// may override the OS default or their own preference; anything above
    /// the User Preference rung pins the value (SPEC section 40).
    pub user_override_permitted: bool,
}

/// Merge provenance-tagged `(path, layer value)` entries into the effective
/// document: per path, the entry whose rank maps highest on the SPEC
/// section 39 ladder wins ([`resolve`] does the picking, so tie behavior is
/// identical: the **first** entry at the winning rung wins — callers order
/// layers, and the real loader rejects duplicate policy ids instead).
pub fn merge<V>(
    entries: impl IntoIterator<Item = (String, LayerValue<V>)>,
) -> BTreeMap<String, EffectiveEntry<V>> {
    let mut per_path: BTreeMap<String, Vec<(PolicySource, LayerValue<V>)>> = BTreeMap::new();
    for (path, layer_value) in entries {
        let source = layer_value.provenance.policy_source();
        per_path
            .entry(path)
            .or_default()
            .push((source, layer_value));
    }
    per_path
        .into_iter()
        .map(|(path, candidates)| {
            let resolved = resolve(candidates).expect("per-path candidate list is never empty");
            let winner = resolved.value;
            let user_override_permitted = winner.provenance.rank >= USER_OVERRIDE_MIN_RANK;
            (
                path,
                EffectiveEntry {
                    value: winner.value,
                    provenance: winner.provenance,
                    classification: winner.classification,
                    user_override_permitted,
                },
            )
        })
        .collect()
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

    // -- Milestone 4: SourceKind / Provenance / merge ------------------------

    /// Convenience constructors for merge tests.
    fn layer(
        kind: SourceKind,
        rank: u32,
        policy_id: &str,
        name: &str,
        value: &str,
        classification: Classification,
    ) -> LayerValue<String> {
        LayerValue {
            value: value.to_string(),
            provenance: Provenance {
                kind,
                rank,
                policy_id: policy_id.to_string(),
                source_name: name.to_string(),
            },
            classification,
        }
    }

    fn os_default(value: &str) -> LayerValue<String> {
        layer(
            SourceKind::OsSecureDefault,
            6,
            "personal-defaults",
            "OS default",
            value,
            Classification::AutoRemediate,
        )
    }

    fn user_pref(value: &str) -> LayerValue<String> {
        layer(
            SourceKind::LocalUserPreference,
            5,
            "personal-defaults",
            "Personal preference",
            value,
            Classification::AutoRemediate,
        )
    }

    #[test]
    fn source_kind_strings_match_the_policy_source_schema_enum() {
        // The policy_source_kind enum of schemas/policy/policy-source.json,
        // verbatim — the schema is the contract for these spellings.
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/policy/policy-source.json"))
                .unwrap();
        let schema_kinds: Vec<&str> = schema["$defs"]["policy_source_kind"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(schema_kinds.len(), SourceKind::ALL.len());
        for kind in SourceKind::ALL {
            assert!(
                schema_kinds.contains(&kind.as_str()),
                "{} missing from the schema enum",
                kind.as_str()
            );
            // serde spelling == as_str spelling == schema spelling.
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("{:?}", kind.as_str())
            );
            let back: SourceKind = serde_json::from_str(&format!("{:?}", kind.as_str())).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn fixed_ranks_match_the_schema_documented_ladder() {
        // policy-source.json precedence_rank description: 1 = hard OS safety
        // constraint, 2 = organization_baseline, 3 = organization_role_policy,
        // 4 = temporary_approved_exception, 5 = local_user_preference,
        // 6 = os_secure_default; device_specific_override has no fixed rung.
        let expected = [
            (SourceKind::OsHardSafetyConstraint, Some(1)),
            (SourceKind::OrganizationBaseline, Some(2)),
            (SourceKind::OrganizationRolePolicy, Some(3)),
            (SourceKind::TemporaryApprovedException, Some(4)),
            (SourceKind::LocalUserPreference, Some(5)),
            (SourceKind::OsSecureDefault, Some(6)),
            (SourceKind::DeviceSpecificOverride, None),
        ];
        for (kind, rank) in expected {
            assert_eq!(kind.fixed_rank(), rank, "{}", kind.as_str());
        }
    }

    #[test]
    fn rank_maps_positionally_onto_the_ladder() {
        assert_eq!(
            policy_source_for_rank(1),
            PolicySource::HardOsSafetyConstraint
        );
        assert_eq!(
            policy_source_for_rank(2),
            PolicySource::OrganizationMandatory
        );
        assert_eq!(policy_source_for_rank(3), PolicySource::OrganizationRole);
        assert_eq!(
            policy_source_for_rank(4),
            PolicySource::TemporaryApprovedException
        );
        assert_eq!(policy_source_for_rank(5), PolicySource::UserPreference);
        assert_eq!(policy_source_for_rank(6), PolicySource::OsDefault);
        // Below the ladder (device_specific_override at an explicit deep
        // rank) merges at the OS-default rung.
        assert_eq!(policy_source_for_rank(9), PolicySource::OsDefault);
    }

    /// SPEC section 40's org scenario, with the Acme fixture identity
    /// (fixtures/organizations/acme): the `eng-baseline-v12`
    /// organization_baseline (rank 2) wins over a user preference; the
    /// override is not permitted. Engine-level only — nothing org renders
    /// in the VM before M5 (design section 8).
    #[test]
    fn acme_org_baseline_beats_user_preference_and_pins_the_value() {
        let effective = merge(vec![
            ("security.firewall".to_string(), os_default("enabled")),
            ("security.firewall".to_string(), user_pref("disabled")),
            (
                "security.firewall".to_string(),
                layer(
                    SourceKind::OrganizationBaseline,
                    2,
                    "eng-baseline-v12",
                    "Acme Engineering Baseline",
                    "enabled",
                    Classification::AutoRemediate,
                ),
            ),
        ]);
        let entry = &effective["security.firewall"];
        assert_eq!(entry.value, "enabled");
        assert_eq!(entry.provenance.kind, SourceKind::OrganizationBaseline);
        assert_eq!(entry.provenance.rank, 2);
        assert_eq!(entry.provenance.policy_id, "eng-baseline-v12");
        assert_eq!(entry.provenance.source_name, "Acme Engineering Baseline");
        assert!(!entry.user_override_permitted, "rank 2 pins the value");
    }

    #[test]
    fn personal_mode_user_preference_beats_os_default_and_stays_overridable() {
        let effective = merge(vec![
            ("security.firewall".to_string(), os_default("enabled")),
            ("security.firewall".to_string(), user_pref("disabled")),
            ("time.timezone".to_string(), os_default("UTC")),
        ]);
        let firewall = &effective["security.firewall"];
        assert_eq!(firewall.value, "disabled");
        assert_eq!(firewall.provenance.kind, SourceKind::LocalUserPreference);
        assert_eq!(firewall.provenance.rank, 5);
        assert!(firewall.user_override_permitted);

        let timezone = &effective["time.timezone"];
        assert_eq!(timezone.value, "UTC");
        assert_eq!(timezone.provenance.kind, SourceKind::OsSecureDefault);
        assert_eq!(timezone.provenance.rank, 6);
        assert!(
            timezone.user_override_permitted,
            "OS default is overridable"
        );
    }

    #[test]
    fn exception_rung_beats_user_preference_and_carries_classification() {
        let effective = merge(vec![
            ("security.firewall".to_string(), user_pref("enabled")),
            (
                "security.firewall".to_string(),
                layer(
                    SourceKind::TemporaryApprovedException,
                    4,
                    "exc-2026-014",
                    "Approved exception",
                    "disabled",
                    Classification::AlertOnly,
                ),
            ),
        ]);
        let entry = &effective["security.firewall"];
        assert_eq!(entry.value, "disabled");
        assert_eq!(
            entry.provenance.kind,
            SourceKind::TemporaryApprovedException
        );
        assert_eq!(entry.classification, Classification::AlertOnly);
        assert!(!entry.user_override_permitted);
    }

    #[test]
    fn device_specific_override_merges_at_its_stored_rank() {
        // Stored rank 2: ties with organization_baseline's rung; the first
        // entry at the winning rung wins (resolve semantics, pinned above).
        let effective = merge(vec![
            (
                "security.firewall".to_string(),
                layer(
                    SourceKind::DeviceSpecificOverride,
                    2,
                    "dev-override-7",
                    "Device override",
                    "disabled",
                    Classification::AutoRemediate,
                ),
            ),
            (
                "security.firewall".to_string(),
                layer(
                    SourceKind::OrganizationBaseline,
                    2,
                    "eng-baseline-v12",
                    "Acme Engineering Baseline",
                    "enabled",
                    Classification::AutoRemediate,
                ),
            ),
        ]);
        let entry = &effective["security.firewall"];
        assert_eq!(entry.value, "disabled");
        assert_eq!(entry.provenance.kind, SourceKind::DeviceSpecificOverride);
        assert!(!entry.user_override_permitted);
    }

    #[test]
    fn merge_of_nothing_is_empty() {
        let effective: BTreeMap<String, EffectiveEntry<String>> = merge(Vec::new());
        assert!(effective.is_empty());
    }

    #[test]
    fn classification_serde_uses_spec_43_spellings() {
        for (classification, wire) in [
            (Classification::AutoRemediate, "\"auto_remediate\""),
            (Classification::AlertOnly, "\"alert_only\""),
            (Classification::ApprovalRequired, "\"approval_required\""),
        ] {
            assert_eq!(serde_json::to_string(&classification).unwrap(), wire);
            let back: Classification = serde_json::from_str(wire).unwrap();
            assert_eq!(back, classification);
        }
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
