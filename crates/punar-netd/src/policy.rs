//! Strict project-network policy loading and restrictive resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    Cidr, Decision, ModelError, ZoneDefinition, ZoneMembership, validate_project_id,
    validate_zone_name,
};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("project manifest is invalid: {0}")]
    Manifest(String),
    #[error("project network policy is invalid: {0}")]
    Policy(String),
    #[error("zone membership is invalid: {0}")]
    Membership(String),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("project policy names {policy:?}, but the manifest names {manifest:?}")]
    ProjectMismatch { policy: String, manifest: String },
    #[error("network rule names unknown zone {0:?}")]
    UnknownZone(String),
    #[error("network rule names zone {0:?} more than once")]
    DuplicateRule(String),
    #[error("zone definition names {0:?} more than once")]
    DuplicateZone(String),
    #[error("the internet residual cannot carry CIDR members")]
    InternetHasMembers,
    #[error("zone {zone:?} display-name address {address} is outside all of that zone's CIDRs")]
    AddressNameOutsideZone { zone: String, address: IpAddr },
    #[error("zones {left:?} and {right:?} contain overlapping CIDRs {left_cidr} and {right_cidr}")]
    OverlappingZones {
        left: String,
        right: String,
        left_cidr: Cidr,
        right_cidr: Cidr,
    },
    #[error("the residual zone named internet must be the only zone with kind internet")]
    InvalidInternetZone,
    #[error("expires_at is supported only for approval_required rules")]
    UnsupportedExpiry,
    #[error("approval expiry {0:?} is not a valid RFC 3339 timestamp")]
    InvalidExpiry(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundBy {
    ProjectNetworkPolicy,
    Manifest,
    Both,
    Residual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveRule {
    pub zone: String,
    pub decision: Decision,
    pub bound_by: BoundBy,
    pub manifest_decision: Option<Decision>,
    pub policy_decision: Option<Decision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerNetwork {
    pub mode: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompiledProject {
    pub project_id: String,
    pub rules: Vec<EffectiveRule>,
    pub container_network: ContainerNetwork,
}

impl CompiledProject {
    pub fn rule(&self, zone: &str) -> Option<&EffectiveRule> {
        self.rules.iter().find(|rule| rule.zone == zone)
    }
}

#[derive(Debug, Deserialize)]
struct ManifestDoc {
    project: ManifestProject,
    permissions: ManifestPermissions,
}

#[derive(Debug, Deserialize)]
struct ManifestProject {
    name: String,
}

#[derive(Debug, Deserialize)]
struct ManifestPermissions {
    network: BTreeMap<String, Decision>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDoc {
    project_id: String,
    #[serde(default)]
    display_name: Option<String>,
    rules: Vec<PolicyRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRule {
    zone: String,
    decision: Decision,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MembershipDoc {
    v: u64,
    zones: BTreeMap<String, MembershipZone>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MembershipZone {
    cidrs: Vec<String>,
    #[serde(default)]
    names: BTreeMap<String, String>,
}

pub fn index_zones(
    zones: Vec<ZoneDefinition>,
) -> Result<BTreeMap<String, ZoneDefinition>, PolicyError> {
    let mut indexed = BTreeMap::new();
    for zone in zones {
        zone.validate()?;
        let name = zone.name.clone();
        if indexed.insert(name.clone(), zone).is_some() {
            return Err(PolicyError::DuplicateZone(name));
        }
    }
    if !indexed.contains_key("internet") {
        return Err(PolicyError::UnknownZone("internet".to_string()));
    }
    if indexed["internet"].kind != crate::model::ZoneKind::Internet
        || indexed
            .iter()
            .any(|(name, zone)| name != "internet" && zone.kind == crate::model::ZoneKind::Internet)
    {
        return Err(PolicyError::InvalidInternetZone);
    }
    Ok(indexed)
}

pub fn parse_zone_memberships(
    input: &str,
    zones: &BTreeMap<String, ZoneDefinition>,
) -> Result<BTreeMap<String, ZoneMembership>, PolicyError> {
    let raw: MembershipDoc =
        serde_json::from_str(input).map_err(|e| PolicyError::Membership(e.to_string()))?;
    if raw.v != 1 {
        return Err(PolicyError::Membership(format!(
            "unsupported membership version {}",
            raw.v
        )));
    }
    let mut output = BTreeMap::new();
    for (name, membership) in raw.zones {
        validate_zone_name(&name)?;
        if !zones.contains_key(&name) {
            return Err(PolicyError::UnknownZone(name));
        }
        if name == "internet" && (!membership.cidrs.is_empty() || !membership.names.is_empty()) {
            return Err(PolicyError::InternetHasMembers);
        }
        let mut cidrs = BTreeSet::new();
        for value in membership.cidrs {
            cidrs.insert(Cidr::parse(&value)?);
        }
        let cidrs: Vec<Cidr> = cidrs.into_iter().collect();
        let mut names = BTreeMap::new();
        for (address, display) in membership.names {
            let parsed = address
                .parse::<IpAddr>()
                .map_err(|_| ModelError::InvalidAddressName(address.clone()))?;
            if display.is_empty() || display.len() > 255 || display.chars().any(char::is_control) {
                return Err(PolicyError::Membership(format!(
                    "display name for {address:?} is empty, too long, or contains a control character"
                )));
            }
            if !cidrs.iter().any(|cidr| cidr.contains(parsed)) {
                return Err(PolicyError::AddressNameOutsideZone {
                    zone: name.clone(),
                    address: parsed,
                });
            }
            names.insert(parsed, display);
        }
        output.insert(name, ZoneMembership { cidrs, names });
    }
    let entries: Vec<_> = output.iter().collect();
    for (index, (left_name, left)) in entries.iter().enumerate() {
        for (right_name, right) in entries.iter().skip(index + 1) {
            for left_cidr in &left.cidrs {
                for right_cidr in &right.cidrs {
                    if left_cidr.overlaps(*right_cidr) {
                        return Err(PolicyError::OverlappingZones {
                            left: (*left_name).clone(),
                            right: (*right_name).clone(),
                            left_cidr: *left_cidr,
                            right_cidr: *right_cidr,
                        });
                    }
                }
            }
        }
    }
    Ok(output)
}

pub fn compile_project(
    manifest_yaml: &str,
    policy_json: &str,
    zones: &BTreeMap<String, ZoneDefinition>,
) -> Result<CompiledProject, PolicyError> {
    let manifest: ManifestDoc =
        serde_norway::from_str(manifest_yaml).map_err(|e| PolicyError::Manifest(e.to_string()))?;
    let policy: PolicyDoc =
        serde_json::from_str(policy_json).map_err(|e| PolicyError::Policy(e.to_string()))?;
    let _ = &policy.display_name;
    validate_project_id(&manifest.project.name)?;
    validate_project_id(&policy.project_id)?;
    if manifest.project.name != policy.project_id {
        return Err(PolicyError::ProjectMismatch {
            policy: policy.project_id,
            manifest: manifest.project.name,
        });
    }

    for zone in manifest.permissions.network.keys() {
        validate_zone_name(zone)?;
        if !zones.contains_key(zone) {
            return Err(PolicyError::UnknownZone(zone.clone()));
        }
    }
    let mut policy_rules = BTreeMap::new();
    for rule in policy.rules {
        validate_zone_name(&rule.zone)?;
        if !zones.contains_key(&rule.zone) {
            return Err(PolicyError::UnknownZone(rule.zone));
        }
        if let Some(expiry) = &rule.expires_at {
            if rule.decision != Decision::ApprovalRequired {
                return Err(PolicyError::UnsupportedExpiry);
            }
            if punar_common::time::unix_seconds_from_rfc3339(expiry).is_none() {
                return Err(PolicyError::InvalidExpiry(expiry.clone()));
            }
        }
        let zone = rule.zone.clone();
        if policy_rules.insert(zone.clone(), rule).is_some() {
            return Err(PolicyError::DuplicateRule(zone));
        }
    }

    let mut rules = Vec::with_capacity(zones.len());
    for name in zones.keys() {
        let manifest_decision = manifest.permissions.network.get(name).copied();
        let policy_decision = policy_rules.get(name).map(|rule| rule.decision);
        let (decision, bound_by) = match (manifest_decision, policy_decision) {
            (Some(left), Some(right)) if left == right => (left, BoundBy::Both),
            (Some(left), Some(right)) if left.strictness() > right.strictness() => {
                (left, BoundBy::Manifest)
            }
            (Some(_), Some(right)) => (right, BoundBy::ProjectNetworkPolicy),
            (Some(left), None) => (left, BoundBy::Manifest),
            (None, Some(right)) => (right, BoundBy::ProjectNetworkPolicy),
            (None, None) => (Decision::Deny, BoundBy::Residual),
        };
        rules.push(EffectiveRule {
            zone: name.clone(),
            decision,
            bound_by,
            manifest_decision,
            policy_decision,
        });
    }

    let any_allow = rules.iter().any(|rule| rule.decision == Decision::Allow);
    Ok(CompiledProject {
        project_id: manifest.project.name,
        rules,
        container_network: ContainerNetwork {
            mode: "none".to_string(),
            reason: if any_allow {
                "allow_not_grantable"
            } else {
                "deny_by_construction"
            }
            .to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ZoneKind;

    fn zones() -> BTreeMap<String, ZoneDefinition> {
        index_zones(vec![
            ZoneDefinition {
                name: "internet".into(),
                display_name: None,
                description: None,
                kind: ZoneKind::Internet,
                relay_mode: None,
            },
            ZoneDefinition {
                name: "corp_dev".into(),
                display_name: None,
                description: None,
                kind: ZoneKind::Corporate,
                relay_mode: None,
            },
            ZoneDefinition {
                name: "corp_prod".into(),
                display_name: None,
                description: None,
                kind: ZoneKind::Production,
                relay_mode: None,
            },
            ZoneDefinition {
                name: "privileged_db".into(),
                display_name: None,
                description: None,
                kind: ZoneKind::Privileged,
                relay_mode: None,
            },
        ])
        .unwrap()
    }

    const MANIFEST: &str = r#"
project: { name: atlas }
permissions:
  network:
    internet: allow
    corp_dev: allow
    corp_prod: allow
"#;

    #[test]
    fn strictest_source_wins_and_unlisted_fails_closed() {
        let policy = r#"{
          "project_id":"atlas",
          "rules":[
            {"zone":"internet","decision":"allow"},
            {"zone":"corp_dev","decision":"approval_required"},
            {"zone":"corp_prod","decision":"deny"}
          ]
        }"#;
        let compiled = compile_project(MANIFEST, policy, &zones()).unwrap();
        assert_eq!(compiled.rule("internet").unwrap().decision, Decision::Allow);
        assert_eq!(
            compiled.rule("corp_dev").unwrap().decision,
            Decision::ApprovalRequired
        );
        assert_eq!(compiled.rule("corp_prod").unwrap().decision, Decision::Deny);
        let missing = compiled.rule("privileged_db").unwrap();
        assert_eq!(missing.decision, Decision::Deny);
        assert_eq!(missing.bound_by, BoundBy::Residual);
        assert_eq!(compiled.container_network.reason, "allow_not_grantable");
    }

    #[test]
    fn unknown_duplicate_and_cross_project_inputs_are_refused() {
        let unknown = r#"{"project_id":"atlas","rules":[{"zone":"elsewhere","decision":"allow"}]}"#;
        assert!(matches!(
            compile_project(MANIFEST, unknown, &zones()),
            Err(PolicyError::UnknownZone(_))
        ));
        let duplicate = r#"{"project_id":"atlas","rules":[{"zone":"internet","decision":"allow"},{"zone":"internet","decision":"deny"}]}"#;
        assert!(matches!(
            compile_project(MANIFEST, duplicate, &zones()),
            Err(PolicyError::DuplicateRule(_))
        ));
        let mismatch = r#"{"project_id":"other","rules":[{"zone":"internet","decision":"deny"}]}"#;
        assert!(matches!(
            compile_project(MANIFEST, mismatch, &zones()),
            Err(PolicyError::ProjectMismatch { .. })
        ));
    }

    #[test]
    fn expiry_is_narrow_and_fail_closed() {
        let allow_expiry = r#"{"project_id":"atlas","rules":[{"zone":"internet","decision":"allow","expires_at":"2026-08-29T00:00:00Z"}]}"#;
        assert!(matches!(
            compile_project(MANIFEST, allow_expiry, &zones()),
            Err(PolicyError::UnsupportedExpiry)
        ));
        let bad = r#"{"project_id":"atlas","rules":[{"zone":"internet","decision":"approval_required","expires_at":"later"}]}"#;
        assert!(matches!(
            compile_project(MANIFEST, bad, &zones()),
            Err(PolicyError::InvalidExpiry(_))
        ));
    }

    #[test]
    fn memberships_require_canonical_known_non_residual_cidrs() {
        let parsed = parse_zone_memberships(
            r#"{"v":1,"zones":{"corp_prod":{"cidrs":["10.30.0.0/16"],"names":{"10.30.0.7":"prod-api"}}}}"#,
            &zones(),
        )
        .unwrap();
        assert_eq!(parsed["corp_prod"].cidrs[0].to_string(), "10.30.0.0/16");
        assert!(
            parse_zone_memberships(
                r#"{"v":1,"zones":{"corp_prod":{"cidrs":["10.30.1.7/16"]}}}"#,
                &zones()
            )
            .is_err()
        );
        assert!(matches!(
            parse_zone_memberships(
                r#"{"v":1,"zones":{"internet":{"cidrs":["0.0.0.0/0"]}}}"#,
                &zones()
            ),
            Err(PolicyError::InternetHasMembers)
        ));
        assert!(matches!(
            parse_zone_memberships(
                r#"{"v":1,"zones":{"corp_prod":{"cidrs":["10.30.0.0/16"],"names":{"10.20.0.7":"wrong-zone"}}}}"#,
                &zones()
            ),
            Err(PolicyError::AddressNameOutsideZone { .. })
        ));
        assert!(matches!(
            parse_zone_memberships(
                r#"{"v":1,"zones":{"corp_dev":{"cidrs":["10.20.0.0/16"]},"corp_prod":{"cidrs":["10.20.9.0/24"]}}}"#,
                &zones()
            ),
            Err(PolicyError::OverlappingZones { .. })
        ));
    }
}
