//! Deterministic generation of the netd-owned nftables table.
//!
//! This module cannot execute anything. Its output is the complete input for
//! a later fixed-argv `nft -f <root-owned-file>` transaction.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use thiserror::Error;

use crate::model::{
    Cidr, Decision, ModelError, ZoneDefinition, ZoneMembership, validate_cgroup_path,
    validate_session_id,
};
use crate::policy::CompiledProject;

pub const TABLE_FAMILY: &str = "inet";
pub const TABLE_NAME: &str = "punar-net";

#[derive(Debug, Error)]
pub enum NftError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("session {0:?} has no internet residual rule")]
    MissingInternetRule(String),
    #[error("session {session:?} references policy for project {policy:?}, not {binding:?}")]
    ProjectMismatch {
        session: String,
        policy: String,
        binding: String,
    },
    #[error("zone membership references unknown zone {0:?}")]
    UnknownMembership(String),
    #[error("zone map key {key:?} does not match definition name {name:?}")]
    ZoneKeyMismatch { key: String, name: String },
    #[error("session policy references unknown zone {0:?}")]
    UnknownPolicyZone(String),
    #[error("session policy names zone {0:?} more than once")]
    DuplicatePolicyZone(String),
    #[error("session id {0:?} appears more than once")]
    DuplicateSession(String),
    #[error("cgroup path {0:?} is bound to more than one session")]
    DuplicateCgroup(String),
}

#[derive(Debug, Clone)]
pub struct SessionBinding {
    pub session_id: String,
    pub project_id: String,
    pub cgroup_path: String,
    pub policy: CompiledProject,
}

impl SessionBinding {
    fn validate(&self, zones: &BTreeMap<String, ZoneDefinition>) -> Result<(), NftError> {
        validate_session_id(&self.session_id)?;
        validate_cgroup_path(&self.cgroup_path)?;
        if self.project_id != self.policy.project_id {
            return Err(NftError::ProjectMismatch {
                session: self.session_id.clone(),
                policy: self.policy.project_id.clone(),
                binding: self.project_id.clone(),
            });
        }
        if self.policy.rule("internet").is_none() {
            return Err(NftError::MissingInternetRule(self.session_id.clone()));
        }
        let mut seen = std::collections::BTreeSet::new();
        for rule in &self.policy.rules {
            if !zones.contains_key(&rule.zone) {
                return Err(NftError::UnknownPolicyZone(rule.zone.clone()));
            }
            if !seen.insert(rule.zone.clone()) {
                return Err(NftError::DuplicatePolicyZone(rule.zone.clone()));
            }
        }
        Ok(())
    }

    fn tag(&self) -> &str {
        self.session_id
            .strip_prefix("agt_")
            .expect("validated session id")
    }

    fn cgroup_level(&self) -> usize {
        self.cgroup_path
            .split('/')
            .filter(|part| !part.is_empty())
            .count()
    }
}

pub fn render_table(
    replace_existing: bool,
    zones: &BTreeMap<String, ZoneDefinition>,
    memberships: &BTreeMap<String, ZoneMembership>,
    sessions: &[SessionBinding],
) -> Result<String, NftError> {
    for (key, zone) in zones {
        zone.validate()?;
        if key != &zone.name {
            return Err(NftError::ZoneKeyMismatch {
                key: key.clone(),
                name: zone.name.clone(),
            });
        }
    }
    for name in memberships.keys() {
        if !zones.contains_key(name) {
            return Err(NftError::UnknownMembership(name.clone()));
        }
    }
    let mut session_ids = std::collections::BTreeSet::new();
    let mut cgroups = std::collections::BTreeSet::new();
    for session in sessions {
        session.validate(zones)?;
        if !session_ids.insert(session.session_id.clone()) {
            return Err(NftError::DuplicateSession(session.session_id.clone()));
        }
        if !cgroups.insert(session.cgroup_path.clone()) {
            return Err(NftError::DuplicateCgroup(session.cgroup_path.clone()));
        }
    }

    let mut output = String::new();
    if replace_existing {
        writeln!(output, "destroy table {TABLE_FAMILY} {TABLE_NAME}").unwrap();
    }
    writeln!(output, "table {TABLE_FAMILY} {TABLE_NAME} {{").unwrap();
    render_sets(&mut output, memberships);
    render_counters(&mut output, sessions);
    render_egress(&mut output, sessions);
    for session in sessions {
        render_session_chain(&mut output, memberships, session)?;
    }
    writeln!(output, "}}").unwrap();
    Ok(output)
}

fn render_sets(output: &mut String, memberships: &BTreeMap<String, ZoneMembership>) {
    for (zone, members) in memberships {
        let v4: Vec<Cidr> = members
            .cidrs
            .iter()
            .copied()
            .filter(|cidr| cidr.is_v4())
            .collect();
        let v6: Vec<Cidr> = members
            .cidrs
            .iter()
            .copied()
            .filter(|cidr| !cidr.is_v4())
            .collect();
        if !v4.is_empty() {
            writeln!(
                output,
                "  set z_{zone}_v4 {{ type ipv4_addr; flags interval; elements = {{ {} }} }}",
                join_cidrs(&v4)
            )
            .unwrap();
        }
        if !v6.is_empty() {
            writeln!(
                output,
                "  set z_{zone}_v6 {{ type ipv6_addr; flags interval; elements = {{ {} }} }}",
                join_cidrs(&v6)
            )
            .unwrap();
        }
    }
}

fn render_counters(output: &mut String, sessions: &[SessionBinding]) {
    for session in sessions {
        let tag = session.tag();
        for rule in &session.policy.rules {
            let suffix = if rule.zone == "internet" {
                "residual"
            } else {
                &rule.zone
            };
            writeln!(
                output,
                "  counter c_{tag}_{suffix}_{} {{ }}",
                enforcement_word(rule.decision)
            )
            .unwrap();
        }
    }
}

fn render_egress(output: &mut String, sessions: &[SessionBinding]) {
    writeln!(output, "  chain egress {{").unwrap();
    writeln!(
        output,
        "    type filter hook output priority filter - 10; policy accept;"
    )
    .unwrap();
    for session in sessions {
        writeln!(
            output,
            "    socket cgroupv2 level {} \"{}\" jump s_{}",
            session.cgroup_level(),
            session.cgroup_path.replace('\\', "\\\\"),
            session.tag()
        )
        .unwrap();
    }
    writeln!(output, "  }}").unwrap();
}

fn render_session_chain(
    output: &mut String,
    memberships: &BTreeMap<String, ZoneMembership>,
    session: &SessionBinding,
) -> Result<(), NftError> {
    let tag = session.tag();
    writeln!(output, "  chain s_{tag} {{").unwrap();

    // Blocks first: overlapping CIDRs can never let a broader allow eclipse
    // a narrower production/privileged deny.
    for rule in session
        .policy
        .rules
        .iter()
        .filter(|rule| rule.zone != "internet" && rule.decision.blocks())
    {
        render_zone_rules(output, memberships, tag, &rule.zone, rule.decision);
    }
    for rule in session
        .policy
        .rules
        .iter()
        .filter(|rule| rule.zone != "internet" && rule.decision == Decision::Allow)
    {
        render_zone_rules(output, memberships, tag, &rule.zone, rule.decision);
    }

    writeln!(output, "    ip daddr 127.0.0.0/8 accept").unwrap();
    writeln!(output, "    ip6 daddr ::1/128 accept").unwrap();
    writeln!(output, "    ip daddr 169.254.0.0/16 accept").unwrap();
    writeln!(output, "    ip6 daddr fe80::/10 accept").unwrap();

    let residual = session
        .policy
        .rule("internet")
        .ok_or_else(|| NftError::MissingInternetRule(session.session_id.clone()))?;
    let counter = format!("c_{tag}_residual_{}", enforcement_word(residual.decision));
    if residual.decision == Decision::Allow {
        writeln!(output, "    counter name {counter} accept").unwrap();
    } else {
        render_log(output, "internet", tag);
        writeln!(
            output,
            "    counter name {counter} reject with icmpx type admin-prohibited"
        )
        .unwrap();
    }
    writeln!(output, "  }}").unwrap();
    Ok(())
}

fn render_zone_rules(
    output: &mut String,
    memberships: &BTreeMap<String, ZoneMembership>,
    tag: &str,
    zone: &str,
    decision: Decision,
) {
    let Some(members) = memberships.get(zone) else {
        return;
    };
    let has_v4 = members.cidrs.iter().any(|cidr| cidr.is_v4());
    let has_v6 = members.cidrs.iter().any(|cidr| !cidr.is_v4());
    let counter = format!("c_{tag}_{zone}_{}", enforcement_word(decision));
    for (family, suffix, present) in [("ip", "v4", has_v4), ("ip6", "v6", has_v6)] {
        if !present {
            continue;
        }
        if decision.blocks() {
            writeln!(
                output,
                "    {family} daddr @z_{zone}_{suffix} limit rate 5/minute log prefix \"punar-net deny {zone} {tag} \" level info"
            )
            .unwrap();
            writeln!(
                output,
                "    {family} daddr @z_{zone}_{suffix} counter name {counter} reject with icmpx type admin-prohibited"
            )
            .unwrap();
        } else {
            writeln!(
                output,
                "    {family} daddr @z_{zone}_{suffix} counter name {counter} accept"
            )
            .unwrap();
        }
    }
}

fn render_log(output: &mut String, zone: &str, tag: &str) {
    writeln!(
        output,
        "    limit rate 5/minute log prefix \"punar-net deny {zone} {tag} \" level info"
    )
    .unwrap();
}

fn enforcement_word(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::ApprovalRequired | Decision::Deny => "deny",
    }
}

fn join_cidrs(cidrs: &[Cidr]) -> String {
    cidrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::model::{RelayMode, ZoneKind};
    use crate::policy::{BoundBy, ContainerNetwork, EffectiveRule};

    fn fixture() -> (
        BTreeMap<String, ZoneDefinition>,
        BTreeMap<String, ZoneMembership>,
        SessionBinding,
    ) {
        let mut zones = BTreeMap::new();
        for (name, kind) in [
            ("internet", ZoneKind::Internet),
            ("corp_dev", ZoneKind::Corporate),
            ("corp_prod", ZoneKind::Production),
        ] {
            zones.insert(
                name.to_string(),
                ZoneDefinition {
                    name: name.to_string(),
                    display_name: None,
                    description: None,
                    kind,
                    relay_mode: Some(RelayMode::Direct),
                },
            );
        }
        let mut memberships = BTreeMap::new();
        memberships.insert(
            "corp_dev".to_string(),
            ZoneMembership {
                cidrs: vec![Cidr::parse("127.0.0.9/32").unwrap()],
                names: BTreeMap::new(),
            },
        );
        memberships.insert(
            "corp_prod".to_string(),
            ZoneMembership {
                cidrs: vec![Cidr::parse("127.0.0.7/32").unwrap()],
                names: BTreeMap::new(),
            },
        );
        let mk = |zone: &str, decision| EffectiveRule {
            zone: zone.to_string(),
            decision,
            bound_by: BoundBy::Both,
            manifest_decision: Some(decision),
            policy_decision: Some(decision),
        };
        let policy = CompiledProject {
            project_id: "atlas".to_string(),
            rules: vec![
                mk("corp_dev", Decision::Allow),
                mk("corp_prod", Decision::Deny),
                mk("internet", Decision::Allow),
            ],
            container_network: ContainerNetwork {
                mode: "none".into(),
                reason: "allow_not_grantable".into(),
            },
        };
        let session = SessionBinding {
            session_id: "agt_4f21c09ab3e1".to_string(),
            project_id: "atlas".to_string(),
            cgroup_path:
                "/user.slice/user-1000.slice/user@1000.service/app.slice/punar-agent-4f21.scope"
                    .to_string(),
            policy,
        };
        (zones, memberships, session)
    }

    #[test]
    fn golden_ruleset_pins_security_order_and_owned_table() {
        let (zones, memberships, session) = fixture();
        let rendered = render_table(true, &zones, &memberships, &[session]).unwrap();
        let deny_log = rendered.find("corp_prod_v4 limit rate").unwrap();
        let deny_reject = rendered.find("corp_prod_v4 counter name").unwrap();
        let allow = rendered.find("corp_dev_v4 counter name").unwrap();
        let loopback = rendered.find("ip daddr 127.0.0.0/8 accept").unwrap();
        let residual = rendered
            .find("counter name c_4f21c09ab3e1_residual_allow accept")
            .unwrap();
        assert!(deny_log < deny_reject);
        assert!(deny_reject < allow);
        assert!(allow < loopback);
        assert!(loopback < residual);
        assert!(rendered.starts_with("destroy table inet punar-net\ntable inet punar-net"));
        assert!(!rendered.contains("punar-base"));
        assert_eq!(rendered.matches("corp_prod_v4 counter name").count(), 1);
    }

    #[test]
    fn rate_limit_never_guards_the_enforcing_reject() {
        let (zones, memberships, session) = fixture();
        let rendered = render_table(false, &zones, &memberships, &[session]).unwrap();
        for line in rendered.lines().filter(|line| line.contains("reject")) {
            assert!(!line.contains("limit rate"), "{line}");
            assert!(line.contains("counter name"), "{line}");
        }
    }

    #[test]
    fn unsafe_cgroup_path_cannot_reach_output() {
        let (zones, memberships, mut session) = fixture();
        session.cgroup_path = "/user.slice/\"; destroy table inet punar-base".into();
        assert!(matches!(
            render_table(false, &zones, &memberships, &[session]),
            Err(NftError::Model(ModelError::InvalidCgroupPath(_)))
        ));
    }

    #[test]
    fn duplicate_session_or_cgroup_attribution_is_refused() {
        let (zones, memberships, session) = fixture();
        assert!(matches!(
            render_table(
                false,
                &zones,
                &memberships,
                &[session.clone(), session.clone()]
            ),
            Err(NftError::DuplicateSession(_))
        ));
        let mut other = session.clone();
        other.session_id = "agt_ABC9".into();
        assert!(matches!(
            render_table(false, &zones, &memberships, &[session, other]),
            Err(NftError::DuplicateCgroup(_))
        ));
    }
}
