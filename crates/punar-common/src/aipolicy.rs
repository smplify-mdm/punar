//! The AI authority model (SPEC section 20) as data: the shipped policy
//! document, the capability↔token map, and the layered evaluation that turns
//! "an agent asked for `security.firewall`" into `allow`, `deny`, or
//! `approval_required` (Milestone 9).
//!
//! The document shape is `schemas/policy/ai-policy.json`, whose keys copy
//! the SPEC section 20 example verbatim — including its two **distinct**
//! decision vocabularies: `host`/`network` use the shared
//! [`Decision`] enum (`allow | deny | approval_required`) while `credentials`
//! uses [`CredentialDecision`] (`allow | deny | request`). They are not
//! merged here, because the schema does not merge them and the difference is
//! real: `request` is a broker-side flow, not a capability gate.
//!
//! # Fail closed, and say so
//!
//! [`AiAuthority::host_ruling`] returns `None` when no layer names the token,
//! and [`host_token_for_capability`] returns `None` for a capability the map
//! does not cover. Both mean the same thing to the daemon: **denied**. Punar
//! does not guess what an organization meant to write, and it does not let a
//! capability slip through a gate because nobody remembered to name it.
//!
//! # What this module deliberately does not do in Milestone 9
//!
//! `ai.agents.<name>` profiles parse and are preserved, but **M9 evaluates
//! the `default` profile only**. Selecting a named profile needs a mapping
//! from the kernel-attested session id (`agt_…`) to an agent *name*, and the
//! only place that mapping is published today is
//! `/run/punar/agents.json` — a `0644 punar:punar` display file that any
//! local process can rewrite (docs/api/ipc.md section 11). Letting a
//! rewritable file choose which authority profile applies would make policy
//! selection an attack surface. The baseline applies to every agent until
//! that mapping has an unforgeable source; the limit is stated rather than
//! quietly worked around.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Decision;

/// Where the shipped personal-defaults document lives in the image.
pub const AI_DEFAULTS_FILE: &str = "/usr/share/punar/policy/ai-defaults.yaml";

/// The profile every agent is evaluated against in M9 (module docs).
pub const DEFAULT_PROFILE: &str = "default";

/// Graded filesystem access (SPEC section 20). Deliberately distinct from
/// [`Decision`]: filesystem authority distinguishes write from read, and
/// `allow` is not a valid filesystem value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemAccess {
    ReadWrite,
    Read,
    Deny,
}

/// Credential grant values (SPEC sections 17, 20). `request` is the
/// manifest-local spelling of "a human decides"; it is *equivalent in
/// intent* to `approval_required` and deliberately not the same token,
/// because `schemas/common/defs.json` keeps the two enums apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialDecision {
    Allow,
    Deny,
    Request,
}

impl CredentialDecision {
    /// All values, in schema order.
    pub const ALL: [CredentialDecision; 3] = [
        CredentialDecision::Allow,
        CredentialDecision::Deny,
        CredentialDecision::Request,
    ];

    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialDecision::Allow => "allow",
            CredentialDecision::Deny => "deny",
            CredentialDecision::Request => "request",
        }
    }
}

/// One agent authority profile — the four blocks SPEC section 20 exemplifies.
///
/// Growth blocks (`schemas/policy/ai-policy.json` allows any additional
/// snake_case block) parse into nothing here and are ignored by the engine.
/// That is safe by construction: an ignored block names no capability, and a
/// capability with no rule is denied.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentProfile {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub filesystem: BTreeMap<String, FilesystemAccess>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub host: BTreeMap<String, Decision>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub network: BTreeMap<String, Decision>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, CredentialDecision>,
}

/// `ai.agents` — the required `default` profile plus any named ones.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiAgents {
    pub default: AgentProfile,
    /// Per-agent profiles, parsed and preserved, **not selected in M9**
    /// (module docs).
    #[serde(flatten)]
    pub named: BTreeMap<String, AgentProfile>,
}

/// `ai` — the document root.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiRoot {
    pub agents: AiAgents,
}

/// An AI authority policy document (`schemas/policy/ai-policy.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiPolicyDocument {
    pub ai: AiRoot,
}

/// One provenance-tagged authority document in the SPEC section 39 ladder.
///
/// `rank` is the schema's fixed ladder rank — **1 is strongest** (hard OS
/// safety constraint), 6 is the OS secure default that ships with Punar. The
/// loader supplies it; this module only compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiLayer {
    pub policy_id: String,
    pub source_name: String,
    pub rank: u32,
    pub document: AiPolicyDocument,
}

/// A decision plus the citation that produced it. Every restriction Punar
/// states names its source (SPEC section 73, DESIGN_LANGUAGE section 8) — so
/// the engine returns the citation with the answer rather than leaving the
/// caller to guess at one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiRuling {
    pub decision: Decision,
    pub token: String,
    pub policy_id: String,
    pub source_name: String,
    pub rank: u32,
}

/// A credential ruling, with the same citation discipline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRuling {
    pub decision: CredentialDecision,
    pub policy_key: String,
    pub policy_id: String,
    pub source_name: String,
    pub rank: u32,
}

/// The effective AI authority for this device: the shipped OS defaults plus
/// any higher-ranked layers, resolved per token by the section 39 ladder.
#[derive(Debug, Clone, Default)]
pub struct AiAuthority {
    /// Sorted by ascending `rank`, i.e. strongest first.
    layers: Vec<AiLayer>,
}

impl AiAuthority {
    /// Build from layers in any order.
    pub fn new(mut layers: Vec<AiLayer>) -> Self {
        layers.sort_by_key(|l| l.rank);
        AiAuthority { layers }
    }

    /// The layers, strongest first.
    pub fn layers(&self) -> &[AiLayer] {
        &self.layers
    }

    /// Whether any authority document is loaded at all. An empty authority
    /// denies everything an agent asks for — which is the correct answer to
    /// "we could not read the policy", not a reason to fall back to allow.
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// The ruling for a `host` token (`firewall`, `hostname`, `timezone`).
    ///
    /// The highest-precedence layer that **names** the token wins; a layer
    /// that is silent about it does not participate. `None` means no layer
    /// named it, which the caller must treat as a denial.
    pub fn host_ruling(&self, token: &str) -> Option<AiRuling> {
        self.layers.iter().find_map(|layer| {
            layer
                .document
                .ai
                .agents
                .default
                .host
                .get(token)
                .map(|decision| AiRuling {
                    decision: *decision,
                    token: token.to_string(),
                    policy_id: layer.policy_id.clone(),
                    source_name: layer.source_name.clone(),
                    rank: layer.rank,
                })
        })
    }

    /// The ruling for a `credentials` key (`github`, `aws_dev`, `aws_prod`).
    ///
    /// The key is the **snake_case policy key**, never the kebab-case
    /// credential class id — the two spellings are bridged by the broker's
    /// declared `policy_key` field, never by a `replace('-', '_')` guess
    /// (design plan section 6.1).
    pub fn credential_ruling(&self, policy_key: &str) -> Option<CredentialRuling> {
        self.layers.iter().find_map(|layer| {
            layer
                .document
                .ai
                .agents
                .default
                .credentials
                .get(policy_key)
                .map(|decision| CredentialRuling {
                    decision: *decision,
                    policy_key: policy_key.to_string(),
                    policy_id: layer.policy_id.clone(),
                    source_name: layer.source_name.clone(),
                    rank: layer.rank,
                })
        })
    }

    /// Every `host` token any layer names, strongest layer first. Feeds the
    /// explainability surfaces (SPEC section 40) — including the tokens that
    /// map to no capability in this milestone, which are printed with an
    /// explicit marker rather than silently dropped.
    pub fn host_tokens(&self) -> Vec<String> {
        let mut tokens: Vec<String> = Vec::new();
        for layer in &self.layers {
            for token in layer.document.ai.agents.default.host.keys() {
                if !tokens.iter().any(|t| t == token) {
                    tokens.push(token.clone());
                }
            }
        }
        tokens
    }
}

// ---------------------------------------------------------------------------
// The capability ↔ section 20 token map
// ---------------------------------------------------------------------------

/// The complete map from a Milestone 9 registry capability to its SPEC
/// section 20 `host` token.
///
/// `hostname` and `timezone` are not in section 20's *example*, but the
/// section's category list names "system mutation" and the schema's `host`
/// block accepts any snake_case token. They are named here honestly rather
/// than smuggled in under `system_package`.
///
/// **This table is the whole map.** A capability that is not in it has no AI
/// authority rule and is denied (module docs).
pub const HOST_TOKEN_BY_CAPABILITY: [(&str, &str); 3] = [
    ("security.firewall", "firewall"),
    ("system.hostname", "hostname"),
    ("time.timezone", "timezone"),
];

/// The section 20 `host` token for a registry capability, or `None` — which
/// means **deny**, never "allow by default".
pub fn host_token_for_capability(capability: &str) -> Option<&'static str> {
    HOST_TOKEN_BY_CAPABILITY
        .iter()
        .find(|(cap, _)| *cap == capability)
        .map(|(_, token)| *token)
}

/// The registry capability a `host` token governs, or `None` when the token
/// is **inert** in this milestone: policy may name `user_package`, but no
/// capability implements package installation yet, so the rule enforces
/// nothing. Surfaces print such rows with an explicit marker — the M8
/// `not_yet_observed` idiom applied to policy (SPEC 1.22).
pub fn capability_for_host_token(token: &str) -> Option<&'static str> {
    HOST_TOKEN_BY_CAPABILITY
        .iter()
        .find(|(_, t)| *t == token)
        .map(|(cap, _)| *cap)
}

/// Whether a `host` token names a rule that nothing in this milestone can
/// enforce.
pub fn is_inert_host_token(token: &str) -> bool {
    capability_for_host_token(token).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped personal defaults, compiled in so the test reads exactly
    /// the bytes the image ships (the M8 `process-classes.json` pattern).
    const PERSONAL_DEFAULTS: &str =
        include_str!("../../../fixtures/policies/ai-policy-personal-defaults.yaml");
    /// The Acme org fixture — `host.firewall: deny`, the deliberate
    /// divergence from the personal default.
    const ENG_AI_V3: &str =
        include_str!("../../../fixtures/policies/ai-policy-engineering-standard.yaml");

    /// Parse YAML through JSON: `punar-common` has no YAML dependency (the
    /// daemons do), and the document shape is format-agnostic. The fixtures
    /// are re-expressed here only to the extent the test needs.
    fn document(
        host: &[(&str, Decision)],
        creds: &[(&str, CredentialDecision)],
    ) -> AiPolicyDocument {
        AiPolicyDocument {
            ai: AiRoot {
                agents: AiAgents {
                    default: AgentProfile {
                        host: host.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
                        credentials: creds.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
                        ..AgentProfile::default()
                    },
                    named: BTreeMap::new(),
                },
            },
        }
    }

    fn personal() -> AiLayer {
        AiLayer {
            policy_id: "personal-defaults".to_string(),
            source_name: "Personal defaults".to_string(),
            rank: 6,
            document: document(
                &[
                    ("firewall", Decision::ApprovalRequired),
                    ("hostname", Decision::ApprovalRequired),
                    ("timezone", Decision::ApprovalRequired),
                    ("user_management", Decision::Deny),
                ],
                &[
                    ("github", CredentialDecision::Allow),
                    ("aws_dev", CredentialDecision::Request),
                    ("aws_prod", CredentialDecision::Deny),
                ],
            ),
        }
    }

    fn org() -> AiLayer {
        AiLayer {
            policy_id: "eng-ai-v3".to_string(),
            source_name: "Acme Engineering AI Policy".to_string(),
            rank: 2,
            document: document(
                &[("firewall", Decision::Deny)],
                &[("aws_prod", CredentialDecision::Deny)],
            ),
        }
    }

    /// Personal mode: the firewall is the highest-risk capability M9 owns,
    /// and the personal default is `approval_required` — because in personal
    /// mode the user *is* the approver, and a flat denial would violate
    /// section 73's "whether approval is possible".
    #[test]
    fn personal_defaults_gate_the_firewall_behind_a_human() {
        let authority = AiAuthority::new(vec![personal()]);
        let ruling = authority.host_ruling("firewall").unwrap();
        assert_eq!(ruling.decision, Decision::ApprovalRequired);
        assert_eq!(ruling.policy_id, "personal-defaults");
        assert_eq!(
            authority.host_ruling("user_management").unwrap().decision,
            Decision::Deny
        );
    }

    /// Enrolled, the org baseline outranks the OS default and the agent is
    /// denied outright, citing the organization — the section 39 ladder,
    /// live. Neither answer is a special case.
    #[test]
    fn the_org_layer_outranks_the_personal_default() {
        let authority = AiAuthority::new(vec![personal(), org()]);
        let ruling = authority.host_ruling("firewall").unwrap();
        assert_eq!(ruling.decision, Decision::Deny);
        assert_eq!(ruling.policy_id, "eng-ai-v3");
        assert_eq!(ruling.source_name, "Acme Engineering AI Policy");
        // A token the org layer is silent about still resolves from the OS
        // default: a layer that says nothing does not say "allow".
        let timezone = authority.host_ruling("timezone").unwrap();
        assert_eq!(timezone.decision, Decision::ApprovalRequired);
        assert_eq!(timezone.policy_id, "personal-defaults");
    }

    #[test]
    fn an_unnamed_token_has_no_ruling_and_an_empty_authority_has_none_at_all() {
        let authority = AiAuthority::new(vec![personal()]);
        assert!(authority.host_ruling("container_access").is_none());
        assert!(authority.credential_ruling("stripe_prod").is_none());

        let empty = AiAuthority::default();
        assert!(empty.is_empty());
        assert!(empty.host_ruling("firewall").is_none());
    }

    #[test]
    fn credential_rulings_use_the_snake_case_policy_key() {
        let authority = AiAuthority::new(vec![personal()]);
        assert_eq!(
            authority.credential_ruling("github").unwrap().decision,
            CredentialDecision::Allow
        );
        assert_eq!(
            authority.credential_ruling("aws_dev").unwrap().decision,
            CredentialDecision::Request
        );
        assert_eq!(
            authority.credential_ruling("aws_prod").unwrap().decision,
            CredentialDecision::Deny
        );
        // The kebab-case class id is NOT a policy key; the bridge is the
        // broker's declared `policy_key` field, never a guess here.
        assert!(authority.credential_ruling("aws-dev").is_none());
    }

    #[test]
    fn the_capability_map_is_total_and_reversible() {
        for (capability, token) in HOST_TOKEN_BY_CAPABILITY {
            assert_eq!(host_token_for_capability(capability), Some(token));
            assert_eq!(capability_for_host_token(token), Some(capability));
            assert!(!is_inert_host_token(token));
        }
        // Fail closed: a capability outside the map has no rule at all.
        assert_eq!(host_token_for_capability("system.install_package"), None);
        // Policy vocabulary M9 cannot enforce is inert, and says so.
        for token in ["user_package", "system_package", "user_management"] {
            assert!(is_inert_host_token(token), "{token}");
        }
    }

    #[test]
    fn host_tokens_lists_every_named_token_strongest_layer_first() {
        let authority = AiAuthority::new(vec![personal(), org()]);
        let tokens = authority.host_tokens();
        assert_eq!(tokens.first().unwrap(), "firewall");
        for expected in ["firewall", "hostname", "timezone", "user_management"] {
            assert!(tokens.iter().any(|t| t == expected), "{expected}");
        }
    }

    /// The two shipped fixtures are real files with real content — this
    /// guards against a rename or an empty file passing unnoticed.
    #[test]
    fn the_shipped_fixtures_exist_and_carry_the_section_20_blocks() {
        for (name, text) in [
            ("personal defaults", PERSONAL_DEFAULTS),
            ("eng-ai-v3", ENG_AI_V3),
        ] {
            assert!(text.contains("ai:"), "{name}");
            assert!(text.contains("agents:"), "{name}");
            assert!(text.contains("default:"), "{name}");
            assert!(text.contains("credentials:"), "{name}");
        }
        assert!(PERSONAL_DEFAULTS.contains("firewall: approval_required"));
        assert!(ENG_AI_V3.contains("firewall: deny"));
    }

    #[test]
    fn the_two_decision_vocabularies_stay_apart() {
        for decision in CredentialDecision::ALL {
            let text = serde_json::to_string(&decision).unwrap();
            assert_eq!(text, format!("{:?}", decision.as_str()));
        }
        // `approval_required` is not a credential value, and `request` is
        // not a capability decision. The schema keeps them apart; so do we.
        assert!(serde_json::from_str::<CredentialDecision>("\"approval_required\"").is_err());
        assert!(serde_json::from_str::<Decision>("\"request\"").is_err());
    }
}
