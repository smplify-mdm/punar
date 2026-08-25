//! The effective AI **credentials** decision (spec section 20, resolved
//! through the section 39 ladder) and the section 73 prose that carries it.
//!
//! # What this module reads, and what it deliberately does not
//!
//! It reads the `ai.agents.default.credentials` block of AI authority
//! documents — `schemas/policy/ai-policy.json` shape — and nothing else.
//! Not `host`, not `filesystem`, not `network`: those gate capability
//! mutations, which is punard's half of Milestone 9. The broker is not a
//! second policy engine; it answers one question (`allow | request |
//! deny`) about one key.
//!
//! **Per-agent profiles are not consulted in Milestone 9, and that is
//! stated rather than silently skipped.** `ai-policy.json` allows
//! `ai.agents.<agent-name>` overrides, but the broker's attested input is
//! an *agent session id* (`agt_…`) from the peer's cgroup, not an agent
//! product name; the name lives in `agents.json`, which is documented as
//! display-grade and non-authoritative (ipc.md section 11). Reading a
//! forgeable file to pick a *stricter or looser* authority profile would
//! be exactly the kind of guess spec section 60 forbids. Per-agent
//! credential profiles arrive when the broker has an attested name.
//!
//! # Fail-closed, in three places
//!
//! 1. No document names the key → `deny`, cited as the OS fail-closed
//!    default. Punar does not guess.
//! 2. A layer that cannot be parsed → `deny` for every key, cited by
//!    filename. A broken org layer must never fail *open*.
//! 3. A class whose `max_ttl` is zero is never issued, whatever policy
//!    says (see [`crate::classes::CredentialClass::issuable`]).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use punar_common::audit::POLICY_PERSONAL_DEFAULTS;
use punar_policy::{PolicySource, Provenance, SourceKind, policy_source_for_rank, resolve};
use serde::{Deserialize, Serialize};

use crate::classes::CredentialClass;

/// Citation used when **no** policy document names a credential key. It is
/// not `personal-defaults`: claiming the user wrote a rule they did not
/// write would be a false citation in the audit trail.
pub const POLICY_FAIL_CLOSED: &str = "os-fail-closed";

/// The manifest-local credential decision enum of
/// `schemas/policy/ai-policy.json` (`allow | deny | request`). Spelled
/// `request` — not `approval_required` — because every spec manifest
/// spells it that way for credentials; the *runtime* record of the outcome
/// uses the shared [`punar_common::Decision`] enum, where it becomes
/// `approval_required`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialGrant {
    Allow,
    Deny,
    Request,
}

impl CredentialGrant {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialGrant::Allow => "allow",
            CredentialGrant::Deny => "deny",
            CredentialGrant::Request => "request",
        }
    }

    /// The shared section 20 decision this grant records as.
    pub fn decision(self) -> punar_common::Decision {
        match self {
            CredentialGrant::Allow => punar_common::Decision::Allow,
            CredentialGrant::Deny => punar_common::Decision::Deny,
            CredentialGrant::Request => punar_common::Decision::ApprovalRequired,
        }
    }
}

/// The effective decision for one credential key, with the citation that
/// produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialAuthority {
    pub grant: CredentialGrant,
    pub policy_id: String,
    pub policy_name: String,
    /// Which rung of the section 39 ladder won.
    pub source: PolicySource,
    /// True when an organization layer decided this. DESIGN_LANGUAGE
    /// section 8: org citations only when enrolled.
    pub from_org: bool,
    /// False when no document named the key and the fail-closed default
    /// answered.
    pub stated: bool,
}

impl CredentialAuthority {
    fn fail_closed(reason_name: &str, policy_id: &str) -> CredentialAuthority {
        CredentialAuthority {
            grant: CredentialGrant::Deny,
            policy_id: policy_id.to_string(),
            policy_name: reason_name.to_string(),
            source: PolicySource::OsDefault,
            from_org: false,
            stated: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Document shape (the `credentials` block only)
// ---------------------------------------------------------------------------

/// One AI authority document. Deliberately **not**
/// `deny_unknown_fields`: this crate reads one block of a document another
/// component owns, and a new sibling block (`host`, `browser`, …) must not
/// break credential issuance.
#[derive(Debug, Clone, Deserialize)]
struct AiDocument {
    ai: AiBlock,
}

#[derive(Debug, Clone, Deserialize)]
struct AiBlock {
    agents: AgentsBlock,
}

#[derive(Debug, Clone, Deserialize)]
struct AgentsBlock {
    default: AuthorityProfile,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthorityProfile {
    #[serde(default)]
    credentials: BTreeMap<String, CredentialGrant>,
}

/// One loaded layer: its credentials map plus where it sits on the ladder.
#[derive(Debug, Clone)]
struct Layer {
    credentials: BTreeMap<String, CredentialGrant>,
    provenance: Provenance,
    from_org: bool,
}

/// Every AI authority document this device has, in ladder order.
#[derive(Debug, Clone, Default)]
pub struct AiPolicySet {
    layers: Vec<Layer>,
    /// Documents that exist but could not be understood. Any entry here
    /// forces every decision to `deny` (see module docs, rule 2).
    broken: Vec<String>,
    /// Warnings worth printing at start (never a reason to fail open).
    pub warnings: Vec<String>,
}

/// Why the personal-defaults document could not be loaded.
#[derive(Debug)]
pub struct PolicyLoadError {
    pub path: PathBuf,
    pub detail: String,
}

impl fmt::Display for PolicyLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.detail)
    }
}

impl std::error::Error for PolicyLoadError {}

impl AiPolicySet {
    /// Load the personal defaults document (rank 6) and any organization
    /// AI authority layers (rank 2).
    ///
    /// `defaults_path` is `usr/share/punar/policy/ai-defaults.yaml` in the
    /// image — the document Milestone 9 ships. It is **required**: a broker
    /// that started without it would answer every request from the
    /// fail-closed default, which is safe but silently wrong, so the daemon
    /// refuses to start instead.
    ///
    /// `org_dir` is `/var/lib/punar/policy.d` — **the same directory
    /// punard's AI loader reads**, not a broker-private one. That is the
    /// whole point: the two daemons must reach the same section 39 verdict
    /// about one org document, and they cannot do that from two drop
    /// points. It also keeps `policy.d`-is-empty as the single
    /// machine-checkable unmanaged-first invariant (milestone-5.md section
    /// 10.2) instead of splitting it across a reserved subdirectory.
    ///
    /// Each layer is a `<policy_id>.yaml` document **beside its
    /// `<policy_id>.json` policy-source envelope**, exactly as
    /// `punard::aipolicy` requires. A YAML with no envelope is ignored,
    /// loudly: provenance is not guessable, and a document that cannot say
    /// who wrote it and at what rank must not outrank the OS default by
    /// having its rank invented from its filename. The desired-state
    /// envelopes enrollment writes here (`eng-baseline-v12.json`) carry no
    /// AI document and are simply not `.yaml`, so they are skipped.
    ///
    /// Milestone 9 ships **no producer** for an org AI document — the
    /// enrolled ladder demo runs through punard's capability path — so in
    /// practice there is none, and no org document is simply no org
    /// opinion. It is read rather than ignored because a broker that could
    /// not see an org layer that *is* there would be citing personal
    /// defaults over a managed decision.
    pub fn load(defaults_path: &Path, org_dir: &Path) -> Result<AiPolicySet, PolicyLoadError> {
        let text = std::fs::read_to_string(defaults_path).map_err(|e| PolicyLoadError {
            path: defaults_path.to_path_buf(),
            detail: format!("the AI authority defaults could not be read: {e}"),
        })?;
        let defaults = parse_document(&text).map_err(|detail| PolicyLoadError {
            path: defaults_path.to_path_buf(),
            detail,
        })?;

        let mut set = AiPolicySet {
            layers: vec![Layer {
                credentials: defaults,
                provenance: Provenance {
                    kind: SourceKind::OsSecureDefault,
                    rank: SourceKind::OsSecureDefault.fixed_rank().unwrap_or(6),
                    policy_id: POLICY_PERSONAL_DEFAULTS.to_string(),
                    source_name: "Personal defaults".to_string(),
                },
                from_org: false,
            }],
            broken: Vec::new(),
            warnings: Vec::new(),
        };
        set.load_org_dir(org_dir);
        Ok(set)
    }

    /// A set with no documents at all — every decision is fail-closed
    /// `deny`. Used by tests and by nothing in the shipping wiring.
    pub fn empty() -> AiPolicySet {
        AiPolicySet::default()
    }

    fn load_org_dir(&mut self, org_dir: &Path) {
        let mut files: Vec<PathBuf> = match std::fs::read_dir(org_dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .is_some_and(|ext| ext == "yaml" || ext == "yml")
                })
                .collect(),
            Err(_) => return, // absent or unreadable: no org opinion
        };
        files.sort();
        for path in files {
            let envelope_path = path.with_extension("json");
            let provenance = match read_envelope(&envelope_path) {
                Ok(provenance) => provenance,
                Err(detail) => {
                    // Ignored, not `broken`: a document with no readable
                    // provenance has no authority to be broken *at*. Denying
                    // every credential because an unattributed file exists
                    // would hand a drop-anything-in-policy.d writer a global
                    // outage; punard::aipolicy skips these for the same
                    // reason, and both daemons must skip the same files.
                    self.warnings.push(format!(
                        "{}: {detail}; ignored — an AI authority document may not \
                         outrank the OS default without declaring who wrote it and \
                         at what rank",
                        path.display()
                    ));
                    continue;
                }
            };
            let policy_id = provenance.policy_id.clone();
            match std::fs::read_to_string(&path).map_err(|e| e.to_string()) {
                Ok(text) => match parse_document(&text) {
                    Ok(credentials) => {
                        let from_org = matches!(
                            provenance.kind,
                            SourceKind::OrganizationBaseline
                                | SourceKind::OrganizationRolePolicy
                                | SourceKind::TemporaryApprovedException
                        );
                        self.layers.push(Layer {
                            credentials,
                            provenance,
                            from_org,
                        });
                    }
                    Err(detail) => {
                        self.broken.push(policy_id);
                        self.warnings.push(format!(
                            "{} is not a readable AI authority document ({detail}); every \
                             credential request is denied until it is fixed",
                            path.display()
                        ));
                    }
                },
                Err(detail) => {
                    self.broken.push(policy_id);
                    self.warnings.push(format!(
                        "{} could not be read ({detail}); every credential request is \
                         denied until it is fixed",
                        path.display()
                    ));
                }
            }
        }
    }

    /// True when an organization layer is present (the enrollment signal
    /// this crate can prove for itself).
    pub fn enrolled(&self) -> bool {
        self.layers.iter().any(|layer| layer.from_org)
    }

    /// The effective decision for one snake_case policy key.
    pub fn credential_decision(&self, policy_key: &str) -> CredentialAuthority {
        if let Some(broken) = self.broken.first() {
            return CredentialAuthority::fail_closed("Unreadable policy layer", broken);
        }
        let entries = self.layers.iter().filter_map(|layer| {
            layer
                .credentials
                .get(policy_key)
                .map(|grant| (layer.provenance.policy_source(), (*grant, layer)))
        });
        match resolve(entries) {
            Some(resolved) => {
                let (grant, layer) = resolved.value;
                CredentialAuthority {
                    grant,
                    policy_id: layer.provenance.policy_id.clone(),
                    policy_name: layer.provenance.source_name.clone(),
                    source: policy_source_for_rank(layer.provenance.rank),
                    from_org: layer.from_org,
                    stated: true,
                }
            }
            None => CredentialAuthority::fail_closed(
                "OS default — no policy names this credential",
                POLICY_FAIL_CLOSED,
            ),
        }
    }
}

fn parse_document(text: &str) -> Result<BTreeMap<String, CredentialGrant>, String> {
    let document: AiDocument = serde_norway::from_str(text)
        .map_err(|e| format!("not a valid AI authority document: {e}"))?;
    Ok(document.ai.agents.default.credentials)
}

/// The provenance half of an org AI drop: the `schemas/policy/policy-source.json`
/// envelope, minus the desired-state payload this crate does not read.
///
/// Deliberately a small local mirror of `punard::aipolicy::AiSourceEnvelope`
/// rather than a shared type: `punar-secrets` must not depend on punard (it
/// is a separate daemon with a separate blast radius), and the shared piece
/// that actually matters — the ladder itself — already lives in
/// `punar-policy`, which both use. The **rules** are what must not diverge,
/// and they are pinned by test in both crates.
#[derive(Debug, Deserialize)]
struct AiSourceEnvelope {
    policy_id: String,
    source_kind: SourceKind,
    precedence_rank: u32,
    #[serde(default)]
    source_name: Option<String>,
}

/// Read `<policy_id>.json` beside an AI document and turn it into the
/// provenance that document is allowed to claim.
///
/// A stored rank that contradicts the schema's fixed ladder is a corrupt
/// envelope, not a novel rung — the same judgment punard's `policy.d`
/// loaders make. `device_specific_override` has no fixed rung, so its
/// stored rank is taken as data.
fn read_envelope(path: &Path) -> Result<Provenance, String> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "no readable provenance envelope at {} ({e})",
            path.display()
        )
    })?;
    let envelope: AiSourceEnvelope = serde_json::from_str(&text).map_err(|e| {
        format!(
            "{} is not a valid policy-source envelope ({e})",
            path.display()
        )
    })?;
    if envelope
        .source_kind
        .fixed_rank()
        .is_some_and(|fixed| fixed != envelope.precedence_rank)
    {
        return Err(format!(
            "{} stores precedence_rank {} for source_kind {}",
            path.display(),
            envelope.precedence_rank,
            envelope.source_kind.as_str()
        ));
    }
    Ok(Provenance {
        kind: envelope.source_kind,
        rank: envelope.precedence_rank,
        source_name: envelope
            .source_name
            .unwrap_or_else(|| envelope.policy_id.clone()),
        policy_id: envelope.policy_id,
    })
}

// ---------------------------------------------------------------------------
// Section 73 voice
// ---------------------------------------------------------------------------

/// The denial a `deny` class produces — spec section 73's four beats:
/// what happened, why, which policy, what to do next; plus the fourth
/// thing section 73 demands of an AI-facing denial, *whether approval is
/// possible*, answered honestly with "not for this class".
///
/// `event_id` is the audit event this denial was already recorded as, so
/// the human reading the agent's transcript and the human reading the
/// trail are looking at the same fact (Plate D-012 section II.03).
pub fn credential_denied_message(
    class: &CredentialClass,
    authority: &CredentialAuthority,
    requester: &str,
    event_id: &str,
) -> String {
    let citation = if authority.from_org {
        format!(
            "Policy: {} · {}",
            authority.policy_name, authority.policy_id
        )
    } else if authority.stated {
        format!("Policy: {} — you made this rule.", authority.policy_name)
    } else {
        format!(
            "Policy: {} — no policy names this credential, so Punar refuses it \
             rather than guessing.",
            authority.policy_name
        )
    };
    let next = if authority.from_org {
        "Request an exception: approval required.\n\
         Change it: ask the policy owner named above."
    } else {
        "Change it: punarctl policy effective --ai, or System Control → AI.\n\
         Approval is not available for this class."
    };
    format!(
        "{} credentials are not issued to {requester} on this device.\n\n\
         {citation}\n\
         Requested by: {requester}\n\
         Recorded: {event_id} — the requester was told the same sentence you are reading.\n\n\
         {next}",
        class.display
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classes::ClassCatalog;

    const SECTION_20: &str = "ai:\n  agents:\n    default:\n      filesystem:\n        \
workspace: read_write\n      host:\n        firewall: deny\n      network:\n        \
internet: allow\n      credentials:\n        github: allow\n        aws_dev: request\n        \
aws_prod: deny\n";

    fn dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "punar-secrets-policy-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The shipped defaults plus the org drop directory — named `policy.d`
    /// because that is what it is: the one directory punard reads too.
    fn personal(tag: &str, body: &str) -> (PathBuf, PathBuf) {
        let dir = dir(tag);
        let defaults = dir.join("ai-defaults.yaml");
        std::fs::write(&defaults, body).unwrap();
        (defaults, dir.join("policy.d"))
    }

    /// Drop one org AI document the way a real one arrives: the YAML plus
    /// its policy-source envelope.
    fn drop_org(org: &Path, policy_id: &str, body: &str, envelope: &str) {
        std::fs::create_dir_all(org).unwrap();
        std::fs::write(org.join(format!("{policy_id}.yaml")), body).unwrap();
        std::fs::write(org.join(format!("{policy_id}.json")), envelope).unwrap();
    }

    const ENG_AI_V3_ENVELOPE: &str =
        include_str!("../../../fixtures/policies/policy-source-eng-ai-v3.json");

    #[test]
    fn the_section_20_block_resolves_to_its_three_decisions() {
        let (defaults, org) = personal("s20", SECTION_20);
        let set = AiPolicySet::load(&defaults, &org).unwrap();
        assert!(!set.enrolled());
        assert_eq!(
            set.credential_decision("github").grant,
            CredentialGrant::Allow
        );
        assert_eq!(
            set.credential_decision("aws_dev").grant,
            CredentialGrant::Request
        );
        let prod = set.credential_decision("aws_prod");
        assert_eq!(prod.grant, CredentialGrant::Deny);
        assert_eq!(prod.policy_id, POLICY_PERSONAL_DEFAULTS);
        assert!(prod.stated);
        assert!(!prod.from_org);
    }

    #[test]
    fn an_unnamed_credential_is_denied_and_says_so() {
        let (defaults, org) = personal("unnamed", SECTION_20);
        let set = AiPolicySet::load(&defaults, &org).unwrap();
        let decision = set.credential_decision("gcp_prod");
        assert_eq!(decision.grant, CredentialGrant::Deny);
        assert_eq!(decision.policy_id, POLICY_FAIL_CLOSED);
        assert!(!decision.stated, "the trail must not claim a rule exists");
    }

    /// The section 39 ladder, on the credential block: an organization
    /// layer outranks personal defaults, in both directions.
    #[test]
    fn an_org_layer_outranks_personal_defaults() {
        let (defaults, org) = personal("ladder", SECTION_20);
        drop_org(
            &org,
            "eng-ai-v3",
            "ai:\n  agents:\n    default:\n      credentials:\n        github: deny\n        \
             aws_prod: allow\n",
            ENG_AI_V3_ENVELOPE,
        );
        // The desired-state envelope enrollment writes into the same
        // directory carries no AI document and must not become a layer.
        std::fs::write(
            org.join("eng-baseline-v12.json"),
            r#"{"policy_id":"eng-baseline-v12","source_kind":"organization_baseline",
                "precedence_rank":2,"policy":{}}"#,
        )
        .unwrap();
        let set = AiPolicySet::load(&defaults, &org).unwrap();
        assert!(set.enrolled());
        assert_eq!(set.layers.len(), 2, "defaults + one org AI layer");

        let github = set.credential_decision("github");
        assert_eq!(github.grant, CredentialGrant::Deny);
        assert_eq!(github.policy_id, "eng-ai-v3");
        assert_eq!(github.policy_name, "Acme Engineering AI Policy");
        assert!(github.from_org);

        // The org layer can also loosen; the ladder is precedence, not
        // "strictest wins" (spec section 39).
        assert_eq!(
            set.credential_decision("aws_prod").grant,
            CredentialGrant::Allow
        );
        // Keys the org layer does not mention still come from defaults.
        let aws_dev = set.credential_decision("aws_dev");
        assert_eq!(aws_dev.grant, CredentialGrant::Request);
        assert_eq!(aws_dev.policy_id, POLICY_PERSONAL_DEFAULTS);
    }

    #[test]
    fn a_broken_org_layer_denies_everything_instead_of_failing_open() {
        let (defaults, org) = personal("broken", SECTION_20);
        drop_org(
            &org,
            "acme",
            "ai: [this is not a policy]\n",
            r#"{"policy_id":"acme","source_kind":"organization_baseline","precedence_rank":2}"#,
        );
        let set = AiPolicySet::load(&defaults, &org).unwrap();
        let github = set.credential_decision("github");
        assert_eq!(github.grant, CredentialGrant::Deny);
        assert_eq!(github.policy_id, "acme");
        assert!(!set.warnings.is_empty());
    }

    /// Provenance is not guessable — the rule punard's loader states, held
    /// here too, because the two daemons must skip exactly the same files.
    /// A YAML with no envelope, or one whose envelope lies about its rung,
    /// is ignored: it never becomes a rank-2 organization layer just by
    /// being named after one.
    #[test]
    fn a_yaml_without_a_truthful_envelope_is_ignored_not_obeyed() {
        let (defaults, org) = personal("noprov", SECTION_20);
        std::fs::create_dir_all(&org).unwrap();
        std::fs::write(
            org.join("mystery.yaml"),
            "ai:\n  agents:\n    default:\n      credentials:\n        github: deny\n",
        )
        .unwrap();
        drop_org(
            &org,
            "liar",
            "ai:\n  agents:\n    default:\n      credentials:\n        aws_dev: allow\n",
            r#"{"policy_id":"liar","source_kind":"organization_baseline","precedence_rank":1}"#,
        );

        let set = AiPolicySet::load(&defaults, &org).unwrap();
        assert!(!set.enrolled(), "neither drop earned an org rung");
        assert_eq!(
            set.credential_decision("github").grant,
            CredentialGrant::Allow,
            "the personal default still answers"
        );
        assert_eq!(
            set.credential_decision("aws_dev").grant,
            CredentialGrant::Request
        );
        assert_eq!(set.warnings.len(), 2, "both were ignored loudly");
        // Ignored, not `broken`: an unattributed file must not take every
        // credential on the device down with it.
        assert!(set.broken.is_empty());
    }

    #[test]
    fn a_missing_or_malformed_defaults_document_refuses_to_start() {
        let missing = AiPolicySet::load(
            Path::new("/nonexistent/ai-defaults.yaml"),
            Path::new("/nonexistent/policy.d"),
        );
        assert!(missing.is_err());

        let (defaults, org) = personal("malformed", "ai: 3\n");
        assert!(AiPolicySet::load(&defaults, &org).is_err());
    }

    /// A document that carries blocks this crate does not read must still
    /// load: the broker is not the owner of the whole document.
    #[test]
    fn unknown_sibling_blocks_are_tolerated() {
        let (defaults, org) = personal(
            "siblings",
            "ai:\n  agents:\n    default:\n      browser_automation:\n        \
             chrome: deny\n      credentials:\n        github: allow\n",
        );
        let set = AiPolicySet::load(&defaults, &org).unwrap();
        assert_eq!(
            set.credential_decision("github").grant,
            CredentialGrant::Allow
        );
    }

    #[test]
    fn an_empty_set_denies_everything() {
        let set = AiPolicySet::empty();
        assert_eq!(
            set.credential_decision("github").grant,
            CredentialGrant::Deny
        );
    }

    #[test]
    fn the_denial_prose_carries_the_four_beats_and_the_citation_that_applies() {
        let catalog = ClassCatalog::parse(include_str!("../share/classes.yaml")).unwrap();
        let class = catalog.get("aws-prod").unwrap();
        let (defaults, org) = personal("voice", SECTION_20);
        let set = AiPolicySet::load(&defaults, &org).unwrap();
        let authority = set.credential_decision("aws_prod");

        let message = credential_denied_message(class, &authority, "agt_4f21c09ab3e1", "evt_502");
        assert!(message.contains("AWS production (mock) credentials are not issued"));
        assert!(message.contains("personal defaults") || message.contains("Personal defaults"));
        assert!(message.contains("you made this rule"));
        assert!(message.contains("agt_4f21c09ab3e1"));
        assert!(message.contains("evt_502"));
        assert!(message.contains("punarctl policy effective --ai"));
        assert!(
            message.contains("Approval is not available for this class"),
            "section 73 requires saying whether approval is possible"
        );
    }

    #[test]
    fn an_enrolled_denial_cites_the_org_and_offers_the_exception_path() {
        let catalog = ClassCatalog::parse(include_str!("../share/classes.yaml")).unwrap();
        let class = catalog.get("aws-prod").unwrap();
        let authority = CredentialAuthority {
            grant: CredentialGrant::Deny,
            policy_id: "eng-ai-v3".to_string(),
            policy_name: "Acme AI Engineering Baseline v3".to_string(),
            source: PolicySource::OrganizationMandatory,
            from_org: true,
            stated: true,
        };
        let message = credential_denied_message(class, &authority, "agt_1", "evt_9");
        assert!(message.contains("Acme AI Engineering Baseline v3 · eng-ai-v3"));
        assert!(message.contains("Request an exception"));
        assert!(
            !message.contains("you made this rule"),
            "org citations replace the personal one (DESIGN_LANGUAGE section 8)"
        );
    }
}
