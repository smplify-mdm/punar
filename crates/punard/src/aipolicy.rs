//! Loading the AI authority documents punard evaluates (SPEC section 20;
//! docs/development/milestone-9.md section 5).
//!
//! The types and the evaluation live in [`punar_common::aipolicy`] — shared,
//! because `punar-secrets` must reach the same verdict about a credential
//! class that punard reaches about a capability. This module is only the
//! **loader**: where the documents come from, what happens when one is
//! missing or malformed, and how a layer earns its rank in the section 39
//! ladder.
//!
//! # Two sources, and no third
//!
//! 1. **The shipped personal defaults**, `ai-defaults.yaml`
//!    ([`punar_common::aipolicy::AI_DEFAULTS_FILE`]), rank 6
//!    (`os_secure_default`). Compiled into the binary as a fallback so a
//!    missing or corrupt file degrades to the *known* defaults rather than
//!    to no policy at all — the M8 `process-classes.json` pattern, and the
//!    same bytes either way.
//! 2. **Organization AI documents** dropped into `policy.d/` as
//!    `<stem>.yaml` **beside a `<stem>.json` policy-source envelope** that
//!    declares the `policy_id`, `source_kind` and rank.
//!
//! A YAML with no envelope is **ignored, loudly**. Provenance is not
//! guessable: a document that cannot say who wrote it and at what rank has
//! no business outranking the OS default, and inventing a rank for it would
//! be exactly the "Punar does not guess" failure the milestone is about.
//!
//! # Honest status of source 2
//!
//! Milestone 9 ships **no producer** for an org AI document: the mock
//! control plane serves `eng-baseline-v12` only, and the enrollment chain
//! writes desired-state envelopes. The drop point is real and root-only
//! (a root file-drop into `policy.d/` is the documented manual path since
//! M4, milestone-5.md section 5.1), it is unit-tested against the shipped
//! `eng-ai-v3` fixture pair, and it will be fed by enrollment when an
//! organization publishes one. Until then this device evaluates the
//! personal defaults, and no surface claims otherwise.

use std::fs;
use std::io;
use std::path::Path;

use punar_common::aipolicy::{AiAuthority, AiLayer, AiPolicyDocument};
use punar_common::audit::POLICY_PERSONAL_DEFAULTS;
use punar_policy::SourceKind;
use serde::Deserialize;

/// The compiled-in copy of the shipped document. Single source of truth: the
/// image installs *this file* to
/// [`punar_common::aipolicy::AI_DEFAULTS_FILE`], and CI validates it against
/// `schemas/policy/ai-policy.json` through the existing
/// `fixtures/policies/ai-policy-*.yaml` glob.
pub const PERSONAL_DEFAULTS_YAML: &str =
    include_str!("../../../fixtures/policies/ai-policy-personal-defaults.yaml");

/// Display name for the shipped layer (DESIGN_LANGUAGE section 8: personal
/// mode cites PERSONAL DEFAULTS, org citations only when enrolled).
pub const PERSONAL_DEFAULTS_NAME: &str = "Personal defaults";

/// Rank of the shipped layer: `os_secure_default`, the weakest rung.
fn personal_rank() -> u32 {
    SourceKind::OsSecureDefault
        .fixed_rank()
        .expect("os_secure_default is a laddered kind")
}

/// The provenance half of an org AI drop — the same envelope shape the M4
/// `policy.d` loader reads, minus the desired-state payload it does not use.
#[derive(Debug, Deserialize)]
struct AiSourceEnvelope {
    policy_id: String,
    source_kind: SourceKind,
    precedence_rank: u32,
    #[serde(default)]
    source_name: Option<String>,
    /// Present on a desired-state envelope; irrelevant to an AI document and
    /// deliberately tolerated rather than rejected, so one envelope can
    /// describe both halves of a future org drop.
    #[serde(default)]
    #[allow(dead_code)]
    policy: Option<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    approval_id: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    expires_at: Option<String>,
}

/// Parse one AI authority document from YAML.
pub fn parse_document(text: &str) -> Result<AiPolicyDocument, String> {
    serde_norway::from_str::<AiPolicyDocument>(text).map_err(|e| e.to_string())
}

/// Load the effective AI authority for this device.
///
/// Never fails: an unreadable or malformed defaults file falls back to the
/// compiled-in copy (with a loud log), and a malformed org drop is skipped
/// (with a loud log) rather than taking the daemon down. The reasoning is
/// the same in both directions — the *safe* state here is "the strictest
/// policy we can still read", and refusing to boot would leave the device
/// with no gate at all.
pub fn load_authority(defaults_path: &Path, policy_dir: &Path) -> AiAuthority {
    let mut layers = vec![personal_layer(defaults_path)];
    match load_org_layers(policy_dir) {
        Ok(org) => layers.extend(org),
        Err(e) => eprintln!(
            "punard: could not read AI authority drops in {}: {e}; \
             evaluating personal defaults only",
            policy_dir.display()
        ),
    }
    AiAuthority::new(layers)
}

/// The rank-6 shipped layer, from disk when readable and from the compiled
/// copy otherwise.
fn personal_layer(defaults_path: &Path) -> AiLayer {
    let from_disk = fs::read_to_string(defaults_path)
        .map_err(|e| e.to_string())
        .and_then(|text| parse_document(&text));
    let document = match from_disk {
        Ok(document) => document,
        Err(e) => {
            eprintln!(
                "punard: AI defaults at {} unusable ({e}); using the compiled-in \
                 personal defaults — the same bytes the image ships",
                defaults_path.display()
            );
            parse_document(PERSONAL_DEFAULTS_YAML)
                .expect("the compiled-in personal defaults parse; a unit test pins this")
        }
    };
    AiLayer {
        policy_id: POLICY_PERSONAL_DEFAULTS.to_string(),
        source_name: PERSONAL_DEFAULTS_NAME.to_string(),
        rank: personal_rank(),
        document,
    }
}

/// Every `<stem>.yaml` in `policy_dir` that has a `<stem>.json` provenance
/// envelope beside it, in ascending filename order.
fn load_org_layers(policy_dir: &Path) -> io::Result<Vec<AiLayer>> {
    let mut files: Vec<_> = match fs::read_dir(policy_dir) {
        Ok(entries) => entries
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
            })
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    files.sort();

    let mut layers = Vec::new();
    for path in files {
        let envelope_path = path.with_extension("json");
        let Ok(envelope_text) = fs::read_to_string(&envelope_path) else {
            eprintln!(
                "punard: {} has no provenance envelope at {}; ignored — an AI \
                 authority document may not outrank the OS default without \
                 declaring who wrote it and at what rank",
                path.display(),
                envelope_path.display()
            );
            continue;
        };
        let envelope: AiSourceEnvelope = match serde_json::from_str(&envelope_text) {
            Ok(envelope) => envelope,
            Err(e) => {
                eprintln!(
                    "punard: {} is not a valid policy-source envelope ({e}); \
                     {} ignored",
                    envelope_path.display(),
                    path.display()
                );
                continue;
            }
        };
        // A stored rank that contradicts the schema's fixed ladder is a
        // corrupt envelope, exactly as in the M4 loader.
        if envelope
            .source_kind
            .fixed_rank()
            .is_some_and(|fixed| fixed != envelope.precedence_rank)
        {
            eprintln!(
                "punard: {} stores precedence_rank {} for source_kind {}; ignored",
                envelope_path.display(),
                envelope.precedence_rank,
                envelope.source_kind.as_str()
            );
            continue;
        }
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => {
                eprintln!("punard: could not read {}: {e}; ignored", path.display());
                continue;
            }
        };
        match parse_document(&text) {
            Ok(document) => layers.push(AiLayer {
                source_name: envelope
                    .source_name
                    .unwrap_or_else(|| envelope.policy_id.clone()),
                policy_id: envelope.policy_id,
                rank: envelope.precedence_rank,
                document,
            }),
            Err(e) => eprintln!(
                "punard: {} is not a valid AI authority document ({e}); ignored",
                path.display()
            ),
        }
    }
    Ok(layers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use punar_common::Decision;
    use punar_common::aipolicy::CredentialDecision;

    const ENG_AI_V3: &str =
        include_str!("../../../fixtures/policies/ai-policy-engineering-standard.yaml");
    const ENG_AI_V3_ENVELOPE: &str =
        include_str!("../../../fixtures/policies/policy-source-eng-ai-v3.json");

    fn dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("punard-ai-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The compiled fallback must always parse — the `expect` in
    /// [`personal_layer`] is only honest if this holds.
    #[test]
    fn the_compiled_personal_defaults_parse() {
        let document = parse_document(PERSONAL_DEFAULTS_YAML).unwrap();
        let profile = &document.ai.agents.default;
        assert_eq!(
            profile.host.get("firewall"),
            Some(&Decision::ApprovalRequired)
        );
        assert_eq!(profile.host.get("user_management"), Some(&Decision::Deny));
        assert_eq!(profile.host.get("system_update"), Some(&Decision::Deny));
        assert_eq!(
            profile.credentials.get("aws_dev"),
            Some(&CredentialDecision::Request)
        );
    }

    /// A missing defaults file must not leave the device ungated.
    #[test]
    fn a_missing_defaults_file_falls_back_to_the_compiled_copy() {
        let dir = dir("missing");
        let authority = load_authority(&dir.join("nope.yaml"), &dir.join("policy.d"));
        let ruling = authority.host_ruling("firewall").unwrap();
        assert_eq!(ruling.decision, Decision::ApprovalRequired);
        assert_eq!(ruling.policy_id, POLICY_PERSONAL_DEFAULTS);
        assert_eq!(ruling.rank, 6);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// So must a corrupt one — and it must say so rather than pretend.
    #[test]
    fn a_corrupt_defaults_file_falls_back_to_the_compiled_copy() {
        let dir = dir("corrupt");
        let path = dir.join("ai-defaults.yaml");
        fs::write(&path, "ai: [this is not a mapping]\n").unwrap();
        let authority = load_authority(&path, &dir.join("policy.d"));
        assert_eq!(
            authority.host_ruling("firewall").unwrap().decision,
            Decision::ApprovalRequired
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The section 39 ladder, end to end: an org drop with a declared
    /// provenance envelope outranks the shipped default, and the citation
    /// names the organization. This is the enrolled `eng-ai-v3` story.
    #[test]
    fn an_org_drop_with_provenance_outranks_the_personal_default() {
        let dir = dir("org");
        let policy_d = dir.join("policy.d");
        fs::create_dir_all(&policy_d).unwrap();
        fs::write(policy_d.join("eng-ai-v3.yaml"), ENG_AI_V3).unwrap();
        fs::write(policy_d.join("eng-ai-v3.json"), ENG_AI_V3_ENVELOPE).unwrap();

        let authority = load_authority(&dir.join("ai-defaults.yaml"), &policy_d);
        assert_eq!(authority.layers().len(), 2);
        let firewall = authority.host_ruling("firewall").unwrap();
        assert_eq!(firewall.decision, Decision::Deny);
        assert_eq!(firewall.policy_id, "eng-ai-v3");
        assert_eq!(firewall.source_name, "Acme Engineering AI Policy");
        // A token the org document does not name still resolves from the
        // shipped default: silence is not permission.
        assert_eq!(
            authority.host_ruling("timezone").unwrap().policy_id,
            POLICY_PERSONAL_DEFAULTS
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Provenance is not guessable. A YAML with no envelope is ignored —
    /// otherwise anything root ever dropped in `policy.d` could silently
    /// become policy at an invented rank.
    #[test]
    fn a_yaml_without_a_provenance_envelope_is_ignored() {
        let dir = dir("noprov");
        let policy_d = dir.join("policy.d");
        fs::create_dir_all(&policy_d).unwrap();
        fs::write(policy_d.join("mystery.yaml"), ENG_AI_V3).unwrap();

        let authority = load_authority(&dir.join("ai-defaults.yaml"), &policy_d);
        assert_eq!(authority.layers().len(), 1);
        assert_eq!(
            authority.host_ruling("firewall").unwrap().decision,
            Decision::ApprovalRequired
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A malformed drop is skipped, not fatal — and never silently upgrades
    /// the device's authority.
    #[test]
    fn a_malformed_org_drop_is_skipped() {
        let dir = dir("bad");
        let policy_d = dir.join("policy.d");
        fs::create_dir_all(&policy_d).unwrap();
        fs::write(policy_d.join("broken.yaml"), ": not : yaml :\n").unwrap();
        fs::write(policy_d.join("broken.json"), ENG_AI_V3_ENVELOPE).unwrap();
        // And one whose stored rank contradicts its declared kind.
        fs::write(policy_d.join("liar.yaml"), ENG_AI_V3).unwrap();
        fs::write(
            policy_d.join("liar.json"),
            r#"{"policy_id":"liar","source_kind":"organization_baseline","precedence_rank":1}"#,
        )
        .unwrap();

        let authority = load_authority(&dir.join("ai-defaults.yaml"), &policy_d);
        assert_eq!(authority.layers().len(), 1);
        assert_eq!(
            authority.host_ruling("firewall").unwrap().policy_id,
            POLICY_PERSONAL_DEFAULTS
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
