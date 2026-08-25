//! The credential-class catalog — **data, not code**
//! (milestone-9.md section 6.1, ipc.md section 16.3).
//!
//! `punar-secrets` ships no credential class in a Rust literal. The classes
//! it serves are read from `usr/share/punar/secrets/classes.yaml` at start;
//! a class that is not in that file does not exist, and a malformed file
//! refuses daemon start rather than serving a half-catalog (the `punard`
//! `policy.d` posture).
//!
//! Naming, decided once and enforced here: the class **id** is kebab-case
//! (`aws-dev`) — it is what travels on the wire, into the audit `resource`
//! field and into the M8 ledger, and spec section 29's request example
//! spells it that way. The **policy key** is snake_case (`aws_dev`),
//! because `schemas/policy/ai-policy.json`'s `propertyNames` pattern
//! forbids hyphens. The mapping is the declared `policy_key` field, never a
//! `replace('-','_')` guess, so the two spellings cannot drift apart
//! silently.

use std::fmt;
use std::path::{Path, PathBuf};

use punar_common::Risk;
use serde::{Deserialize, Serialize};

/// Lowest TTL a caller may request, seconds (ipc.md section 16.3).
pub const TTL_MIN_SECS: u64 = 5;
/// Highest TTL any class may declare, seconds (spec section 29's example
/// TTL is 3600; a class may declare less, never more).
pub const TTL_MAX_SECS: u64 = 3600;
/// The only provider Milestone 9 has. A real provider is Phase 2 work;
/// accepting an unknown provider name here would let a data file claim an
/// upstream that does not exist.
pub const PROVIDER_MOCK: &str = "mock";
/// The honesty label that travels with everything the mock issues.
pub const ATTESTATION_SIMULATED: &str = "simulated";

/// One credential class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClass {
    /// Kebab-case wire id (`github`, `aws-dev`, `aws-prod`).
    pub id: String,
    /// Human label for the issuance card (`"AWS development (mock)"`).
    pub display: String,
    /// Snake_case key under `ai.agents.default.credentials` in the AI
    /// authority document.
    pub policy_key: String,
    /// TTL used when the caller does not ask for one, seconds.
    pub default_ttl: u64,
    /// Longest TTL this class will ever issue, seconds. **Zero means the
    /// class is never issuable** — the shape `aws-prod` ships with, so a
    /// misconfigured policy still cannot mint a production token.
    pub max_ttl: u64,
    pub risk: Risk,
}

impl CredentialClass {
    /// Clamp a requested TTL into `[TTL_MIN_SECS, max_ttl]`, or use the
    /// class default when the caller asked for nothing. Clamping (rather
    /// than rejecting) matches `audit.tail`'s `n`: a request for more than
    /// policy allows is answered with what policy allows.
    pub fn effective_ttl(&self, requested: Option<u64>) -> u64 {
        let ttl = requested.unwrap_or(self.default_ttl);
        ttl.clamp(TTL_MIN_SECS.min(self.max_ttl), self.max_ttl)
    }

    /// Whether this class can ever produce a token (see `max_ttl`).
    pub fn issuable(&self) -> bool {
        self.max_ttl > 0
    }
}

/// The catalog as parsed from YAML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassCatalog {
    pub version: u64,
    pub provider: String,
    pub classes: Vec<CredentialClass>,
}

/// Why a catalog was refused. Every variant names the file and the exact
/// offending value: a broker that starts on a catalog it half-understood
/// would issue against a class nobody wrote.
#[derive(Debug)]
pub struct CatalogError {
    pub path: PathBuf,
    pub detail: String,
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.detail)
    }
}

impl std::error::Error for CatalogError {}

impl ClassCatalog {
    /// Read and validate a catalog file.
    pub fn load(path: impl AsRef<Path>) -> Result<ClassCatalog, CatalogError> {
        let path = path.as_ref();
        let fail = |detail: String| CatalogError {
            path: path.to_path_buf(),
            detail,
        };
        let text = std::fs::read_to_string(path)
            .map_err(|e| fail(format!("credential classes could not be read: {e}")))?;
        let catalog: ClassCatalog = serde_norway::from_str(&text)
            .map_err(|e| fail(format!("credential classes are not a valid catalog: {e}")))?;
        catalog.validate().map_err(fail)?;
        Ok(catalog)
    }

    /// Parse from a string (tests, and the `load` path above).
    pub fn parse(text: &str) -> Result<ClassCatalog, String> {
        let catalog: ClassCatalog =
            serde_norway::from_str(text).map_err(|e| format!("not a valid catalog: {e}"))?;
        catalog.validate()?;
        Ok(catalog)
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!(
                "catalog version {} is not supported; this build reads version 1",
                self.version
            ));
        }
        if self.provider != PROVIDER_MOCK {
            return Err(format!(
                "provider {:?} does not exist in this release — Milestone 9 ships the \
                 {PROVIDER_MOCK} provider only, and a catalog may not claim an upstream \
                 that is not there",
                self.provider
            ));
        }
        if self.classes.is_empty() {
            return Err(
                "a catalog with no classes would make every request a lie about \
                        what exists; list at least one class"
                    .to_string(),
            );
        }
        for class in &self.classes {
            if !class_id_ok(&class.id) {
                return Err(format!(
                    "credential class id {:?} must be kebab-case (^[a-z][a-z0-9-]*$, \
                     at most 64 bytes) so it is a valid audit resource and ledger \
                     resource class",
                    class.id
                ));
            }
            if !policy_key_ok(&class.policy_key) {
                return Err(format!(
                    "policy_key {:?} for class {:?} must be snake_case \
                     (^[a-z][a-z0-9_]*$) — schemas/policy/ai-policy.json forbids \
                     hyphens in credential keys",
                    class.policy_key, class.id
                ));
            }
            if class.display.trim().is_empty() {
                return Err(format!("class {:?} has an empty display name", class.id));
            }
            if class.max_ttl > TTL_MAX_SECS {
                return Err(format!(
                    "class {:?} declares max_ttl {} s, above the {TTL_MAX_SECS} s ceiling",
                    class.id, class.max_ttl
                ));
            }
            if class.max_ttl > 0 && class.max_ttl < TTL_MIN_SECS {
                return Err(format!(
                    "class {:?} declares max_ttl {} s, below the {TTL_MIN_SECS} s floor \
                     (use 0 for a class that is never issued)",
                    class.id, class.max_ttl
                ));
            }
            if class.default_ttl > class.max_ttl {
                return Err(format!(
                    "class {:?} declares default_ttl {} s above its max_ttl {} s",
                    class.id, class.default_ttl, class.max_ttl
                ));
            }
        }
        for (i, class) in self.classes.iter().enumerate() {
            if self.classes[..i].iter().any(|c| c.id == class.id) {
                return Err(format!("duplicate credential class id {:?}", class.id));
            }
            if self.classes[..i]
                .iter()
                .any(|c| c.policy_key == class.policy_key)
            {
                return Err(format!(
                    "duplicate policy_key {:?}: two classes cannot read one policy key",
                    class.policy_key
                ));
            }
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&CredentialClass> {
        self.classes.iter().find(|class| class.id == id)
    }

    pub fn ids(&self) -> Vec<&str> {
        self.classes.iter().map(|c| c.id.as_str()).collect()
    }
}

/// Kebab-case class id, also valid as a `punar_common::ledger`
/// `ResourceClass` (`^[a-z][a-z0-9_-]*$`) and as an audit `resource`.
pub fn class_id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= punar_common::ledger::MAX_RESOURCE_CLASS_BYTES
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Snake_case policy key, matching `ai-policy.json`'s `propertyNames`.
pub fn policy_key_ok(key: &str) -> bool {
    !key.is_empty()
        && key.starts_with(|c: char| c.is_ascii_lowercase())
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped catalog is a test fixture as well as a data file: if it
    /// stops validating, the daemon stops starting.
    const SHIPPED: &str = include_str!("../share/classes.yaml");

    #[test]
    fn the_shipped_catalog_parses_and_matches_the_documented_classes() {
        let catalog = ClassCatalog::parse(SHIPPED).expect("shipped catalog validates");
        assert_eq!(catalog.provider, PROVIDER_MOCK);
        assert_eq!(catalog.ids(), vec!["github", "aws-dev", "aws-prod"]);

        let github = catalog.get("github").unwrap();
        assert_eq!(github.policy_key, "github");
        assert_eq!(github.default_ttl, 3600);
        assert_eq!(github.risk, Risk::Low);

        // The kebab/snake split, pinned: this is the pair the ledger and
        // the policy document read respectively.
        let aws_dev = catalog.get("aws-dev").unwrap();
        assert_eq!(aws_dev.id, "aws-dev");
        assert_eq!(aws_dev.policy_key, "aws_dev");

        // aws-prod cannot be issued even if a policy said allow.
        let aws_prod = catalog.get("aws-prod").unwrap();
        assert!(!aws_prod.issuable());
        assert_eq!(aws_prod.risk, Risk::High);
    }

    #[test]
    fn every_shipped_class_id_is_a_valid_ledger_resource_class() {
        let catalog = ClassCatalog::parse(SHIPPED).unwrap();
        for id in catalog.ids() {
            assert!(
                punar_common::ledger::ResourceClass::new(
                    punar_common::ledger::ResourceCategory::CredentialClasses,
                    id
                )
                .is_ok(),
                "class id {id:?} must be usable as a ledger resource class"
            );
        }
    }

    #[test]
    fn ttl_requests_are_clamped_never_widened() {
        let catalog = ClassCatalog::parse(SHIPPED).unwrap();
        let github = catalog.get("github").unwrap();
        assert_eq!(github.effective_ttl(None), 3600);
        assert_eq!(github.effective_ttl(Some(5)), 5);
        assert_eq!(github.effective_ttl(Some(60)), 60);
        assert_eq!(github.effective_ttl(Some(1)), TTL_MIN_SECS);
        assert_eq!(github.effective_ttl(Some(99_999)), 3600);
        // A never-issuable class clamps to zero and is refused earlier.
        assert_eq!(catalog.get("aws-prod").unwrap().effective_ttl(Some(60)), 0);
    }

    fn catalog_error(yaml: &str) -> String {
        ClassCatalog::parse(yaml).expect_err("catalog should be refused")
    }

    #[test]
    fn a_catalog_that_cannot_be_trusted_is_refused() {
        let base = |body: &str| format!("version: 1\nprovider: mock\nclasses:\n{body}");
        let class = |id: &str, key: &str, default_ttl: u64, max_ttl: u64| {
            format!(
                "  - id: {id}\n    display: X\n    policy_key: {key}\n    \
                 default_ttl: {default_ttl}\n    max_ttl: {max_ttl}\n    risk: low\n"
            )
        };

        assert!(catalog_error("version: 2\nprovider: mock\nclasses: []").contains("version 2"));
        assert!(
            catalog_error("version: 1\nprovider: vault\nclasses: []").contains("does not exist")
        );
        assert!(catalog_error("version: 1\nprovider: mock\nclasses: []").contains("no classes"));
        assert!(
            catalog_error(&base(&class("AWS_Dev", "aws_dev", 60, 60))).contains("kebab-case"),
            "an id that is not kebab-case is refused"
        );
        assert!(
            catalog_error(&base(&class("aws-dev", "aws-dev", 60, 60))).contains("snake_case"),
            "a hyphenated policy key would never match the policy document"
        );
        assert!(catalog_error(&base(&class("a", "a", 60, 99_999))).contains("ceiling"));
        assert!(catalog_error(&base(&class("a", "a", 600, 60))).contains("above its max_ttl"));
        assert!(catalog_error(&base(&class("a", "a", 1, 1))).contains("floor"));
        assert!(
            catalog_error(&format!(
                "{}{}",
                base(&class("a", "a", 60, 60)),
                class("a", "b", 60, 60)
            ))
            .contains("duplicate credential class id")
        );
        assert!(
            catalog_error(&format!(
                "{}{}",
                base(&class("a", "k", 60, 60)),
                class("b", "k", 60, 60)
            ))
            .contains("duplicate policy_key")
        );
        // An unknown field is a typo in a security-relevant data file, not
        // something to ignore.
        assert!(
            ClassCatalog::parse(
                "version: 1\nprovider: mock\nclasses:\n  - id: a\n    display: X\n    \
                 policy_key: a\n    default_ttl: 60\n    max_ttl: 60\n    risk: low\n    \
                 ttl: 9\n"
            )
            .is_err()
        );
    }

    #[test]
    fn load_reports_the_path_it_could_not_read() {
        let err = ClassCatalog::load("/nonexistent/punar/classes.yaml").unwrap_err();
        assert!(err.to_string().contains("classes.yaml"), "{err}");
    }
}
