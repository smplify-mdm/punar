//! The layered desired-state document: org-layer loading (`policy.d/`),
//! `DeviceDesiredState` flattening, and the effective-document computation
//! over [`punar_policy::merge`] (SPEC sections 38, 39, 40;
//! docs/development/milestone-4.md section 3).
//!
//! Personal mode (design language section 8): the shipped image's
//! `policy.d/` is empty, so the only layers that ever apply in the VM are
//! the OS defaults and user preferences. The org rungs exist here — loaded,
//! validated, merged, and tested against `fixtures/organizations/acme` — so
//! Milestone 5 enrollment drops files into an engine that already works.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use punar_policy::{Classification, EffectiveEntry, LayerValue, Provenance, SourceKind, merge};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::capability::Registry;
use crate::state::{OsDefaultsStore, PreferencesStore};
use crate::util::write_atomic;

/// The built-in personal-mode policy id (`punar_common` audit constant,
/// re-exported here for provenance construction).
pub const POLICY_PERSONAL_DEFAULTS: &str = punar_common::audit::POLICY_PERSONAL_DEFAULTS;

/// Personal-mode provenance for the OS-default layer (rank 6).
pub fn personal_os_default() -> Provenance {
    Provenance {
        kind: SourceKind::OsSecureDefault,
        rank: SourceKind::OsSecureDefault.fixed_rank().expect("laddered"),
        policy_id: POLICY_PERSONAL_DEFAULTS.to_string(),
        source_name: "OS default".to_string(),
    }
}

/// Personal-mode provenance for the User Preference layer (rank 5).
pub fn personal_user_preference() -> Provenance {
    Provenance {
        kind: SourceKind::LocalUserPreference,
        rank: SourceKind::LocalUserPreference
            .fixed_rank()
            .expect("laddered"),
        policy_id: POLICY_PERSONAL_DEFAULTS.to_string(),
        source_name: "Personal preference".to_string(),
    }
}

// ---------------------------------------------------------------------------
// policy.d loader (org layers; reserved until M5 in the image)
// ---------------------------------------------------------------------------

/// A `schemas/policy/policy-source.json` envelope as stored in `policy.d/`.
/// Strict (`deny_unknown_fields`), mirroring the schema's
/// `additionalProperties: false`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicySourceEnvelope {
    policy_id: String,
    source_kind: SourceKind,
    precedence_rank: u32,
    #[serde(default)]
    source_name: Option<String>,
    /// `DeviceDesiredState` payload (`schemas/desired-state`).
    #[serde(default)]
    policy: Option<Value>,
    // Envelope fields the M4 loader accepts but does not act on yet
    // (approvals are M9; expiry enforcement arrives with enrollment).
    #[serde(default)]
    approval_id: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
}

/// One provenance-tagged layer opinion: `(capability path, layer value)`.
pub type Layer = (String, LayerValue<Value>);

/// Result of loading `policy.d/`.
#[derive(Debug, Default)]
pub struct LoadedPolicies {
    /// Flattened org-layer entries, in ascending-filename order.
    pub layers: Vec<Layer>,
    /// `spec.*` paths that have no registered capability yet — logged once
    /// at load and ignored (they land with their capabilities, M5+).
    pub unmapped: Vec<String>,
}

/// Load every `*.json` policy-source envelope from `dir` (ascending
/// filename order; an absent directory is simply empty). Errors — a corrupt
/// envelope, a duplicate `policy_id`, or a stored `precedence_rank` that
/// contradicts the schema's fixed ladder — refuse daemon start, the same
/// posture as a corrupt store.
pub fn load_policy_dir(dir: &Path) -> io::Result<LoadedPolicies> {
    let mut files: Vec<_> = match fs::read_dir(dir) {
        Ok(entries) => entries
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    files.sort();

    let mut loaded = LoadedPolicies::default();
    let mut seen_ids: Vec<String> = Vec::new();
    for path in files {
        let content = fs::read_to_string(&path)?;
        let envelope: PolicySourceEnvelope = serde_json::from_str(&content).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is not a valid policy-source envelope: {e}",
                    path.display()
                ),
            )
        })?;
        if seen_ids.contains(&envelope.policy_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "duplicate policy_id {:?} in {} — refusing to start",
                    envelope.policy_id,
                    dir.display()
                ),
            ));
        }
        // The six laddered kinds have schema-fixed ranks; a contradicting
        // stored rank is a corrupt envelope. device_specific_override's
        // rank is stored data and accepted as-is.
        let contradicted = envelope
            .source_kind
            .fixed_rank()
            .is_some_and(|fixed| envelope.precedence_rank != fixed);
        if contradicted {
            let fixed = envelope.source_kind.fixed_rank().expect("checked above");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: source_kind {} has fixed precedence rank {fixed}, \
                     but the envelope stores {} — refusing to start",
                    path.display(),
                    envelope.source_kind.as_str(),
                    envelope.precedence_rank
                ),
            ));
        }
        let _ = (&envelope.approval_id, &envelope.expires_at); // accepted, unused in M4

        let provenance = Provenance {
            kind: envelope.source_kind,
            rank: envelope.precedence_rank,
            policy_id: envelope.policy_id.clone(),
            source_name: envelope
                .source_name
                .clone()
                .unwrap_or_else(|| envelope.policy_id.clone()),
        };
        match &envelope.policy {
            Some(payload) => {
                let flat = flatten_desired_state(payload);
                for (cap_path, value) in flat.mapped {
                    loaded.layers.push((
                        cap_path,
                        LayerValue {
                            value,
                            provenance: provenance.clone(),
                            // M4 default: the envelope schema carries no
                            // per-path classification yet; richer payloads
                            // arrive with enrollment (SPEC section 43 —
                            // alert_only / approval_required stay
                            // representable and engine-tested).
                            classification: Classification::AutoRemediate,
                        },
                    ));
                }
                loaded.unmapped.extend(flat.unmapped);
            }
            None => loaded.unmapped.push(format!(
                "{} (envelope without embedded policy payload)",
                envelope.policy_id
            )),
        }
        seen_ids.push(envelope.policy_id);
    }
    Ok(loaded)
}

/// Result of flattening one `DeviceDesiredState` payload.
#[derive(Debug, Default, PartialEq)]
pub struct FlattenedSpec {
    /// `(capability path, state value)` pairs for registered capabilities.
    pub mapped: Vec<(String, Value)>,
    /// `spec.*` paths this milestone has no capability for.
    pub unmapped: Vec<String>,
}

/// Flatten a `DeviceDesiredState` document (SPEC section 38) into
/// capability paths. M4 maps exactly
/// `spec.security.firewall.enabled: true|false` →
/// `security.firewall: "enabled"|"disabled"`; every other `spec.*` subtree
/// is reported in `unmapped` (no registered capability exists for it yet —
/// honest limit, milestone-4.md section 3.2).
pub fn flatten_desired_state(document: &Value) -> FlattenedSpec {
    let mut flat = FlattenedSpec::default();
    let Some(spec) = document.get("spec").and_then(Value::as_object) else {
        flat.unmapped
            .push("(document without spec object)".to_string());
        return flat;
    };
    for (section, body) in spec {
        match (section.as_str(), body.as_object()) {
            ("security", Some(security)) => {
                for (key, setting) in security {
                    match (
                        key.as_str(),
                        setting.get("enabled").and_then(Value::as_bool),
                    ) {
                        ("firewall", Some(enabled)) => flat.mapped.push((
                            "security.firewall".to_string(),
                            if enabled {
                                json!("enabled")
                            } else {
                                json!("disabled")
                            },
                        )),
                        _ => flat.unmapped.push(format!("spec.security.{key}")),
                    }
                }
            }
            _ => flat.unmapped.push(format!("spec.{section}")),
        }
    }
    flat
}

// ---------------------------------------------------------------------------
// Effective document
// ---------------------------------------------------------------------------

/// The merged effective desired-state document — the in-memory truth,
/// recomputed at startup and on every `capabilities.set`
/// (milestone-4.md section 3.2).
#[derive(Debug, Clone)]
pub struct EffectiveDocument {
    /// RFC 3339, when this document was computed.
    pub computed_at: String,
    pub entries: BTreeMap<String, EffectiveEntry<Value>>,
}

impl EffectiveDocument {
    pub fn get(&self, path: &str) -> Option<&EffectiveEntry<Value>> {
        self.entries.get(path)
    }
}

/// Compute the effective document from the layers:
///
/// - rank 6, OS default: the backend's compiled default
///   ([`crate::capability::Capability::default_desired`]) where fixed, else
///   the persisted first-observation seed;
/// - rank 5, user preference: every recorded `preferences.json` entry;
/// - ranks 1–4 (and stored-rank overrides): the loaded `policy.d` layers.
///
/// Classification is data in the document (SPEC section 43): personal mode
/// classifies every capability `auto_remediate` — for the firewall that is
/// the SPEC 43 example; for hostname/timezone the desired state IS the
/// user's own recorded choice (or the stable seed), so restoring it is the
/// preference-honoring action.
pub fn compute_effective(
    registry: &Registry,
    os_defaults: &OsDefaultsStore,
    preferences: &PreferencesStore,
    org_layers: &[Layer],
    computed_at: String,
) -> EffectiveDocument {
    let mut layers: Vec<Layer> = Vec::new();
    for cap in registry.iter() {
        let id = cap.descriptor().capability.to_string();
        let default = cap
            .default_desired()
            .or_else(|| os_defaults.get(&id))
            .unwrap_or_else(|| json!("unknown"));
        layers.push((
            id,
            LayerValue {
                value: default,
                provenance: personal_os_default(),
                classification: Classification::AutoRemediate,
            },
        ));
    }
    for (id, entry) in preferences.entries() {
        layers.push((
            id,
            LayerValue {
                value: entry.value,
                provenance: personal_user_preference(),
                classification: Classification::AutoRemediate,
            },
        ));
    }
    layers.extend(org_layers.iter().cloned());

    EffectiveDocument {
        computed_at,
        entries: merge(layers),
    }
}

/// Materialize the document at `path` (0600, atomic) — a
/// **non-authoritative debug artifact**: the in-memory document is the
/// truth and is rebuilt from the layers at startup
/// (milestone-4.md section 3.2).
pub fn write_effective_debug_copy(path: &Path, doc: &EffectiveDocument) -> io::Result<()> {
    let value = json!({
        "computed_at": doc.computed_at,
        "note": "non-authoritative debug copy; punard recomputes from the layer stores",
        "entries": doc.entries,
    });
    let bytes = serde_json::to_vec_pretty(&value).expect("effective document serializes");
    write_atomic(path, &bytes, 0o600)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use punar_policy::USER_OVERRIDE_MIN_RANK;

    use super::*;
    use crate::capability::mock::MockCapability;
    use crate::state::PreferenceEntry;

    const ACME_ENVELOPE: &str =
        include_str!("../../../fixtures/organizations/acme/policy-source-eng-baseline-v12.json");
    const ACME_DESIRED: &str =
        include_str!("../../../fixtures/organizations/acme/desired-state-eng-baseline-v12.json");

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("punard-policy-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The Acme envelope fixture with its DeviceDesiredState fixture
    /// embedded as the `policy` payload (the two ship as separate fixture
    /// files; a policy.d drop carries them combined).
    fn acme_combined() -> Value {
        let mut envelope: Value = serde_json::from_str(ACME_ENVELOPE).unwrap();
        let desired: Value = serde_json::from_str(ACME_DESIRED).unwrap();
        envelope
            .as_object_mut()
            .unwrap()
            .insert("policy".to_string(), desired);
        envelope
    }

    #[test]
    fn flatten_maps_the_acme_firewall_and_reports_the_rest() {
        let desired: Value = serde_json::from_str(ACME_DESIRED).unwrap();
        let flat = flatten_desired_state(&desired);
        assert_eq!(
            flat.mapped,
            [("security.firewall".to_string(), json!("enabled"))]
        );
        for expected in [
            "spec.security.diskEncryption",
            "spec.security.secureBoot",
            "spec.applications",
            "spec.ai",
            "spec.network",
            "spec.update",
        ] {
            assert!(
                flat.unmapped.iter().any(|u| u == expected),
                "{expected} missing from unmapped: {:?}",
                flat.unmapped
            );
        }
    }

    #[test]
    fn flatten_maps_firewall_disabled() {
        let doc = json!({"spec": {"security": {"firewall": {"enabled": false}}}});
        let flat = flatten_desired_state(&doc);
        assert_eq!(
            flat.mapped,
            [("security.firewall".to_string(), json!("disabled"))]
        );
        assert!(flat.unmapped.is_empty());
    }

    #[test]
    fn load_policy_dir_reads_acme_envelopes_in_filename_order() {
        let dir = tmp("load-acme");
        std::fs::write(
            dir.join("eng-baseline-v12.json"),
            serde_json::to_string(&acme_combined()).unwrap(),
        )
        .unwrap();
        let loaded = load_policy_dir(&dir).unwrap();
        assert_eq!(loaded.layers.len(), 1);
        let (path, layer) = &loaded.layers[0];
        assert_eq!(path, "security.firewall");
        assert_eq!(layer.value, json!("enabled"));
        assert_eq!(layer.provenance.kind, SourceKind::OrganizationBaseline);
        assert_eq!(layer.provenance.rank, 2);
        assert_eq!(layer.provenance.policy_id, "eng-baseline-v12");
        assert_eq!(layer.provenance.source_name, "Acme Engineering Baseline");
        assert!(!loaded.unmapped.is_empty(), "acme spec has unmapped paths");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn absent_policy_dir_is_empty_not_an_error() {
        let dir = tmp("load-absent").join("does-not-exist");
        let loaded = load_policy_dir(&dir).unwrap();
        assert!(loaded.layers.is_empty());
        assert!(loaded.unmapped.is_empty());
    }

    #[test]
    fn duplicate_policy_id_refuses_to_start() {
        let dir = tmp("load-dup");
        let combined = serde_json::to_string(&acme_combined()).unwrap();
        std::fs::write(dir.join("a.json"), &combined).unwrap();
        std::fs::write(dir.join("b.json"), &combined).unwrap();
        let err = load_policy_dir(&dir).unwrap_err();
        assert!(err.to_string().contains("duplicate policy_id"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn contradicted_fixed_rank_refuses_to_start() {
        let dir = tmp("load-rank");
        let mut envelope = acme_combined();
        envelope["precedence_rank"] = json!(5); // organization_baseline is fixed at 2
        std::fs::write(
            dir.join("bad.json"),
            serde_json::to_string(&envelope).unwrap(),
        )
        .unwrap();
        let err = load_policy_dir(&dir).unwrap_err();
        assert!(err.to_string().contains("fixed precedence rank"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_envelope_refuses_to_start() {
        let dir = tmp("load-corrupt");
        std::fs::write(dir.join("bad.json"), "{oops").unwrap();
        assert!(load_policy_dir(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn stores(tag: &str) -> (PathBuf, OsDefaultsStore, PreferencesStore) {
        let dir = tmp(tag);
        let os_defaults = OsDefaultsStore::load(&dir.join("os-defaults.json")).unwrap();
        let preferences = PreferencesStore::load(&dir.join("preferences.json")).unwrap();
        (dir, os_defaults, preferences)
    }

    #[test]
    fn personal_mode_effective_document_prefers_the_user_over_the_seed() {
        let (dir, os_defaults, preferences) = stores("eff-personal");
        let registry = Registry::new(vec![
            Box::new(MockCapability::with_default(
                "security.firewall",
                json!("enabled"),
                json!("enabled"),
            )),
            Box::new(MockCapability::new("time.timezone", json!("UTC"))),
        ]);
        os_defaults.seed("time.timezone", json!("UTC")).unwrap();
        preferences
            .set(
                "security.firewall",
                PreferenceEntry {
                    value: json!("disabled"),
                    set_at: "2026-08-25T09:14:02Z".into(),
                    set_by: "root".into(),
                },
            )
            .unwrap();

        let doc = compute_effective(&registry, &os_defaults, &preferences, &[], "now".into());
        let firewall = doc.get("security.firewall").unwrap();
        assert_eq!(firewall.value, json!("disabled"));
        assert_eq!(firewall.provenance.kind, SourceKind::LocalUserPreference);
        assert_eq!(firewall.provenance.rank, USER_OVERRIDE_MIN_RANK);
        assert_eq!(firewall.provenance.policy_id, POLICY_PERSONAL_DEFAULTS);
        assert!(firewall.user_override_permitted);

        let timezone = doc.get("time.timezone").unwrap();
        assert_eq!(timezone.value, json!("UTC"));
        assert_eq!(timezone.provenance.kind, SourceKind::OsSecureDefault);
        assert_eq!(timezone.provenance.source_name, "OS default");
        assert!(timezone.user_override_permitted);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SPEC section 39/40 against the real Acme fixtures: the
    /// organization_baseline (rank 2) outranks the user preference and pins
    /// the value. Engine-level only — nothing org renders in the VM before
    /// M5 (design language section 8).
    #[test]
    fn acme_org_layer_beats_the_user_preference_end_to_end() {
        let (dir, os_defaults, preferences) = stores("eff-acme");
        let policy_dir = dir.join("policy.d");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(
            policy_dir.join("eng-baseline-v12.json"),
            serde_json::to_string(&acme_combined()).unwrap(),
        )
        .unwrap();
        let registry = Registry::new(vec![Box::new(MockCapability::new(
            "security.firewall",
            json!("disabled"),
        ))]);
        preferences
            .set(
                "security.firewall",
                PreferenceEntry {
                    value: json!("disabled"),
                    set_at: "2026-08-25T09:14:02Z".into(),
                    set_by: "root".into(),
                },
            )
            .unwrap();

        let loaded = load_policy_dir(&policy_dir).unwrap();
        let doc = compute_effective(
            &registry,
            &os_defaults,
            &preferences,
            &loaded.layers,
            "now".into(),
        );
        let firewall = doc.get("security.firewall").unwrap();
        assert_eq!(firewall.value, json!("enabled"));
        assert_eq!(firewall.provenance.kind, SourceKind::OrganizationBaseline);
        assert_eq!(firewall.provenance.policy_id, "eng-baseline-v12");
        assert!(
            !firewall.user_override_permitted,
            "rank 2 pins the value (SPEC section 40 'Not permitted')"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn effective_debug_copy_is_written_0600() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, os_defaults, preferences) = stores("eff-debug");
        let registry = Registry::new(vec![Box::new(MockCapability::new(
            "mock.widget",
            json!("off"),
        ))]);
        os_defaults.seed("mock.widget", json!("off")).unwrap();
        let doc = compute_effective(&registry, &os_defaults, &preferences, &[], "now".into());
        let path = dir.join("effective.json");
        write_effective_debug_copy(&path, &doc).unwrap();
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(raw["computed_at"], "now");
        assert_eq!(raw["entries"]["mock.widget"]["value"], "off");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
