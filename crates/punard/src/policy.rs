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

use std::collections::{BTreeMap, BTreeSet};
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

/// One provenance-tagged organization opinion about application lifecycle.
/// Application names are catalog ids (docs/design/app-catalog.md section
/// 1.3), never package-manager identifiers supplied by an IPC caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationPolicyLayer {
    pub provenance: Provenance,
    pub required: BTreeSet<String>,
    pub denied: BTreeSet<String>,
    pub allow_user_install: Option<bool>,
}

/// The two lifecycle mutations governed by SPEC section 46.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationPolicyAction {
    Install,
    Remove,
}

/// A closed reason vocabulary for authorization, audit details and UI copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationPolicyReason {
    Required,
    Denied,
    UserInstallAllowed,
    UserInstallBlocked,
    NoManagedPolicy,
    UserRemovalAllowed,
}

impl ApplicationPolicyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Denied => "denied",
            Self::UserInstallAllowed => "user_install_allowed",
            Self::UserInstallBlocked => "user_install_blocked",
            Self::NoManagedPolicy => "no_managed_policy",
            Self::UserRemovalAllowed => "user_removal_allowed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationPolicyDecision {
    pub allowed: bool,
    pub reason: ApplicationPolicyReason,
    pub provenance: Option<Provenance>,
}

/// Result of loading `policy.d/`.
#[derive(Debug, Default)]
pub struct LoadedPolicies {
    /// Flattened org-layer entries, in ascending-filename order.
    pub layers: Vec<Layer>,
    /// SPEC section 46 application layers, retained separately because app
    /// membership is not a scalar capability value.
    pub applications: Vec<ApplicationPolicyLayer>,
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
                if let Some(application) = extract_application_policy(payload, &provenance)? {
                    loaded.applications.push(application);
                }
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

fn non_empty_catalog_id(value: &Value, field: &str, path: &Path) -> io::Result<String> {
    let Some(id) = value.as_str().map(str::trim).filter(|id| !id.is_empty()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: {field} must contain non-empty catalog ids",
                path.display()
            ),
        ));
    };
    Ok(id.to_string())
}

/// Extract and validate the strict `spec.applications` shape from a desired
/// state payload. The envelope schema intentionally permits other policy
/// document kinds, so absence is not an error; once the subtree exists,
/// malformed lifecycle policy refuses daemon start/enrollment.
fn extract_application_policy(
    document: &Value,
    provenance: &Provenance,
) -> io::Result<Option<ApplicationPolicyLayer>> {
    let Some(applications) = document
        .get("spec")
        .and_then(|spec| spec.get("applications"))
    else {
        return Ok(None);
    };
    let path = Path::new("spec.applications");
    let Some(object) = applications.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "spec.applications must be an object",
        ));
    };
    for key in object.keys() {
        if !matches!(key.as_str(), "required" | "denied" | "allowUserInstall") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("spec.applications contains unsupported field {key:?}"),
            ));
        }
    }

    let Some(required_values) = object.get("required").and_then(Value::as_array) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "spec.applications.required must be an array",
        ));
    };
    let mut required = BTreeSet::new();
    for value in required_values {
        let id = non_empty_catalog_id(value, "spec.applications.required", path)?;
        if !required.insert(id.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("spec.applications.required contains duplicate {id:?}"),
            ));
        }
    }

    let mut denied = BTreeSet::new();
    if let Some(denied_values) = object.get("denied") {
        let Some(entries) = denied_values.as_array() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "spec.applications.denied must be an array",
            ));
        };
        for entry in entries {
            let Some(entry) = entry.as_object() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "spec.applications.denied entries must be objects",
                ));
            };
            if entry.len() != 1 || !entry.contains_key("package") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "spec.applications.denied entries contain only package",
                ));
            }
            let id = non_empty_catalog_id(
                entry.get("package").expect("checked above"),
                "spec.applications.denied.package",
                path,
            )?;
            if !denied.insert(id.clone()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("spec.applications.denied contains duplicate {id:?}"),
                ));
            }
        }
    }
    if let Some(conflict) = required.intersection(&denied).next() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("spec.applications cannot require and deny {conflict:?}"),
        ));
    }

    let allow_user_install = match object.get("allowUserInstall") {
        Some(value) => Some(value.as_bool().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "spec.applications.allowUserInstall must be boolean",
            )
        })?),
        None => None,
    };

    Ok(Some(ApplicationPolicyLayer {
        provenance: provenance.clone(),
        required,
        denied,
        allow_user_install,
    }))
}

fn higher_precedence<'a>(
    current: Option<&'a ApplicationPolicyLayer>,
    candidate: &'a ApplicationPolicyLayer,
) -> Option<&'a ApplicationPolicyLayer> {
    match current {
        Some(winner) if winner.provenance.rank <= candidate.provenance.rank => Some(winner),
        _ => Some(candidate),
    }
}

/// Resolve one application lifecycle request through the same lower-rank-wins
/// precedence ladder as scalar desired state. On a managed device, absence of
/// a usable application layer fails closed for installs; removing a
/// non-required app remains the user's choice.
pub fn evaluate_application_policy(
    layers: &[ApplicationPolicyLayer],
    id: &str,
    action: ApplicationPolicyAction,
) -> ApplicationPolicyDecision {
    let mut membership: Option<&ApplicationPolicyLayer> = None;
    for layer in layers {
        if layer.required.contains(id) || layer.denied.contains(id) {
            membership = higher_precedence(membership, layer);
        }
    }
    if let Some(layer) = membership {
        let required = layer.required.contains(id);
        return match (action, required) {
            (ApplicationPolicyAction::Install, true) => ApplicationPolicyDecision {
                allowed: true,
                reason: ApplicationPolicyReason::Required,
                provenance: Some(layer.provenance.clone()),
            },
            (ApplicationPolicyAction::Install, false) => ApplicationPolicyDecision {
                allowed: false,
                reason: ApplicationPolicyReason::Denied,
                provenance: Some(layer.provenance.clone()),
            },
            (ApplicationPolicyAction::Remove, true) => ApplicationPolicyDecision {
                allowed: false,
                reason: ApplicationPolicyReason::Required,
                provenance: Some(layer.provenance.clone()),
            },
            (ApplicationPolicyAction::Remove, false) => ApplicationPolicyDecision {
                allowed: true,
                reason: ApplicationPolicyReason::UserRemovalAllowed,
                provenance: Some(layer.provenance.clone()),
            },
        };
    }

    if action == ApplicationPolicyAction::Remove {
        return ApplicationPolicyDecision {
            allowed: true,
            reason: ApplicationPolicyReason::UserRemovalAllowed,
            provenance: None,
        };
    }

    let mut install_policy: Option<&ApplicationPolicyLayer> = None;
    for layer in layers {
        if layer.allow_user_install.is_some() {
            install_policy = higher_precedence(install_policy, layer);
        }
    }
    match install_policy {
        Some(layer) if layer.allow_user_install == Some(true) => ApplicationPolicyDecision {
            allowed: true,
            reason: ApplicationPolicyReason::UserInstallAllowed,
            provenance: Some(layer.provenance.clone()),
        },
        Some(layer) => ApplicationPolicyDecision {
            allowed: false,
            reason: ApplicationPolicyReason::UserInstallBlocked,
            provenance: Some(layer.provenance.clone()),
        },
        None => ApplicationPolicyDecision {
            allowed: false,
            reason: ApplicationPolicyReason::NoManagedPolicy,
            provenance: None,
        },
    }
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
/// `security.firewall: "enabled"|"disabled"`. `spec.applications` is consumed
/// by the set-membership application-policy engine above; every other
/// `spec.*` subtree is reported in `unmapped` (no registered capability exists
/// for it yet — honest limit, milestone-4.md section 3.2).
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
            ("applications", Some(_)) => {}
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
        assert_eq!(loaded.applications.len(), 1);
        assert_eq!(
            loaded.applications[0].required,
            BTreeSet::from(["git".to_string(), "podman".to_string()])
        );
        assert!(loaded.applications[0].denied.is_empty());
        assert_eq!(loaded.applications[0].allow_user_install, None);
        assert!(!loaded.unmapped.is_empty(), "acme spec has unmapped paths");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn managed_application_policy_is_precedence_aware_and_fail_closed() {
        let baseline = ApplicationPolicyLayer {
            provenance: Provenance {
                kind: SourceKind::OrganizationBaseline,
                rank: 2,
                policy_id: "baseline".into(),
                source_name: "Engineering Baseline".into(),
            },
            required: BTreeSet::from(["claude-desktop".into()]),
            denied: BTreeSet::from(["discord".into()]),
            allow_user_install: Some(false),
        };
        let role = ApplicationPolicyLayer {
            provenance: Provenance {
                kind: SourceKind::OrganizationRolePolicy,
                rank: 3,
                policy_id: "developer-role".into(),
                source_name: "Developer Role".into(),
            },
            required: BTreeSet::new(),
            denied: BTreeSet::new(),
            allow_user_install: Some(true),
        };
        let layers = [role, baseline];

        let required = evaluate_application_policy(
            &layers,
            "claude-desktop",
            ApplicationPolicyAction::Install,
        );
        assert!(required.allowed);
        assert_eq!(required.reason, ApplicationPolicyReason::Required);
        assert_eq!(required.provenance.unwrap().policy_id, "baseline");

        let remove_required =
            evaluate_application_policy(&layers, "claude-desktop", ApplicationPolicyAction::Remove);
        assert!(!remove_required.allowed);
        assert_eq!(remove_required.reason, ApplicationPolicyReason::Required);

        let denied =
            evaluate_application_policy(&layers, "discord", ApplicationPolicyAction::Install);
        assert!(!denied.allowed);
        assert_eq!(denied.reason, ApplicationPolicyReason::Denied);

        let optional =
            evaluate_application_policy(&layers, "spotify", ApplicationPolicyAction::Install);
        assert!(!optional.allowed, "rank-2 false beats rank-3 true");
        assert_eq!(optional.reason, ApplicationPolicyReason::UserInstallBlocked);
        assert_eq!(optional.provenance.unwrap().policy_id, "baseline");

        let remove_optional =
            evaluate_application_policy(&layers, "spotify", ApplicationPolicyAction::Remove);
        assert!(remove_optional.allowed);
        assert_eq!(
            remove_optional.reason,
            ApplicationPolicyReason::UserRemovalAllowed
        );

        let missing = evaluate_application_policy(&[], "spotify", ApplicationPolicyAction::Install);
        assert!(!missing.allowed);
        assert_eq!(missing.reason, ApplicationPolicyReason::NoManagedPolicy);
    }

    #[test]
    fn contradictory_application_membership_refuses_policy_load() {
        let dir = tmp("load-app-conflict");
        let mut envelope = acme_combined();
        envelope["policy"]["spec"]["applications"] = json!({
            "required": ["spotify"],
            "denied": [{"package": "spotify"}],
            "allowUserInstall": true
        });
        std::fs::write(
            dir.join("bad.json"),
            serde_json::to_vec_pretty(&envelope).unwrap(),
        )
        .unwrap();
        let error = load_policy_dir(&dir).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot require and deny \"spotify\""),
            "{error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn absent_policy_dir_is_empty_not_an_error() {
        let dir = tmp("load-absent").join("does-not-exist");
        let loaded = load_policy_dir(&dir).unwrap();
        assert!(loaded.layers.is_empty());
        assert!(loaded.applications.is_empty());
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
