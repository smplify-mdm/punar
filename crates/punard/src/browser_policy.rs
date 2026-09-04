//! Chromium managed-policy extraction, precedence merge, and rendering.
//!
//! The writable vocabulary is loaded from the reviewed data file in
//! `browser/integration`; there is no arbitrary JSON pass-through. Punar
//! supplies a root-owned policy file to upstream Chromium and never patches,
//! injects into, or weakens the browser.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::policy::{
    ApplicationPolicyAction, ApplicationPolicyLayer, ApplicationPolicyReason,
    evaluate_webapp_policy,
};
use crate::util::{remove_synced, write_atomic_synced};
use punar_common::webapp::origin_from_start_url;
use punar_policy::Provenance;
use serde::Deserialize;
use serde_json::{Map, Value, json};

pub const CAPABILITY_ID: &str = "browser.policy";

const POLICY_ALLOWLIST: &str = include_str!("../../../browser/integration/policy-allowlist.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyAllowlist {
    v: u64,
    families: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserPolicyLayer {
    pub provenance: Provenance,
    pub policies: BTreeMap<String, Value>,
}

fn allowlist() -> io::Result<BTreeSet<String>> {
    let document: PolicyAllowlist = serde_json::from_str(POLICY_ALLOWLIST).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("browser policy allowlist is invalid: {error}"),
        )
    })?;
    if document.v != 1 || document.families.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "browser policy allowlist must be version 1 and contain families",
        ));
    }
    let mut keys = BTreeSet::new();
    for (family, values) in document.families {
        if family.is_empty() || values.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "browser policy allowlist families must be non-empty",
            ));
        }
        for key in values {
            if !keys.insert(key.clone()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("browser policy allowlist repeats {key:?}"),
                ));
            }
        }
    }
    Ok(keys)
}

fn string_list(value: &Value, key: &str) -> io::Result<()> {
    let Some(values) = value.as_array() else {
        return Err(invalid(key, "must be an array of strings"));
    };
    if values.len() > 1000
        || values.iter().any(|entry| {
            entry
                .as_str()
                .is_none_or(|text| text.is_empty() || text.len() > 2048 || text.contains('\0'))
        })
    {
        return Err(invalid(
            key,
            "must contain at most 1000 non-empty bounded strings",
        ));
    }
    Ok(())
}

fn object(value: &Value, key: &str) -> io::Result<()> {
    value
        .as_object()
        .map(|_| ())
        .ok_or_else(|| invalid(key, "must be an object"))
}

fn webapp_force_list(value: &Value) -> io::Result<()> {
    let Some(entries) = value.as_array() else {
        return Err(invalid("WebAppInstallForceList", "must be an array"));
    };
    if entries.len() > 256 {
        return Err(invalid(
            "WebAppInstallForceList",
            "may contain at most 256 entries",
        ));
    }
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            return Err(invalid("WebAppInstallForceList", "entries must be objects"));
        };
        let allowed = [
            "url",
            "default_launch_container",
            "create_desktop_shortcut",
            "fallback_app_name",
            "custom_name",
            "custom_icon",
            "install_as_shortcut",
        ];
        if entry.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(invalid(
                "WebAppInstallForceList",
                "entry contains an unsupported field",
            ));
        }
        let url = entry.get("url").and_then(Value::as_str).ok_or_else(|| {
            invalid(
                "WebAppInstallForceList",
                "every entry requires a string url",
            )
        })?;
        origin_from_start_url(url).map_err(|error| invalid("WebAppInstallForceList", &error))?;
        if let Some(container) = entry.get("default_launch_container")
            && !matches!(container.as_str(), Some("tab" | "window"))
        {
            return Err(invalid(
                "WebAppInstallForceList",
                "default_launch_container must be tab or window",
            ));
        }
        for field in ["create_desktop_shortcut", "install_as_shortcut"] {
            if entry.get(field).is_some_and(|value| !value.is_boolean()) {
                return Err(invalid(
                    "WebAppInstallForceList",
                    &format!("{field} must be boolean"),
                ));
            }
        }
        for field in ["fallback_app_name", "custom_name"] {
            if entry.get(field).is_some_and(|value| {
                value
                    .as_str()
                    .is_none_or(|text| text.is_empty() || text.len() > 128)
            }) {
                return Err(invalid(
                    "WebAppInstallForceList",
                    &format!("{field} must be a non-empty bounded string"),
                ));
            }
        }
        if entry.contains_key("custom_icon") {
            return Err(invalid(
                "WebAppInstallForceList",
                "custom_icon is allowlisted upstream but Punar refuses it because M11 never fetches icons",
            ));
        }
    }
    Ok(())
}

fn webapp_settings(value: &Value) -> io::Result<()> {
    let Some(entries) = value.as_array() else {
        return Err(invalid("WebAppSettings", "must be an array"));
    };
    if entries.len() > 256 {
        return Err(invalid("WebAppSettings", "may contain at most 256 entries"));
    }
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            return Err(invalid("WebAppSettings", "entries must be objects"));
        };
        if entry.keys().any(|key| {
            !matches!(
                key.as_str(),
                "manifest_id"
                    | "run_on_os_login"
                    | "prevent_close_after_run_on_os_login"
                    | "force_unregister_os_integration"
            )
        }) {
            return Err(invalid(
                "WebAppSettings",
                "entry contains an unsupported field",
            ));
        }
        let manifest_id = entry
            .get("manifest_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("WebAppSettings", "every entry requires manifest_id"))?;
        if manifest_id != "*" {
            origin_from_start_url(manifest_id)
                .map_err(|error| invalid("WebAppSettings", &error))?;
        }
        if entry.get("run_on_os_login").is_some_and(|value| {
            !matches!(value.as_str(), Some("allowed" | "blocked" | "run_windowed"))
        }) {
            return Err(invalid(
                "WebAppSettings",
                "run_on_os_login has an unsupported value",
            ));
        }
        for field in [
            "prevent_close_after_run_on_os_login",
            "force_unregister_os_integration",
        ] {
            if entry.get(field).is_some_and(|value| !value.is_boolean()) {
                return Err(invalid(
                    "WebAppSettings",
                    &format!("{field} must be boolean"),
                ));
            }
        }
    }
    Ok(())
}

fn invalid(key: &str, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "spec.browser policy {key:?} {reason}. Policy: browser/integration/policy-allowlist.json. Next step: correct the policy document; nothing was written"
        ),
    )
}

fn validate_value(key: &str, value: &Value) -> io::Result<()> {
    match key {
        "ExtensionInstallBlocklist"
        | "ExtensionInstallAllowlist"
        | "ExtensionInstallForcelist"
        | "URLBlocklist"
        | "URLAllowlist"
        | "CACertificates" => string_list(value, key),
        "ExtensionSettings" => object(value, key),
        "WebAppInstallForceList" => webapp_force_list(value),
        "WebAppSettings" => webapp_settings(value),
        "WebAppInstallByUserEnabled"
        | "PromptForDownloadLocation"
        | "SitePerProcess"
        | "RemoteDebuggingAllowed"
        | "SSLErrorOverrideAllowed"
        | "InsecurePrivateNetworkRequestsAllowed" => {
            if value.is_boolean() {
                Ok(())
            } else {
                Err(invalid(key, "must be boolean"))
            }
        }
        "DownloadRestrictions" => {
            if value.as_u64().is_some_and(|number| number <= 4) {
                Ok(())
            } else {
                Err(invalid(key, "must be an integer from 0 through 4"))
            }
        }
        "DownloadDirectory" => {
            if value
                .as_str()
                .is_some_and(|text| !text.is_empty() && text.len() <= 4096 && !text.contains('\0'))
            {
                Ok(())
            } else {
                Err(invalid(key, "must be a non-empty bounded string"))
            }
        }
        _ => Err(invalid(key, "is not allowlisted")),
    }
}

fn validate_hardening(key: &str, value: &Value) -> io::Result<()> {
    let correct = match key {
        "SitePerProcess" => value == &json!(true),
        "RemoteDebuggingAllowed"
        | "SSLErrorOverrideAllowed"
        | "InsecurePrivateNetworkRequestsAllowed" => value == &json!(false),
        _ => true,
    };
    if correct {
        Ok(())
    } else {
        Err(invalid(key, "requests a security-weakening value"))
    }
}

/// Re-validate a fully rendered document immediately before the privileged
/// backend writes it. This second boundary prevents a corrupt intermediate
/// state file from widening the allowlisted vocabulary.
pub fn validate_rendered_policy(value: &Value) -> io::Result<()> {
    let Some(object) = value.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rendered browser policy must be an object",
        ));
    };
    if object.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rendered browser policy must not be empty",
        ));
    }
    let allowed = allowlist()?;
    for (key, policy_value) in object {
        if !allowed.contains(key) {
            return Err(invalid(key, "is not allowlisted"));
        }
        validate_value(key, policy_value)?;
        validate_hardening(key, policy_value)?;
    }
    Ok(())
}

pub fn extract_browser_policy(
    document: &Value,
    provenance: &Provenance,
) -> io::Result<Option<BrowserPolicyLayer>> {
    let Some(browser) = document.get("spec").and_then(|spec| spec.get("browser")) else {
        return Ok(None);
    };
    let Some(object) = browser.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "spec.browser must be an object",
        ));
    };
    if object.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "spec.browser must contain at least one managed Chromium policy",
        ));
    }
    let allowed = allowlist()?;
    let mut policies = BTreeMap::new();
    for (key, value) in object {
        if !allowed.contains(key) {
            return Err(invalid(key, "is not allowlisted"));
        }
        validate_value(key, value)?;
        validate_hardening(key, value)?;
        policies.insert(key.clone(), value.clone());
    }
    Ok(Some(BrowserPolicyLayer {
        provenance: provenance.clone(),
        policies,
    }))
}

fn put_list_item(policy: &mut BTreeMap<String, Value>, key: &str, value: Value) {
    let values = policy
        .entry(key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(values) = values.as_array_mut()
        && !values.contains(&value)
    {
        values.push(value);
    }
}

/// Produce the exact root-owned Chromium policy object. `None` means a
/// personal device has no managed browser policy and the managed file must
/// be absent, not present-but-empty.
pub fn render_effective_browser_policy(
    applications: &[ApplicationPolicyLayer],
    browsers: &[BrowserPolicyLayer],
) -> io::Result<Option<Value>> {
    let has_application_browser_policy = applications.iter().any(|layer| {
        !layer.required_web_apps.is_empty()
            || !layer.denied_origins.is_empty()
            || layer.allow_user_install.is_some()
    });
    if browsers.is_empty() && !has_application_browser_policy {
        return Ok(None);
    }

    let mut winners: BTreeMap<String, (&BrowserPolicyLayer, &Value)> = BTreeMap::new();
    for layer in browsers {
        for (key, value) in &layer.policies {
            match winners.get(key) {
                Some((winner, _)) if winner.provenance.rank <= layer.provenance.rank => {}
                _ => {
                    winners.insert(key.clone(), (layer, value));
                }
            }
        }
    }
    let mut policy: BTreeMap<String, Value> = winners
        .into_iter()
        .map(|(key, (_, value))| (key, value.clone()))
        .collect();

    let mut origins = BTreeSet::new();
    for layer in applications {
        origins.extend(layer.denied_origins.iter().cloned());
        for manifest in layer.required_web_apps.values() {
            origins.insert(origin_from_start_url(&manifest.start_url).expect("validated policy"));
        }
    }
    for origin in origins {
        let mut winner: Option<(&ApplicationPolicyLayer, bool)> = None;
        for layer in applications {
            let required = layer.required_web_apps.values().any(|manifest| {
                origin_from_start_url(&manifest.start_url).ok().as_deref() == Some(&origin)
            });
            let denied = layer.denied_origins.contains(&origin);
            if required || denied {
                match winner {
                    Some((current, _)) if current.provenance.rank <= layer.provenance.rank => {}
                    _ => winner = Some((layer, required)),
                }
            }
        }
        if winner.is_some_and(|(_, required)| !required) {
            put_list_item(&mut policy, "URLBlocklist", json!(origin));
        }
    }

    let mut required_ids = BTreeSet::new();
    for layer in applications {
        required_ids.extend(layer.required_web_apps.keys().cloned());
    }
    for id in required_ids {
        let winner = applications
            .iter()
            .filter_map(|layer| layer.required_web_apps.get(&id).map(|app| (layer, app)))
            .min_by_key(|(layer, _)| layer.provenance.rank);
        if let Some((_, app)) = winner {
            let origin = origin_from_start_url(&app.start_url).expect("validated policy");
            let decision = evaluate_webapp_policy(
                applications,
                &id,
                &origin,
                ApplicationPolicyAction::Install,
            );
            // A higher-precedence origin denial must beat a lower-precedence
            // required app. Otherwise Chromium would be told both to block
            // the origin and force-install it.
            if !decision.allowed || decision.reason != ApplicationPolicyReason::RequiredWebApp {
                continue;
            }
            put_list_item(
                &mut policy,
                "WebAppInstallForceList",
                json!({
                    "url": app.start_url,
                    "default_launch_container": "window",
                    "create_desktop_shortcut": false,
                    "custom_name": app.name,
                }),
            );
            put_list_item(
                &mut policy,
                "WebAppSettings",
                json!({
                    "manifest_id": app.start_url,
                    "run_on_os_login": "blocked",
                }),
            );
        }
    }

    if let Some(layer) = applications
        .iter()
        .filter(|layer| layer.allow_user_install.is_some())
        .min_by_key(|layer| layer.provenance.rank)
    {
        policy.insert(
            "WebAppInstallByUserEnabled".into(),
            json!(layer.allow_user_install == Some(true)),
        );
    }

    for (key, value) in [
        ("SitePerProcess", json!(true)),
        ("RemoteDebuggingAllowed", json!(false)),
        ("SSLErrorOverrideAllowed", json!(false)),
        ("InsecurePrivateNetworkRequestsAllowed", json!(false)),
    ] {
        policy.insert(key.into(), value);
    }

    for (key, value) in &policy {
        validate_value(key, value)?;
        validate_hardening(key, value)?;
    }
    Ok(Some(Value::Object(Map::from_iter(policy))))
}

/// Persist the root-private renderer output consumed by the capability
/// backend. Absence is meaningful: personal mode removes the source so the
/// managed Chromium file is driven to `unmanaged` rather than `{}`.
pub fn persist_rendered_browser_policy(
    path: &Path,
    applications: &[ApplicationPolicyLayer],
    browsers: &[BrowserPolicyLayer],
) -> io::Result<()> {
    let Some(value) = render_effective_browser_policy(applications, browsers)? else {
        return remove_synced(path);
    };
    validate_rendered_policy(&value)?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "rendered browser policy path has no parent",
        )
    })?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let mut bytes = serde_json::to_vec_pretty(&value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    bytes.push(b'\n');
    write_atomic_synced(path, &bytes, 0o600)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use punar_common::webapp::{WebAppIconRequest, WebAppManifest};
    use punar_policy::SourceKind;

    fn provenance(rank: u32) -> Provenance {
        Provenance {
            kind: SourceKind::DeviceSpecificOverride,
            rank,
            policy_id: format!("browser-{rank}"),
            source_name: "Browser fixture".into(),
        }
    }

    #[test]
    fn unknown_and_weakening_keys_are_refused() {
        let unknown = json!({"spec": {"browser": {"NoSandbox": true}}});
        assert!(extract_browser_policy(&unknown, &provenance(2)).is_err());
        let weak = json!({"spec": {"browser": {"SitePerProcess": false}}});
        let error = extract_browser_policy(&weak, &provenance(2)).unwrap_err();
        assert!(error.to_string().contains("security-weakening"));
    }

    #[test]
    fn applications_render_real_origin_and_install_controls() {
        let required = WebAppManifest {
            v: 1,
            id: "linear".into(),
            name: "Linear".into(),
            start_url: "https://linear.app/inbox".into(),
            context: "org-acme".into(),
            workspace: "atlas".into(),
            icon: WebAppIconRequest::Generated,
        };
        let applications = ApplicationPolicyLayer {
            provenance: provenance(2),
            required: BTreeSet::new(),
            denied: BTreeSet::new(),
            required_web_apps: BTreeMap::from([("linear".into(), required)]),
            denied_origins: BTreeSet::from(["https://social.example".into()]),
            allow_user_install: Some(false),
        };
        let policy = render_effective_browser_policy(&[applications], &[])
            .unwrap()
            .unwrap();
        assert_eq!(policy["URLBlocklist"], json!(["https://social.example"]));
        assert_eq!(policy["WebAppInstallByUserEnabled"], json!(false));
        assert_eq!(policy["SitePerProcess"], json!(true));
        assert_eq!(policy["RemoteDebuggingAllowed"], json!(false));
        assert_eq!(
            policy["WebAppInstallForceList"][0]["url"],
            json!("https://linear.app/inbox")
        );
    }

    #[test]
    fn no_org_browser_opinion_means_no_managed_file() {
        assert_eq!(render_effective_browser_policy(&[], &[]).unwrap(), None);
    }

    #[test]
    fn higher_precedence_origin_denial_suppresses_required_install() {
        let required = WebAppManifest {
            v: 1,
            id: "linear".into(),
            name: "Linear".into(),
            start_url: "https://linear.app/inbox".into(),
            context: "org-acme".into(),
            workspace: "atlas".into(),
            icon: WebAppIconRequest::Generated,
        };
        let baseline = ApplicationPolicyLayer {
            provenance: provenance(3),
            required: BTreeSet::new(),
            denied: BTreeSet::new(),
            required_web_apps: BTreeMap::from([("linear".into(), required)]),
            denied_origins: BTreeSet::new(),
            allow_user_install: None,
        };
        let device_override = ApplicationPolicyLayer {
            provenance: provenance(1),
            required: BTreeSet::new(),
            denied: BTreeSet::new(),
            required_web_apps: BTreeMap::new(),
            denied_origins: BTreeSet::from(["https://linear.app".into()]),
            allow_user_install: None,
        };

        let policy = render_effective_browser_policy(&[baseline, device_override], &[])
            .unwrap()
            .unwrap();
        assert_eq!(policy["URLBlocklist"], json!(["https://linear.app"]));
        assert!(policy.get("WebAppInstallForceList").is_none());
        assert!(policy.get("WebAppSettings").is_none());
    }
}
