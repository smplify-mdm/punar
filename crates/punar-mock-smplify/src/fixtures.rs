//! Fixture loading: the Acme tree, served verbatim.
//!
//! The repo keeps the policy-source envelope and the `DeviceDesiredState`
//! payload as **separate fixture files**, while a `policy.d/` drop carries
//! them combined (the M4 loader's own test states this —
//! `crates/punard/src/policy.rs`). `policy.fetch` therefore performs
//! exactly one mechanical composition here: envelope fields verbatim +
//! `"policy": <desired-state file contents verbatim>`. Nothing is edited.
//!
//! **Decision — baseline only** (milestone-5.md section 4.4): the fetch set
//! is `eng-baseline-v12` alone. `policy-source-eng-ai-v3.json` has no
//! embedded `DeviceDesiredState` and no registered capability consumes
//! `spec.ai` until M7+ — serving it would add a load-time warning and zero
//! observable state. It joins the fetch set when AI capabilities land.
//!
//! Everything is loaded once at startup and fails loudly on any defect:
//! this is CI scaffolding, and a half-loaded fixture set that limps along
//! would only move the failure somewhere less legible.

use std::fmt;
use std::path::Path;

use serde_json::Value;

use crate::rbac::AdminDirectory;

/// A fixture-tree defect. One string, verbose on purpose — the only reader
/// is a person staring at a failed check.
#[derive(Debug)]
pub struct FixtureError(pub String);

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FixtureError {}

/// The loaded, composed fixture set the server answers from.
#[derive(Debug, Clone)]
pub struct FixtureSet {
    /// `org.json` `id` (log line only).
    pub org_id: String,
    /// `org.json` `discovery.domain` — the one domain `org.discover`
    /// answers for.
    pub domain: String,
    /// `org.json`, verbatim: the `organization` object in `org.discover`
    /// and `enroll.register` results.
    pub organization: Value,
    /// Composed policy-source envelopes (envelope fields verbatim +
    /// embedded `policy` payload) — the `policy.fetch` result set.
    pub policies: Vec<Value>,
    /// M10: the admin role table (`admins.json`), read only by the mock and
    /// served to nobody. Absent ⇒ the admin surface refuses everything and
    /// names the missing file (milestone-10.md section 9.1).
    pub admins: AdminDirectory,
}

/// Load and compose the fixture tree at `dir`.
pub fn load(dir: &Path) -> Result<FixtureSet, FixtureError> {
    let org_path = dir.join("org.json");
    let organization = read_json(&org_path)?;
    let org = organization
        .as_object()
        .ok_or_else(|| FixtureError(format!("{}: not a JSON object", org_path.display())))?;

    let org_id = str_field(org.get("id"), &org_path, "id")?;
    let domain = str_field(
        org.get("discovery").and_then(|d| d.get("domain")),
        &org_path,
        "discovery.domain",
    )?;
    let enrollment = org
        .get("enrollment")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            FixtureError(format!(
                "{}: missing \"enrollment\" object",
                org_path.display()
            ))
        })?;
    let baseline_id = str_field(
        enrollment.get("baseline_policy_id"),
        &org_path,
        "enrollment.baseline_policy_id",
    )?;
    let desired_state_file = str_field(
        enrollment.get("desired_state_file"),
        &org_path,
        "enrollment.desired_state_file",
    )?;
    // Both names become path components inside `dir`; refuse anything that
    // could step outside it. Cheap honesty, not a security boundary — the
    // fixtures ship in /usr/share and only root runs this.
    require_bare_name(&baseline_id, &org_path, "enrollment.baseline_policy_id")?;
    require_bare_name(
        &desired_state_file,
        &org_path,
        "enrollment.desired_state_file",
    )?;

    let envelope_path = dir.join(format!("policy-source-{baseline_id}.json"));
    let mut envelope = read_json(&envelope_path)?;
    {
        let envelope_obj = envelope.as_object_mut().ok_or_else(|| {
            FixtureError(format!("{}: not a JSON object", envelope_path.display()))
        })?;
        let envelope_id = envelope_obj
            .get("policy_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if envelope_id != baseline_id {
            return Err(FixtureError(format!(
                "{}: policy_id {envelope_id:?} does not match org.json \
                 enrollment.baseline_policy_id {baseline_id:?}",
                envelope_path.display()
            )));
        }
        if envelope_obj.contains_key("policy") {
            return Err(FixtureError(format!(
                "{}: already carries an embedded \"policy\" payload — the repo \
                 keeps envelope and desired state as separate fixture files \
                 (milestone-5.md section 4.4)",
                envelope_path.display()
            )));
        }
        let payload_path = dir.join(&desired_state_file);
        let payload = read_json(&payload_path)?;
        envelope_obj.insert("policy".to_string(), payload);
    }

    Ok(FixtureSet {
        org_id,
        domain,
        organization,
        policies: vec![envelope],
        admins: AdminDirectory::load(dir),
    })
}

fn read_json(path: &Path) -> Result<Value, FixtureError> {
    let bytes = std::fs::read(path)
        .map_err(|e| FixtureError(format!("{}: cannot read: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| FixtureError(format!("{}: not valid JSON: {e}", path.display())))
}

fn str_field(value: Option<&Value>, path: &Path, field: &str) -> Result<String, FixtureError> {
    value
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            FixtureError(format!(
                "{}: missing or empty string field \"{field}\"",
                path.display()
            ))
        })
}

fn require_bare_name(name: &str, path: &Path, field: &str) -> Result<(), FixtureError> {
    let safe = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !name.starts_with('.');
    if safe {
        Ok(())
    } else {
        Err(FixtureError(format!(
            "{}: \"{field}\" value {name:?} must be a bare fixture name \
             ([A-Za-z0-9._-], no leading dot) — it becomes a path component \
             inside the fixture directory",
            path.display()
        )))
    }
}
