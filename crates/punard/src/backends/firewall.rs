//! `security.firewall` — nftables table `inet punar-base`
//! (docs/development/milestone-3.md section 4.1).
//!
//! Backend contract: spawn `nft` with a **fixed argv, never a shell** (SPEC
//! section 10). Observe/verify parse `nft -j list table inet punar-base`;
//! apply enabled runs `nft -f <vendored ruleset>` (the ruleset starts with
//! `destroy table`, so re-apply is idempotent — verified on nftables 1.1.6);
//! apply disabled runs `nft destroy table inet punar-base`.

use std::path::PathBuf;
use std::time::Duration;

use punar_common::CapabilityId;
use serde_json::{Value, json};

use crate::capability::{BackendError, Capability, DescriptorMeta};
use crate::util::run_with_timeout;

pub const CAPABILITY_ID: &str = "security.firewall";
pub const TABLE_FAMILY: &str = "inet";
pub const TABLE_NAME: &str = "punar-base";

pub struct FirewallBackend {
    /// Path to the `nft` binary (fixed argv; `/usr/bin/nft` in the image).
    pub nft_bin: PathBuf,
    /// Vendored ruleset file (`/usr/share/punar/nftables/punar-base.nft`).
    pub ruleset_path: PathBuf,
    /// Deadline for each nft invocation (part of the 10 s request budget).
    pub timeout: Duration,
}

impl FirewallBackend {
    pub fn new(nft_bin: PathBuf, ruleset_path: PathBuf) -> Self {
        FirewallBackend {
            nft_bin,
            ruleset_path,
            timeout: Duration::from_secs(8),
        }
    }

    fn nft(&self, args: &[&str]) -> Result<crate::util::CommandResult, BackendError> {
        run_with_timeout(&self.nft_bin, args, self.timeout).map_err(|e| {
            BackendError::new(format!("running {} failed: {e}", self.nft_bin.display()))
        })
    }
}

/// Judge a captured `nft -j list table inet punar-base` document against the
/// punar-base baseline. Returns `Ok(true)` when the table matches (the three
/// chains with the expected hooks and policies, and nothing extra),
/// `Ok(false)` for any deviation, `Err` for unparsable input.
///
/// Pure function; unit-tested against real 1.1.6 captures in
/// `tests/fixtures/`.
pub fn ruleset_matches_baseline(nft_json: &str) -> Result<bool, String> {
    let doc: Value =
        serde_json::from_str(nft_json).map_err(|e| format!("nft -j output is not JSON: {e}"))?;
    let items = doc
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| "nft -j output has no \"nftables\" array".to_string())?;

    let mut table_seen = false;
    // (name, hook, policy) for chains of our table.
    let mut chains: Vec<(String, String, String)> = Vec::new();

    for item in items {
        if let Some(table) = item.get("table") {
            if table.get("family").and_then(Value::as_str) == Some(TABLE_FAMILY)
                && table.get("name").and_then(Value::as_str) == Some(TABLE_NAME)
            {
                table_seen = true;
            }
        }
        if let Some(chain) = item.get("chain") {
            if chain.get("family").and_then(Value::as_str) != Some(TABLE_FAMILY)
                || chain.get("table").and_then(Value::as_str) != Some(TABLE_NAME)
            {
                continue;
            }
            let name = chain.get("name").and_then(Value::as_str).unwrap_or("");
            // Base-chain attributes; a chain missing them is not a base
            // chain and therefore filters nothing — treat as deviation.
            if chain.get("type").and_then(Value::as_str) != Some("filter")
                || chain.get("prio").and_then(Value::as_i64) != Some(0)
            {
                return Ok(false);
            }
            let hook = chain.get("hook").and_then(Value::as_str).unwrap_or("");
            let policy = chain.get("policy").and_then(Value::as_str).unwrap_or("");
            chains.push((name.to_string(), hook.to_string(), policy.to_string()));
        }
    }

    if !table_seen {
        return Ok(false);
    }
    let expected = [
        ("input", "input", "drop"),
        ("forward", "forward", "drop"),
        ("output", "output", "accept"),
    ];
    if chains.len() != expected.len() {
        return Ok(false);
    }
    for (name, hook, policy) in expected {
        if !chains
            .iter()
            .any(|(n, h, p)| n == name && h == hook && p == policy)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

impl Capability for FirewallBackend {
    fn descriptor(&self) -> DescriptorMeta {
        DescriptorMeta {
            capability: CapabilityId::new(CAPABILITY_ID).expect("static id is valid"),
            risk: "high",
            verification: "nftables",
            audit_category: "security",
            state_schema: Some(json!({ "enum": ["enabled", "disabled"] })),
            allowed_desired_states: Some(vec![json!("enabled"), json!("disabled")]),
        }
    }

    fn validate(&self, desired: &Value) -> Result<(), String> {
        match desired.as_str() {
            Some("enabled") | Some("disabled") => Ok(()),
            _ => Err(format!(
                "security.firewall accepts \"enabled\" or \"disabled\", not {desired}"
            )),
        }
    }

    fn observe(&self) -> Result<Value, BackendError> {
        let res = self.nft(&["-j", "list", "table", TABLE_FAMILY, TABLE_NAME])?;
        if !res.success {
            // Absent table (nft exits nonzero) — the firewall is off.
            return Ok(json!("disabled"));
        }
        match ruleset_matches_baseline(&res.stdout) {
            Ok(true) => Ok(json!("enabled")),
            // Present but deviating table: not the protection we promise.
            Ok(false) => Ok(json!("disabled")),
            Err(e) => Err(BackendError::new(format!(
                "could not parse nft -j output: {e}"
            ))),
        }
    }

    fn apply(&self, desired: &Value) -> Result<(), BackendError> {
        let ruleset = self
            .ruleset_path
            .to_str()
            .ok_or_else(|| BackendError::new("ruleset path is not valid UTF-8"))?;
        let res = match desired.as_str() {
            Some("enabled") => self.nft(&["-f", ruleset])?,
            Some("disabled") => self.nft(&["destroy", "table", TABLE_FAMILY, TABLE_NAME])?,
            _ => {
                return Err(BackendError::new(format!(
                    "invalid desired state {desired}"
                )));
            }
        };
        if res.success {
            Ok(())
        } else {
            Err(BackendError::new(format!(
                "nft exited nonzero: {}",
                res.stderr.trim()
            )))
        }
    }

    fn default_desired(&self) -> Option<Value> {
        // OS default: default-deny inbound (SPEC section 44.4).
        Some(json!("enabled"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = include_str!("../../tests/fixtures/nft-list-punar-base-full.json");
    const DEGRADED: &str = include_str!("../../tests/fixtures/nft-list-punar-base-degraded.json");

    #[test]
    fn real_full_capture_matches_baseline() {
        assert_eq!(ruleset_matches_baseline(FULL), Ok(true));
    }

    #[test]
    fn real_degraded_capture_is_rejected() {
        // Input policy accept + missing output chain → not our baseline.
        assert_eq!(ruleset_matches_baseline(DEGRADED), Ok(false));
    }

    #[test]
    fn missing_table_is_rejected() {
        let empty = r#"{"nftables": [{"metainfo": {"version": "1.1.6", "release_name": "x", "json_schema_version": 1}}]}"#;
        assert_eq!(ruleset_matches_baseline(empty), Ok(false));
    }

    #[test]
    fn extra_chain_is_rejected() {
        let mut doc: Value = serde_json::from_str(FULL).unwrap();
        doc["nftables"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "chain": {"family": "inet", "table": "punar-base", "name": "sneaky",
                           "handle": 9, "type": "filter", "hook": "input", "prio": 0,
                           "policy": "accept"}
            }));
        assert_eq!(ruleset_matches_baseline(&doc.to_string()), Ok(false));
    }

    #[test]
    fn wrong_priority_is_rejected() {
        let mangled = FULL.replace(
            "\"prio\": 0, \"policy\": \"drop\"",
            "\"prio\": 100, \"policy\": \"drop\"",
        );
        assert_eq!(ruleset_matches_baseline(&mangled), Ok(false));
    }

    #[test]
    fn other_tables_chains_are_ignored() {
        let mut doc: Value = serde_json::from_str(FULL).unwrap();
        doc["nftables"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "chain": {"family": "ip", "table": "other", "name": "input",
                           "handle": 1, "type": "filter", "hook": "input", "prio": 0,
                           "policy": "accept"}
            }));
        assert_eq!(ruleset_matches_baseline(&doc.to_string()), Ok(true));
    }

    #[test]
    fn garbage_is_an_error_not_a_judgement() {
        assert!(ruleset_matches_baseline("not json").is_err());
        assert!(ruleset_matches_baseline("{}").is_err());
    }

    #[test]
    fn validate_accepts_only_the_two_states() {
        let b = FirewallBackend::new(PathBuf::from("/usr/bin/nft"), PathBuf::from("/tmp/r.nft"));
        assert!(b.validate(&json!("enabled")).is_ok());
        assert!(b.validate(&json!("disabled")).is_ok());
        assert!(b.validate(&json!("on")).is_err());
        assert!(b.validate(&json!(true)).is_err());
    }
}
