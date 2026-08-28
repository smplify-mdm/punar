//! Typed, non-executable installer wire objects.
//!
//! The installer deliberately has no command, hook, script, chroot, or
//! caller-supplied path field.  `install.plan` returns one complete object;
//! its token is SHA-256 over [`canonical_json`] of the nested `plan` value.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The production data-volume default.  `none` exists only behind the
/// installer's explicit destructive confirmation flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallEncryption {
    Luks2,
    None,
}

/// Recovery handling selected before a plan is confirmed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallRecoveryMode {
    PersonalCopy,
    OrganizationEscrow,
    None,
}

/// Strict params for `install.plan`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPlanParams {
    /// Exact device node returned by `install.targets`; never an arbitrary
    /// caller-controlled path.
    pub disk: String,
    /// One XKB keymap token, used later by the fixed install pipeline.
    pub keymap: String,
    pub encryption: InstallEncryption,
    pub recovery_mode: InstallRecoveryMode,
}

/// One observed existing partition.  Every field is read-only discovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallTargetPartition {
    pub number: u32,
    pub device: String,
    pub start_bytes: u64,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partuuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_guid: Option<String>,
}

/// One disk safe to show on the target-selection screen.  Boot media and
/// answer media never appear in this collection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallTarget {
    pub device: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wwn: Option<String>,
    pub size_bytes: u64,
    pub logical_sector_bytes: u64,
    pub removable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_table: Option<String>,
    pub eligible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ineligible_reason: Option<String>,
    pub partitions: Vec<InstallTargetPartition>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallTargetsResult {
    pub v: u8,
    pub minimum_disk_bytes: u64,
    pub targets: Vec<InstallTarget>,
}

/// The physical identity inside the hashed plan.  `install.apply` will
/// re-read all of it immediately before its first write.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallDiskIdentity {
    pub device: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub serial: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wwn: Option<String>,
    pub size_bytes: u64,
    pub logical_sector_bytes: u64,
    pub existing_gpt_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPayloadPlan {
    pub release_id: String,
    pub filename: String,
    pub digest_sha256: String,
    pub compressed_size_bytes: u64,
    pub uncompressed_size_bytes: u64,
}

/// One future GPT partition.  Offsets and sizes are bytes and aligned to
/// both the disk logical-sector size and 1 MiB.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPartitionPlan {
    pub number: u32,
    pub name: String,
    pub type_guid: String,
    pub partuuid: String,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<String>,
    pub encrypted: bool,
}

/// The complete user-confirmed object.  Adding a future field changes the
/// token, so old confirmations cannot silently authorize a wider plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPlan {
    pub schema_version: u8,
    pub architecture: String,
    pub boot_platform: String,
    pub disk: InstallDiskIdentity,
    pub keymap: String,
    pub encryption: InstallEncryption,
    pub recovery_mode: InstallRecoveryMode,
    pub payload: InstallPayloadPlan,
    pub partitions: Vec<InstallPartitionPlan>,
    pub data_subvolumes: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPlanResult {
    pub v: u8,
    pub plan: InstallPlan,
    pub plan_token: String,
}

/// Deterministic JSON used by the installer confirmation token.
///
/// Objects are recursively sorted by Unicode code point, arrays retain their
/// order, strings use serde_json's JSON escaping, and no insignificant
/// whitespace is emitted.  The current plan has integer numbers only.  This
/// intentionally matches the JSON bytes from `jq -cS` **before jq's trailing
/// line terminator**, which the VM assertion can use without a second parser.
pub fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    let sorted = sort_json(value);
    serde_json::to_vec(&sorted)
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, sort_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_recursively_without_whitespace() {
        let value = serde_json::json!({"z": 1, "a": {"y": 2, "b": [3, {"q": 4, "c": 5}]}});
        assert_eq!(
            canonical_json(&value).unwrap(),
            br#"{"a":{"b":[3,{"c":5,"q":4}],"y":2},"z":1}"#
        );
    }
}
