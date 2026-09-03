//! Typed, non-executable installer wire objects.
//!
//! The installer deliberately has no command, hook, script, chroot, or
//! caller-supplied path field.  `install.plan` returns one complete object;
//! its token is SHA-256 over [`canonical_json`] of the nested `plan` value.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::update::BootArtifactKind;

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

/// Offline support posture for one observed device and for the report as a
/// whole. `partial` is deliberately distinct from `unsupported`: a driver
/// may exist while firmware or binding evidence is incomplete.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallHardwareCoverage {
    Full,
    Partial,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallHardwareBus {
    Pci,
    Usb,
    Platform,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallHardwareFunction {
    Graphics,
    Network,
    Storage,
    Input,
    Audio,
    Bluetooth,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallHardwareReason {
    DriverBound,
    FirmwareMissing,
    DriverUnbound,
    NoModuleClaim,
    ModaliasUnavailable,
    ModuleMetadataUnavailable,
}

/// One kernel-observed device. No serial number, MAC address, network
/// destination or user data belongs in this report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallHardwareDevice {
    pub bus: InstallHardwareBus,
    pub address: String,
    pub function: InstallHardwareFunction,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modalias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    pub claiming_modules: Vec<String>,
    pub requested_firmware: Vec<String>,
    pub missing_firmware: Vec<String>,
    pub coverage: InstallHardwareCoverage,
    pub reason: InstallHardwareReason,
}

/// Result returned before destructive confirmation. The seed phase observes
/// the same bounded evidence again and writes that fresh report into installed
/// shared state, then verifies its exact durable bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallHardwareReport {
    pub v: u8,
    pub generated_at: String,
    pub architecture: String,
    pub kernel_release: String,
    pub overall: InstallHardwareCoverage,
    pub graphics_usable: bool,
    pub disk_below_minimum_target: bool,
    /// Remains false until this exact model has passed the published physical
    /// hardware matrix. Kernel binding is not a qualification claim.
    pub bare_hardware_qualified: bool,
    pub devices: Vec<InstallHardwareDevice>,
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
    pub uncompressed_digest_sha256: String,
    pub uncompressed_size_bytes: u64,
}

/// The signed boot artifact installed beside the verified root-slot payload.
/// Keeping this identity inside the confirmation token prevents a release
/// manifest with the same release id and payload from substituting a different
/// UKI or Raspberry Pi boot filesystem after the user confirms the plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallBootArtifactPlan {
    pub kind: BootArtifactKind,
    pub filename: String,
    pub digest_sha256: String,
    pub size_bytes: u64,
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
    pub boot_artifact: InstallBootArtifactPlan,
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
    /// Live-kernel evidence captured for the selected target before the user
    /// authorizes the destructive plan. It is not a physical qualification
    /// claim and is deliberately outside the hashed disk plan.
    pub hardware_report: InstallHardwareReport,
}

/// The only caller-provided seed value. All other seed fields are derived by
/// `punard` from the verified plan and its own clock; account data is never an
/// installer input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallSeedParams {
    pub locale: String,
}

/// Strict params for `install.apply`.
///
/// Secret material is deliberately absent. Attended calls carry a sealed
/// `passphrase_fd`; unattended calls omit it so `punard` generates the disk
/// passphrase itself. `oobe_answers_fd`, `unattended_answers_fd` and
/// `unattended_signature_fd` name sealed anonymous-memory descriptors held
/// open by the authenticated peer. `recovery_output_fd` names a one-way pipe
/// or Unix socket used for the personal recovery/custody disclosure. The
/// daemon duplicates them without placing secret bytes in a request, process
/// argument, environment variable, result, status document, or audit event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallApplyParams {
    pub plan_token: String,
    pub disk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase_fd: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_output_fd: Option<u32>,
    pub keymap: String,
    pub seed: InstallSeedParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oobe_answers_fd: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unattended_answers_fd: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unattended_signature_fd: Option<u32>,
    pub unattended: bool,
}

/// Human confirmation for the personal recovery-key gate. The two challenged
/// groups are themselves key material, so even this acknowledgement carries
/// only a sealed-memory descriptor number on the JSON wire.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRecoveryAckParams {
    pub plan_token: String,
    pub groups_fd: u32,
}

/// Overall state exposed by `install.status` and `/run/punar/install.json`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallOverallState {
    Idle,
    Running,
    Awaiting,
    Succeeded,
    Failed,
}

/// The nine executor phases. The two verification phases are distinct on the
/// wire so a failure can say whether release trust or the installed result
/// failed, while the surface may label both simply “verify”.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPhase {
    VerifyRelease,
    Partition,
    Encrypt,
    Format,
    WriteSlotA,
    ReRead,
    Boot,
    Seed,
    VerifyInstalled,
}

impl InstallPhase {
    pub const ALL: [Self; 9] = [
        Self::VerifyRelease,
        Self::Partition,
        Self::Encrypt,
        Self::Format,
        Self::WriteSlotA,
        Self::ReRead,
        Self::Boot,
        Self::Seed,
        Self::VerifyInstalled,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPhaseState {
    Pending,
    Running,
    Waiting,
    Complete,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallAwaiting {
    RecoveryKeyAck,
    OrganizationEscrowReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstallPhaseProgress {
    pub phase: InstallPhase,
    pub state: InstallPhaseState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstallFailure {
    pub message: String,
    pub disk_state: String,
    pub next_step: String,
}

/// Read-only installer state. Result structs intentionally tolerate unknown
/// fields so an older shell can watch a newer daemon without breaking.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstallStatusResult {
    pub v: u8,
    pub state: InstallOverallState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<InstallPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub awaiting: Option<InstallAwaiting>,
    pub phases: Vec<InstallPhaseProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<InstallFailure>,
}

impl InstallStatusResult {
    pub fn idle() -> Self {
        Self {
            v: 1,
            state: InstallOverallState::Idle,
            plan_token: None,
            disk: None,
            phase: None,
            awaiting: None,
            phases: InstallPhase::ALL
                .into_iter()
                .map(|phase| InstallPhaseProgress {
                    phase,
                    state: InstallPhaseState::Pending,
                    completed_bytes: None,
                    total_bytes: None,
                    detail: None,
                })
                .collect(),
            failure: None,
        }
    }
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

    #[test]
    fn apply_params_have_descriptor_numbers_but_no_secret_fields() {
        let value = serde_json::json!({
            "plan_token": "0".repeat(64),
            "disk": "/dev/vda",
            "passphrase_fd": 3,
            "recovery_output_fd": 4,
            "keymap": "us",
            "seed": {"locale": "C.UTF-8"},
            "unattended_answers_fd": 6,
            "unattended_signature_fd": 7,
            "unattended": false
        });
        let params: InstallApplyParams = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(params.passphrase_fd, Some(3));
        assert_eq!(params.unattended_answers_fd, Some(6));
        assert_eq!(params.unattended_signature_fd, Some(7));
        for forbidden in ["passphrase", "recovery_key", "password", "account"] {
            let mut object = value.as_object().unwrap().clone();
            object.insert(forbidden.into(), Value::String("secret".into()));
            assert!(
                serde_json::from_value::<InstallApplyParams>(Value::Object(object)).is_err(),
                "{forbidden}"
            );
        }
    }

    #[test]
    fn recovery_ack_has_only_a_plan_token_and_descriptor_number() {
        let value = serde_json::json!({
            "plan_token": "0".repeat(64),
            "groups_fd": 5
        });
        let params: InstallRecoveryAckParams = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(params.groups_fd, 5);
        for forbidden in ["first_group", "second_group", "groups", "recovery_key"] {
            let mut object = value.as_object().unwrap().clone();
            object.insert(forbidden.into(), Value::String("secret".into()));
            assert!(
                serde_json::from_value::<InstallRecoveryAckParams>(Value::Object(object)).is_err(),
                "{forbidden}"
            );
        }
    }

    #[test]
    fn idle_status_has_the_fixed_nine_phase_order_and_no_secret_field() {
        let value = serde_json::to_value(InstallStatusResult::idle()).unwrap();
        assert_eq!(value["state"], "idle");
        assert_eq!(value["phases"].as_array().unwrap().len(), 9);
        assert_eq!(value["phases"][0]["phase"], "verify_release");
        assert_eq!(value["phases"][8]["phase"], "verify_installed");
        let text = serde_json::to_string(&value).unwrap();
        for forbidden in ["passphrase", "recovery_key", "password", "account"] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }
}
