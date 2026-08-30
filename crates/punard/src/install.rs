//! Installer discovery, destructive-plan construction, bounded secret intake,
//! and secret-free status reporting.
//!
//! The internal executor now owns release verification, fixed-layout disk
//! preparation, bounded slot-A writing, a physical re-read, UEFI boot
//! installation, shared-state seeding, hardware/audit handoff and read-only
//! final verification. The public `install.apply` method stays absent until
//! the transaction also owns the complete descriptor/orchestration boundary.
//! A half-installer is not an install API.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{IoSliceMut, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};

use punar_common::audit::{AUDIT_LOG_PATH, validate_event_schema};
use punar_common::install::{
    InstallApplyParams, InstallAwaiting, InstallBootArtifactPlan, InstallDiskIdentity,
    InstallEncryption, InstallFailure, InstallHardwareCoverage, InstallHardwareReport,
    InstallOverallState, InstallPartitionPlan, InstallPayloadPlan, InstallPhase, InstallPhaseState,
    InstallPlan, InstallPlanParams, InstallPlanResult, InstallRecoveryAckParams,
    InstallRecoveryMode, InstallStatusResult, InstallTarget, InstallTargetPartition,
    InstallTargetsResult, canonical_json,
};
use punar_common::update::{
    Architecture, BootArtifactKind, BootPlatform, ReleaseKeySet, ReleaseManifest, verify_reader,
    verify_release_manifest,
};
use punar_common::{AuditEvent, Decision, Redacted};
use punar_recovery::{
    PersonalRecoveryConfirmation, PersonalRecoveryView, RecoveryBinding, SecretRecoveryKey,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::enroll::ControlPlaneClient;
use crate::hardware::{HardwareSources, observe_install_hardware};
use crate::util::{hex, random_hex, sha256_hex, write_atomic, write_atomic_synced};

pub const ESP_PARTUUID: &str = "8bb56554-b5f1-4058-90ac-8dc91a8e2bd4";
pub const PI_BOOT_A_PARTUUID: &str = "79115027-a3f0-43dc-a251-4a0c637b135f";
pub const PI_BOOT_B_PARTUUID: &str = "706d6f54-d8b9-4276-9f4f-f1ac379a482e";
pub const ROOT_A_PARTUUID: &str = "1beabfe0-9cb8-4b49-91ef-d372b845e7ea";
pub const ROOT_B_PARTUUID: &str = "2b1b91a9-cf2c-4e9c-a723-5ec997971662";
pub const DATA_PARTUUID: &str = "21d4af4f-a19c-4c6a-b4e8-dd50e9f7ecb9";

const ESP_TYPE_GUID: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
const X86_ROOT_TYPE_GUID: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
const ARM_ROOT_TYPE_GUID: &str = "b921b045-1df0-41c3-af44-4c6f280d3fae";
const DATA_TYPE_GUID: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";
const ANSWERS_LABEL: &str = "PUNAR_ANSWERS";
const GIB: u64 = 1024 * 1024 * 1024;
const ALIGNMENT: u64 = 1024 * 1024;
const ESP_SIZE: u64 = GIB;
const ROOT_SIZE: u64 = 8 * GIB;
const DATA_MINIMUM: u64 = 16 * GIB;
const TARGET_DISK_BYTES: u64 = 128_000_000_000;
const GPT_LBAS: u64 = 34;
const PLAN_REGISTRY_LIMIT: usize = 16;
const PASSPHRASE_MAX_BYTES: usize = 4096;
const OOBE_ANSWERS_MAX_BYTES: usize = 1024 * 1024;
const RECOVERY_GROUPS_MAX_BYTES: usize = 64;
const SLOT_IO_BYTES: usize = 4 * 1024 * 1024;
const STATUS_PROGRESS_BYTES: u64 = 64 * 1024 * 1024;
const DIRECT_IO_BLOCK_BYTES: usize = 4096;
const DIRECT_IO_BLOCKS: usize = SLOT_IO_BYTES / DIRECT_IO_BLOCK_BYTES;
const REPART_DEFINITION_MAX_BYTES: u64 = 64 * 1024;
const RECOVERY_KEY_OUTPUT_MAX_BYTES: u64 = 128;
const LUKS_UUID_OUTPUT_MAX_BYTES: u64 = 64;
const LUKS_METADATA_MAX_BYTES: u64 = 1024 * 1024;
const BOOTLOADER_MAX_BYTES: u64 = 16 * 1024 * 1024;
const PI_BOOT_CONFIG_MAX_BYTES: usize = 64 * 1024;
const PI_KERNEL_MAX_BYTES: u64 = 128 * 1024 * 1024;
const PI_INITRAMFS_MAX_BYTES: u64 = 768 * 1024 * 1024;
const HARDWARE_REPORT_MAX_BYTES: usize = 8 * 1024 * 1024;
const AUDIT_HANDOFF_MAX_BYTES: usize = 16 * 1024 * 1024;

const PUNAR_PARTUUIDS: [&str; 6] = [
    ESP_PARTUUID,
    PI_BOOT_A_PARTUUID,
    PI_BOOT_B_PARTUUID,
    ROOT_A_PARTUUID,
    ROOT_B_PARTUUID,
    DATA_PARTUUID,
];

#[derive(Clone, Debug)]
pub struct InstallerSources {
    pub sys_class_block: PathBuf,
    pub dev_root: PathBuf,
    pub udev_data_root: PathBuf,
    pub mountinfo_path: PathBuf,
    pub release_manifest_path: PathBuf,
    pub release_signature_path: PathBuf,
    pub release_keys_dir: PathBuf,
    pub status_path: PathBuf,
    pub zstd_path: PathBuf,
    pub repart_path: PathBuf,
    pub cryptenroll_path: PathBuf,
    pub cryptsetup_path: PathBuf,
    pub bootctl_path: PathBuf,
    pub repart_definitions_root: PathBuf,
    pub repart_runtime_root: PathBuf,
    pub hardware: HardwareSources,
    /// Live device identity and audit source. `Daemon::new` binds these to
    /// its configured state/audit paths so test and production identities
    /// cannot drift between the daemon and installer.
    pub live_device_id_path: PathBuf,
    pub live_audit_path: PathBuf,
    /// Test-only seam. Production always verifies exact manifest bytes
    /// against `release_keys_dir` and leaves this `None`.
    pub release_manifest_override: Option<ReleaseManifest>,
    /// Cross-architecture test seam; production derives the compiled target.
    pub architecture_override: Option<Architecture>,
    /// Raspberry Pi media selects this explicitly when its live profile is
    /// assembled. UEFI is the production default for the current ISO.
    pub boot_platform_override: Option<BootPlatform>,
    /// Unit-test-only seam for a fake repart program targeting a sparse
    /// regular file. This field does not exist in production builds.
    #[cfg(test)]
    pub allow_regular_target_for_tests: bool,
    /// Unit-test-only mounted ESP. Production always mounts partition 1 with
    /// the safe in-process mount syscall path.
    #[cfg(test)]
    pub mounted_esp_override: Option<PathBuf>,
    /// Unit-test-only mounted `@var` subvolume. Production always derives,
    /// unlocks and mounts the platform's fixed data partition itself.
    #[cfg(test)]
    pub mounted_data_override: Option<PathBuf>,
    /// Unit-test-only mounted root slot A. Production always mounts partition
    /// 2 read-only for the final installed-system check.
    #[cfg(test)]
    pub mounted_root_override: Option<PathBuf>,
    /// Unit-test-only evidence. Production always observes the running
    /// kernel, sysfs, module aliases and firmware tree.
    #[cfg(test)]
    pub hardware_report_override: Option<InstallHardwareReport>,
}

impl Default for InstallerSources {
    fn default() -> Self {
        Self {
            sys_class_block: PathBuf::from("/sys/class/block"),
            dev_root: PathBuf::from("/dev"),
            udev_data_root: PathBuf::from("/run/udev/data"),
            mountinfo_path: PathBuf::from("/proc/self/mountinfo"),
            release_manifest_path: PathBuf::from("/run/punar/install/release.json"),
            release_signature_path: PathBuf::from("/run/punar/install/release.json.sig"),
            release_keys_dir: PathBuf::from("/usr/share/punar/release-keys"),
            status_path: PathBuf::from("/run/punar/install.json"),
            zstd_path: PathBuf::from("/usr/bin/zstd"),
            repart_path: PathBuf::from("/usr/bin/systemd-repart"),
            cryptenroll_path: PathBuf::from("/usr/bin/systemd-cryptenroll"),
            cryptsetup_path: PathBuf::from("/usr/bin/cryptsetup"),
            bootctl_path: PathBuf::from("/usr/bin/bootctl"),
            repart_definitions_root: PathBuf::from("/usr/share/punar/repart.d"),
            repart_runtime_root: PathBuf::from("/run/punar/install"),
            hardware: HardwareSources::default(),
            live_device_id_path: PathBuf::from("/var/lib/punar/device-id"),
            live_audit_path: PathBuf::from(AUDIT_LOG_PATH),
            release_manifest_override: None,
            architecture_override: None,
            boot_platform_override: None,
            #[cfg(test)]
            allow_regular_target_for_tests: false,
            #[cfg(test)]
            mounted_esp_override: None,
            #[cfg(test)]
            mounted_data_override: None,
            #[cfg(test)]
            mounted_root_override: None,
            #[cfg(test)]
            hardware_report_override: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("installer refused the request: {0}")]
    Refused(String),
    #[error("installer parameters are invalid: {0}")]
    Invalid(String),
    #[error("installer release verification failed: {0}")]
    Trust(String),
    #[error("installer discovery failed: {0}")]
    Io(#[from] std::io::Error),
}

impl InstallError {
    pub fn is_refusal(&self) -> bool {
        matches!(self, Self::Refused(_) | Self::Invalid(_))
    }
}

#[derive(Clone)]
pub struct Installer {
    sources: InstallerSources,
    plans: Arc<Mutex<PlanRegistry>>,
    status: Arc<Mutex<InstallStatusResult>>,
    recovery: Arc<RecoveryGate>,
    /// Digest of the exact seed bytes written by this boot. Final
    /// verification compares the re-opened filesystem against this value,
    /// not merely against another serialization of caller inputs.
    seed_digest: Arc<Mutex<Option<String>>>,
    /// Digest of the exact hardware evidence written beside the seed.
    hardware_report_digest: Arc<Mutex<Option<String>>>,
}

/// Exact terminal records copied into the installed audit trail after the
/// installed root and shared state have passed their read-only checks. The
/// event type has no secret-bearing field; this wrapper prevents a caller
/// from substituting unrelated schema-valid events. Recovery is absent only
/// for the explicit unencrypted lane; claiming enrollment there is refused.
pub struct InstallAuditEvents {
    pub recovery_enrolled: Option<AuditEvent>,
    pub apply_success: AuditEvent,
}

/// Non-secret identity read back from the LUKS2 volume after systemd enrolls
/// its recovery token. Organization escrow binds to the filesystem UUID, not
/// the deterministic GPT partition UUID in the install plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryKeyIdentity {
    pub luks_uuid: String,
    pub recovery_keyslot: u8,
}

/// Locally verified proof that the organization custody checkpoint completed.
/// Possession means the signed receipt matched the exact ciphertext envelope
/// and the installer may advance past `encrypt`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationEscrowEvidence {
    pub organization_id: String,
    pub tenant_key_id: String,
    pub device_id: String,
    pub luks_uuid: String,
    pub recovery_keyslot: u8,
    pub receipt_id: String,
    pub received_at: String,
    pub envelope_sha256: String,
}

/// Non-serializable, non-debuggable apply inputs duplicated from descriptors
/// owned by the authenticated peer. Both buffers zeroize on every return
/// path, including validation and child-process failures.
pub struct InstallApplyInputs {
    passphrase: Option<Zeroizing<Vec<u8>>>,
    recovery_output: Option<File>,
    oobe_answers: Option<Zeroizing<Vec<u8>>>,
}

impl InstallApplyInputs {
    pub fn passphrase(&self) -> Option<&[u8]> {
        self.passphrase.as_deref().map(Vec::as_slice)
    }

    pub fn recovery_output_mut(&mut self) -> Option<&mut File> {
        self.recovery_output.as_mut()
    }

    pub fn oobe_answers(&self) -> Option<&[u8]> {
        self.oobe_answers.as_deref().map(Vec::as_slice)
    }
}

#[derive(Debug, Default)]
struct PlanRegistry {
    order: VecDeque<String>,
    plans: BTreeMap<String, InstallPlan>,
}

#[derive(Default)]
struct RecoveryGate {
    state: Mutex<RecoveryGateState>,
    changed: Condvar,
}

#[derive(Default)]
enum RecoveryGateState {
    #[default]
    Idle,
    Personal {
        plan_token: String,
        view: PersonalRecoveryView,
    },
    Confirmed {
        plan_token: String,
        confirmation: PersonalRecoveryConfirmation,
    },
    Organization {
        plan_token: String,
        organization_id: String,
        device_id: String,
        identity: RecoveryKeyIdentity,
        recovery_key: SecretRecoveryKey,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallSeedDocument {
    v: u8,
    locale: String,
    keymap: String,
    installed_at: String,
    image_version: String,
    disk_encrypted: bool,
    disk_recovery: InstallSeedRecovery,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct InstallSeedRecovery {
    mode: InstallRecoveryMode,
}

impl PlanRegistry {
    fn insert(&mut self, token: String, plan: InstallPlan) {
        if self.plans.contains_key(&token) {
            self.order.retain(|existing| existing != &token);
        }
        self.order.push_back(token.clone());
        self.plans.insert(token, plan);
        while self.order.len() > PLAN_REGISTRY_LIMIT {
            if let Some(expired) = self.order.pop_front() {
                self.plans.remove(&expired);
            }
        }
    }

    fn get(&self, token: &str) -> Option<InstallPlan> {
        self.plans.get(token).cloned()
    }
}

#[derive(Clone, Debug)]
struct ObservedDisk {
    target: InstallTarget,
    protected: bool,
}

/// `O_DIRECT` requires every userspace base address and length to be aligned.
/// A vector of these blocks is heap-backed, contiguous and 4096-byte aligned
/// without weakening this crate's `forbid(unsafe_code)` boundary.
#[cfg(target_os = "linux")]
#[repr(align(4096))]
struct DirectIoBlock([u8; DIRECT_IO_BLOCK_BYTES]);

/// The install surface exists only when this exact UKI command-line token is
/// present. Substrings and alternate values do not enable it.
pub fn live_mode_from_cmdline(cmdline: &str) -> bool {
    cmdline
        .split_ascii_whitespace()
        .any(|word| word == "punar.live=1")
}

impl Installer {
    pub fn new(sources: InstallerSources) -> Self {
        Self {
            sources,
            plans: Arc::new(Mutex::new(PlanRegistry::default())),
            status: Arc::new(Mutex::new(InstallStatusResult::idle())),
            recovery: Arc::new(RecoveryGate::default()),
            seed_digest: Arc::new(Mutex::new(None)),
            hardware_report_digest: Arc::new(Mutex::new(None)),
        }
    }

    pub fn status(&self) -> InstallStatusResult {
        self.status.lock().unwrap().clone()
    }

    /// Publish the initial idle state only in a live environment. Later
    /// transaction transitions use this same atomic writer, so the shell's
    /// FileView never observes a partial JSON document.
    pub fn initialize_status_file(&self) -> Result<(), InstallError> {
        if let Some(parent) = self.sources.status_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut bytes = serde_json::to_vec(&self.status())
            .map_err(|error| InstallError::Invalid(error.to_string()))?;
        bytes.push(b'\n');
        write_atomic(&self.sources.status_path, &bytes, 0o644)?;
        Ok(())
    }

    /// Begin the fixed nine-phase transaction. A second caller may not reset
    /// or replace a running, awaiting, or succeeded install in this live boot.
    pub fn start_transaction_status(
        &self,
        plan_token: &str,
        disk: &str,
        root_slot_bytes: u64,
    ) -> Result<(), InstallError> {
        validate_plan_token(plan_token)?;
        device_path(&self.sources.dev_root, disk)?;
        if root_slot_bytes == 0 {
            return Err(InstallError::Invalid(
                "the root-slot progress denominator must be non-zero".into(),
            ));
        }
        self.transition_status(|current| {
            if matches!(
                current.state,
                InstallOverallState::Running
                    | InstallOverallState::Awaiting
                    | InstallOverallState::Succeeded
            ) {
                return Err(InstallError::Refused(
                    "an installation transaction is already active or complete".into(),
                ));
            }
            let mut next = InstallStatusResult::idle();
            next.state = InstallOverallState::Running;
            next.plan_token = Some(plan_token.to_string());
            next.disk = Some(disk.to_string());
            next.phase = Some(InstallPhase::VerifyRelease);
            next.phases[phase_index(InstallPhase::VerifyRelease)].state =
                InstallPhaseState::Running;
            let write = &mut next.phases[phase_index(InstallPhase::WriteSlotA)];
            write.completed_bytes = Some(0);
            write.total_bytes = Some(root_slot_bytes);
            Ok(next)
        })?;
        *self.seed_digest.lock().unwrap() = None;
        *self.hardware_report_digest.lock().unwrap() = None;
        Ok(())
    }

    /// Advance to exactly the next named phase. Skipping or moving backward
    /// is refused rather than rendered as fabricated progress.
    pub fn enter_phase(&self, phase: InstallPhase) -> Result<(), InstallError> {
        self.transition_status(|current_status| {
            if current_status.state != InstallOverallState::Running {
                return Err(InstallError::Invalid(
                    "installer phase advancement requires a running transaction".into(),
                ));
            }
            let current = current_status.phase.ok_or_else(|| {
                InstallError::Invalid("the running installer has no current phase".into())
            })?;
            let current_index = phase_index(current);
            let target_index = phase_index(phase);
            if target_index != current_index + 1 {
                return Err(InstallError::Invalid(
                    "installer phases must advance exactly once in fixed order".into(),
                ));
            }
            if current == InstallPhase::WriteSlotA {
                let progress = &current_status.phases[current_index];
                if progress.completed_bytes != progress.total_bytes {
                    return Err(InstallError::Invalid(
                        "root slot A must be completely written before re-read verification".into(),
                    ));
                }
            }
            let mut next = current_status.clone();
            next.phases[current_index].state = InstallPhaseState::Complete;
            next.phases[target_index].state = InstallPhaseState::Running;
            next.phase = Some(phase);
            Ok(next)
        })
    }

    pub fn update_write_progress(&self, completed_bytes: u64) -> Result<(), InstallError> {
        self.transition_status(|current| {
            if current.state != InstallOverallState::Running
                || current.phase != Some(InstallPhase::WriteSlotA)
            {
                return Err(InstallError::Invalid(
                    "byte progress is available only while writing root slot A".into(),
                ));
            }
            let mut next = current.clone();
            let progress = &mut next.phases[phase_index(InstallPhase::WriteSlotA)];
            let total = progress.total_bytes.ok_or_else(|| {
                InstallError::Invalid("root-slot progress has no denominator".into())
            })?;
            let previous = progress.completed_bytes.unwrap_or(0);
            if completed_bytes < previous || completed_bytes > total {
                return Err(InstallError::Invalid(
                    "root-slot progress must be monotonic and no greater than its total".into(),
                ));
            }
            progress.completed_bytes = Some(completed_bytes);
            Ok(next)
        })
    }

    pub fn await_recovery_status(&self, awaiting: InstallAwaiting) -> Result<(), InstallError> {
        self.transition_status(|current| {
            if current.state != InstallOverallState::Running
                || current.phase != Some(InstallPhase::Encrypt)
            {
                return Err(InstallError::Invalid(
                    "the recovery checkpoint may be entered only after encryption".into(),
                ));
            }
            let mut next = current.clone();
            next.state = InstallOverallState::Awaiting;
            next.awaiting = Some(awaiting);
            next.phases[phase_index(InstallPhase::Encrypt)].state = InstallPhaseState::Waiting;
            Ok(next)
        })
    }

    pub fn resume_recovery_status(&self) -> Result<(), InstallError> {
        self.transition_status(|current| {
            if current.state != InstallOverallState::Awaiting
                || current.phase != Some(InstallPhase::Encrypt)
                || current.awaiting.is_none()
            {
                return Err(InstallError::Invalid(
                    "no recovery checkpoint is awaiting confirmation".into(),
                ));
            }
            let mut next = current.clone();
            next.state = InstallOverallState::Running;
            next.awaiting = None;
            next.phases[phase_index(InstallPhase::Encrypt)].state = InstallPhaseState::Complete;
            Ok(next)
        })
    }

    pub fn complete_transaction_status(&self) -> Result<(), InstallError> {
        self.transition_status(|current| {
            if current.state != InstallOverallState::Running
                || current.phase != Some(InstallPhase::VerifyInstalled)
            {
                return Err(InstallError::Invalid(
                    "installation can complete only from final verification".into(),
                ));
            }
            let mut next = current.clone();
            next.phases[phase_index(InstallPhase::VerifyInstalled)].state =
                InstallPhaseState::Complete;
            next.state = InstallOverallState::Succeeded;
            next.phase = None;
            Ok(next)
        })
    }

    /// Record a secret-free terminal failure with an honest description of
    /// whether destructive work had begun.
    pub fn fail_transaction_status(
        &self,
        phase: InstallPhase,
        error: &InstallError,
    ) -> Result<(), InstallError> {
        let mut failed_plan_token = None;
        self.transition_status(|current| {
            if !matches!(
                current.state,
                InstallOverallState::Running | InstallOverallState::Awaiting
            ) {
                return Err(InstallError::Invalid(
                    "only an active installation can enter failed state".into(),
                ));
            }
            if current.phase != Some(phase) {
                return Err(InstallError::Invalid(
                    "the failure phase must match the active installer phase".into(),
                ));
            }
            failed_plan_token = current.plan_token.clone();
            let mut next = current.clone();
            let index = phase_index(phase);
            next.state = InstallOverallState::Failed;
            next.phase = Some(phase);
            next.awaiting = None;
            next.phases[index].state = InstallPhaseState::Failed;
            let disk_changed = index >= phase_index(InstallPhase::Partition);
            next.failure = Some(InstallFailure {
                message: format!(
                    "The installation stopped during {}: {}.",
                    phase_name(phase),
                    public_error_reason(error)
                ),
                disk_state: if disk_changed {
                    "The selected disk may be partially prepared and is not guaranteed to boot."
                        .into()
                } else {
                    "No disk bytes were changed by the installer.".into()
                },
                next_step: if disk_changed {
                    "Restart from the Punar installation medium and begin the installation again."
                        .into()
                } else {
                    "Correct the reported condition, refresh the plan, and try again.".into()
                },
            });
            Ok(next)
        })?;
        if let Some(plan_token) = failed_plan_token {
            self.cancel_recovery(&plan_token);
        }
        *self.seed_digest.lock().unwrap() = None;
        Ok(())
    }

    /// Serialize state transitions under the same lock used by readers. The
    /// file is replaced before the in-memory value, so a failed publish never
    /// advertises a transition through only one of the two read sides.
    fn transition_status(
        &self,
        transition: impl FnOnce(&InstallStatusResult) -> Result<InstallStatusResult, InstallError>,
    ) -> Result<(), InstallError> {
        let mut current = self.status.lock().unwrap();
        let next = transition(&current)?;
        let mut bytes =
            serde_json::to_vec(&next).map_err(|error| InstallError::Invalid(error.to_string()))?;
        bytes.push(b'\n');
        write_atomic(&self.sources.status_path, &bytes, 0o644)?;
        *current = next;
        Ok(())
    }

    /// Re-read the signed manifest and verify both the compressed root payload
    /// and boot artifact through already-open descriptors. No target byte is
    /// touched in this phase.
    pub fn verify_release_payload(&self, plan: &InstallPlan) -> Result<(), InstallError> {
        self.require_transaction_phase(plan, InstallPhase::VerifyRelease)?;
        self.open_verified_payload(plan).map(drop)?;
        self.open_verified_boot_artifact(plan).map(drop)
    }

    /// Materialize Punar's fixed GPT, ESP and shared-data filesystem from the
    /// definition files shipped in the immutable image. For an encrypted
    /// plan, the passphrase travels through the child's anonymous stdin pipe;
    /// it is never a path, argument, environment value, status field or
    /// captured output.
    ///
    /// `systemd-repart` performs partitioning, LUKS creation and formatting as
    /// one crash-consistent operation. The public nine-phase status retains
    /// those three user-facing checkpoints: while the tool runs, `partition`
    /// is active; only after a successful exit are `encrypt` and `format`
    /// completed and `write_slot_a` entered. A failure therefore never claims
    /// that any of the three preparation checkpoints completed.
    pub fn prepare_disk_layout(
        &self,
        plan: &InstallPlan,
        inputs: &InstallApplyInputs,
    ) -> Result<(), InstallError> {
        self.require_transaction_phase(plan, InstallPhase::Partition)?;
        let token = sha256_hex(
            &canonical_json(plan).map_err(|error| InstallError::Invalid(error.to_string()))?,
        );
        let refreshed = self.compute_plan(&InstallPlanParams {
            disk: plan.disk.device.clone(),
            keymap: plan.keymap.clone(),
            encryption: plan.encryption,
            recovery_mode: plan.recovery_mode,
        })?;
        if refreshed.plan_token != token || refreshed.plan != *plan {
            return Err(InstallError::Invalid(
                "the physical disk, GPT edges, or signed release changed at the destructive boundary"
                    .into(),
            ));
        }

        let passphrase = match (plan.encryption, inputs.passphrase()) {
            (InstallEncryption::Luks2, Some(passphrase)) if !passphrase.is_empty() => {
                Some(passphrase)
            }
            (InstallEncryption::Luks2, _) => {
                return Err(InstallError::Invalid(
                    "an encrypted disk preparation requires a non-empty passphrase descriptor"
                        .into(),
                ));
            }
            (InstallEncryption::None, None) => None,
            (InstallEncryption::None, Some(_)) => {
                return Err(InstallError::Invalid(
                    "an unencrypted disk preparation must not receive a passphrase".into(),
                ));
            }
        };

        let target = device_path(&self.sources.dev_root, &plan.disk.device)?;
        #[cfg(test)]
        let allow_regular_target = self.sources.allow_regular_target_for_tests;
        #[cfg(not(test))]
        let allow_regular_target = false;
        validate_repart_target(&target, allow_regular_target)?;
        let rendered = self
            .sources
            .repart_runtime_root
            .join(format!("definitions-{token}"));
        create_private_directory(&rendered)?;

        let base = self
            .sources
            .repart_definitions_root
            .join(match plan_boot_platform(plan)? {
                BootPlatform::Uefi => "install",
                BootPlatform::RaspberryPi => "install-raspberry-pi",
            });
        let encrypted = self
            .sources
            .repart_definitions_root
            .join("install-encrypted");
        let streaming = self
            .sources
            .repart_definitions_root
            .join("install-streaming");
        let definition_sources = if plan.encryption == InstallEncryption::Luks2 {
            vec![base, encrypted, streaming]
        } else {
            vec![base, streaming]
        };
        let prepared = render_repart_definitions(&rendered, &definition_sources).and_then(|()| {
            run_systemd_repart(&self.sources.repart_path, &rendered, &target, passphrase)
        });
        // The merged files contain no secret material. Cleanup is best-effort
        // because a completed destructive operation must never be reported as
        // failed solely because a transient /run directory could not unlink.
        let _ = fs::remove_dir_all(&rendered);
        prepared?;

        self.enter_phase(InstallPhase::Encrypt)?;
        if plan.encryption == InstallEncryption::None {
            // The wire keeps one phase vocabulary for encrypted and explicit
            // opt-out installs. With no LUKS header there is no recovery key
            // to enroll or acknowledge, so these two completed operations are
            // advanced together only after repart has succeeded.
            self.enter_phase(InstallPhase::Format)?;
            self.enter_phase(InstallPhase::WriteSlotA)?;
        }
        Ok(())
    }

    /// Ask the pinned systemd primitive to generate and enroll its typed
    /// 256-bit recovery key into the new LUKS2 data partition. The existing
    /// passphrase enters on anonymous stdin; the recovery key leaves on an
    /// anonymous stdout pipe into a zeroizing owner. A second fixed command
    /// reads only LUKS metadata to identify the `systemd-recovery` keyslot.
    ///
    /// This deliberately leaves the transaction in `encrypt`. The caller
    /// must route the returned owner through either the personal disclosure
    /// checkpoint or organization escrow and may advance to `format` only
    /// after that custody gate succeeds.
    #[cfg(target_os = "linux")]
    pub fn enroll_recovery_key(
        &self,
        plan: &InstallPlan,
        inputs: &InstallApplyInputs,
    ) -> Result<(SecretRecoveryKey, RecoveryKeyIdentity), InstallError> {
        self.require_transaction_phase(plan, InstallPhase::Encrypt)?;
        if plan.encryption != InstallEncryption::Luks2
            || plan.recovery_mode == InstallRecoveryMode::None
        {
            return Err(InstallError::Invalid(
                "recovery enrollment requires an encrypted plan with a custody mode".into(),
            ));
        }
        let passphrase = inputs
            .passphrase()
            .filter(|passphrase| !passphrase.is_empty())
            .ok_or_else(|| {
                InstallError::Invalid(
                    "recovery enrollment requires the active install passphrase descriptor".into(),
                )
            })?;
        let target = partition_device_path(
            &self.sources.dev_root,
            &plan.disk.device,
            data_partition_number(plan)?,
        )?;
        #[cfg(test)]
        let allow_regular_target = self.sources.allow_regular_target_for_tests;
        #[cfg(not(test))]
        let allow_regular_target = false;
        validate_repart_target(&target, allow_regular_target)?;

        let recovery_key =
            run_systemd_cryptenroll(&self.sources.cryptenroll_path, &target, passphrase)?;
        let recovery_keyslot =
            read_systemd_recovery_keyslot(&self.sources.cryptsetup_path, &target)?;
        let luks_uuid = read_luks_uuid(&self.sources.cryptsetup_path, &target)?;
        Ok((
            recovery_key,
            RecoveryKeyIdentity {
                luks_uuid,
                recovery_keyslot,
            },
        ))
    }

    /// Decompress the already-verified artifact into root slot A through one
    /// bounded 4 MiB buffer, hashing the exact raw bytes as they are written.
    /// The destination is derived from the confirmed disk, never supplied by
    /// the IPC caller.
    #[cfg(target_os = "linux")]
    pub fn write_slot_a(&self, plan: &InstallPlan) -> Result<(), InstallError> {
        use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};

        self.require_transaction_phase(plan, InstallPhase::WriteSlotA)?;
        validate_root_slot_payload(plan)?;
        let payload = self.open_verified_payload(plan)?;
        let slot_path = partition_device_path(&self.sources.dev_root, &plan.disk.device, 2)?;
        let mut slot = fs::OpenOptions::new()
            .write(true)
            .custom_flags(
                i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits())
                    .expect("open flags fit libc::c_int"),
            )
            .open(&slot_path)?;
        if !slot.metadata()?.file_type().is_block_device() {
            return Err(InstallError::Refused(
                "root slot A is not a block device".into(),
            ));
        }

        let mut child = Command::new(&self.sources.zstd_path)
            .args(["-dc", "--"])
            .stdin(Stdio::from(payload))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut decompressed = child.stdout.take().ok_or_else(|| {
            InstallError::Io(std::io::Error::other(
                "zstd did not provide its fixed output pipe",
            ))
        })?;
        let mut last_published = 0_u64;
        let copied = stream_exact_payload(
            &mut decompressed,
            &mut slot,
            plan.payload.uncompressed_size_bytes,
            &plan.payload.uncompressed_digest_sha256,
            |completed| {
                if completed == plan.payload.uncompressed_size_bytes
                    || completed.saturating_sub(last_published) >= STATUS_PROGRESS_BYTES
                {
                    self.update_write_progress(completed)?;
                    last_published = completed;
                }
                Ok(())
            },
        );
        drop(decompressed);
        if let Err(error) = copied {
            let _ = child.kill();
            let _ = child.wait();
            let _ = slot.sync_all();
            return Err(error);
        }
        let status = child.wait()?;
        if !status.success() {
            let _ = slot.sync_all();
            return Err(InstallError::Io(std::io::Error::other(
                "zstd refused the verified release payload",
            )));
        }
        slot.sync_all()?;
        drop(slot);
        Ok(())
    }

    /// Close the writer, re-open slot A with `O_DIRECT`, and hash the bytes
    /// returned by the block device. This cannot be satisfied by hashing the
    /// write buffer or by a normal page-cache read.
    #[cfg(target_os = "linux")]
    pub fn verify_written_slot_a(&self, plan: &InstallPlan) -> Result<(), InstallError> {
        self.require_transaction_phase(plan, InstallPhase::ReRead)?;
        validate_root_slot_payload(plan)?;
        let slot_path = partition_device_path(&self.sources.dev_root, &plan.disk.device, 2)?;
        digest_direct_block_device(
            &slot_path,
            plan.payload.uncompressed_size_bytes,
            &plan.payload.uncompressed_digest_sha256,
            "root slot A",
        )
    }

    /// Install the release's already-verified boot artifact onto the target
    /// boot partition. Initial installation deliberately creates one
    /// permanently uncounted slot-A UKI: there is no known-good slot B to
    /// fall back to yet. Later updates use the separate `+3-0` counted-name
    /// path once a last-known-good release exists.
    ///
    /// The target ESP is derived from the confirmed disk, mounted with
    /// `nodev,nosuid,noexec,nosymfollow`, and always unmounted before the
    /// transaction may enter `seed`. `bootctl --no-variables` keeps firmware
    /// NVRAM outside the disk-scoped destructive confirmation.
    #[cfg(target_os = "linux")]
    pub fn install_boot_artifact(&self, plan: &InstallPlan) -> Result<(), InstallError> {
        self.require_transaction_phase(plan, InstallPhase::Boot)?;
        let manifest = self.release_manifest_for_plan(plan)?;
        match (manifest.boot_platform, manifest.boot_artifact.kind) {
            (BootPlatform::Uefi, BootArtifactKind::Uki) => {
                self.install_uefi_boot_artifact(plan, &manifest)?;
                self.enter_phase(InstallPhase::Seed)
            }
            (BootPlatform::RaspberryPi, BootArtifactKind::RaspberryPiBootfs) => {
                self.install_raspberry_pi_boot_artifact(plan)?;
                self.enter_phase(InstallPhase::Seed)
            }
            _ => Err(InstallError::Trust(
                "the signed boot artifact does not match its boot platform".into(),
            )),
        }
    }

    /// Seed only persistent, device-scoped state into the freshly created
    /// `@var` subvolume. Account identity is intentionally absent: it belongs
    /// to first boot. The optional OOBE document is copied byte-for-byte and
    /// `seed.json` is the last file written, so a pre-seed failure remains the
    /// documented "write nothing" case.
    #[cfg(target_os = "linux")]
    pub fn seed_installed_system(
        &self,
        plan: &InstallPlan,
        params: &InstallApplyParams,
        inputs: &InstallApplyInputs,
    ) -> Result<(), InstallError> {
        self.require_transaction_phase(plan, InstallPhase::Seed)?;
        validate_apply_params(params)?;
        let token = sha256_hex(
            &canonical_json(plan).map_err(|error| InstallError::Invalid(error.to_string()))?,
        );
        if params.plan_token != token
            || params.disk != plan.disk.device
            || params.keymap != plan.keymap
        {
            return Err(InstallError::Invalid(
                "the seed request is not bound to the active installation plan".into(),
            ));
        }
        if inputs.oobe_answers().is_some() != params.oobe_answers_fd.is_some() {
            return Err(InstallError::Invalid(
                "the OOBE answer descriptor was not consumed exactly once".into(),
            ));
        }

        let manifest = self.release_manifest_for_plan(plan)?;
        let seed = InstallSeedDocument {
            v: 1,
            locale: params.seed.locale.clone(),
            keymap: plan.keymap.clone(),
            installed_at: punar_common::time::utc_now_rfc3339(),
            image_version: format!("{}-{}", manifest.image_id, manifest.version),
            disk_encrypted: plan.encryption == InstallEncryption::Luks2,
            disk_recovery: InstallSeedRecovery {
                mode: plan.recovery_mode,
            },
        };
        let mut seed_bytes =
            serde_json::to_vec(&seed).map_err(|error| InstallError::Invalid(error.to_string()))?;
        seed_bytes.push(b'\n');
        let hardware_report =
            self.observe_hardware_report(plan.disk.size_bytes < TARGET_DISK_BYTES)?;
        if !hardware_report.graphics_usable {
            return Err(InstallError::Refused(
                "the usable graphics driver disappeared before installed-state seeding".into(),
            ));
        }
        let mut hardware_report_bytes = serde_json::to_vec(&hardware_report)
            .map_err(|error| InstallError::Invalid(error.to_string()))?;
        hardware_report_bytes.push(b'\n');
        if hardware_report_bytes.len() > HARDWARE_REPORT_MAX_BYTES {
            return Err(InstallError::Refused(
                "the hardware report exceeds its fixed installed-state limit".into(),
            ));
        }
        let installed_device_id = read_validated_device_id(&self.sources.live_device_id_path)?;

        let data = self.mount_data_volume(plan, inputs, &token, false)?;
        let lib_dir = data.path().join("lib");
        ensure_directory_exact(&lib_dir, 0o755)?;
        let punar_dir = lib_dir.join("punar");
        ensure_directory_exact(&punar_dir, 0o700)?;
        let install_dir = punar_dir.join("install");
        ensure_directory_exact(&install_dir, 0o700)?;

        let dbus_dir = lib_dir.join("dbus");
        ensure_directory_exact(&dbus_dir, 0o755)?;
        write_new_synced_exact(
            &dbus_dir.join("machine-id"),
            format!("{}\n", random_hex(16)?).as_bytes(),
            0o444,
        )?;
        write_new_synced_exact(&punar_dir.join("device-id"), &installed_device_id, 0o600)?;

        if let Some(answers) = inputs.oobe_answers() {
            write_new_synced_exact(&install_dir.join("oobe-answers.json"), answers, 0o600)?;
        }
        write_new_synced_exact(
            &punar_dir.join("hardware-report.json"),
            &hardware_report_bytes,
            0o644,
        )?;
        write_new_synced_exact(&install_dir.join("seed.json"), &seed_bytes, 0o644)?;

        let filesystem = File::open(data.path())?;
        rustix::fs::syncfs(&filesystem).map_err(rustix_install_io)?;
        drop(filesystem);
        data.finish()?;
        *self.seed_digest.lock().unwrap() = Some(sha256_hex(&seed_bytes));
        *self.hardware_report_digest.lock().unwrap() = Some(sha256_hex(&hardware_report_bytes));
        self.enter_phase(InstallPhase::VerifyInstalled)
    }

    /// Re-open both mutable and immutable installed filesystems read-only and
    /// compare their durable contents to the active plan and to the exact
    /// seed bytes written by this daemon boot. Only this method may publish a
    /// succeeded installation.
    #[cfg(target_os = "linux")]
    pub fn verify_installed_system(
        &self,
        plan: &InstallPlan,
        params: &InstallApplyParams,
        inputs: &InstallApplyInputs,
        audit_events: &InstallAuditEvents,
    ) -> Result<(), InstallError> {
        self.require_transaction_phase(plan, InstallPhase::VerifyInstalled)?;
        let token = sha256_hex(
            &canonical_json(plan).map_err(|error| InstallError::Invalid(error.to_string()))?,
        );
        if params.plan_token != token || params.disk != plan.disk.device {
            return Err(InstallError::Invalid(
                "final verification is not bound to the active installation plan".into(),
            ));
        }
        let expected_seed_digest = self
            .seed_digest
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| InstallError::Invalid("no seed identity is active".into()))?;
        let expected_hardware_report_digest = self.hardware_report_digest.lock().unwrap().clone();
        let Some(expected_hardware_report_digest) = expected_hardware_report_digest else {
            return Err(InstallError::Invalid(
                "no hardware-report identity is active".into(),
            ));
        };
        let expected_device_id = read_validated_device_id(&self.sources.live_device_id_path)?;

        let data = self.mount_data_volume(plan, inputs, &token, true)?;
        let manifest = self.release_manifest_for_plan(plan)?;
        let expected_image_version = format!("{}-{}", manifest.image_id, manifest.version);
        let expectations = InstalledSeedExpectations {
            seed_digest: &expected_seed_digest,
            hardware_report_digest: &expected_hardware_report_digest,
            device_id: &expected_device_id,
            image_version: &expected_image_version,
        };
        verify_installed_seed(data.path(), plan, params, inputs, &expectations)?;
        data.finish()?;

        let root = self.mount_root_slot_a(plan, &token)?;
        require_bounded_regular_file(
            &root.path().join("usr/lib/systemd/system/punard.service"),
            1024 * 1024,
            "installed punard service",
        )?;
        root.finish()?;

        let device_id = std::str::from_utf8(&expected_device_id)
            .map_err(|_| InstallError::Trust("the live device identity is invalid".into()))?
            .strip_suffix('\n')
            .ok_or_else(|| InstallError::Trust("the live device identity is invalid".into()))?;
        let recovery_required = plan.recovery_mode != InstallRecoveryMode::None;
        let audit_bytes = build_installed_audit_handoff(
            &self.sources.live_audit_path,
            device_id,
            audit_events,
            recovery_required,
        )?;

        let data = self.mount_data_volume(plan, inputs, &token, false)?;
        let log_dir = data.path().join("log");
        ensure_directory_exact(&log_dir, 0o755)?;
        let audit_dir = log_dir.join("punar");
        ensure_directory_exact(&audit_dir, 0o750)?;
        write_new_synced_exact(&audit_dir.join("audit.jsonl"), &audit_bytes, 0o640)?;
        let filesystem = File::open(data.path())?;
        rustix::fs::syncfs(&filesystem).map_err(rustix_install_io)?;
        drop(filesystem);
        data.finish()?;

        let data = self.mount_data_volume(plan, inputs, &token, true)?;
        verify_installed_audit(
            data.path(),
            &audit_bytes,
            device_id,
            audit_events,
            recovery_required,
        )?;
        data.finish()?;

        self.complete_transaction_status()?;
        *self.seed_digest.lock().unwrap() = None;
        *self.hardware_report_digest.lock().unwrap() = None;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn install_uefi_boot_artifact(
        &self,
        plan: &InstallPlan,
        manifest: &ReleaseManifest,
    ) -> Result<(), InstallError> {
        // Re-verify through one open descriptor before touching the ESP. The
        // bounded copy below hashes the bytes again, closing an in-place
        // source-mutation race between this check and the final rename.
        let mut boot_artifact = self.open_verified_boot_artifact(plan)?;
        let token = sha256_hex(
            &canonical_json(plan).map_err(|error| InstallError::Invalid(error.to_string()))?,
        );
        let esp = self.mount_boot_partition_a(plan, &token, false)?;
        run_bootctl(&self.sources.bootctl_path, esp.path())?;

        let fallback = esp
            .path()
            .join("EFI/BOOT")
            .join(uefi_fallback_filename(manifest.architecture));
        require_bounded_regular_file(&fallback, BOOTLOADER_MAX_BYTES, "UEFI fallback bootloader")?;

        let version = manifest.version.to_string();
        let uki_dir = esp.path().join("EFI/Linux");
        fs::create_dir_all(&uki_dir)?;
        let uki_name = format!("punar_{version}.efi");
        let installed_uki = uki_dir.join(&uki_name);
        copy_verified_file_atomic(
            &mut boot_artifact,
            &installed_uki,
            plan.boot_artifact.size_bytes,
            &plan.boot_artifact.digest_sha256,
        )?;

        let loader_dir = esp.path().join("loader");
        fs::create_dir_all(&loader_dir)?;
        let selector = format!("punar_{version}*.efi");
        let loader = format!("preferred {selector}\ntimeout 0\neditor no\n");
        write_atomic_synced(&loader_dir.join("loader.conf"), loader.as_bytes(), 0o644)?;

        let mut installed = open_regular_nofollow(&installed_uki, "installed slot-A UKI")?;
        verify_reader(
            &mut installed,
            &plan.boot_artifact.digest_sha256,
            plan.boot_artifact.size_bytes,
        )
        .map_err(|error| InstallError::Trust(error.to_string()))?;
        drop(installed);

        // `syncfs` covers bootctl's files, the UKI rename and loader.conf on
        // the one target filesystem. A successful phase is therefore never
        // published while those directory updates exist only in cache.
        let filesystem = File::open(esp.path())?;
        rustix::fs::syncfs(&filesystem).map_err(rustix_install_io)?;
        drop(filesystem);
        esp.finish()
    }

    #[cfg(target_os = "linux")]
    fn install_raspberry_pi_boot_artifact(&self, plan: &InstallPlan) -> Result<(), InstallError> {
        use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};

        validate_raspberry_pi_boot_plan(plan)?;
        let mut artifact = self.open_verified_boot_artifact(plan)?;
        let target = partition_device_path(&self.sources.dev_root, &plan.disk.device, 1)?;
        #[cfg(test)]
        let allow_regular_target = self.sources.allow_regular_target_for_tests;
        #[cfg(not(test))]
        let allow_regular_target = false;
        validate_repart_target(&target, allow_regular_target)?;

        let mut boot_partition = fs::OpenOptions::new()
            .write(true)
            .custom_flags(
                i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits())
                    .expect("open flags fit libc::c_int"),
            )
            .open(&target)?;
        let file_type = boot_partition.metadata()?.file_type();
        if !(file_type.is_block_device() || allow_regular_target && file_type.is_file()) {
            return Err(InstallError::Refused(
                "Raspberry Pi boot slot A is not a block device".into(),
            ));
        }
        stream_exact_payload(
            &mut artifact,
            &mut boot_partition,
            plan.boot_artifact.size_bytes,
            &plan.boot_artifact.digest_sha256,
            |_| Ok(()),
        )?;
        boot_partition.sync_all()?;
        drop(boot_partition);

        digest_installed_partition(
            &target,
            plan.boot_artifact.size_bytes,
            &plan.boot_artifact.digest_sha256,
            allow_regular_target,
            "Raspberry Pi boot slot A",
        )?;

        let token = sha256_hex(
            &canonical_json(plan).map_err(|error| InstallError::Invalid(error.to_string()))?,
        );
        let boot = self.mount_boot_partition_a(plan, &token, true)?;
        validate_raspberry_pi_boot_filesystem(boot.path())?;
        boot.finish()
    }

    #[cfg(target_os = "linux")]
    fn mount_boot_partition_a(
        &self,
        plan: &InstallPlan,
        token: &str,
        read_only: bool,
    ) -> Result<MountedEsp, InstallError> {
        let source = partition_device_path(&self.sources.dev_root, &plan.disk.device, 1)?;
        #[cfg(test)]
        let allow_regular_target = self.sources.allow_regular_target_for_tests;
        #[cfg(not(test))]
        let allow_regular_target = false;
        validate_repart_target(&source, allow_regular_target)?;

        #[cfg(test)]
        if let Some(path) = &self.sources.mounted_esp_override {
            if !fs::symlink_metadata(path)?.file_type().is_dir() {
                return Err(InstallError::Refused(
                    "the test ESP override is not a directory".into(),
                ));
            }
            return Ok(MountedEsp::borrowed(path.clone()));
        }

        let path = self
            .sources
            .repart_runtime_root
            .join(format!("esp-{token}"));
        create_private_directory(&path)?;
        let mut flags = rustix::mount::MountFlags::NODEV
            | rustix::mount::MountFlags::NOSUID
            | rustix::mount::MountFlags::NOEXEC
            | rustix::mount::MountFlags::NOSYMFOLLOW;
        if read_only {
            flags |= rustix::mount::MountFlags::RDONLY;
        }
        if let Err(error) = rustix::mount::mount(&source, &path, "vfat", flags, Some(c"umask=0077"))
        {
            let _ = fs::remove_dir(&path);
            return Err(rustix_install_io(error));
        }
        Ok(MountedEsp::mounted(path))
    }

    #[cfg(target_os = "linux")]
    fn mount_data_volume(
        &self,
        plan: &InstallPlan,
        inputs: &InstallApplyInputs,
        token: &str,
        read_only: bool,
    ) -> Result<MountedData, InstallError> {
        match (plan.encryption, inputs.passphrase()) {
            (InstallEncryption::Luks2, Some(passphrase)) if !passphrase.is_empty() => {}
            (InstallEncryption::Luks2, _) => {
                return Err(InstallError::Invalid(
                    "mounting encrypted install data requires the active passphrase descriptor"
                        .into(),
                ));
            }
            (InstallEncryption::None, None) => {}
            (InstallEncryption::None, Some(_)) => {
                return Err(InstallError::Invalid(
                    "an unencrypted install must not retain a passphrase descriptor".into(),
                ));
            }
        }
        #[cfg(test)]
        if let Some(path) = &self.sources.mounted_data_override {
            if !fs::symlink_metadata(path)?.file_type().is_dir() {
                return Err(InstallError::Refused(
                    "the test data override is not a directory".into(),
                ));
            }
            return Ok(MountedData::borrowed(path.clone()));
        }

        let partition = partition_device_path(
            &self.sources.dev_root,
            &plan.disk.device,
            data_partition_number(plan)?,
        )?;
        validate_repart_target(&partition, false)?;
        let mapping = if plan.encryption == InstallEncryption::Luks2 {
            let passphrase = inputs
                .passphrase()
                .expect("encrypted passphrase validated above");
            Some(open_luks_mapping(
                &self.sources.cryptsetup_path,
                &self.sources.dev_root,
                &partition,
                token,
                passphrase,
            )?)
        } else {
            None
        };
        let source = mapping
            .as_ref()
            .map(|mapping| mapping.path.as_path())
            .unwrap_or(partition.as_path());
        validate_repart_target(source, false)?;

        let path = self
            .sources
            .repart_runtime_root
            .join(format!("data-{token}"));
        create_private_directory(&path)?;
        let mut flags = rustix::mount::MountFlags::NODEV
            | rustix::mount::MountFlags::NOSUID
            | rustix::mount::MountFlags::NOEXEC
            | rustix::mount::MountFlags::NOSYMFOLLOW;
        if read_only {
            flags |= rustix::mount::MountFlags::RDONLY;
        }
        if let Err(error) = rustix::mount::mount(
            source,
            &path,
            "btrfs",
            flags,
            Some(c"subvol=@var,compress=zstd:1,noatime"),
        ) {
            let _ = fs::remove_dir(&path);
            drop(mapping);
            return Err(rustix_install_io(error));
        }
        Ok(MountedData::mounted(path, mapping))
    }

    #[cfg(target_os = "linux")]
    fn mount_root_slot_a(
        &self,
        plan: &InstallPlan,
        token: &str,
    ) -> Result<MountedFilesystem, InstallError> {
        #[cfg(test)]
        if let Some(path) = &self.sources.mounted_root_override {
            if !fs::symlink_metadata(path)?.file_type().is_dir() {
                return Err(InstallError::Refused(
                    "the test root override is not a directory".into(),
                ));
            }
            return Ok(MountedFilesystem::borrowed(path.clone()));
        }

        let source = partition_device_path(&self.sources.dev_root, &plan.disk.device, 2)?;
        validate_repart_target(&source, false)?;
        let path = self
            .sources
            .repart_runtime_root
            .join(format!("root-{token}"));
        create_private_directory(&path)?;
        let flags = rustix::mount::MountFlags::RDONLY
            | rustix::mount::MountFlags::NODEV
            | rustix::mount::MountFlags::NOSUID
            | rustix::mount::MountFlags::NOEXEC
            | rustix::mount::MountFlags::NOSYMFOLLOW;
        if let Err(error) =
            rustix::mount::mount(&source, &path, "ext4", flags, None::<&std::ffi::CStr>)
        {
            let _ = fs::remove_dir(&path);
            return Err(rustix_install_io(error));
        }
        Ok(MountedFilesystem::mounted(path))
    }

    fn require_transaction_phase(
        &self,
        plan: &InstallPlan,
        phase: InstallPhase,
    ) -> Result<(), InstallError> {
        let token = sha256_hex(
            &canonical_json(plan).map_err(|error| InstallError::Invalid(error.to_string()))?,
        );
        let status = self.status();
        if status.state != InstallOverallState::Running
            || status.plan_token.as_deref() != Some(token.as_str())
            || status.disk.as_deref() != Some(plan.disk.device.as_str())
            || status.phase != Some(phase)
        {
            return Err(InstallError::Invalid(
                "the executor phase is not bound to this active installation plan".into(),
            ));
        }
        Ok(())
    }

    fn open_verified_payload(&self, plan: &InstallPlan) -> Result<File, InstallError> {
        let manifest = self.release_manifest_for_plan(plan)?;
        let parent = self
            .sources
            .release_manifest_path
            .parent()
            .ok_or_else(|| InstallError::Trust("release directory is unavailable".into()))?;
        open_verified_release_file(
            parent,
            &manifest.payload.filename,
            &plan.payload.digest_sha256,
            plan.payload.compressed_size_bytes,
            "release payload",
        )
    }

    fn open_verified_boot_artifact(&self, plan: &InstallPlan) -> Result<File, InstallError> {
        let manifest = self.release_manifest_for_plan(plan)?;
        let parent = self
            .sources
            .release_manifest_path
            .parent()
            .ok_or_else(|| InstallError::Trust("release directory is unavailable".into()))?;
        open_verified_release_file(
            parent,
            &manifest.boot_artifact.filename,
            &plan.boot_artifact.digest_sha256,
            plan.boot_artifact.size_bytes,
            "release boot artifact",
        )
    }

    fn release_manifest_for_plan(
        &self,
        plan: &InstallPlan,
    ) -> Result<ReleaseManifest, InstallError> {
        let manifest = self.release_manifest()?;
        if manifest.release_id != plan.payload.release_id
            || manifest.payload.filename != plan.payload.filename
            || manifest.payload.digest_sha256 != plan.payload.digest_sha256
            || manifest.payload.size_bytes != plan.payload.compressed_size_bytes
            || manifest.payload.uncompressed_digest_sha256
                != plan.payload.uncompressed_digest_sha256
            || manifest.payload.uncompressed_size_bytes != plan.payload.uncompressed_size_bytes
            || manifest.boot_artifact.kind != plan.boot_artifact.kind
            || manifest.boot_artifact.filename != plan.boot_artifact.filename
            || manifest.boot_artifact.digest_sha256 != plan.boot_artifact.digest_sha256
            || manifest.boot_artifact.size_bytes != plan.boot_artifact.size_bytes
        {
            return Err(InstallError::Trust(
                "the signed release no longer matches the confirmed install plan".into(),
            ));
        }
        Ok(manifest)
    }

    pub fn targets(&self) -> Result<InstallTargetsResult, InstallError> {
        let mut targets = self
            .observe_disks()?
            .into_iter()
            .filter(|disk| !disk.protected)
            .map(|disk| disk.target)
            .collect::<Vec<_>>();
        targets.sort_by(|a, b| a.device.cmp(&b.device));
        Ok(InstallTargetsResult {
            v: 1,
            minimum_disk_bytes: minimum_disk_bytes(512, self.boot_platform()),
            targets,
        })
    }

    fn observe_hardware_report(
        &self,
        disk_below_minimum_target: bool,
    ) -> Result<InstallHardwareReport, InstallError> {
        #[cfg(test)]
        if let Some(mut report) = self.sources.hardware_report_override.clone() {
            report.disk_below_minimum_target = disk_below_minimum_target;
            report.bare_hardware_qualified = false;
            Self::require_bounded_hardware_report(&report)?;
            return Ok(report);
        }

        let report = observe_install_hardware(
            &self.sources.hardware,
            &self.architecture().to_string(),
            disk_below_minimum_target,
        )
        .map_err(InstallError::Io)?;
        Self::require_bounded_hardware_report(&report)?;
        Ok(report)
    }

    fn require_bounded_hardware_report(report: &InstallHardwareReport) -> Result<(), InstallError> {
        let bytes =
            serde_json::to_vec(report).map_err(|error| InstallError::Invalid(error.to_string()))?;
        if bytes.len().saturating_add(1) > HARDWARE_REPORT_MAX_BYTES {
            return Err(InstallError::Refused(
                "the hardware report exceeds its fixed installed-state limit".into(),
            ));
        }
        Ok(())
    }

    pub fn plan(&self, params: &InstallPlanParams) -> Result<InstallPlanResult, InstallError> {
        let result = self.compute_plan(params)?;
        self.plans
            .lock()
            .unwrap()
            .insert(result.plan_token.clone(), result.plan.clone());
        Ok(result)
    }

    /// Compute a plan without admitting its token to the current-boot
    /// registry. This distinction is security-relevant: a failed apply
    /// revalidation must not silently mint an admissible token for the
    /// changed disk it just refused.
    fn compute_plan(&self, params: &InstallPlanParams) -> Result<InstallPlanResult, InstallError> {
        validate_answers(params)?;
        let disks = self.observe_disks()?;
        let observed = disks
            .iter()
            .find(|disk| disk.target.device == params.disk)
            .ok_or_else(|| {
                InstallError::Invalid(
                    "disk must exactly match a device returned by install.targets".into(),
                )
            })?;
        if observed.protected {
            return Err(InstallError::Refused(
                "the selected disk carries the live system or PUNAR_ANSWERS and cannot be erased"
                    .into(),
            ));
        }
        if !observed.target.eligible {
            return Err(InstallError::Refused(
                observed
                    .target
                    .ineligible_reason
                    .clone()
                    .unwrap_or_else(|| "the selected disk is not installable".into()),
            ));
        }

        for disk in disks
            .iter()
            .filter(|disk| disk.target.device != params.disk)
        {
            if disk
                .target
                .partitions
                .iter()
                .any(|partition| partition.partuuid.as_deref().is_some_and(is_punar_partuuid))
            {
                return Err(InstallError::Refused(format!(
                    "{} already carries a Punar partition; detach the other Punar disk before installing",
                    disk.target.device
                )));
            }
        }

        let serial = observed.target.serial.clone().ok_or_else(|| {
            InstallError::Refused(
                "the selected disk exposes no stable serial number, so Punar cannot bind the confirmation to physical hardware"
                    .into(),
            )
        })?;
        let manifest = self.release_manifest()?;
        let architecture = self.architecture();
        let boot_platform = self.boot_platform();
        if manifest.architecture != architecture || manifest.boot_platform != boot_platform {
            return Err(InstallError::Trust(format!(
                "signed release target is {}/{}, but this live environment is {}/{}",
                manifest.architecture, manifest.boot_platform, architecture, boot_platform
            )));
        }

        let disk_path = device_path(&self.sources.dev_root, &params.disk)?;
        let existing_gpt_sha256 = gpt_edge_sha256(
            &disk_path,
            observed.target.size_bytes,
            observed.target.logical_sector_bytes,
        )?;
        let (partitions, data_bytes) = partition_plan(
            observed.target.size_bytes,
            observed.target.logical_sector_bytes,
            architecture,
            boot_platform,
            params.encryption,
        )?;

        let hardware_report =
            self.observe_hardware_report(observed.target.size_bytes < TARGET_DISK_BYTES)?;
        if !hardware_report.graphics_usable {
            return Err(InstallError::Refused(
                "no graphics device has a matching, bound kernel driver; this desktop image cannot be installed on the selected hardware"
                    .into(),
            ));
        }

        let mut warnings = Vec::new();
        if observed.target.size_bytes < TARGET_DISK_BYTES {
            warnings.push(
                "This disk is below Punar's 128 GB minimum target. Punar will install, but this capacity has not completed bare-hardware qualification."
                    .into(),
            );
        }
        if observed.target.partitions.iter().any(|partition| {
            partition.label.as_deref() == Some("PUNAR-DATA")
                || partition.filesystem.as_deref() == Some("crypto_LUKS")
        }) {
            warnings.push(
                "The selected disk already contains Punar data or encrypted data; installation destroys it and does not provide repair-mode preservation."
                    .into(),
            );
        }
        match hardware_report.overall {
            InstallHardwareCoverage::Full => {}
            InstallHardwareCoverage::Partial => warnings.push(
                "Some detected hardware has a matching kernel module but is unbound or missing requested firmware. Review the hardware report before installing."
                    .into(),
            ),
            InstallHardwareCoverage::Unsupported => warnings.push(
                "Some detected hardware has no matching kernel module. Review the hardware report before installing; this is not a physical qualification claim."
                    .into(),
            ),
        }
        debug_assert!(data_bytes >= DATA_MINIMUM);

        let plan = InstallPlan {
            schema_version: 1,
            architecture: architecture.to_string(),
            boot_platform: boot_platform.to_string(),
            disk: InstallDiskIdentity {
                device: observed.target.device.clone(),
                model: observed.target.model.clone(),
                serial,
                wwn: observed.target.wwn.clone(),
                size_bytes: observed.target.size_bytes,
                logical_sector_bytes: observed.target.logical_sector_bytes,
                existing_gpt_sha256,
            },
            keymap: params.keymap.clone(),
            encryption: params.encryption,
            recovery_mode: params.recovery_mode,
            payload: InstallPayloadPlan {
                release_id: manifest.release_id,
                filename: manifest.payload.filename,
                digest_sha256: manifest.payload.digest_sha256,
                compressed_size_bytes: manifest.payload.size_bytes,
                uncompressed_digest_sha256: manifest.payload.uncompressed_digest_sha256,
                uncompressed_size_bytes: manifest.payload.uncompressed_size_bytes,
            },
            boot_artifact: InstallBootArtifactPlan {
                kind: manifest.boot_artifact.kind,
                filename: manifest.boot_artifact.filename,
                digest_sha256: manifest.boot_artifact.digest_sha256,
                size_bytes: manifest.boot_artifact.size_bytes,
            },
            partitions,
            data_subvolumes: vec!["@var".into(), "@home".into(), "@var-tmp".into()],
            warnings,
        };
        let plan_token = sha256_hex(
            &canonical_json(&plan).map_err(|error| InstallError::Invalid(error.to_string()))?,
        );
        Ok(InstallPlanResult {
            v: 1,
            plan,
            plan_token,
            hardware_report,
        })
    }

    /// Re-establish every property the person confirmed immediately before
    /// the future transaction's first write.
    ///
    /// Success still changes no bytes. It proves the token was minted by this
    /// daemon boot, the fixed apply fields agree with the cached plan, and a
    /// fresh discovery/manifest/GPT-edge pass produces the same canonical
    /// token. The mutating executor is allowed to begin only after this call.
    pub fn preflight_apply(
        &self,
        params: &InstallApplyParams,
    ) -> Result<InstallPlan, InstallError> {
        validate_apply_params(params)?;
        let cached = self
            .plans
            .lock()
            .unwrap()
            .get(&params.plan_token)
            .ok_or_else(|| {
                InstallError::Invalid(
                    "plan_token was not produced by this live environment during this boot".into(),
                )
            })?;
        if cached.disk.device != params.disk {
            return Err(InstallError::Invalid(
                "disk does not match the disk inside the confirmed plan".into(),
            ));
        }
        if cached.keymap != params.keymap {
            return Err(InstallError::Invalid(
                "keymap does not match the keymap inside the confirmed plan".into(),
            ));
        }
        match (cached.encryption, params.passphrase_fd) {
            (InstallEncryption::Luks2, None) => {
                return Err(InstallError::Invalid(
                    "an encrypted installation requires passphrase_fd".into(),
                ));
            }
            (InstallEncryption::None, Some(_)) => {
                return Err(InstallError::Invalid(
                    "an unencrypted installation must not carry passphrase_fd".into(),
                ));
            }
            _ => {}
        }
        match (cached.recovery_mode, params.recovery_output_fd) {
            (InstallRecoveryMode::PersonalCopy, None) => {
                return Err(InstallError::Invalid(
                    "a personal recovery install requires recovery_output_fd".into(),
                ));
            }
            (InstallRecoveryMode::OrganizationEscrow | InstallRecoveryMode::None, Some(_)) => {
                return Err(InstallError::Invalid(
                    "recovery_output_fd is available only for personal recovery".into(),
                ));
            }
            _ => {}
        }

        let refreshed = self.compute_plan(&InstallPlanParams {
            disk: params.disk.clone(),
            keymap: params.keymap.clone(),
            encryption: cached.encryption,
            recovery_mode: cached.recovery_mode,
        })?;
        if refreshed.plan_token != params.plan_token || refreshed.plan != cached {
            return Err(InstallError::Invalid(
                "the physical disk, existing GPT edges, or signed release changed after confirmation"
                    .into(),
            ));
        }
        Ok(cached)
    }

    /// Duplicate and consume the caller's bounded descriptor inputs without
    /// ever putting their bytes in IPC JSON, argv, environment variables or
    /// loggable error values. Call only after [`Self::preflight_apply`].
    #[cfg(target_os = "linux")]
    pub fn read_apply_inputs(
        &self,
        peer_pid: Option<i32>,
        params: &InstallApplyParams,
    ) -> Result<InstallApplyInputs, InstallError> {
        validate_apply_params(params)?;
        let passphrase = params
            .passphrase_fd
            .map(|fd| read_peer_descriptor(peer_pid, fd, PASSPHRASE_MAX_BYTES, "passphrase"))
            .transpose()?;
        let recovery_output = params
            .recovery_output_fd
            .map(|fd| {
                duplicate_peer_descriptor(peer_pid, fd, "recovery output")
                    .and_then(validate_recovery_output_file)
            })
            .transpose()?;
        let oobe_answers = params
            .oobe_answers_fd
            .map(|fd| read_peer_descriptor(peer_pid, fd, OOBE_ANSWERS_MAX_BYTES, "OOBE answers"))
            .transpose()?;
        if let Some(bytes) = &oobe_answers {
            std::str::from_utf8(bytes).map_err(|_| {
                InstallError::Invalid("the OOBE answers descriptor is not valid UTF-8".into())
            })?;
        }
        Ok(InstallApplyInputs {
            passphrase,
            recovery_output,
            oobe_answers,
        })
    }

    /// Arm the personal recovery checkpoint and disclose the key only through
    /// the caller-provided non-serializing sink. The gate is installed only
    /// after the sink accepts the complete key and challenge tuple.
    pub fn begin_personal_recovery(
        &self,
        plan_token: &str,
        recovery_key: SecretRecoveryKey,
        recovery_keyslot: u8,
        disclose: impl FnOnce(&str, [u8; 2]) -> Result<(), InstallError>,
    ) -> Result<(), InstallError> {
        validate_plan_token(plan_token)?;
        let mut state = self.recovery.state.lock().unwrap();
        if !matches!(*state, RecoveryGateState::Idle) {
            return Err(InstallError::Refused(
                "a recovery confirmation is already active".into(),
            ));
        }
        let view = recovery_key
            .into_personal_view(recovery_keyslot)
            .map_err(|error| InstallError::Invalid(error.to_string()))?;
        disclose(view.recovery_key_text(), view.confirmation_groups())?;
        *state = RecoveryGateState::Personal {
            plan_token: plan_token.to_string(),
            view,
        };
        self.recovery.changed.notify_all();
        Ok(())
    }

    /// Arm the managed-device checkpoint before any wrapped material leaves
    /// the device. The key remains solely in this non-serializing gate while
    /// status is `awaiting: organization_escrow_receipt`.
    #[cfg(target_os = "linux")]
    pub fn begin_organization_recovery(
        &self,
        plan: &InstallPlan,
        plan_token: &str,
        organization_id: &str,
        recovery_key: SecretRecoveryKey,
        identity: RecoveryKeyIdentity,
    ) -> Result<(), InstallError> {
        validate_plan_token(plan_token)?;
        self.require_transaction_phase(plan, InstallPhase::Encrypt)?;
        if plan.recovery_mode != InstallRecoveryMode::OrganizationEscrow
            || plan.encryption != InstallEncryption::Luks2
        {
            return Err(InstallError::Invalid(
                "organization recovery requires an encrypted organization_escrow plan".into(),
            ));
        }
        let expected_token = sha256_hex(
            &canonical_json(plan).map_err(|error| InstallError::Invalid(error.to_string()))?,
        );
        if plan_token != expected_token {
            return Err(InstallError::Invalid(
                "the organization recovery checkpoint does not match this plan_token".into(),
            ));
        }
        let device_id_bytes = read_validated_device_id(&self.sources.live_device_id_path)?;
        let device_id = std::str::from_utf8(&device_id_bytes)
            .expect("validated device identity is UTF-8")
            .trim_end_matches('\n')
            .to_string();
        RecoveryBinding {
            organization_id: organization_id.to_string(),
            tenant_key_id: "pending".into(),
            device_id: device_id.clone(),
            luks_uuid: identity.luks_uuid.clone(),
            recovery_keyslot: identity.recovery_keyslot,
        }
        .validate()
        .map_err(|_| {
            InstallError::Invalid("the organization recovery binding is invalid".into())
        })?;

        let mut state = self.recovery.state.lock().unwrap();
        if !matches!(*state, RecoveryGateState::Idle) {
            return Err(InstallError::Refused(
                "a recovery confirmation is already active".into(),
            ));
        }
        self.await_recovery_status(InstallAwaiting::OrganizationEscrowReceipt)?;
        *state = RecoveryGateState::Organization {
            plan_token: plan_token.to_string(),
            organization_id: organization_id.to_string(),
            device_id,
            identity,
            recovery_key,
        };
        self.recovery.changed.notify_all();
        Ok(())
    }

    /// Retry-safe managed custody: fetch the authenticated tenant key, wrap
    /// locally, upload ciphertext only, and verify the signed exact-envelope
    /// receipt. Every error leaves both the key and the awaiting checkpoint
    /// intact. Only a verified receipt completes the `encrypt` phase.
    pub fn attempt_organization_recovery(
        &self,
        plan_token: &str,
        client: &ControlPlaneClient,
        device_token: &Redacted<String>,
    ) -> Result<OrganizationEscrowEvidence, InstallError> {
        validate_plan_token(plan_token)?;
        let mut state = self.recovery.state.lock().unwrap();
        let RecoveryGateState::Organization {
            plan_token: expected_token,
            organization_id,
            device_id,
            identity,
            recovery_key,
        } = &mut *state
        else {
            return Err(InstallError::Invalid(
                "no organization recovery checkpoint is active".into(),
            ));
        };
        if expected_token != plan_token {
            return Err(InstallError::Invalid(
                "no organization recovery checkpoint matches this plan_token".into(),
            ));
        }

        let tenant = client.recovery_key(device_token).map_err(|_| {
            InstallError::Io(std::io::Error::other(
                "organization recovery escrow is unavailable",
            ))
        })?;
        if tenant.organization_id != *organization_id {
            return Err(InstallError::Trust(
                "organization recovery tenant identity did not match enrollment".into(),
            ));
        }
        let binding = RecoveryBinding {
            organization_id: organization_id.clone(),
            tenant_key_id: tenant.key_id.clone(),
            device_id: device_id.clone(),
            luks_uuid: identity.luks_uuid.clone(),
            recovery_keyslot: identity.recovery_keyslot,
        };
        let envelope = tenant.seal(&binding, recovery_key).map_err(|_| {
            InstallError::Trust(
                "organization recovery envelope construction failed verification".into(),
            )
        })?;
        let raw_receipt = client
            .recovery_escrow(device_token, &envelope)
            .map_err(|_| {
                InstallError::Io(std::io::Error::other(
                    "organization recovery escrow is unavailable",
                ))
            })?;
        let receipt = raw_receipt.verify(&tenant, &envelope).map_err(|_| {
            InstallError::Trust("organization recovery escrow receipt failed verification".into())
        })?;
        let evidence = OrganizationEscrowEvidence {
            organization_id: organization_id.clone(),
            tenant_key_id: tenant.key_id,
            device_id: device_id.clone(),
            luks_uuid: identity.luks_uuid.clone(),
            recovery_keyslot: identity.recovery_keyslot,
            receipt_id: receipt.receipt_id().to_string(),
            received_at: receipt.received_at().to_string(),
            envelope_sha256: receipt.envelope_sha256().to_string(),
        };

        self.resume_recovery_status()?;
        *state = RecoveryGateState::Idle;
        self.recovery.changed.notify_all();
        Ok(evidence)
    }

    /// Consume the two challenged recovery groups from a sealed peer memfd.
    /// Neither group is returned, serialized, or included in an error.
    #[cfg(target_os = "linux")]
    pub fn acknowledge_personal_recovery(
        &self,
        peer_pid: Option<i32>,
        params: &InstallRecoveryAckParams,
    ) -> Result<(), InstallError> {
        validate_plan_token(&params.plan_token)?;
        validate_descriptor_number(params.groups_fd, "groups_fd")?;
        let groups = read_peer_descriptor(
            peer_pid,
            params.groups_fd,
            RECOVERY_GROUPS_MAX_BYTES,
            "recovery confirmation",
        )?;
        self.acknowledge_personal_recovery_bytes(&params.plan_token, &groups)
    }

    fn acknowledge_personal_recovery_bytes(
        &self,
        plan_token: &str,
        groups: &[u8],
    ) -> Result<(), InstallError> {
        let text = std::str::from_utf8(groups).map_err(|_| {
            InstallError::Invalid("the recovery confirmation is not valid UTF-8".into())
        })?;
        let mut values = text.split_ascii_whitespace();
        let first = values.next().ok_or_else(|| {
            InstallError::Invalid("the recovery confirmation must contain two groups".into())
        })?;
        let second = values.next().ok_or_else(|| {
            InstallError::Invalid("the recovery confirmation must contain two groups".into())
        })?;
        if values.next().is_some() {
            return Err(InstallError::Invalid(
                "the recovery confirmation must contain exactly two groups".into(),
            ));
        }

        let mut state = self.recovery.state.lock().unwrap();
        let current = std::mem::take(&mut *state);
        match current {
            RecoveryGateState::Personal {
                plan_token: expected,
                mut view,
            } if expected == plan_token => {
                if let Err(error) = view.confirm_groups(first, second) {
                    *state = RecoveryGateState::Personal {
                        plan_token: expected,
                        view,
                    };
                    return Err(InstallError::Invalid(error.to_string()));
                }
                let confirmation = view
                    .finish()
                    .map_err(|error| InstallError::Invalid(error.to_string()))?;
                *state = RecoveryGateState::Confirmed {
                    plan_token: expected,
                    confirmation,
                };
                self.recovery.changed.notify_all();
                Ok(())
            }
            other => {
                *state = other;
                Err(InstallError::Invalid(
                    "no personal recovery checkpoint matches this plan_token".into(),
                ))
            }
        }
    }

    /// Wait without a timeout: proceeding by default would create an
    /// encrypted device whose owner may not hold its recovery key.
    pub fn wait_for_personal_recovery(
        &self,
        plan_token: &str,
    ) -> Result<PersonalRecoveryConfirmation, InstallError> {
        validate_plan_token(plan_token)?;
        let mut state = self.recovery.state.lock().unwrap();
        loop {
            match &*state {
                RecoveryGateState::Personal {
                    plan_token: expected,
                    ..
                } if expected == plan_token => {
                    state = self.recovery.changed.wait(state).unwrap();
                }
                RecoveryGateState::Confirmed {
                    plan_token: expected,
                    ..
                } if expected == plan_token => {
                    let RecoveryGateState::Confirmed { confirmation, .. } =
                        std::mem::take(&mut *state)
                    else {
                        unreachable!()
                    };
                    return Ok(confirmation);
                }
                _ => {
                    return Err(InstallError::Invalid(
                        "no personal recovery checkpoint matches this plan_token".into(),
                    ));
                }
            }
        }
    }

    /// Abandon an active checkpoint on transaction failure. Dropping either
    /// view zeroizes the only in-memory owner of the recovery key.
    pub fn cancel_recovery(&self, plan_token: &str) {
        let mut state = self.recovery.state.lock().unwrap();
        let matches = match &*state {
            RecoveryGateState::Personal {
                plan_token: expected,
                ..
            }
            | RecoveryGateState::Confirmed {
                plan_token: expected,
                ..
            }
            | RecoveryGateState::Organization {
                plan_token: expected,
                ..
            } => expected == plan_token,
            RecoveryGateState::Idle => false,
        };
        if matches {
            *state = RecoveryGateState::Idle;
            self.recovery.changed.notify_all();
        }
    }

    fn architecture(&self) -> Architecture {
        self.sources.architecture_override.unwrap_or_else(|| {
            if std::env::consts::ARCH == "aarch64" {
                Architecture::Aarch64
            } else {
                Architecture::X86_64
            }
        })
    }

    fn boot_platform(&self) -> BootPlatform {
        self.sources
            .boot_platform_override
            .unwrap_or(BootPlatform::Uefi)
    }

    fn release_manifest(&self) -> Result<ReleaseManifest, InstallError> {
        if let Some(manifest) = &self.sources.release_manifest_override {
            manifest
                .validate()
                .map_err(|error| InstallError::Trust(error.to_string()))?;
            return Ok(manifest.clone());
        }
        let document = fs::read(&self.sources.release_manifest_path)?;
        let signature = fs::read(&self.sources.release_signature_path)?;
        let keys = ReleaseKeySet::load_dir(&self.sources.release_keys_dir)
            .map_err(|error| InstallError::Trust(error.to_string()))?;
        verify_release_manifest(&document, &signature, &keys)
            .map_err(|error| InstallError::Trust(error.to_string()))
    }

    fn observe_disks(&self) -> Result<Vec<ObservedDisk>, InstallError> {
        let mounted = protected_block_devices(&self.sources)?;
        let mut entries =
            fs::read_dir(&self.sources.sys_class_block)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());

        let names = entries
            .iter()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect::<Vec<_>>();
        let disk_names = names
            .iter()
            .filter(|name| {
                !is_pseudo_disk(name)
                    && !self
                        .sources
                        .sys_class_block
                        .join(name)
                        .join("partition")
                        .exists()
            })
            .cloned()
            .collect::<Vec<_>>();

        let mut partitions_by_disk: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for name in &names {
            if !self
                .sources
                .sys_class_block
                .join(name)
                .join("partition")
                .exists()
            {
                continue;
            }
            if let Some(parent) = parent_disk(name, &disk_names) {
                partitions_by_disk
                    .entry(parent.to_string())
                    .or_default()
                    .push(name.clone());
            }
        }

        let mut disks = Vec::new();
        for name in disk_names {
            let root = self.sources.sys_class_block.join(&name);
            let sectors = read_u64(root.join("size")).unwrap_or(0);
            let logical_sector_bytes = read_u64(root.join("queue/logical_block_size"))
                .filter(|value| valid_sector_size(*value))
                .unwrap_or(512);
            let size_bytes = sectors.checked_mul(512).unwrap_or(0);
            let udev = udev_properties(&root, &self.sources.udev_data_root);
            let dev_id = read_trimmed(root.join("dev"));
            let read_only = read_u64(root.join("ro")).unwrap_or(1) != 0;
            let removable = read_u64(root.join("removable")).unwrap_or(0) != 0;
            let model = first_hardware_text([
                read_trimmed(root.join("device/model")),
                udev.get("ID_MODEL").cloned(),
            ]);
            let serial = first_hardware_text([
                read_trimmed(root.join("device/serial")),
                udev.get("ID_SERIAL_SHORT").cloned(),
                udev.get("ID_SERIAL").cloned(),
            ]);
            let wwn = first_hardware_text([
                read_trimmed(root.join("device/wwid")),
                udev.get("ID_WWN").cloned(),
            ]);

            let mut partitions = Vec::new();
            let mut protected = dev_id.as_ref().is_some_and(|id| mounted.contains(id));
            for partition_name in partitions_by_disk.get(&name).into_iter().flatten() {
                let partition_root = self.sources.sys_class_block.join(partition_name);
                let partition_udev = udev_properties(&partition_root, &self.sources.udev_data_root);
                let partition_dev_id = read_trimmed(partition_root.join("dev"));
                protected |= partition_dev_id
                    .as_ref()
                    .is_some_and(|id| mounted.contains(id));
                let label = partition_udev.get("ID_FS_LABEL").cloned();
                protected |= label.as_deref() == Some(ANSWERS_LABEL);
                partitions.push(InstallTargetPartition {
                    number: read_u64(partition_root.join("partition")).unwrap_or(0) as u32,
                    device: format!("/dev/{partition_name}"),
                    start_bytes: read_u64(partition_root.join("start"))
                        .and_then(|value| value.checked_mul(512))
                        .unwrap_or(0),
                    size_bytes: read_u64(partition_root.join("size"))
                        .and_then(|value| value.checked_mul(512))
                        .unwrap_or(0),
                    filesystem: partition_udev.get("ID_FS_TYPE").cloned(),
                    label,
                    partuuid: partition_udev
                        .get("ID_PART_ENTRY_UUID")
                        .map(|value| value.to_ascii_lowercase()),
                    type_guid: partition_udev
                        .get("ID_PART_ENTRY_TYPE")
                        .map(|value| value.to_ascii_lowercase()),
                });
            }
            partitions.sort_by_key(|partition| partition.number);

            let platform = self.boot_platform();
            let required = minimum_disk_bytes(logical_sector_bytes, platform);
            let ineligible_reason = if read_only {
                Some("the disk is read-only".to_string())
            } else if size_bytes < required {
                let fixed_gib = fixed_install_bytes(platform) / GIB;
                let required_gib = fixed_gib + DATA_MINIMUM / GIB;
                Some(format!(
                    "Punar needs {required_gib} GiB plus partition metadata ({required} bytes), and this disk has {size_bytes} bytes. {fixed_gib} GiB is the operating system, its boot files and rollback copy; 16 GiB is the floor for user data."
                ))
            } else {
                None
            };
            disks.push(ObservedDisk {
                target: InstallTarget {
                    device: format!("/dev/{name}"),
                    model,
                    serial,
                    wwn,
                    size_bytes,
                    logical_sector_bytes,
                    removable,
                    partition_table: udev.get("ID_PART_TABLE_TYPE").cloned(),
                    eligible: ineligible_reason.is_none(),
                    ineligible_reason,
                    partitions,
                },
                protected,
            });
        }
        Ok(disks)
    }
}

fn open_verified_release_file(
    parent: &Path,
    filename: &str,
    digest_sha256: &str,
    size_bytes: u64,
    description: &str,
) -> Result<File, InstallError> {
    use std::os::unix::fs::OpenOptionsExt;

    let path = parent.join(filename);
    if path.file_name().and_then(|name| name.to_str()) != Some(filename) {
        return Err(InstallError::Trust(format!(
            "{description} filename escapes its fixed directory"
        )));
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits())
                .expect("open flags fit libc::c_int"),
        )
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(InstallError::Trust(format!(
            "{description} is not a regular file"
        )));
    }
    verify_reader(&mut file, digest_sha256, size_bytes)
        .map_err(|error| InstallError::Trust(error.to_string()))?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[cfg(target_os = "linux")]
struct MountedEsp {
    path: PathBuf,
    mounted: bool,
    remove_directory: bool,
}

#[cfg(target_os = "linux")]
impl MountedEsp {
    fn mounted(path: PathBuf) -> Self {
        Self {
            path,
            mounted: true,
            remove_directory: true,
        }
    }

    #[cfg(test)]
    fn borrowed(path: PathBuf) -> Self {
        Self {
            path,
            mounted: false,
            remove_directory: false,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn finish(mut self) -> Result<(), InstallError> {
        if self.mounted {
            rustix::mount::unmount(&self.path, rustix::mount::UnmountFlags::empty())
                .map_err(rustix_install_io)?;
            self.mounted = false;
        }
        if self.remove_directory {
            // `/run` is transient and cleanup cannot invalidate a completed,
            // durably unmounted ESP transaction.
            let _ = fs::remove_dir(&self.path);
            self.remove_directory = false;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for MountedEsp {
    fn drop(&mut self) {
        if self.mounted {
            let _ = rustix::mount::unmount(&self.path, rustix::mount::UnmountFlags::empty());
            self.mounted = false;
        }
        if self.remove_directory {
            let _ = fs::remove_dir(&self.path);
            self.remove_directory = false;
        }
    }
}

#[cfg(target_os = "linux")]
struct OpenedLuksMapping {
    cryptsetup_path: PathBuf,
    name: String,
    path: PathBuf,
    open: bool,
}

#[cfg(target_os = "linux")]
impl OpenedLuksMapping {
    fn finish(mut self) -> Result<(), InstallError> {
        if self.open {
            close_luks_mapping(&self.cryptsetup_path, &self.name)?;
            self.open = false;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for OpenedLuksMapping {
    fn drop(&mut self) {
        if self.open {
            let _ = close_luks_mapping(&self.cryptsetup_path, &self.name);
            self.open = false;
        }
    }
}

#[cfg(target_os = "linux")]
struct MountedData {
    filesystem: MountedFilesystem,
    mapping: Option<OpenedLuksMapping>,
}

#[cfg(target_os = "linux")]
impl MountedData {
    fn mounted(path: PathBuf, mapping: Option<OpenedLuksMapping>) -> Self {
        Self {
            filesystem: MountedFilesystem::mounted(path),
            mapping,
        }
    }

    #[cfg(test)]
    fn borrowed(path: PathBuf) -> Self {
        Self {
            filesystem: MountedFilesystem::borrowed(path),
            mapping: None,
        }
    }

    fn path(&self) -> &Path {
        self.filesystem.path()
    }

    fn finish(mut self) -> Result<(), InstallError> {
        if let Err(error) = self.filesystem.finish_inner() {
            // Never close a device-mapper node that may still back a live
            // mount. Leaking it until the transient live boot ends is safer
            // than tearing storage out from under the VFS.
            if let Some(mapping) = self.mapping.take() {
                std::mem::forget(mapping);
            }
            return Err(error);
        }
        if let Some(mapping) = self.mapping.take() {
            mapping.finish()?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for MountedData {
    fn drop(&mut self) {
        if self.filesystem.finish_inner().is_ok() {
            if let Some(mapping) = self.mapping.take() {
                drop(mapping);
            }
        } else if let Some(mapping) = self.mapping.take() {
            std::mem::forget(mapping);
        }
    }
}

#[cfg(target_os = "linux")]
struct MountedFilesystem {
    path: PathBuf,
    mounted: bool,
    remove_directory: bool,
}

#[cfg(target_os = "linux")]
impl MountedFilesystem {
    fn mounted(path: PathBuf) -> Self {
        Self {
            path,
            mounted: true,
            remove_directory: true,
        }
    }

    #[cfg(test)]
    fn borrowed(path: PathBuf) -> Self {
        Self {
            path,
            mounted: false,
            remove_directory: false,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn finish(mut self) -> Result<(), InstallError> {
        self.finish_inner()
    }

    fn finish_inner(&mut self) -> Result<(), InstallError> {
        if self.mounted {
            rustix::mount::unmount(&self.path, rustix::mount::UnmountFlags::empty())
                .map_err(rustix_install_io)?;
            self.mounted = false;
        }
        if self.remove_directory {
            let _ = fs::remove_dir(&self.path);
            self.remove_directory = false;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for MountedFilesystem {
    fn drop(&mut self) {
        if self.mounted {
            let _ = rustix::mount::unmount(&self.path, rustix::mount::UnmountFlags::empty());
            self.mounted = false;
        }
        if self.remove_directory {
            let _ = fs::remove_dir(&self.path);
            self.remove_directory = false;
        }
    }
}

#[cfg(target_os = "linux")]
fn rustix_install_io(error: rustix::io::Errno) -> InstallError {
    InstallError::Io(std::io::Error::from_raw_os_error(error.raw_os_error()))
}

fn uefi_fallback_filename(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "BOOTX64.EFI",
        Architecture::Aarch64 => "BOOTAA64.EFI",
    }
}

fn run_bootctl(binary: &Path, esp: &Path) -> Result<(), InstallError> {
    let mut esp_argument = OsString::from("--esp-path=");
    esp_argument.push(esp.as_os_str());
    let status = fixed_tool_command(binary)
        .arg("install")
        .arg(esp_argument)
        .arg("--no-variables")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(InstallError::Io(std::io::Error::other(
            "bootctl did not install the fixed removable-media bootloader",
        )));
    }
    Ok(())
}

fn require_bounded_regular_file(
    path: &Path,
    maximum_size: u64,
    description: &str,
) -> Result<(), InstallError> {
    let file = open_regular_nofollow(path, description)?;
    let size = file.metadata()?.len();
    if size == 0 || size > maximum_size {
        return Err(InstallError::Io(std::io::Error::other(format!(
            "{description} has an invalid size"
        ))));
    }
    Ok(())
}

fn open_regular_nofollow(path: &Path, description: &str) -> Result<File, InstallError> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits())
                .expect("open flags fit libc::c_int"),
        )
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(InstallError::Refused(format!(
            "{description} is not a regular file"
        )));
    }
    Ok(file)
}

fn copy_verified_file_atomic(
    source: &mut File,
    destination: &Path,
    expected_size: u64,
    expected_digest: &str,
) -> Result<(), InstallError> {
    use std::os::unix::fs::OpenOptionsExt;

    let parent = destination.parent().ok_or_else(|| {
        InstallError::Invalid("the installed boot artifact has no parent directory".into())
    })?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| InstallError::Invalid("the installed boot artifact has no name".into()))?;
    let temporary = parent.join(format!(".{name}.new"));
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(InstallError::Io(error)),
    }

    let copied = (|| {
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temporary)?;
        source.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut remaining = expected_size;
        let mut buffer = vec![0_u8; SLOT_IO_BYTES];
        while remaining != 0 {
            let wanted = usize::try_from(remaining.min(SLOT_IO_BYTES as u64))
                .expect("bounded boot-artifact chunk fits usize");
            let read = source.read(&mut buffer[..wanted])?;
            if read == 0 {
                return Err(InstallError::Trust(
                    "the boot artifact ended before its signed size".into(),
                ));
            }
            output.write_all(&buffer[..read])?;
            hasher.update(&buffer[..read]);
            remaining -= read as u64;
        }
        let mut extra = [0_u8; 1];
        if source.read(&mut extra)? != 0 {
            return Err(InstallError::Trust(
                "the boot artifact exceeds its signed size".into(),
            ));
        }
        if hex(&hasher.finalize()) != expected_digest {
            return Err(InstallError::Trust(
                "the copied boot artifact does not match its signed digest".into(),
            ));
        }
        output.sync_all()?;
        drop(output);
        fs::rename(&temporary, destination)?;
        Ok(())
    })();
    if copied.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    copied
}

fn create_private_directory(path: &Path) -> Result<(), InstallError> {
    use std::os::unix::fs::DirBuilderExt;

    let parent = path.parent().ok_or_else(|| {
        InstallError::Invalid("the repart runtime directory has no parent".into())
    })?;
    fs::create_dir_all(parent)?;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path).map_err(InstallError::Io)
}

/// Merge the immutable base and overlays with explicit later-source-wins
/// semantics. Every input must be one bounded regular `.conf` file opened
/// with `O_NOFOLLOW`; the fresh output directory receives each final name
/// exactly once. This keeps symlinks and mutable include paths out of the
/// destructive command's trust boundary.
fn render_repart_definitions(destination: &Path, sources: &[PathBuf]) -> Result<(), InstallError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut rendered = BTreeMap::<OsString, Vec<u8>>::new();
    for source in sources {
        let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let name = entry.file_name();
            let is_definition = Path::new(&name)
                .extension()
                .is_some_and(|extension| extension == "conf");
            if !is_definition {
                continue;
            }
            let mut file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(
                    i32::try_from(
                        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits(),
                    )
                    .expect("open flags fit libc::c_int"),
                )
                .open(entry.path())?;
            if !file.metadata()?.file_type().is_file() {
                return Err(InstallError::Refused(
                    "a shipped repart definition is not a regular file".into(),
                ));
            }
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(REPART_DEFINITION_MAX_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > REPART_DEFINITION_MAX_BYTES {
                return Err(InstallError::Refused(
                    "a shipped repart definition exceeds the fixed size limit".into(),
                ));
            }
            rendered.insert(name, bytes);
        }
    }
    if rendered.is_empty() {
        return Err(InstallError::Refused(
            "the shipped repart definition set is empty".into(),
        ));
    }
    for (name, bytes) in rendered {
        let path = destination.join(name);
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
    }
    Ok(())
}

fn validate_repart_target(path: &Path, allow_regular_for_tests: bool) -> Result<(), InstallError> {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits())
                .expect("open flags fit libc::c_int"),
        )
        .open(path)?;
    let kind = file.metadata()?.file_type();
    if !(kind.is_block_device() || allow_regular_for_tests && kind.is_file()) {
        return Err(InstallError::Refused(
            "the confirmed installer target is no longer a block device".into(),
        ));
    }
    Ok(())
}

fn run_systemd_repart(
    binary: &Path,
    definitions: &Path,
    target: &Path,
    passphrase: Option<&[u8]>,
) -> Result<(), InstallError> {
    let mut definitions_arg = OsString::from("--definitions=");
    definitions_arg.push(definitions.as_os_str());
    let mut command = fixed_tool_command(binary);
    command
        .args([
            "--dry-run=no",
            "--offline=no",
            "--empty=force",
            "--pretty=no",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if passphrase.is_some() {
        command.arg("--key-file=/dev/stdin").stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    command.arg(definitions_arg).arg(target);

    let mut child = command.spawn()?;
    if let Some(secret) = passphrase {
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| {
                InstallError::Io(std::io::Error::other(
                    "systemd-repart did not provide its fixed input pipe",
                ))
            })
            .and_then(|mut stdin| stdin.write_all(secret).map_err(InstallError::Io));
        if let Err(error) = write_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(InstallError::Io(std::io::Error::other(
            "systemd-repart did not prepare the fixed Punar disk layout",
        )));
    }
    Ok(())
}

fn run_systemd_cryptenroll(
    binary: &Path,
    target: &Path,
    passphrase: &[u8],
) -> Result<SecretRecoveryKey, InstallError> {
    let mut command = fixed_tool_command(binary);
    command
        .args(["--unlock-key-file=/dev/stdin", "--recovery-key"])
        .arg(target)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| {
            InstallError::Io(std::io::Error::other(
                "systemd-cryptenroll did not provide its fixed input pipe",
            ))
        })
        .and_then(|mut stdin| stdin.write_all(passphrase).map_err(InstallError::Io));
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }

    let mut stdout = child.stdout.take().ok_or_else(|| {
        InstallError::Io(std::io::Error::other(
            "systemd-cryptenroll did not provide its fixed recovery pipe",
        ))
    })?;
    let mut bytes = Zeroizing::new(Vec::new());
    if let Err(error) = Read::by_ref(&mut stdout)
        .take(RECOVERY_KEY_OUTPUT_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(InstallError::Io(error));
    }
    drop(stdout);
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > RECOVERY_KEY_OUTPUT_MAX_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(InstallError::Io(std::io::Error::other(
            "systemd-cryptenroll returned an invalid recovery key",
        )));
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(InstallError::Io(std::io::Error::other(
            "systemd-cryptenroll did not enroll a recovery key",
        )));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        InstallError::Io(std::io::Error::other(
            "systemd-cryptenroll returned an invalid recovery key",
        ))
    })?;
    SecretRecoveryKey::parse(text.trim()).map_err(|_| {
        InstallError::Io(std::io::Error::other(
            "systemd-cryptenroll returned an invalid recovery key",
        ))
    })
}

fn read_systemd_recovery_keyslot(binary: &Path, target: &Path) -> Result<u8, InstallError> {
    let mut command = fixed_tool_command(binary);
    command
        .args(["luksDump", "--dump-json-metadata"])
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take().ok_or_else(|| {
        InstallError::Io(std::io::Error::other(
            "cryptsetup did not provide its fixed metadata pipe",
        ))
    })?;
    let mut bytes = Vec::new();
    if let Err(error) = Read::by_ref(&mut stdout)
        .take(LUKS_METADATA_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(InstallError::Io(error));
    }
    drop(stdout);
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > LUKS_METADATA_MAX_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(InstallError::Io(std::io::Error::other(
            "the LUKS metadata exceeded the fixed inspection limit",
        )));
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(InstallError::Io(std::io::Error::other(
            "cryptsetup did not inspect the recovery keyslot",
        )));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
        InstallError::Io(std::io::Error::other(
            "cryptsetup returned invalid LUKS metadata",
        ))
    })?;
    let tokens = metadata
        .get("tokens")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            InstallError::Io(std::io::Error::other(
                "the LUKS metadata has no token registry",
            ))
        })?;
    let slots = tokens
        .values()
        .filter(|token| {
            token.get("type").and_then(serde_json::Value::as_str) == Some("systemd-recovery")
        })
        .filter_map(|token| token.get("keyslots").and_then(serde_json::Value::as_array))
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|slot| slot.parse::<u8>().ok())
        .filter(|slot| *slot <= 31)
        .collect::<BTreeSet<_>>();
    if slots.len() != 1 {
        return Err(InstallError::Io(std::io::Error::other(
            "the LUKS metadata does not identify exactly one recovery keyslot",
        )));
    }
    Ok(*slots.iter().next().expect("one recovery keyslot exists"))
}

fn read_luks_uuid(binary: &Path, target: &Path) -> Result<String, InstallError> {
    let mut command = fixed_tool_command(binary);
    command
        .arg("luksUUID")
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take().ok_or_else(|| {
        InstallError::Io(std::io::Error::other(
            "cryptsetup did not provide its fixed UUID pipe",
        ))
    })?;
    let mut bytes = Vec::new();
    if let Err(error) = Read::by_ref(&mut stdout)
        .take(LUKS_UUID_OUTPUT_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(InstallError::Io(error));
    }
    drop(stdout);
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > LUKS_UUID_OUTPUT_MAX_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(InstallError::Io(std::io::Error::other(
            "cryptsetup returned an invalid LUKS UUID",
        )));
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(InstallError::Io(std::io::Error::other(
            "cryptsetup did not inspect the LUKS UUID",
        )));
    }
    let uuid = std::str::from_utf8(&bytes)
        .map_err(|_| {
            InstallError::Io(std::io::Error::other(
                "cryptsetup returned an invalid LUKS UUID",
            ))
        })?
        .trim();
    let valid = uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    if !valid {
        return Err(InstallError::Io(std::io::Error::other(
            "cryptsetup returned an invalid LUKS UUID",
        )));
    }
    Ok(uuid.to_ascii_lowercase())
}

#[cfg(target_os = "linux")]
fn open_luks_mapping(
    binary: &Path,
    dev_root: &Path,
    target: &Path,
    plan_token: &str,
    passphrase: &[u8],
) -> Result<OpenedLuksMapping, InstallError> {
    validate_plan_token(plan_token)?;
    if passphrase.is_empty() {
        return Err(InstallError::Invalid(
            "the LUKS passphrase descriptor is empty".into(),
        ));
    }
    let name = format!("punar-install-data-{}", &plan_token[..16]);
    run_cryptsetup_open(binary, target, &name, passphrase)?;
    let path = dev_root.join("mapper").join(&name);
    if let Err(error) = validate_repart_target(&path, false) {
        let _ = close_luks_mapping(binary, &name);
        return Err(error);
    }
    Ok(OpenedLuksMapping {
        cryptsetup_path: binary.to_path_buf(),
        name,
        path,
        open: true,
    })
}

#[cfg(target_os = "linux")]
fn run_cryptsetup_open(
    binary: &Path,
    target: &Path,
    name: &str,
    passphrase: &[u8],
) -> Result<(), InstallError> {
    let mut command = fixed_tool_command(binary);
    command
        .args(["open", "--type", "luks2", "--key-file=-"])
        .arg(target)
        .arg(name)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| {
            InstallError::Io(std::io::Error::other(
                "cryptsetup did not provide its fixed unlock pipe",
            ))
        })
        .and_then(|mut stdin| stdin.write_all(passphrase).map_err(InstallError::Io));
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(InstallError::Io(std::io::Error::other(
            "cryptsetup did not unlock the installed data volume",
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn close_luks_mapping(binary: &Path, name: &str) -> Result<(), InstallError> {
    let status = fixed_tool_command(binary)
        .args(["close", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(InstallError::Io(std::io::Error::other(
            "cryptsetup did not close the installed data volume",
        )));
    }
    Ok(())
}

fn fixed_tool_command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    command.env_clear().env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    command.env("LC_ALL", "C").env("SYSTEMD_COLORS", "0");
    command
}

#[cfg(target_os = "linux")]
fn read_peer_descriptor(
    peer_pid: Option<i32>,
    descriptor: u32,
    maximum: usize,
    kind: &'static str,
) -> Result<Zeroizing<Vec<u8>>, InstallError> {
    let file = duplicate_peer_descriptor(peer_pid, descriptor, kind)?;
    read_secret_descriptor_file(file, maximum, kind)
}

#[cfg(target_os = "linux")]
fn duplicate_peer_descriptor(
    peer_pid: Option<i32>,
    descriptor: u32,
    kind: &'static str,
) -> Result<File, InstallError> {
    use rustix::process::{Pid, PidfdFlags, PidfdGetfdFlags, pidfd_getfd, pidfd_open};

    let pid = peer_pid
        .and_then(Pid::from_raw)
        .ok_or_else(|| InstallError::Invalid(format!("the {kind} descriptor has no live peer")))?;
    let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(|error| {
        InstallError::Io(std::io::Error::from_raw_os_error(error.raw_os_error()))
    })?;
    let foreign_fd = i32::try_from(descriptor)
        .map_err(|_| InstallError::Invalid(format!("the {kind} descriptor is out of range")))?;
    let owned = pidfd_getfd(&pidfd, foreign_fd, PidfdGetfdFlags::empty()).map_err(|error| {
        InstallError::Io(std::io::Error::from_raw_os_error(error.raw_os_error()))
    })?;
    Ok(File::from(owned))
}

#[cfg(target_os = "linux")]
fn read_secret_descriptor_file(
    mut file: File,
    maximum: usize,
    kind: &'static str,
) -> Result<Zeroizing<Vec<u8>>, InstallError> {
    use rustix::fs::{SealFlags, fcntl_get_seals};

    let required = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK;
    let seals = fcntl_get_seals(&file).map_err(|_| {
        InstallError::Invalid(format!(
            "the {kind} descriptor must refer to sealed anonymous memory"
        ))
    })?;
    if !seals.contains(required) {
        return Err(InstallError::Invalid(format!(
            "the {kind} descriptor must be sealed against writes and resizing"
        )));
    }
    file.seek(SeekFrom::Start(0))?;
    read_descriptor_file(file, maximum, kind)
}

#[cfg(target_os = "linux")]
fn validate_recovery_output_file(file: File) -> Result<File, InstallError> {
    use std::os::unix::fs::FileTypeExt;

    let file_type = file.metadata()?.file_type();
    if !file_type.is_fifo() && !file_type.is_socket() {
        return Err(InstallError::Invalid(
            "the recovery output descriptor must be a pipe or Unix socket".into(),
        ));
    }
    Ok(file)
}

fn read_descriptor_file(
    mut file: File,
    maximum: usize,
    kind: &'static str,
) -> Result<Zeroizing<Vec<u8>>, InstallError> {
    if !file.metadata()?.file_type().is_file() {
        return Err(InstallError::Invalid(format!(
            "the {kind} descriptor must refer to a regular file"
        )));
    }

    let mut bytes = Zeroizing::new(Vec::with_capacity(maximum.min(4096)));
    Read::by_ref(&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() {
        return Err(InstallError::Invalid(format!(
            "the {kind} descriptor is empty"
        )));
    }
    if bytes.len() > maximum {
        return Err(InstallError::Invalid(format!(
            "the {kind} descriptor exceeds the {maximum}-byte limit"
        )));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn ensure_directory_exact(path: &Path, mode: u32) -> Result<(), InstallError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(InstallError::Refused(format!(
                "{} is not an installed-system directory",
                path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(mode).create(path)?;
        }
        Err(error) => return Err(InstallError::Io(error)),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.mode() & 0o7777 != mode
        || metadata.uid() != expected_install_owner()
        || metadata.gid() != expected_install_group()
    {
        return Err(InstallError::Refused(format!(
            "{} does not have the required owner and mode",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(test)))]
const fn expected_install_owner() -> u32 {
    0
}

#[cfg(all(target_os = "linux", not(test)))]
const fn expected_install_group() -> u32 {
    0
}

#[cfg(all(target_os = "linux", test))]
fn expected_install_owner() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(all(target_os = "linux", test))]
fn expected_install_group() -> u32 {
    rustix::process::getegid().as_raw()
}

#[cfg(target_os = "linux")]
fn write_new_synced_exact(path: &Path, bytes: &[u8], mode: u32) -> Result<(), InstallError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(InstallError::Refused(format!(
                "{} already exists on the freshly formatted target",
                path.display()
            )));
        }
        Err(error) => return Err(InstallError::Io(error)),
    }
    // Start private even for the advisory seed, then widen explicitly after
    // the atomic rename. This is independent of punard.service's umask.
    write_atomic_synced(path, bytes, 0o600)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    let file = open_regular_nofollow(path, "installed seed artifact")?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    if metadata.mode() & 0o7777 != mode
        || metadata.uid() != expected_install_owner()
        || metadata.gid() != expected_install_group()
    {
        return Err(InstallError::Refused(format!(
            "{} does not have the required owner and mode",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_bounded_regular(
    path: &Path,
    maximum: usize,
    description: &str,
) -> Result<Vec<u8>, InstallError> {
    let mut file = open_regular_nofollow(path, description)?;
    let mut bytes = Vec::with_capacity(maximum.min(4096));
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(InstallError::Refused(format!(
            "{description} exceeds its fixed size limit"
        )));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn validate_device_id_bytes(bytes: &[u8]) -> Result<(), InstallError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| InstallError::Trust("the device identity is not UTF-8".into()))?;
    let token = text.strip_suffix('\n').ok_or_else(|| {
        InstallError::Trust("the device identity is not newline-terminated".into())
    })?;
    let suffix = token
        .strip_prefix("dev_")
        .filter(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 60
                && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        .ok_or_else(|| InstallError::Trust("the device identity is invalid".into()))?;
    debug_assert!(!suffix.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_validated_device_id(path: &Path) -> Result<Vec<u8>, InstallError> {
    let bytes = read_bounded_regular(path, 65, "live device identity")?;
    validate_device_id_bytes(&bytes)?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn parse_validated_audit(bytes: &[u8], device_id: &str) -> Result<Vec<AuditEvent>, InstallError> {
    const FIELDS: [&str; 12] = [
        "action",
        "agent_session_id",
        "decision",
        "device_id",
        "event_id",
        "policy_ids",
        "project_id",
        "resource",
        "result",
        "source",
        "timestamp",
        "user_id",
    ];

    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(InstallError::Trust(
            "the audit log ends in a partial record".into(),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| InstallError::Trust("the audit log is not UTF-8".into()))?;
    let mut events = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            return Err(InstallError::Trust(
                "the audit log contains an empty record".into(),
            ));
        }
        let raw: serde_json::Value = serde_json::from_str(line)
            .map_err(|_| InstallError::Trust("the audit log contains invalid JSON".into()))?;
        let object = raw.as_object().ok_or_else(|| {
            InstallError::Trust("the audit log contains a non-object record".into())
        })?;
        if object.len() != FIELDS.len() || FIELDS.iter().any(|field| !object.contains_key(*field)) {
            return Err(InstallError::Trust(
                "the audit log contains an unknown, missing or secret-shaped field".into(),
            ));
        }
        let event: AuditEvent = serde_json::from_value(raw)
            .map_err(|_| InstallError::Trust("the audit record has the wrong shape".into()))?;
        validate_event_schema(&event).map_err(|_| {
            InstallError::Trust("the audit record does not conform to its schema".into())
        })?;
        if event.device_id != device_id {
            return Err(InstallError::Trust(
                "the audit record belongs to a different device identity".into(),
            ));
        }
        if events
            .iter()
            .any(|existing: &AuditEvent| existing.event_id == event.event_id)
        {
            return Err(InstallError::Trust(
                "the audit log contains a duplicate event id".into(),
            ));
        }
        events.push(event);
    }
    Ok(events)
}

#[cfg(target_os = "linux")]
fn validate_install_terminal_event(
    event: &AuditEvent,
    device_id: &str,
    action: &str,
    resource: &str,
    result: &str,
) -> Result<(), InstallError> {
    validate_event_schema(event).map_err(|_| {
        InstallError::Trust("an installation terminal event is not schema-conformant".into())
    })?;
    if event.device_id != device_id
        || event.action != action
        || event.resource.as_deref() != Some(resource)
        || event.decision != Decision::Allow
        || event.result != result
        || event.source != punar_common::PrincipalKind::Human
        || event.agent_session_id.as_deref() != Some(punar_common::audit::AGENT_SESSION_NONE)
        || event.project_id.as_deref() != Some(punar_common::audit::PROJECT_ID_SYSTEM)
    {
        return Err(InstallError::Trust(
            "an installation terminal event is not bound to this human-authorized install".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn append_audit_event_once(
    bytes: &mut Vec<u8>,
    events: &mut Vec<AuditEvent>,
    event: &AuditEvent,
) -> Result<(), InstallError> {
    if let Some(existing) = events
        .iter()
        .find(|existing| existing.event_id == event.event_id)
    {
        if existing != event {
            return Err(InstallError::Trust(
                "an installation event id was reused with different content".into(),
            ));
        }
        return Ok(());
    }
    let mut line = serde_json::to_vec(event)
        .map_err(|_| InstallError::Trust("an installation audit event did not serialize".into()))?;
    line.push(b'\n');
    if bytes.len().saturating_add(line.len()) > AUDIT_HANDOFF_MAX_BYTES {
        return Err(InstallError::Refused(
            "the installed audit handoff exceeds its fixed size limit".into(),
        ));
    }
    bytes.extend_from_slice(&line);
    events.push(event.clone());
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_install_audit_events(
    events: &[AuditEvent],
    terminal: &InstallAuditEvents,
    recovery_required: bool,
) -> Result<(), InstallError> {
    let has_plan = events.iter().any(|event| {
        event.action == "install.plan"
            && event.resource.as_deref() == Some("system_disk")
            && event.decision == Decision::Allow
            && event.source == punar_common::PrincipalKind::Human
            && event.user_id == terminal.apply_success.user_id
            && event.agent_session_id.as_deref() == Some(punar_common::audit::AGENT_SESSION_NONE)
            && event.result == "success"
    });
    let has_recovery = terminal
        .recovery_enrolled
        .as_ref()
        .is_some_and(|expected| events.iter().any(|event| event == expected));
    let has_apply = events.iter().any(|event| event == &terminal.apply_success);
    if !has_plan || (recovery_required && !has_recovery) || !has_apply {
        return Err(InstallError::Trust(
            "the installed audit handoff is missing a required installation event".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn build_installed_audit_handoff(
    source: &Path,
    device_id: &str,
    terminal: &InstallAuditEvents,
    recovery_required: bool,
) -> Result<Vec<u8>, InstallError> {
    match (recovery_required, terminal.recovery_enrolled.as_ref()) {
        (true, Some(event)) => validate_install_terminal_event(
            event,
            device_id,
            "install.recovery_key",
            "system_disk",
            "enrolled",
        )?,
        (true, None) => {
            return Err(InstallError::Trust(
                "the encrypted installation has no recovery-enrollment event".into(),
            ));
        }
        (false, Some(_)) => {
            return Err(InstallError::Trust(
                "the unencrypted installation falsely claims recovery enrollment".into(),
            ));
        }
        (false, None) => {}
    }
    validate_install_terminal_event(
        &terminal.apply_success,
        device_id,
        "install.apply",
        "system_image",
        "success",
    )?;
    if terminal
        .recovery_enrolled
        .as_ref()
        .is_some_and(|event| event.user_id != terminal.apply_success.user_id)
    {
        return Err(InstallError::Trust(
            "the installation terminal events belong to different human actors".into(),
        ));
    }
    let mut bytes = read_bounded_regular(
        source,
        AUDIT_HANDOFF_MAX_BYTES,
        "live installation audit log",
    )?;
    let mut events = parse_validated_audit(&bytes, device_id)?;
    if let Some(recovery) = terminal.recovery_enrolled.as_ref() {
        append_audit_event_once(&mut bytes, &mut events, recovery)?;
    }
    append_audit_event_once(&mut bytes, &mut events, &terminal.apply_success)?;
    require_install_audit_events(&events, terminal, recovery_required)?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn verify_installed_audit(
    var_root: &Path,
    expected: &[u8],
    device_id: &str,
    terminal: &InstallAuditEvents,
    recovery_required: bool,
) -> Result<(), InstallError> {
    verify_installed_directory_mode(&var_root.join("log"), 0o755)?;
    verify_installed_directory_mode(&var_root.join("log/punar"), 0o750)?;
    let path = var_root.join("log/punar/audit.jsonl");
    let actual = read_bounded_regular(&path, AUDIT_HANDOFF_MAX_BYTES, "installed audit log")?;
    verify_installed_file_mode(&path, 0o640)?;
    if actual != expected {
        return Err(InstallError::Trust(
            "the installed audit log changed between its durable write and read-only verification"
                .into(),
        ));
    }
    let events = parse_validated_audit(&actual, device_id)?;
    require_install_audit_events(&events, terminal, recovery_required)
}

#[cfg(target_os = "linux")]
fn verify_installed_directory_mode(path: &Path, mode: u32) -> Result<(), InstallError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o7777 != mode
        || metadata.uid() != expected_install_owner()
        || metadata.gid() != expected_install_group()
    {
        return Err(InstallError::Refused(format!(
            "{} does not have the required directory type, owner and mode",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_installed_file_mode(path: &Path, mode: u32) -> Result<(), InstallError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = open_regular_nofollow(path, "installed seed artifact")?.metadata()?;
    if metadata.permissions().mode() & 0o7777 != mode
        || metadata.uid() != expected_install_owner()
        || metadata.gid() != expected_install_group()
    {
        return Err(InstallError::Refused(format!(
            "{} does not have the required owner and mode",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct InstalledSeedExpectations<'a> {
    seed_digest: &'a str,
    hardware_report_digest: &'a str,
    device_id: &'a [u8],
    image_version: &'a str,
}

#[cfg(target_os = "linux")]
fn verify_installed_seed(
    var_root: &Path,
    plan: &InstallPlan,
    params: &InstallApplyParams,
    inputs: &InstallApplyInputs,
    expected: &InstalledSeedExpectations<'_>,
) -> Result<(), InstallError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let punar_dir = var_root.join("lib/punar");
    let metadata = fs::symlink_metadata(&punar_dir)?;
    if !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.uid() != expected_install_owner()
        || metadata.gid() != expected_install_group()
    {
        return Err(InstallError::Refused(
            "the installed Punar state directory has the wrong type, owner or mode".into(),
        ));
    }

    let seed_path = punar_dir.join("install/seed.json");
    let seed_bytes = read_bounded_regular(&seed_path, 4096, "installed seed")?;
    verify_installed_file_mode(&seed_path, 0o644)?;
    if sha256_hex(&seed_bytes) != expected.seed_digest {
        return Err(InstallError::Trust(
            "the installed seed changed between its durable write and read-only verification"
                .into(),
        ));
    }
    let seed: InstallSeedDocument = serde_json::from_slice(&seed_bytes)
        .map_err(|_| InstallError::Trust("the installed seed is invalid".into()))?;
    if seed.v != 1
        || seed.locale != params.seed.locale
        || seed.keymap != plan.keymap
        || !punar_common::time::is_rfc3339_timestamp(&seed.installed_at)
        || seed.image_version != expected.image_version
        || seed.disk_encrypted != (plan.encryption == InstallEncryption::Luks2)
        || seed.disk_recovery.mode != plan.recovery_mode
    {
        return Err(InstallError::Trust(
            "the installed seed does not match the confirmed plan".into(),
        ));
    }

    let machine_path = var_root.join("lib/dbus/machine-id");
    let machine_id = read_bounded_regular(&machine_path, 33, "installed machine id")?;
    verify_installed_file_mode(&machine_path, 0o444)?;
    let machine_text = std::str::from_utf8(&machine_id).unwrap_or_default();
    if machine_text.len() != 33
        || !machine_text.ends_with('\n')
        || !machine_text[..32]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(InstallError::Trust(
            "the installed machine id is invalid".into(),
        ));
    }

    let device_path = punar_dir.join("device-id");
    let device_id = read_bounded_regular(&device_path, 65, "installed device id")?;
    verify_installed_file_mode(&device_path, 0o600)?;
    validate_device_id_bytes(&device_id)?;
    if device_id != expected.device_id {
        return Err(InstallError::Trust(
            "the installed device id does not match its installation audit identity".into(),
        ));
    }

    let hardware_path = punar_dir.join("hardware-report.json");
    let hardware_bytes = read_bounded_regular(
        &hardware_path,
        HARDWARE_REPORT_MAX_BYTES,
        "installed hardware report",
    )?;
    verify_installed_file_mode(&hardware_path, 0o644)?;
    if sha256_hex(&hardware_bytes) != expected.hardware_report_digest {
        return Err(InstallError::Trust(
            "the installed hardware report changed between its durable write and read-only verification"
                .into(),
        ));
    }
    let hardware: InstallHardwareReport = serde_json::from_slice(&hardware_bytes)
        .map_err(|_| InstallError::Trust("the installed hardware report is invalid".into()))?;
    if hardware.v != 1
        || hardware.architecture != plan.architecture
        || !punar_common::time::is_rfc3339_timestamp(&hardware.generated_at)
        || !hardware.graphics_usable
        || hardware.disk_below_minimum_target != (plan.disk.size_bytes < TARGET_DISK_BYTES)
        || hardware.bare_hardware_qualified
    {
        return Err(InstallError::Trust(
            "the installed hardware report does not match the confirmed installation".into(),
        ));
    }

    let answers_path = punar_dir.join("install/oobe-answers.json");
    match inputs.oobe_answers() {
        Some(expected) => {
            let actual = read_bounded_regular(
                &answers_path,
                OOBE_ANSWERS_MAX_BYTES,
                "installed OOBE answers",
            )?;
            verify_installed_file_mode(&answers_path, 0o600)?;
            if actual != expected {
                return Err(InstallError::Trust(
                    "the installed OOBE answers are not byte-identical to their sealed input"
                        .into(),
                ));
            }
        }
        None => match fs::symlink_metadata(&answers_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(InstallError::Trust(
                    "the installed system contains unrequested OOBE answers".into(),
                ));
            }
            Err(error) => return Err(InstallError::Io(error)),
        },
    }
    Ok(())
}

const fn phase_index(phase: InstallPhase) -> usize {
    match phase {
        InstallPhase::VerifyRelease => 0,
        InstallPhase::Partition => 1,
        InstallPhase::Encrypt => 2,
        InstallPhase::Format => 3,
        InstallPhase::WriteSlotA => 4,
        InstallPhase::ReRead => 5,
        InstallPhase::Boot => 6,
        InstallPhase::Seed => 7,
        InstallPhase::VerifyInstalled => 8,
    }
}

const fn phase_name(phase: InstallPhase) -> &'static str {
    match phase {
        InstallPhase::VerifyRelease => "release verification",
        InstallPhase::Partition => "disk partitioning",
        InstallPhase::Encrypt => "disk encryption",
        InstallPhase::Format => "filesystem creation",
        InstallPhase::WriteSlotA => "root-slot writing",
        InstallPhase::ReRead => "written-image verification",
        InstallPhase::Boot => "boot installation",
        InstallPhase::Seed => "first-boot seeding",
        InstallPhase::VerifyInstalled => "installed-system verification",
    }
}

const fn public_error_reason(error: &InstallError) -> &'static str {
    match error {
        InstallError::Refused(_) => "a safety precondition was refused",
        InstallError::Invalid(_) => "an installer input or transition was invalid",
        InstallError::Trust(_) => "a required trust verification failed",
        InstallError::Io(_) => "a required device or filesystem operation failed",
    }
}

fn validate_answers(params: &InstallPlanParams) -> Result<(), InstallError> {
    if params.keymap.is_empty()
        || params.keymap.len() > 64
        || !params
            .keymap
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_+-".contains(&byte))
    {
        return Err(InstallError::Invalid(
            "keymap must be one 1–64 character XKB token".into(),
        ));
    }
    match (params.encryption, params.recovery_mode) {
        (InstallEncryption::None, InstallRecoveryMode::None)
        | (InstallEncryption::Luks2, InstallRecoveryMode::PersonalCopy)
        | (InstallEncryption::Luks2, InstallRecoveryMode::OrganizationEscrow) => Ok(()),
        (InstallEncryption::None, _) => Err(InstallError::Invalid(
            "an unencrypted plan cannot create or escrow an encryption recovery key".into(),
        )),
        (InstallEncryption::Luks2, InstallRecoveryMode::None) => Err(InstallError::Invalid(
            "an encrypted plan requires personal_copy or organization_escrow recovery".into(),
        )),
    }
}

fn validate_apply_params(params: &InstallApplyParams) -> Result<(), InstallError> {
    validate_plan_token(&params.plan_token)?;
    for (name, fd) in [
        ("passphrase_fd", params.passphrase_fd),
        ("recovery_output_fd", params.recovery_output_fd),
        ("oobe_answers_fd", params.oobe_answers_fd),
    ] {
        if let Some(fd) = fd {
            validate_descriptor_number(fd, name)?;
        }
    }
    let locale = params.seed.locale.as_str();
    if locale.is_empty()
        || locale.len() > 64
        || !locale
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.@-".contains(&byte))
    {
        return Err(InstallError::Invalid(
            "seed.locale must be one 1–64 character locale token".into(),
        ));
    }
    Ok(())
}

fn validate_plan_token(plan_token: &str) -> Result<(), InstallError> {
    if plan_token.len() != 64
        || !plan_token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(InstallError::Invalid(
            "plan_token must be one lowercase SHA-256 digest".into(),
        ));
    }
    Ok(())
}

fn validate_descriptor_number(descriptor: u32, name: &str) -> Result<(), InstallError> {
    if !(3..=1_048_575).contains(&descriptor) {
        return Err(InstallError::Invalid(format!(
            "{name} must name a non-standard descriptor held by the calling process"
        )));
    }
    Ok(())
}

fn partition_plan(
    disk_bytes: u64,
    sector_bytes: u64,
    architecture: Architecture,
    boot_platform: BootPlatform,
    encryption: InstallEncryption,
) -> Result<(Vec<InstallPartitionPlan>, u64), InstallError> {
    if !valid_sector_size(sector_bytes) {
        return Err(InstallError::Invalid(
            "the disk logical-sector size is unsupported".into(),
        ));
    }
    let first = align_up(GPT_LBAS * sector_bytes, ALIGNMENT)
        .ok_or_else(|| InstallError::Invalid("disk geometry overflow".into()))?;
    let usable_end = disk_bytes
        .checked_sub(GPT_LBAS * sector_bytes)
        .map(|value| align_down(value, ALIGNMENT))
        .ok_or_else(|| InstallError::Refused("disk is too small for a GPT".into()))?;
    let root_a = first + ESP_SIZE;
    let (boot_b, root_b, data) = match boot_platform {
        BootPlatform::Uefi => (None, root_a + ROOT_SIZE, root_a + 2 * ROOT_SIZE),
        BootPlatform::RaspberryPi => {
            let boot_b = root_a + ROOT_SIZE;
            let root_b = boot_b + ESP_SIZE;
            (Some(boot_b), root_b, root_b + ROOT_SIZE)
        }
    };
    let data_size = usable_end.checked_sub(data).ok_or_else(|| {
        InstallError::Refused("disk is too small for Punar's fixed A/B layout".into())
    })?;
    if data_size < DATA_MINIMUM {
        let fixed_gib = fixed_install_bytes(boot_platform) / GIB;
        let required_gib = fixed_gib + DATA_MINIMUM / GIB;
        return Err(InstallError::Refused(format!(
            "Punar needs {required_gib} GiB plus partition metadata ({} bytes), and this disk has {disk_bytes} bytes. {fixed_gib} GiB is the operating system, its boot files and rollback copy; 16 GiB is the floor for user data.",
            minimum_disk_bytes(sector_bytes, boot_platform)
        )));
    }
    let root_type = match architecture {
        Architecture::X86_64 => X86_ROOT_TYPE_GUID,
        Architecture::Aarch64 => ARM_ROOT_TYPE_GUID,
    };
    let partitions = match boot_platform {
        BootPlatform::Uefi => vec![
            partition(
                1,
                "PUNAR-ESP",
                ESP_TYPE_GUID,
                ESP_PARTUUID,
                first,
                ESP_SIZE,
                Some("vfat"),
                false,
            ),
            partition(
                2,
                "PUNAR-ROOT-A",
                root_type,
                ROOT_A_PARTUUID,
                root_a,
                ROOT_SIZE,
                Some("ext4"),
                false,
            ),
            partition(
                3,
                "PUNAR-ROOT-B",
                root_type,
                ROOT_B_PARTUUID,
                root_b,
                ROOT_SIZE,
                None,
                false,
            ),
            partition(
                4,
                "PUNAR-DATA",
                DATA_TYPE_GUID,
                DATA_PARTUUID,
                data,
                data_size,
                Some("btrfs"),
                encryption == InstallEncryption::Luks2,
            ),
        ],
        BootPlatform::RaspberryPi => vec![
            partition(
                1,
                "PUNAR-BOOT-A",
                ESP_TYPE_GUID,
                PI_BOOT_A_PARTUUID,
                first,
                ESP_SIZE,
                Some("vfat"),
                false,
            ),
            partition(
                2,
                "PUNAR-ROOT-A",
                root_type,
                ROOT_A_PARTUUID,
                root_a,
                ROOT_SIZE,
                Some("ext4"),
                false,
            ),
            partition(
                3,
                "PUNAR-BOOT-B",
                ESP_TYPE_GUID,
                PI_BOOT_B_PARTUUID,
                boot_b.expect("Raspberry Pi layout has boot slot B"),
                ESP_SIZE,
                Some("vfat"),
                false,
            ),
            partition(
                4,
                "PUNAR-ROOT-B",
                root_type,
                ROOT_B_PARTUUID,
                root_b,
                ROOT_SIZE,
                None,
                false,
            ),
            partition(
                5,
                "PUNAR-DATA",
                DATA_TYPE_GUID,
                DATA_PARTUUID,
                data,
                data_size,
                Some("btrfs"),
                encryption == InstallEncryption::Luks2,
            ),
        ],
    };
    Ok((partitions, data_size))
}

#[allow(clippy::too_many_arguments)]
fn partition(
    number: u32,
    name: &str,
    type_guid: &str,
    partuuid: &str,
    offset_bytes: u64,
    size_bytes: u64,
    filesystem: Option<&str>,
    encrypted: bool,
) -> InstallPartitionPlan {
    InstallPartitionPlan {
        number,
        name: name.into(),
        type_guid: type_guid.into(),
        partuuid: partuuid.into(),
        offset_bytes,
        size_bytes,
        filesystem: filesystem.map(str::to_string),
        encrypted,
    }
}

fn fixed_install_bytes(boot_platform: BootPlatform) -> u64 {
    let boot_partitions = match boot_platform {
        BootPlatform::Uefi => 1,
        BootPlatform::RaspberryPi => 2,
    };
    boot_partitions * ESP_SIZE + 2 * ROOT_SIZE
}

fn plan_boot_platform(plan: &InstallPlan) -> Result<BootPlatform, InstallError> {
    match plan.boot_platform.as_str() {
        "uefi" => Ok(BootPlatform::Uefi),
        "raspberry_pi" => Ok(BootPlatform::RaspberryPi),
        _ => Err(InstallError::Invalid(
            "install plan has an unknown boot platform".into(),
        )),
    }
}

fn data_partition_number(plan: &InstallPlan) -> Result<u32, InstallError> {
    let number = match plan_boot_platform(plan)? {
        BootPlatform::Uefi => 4,
        BootPlatform::RaspberryPi => 5,
    };
    let partition = plan
        .partitions
        .iter()
        .find(|partition| partition.number == number)
        .ok_or_else(|| InstallError::Invalid("install plan has no data partition".into()))?;
    if partition.name != "PUNAR-DATA" || partition.partuuid != DATA_PARTUUID {
        return Err(InstallError::Invalid(
            "install plan data partition does not match the fixed product layout".into(),
        ));
    }
    Ok(number)
}

fn minimum_disk_bytes(sector_bytes: u64, boot_platform: BootPlatform) -> u64 {
    let start = align_up(GPT_LBAS * sector_bytes, ALIGNMENT).unwrap_or(ALIGNMENT);
    start
        .saturating_add(fixed_install_bytes(boot_platform) + DATA_MINIMUM + GPT_LBAS * sector_bytes)
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

fn valid_sector_size(value: u64) -> bool {
    (512..=65_536).contains(&value) && value.is_power_of_two()
}

fn is_punar_partuuid(value: &str) -> bool {
    PUNAR_PARTUUIDS
        .iter()
        .any(|expected| value.eq_ignore_ascii_case(expected))
}

fn is_pseudo_disk(name: &str) -> bool {
    ["loop", "ram", "zram", "dm-", "md", "sr", "fd"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn parent_disk<'a>(partition: &str, disks: &'a [String]) -> Option<&'a str> {
    disks
        .iter()
        .filter(|disk| partition.starts_with(disk.as_str()))
        .filter(|disk| {
            let suffix = &partition[disk.len()..];
            (!suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()))
                || (suffix.starts_with('p')
                    && suffix.len() > 1
                    && suffix[1..].bytes().all(|byte| byte.is_ascii_digit()))
        })
        .max_by_key(|disk| disk.len())
        .map(String::as_str)
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_u64(path: impl AsRef<Path>) -> Option<u64> {
    read_trimmed(path)?.parse().ok()
}

fn first_hardware_text<const N: usize>(values: [Option<String>; N]) -> Option<String> {
    values.into_iter().flatten().find(|value| {
        !value.is_empty()
            && value.len() <= 256
            && !value.chars().any(|character| character.is_control())
    })
}

fn udev_properties(sys_root: &Path, udev_data_root: &Path) -> BTreeMap<String, String> {
    let Some(dev) = read_trimmed(sys_root.join("dev")) else {
        return BTreeMap::new();
    };
    let Ok(content) = fs::read_to_string(udev_data_root.join(format!("b{dev}"))) else {
        return BTreeMap::new();
    };
    content
        .lines()
        .filter_map(|line| line.strip_prefix("E:"))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

#[derive(Clone, Debug)]
struct MountRecord {
    device: String,
    mount_point: String,
}

fn mount_records(path: &Path) -> Result<Vec<MountRecord>, std::io::Error> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    Ok(content
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let device = fields.nth(2)?;
            let mount_point = fields.nth(1)?;
            let mut parts = device.split(':');
            let valid =
            matches!((parts.next(), parts.next(), parts.next()), (Some(a), Some(b), None) if a.bytes().all(|v| v.is_ascii_digit()) && b.bytes().all(|v| v.is_ascii_digit()))
            ;
            valid.then(|| MountRecord {
                device: device.to_string(),
                mount_point: unescape_mountinfo(mount_point),
            })
        })
        .collect())
}

/// Protect direct mounts and their block ancestry. A live EROFS commonly
/// mounts through dm-verity or a loop whose backing file lives on the USB
/// partition; offering only the top pseudo device would still expose the
/// physical medium. This closure walks `slaves/` and loop backing-file mount
/// ownership until no new major:minor id appears.
fn protected_block_devices(sources: &InstallerSources) -> Result<BTreeSet<String>, std::io::Error> {
    let mounts = mount_records(&sources.mountinfo_path)?;
    let mut protected = mounts
        .iter()
        .map(|record| record.device.clone())
        .collect::<BTreeSet<_>>();
    let entries = fs::read_dir(&sources.sys_class_block)?.collect::<Result<Vec<_>, _>>()?;
    loop {
        let mut changed = false;
        for entry in &entries {
            let root = entry.path();
            let Some(device) = read_trimmed(root.join("dev")) else {
                continue;
            };
            if !protected.contains(&device) {
                continue;
            }
            if let Ok(slaves) = fs::read_dir(root.join("slaves")) {
                for slave in slaves.flatten() {
                    if let Some(slave_device) =
                        read_trimmed(sources.sys_class_block.join(slave.file_name()).join("dev"))
                    {
                        changed |= protected.insert(slave_device);
                    }
                }
            }
            if entry.file_name().to_string_lossy().starts_with("loop") {
                if let Some(backing_file) = read_trimmed(root.join("loop/backing_file")) {
                    let backing_file = if backing_file.starts_with('/') {
                        backing_file
                    } else {
                        format!("/{backing_file}")
                    };
                    if let Some(owner) = mounts
                        .iter()
                        .filter(|record| path_belongs_to(&backing_file, &record.mount_point))
                        .max_by_key(|record| record.mount_point.len())
                    {
                        changed |= protected.insert(owner.device.clone());
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok(protected)
}

fn path_belongs_to(path: &str, mount_point: &str) -> bool {
    mount_point == "/"
        || path == mount_point
        || path
            .strip_prefix(mount_point)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn unescape_mountinfo(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn device_path(dev_root: &Path, device: &str) -> Result<PathBuf, InstallError> {
    let name = device.strip_prefix("/dev/").ok_or_else(|| {
        InstallError::Invalid("disk must be the /dev node returned by install.targets".into())
    })?;
    if name.is_empty()
        || name.contains('/')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(InstallError::Invalid(
            "disk contains an invalid device-node name".into(),
        ));
    }
    Ok(dev_root.join(name))
}

fn partition_device_path(
    dev_root: &Path,
    disk: &str,
    partition: u32,
) -> Result<PathBuf, InstallError> {
    if partition == 0 {
        return Err(InstallError::Invalid(
            "partition number must be greater than zero".into(),
        ));
    }
    let disk_path = device_path(dev_root, disk)?;
    let name = disk_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| InstallError::Invalid("disk has no device-node name".into()))?;
    let separator = if name.as_bytes().last().is_some_and(u8::is_ascii_digit) {
        "p"
    } else {
        ""
    };
    Ok(dev_root.join(format!("{name}{separator}{partition}")))
}

fn validate_root_slot_payload(plan: &InstallPlan) -> Result<(), InstallError> {
    let slot = plan
        .partitions
        .iter()
        .find(|partition| partition.number == 2)
        .ok_or_else(|| InstallError::Invalid("install plan has no root slot A".into()))?;
    if slot.name != "PUNAR-ROOT-A"
        || slot.partuuid != ROOT_A_PARTUUID
        || slot.size_bytes != ROOT_SIZE
        || slot.encrypted
    {
        return Err(InstallError::Invalid(
            "install plan root slot A does not match the fixed product layout".into(),
        ));
    }
    if plan.payload.uncompressed_size_bytes == 0
        || plan.payload.uncompressed_size_bytes > slot.size_bytes
        || plan.payload.uncompressed_size_bytes % DIRECT_IO_BLOCK_BYTES as u64 != 0
    {
        return Err(InstallError::Invalid(
            "release payload does not fit the aligned root slot A write contract".into(),
        ));
    }
    Ok(())
}

fn validate_raspberry_pi_boot_plan(plan: &InstallPlan) -> Result<(), InstallError> {
    if plan.architecture != "aarch64" || plan_boot_platform(plan)? != BootPlatform::RaspberryPi {
        return Err(InstallError::Invalid(
            "Raspberry Pi boot installation requires an aarch64 Raspberry Pi plan".into(),
        ));
    }
    if plan.boot_artifact.size_bytes == 0
        || plan.boot_artifact.size_bytes > ESP_SIZE
        || plan.boot_artifact.size_bytes % DIRECT_IO_BLOCK_BYTES as u64 != 0
    {
        return Err(InstallError::Invalid(
            "Raspberry Pi bootfs must be a non-empty, 4096-byte-aligned raw FAT image no larger than boot slot A"
                .into(),
        ));
    }

    let expected = [
        (
            1,
            "PUNAR-BOOT-A",
            ESP_TYPE_GUID,
            PI_BOOT_A_PARTUUID,
            Some("vfat"),
            false,
        ),
        (
            2,
            "PUNAR-ROOT-A",
            ARM_ROOT_TYPE_GUID,
            ROOT_A_PARTUUID,
            Some("ext4"),
            false,
        ),
        (
            3,
            "PUNAR-BOOT-B",
            ESP_TYPE_GUID,
            PI_BOOT_B_PARTUUID,
            Some("vfat"),
            false,
        ),
        (
            4,
            "PUNAR-ROOT-B",
            ARM_ROOT_TYPE_GUID,
            ROOT_B_PARTUUID,
            None,
            false,
        ),
        (
            5,
            "PUNAR-DATA",
            DATA_TYPE_GUID,
            DATA_PARTUUID,
            Some("btrfs"),
            plan.encryption == InstallEncryption::Luks2,
        ),
    ];
    if plan.partitions.len() != expected.len() {
        return Err(InstallError::Invalid(
            "Raspberry Pi install plan must contain exactly five fixed partitions".into(),
        ));
    }
    for (partition, (number, name, type_guid, partuuid, filesystem, encrypted)) in
        plan.partitions.iter().zip(expected)
    {
        if partition.number != number
            || partition.name != name
            || partition.type_guid != type_guid
            || partition.partuuid != partuuid
            || partition.filesystem.as_deref() != filesystem
            || partition.encrypted != encrypted
        {
            return Err(InstallError::Invalid(
                "Raspberry Pi install plan does not match the fixed boot/root/data layout".into(),
            ));
        }
    }
    if plan.partitions[0].size_bytes != ESP_SIZE
        || plan.partitions[1].size_bytes != ROOT_SIZE
        || plan.partitions[2].size_bytes != ESP_SIZE
        || plan.partitions[3].size_bytes != ROOT_SIZE
        || plan.partitions[4].size_bytes < DATA_MINIMUM
    {
        return Err(InstallError::Invalid(
            "Raspberry Pi install plan has invalid fixed partition sizes".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_raspberry_pi_boot_filesystem(root: &Path) -> Result<(), InstallError> {
    let autoboot = read_bounded_regular(
        &root.join("autoboot.txt"),
        PI_BOOT_CONFIG_MAX_BYTES,
        "Raspberry Pi autoboot.txt",
    )?;
    let cmdline = read_bounded_regular(
        &root.join("cmdline.txt"),
        PI_BOOT_CONFIG_MAX_BYTES,
        "Raspberry Pi cmdline.txt",
    )?;
    let config = read_bounded_regular(
        &root.join("config.txt"),
        PI_BOOT_CONFIG_MAX_BYTES,
        "Raspberry Pi config.txt",
    )?;
    validate_raspberry_pi_autoboot(&autoboot)?;
    validate_raspberry_pi_cmdline(&cmdline)?;
    validate_raspberry_pi_config(&config)?;
    require_bounded_regular_file(
        &root.join("kernel8.img"),
        PI_KERNEL_MAX_BYTES,
        "Raspberry Pi aarch64 kernel",
    )?;
    require_bounded_regular_file(
        &root.join("initramfs8"),
        PI_INITRAMFS_MAX_BYTES,
        "Raspberry Pi initramfs",
    )?;
    Ok(())
}

fn pi_boot_text<'a>(bytes: &'a [u8], description: &str) -> Result<&'a str, InstallError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| InstallError::Trust(format!("{description} is not UTF-8")))?;
    if text.is_empty() || text.contains(['\0', '\r']) {
        return Err(InstallError::Trust(format!(
            "{description} is empty or has unsupported control bytes"
        )));
    }
    Ok(text)
}

fn set_once(slot: &mut Option<String>, value: &str, description: &str) -> Result<(), InstallError> {
    if slot.replace(value.to_string()).is_some() {
        return Err(InstallError::Trust(format!(
            "{description} is defined more than once"
        )));
    }
    Ok(())
}

fn validate_raspberry_pi_autoboot(bytes: &[u8]) -> Result<(), InstallError> {
    let text = pi_boot_text(bytes, "Raspberry Pi autoboot.txt")?;
    let mut section = "";
    let mut tryboot_a_b = None;
    let mut normal_partition = None;
    let mut try_partition = None;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(InstallError::Trust(
                "Raspberry Pi autoboot.txt contains an invalid directive".into(),
            ));
        };
        let key = key.trim();
        let value = value.trim();
        match (section, key) {
            ("all", "tryboot_a_b") => set_once(&mut tryboot_a_b, value, "autoboot tryboot_a_b")?,
            ("all", "boot_partition") => {
                set_once(&mut normal_partition, value, "ordinary boot_partition")?
            }
            ("tryboot", "boot_partition") => {
                set_once(&mut try_partition, value, "tryboot boot_partition")?
            }
            (_, "tryboot_a_b" | "boot_partition") => {
                return Err(InstallError::Trust(
                    "Raspberry Pi autoboot selector appears in an unsafe section".into(),
                ));
            }
            _ => {}
        }
    }
    if tryboot_a_b.as_deref() != Some("1")
        || normal_partition.as_deref() != Some("1")
        || try_partition.as_deref() != Some("3")
    {
        return Err(InstallError::Trust(
            "Raspberry Pi autoboot.txt does not bind ordinary boot to slot A and tryboot to slot B"
                .into(),
        ));
    }
    Ok(())
}

fn validate_raspberry_pi_cmdline(bytes: &[u8]) -> Result<(), InstallError> {
    let text = pi_boot_text(bytes, "Raspberry Pi cmdline.txt")?;
    let lines = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    if lines.len() != 1 {
        return Err(InstallError::Trust(
            "Raspberry Pi cmdline.txt must contain exactly one command line".into(),
        ));
    }
    let tokens = lines[0].split_ascii_whitespace().collect::<Vec<_>>();
    let roots = tokens
        .iter()
        .filter(|token| token.starts_with("root="))
        .copied()
        .collect::<Vec<_>>();
    let expected_root = format!("root=PARTUUID={ROOT_A_PARTUUID}");
    if roots.as_slice() != [expected_root.as_str()]
        || !tokens.contains(&"rootfstype=ext4")
        || !tokens.contains(&"ro")
        || !tokens.contains(&"rootwait")
    {
        return Err(InstallError::Trust(
            "Raspberry Pi cmdline.txt does not bind boot slot A read-only to root slot A".into(),
        ));
    }
    Ok(())
}

fn validate_raspberry_pi_config(bytes: &[u8]) -> Result<(), InstallError> {
    let text = pi_boot_text(bytes, "Raspberry Pi config.txt")?;
    let mut section = "";
    let mut kernel = None;
    let mut initramfs = None;
    let mut arm_64bit = None;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            continue;
        }
        if line
            .split_ascii_whitespace()
            .next()
            .is_some_and(|directive| directive == "include")
        {
            return Err(InstallError::Trust(
                "Raspberry Pi config.txt may not include another configuration file".into(),
            ));
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "kernel" if section == "all" => {
                    set_once(&mut kernel, value, "Raspberry Pi kernel")?
                }
                "arm_64bit" if section == "all" => {
                    set_once(&mut arm_64bit, value, "Raspberry Pi arm_64bit")?
                }
                "kernel" | "arm_64bit" => {
                    return Err(InstallError::Trust(
                        "Raspberry Pi boot identity appears outside config.txt [all]".into(),
                    ));
                }
                "cmdline" | "os_prefix" | "boot_partition" | "tryboot_a_b" => {
                    return Err(InstallError::Trust(format!(
                        "Raspberry Pi config.txt may not redirect {key}"
                    )));
                }
                _ => {}
            }
        } else if let Some(value) = line.strip_prefix("initramfs ") {
            if section != "all" {
                return Err(InstallError::Trust(
                    "Raspberry Pi initramfs appears outside config.txt [all]".into(),
                ));
            }
            set_once(&mut initramfs, value.trim(), "Raspberry Pi initramfs")?;
        }
    }
    if kernel.as_deref() != Some("kernel8.img")
        || initramfs.as_deref() != Some("initramfs8 followkernel")
        || arm_64bit.as_deref() != Some("1")
    {
        return Err(InstallError::Trust(
            "Raspberry Pi config.txt does not select the fixed aarch64 kernel and initramfs".into(),
        ));
    }
    Ok(())
}

fn stream_exact_payload(
    source: &mut impl Read,
    destination: &mut impl Write,
    expected_size: u64,
    expected_digest: &str,
    mut progress: impl FnMut(u64) -> Result<(), InstallError>,
) -> Result<(), InstallError> {
    let mut buffer = vec![0_u8; SLOT_IO_BYTES];
    let mut hasher = Sha256::new();
    let mut completed = 0_u64;
    while completed < expected_size {
        let remaining = expected_size - completed;
        let wanted = usize::try_from(remaining.min(SLOT_IO_BYTES as u64))
            .expect("bounded payload chunk fits usize");
        let read = source.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(InstallError::Trust(
                "decompressed release payload ended before its signed size".into(),
            ));
        }
        destination.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        completed = completed
            .checked_add(read as u64)
            .ok_or_else(|| InstallError::Invalid("release payload size overflow".into()))?;
        progress(completed)?;
    }

    let mut extra = [0_u8; 1];
    if source.read(&mut extra)? != 0 {
        return Err(InstallError::Trust(
            "decompressed release payload exceeds its signed size".into(),
        ));
    }
    if hex(&hasher.finalize()) != expected_digest {
        return Err(InstallError::Trust(
            "decompressed release payload digest does not match its signed identity".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn digest_installed_partition(
    path: &Path,
    expected_size: u64,
    expected_digest: &str,
    allow_regular_target: bool,
    description: &str,
) -> Result<(), InstallError> {
    #[cfg(test)]
    if allow_regular_target && fs::symlink_metadata(path)?.file_type().is_file() {
        let mut file = open_regular_nofollow(path, description)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; SLOT_IO_BYTES];
        let mut remaining = expected_size;
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(SLOT_IO_BYTES as u64))
                .expect("bounded partition chunk fits usize");
            let read = file.read(&mut buffer[..wanted])?;
            if read == 0 {
                return Err(InstallError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("{description} returned a short test re-read"),
                )));
            }
            hasher.update(&buffer[..read]);
            remaining -= read as u64;
        }
        if hex(&hasher.finalize()) != expected_digest {
            return Err(InstallError::Trust(format!(
                "{description} does not match the signed release after test re-read"
            )));
        }
        return Ok(());
    }

    let _ = allow_regular_target;
    digest_direct_block_device(path, expected_size, expected_digest, description)
}

#[cfg(target_os = "linux")]
fn digest_direct_block_device(
    path: &Path,
    expected_size: u64,
    expected_digest: &str,
    description: &str,
) -> Result<(), InstallError> {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};

    if expected_size == 0 || expected_size % DIRECT_IO_BLOCK_BYTES as u64 != 0 {
        return Err(InstallError::Invalid(
            "direct slot verification requires a non-empty 4096-byte-aligned payload".into(),
        ));
    }
    let flags =
        rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::DIRECT;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(flags.bits()).expect("open flags fit libc::c_int"))
        .open(path)?;
    if !file.metadata()?.file_type().is_block_device() {
        return Err(InstallError::Refused(format!(
            "{description} is not a block device"
        )));
    }

    let mut hasher = Sha256::new();
    let mut completed = 0_u64;
    while completed < expected_size {
        let remaining_blocks =
            usize::try_from((expected_size - completed) / DIRECT_IO_BLOCK_BYTES as u64)
                .unwrap_or(usize::MAX);
        let block_count = remaining_blocks.min(DIRECT_IO_BLOCKS);
        let mut blocks = std::iter::repeat_with(|| DirectIoBlock([0; DIRECT_IO_BLOCK_BYTES]))
            .take(block_count)
            .collect::<Vec<_>>();
        let mut slices = blocks
            .iter_mut()
            .map(|block| IoSliceMut::new(&mut block.0))
            .collect::<Vec<_>>();
        let expected_read = block_count * DIRECT_IO_BLOCK_BYTES;
        let read = loop {
            match file.read_vectored(&mut slices) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        drop(slices);
        if read != expected_read {
            return Err(InstallError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("{description} returned a short O_DIRECT re-read"),
            )));
        }
        for block in &blocks {
            hasher.update(block.0.as_slice());
        }
        completed += read as u64;
    }
    if hex(&hasher.finalize()) != expected_digest {
        return Err(InstallError::Trust(format!(
            "{description} does not match the signed release after O_DIRECT re-read"
        )));
    }
    Ok(())
}

fn gpt_edge_sha256(
    path: &Path,
    size_bytes: u64,
    sector_bytes: u64,
) -> Result<String, InstallError> {
    if !valid_sector_size(sector_bytes) {
        return Err(InstallError::Invalid(
            "the disk logical-sector size is unsupported".into(),
        ));
    }
    let edge_bytes = GPT_LBAS
        .checked_mul(sector_bytes)
        .ok_or_else(|| InstallError::Invalid("disk geometry overflow".into()))?;
    if size_bytes < edge_bytes * 2 {
        return Err(InstallError::Refused(
            "disk is too small for GPT metadata".into(),
        ));
    }
    let mut file = File::open(path)?;
    let mut edges = vec![0_u8; (edge_bytes * 2) as usize];
    file.read_exact(&mut edges[..edge_bytes as usize])?;
    file.seek(SeekFrom::Start(size_bytes - edge_bytes))?;
    file.read_exact(&mut edges[edge_bytes as usize..])?;
    Ok(sha256_hex(&edges))
}

#[cfg(test)]
mod tests {
    use super::*;
    use punar_common::audit::{AuditActor, AuditOutcome, AuditWriter};
    use std::io::Write;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQUENCE: AtomicU32 = AtomicU32::new(0);

    struct Fixture {
        root: PathBuf,
        sources: InstallerSources,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "punar-install-test-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::SeqCst)
            ));
            let sys = root.join("sys");
            let dev = root.join("dev");
            let udev = root.join("udev");
            fs::create_dir_all(&sys).unwrap();
            fs::create_dir_all(&dev).unwrap();
            fs::create_dir_all(&udev).unwrap();
            let mountinfo = root.join("mountinfo");
            fs::write(&mountinfo, "").unwrap();
            let mut manifest: ReleaseManifest = serde_json::from_str(include_str!(
                "../../../fixtures/update/valid/release-manifest.json"
            ))
            .unwrap();
            manifest.architecture = Architecture::X86_64;
            manifest.boot_platform = BootPlatform::Uefi;
            manifest.release_id = format!(
                "{}-{}-{}-{}-{}",
                manifest.image_id,
                manifest.channel,
                manifest.architecture,
                manifest.boot_platform,
                manifest.version
            );
            let status_path = root.join("install-status.json");
            let live_device_id_path = root.join("live-device-id");
            fs::write(&live_device_id_path, "dev_fixture001\n").unwrap();
            let live_audit_path = root.join("live-audit.jsonl");
            let mut audit = AuditWriter::open(&live_audit_path).unwrap();
            audit
                .append(&AuditEvent::action(
                    "dev_fixture001",
                    &AuditActor::cli_peer("root"),
                    "install.plan",
                    "system_disk",
                    Decision::Allow,
                    AuditOutcome::Success,
                ))
                .unwrap();
            drop(audit);
            Self {
                root,
                sources: InstallerSources {
                    sys_class_block: sys,
                    dev_root: dev,
                    udev_data_root: udev,
                    mountinfo_path: mountinfo,
                    status_path,
                    release_manifest_override: Some(manifest),
                    architecture_override: Some(Architecture::X86_64),
                    boot_platform_override: Some(BootPlatform::Uefi),
                    live_device_id_path,
                    live_audit_path,
                    hardware_report_override: Some(InstallHardwareReport {
                        v: 1,
                        generated_at: "2026-08-30T00:00:00Z".into(),
                        architecture: "x86_64".into(),
                        kernel_release: "test-kernel".into(),
                        overall: InstallHardwareCoverage::Full,
                        graphics_usable: true,
                        disk_below_minimum_target: false,
                        bare_hardware_qualified: false,
                        devices: vec![punar_common::install::InstallHardwareDevice {
                            bus: punar_common::install::InstallHardwareBus::Pci,
                            address: "0000:00:01.0".into(),
                            function: punar_common::install::InstallHardwareFunction::Graphics,
                            display_name: "Fixture graphics".into(),
                            modalias: Some("pci:v00001AF4d00001050".into()),
                            vendor_id: Some("1af4".into()),
                            device_id: Some("1050".into()),
                            class_id: Some("030000".into()),
                            driver: Some("virtio_gpu".into()),
                            claiming_modules: vec!["virtio_gpu".into()],
                            requested_firmware: Vec::new(),
                            missing_firmware: Vec::new(),
                            coverage: InstallHardwareCoverage::Full,
                            reason: punar_common::install::InstallHardwareReason::DriverBound,
                        }],
                    }),
                    ..InstallerSources::default()
                },
            }
        }

        fn add_disk(&self, name: &str, major: u32, size_bytes: u64, serial: &str) {
            let sys = self.sources.sys_class_block.join(name);
            fs::create_dir_all(sys.join("queue")).unwrap();
            fs::create_dir_all(sys.join("device")).unwrap();
            fs::write(sys.join("size"), format!("{}\n", size_bytes / 512)).unwrap();
            fs::write(sys.join("queue/logical_block_size"), "512\n").unwrap();
            fs::write(sys.join("dev"), format!("{major}:0\n")).unwrap();
            fs::write(sys.join("ro"), "0\n").unwrap();
            fs::write(sys.join("removable"), "0\n").unwrap();
            fs::write(sys.join("device/model"), "Punar Test Disk\n").unwrap();
            fs::write(sys.join("device/serial"), format!("{serial}\n")).unwrap();
            fs::write(
                self.sources.udev_data_root.join(format!("b{major}:0")),
                "E:ID_PART_TABLE_TYPE=gpt\n",
            )
            .unwrap();
            let disk = File::create(self.sources.dev_root.join(name)).unwrap();
            disk.set_len(size_bytes).unwrap();
        }

        fn configure_raspberry_pi(&mut self) {
            let manifest = self.sources.release_manifest_override.as_mut().unwrap();
            manifest.architecture = Architecture::Aarch64;
            manifest.boot_platform = BootPlatform::RaspberryPi;
            manifest.boot_artifact.kind = BootArtifactKind::RaspberryPiBootfs;
            manifest.release_id = format!(
                "{}-{}-{}-{}-{}",
                manifest.image_id,
                manifest.channel,
                manifest.architecture,
                manifest.boot_platform,
                manifest.version
            );
            self.sources.architecture_override = Some(Architecture::Aarch64);
            self.sources.boot_platform_override = Some(BootPlatform::RaspberryPi);
            let report = self.sources.hardware_report_override.as_mut().unwrap();
            report.architecture = "aarch64".into();
        }

        #[allow(clippy::too_many_arguments)]
        fn add_partition(
            &self,
            disk: &str,
            number: u32,
            major: u32,
            minor: u32,
            label: Option<&str>,
            partuuid: Option<&str>,
            filesystem: Option<&str>,
        ) {
            let separator = if disk.as_bytes().last().is_some_and(u8::is_ascii_digit) {
                "p"
            } else {
                ""
            };
            let name = format!("{disk}{separator}{number}");
            let sys = self.sources.sys_class_block.join(&name);
            fs::create_dir_all(&sys).unwrap();
            fs::write(sys.join("partition"), format!("{number}\n")).unwrap();
            fs::write(sys.join("start"), "2048\n").unwrap();
            fs::write(sys.join("size"), "2048\n").unwrap();
            fs::write(sys.join("dev"), format!("{major}:{minor}\n")).unwrap();
            let mut properties = String::new();
            if let Some(label) = label {
                properties.push_str(&format!("E:ID_FS_LABEL={label}\n"));
            }
            if let Some(uuid) = partuuid {
                properties.push_str(&format!("E:ID_PART_ENTRY_UUID={uuid}\n"));
            }
            if let Some(filesystem) = filesystem {
                properties.push_str(&format!("E:ID_FS_TYPE={filesystem}\n"));
            }
            fs::write(
                self.sources
                    .udev_data_root
                    .join(format!("b{major}:{minor}")),
                properties,
            )
            .unwrap();
        }

        fn installer(&self) -> Installer {
            Installer::new(self.sources.clone())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn encrypted_params(disk: &str) -> InstallPlanParams {
        InstallPlanParams {
            disk: disk.into(),
            keymap: "us".into(),
            encryption: InstallEncryption::Luks2,
            recovery_mode: InstallRecoveryMode::PersonalCopy,
        }
    }

    fn organization_encrypted_params(disk: &str) -> InstallPlanParams {
        InstallPlanParams {
            disk: disk.into(),
            keymap: "us".into(),
            encryption: InstallEncryption::Luks2,
            recovery_mode: InstallRecoveryMode::OrganizationEscrow,
        }
    }

    fn unencrypted_params(disk: &str) -> InstallPlanParams {
        InstallPlanParams {
            disk: disk.into(),
            keymap: "us".into(),
            encryption: InstallEncryption::None,
            recovery_mode: InstallRecoveryMode::None,
        }
    }

    fn apply_params(plan: &InstallPlanResult) -> InstallApplyParams {
        InstallApplyParams {
            plan_token: plan.plan_token.clone(),
            disk: plan.plan.disk.device.clone(),
            passphrase_fd: Some(3),
            recovery_output_fd: Some(4),
            keymap: plan.plan.keymap.clone(),
            seed: punar_common::install::InstallSeedParams {
                locale: "C.UTF-8".into(),
            },
            oobe_answers_fd: None,
            unattended: false,
        }
    }

    fn terminal_audit_events() -> InstallAuditEvents {
        let actor = AuditActor::cli_peer("root");
        let mut recovery_enrolled = AuditEvent::action(
            "dev_fixture001",
            &actor,
            "install.recovery_key",
            "system_disk",
            Decision::Allow,
            AuditOutcome::Success,
        );
        recovery_enrolled.result = "enrolled".into();
        InstallAuditEvents {
            recovery_enrolled: Some(recovery_enrolled),
            apply_success: AuditEvent::action(
                "dev_fixture001",
                &actor,
                "install.apply",
                "system_image",
                Decision::Allow,
                AuditOutcome::Success,
            ),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn audit_handoff_rejects_unknown_secret_shaped_fields() {
        let fixture = Fixture::new();
        let bytes = fs::read(&fixture.sources.live_audit_path).unwrap();
        let mut raw: serde_json::Value = serde_json::from_slice(bytes.trim_ascii_end()).unwrap();
        raw.as_object_mut()
            .unwrap()
            .insert("password".into(), serde_json::json!("must-not-copy"));
        let mut changed = serde_json::to_vec(&raw).unwrap();
        changed.push(b'\n');
        fs::write(&fixture.sources.live_audit_path, changed).unwrap();

        let error = build_installed_audit_handoff(
            &fixture.sources.live_audit_path,
            "dev_fixture001",
            &terminal_audit_events(),
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("secret-shaped field"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn audit_handoff_refuses_false_or_missing_recovery_claims() {
        let fixture = Fixture::new();
        let error = build_installed_audit_handoff(
            &fixture.sources.live_audit_path,
            "dev_fixture001",
            &terminal_audit_events(),
            false,
        )
        .unwrap_err();
        assert!(error.to_string().contains("falsely claims"));

        let mut terminal = terminal_audit_events();
        terminal.recovery_enrolled = None;
        let error = build_installed_audit_handoff(
            &fixture.sources.live_audit_path,
            "dev_fixture001",
            &terminal,
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("no recovery-enrollment event"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_audit_must_match_the_durable_handoff_byte_for_byte() {
        let fixture = Fixture::new();
        let terminal = terminal_audit_events();
        let expected = build_installed_audit_handoff(
            &fixture.sources.live_audit_path,
            "dev_fixture001",
            &terminal,
            true,
        )
        .unwrap();
        let var_root = fixture.root.join("installed-var");
        ensure_directory_exact(&var_root, 0o755).unwrap();
        ensure_directory_exact(&var_root.join("log"), 0o755).unwrap();
        ensure_directory_exact(&var_root.join("log/punar"), 0o750).unwrap();
        let audit_path = var_root.join("log/punar/audit.jsonl");
        write_new_synced_exact(&audit_path, &expected, 0o640).unwrap();
        verify_installed_audit(&var_root, &expected, "dev_fixture001", &terminal, true).unwrap();

        let mut changed = expected.clone();
        changed.push(b' ');
        fs::write(&audit_path, changed).unwrap();
        let error = verify_installed_audit(&var_root, &expected, "dev_fixture001", &terminal, true)
            .unwrap_err();
        assert!(error.to_string().contains("changed between"));
    }

    fn first_mib(path: &Path) -> Vec<u8> {
        let mut bytes = vec![0_u8; 1024 * 1024];
        File::open(path).unwrap().read_exact(&mut bytes).unwrap();
        bytes
    }

    fn advance_status_to_boot(installer: &Installer, result: &InstallPlanResult) {
        installer
            .start_transaction_status(
                &result.plan_token,
                &result.plan.disk.device,
                result.plan.payload.uncompressed_size_bytes,
            )
            .unwrap();
        installer.enter_phase(InstallPhase::Partition).unwrap();
        installer.enter_phase(InstallPhase::Encrypt).unwrap();
        installer.enter_phase(InstallPhase::Format).unwrap();
        installer.enter_phase(InstallPhase::WriteSlotA).unwrap();
        installer
            .update_write_progress(result.plan.payload.uncompressed_size_bytes)
            .unwrap();
        installer.enter_phase(InstallPhase::ReRead).unwrap();
        installer.enter_phase(InstallPhase::Boot).unwrap();
    }

    fn advance_status_to_seed(installer: &Installer, result: &InstallPlanResult) {
        advance_status_to_boot(installer, result);
        installer.enter_phase(InstallPhase::Seed).unwrap();
    }

    fn write_raspberry_pi_boot_fixture(root: &Path) {
        fs::create_dir_all(root).unwrap();
        fs::write(
            root.join("autoboot.txt"),
            "[all]\ntryboot_a_b=1\nboot_partition=1\n[tryboot]\nboot_partition=3\n",
        )
        .unwrap();
        fs::write(
            root.join("cmdline.txt"),
            format!("root=PARTUUID={ROOT_A_PARTUUID} rootfstype=ext4 ro rootwait quiet\n"),
        )
        .unwrap();
        fs::write(
            root.join("config.txt"),
            "[all]\narm_64bit=1\nkernel=kernel8.img\ninitramfs initramfs8 followkernel\n",
        )
        .unwrap();
        fs::write(root.join("kernel8.img"), b"fixture aarch64 kernel").unwrap();
        fs::write(root.join("initramfs8"), b"fixture aarch64 initramfs").unwrap();
    }

    #[test]
    fn descriptor_intake_reads_exact_bounded_bytes_without_logging_them() {
        let fixture = Fixture::new();
        let path = fixture.root.join("secret.memfd-fixture");
        fs::write(&path, b"correct horse battery staple").unwrap();
        let bytes = read_descriptor_file(File::open(&path).unwrap(), 64, "test secret").unwrap();
        assert_eq!(bytes.as_slice(), b"correct horse battery staple");

        let error = match read_descriptor_file(File::open(&path).unwrap(), 8, "test secret") {
            Err(error) => error,
            Ok(_) => panic!("an oversized descriptor was accepted"),
        };
        let message = error.to_string();
        assert!(message.contains("8-byte limit"));
        assert!(!message.contains("correct horse"));

        let empty = fixture.root.join("empty");
        fs::write(&empty, b"").unwrap();
        assert!(read_descriptor_file(File::open(empty).unwrap(), 64, "test secret").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn secret_intake_requires_a_write_and_resize_sealed_memfd() {
        use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};

        let fixture = Fixture::new();
        let disk_file = fixture.root.join("disk-backed-secret");
        fs::write(&disk_file, b"must not persist").unwrap();
        let error =
            match read_secret_descriptor_file(File::open(&disk_file).unwrap(), 64, "test secret") {
                Err(error) => error,
                Ok(_) => panic!("a disk-backed secret descriptor was accepted"),
            };
        assert!(error.to_string().contains("sealed anonymous memory"));

        let owned = memfd_create(
            "punar-secret-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .unwrap();
        let mut file = File::from(owned);
        file.write_all(b"correct horse battery staple").unwrap();
        fcntl_add_seals(
            &file,
            SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
        )
        .unwrap();
        let bytes = read_secret_descriptor_file(file, 64, "test secret").unwrap();
        assert_eq!(bytes.as_slice(), b"correct horse battery staple");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_disclosure_accepts_only_a_pipe_or_unix_socket() {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;

        let fixture = Fixture::new();
        let disk_file = fixture.root.join("recovery-output");
        fs::write(&disk_file, b"").unwrap();
        let error = match validate_recovery_output_file(
            File::options().write(true).open(&disk_file).unwrap(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("a disk-backed recovery disclosure was accepted"),
        };
        assert!(error.to_string().contains("pipe or Unix socket"));

        let (writer, _reader) = UnixStream::pair().unwrap();
        let owned: OwnedFd = writer.into();
        assert!(validate_recovery_output_file(File::from(owned)).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn data_unlock_and_close_use_fixed_argv_and_an_anonymous_secret_pipe() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        let binary = fixture.root.join("cryptsetup");
        let capture = fixture.root.join("cryptsetup-capture");
        fs::write(
            &binary,
            format!(
                "#!/bin/sh\nset -eu\n\
                 capture='{}'\n\
                 operation=\"$1\"\n\
                 : > \"${{capture}}.${{operation}}.args\"\n\
                 for argument in \"$@\"; do\n\
                   printf '%s\\n' \"${{argument}}\" >> \"${{capture}}.${{operation}}.args\"\n\
                 done\n\
                 printf '%s\\n' \"${{LC_ALL:-missing}}\" > \"${{capture}}.${{operation}}.locale\"\n\
                 if [ \"${{operation}}\" = open ]; then cat > \"${{capture}}.secret\"; fi\n",
                capture.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        let passphrase = b"never in argv, logs or files outside this test seam";
        run_cryptsetup_open(
            &binary,
            Path::new("/dev/vda4"),
            "punar-install-data-0123456789abcdef",
            passphrase,
        )
        .unwrap();
        close_luks_mapping(&binary, "punar-install-data-0123456789abcdef").unwrap();

        let open_args = fs::read_to_string(capture.with_extension("open.args")).unwrap();
        assert_eq!(
            open_args.lines().collect::<Vec<_>>(),
            [
                "open",
                "--type",
                "luks2",
                "--key-file=-",
                "/dev/vda4",
                "punar-install-data-0123456789abcdef"
            ]
        );
        assert!(
            !open_args
                .as_bytes()
                .windows(passphrase.len())
                .any(|window| window == passphrase)
        );
        assert_eq!(
            fs::read(capture.with_extension("secret")).unwrap(),
            passphrase
        );
        assert_eq!(
            fs::read_to_string(capture.with_extension("close.args"))
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["close", "punar-install-data-0123456789abcdef"]
        );
        assert_eq!(
            fs::read_to_string(capture.with_extension("open.locale"))
                .unwrap()
                .trim(),
            "C"
        );
    }

    #[test]
    fn personal_recovery_gate_is_plan_bound_and_has_no_default_continue() {
        const KEY: &str = "lhkbicdj-trbuftjv-tviijfck-dfvbknrh-uiulbhui-higltier-kecfhkbk-egrirkui";

        let fixture = Fixture::new();
        let installer = fixture.installer();
        let token = "a".repeat(64);
        let mut disclosure = None;
        installer
            .begin_personal_recovery(
                &token,
                SecretRecoveryKey::parse(KEY).unwrap(),
                1,
                |key, groups| {
                    disclosure = Some((key.to_string(), groups));
                    Ok(())
                },
            )
            .unwrap();

        let (displayed, groups) = disclosure.unwrap();
        assert_eq!(displayed, KEY);
        let parts = displayed.split('-').collect::<Vec<_>>();
        let answer = format!(
            "{} {}",
            parts[usize::from(groups[0] - 1)],
            parts[usize::from(groups[1] - 1)]
        );

        let wrong_token = "b".repeat(64);
        assert!(
            installer
                .acknowledge_personal_recovery_bytes(&wrong_token, answer.as_bytes())
                .is_err()
        );
        assert!(
            installer
                .acknowledge_personal_recovery_bytes(&token, b"wrong groups")
                .is_err()
        );
        installer
            .acknowledge_personal_recovery_bytes(&token, answer.as_bytes())
            .unwrap();
        let confirmation = installer.wait_for_personal_recovery(&token).unwrap();
        assert_eq!(confirmation.recovery_keyslot, 1);
        assert!(confirmation.confirmed);
        assert!(installer.wait_for_personal_recovery(&token).is_err());
    }

    #[test]
    fn abandoning_personal_recovery_removes_the_checkpoint() {
        const KEY: &str = "lhkbicdj-trbuftjv-tviijfck-dfvbknrh-uiulbhui-higltier-kecfhkbk-egrirkui";

        let fixture = Fixture::new();
        let installer = fixture.installer();
        let token = "c".repeat(64);
        installer
            .begin_personal_recovery(&token, SecretRecoveryKey::parse(KEY).unwrap(), 2, |_, _| {
                Ok(())
            })
            .unwrap();
        installer.cancel_recovery(&token);
        assert!(installer.wait_for_personal_recovery(&token).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn organization_recovery_retries_in_memory_and_advances_only_after_verified_receipt() {
        use punar_mock_smplify::config::MockConfig;
        use punar_mock_smplify::server::MockServer;

        const KEY: &str = "lhkbicdj-trbuftjv-tviijfck-dfvbknrh-uiulbhui-higltier-kecfhkbk-egrirkui";
        const UUID: &str = "69782a5d-4852-44dc-9b9d-a0c11fd90f5f";

        let mut fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        fixture.sources.allow_regular_target_for_tests = true;
        let installer = fixture.installer();
        let result = installer
            .plan(&organization_encrypted_params("/dev/vda"))
            .unwrap();
        installer
            .start_transaction_status(
                &result.plan_token,
                &result.plan.disk.device,
                result.plan.payload.uncompressed_size_bytes,
            )
            .unwrap();
        installer.enter_phase(InstallPhase::Partition).unwrap();
        installer.enter_phase(InstallPhase::Encrypt).unwrap();
        installer
            .begin_organization_recovery(
                &result.plan,
                &result.plan_token,
                "acme",
                SecretRecoveryKey::parse(KEY).unwrap(),
                RecoveryKeyIdentity {
                    luks_uuid: UUID.into(),
                    recovery_keyslot: 3,
                },
            )
            .unwrap();

        let awaiting = installer.status();
        assert_eq!(awaiting.state, InstallOverallState::Awaiting);
        assert_eq!(
            awaiting.awaiting,
            Some(InstallAwaiting::OrganizationEscrowReceipt)
        );
        assert_eq!(
            awaiting.phases[phase_index(InstallPhase::Encrypt)].state,
            InstallPhaseState::Waiting
        );
        assert!(installer.enter_phase(InstallPhase::Format).is_err());

        let unavailable = ControlPlaneClient::new(fixture.root.join("missing.sock"));
        let unavailable_token = Redacted::new("a".repeat(64));
        assert!(
            installer
                .attempt_organization_recovery(
                    &result.plan_token,
                    &unavailable,
                    &unavailable_token,
                )
                .is_err()
        );
        assert_eq!(installer.status(), awaiting);
        assert!(
            installer
                .attempt_organization_recovery(&"f".repeat(64), &unavailable, &unavailable_token,)
                .is_err()
        );
        assert_eq!(installer.status(), awaiting);

        let socket = fixture.root.join("mock-api.sock");
        let state_dir = fixture.root.join("mock-state");
        let fixtures_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/organizations/acme");
        let handle = MockServer::new(MockConfig {
            socket: socket.clone(),
            fixtures_dir,
            state_dir: state_dir.clone(),
        })
        .unwrap()
        .spawn()
        .unwrap();
        let client = ControlPlaneClient::new(&socket);
        let (device_token, _) = client
            .register("dev_fixture001", &Redacted::new("b".repeat(64)))
            .unwrap();
        let evidence = installer
            .attempt_organization_recovery(&result.plan_token, &client, &device_token)
            .unwrap();
        assert_eq!(evidence.organization_id, "acme");
        assert_eq!(evidence.tenant_key_id, "trk_mock_2026_08");
        assert_eq!(evidence.device_id, "dev_fixture001");
        assert_eq!(evidence.luks_uuid, UUID);
        assert_eq!(evidence.recovery_keyslot, 3);
        assert_eq!(evidence.envelope_sha256.len(), 64);
        assert!(!evidence.receipt_id.is_empty());

        let status = installer.status();
        assert_eq!(status.state, InstallOverallState::Running);
        assert_eq!(status.phase, Some(InstallPhase::Encrypt));
        assert_eq!(status.awaiting, None);
        assert_eq!(
            status.phases[phase_index(InstallPhase::Encrypt)].state,
            InstallPhaseState::Complete
        );
        installer.enter_phase(InstallPhase::Format).unwrap();
        installer.enter_phase(InstallPhase::WriteSlotA).unwrap();

        let custody =
            fs::read_to_string(state_dir.join("received-recovery-envelopes.jsonl")).unwrap();
        assert!(custody.contains("encapsulated_key"));
        assert!(!custody.contains(KEY));
        assert!(!custody.contains(&KEY.replace('-', "")));
        let published_status = fs::read_to_string(&fixture.sources.status_path).unwrap();
        assert!(!published_status.contains(KEY));
        assert!(!published_status.contains(&KEY.replace('-', "")));

        handle.stop();
    }

    #[test]
    fn partition_parenting_handles_sd_nvme_and_mmc_names() {
        let disks = vec![
            "sda".into(),
            "sdaa".into(),
            "nvme0n1".into(),
            "mmcblk0".into(),
        ];
        assert_eq!(parent_disk("sda1", &disks), Some("sda"));
        assert_eq!(parent_disk("sdaa2", &disks), Some("sdaa"));
        assert_eq!(parent_disk("nvme0n1p3", &disks), Some("nvme0n1"));
        assert_eq!(parent_disk("mmcblk0p4", &disks), Some("mmcblk0"));
    }

    #[test]
    fn partition_device_paths_handle_lettered_and_numbered_disk_names() {
        let dev = Path::new("/dev");
        assert_eq!(
            partition_device_path(dev, "/dev/vda", 2).unwrap(),
            PathBuf::from("/dev/vda2")
        );
        assert_eq!(
            partition_device_path(dev, "/dev/nvme0n1", 2).unwrap(),
            PathBuf::from("/dev/nvme0n1p2")
        );
        assert_eq!(
            partition_device_path(dev, "/dev/mmcblk0", 4).unwrap(),
            PathBuf::from("/dev/mmcblk0p4")
        );
        assert!(partition_device_path(dev, "/dev/vda", 0).is_err());
        assert!(partition_device_path(dev, "/dev/../vda", 2).is_err());
    }

    #[test]
    fn exact_payload_stream_rejects_short_extra_and_changed_bytes() {
        let payload = b"the exact decompressed root payload";
        let digest = sha256_hex(payload);
        let mut written = Vec::new();
        let mut progress = Vec::new();
        stream_exact_payload(
            &mut payload.as_slice(),
            &mut written,
            payload.len() as u64,
            &digest,
            |completed| {
                progress.push(completed);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(written, payload);
        assert_eq!(progress, [payload.len() as u64]);

        let mut short_output = Vec::new();
        let error = stream_exact_payload(
            &mut payload[..payload.len() - 1].as_ref(),
            &mut short_output,
            payload.len() as u64,
            &digest,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("ended before"));

        let mut extra_output = Vec::new();
        let error = stream_exact_payload(
            &mut [payload.as_slice(), b"extra"].concat().as_slice(),
            &mut extra_output,
            payload.len() as u64,
            &digest,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("exceeds"));

        let mut changed_output = Vec::new();
        let error = stream_exact_payload(
            &mut payload.as_slice(),
            &mut changed_output,
            payload.len() as u64,
            &"0".repeat(64),
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("digest"));
    }

    #[test]
    fn live_status_starts_idle_and_is_published_atomically_at_0644() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        let installer = fixture.installer();
        installer.initialize_status_file().unwrap();
        let bytes = fs::read(&fixture.sources.status_path).unwrap();
        assert!(bytes.ends_with(b"\n"));
        let status: InstallStatusResult = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status, InstallStatusResult::idle());
        assert_eq!(
            fs::metadata(&fixture.sources.status_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert!(
            fs::read_dir(&fixture.root).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("tmp"))
        );
    }

    #[test]
    fn luks_uuid_readback_is_bounded_canonical_and_strict() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        let output = fixture.root.join("uuid-output");
        let capture = fixture.root.join("uuid-args");
        let tool = fixture.root.join("cryptsetup");
        fs::write(
            &tool,
            format!(
                "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > '{}'\ncat '{}'\n",
                capture.display(),
                output.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        let target = fixture.root.join("data-volume");

        fs::write(&output, "69782A5D-4852-44DC-9B9D-A0C11FD90F5F\n").unwrap();
        assert_eq!(
            read_luks_uuid(&tool, &target).unwrap(),
            "69782a5d-4852-44dc-9b9d-a0c11fd90f5f"
        );
        assert_eq!(
            fs::read_to_string(&capture)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["luksUUID", target.to_str().unwrap()]
        );

        fs::write(&output, "not-a-luks-uuid\n").unwrap();
        assert!(read_luks_uuid(&tool, &target).is_err());
        fs::write(&output, "a".repeat(LUKS_UUID_OUTPUT_MAX_BYTES as usize + 1)).unwrap();
        assert!(read_luks_uuid(&tool, &target).is_err());
    }

    #[test]
    fn transaction_status_proves_ordered_progress_recovery_and_success() {
        let fixture = Fixture::new();
        let installer = fixture.installer();
        let token = "a".repeat(64);
        installer.initialize_status_file().unwrap();
        installer
            .start_transaction_status(&token, "/dev/vda", 100)
            .unwrap();

        let status = installer.status();
        assert_eq!(status.state, InstallOverallState::Running);
        assert_eq!(status.plan_token.as_deref(), Some(token.as_str()));
        assert_eq!(status.disk.as_deref(), Some("/dev/vda"));
        assert_eq!(status.phase, Some(InstallPhase::VerifyRelease));
        assert_eq!(status.phases.len(), InstallPhase::ALL.len());
        assert_eq!(
            status.phases[phase_index(InstallPhase::WriteSlotA)].completed_bytes,
            Some(0)
        );
        assert_eq!(
            status.phases[phase_index(InstallPhase::WriteSlotA)].total_bytes,
            Some(100)
        );
        assert!(
            installer
                .start_transaction_status(&token, "/dev/vda", 100)
                .is_err()
        );
        assert!(installer.enter_phase(InstallPhase::Encrypt).is_err());

        installer.enter_phase(InstallPhase::Partition).unwrap();
        installer.enter_phase(InstallPhase::Encrypt).unwrap();
        installer
            .await_recovery_status(InstallAwaiting::RecoveryKeyAck)
            .unwrap();
        let waiting = installer.status();
        assert_eq!(waiting.state, InstallOverallState::Awaiting);
        assert_eq!(waiting.awaiting, Some(InstallAwaiting::RecoveryKeyAck));
        assert_eq!(
            waiting.phases[phase_index(InstallPhase::Encrypt)].state,
            InstallPhaseState::Waiting
        );
        assert!(installer.enter_phase(InstallPhase::Format).is_err());

        installer.resume_recovery_status().unwrap();
        installer.enter_phase(InstallPhase::Format).unwrap();
        installer.enter_phase(InstallPhase::WriteSlotA).unwrap();
        installer.update_write_progress(40).unwrap();
        assert!(installer.update_write_progress(39).is_err());
        assert!(installer.update_write_progress(101).is_err());
        assert!(installer.enter_phase(InstallPhase::ReRead).is_err());
        installer.update_write_progress(100).unwrap();
        installer.enter_phase(InstallPhase::ReRead).unwrap();
        installer.enter_phase(InstallPhase::Boot).unwrap();
        installer.enter_phase(InstallPhase::Seed).unwrap();
        installer
            .enter_phase(InstallPhase::VerifyInstalled)
            .unwrap();
        installer.complete_transaction_status().unwrap();

        let succeeded = installer.status();
        assert_eq!(succeeded.state, InstallOverallState::Succeeded);
        assert_eq!(succeeded.phase, None);
        assert!(
            succeeded
                .phases
                .iter()
                .all(|phase| phase.state == InstallPhaseState::Complete)
        );
        let persisted: InstallStatusResult =
            serde_json::from_slice(&fs::read(&fixture.sources.status_path).unwrap()).unwrap();
        assert_eq!(persisted, succeeded);
        assert!(
            installer
                .start_transaction_status(&token, "/dev/vda", 100)
                .is_err()
        );
    }

    #[test]
    fn transaction_failure_is_secret_free_honest_and_cancels_recovery() {
        const KEY: &str = "lhkbicdj-trbuftjv-tviijfck-dfvbknrh-uiulbhui-higltier-kecfhkbk-egrirkui";

        let fixture = Fixture::new();
        let installer = fixture.installer();
        let token = "b".repeat(64);
        installer.initialize_status_file().unwrap();
        installer
            .start_transaction_status(&token, "/dev/vda", 100)
            .unwrap();
        installer.enter_phase(InstallPhase::Partition).unwrap();
        installer.enter_phase(InstallPhase::Encrypt).unwrap();
        installer
            .begin_personal_recovery(&token, SecretRecoveryKey::parse(KEY).unwrap(), 1, |_, _| {
                Ok(())
            })
            .unwrap();
        installer
            .await_recovery_status(InstallAwaiting::RecoveryKeyAck)
            .unwrap();
        installer
            .fail_transaction_status(
                InstallPhase::Encrypt,
                &InstallError::Invalid(KEY.to_string()),
            )
            .unwrap();

        let failed = installer.status();
        assert_eq!(failed.state, InstallOverallState::Failed);
        assert_eq!(failed.phase, Some(InstallPhase::Encrypt));
        assert_eq!(failed.awaiting, None);
        assert_eq!(
            failed.phases[phase_index(InstallPhase::Encrypt)].state,
            InstallPhaseState::Failed
        );
        let failure = failed.failure.unwrap();
        assert!(failure.disk_state.contains("partially prepared"));
        assert!(!failure.message.contains(KEY));
        let persisted = fs::read_to_string(&fixture.sources.status_path).unwrap();
        assert!(!persisted.contains(KEY));
        assert!(installer.wait_for_personal_recovery(&token).is_err());

        let second = Fixture::new();
        let installer = second.installer();
        installer.initialize_status_file().unwrap();
        installer
            .start_transaction_status(&token, "/dev/vdb", 100)
            .unwrap();
        installer
            .fail_transaction_status(
                InstallPhase::VerifyRelease,
                &InstallError::Trust(KEY.to_string()),
            )
            .unwrap();
        let failure = installer.status().failure.unwrap();
        assert_eq!(
            failure.disk_state,
            "No disk bytes were changed by the installer."
        );
        assert!(!failure.message.contains(KEY));
    }

    #[test]
    fn exact_layout_is_aligned_and_keeps_the_data_floor() {
        let size = 128_000_000_000;
        let (partitions, data) = partition_plan(
            size,
            512,
            Architecture::X86_64,
            BootPlatform::Uefi,
            InstallEncryption::Luks2,
        )
        .unwrap();
        assert_eq!(partitions.len(), 4);
        assert!(
            partitions
                .iter()
                .all(|part| part.offset_bytes % ALIGNMENT == 0)
        );
        assert!(data >= DATA_MINIMUM);
        assert_eq!(partitions[1].type_guid, X86_ROOT_TYPE_GUID);
        assert!(partitions[3].encrypted);
    }

    #[test]
    fn minimum_layout_refuses_one_byte_too_small() {
        let minimum = minimum_disk_bytes(512, BootPlatform::Uefi);
        assert!(
            partition_plan(
                minimum - 1,
                512,
                Architecture::Aarch64,
                BootPlatform::Uefi,
                InstallEncryption::None
            )
            .is_err()
        );
        let (parts, _) = partition_plan(
            minimum,
            512,
            Architecture::Aarch64,
            BootPlatform::Uefi,
            InstallEncryption::None,
        )
        .unwrap();
        assert_eq!(parts[1].type_guid, ARM_ROOT_TYPE_GUID);
    }

    #[test]
    fn raspberry_pi_layout_has_native_boot_root_pairs_and_platform_minimum() {
        let minimum = minimum_disk_bytes(512, BootPlatform::RaspberryPi);
        assert_eq!(
            minimum - minimum_disk_bytes(512, BootPlatform::Uefi),
            ESP_SIZE
        );
        assert!(
            partition_plan(
                minimum - 1,
                512,
                Architecture::Aarch64,
                BootPlatform::RaspberryPi,
                InstallEncryption::Luks2,
            )
            .is_err()
        );
        let (partitions, data) = partition_plan(
            minimum,
            512,
            Architecture::Aarch64,
            BootPlatform::RaspberryPi,
            InstallEncryption::Luks2,
        )
        .unwrap();
        assert_eq!(data, DATA_MINIMUM);
        assert_eq!(partitions.len(), 5);
        assert_eq!(
            partitions
                .iter()
                .map(|partition| (partition.number, partition.name.as_str()))
                .collect::<Vec<_>>(),
            [
                (1, "PUNAR-BOOT-A"),
                (2, "PUNAR-ROOT-A"),
                (3, "PUNAR-BOOT-B"),
                (4, "PUNAR-ROOT-B"),
                (5, "PUNAR-DATA"),
            ]
        );
        assert_eq!(partitions[0].partuuid, PI_BOOT_A_PARTUUID);
        assert_eq!(partitions[2].partuuid, PI_BOOT_B_PARTUUID);
        assert_eq!(partitions[1].type_guid, ARM_ROOT_TYPE_GUID);
        assert!(partitions[4].encrypted);
    }

    #[test]
    fn invalid_encryption_recovery_combinations_are_refused() {
        let params = InstallPlanParams {
            disk: "/dev/vda".into(),
            keymap: "us".into(),
            encryption: InstallEncryption::None,
            recovery_mode: InstallRecoveryMode::PersonalCopy,
        };
        assert!(validate_answers(&params).is_err());
    }

    #[test]
    fn live_mode_requires_the_exact_kernel_token() {
        assert!(live_mode_from_cmdline("quiet punar.live=1 console=ttyS0"));
        for value in ["", "punar.live=0", "xpunar.live=1", "punar.live=1x"] {
            assert!(!live_mode_from_cmdline(value), "{value}");
        }
    }

    #[test]
    fn targets_exclude_boot_and_answer_media_but_report_small_disks() {
        let fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        fixture.add_disk("vdb", 253, 64 * 1024 * 1024, "LIVE-MEDIA");
        fixture.add_partition("vdb", 1, 253, 1, Some("PUNAR_INSTALL"), None, Some("vfat"));
        let dm = fixture.sources.sys_class_block.join("dm-0");
        fs::create_dir_all(dm.join("slaves/vdb1")).unwrap();
        fs::write(dm.join("dev"), "240:0\n").unwrap();
        fs::write(dm.join("size"), "2048\n").unwrap();
        fixture.add_disk("vdc", 254, 64 * 1024 * 1024, "ANSWERS");
        fixture.add_partition("vdc", 1, 254, 1, Some(ANSWERS_LABEL), None, Some("vfat"));
        fixture.add_disk("vdd", 255, 20 * GIB, "TOO-SMALL");
        fs::write(
            &fixture.sources.mountinfo_path,
            "24 1 240:0 / /run/live rw - erofs /dev/dm-0 rw\n",
        )
        .unwrap();

        let result = fixture.installer().targets().unwrap();
        let devices = result
            .targets
            .iter()
            .map(|target| target.device.as_str())
            .collect::<Vec<_>>();
        assert_eq!(devices, ["/dev/vda", "/dev/vdd"]);
        assert!(result.targets[0].eligible);
        assert!(!result.targets[1].eligible);
        assert!(
            result.targets[1]
                .ineligible_reason
                .as_deref()
                .unwrap()
                .contains("17 GiB")
        );
    }

    #[test]
    fn plan_token_binds_both_gpt_edges_and_the_full_plan() {
        let fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        let installer = fixture.installer();
        let first = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        assert_eq!(
            first.plan_token,
            sha256_hex(&canonical_json(&first.plan).unwrap())
        );
        assert_eq!(first.plan.partitions.len(), 4);
        assert_eq!(first.plan.disk.serial, "TARGET-128G");
        assert!(first.hardware_report.graphics_usable);
        assert!(!first.hardware_report.disk_below_minimum_target);
        assert!(!first.hardware_report.bare_hardware_qualified);
        assert_eq!(
            first.plan.payload.uncompressed_digest_sha256,
            "4444444444444444444444444444444444444444444444444444444444444444"
        );
        assert!(matches!(
            first.plan.boot_artifact.kind,
            punar_common::update::BootArtifactKind::Uki
        ));

        let mut changed_sources = fixture.sources.clone();
        let mut changed_manifest = changed_sources.release_manifest_override.clone().unwrap();
        changed_manifest.boot_artifact.digest_sha256 = "3".repeat(64);
        changed_sources.release_manifest_override = Some(changed_manifest);
        let boot_changed = Installer::new(changed_sources)
            .plan(&encrypted_params("/dev/vda"))
            .unwrap();
        assert_eq!(first.plan.payload, boot_changed.plan.payload);
        assert_ne!(first.plan.boot_artifact, boot_changed.plan.boot_artifact);
        assert_ne!(first.plan_token, boot_changed.plan_token);

        let mut disk = File::options()
            .write(true)
            .open(fixture.sources.dev_root.join("vda"))
            .unwrap();
        disk.seek(SeekFrom::End(-1)).unwrap();
        disk.write_all(&[0x5a]).unwrap();
        drop(disk);
        let changed = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        assert_ne!(
            first.plan.disk.existing_gpt_sha256,
            changed.plan.disk.existing_gpt_sha256
        );
        assert_ne!(first.plan_token, changed.plan_token);
    }

    #[test]
    fn plan_refuses_missing_graphics_without_writing_the_target() {
        let mut fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        let before = first_mib(&fixture.sources.dev_root.join("vda"));
        let report = fixture.sources.hardware_report_override.as_mut().unwrap();
        report.overall = InstallHardwareCoverage::Unsupported;
        report.graphics_usable = false;
        report.devices.clear();

        let error = fixture
            .installer()
            .plan(&encrypted_params("/dev/vda"))
            .unwrap_err();
        assert!(error.to_string().contains("no graphics device"));
        assert_eq!(before, first_mib(&fixture.sources.dev_root.join("vda")));
    }

    #[test]
    fn release_verification_binds_and_reads_the_exact_boot_artifact() {
        let mut fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        let release_dir = fixture.root.join("release");
        fs::create_dir_all(&release_dir).unwrap();
        fixture.sources.release_manifest_path = release_dir.join("release.json");
        let payload = b"fixture compressed root payload";
        let boot_artifact = b"MZ fixture unified kernel image";
        let manifest = fixture.sources.release_manifest_override.as_mut().unwrap();
        manifest.payload.filename = "slot.raw.zst".into();
        manifest.payload.digest_sha256 = sha256_hex(payload);
        manifest.payload.size_bytes = payload.len() as u64;
        manifest.boot_artifact.filename = "punar.efi".into();
        manifest.boot_artifact.digest_sha256 = sha256_hex(boot_artifact);
        manifest.boot_artifact.size_bytes = boot_artifact.len() as u64;
        fs::write(release_dir.join(&manifest.payload.filename), payload).unwrap();
        fs::write(
            release_dir.join(&manifest.boot_artifact.filename),
            boot_artifact,
        )
        .unwrap();

        let installer = fixture.installer();
        let result = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        installer
            .start_transaction_status(
                &result.plan_token,
                &result.plan.disk.device,
                result.plan.payload.uncompressed_size_bytes,
            )
            .unwrap();
        installer.verify_release_payload(&result.plan).unwrap();

        fs::write(
            release_dir.join(&result.plan.boot_artifact.filename),
            b"MZ fixture unified kernel imagf",
        )
        .unwrap();
        let error = installer.verify_release_payload(&result.plan).unwrap_err();
        assert!(error.to_string().contains("digest"));
        assert_eq!(installer.status().phase, Some(InstallPhase::VerifyRelease));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uefi_boot_install_is_disk_bound_durable_and_never_writes_nvram() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        File::create(fixture.sources.dev_root.join("vda1")).unwrap();
        let release_dir = fixture.root.join("release");
        fs::create_dir_all(&release_dir).unwrap();
        fixture.sources.release_manifest_path = release_dir.join("release.json");
        let artifact = b"MZ signed fixture slot-A unified kernel image";
        let manifest = fixture.sources.release_manifest_override.as_mut().unwrap();
        manifest.boot_artifact.filename = "punar-slot-a.efi".into();
        manifest.boot_artifact.digest_sha256 = sha256_hex(artifact);
        manifest.boot_artifact.size_bytes = artifact.len() as u64;
        fs::write(release_dir.join(&manifest.boot_artifact.filename), artifact).unwrap();

        let esp = fixture.root.join("esp");
        fs::create_dir(&esp).unwrap();
        let capture = fixture.root.join("bootctl-capture");
        let fake_bootctl = fixture.root.join("bootctl");
        fs::write(
            &fake_bootctl,
            format!(
                "#!/bin/sh\nset -eu\n\
                 capture='{}'\n\
                 : > \"${{capture}}.args\"\n\
                 esp=''\n\
                 for argument in \"$@\"; do\n\
                   printf '%s\\n' \"${{argument}}\" >> \"${{capture}}.args\"\n\
                   case \"${{argument}}\" in --esp-path=*) esp=\"${{argument#--esp-path=}}\" ;; esac\n\
                 done\n\
                 printf '%s\\n' \"${{LC_ALL:-missing}}\" > \"${{capture}}.locale\"\n\
                 [ -n \"${{esp}}\" ]\n\
                 mkdir -p \"${{esp}}/EFI/BOOT\"\n\
                 printf 'fixture systemd-boot' > \"${{esp}}/EFI/BOOT/BOOTX64.EFI\"\n",
                capture.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_bootctl, fs::Permissions::from_mode(0o755)).unwrap();
        fixture.sources.bootctl_path = fake_bootctl;
        fixture.sources.allow_regular_target_for_tests = true;
        fixture.sources.mounted_esp_override = Some(esp.clone());

        let installer = fixture.installer();
        let result = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        let version = fixture
            .sources
            .release_manifest_override
            .as_ref()
            .unwrap()
            .version
            .to_string();
        advance_status_to_boot(&installer, &result);
        installer.install_boot_artifact(&result.plan).unwrap();

        let arguments = fs::read_to_string(capture.with_extension("args")).unwrap();
        let expected_esp_argument = format!("--esp-path={}", esp.display());
        assert_eq!(
            arguments.lines().collect::<Vec<_>>(),
            ["install", expected_esp_argument.as_str(), "--no-variables"]
        );
        assert!(!arguments.lines().any(|argument| argument == "--variables"));
        assert_eq!(
            fs::read_to_string(capture.with_extension("locale"))
                .unwrap()
                .trim(),
            "C"
        );
        assert_eq!(
            fs::read(esp.join(format!("EFI/Linux/punar_{version}.efi"))).unwrap(),
            artifact
        );
        assert_eq!(
            fs::read_to_string(esp.join("loader/loader.conf")).unwrap(),
            format!("preferred punar_{version}*.efi\ntimeout 0\neditor no\n")
        );
        assert!(esp.join("EFI/BOOT/BOOTX64.EFI").is_file());
        assert!(fs::read_dir(esp.join("EFI/Linux")).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("+3-0")
        }));
        assert_eq!(installer.status().phase, Some(InstallPhase::Seed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn raspberry_pi_bootfs_is_plan_bound_reread_and_tryboot_validated() {
        let mut fixture = Fixture::new();
        fixture.configure_raspberry_pi();
        fixture.add_disk("vda", 252, 128_000_000_000, "PI-TARGET-128G");
        let target = fixture.sources.dev_root.join("vda1");
        let target_file = File::create(&target).unwrap();
        target_file.set_len(ESP_SIZE).unwrap();
        drop(target_file);

        let release_dir = fixture.root.join("release");
        fs::create_dir_all(&release_dir).unwrap();
        fixture.sources.release_manifest_path = release_dir.join("release.json");
        let artifact = vec![0x5a_u8; DIRECT_IO_BLOCK_BYTES * 2];
        let manifest = fixture.sources.release_manifest_override.as_mut().unwrap();
        manifest.boot_artifact.filename = "punar-rpi-boot-a.img".into();
        manifest.boot_artifact.digest_sha256 = sha256_hex(&artifact);
        manifest.boot_artifact.size_bytes = artifact.len() as u64;
        fs::write(
            release_dir.join(&manifest.boot_artifact.filename),
            &artifact,
        )
        .unwrap();

        let mounted_boot = fixture.root.join("mounted-pi-boot-a");
        write_raspberry_pi_boot_fixture(&mounted_boot);
        fixture.sources.allow_regular_target_for_tests = true;
        fixture.sources.mounted_esp_override = Some(mounted_boot);

        let installer = fixture.installer();
        let result = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        assert_eq!(result.plan.partitions.len(), 5);
        assert_eq!(data_partition_number(&result.plan).unwrap(), 5);
        advance_status_to_boot(&installer, &result);
        installer.install_boot_artifact(&result.plan).unwrap();

        let mut installed = vec![0_u8; artifact.len()];
        File::open(target)
            .unwrap()
            .read_exact(&mut installed)
            .unwrap();
        assert_eq!(installed, artifact);
        assert_eq!(installer.status().phase, Some(InstallPhase::Seed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn raspberry_pi_bootfs_refuses_mismatched_root_or_tryboot_selector() {
        let mut fixture = Fixture::new();
        fixture.configure_raspberry_pi();
        fixture.add_disk("vda", 252, 128_000_000_000, "PI-TARGET-128G");
        let target = fixture.sources.dev_root.join("vda1");
        let target_file = File::create(&target).unwrap();
        target_file.set_len(ESP_SIZE).unwrap();
        drop(target_file);

        let release_dir = fixture.root.join("release");
        fs::create_dir_all(&release_dir).unwrap();
        fixture.sources.release_manifest_path = release_dir.join("release.json");
        let artifact = vec![0xa5_u8; DIRECT_IO_BLOCK_BYTES];
        let manifest = fixture.sources.release_manifest_override.as_mut().unwrap();
        manifest.boot_artifact.filename = "punar-rpi-boot-a.img".into();
        manifest.boot_artifact.digest_sha256 = sha256_hex(&artifact);
        manifest.boot_artifact.size_bytes = artifact.len() as u64;
        fs::write(
            release_dir.join(&manifest.boot_artifact.filename),
            &artifact,
        )
        .unwrap();

        let mounted_boot = fixture.root.join("mounted-pi-boot-a");
        write_raspberry_pi_boot_fixture(&mounted_boot);
        fs::write(
            mounted_boot.join("config.txt"),
            "[all]\narm_64bit=1\nkernel=kernel8.img\ninitramfs initramfs8 followkernel\ninclude escape.txt\n",
        )
        .unwrap();
        let include_error = validate_raspberry_pi_boot_filesystem(&mounted_boot).unwrap_err();
        assert!(include_error.to_string().contains("include"));
        fs::write(
            mounted_boot.join("config.txt"),
            "[all]\narm_64bit=1\nkernel=kernel8.img\ninitramfs initramfs8 followkernel\n",
        )
        .unwrap();
        fs::write(
            mounted_boot.join("cmdline.txt"),
            format!("root=PARTUUID={ROOT_B_PARTUUID} rootfstype=ext4 ro rootwait quiet\n"),
        )
        .unwrap();
        fs::write(
            mounted_boot.join("autoboot.txt"),
            "[all]\ntryboot_a_b=1\nboot_partition=3\n[tryboot]\nboot_partition=1\n",
        )
        .unwrap();
        let selector_error = validate_raspberry_pi_boot_filesystem(&mounted_boot).unwrap_err();
        assert!(selector_error.to_string().contains("autoboot"));
        fs::write(
            mounted_boot.join("autoboot.txt"),
            "[all]\ntryboot_a_b=1\nboot_partition=1\n[tryboot]\nboot_partition=3\n",
        )
        .unwrap();
        fixture.sources.allow_regular_target_for_tests = true;
        fixture.sources.mounted_esp_override = Some(mounted_boot);

        let installer = fixture.installer();
        let result = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        advance_status_to_boot(&installer, &result);
        let error = installer.install_boot_artifact(&result.plan).unwrap_err();
        assert!(error.to_string().contains("cmdline"));
        assert_eq!(installer.status().phase, Some(InstallPhase::Boot));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn boot_artifact_tampering_is_refused_before_the_esp_is_touched() {
        let mut fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        File::create(fixture.sources.dev_root.join("vda1")).unwrap();
        let release_dir = fixture.root.join("release");
        fs::create_dir_all(&release_dir).unwrap();
        fixture.sources.release_manifest_path = release_dir.join("release.json");
        let artifact = b"MZ signed fixture slot-A unified kernel image";
        let manifest = fixture.sources.release_manifest_override.as_mut().unwrap();
        manifest.boot_artifact.filename = "punar-slot-a.efi".into();
        manifest.boot_artifact.digest_sha256 = sha256_hex(artifact);
        manifest.boot_artifact.size_bytes = artifact.len() as u64;
        let artifact_path = release_dir.join(&manifest.boot_artifact.filename);
        fs::write(&artifact_path, artifact).unwrap();

        let esp = fixture.root.join("esp");
        fs::create_dir(&esp).unwrap();
        fixture.sources.bootctl_path = fixture.root.join("bootctl-must-not-run");
        fixture.sources.allow_regular_target_for_tests = true;
        fixture.sources.mounted_esp_override = Some(esp.clone());

        let installer = fixture.installer();
        let result = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        advance_status_to_boot(&installer, &result);
        let mut tampered = artifact.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        fs::write(&artifact_path, tampered).unwrap();

        let error = installer.install_boot_artifact(&result.plan).unwrap_err();
        assert!(error.to_string().contains("digest"));
        assert!(fs::read_dir(&esp).unwrap().next().is_none());
        assert_eq!(installer.status().phase, Some(InstallPhase::Boot));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seed_is_last_byte_exact_and_read_only_verified_before_success() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mut fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        let data = fixture.root.join("mounted-var");
        let root = fixture.root.join("mounted-root");
        fs::create_dir(&data).unwrap();
        fs::create_dir_all(root.join("usr/lib/systemd/system")).unwrap();
        fs::write(
            root.join("usr/lib/systemd/system/punard.service"),
            b"[Service]\nExecStart=/usr/bin/punard\n",
        )
        .unwrap();
        fixture.sources.mounted_data_override = Some(data.clone());
        fixture.sources.mounted_root_override = Some(root);

        let installer = fixture.installer();
        let result = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        advance_status_to_seed(&installer, &result);
        let answers = br#"{"v":1,"timezone":"Europe/Berlin"}"#;
        let mut params = apply_params(&result);
        params.oobe_answers_fd = Some(5);
        let inputs = InstallApplyInputs {
            passphrase: Some(Zeroizing::new(b"correct horse battery staple".to_vec())),
            recovery_output: None,
            oobe_answers: Some(Zeroizing::new(answers.to_vec())),
        };

        installer
            .seed_installed_system(&result.plan, &params, &inputs)
            .unwrap();
        assert_eq!(
            installer.status().phase,
            Some(InstallPhase::VerifyInstalled)
        );
        let seed_path = data.join("lib/punar/install/seed.json");
        let hardware_path = data.join("lib/punar/hardware-report.json");
        let seed: InstallSeedDocument =
            serde_json::from_slice(&fs::read(&seed_path).unwrap()).unwrap();
        let hardware: InstallHardwareReport =
            serde_json::from_slice(&fs::read(&hardware_path).unwrap()).unwrap();
        assert_eq!(seed.v, 1);
        assert_eq!(seed.locale, "C.UTF-8");
        assert_eq!(seed.keymap, "us");
        assert!(punar_common::time::is_rfc3339_timestamp(&seed.installed_at));
        assert!(seed.disk_encrypted);
        assert_eq!(seed.disk_recovery.mode, InstallRecoveryMode::PersonalCopy);
        assert_eq!(hardware.architecture, "x86_64");
        assert!(hardware.graphics_usable);
        assert!(!hardware.bare_hardware_qualified);
        assert_eq!(
            fs::read(data.join("lib/punar/install/oobe-answers.json")).unwrap(),
            answers
        );
        assert_eq!(
            fs::metadata(data.join("lib/punar"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            fs::metadata(&seed_path).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        assert_eq!(
            fs::metadata(&hardware_path).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        assert_eq!(
            fs::metadata(data.join("lib/punar/install/oobe-answers.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert_eq!(
            fs::metadata(&seed_path).unwrap().uid(),
            expected_install_owner()
        );
        assert_eq!(
            fs::read(data.join("lib/punar/device-id")).unwrap(),
            b"dev_fixture001\n"
        );

        let audit_events = terminal_audit_events();
        installer
            .verify_installed_system(&result.plan, &params, &inputs, &audit_events)
            .unwrap();
        assert_eq!(installer.status().state, InstallOverallState::Succeeded);
        assert_eq!(installer.status().phase, None);

        let audit_path = data.join("log/punar/audit.jsonl");
        let audit_bytes = fs::read(&audit_path).unwrap();
        let events = parse_validated_audit(&audit_bytes, "dev_fixture001").unwrap();
        assert_eq!(events.len(), 3);
        require_install_audit_events(&events, &audit_events, true).unwrap();
        let audit_text = std::str::from_utf8(&audit_bytes).unwrap();
        for forbidden in [
            "\"password\":",
            "\"passphrase\":",
            "\"recovery_key\":",
            "\"private_key\":",
            "\"token\":",
        ] {
            assert!(!audit_text.contains(forbidden), "found {forbidden}");
        }
        assert_eq!(
            fs::metadata(&audit_path).unwrap().permissions().mode() & 0o7777,
            0o640
        );
        assert_eq!(
            fs::metadata(data.join("log/punar"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o750
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unencrypted_seed_states_no_encryption_and_retains_no_passphrase() {
        let mut fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        let data = fixture.root.join("mounted-var");
        let root = fixture.root.join("mounted-root");
        fs::create_dir(&data).unwrap();
        fs::create_dir_all(root.join("usr/lib/systemd/system")).unwrap();
        fs::write(
            root.join("usr/lib/systemd/system/punard.service"),
            b"[Service]\nExecStart=/usr/bin/punard\n",
        )
        .unwrap();
        fixture.sources.mounted_data_override = Some(data.clone());
        fixture.sources.mounted_root_override = Some(root);

        let installer = fixture.installer();
        let result = installer.plan(&unencrypted_params("/dev/vda")).unwrap();
        advance_status_to_seed(&installer, &result);
        let mut params = apply_params(&result);
        params.passphrase_fd = None;
        params.recovery_output_fd = None;
        let inputs = InstallApplyInputs {
            passphrase: None,
            recovery_output: None,
            oobe_answers: None,
        };
        installer
            .seed_installed_system(&result.plan, &params, &inputs)
            .unwrap();
        let seed: InstallSeedDocument =
            serde_json::from_slice(&fs::read(data.join("lib/punar/install/seed.json")).unwrap())
                .unwrap();
        assert!(!seed.disk_encrypted);
        assert_eq!(seed.disk_recovery.mode, InstallRecoveryMode::None);
        let mut audit_events = terminal_audit_events();
        audit_events.recovery_enrolled = None;
        installer
            .verify_installed_system(&result.plan, &params, &inputs, &audit_events)
            .unwrap();
        assert_eq!(installer.status().state, InstallOverallState::Succeeded);
        let events = parse_validated_audit(
            &fs::read(data.join("log/punar/audit.jsonl")).unwrap(),
            "dev_fixture001",
        )
        .unwrap();
        assert_eq!(events.len(), 2);
        assert!(
            !events
                .iter()
                .any(|event| event.action == "install.recovery_key")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn final_verification_refuses_seed_tampering_and_unrequested_answers() {
        let mut fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        let data = fixture.root.join("mounted-var");
        let root = fixture.root.join("mounted-root");
        fs::create_dir(&data).unwrap();
        fs::create_dir_all(root.join("usr/lib/systemd/system")).unwrap();
        fs::write(
            root.join("usr/lib/systemd/system/punard.service"),
            b"[Service]\nExecStart=/usr/bin/punard\n",
        )
        .unwrap();
        fixture.sources.mounted_data_override = Some(data.clone());
        fixture.sources.mounted_root_override = Some(root);

        let installer = fixture.installer();
        let result = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        advance_status_to_seed(&installer, &result);
        let params = apply_params(&result);
        let inputs = InstallApplyInputs {
            passphrase: Some(Zeroizing::new(b"correct horse battery staple".to_vec())),
            recovery_output: None,
            oobe_answers: None,
        };
        installer
            .seed_installed_system(&result.plan, &params, &inputs)
            .unwrap();
        let audit_events = terminal_audit_events();

        fs::write(
            data.join("lib/punar/install/oobe-answers.json"),
            br#"{"v":1}"#,
        )
        .unwrap();
        let error = installer
            .verify_installed_system(&result.plan, &params, &inputs, &audit_events)
            .unwrap_err();
        assert!(error.to_string().contains("unrequested OOBE answers"));
        assert_eq!(installer.status().state, InstallOverallState::Running);
        assert_eq!(
            installer.status().phase,
            Some(InstallPhase::VerifyInstalled)
        );

        fs::remove_file(data.join("lib/punar/install/oobe-answers.json")).unwrap();
        let hardware_path = data.join("lib/punar/hardware-report.json");
        let original_hardware = fs::read(&hardware_path).unwrap();
        let mut changed_hardware = original_hardware.clone();
        changed_hardware.push(b' ');
        fs::write(&hardware_path, changed_hardware).unwrap();
        let error = installer
            .verify_installed_system(&result.plan, &params, &inputs, &audit_events)
            .unwrap_err();
        assert!(error.to_string().contains("hardware report changed"));
        assert_eq!(installer.status().state, InstallOverallState::Running);
        fs::write(&hardware_path, original_hardware).unwrap();

        let seed_path = data.join("lib/punar/install/seed.json");
        let mut seed = fs::read(&seed_path).unwrap();
        seed.push(b' ');
        fs::write(seed_path, seed).unwrap();
        let error = installer
            .verify_installed_system(&result.plan, &params, &inputs, &audit_events)
            .unwrap_err();
        assert!(error.to_string().contains("seed changed"));
        assert_eq!(installer.status().state, InstallOverallState::Running);
    }

    #[test]
    fn apply_preflight_accepts_only_this_boots_unchanged_plan() {
        let fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        let installer = fixture.installer();
        let plan = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        assert_eq!(
            installer.preflight_apply(&apply_params(&plan)).unwrap(),
            plan.plan
        );

        let stranger = fixture.installer();
        let error = stranger.preflight_apply(&apply_params(&plan)).unwrap_err();
        assert!(error.to_string().contains("during this boot"));
    }

    #[test]
    fn apply_preflight_rereads_identity_and_gpt_edges_before_any_write() {
        let fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        let installer = fixture.installer();
        let plan = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        let mut disk = File::options()
            .write(true)
            .open(fixture.sources.dev_root.join("vda"))
            .unwrap();
        disk.write_all(&[0xa5]).unwrap();
        drop(disk);

        let disk_path = fixture.sources.dev_root.join("vda");
        let before = first_mib(&disk_path);

        let error = installer.preflight_apply(&apply_params(&plan)).unwrap_err();
        assert!(error.to_string().contains("changed after confirmation"));
        assert_eq!(first_mib(&disk_path), before);

        // Revalidation computes the changed plan only for comparison. It
        // must not register that new token as though a person had confirmed
        // a second install.plan result.
        let changed = installer
            .compute_plan(&encrypted_params("/dev/vda"))
            .unwrap();
        let error = installer
            .preflight_apply(&apply_params(&changed))
            .unwrap_err();
        assert!(error.to_string().contains("during this boot"));
        assert_eq!(first_mib(&disk_path), before);
    }

    #[test]
    fn apply_preflight_refuses_a_same_size_physical_disk_swap_without_writing() {
        let fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "ORIGINAL-128G");
        fs::write(
            fixture.sources.sys_class_block.join("vda/device/wwid"),
            "wwn-original\n",
        )
        .unwrap();
        let installer = fixture.installer();
        let plan = installer.plan(&encrypted_params("/dev/vda")).unwrap();

        fs::write(
            fixture.sources.sys_class_block.join("vda/device/serial"),
            "REPLACEMENT-128G\n",
        )
        .unwrap();
        fs::write(
            fixture.sources.sys_class_block.join("vda/device/wwid"),
            "wwn-replacement\n",
        )
        .unwrap();
        let disk_path = fixture.sources.dev_root.join("vda");
        let before = first_mib(&disk_path);

        let error = installer.preflight_apply(&apply_params(&plan)).unwrap_err();
        assert!(error.to_string().contains("changed after confirmation"));
        assert_eq!(first_mib(&disk_path), before);
    }

    #[test]
    fn apply_preflight_refuses_a_reenumerated_device_node_without_writing() {
        let fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "CONFIRMED-128G");
        let installer = fixture.installer();
        let plan = installer.plan(&encrypted_params("/dev/vda")).unwrap();

        fixture.add_disk("vdb", 253, 128_000_000_000, "OTHER-128G");
        fs::remove_dir_all(fixture.sources.sys_class_block.join("vda")).unwrap();
        fs::remove_file(fixture.sources.dev_root.join("vda")).unwrap();
        fs::rename(
            fixture.sources.sys_class_block.join("vdb"),
            fixture.sources.sys_class_block.join("vda"),
        )
        .unwrap();
        fs::rename(
            fixture.sources.dev_root.join("vdb"),
            fixture.sources.dev_root.join("vda"),
        )
        .unwrap();
        let disk_path = fixture.sources.dev_root.join("vda");
        let before = first_mib(&disk_path);

        let error = installer.preflight_apply(&apply_params(&plan)).unwrap_err();
        assert!(error.to_string().contains("changed after confirmation"));
        assert_eq!(first_mib(&disk_path), before);
    }

    #[test]
    fn plan_registry_is_bounded_and_evicts_the_oldest_confirmation() {
        let fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        let installer = fixture.installer();
        let mut params = encrypted_params("/dev/vda");
        params.keymap = "layout0".into();
        let first = installer.plan(&params).unwrap();
        let mut newest = first.clone();
        for index in 1..=PLAN_REGISTRY_LIMIT {
            params.keymap = format!("layout{index}");
            newest = installer.plan(&params).unwrap();
        }

        let error = installer
            .preflight_apply(&apply_params(&first))
            .unwrap_err();
        assert!(error.to_string().contains("during this boot"));
        assert_eq!(
            installer.preflight_apply(&apply_params(&newest)).unwrap(),
            newest.plan
        );
    }

    #[test]
    fn apply_preflight_rejects_fields_outside_the_confirmed_plan() {
        let fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        let installer = fixture.installer();
        let plan = installer.plan(&encrypted_params("/dev/vda")).unwrap();

        let mut changed = apply_params(&plan);
        changed.disk = "/dev/vdb".into();
        assert!(installer.preflight_apply(&changed).is_err());
        changed = apply_params(&plan);
        changed.keymap = "de".into();
        assert!(installer.preflight_apply(&changed).is_err());
        changed = apply_params(&plan);
        changed.passphrase_fd = Some(2);
        assert!(installer.preflight_apply(&changed).is_err());
        changed = apply_params(&plan);
        changed.seed.locale = "../../etc".into();
        assert!(installer.preflight_apply(&changed).is_err());
    }

    #[test]
    fn disk_preparation_and_personal_recovery_use_only_anonymous_secret_pipes() {
        use std::os::unix::fs::PermissionsExt;

        const RECOVERY_KEY: &str =
            "lhkbicdj-trbuftjv-tviijfck-dfvbknrh-uiulbhui-higltier-kecfhkbk-egrirkui";
        const LUKS_UUID: &str = "69782a5d-4852-44dc-9b9d-a0c11fd90f5f";
        let mut fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        let definitions = fixture.root.join("repart.d");
        for directory in ["install", "install-encrypted", "install-streaming"] {
            fs::create_dir_all(definitions.join(directory)).unwrap();
        }
        fs::write(
            definitions.join("install/10-esp.conf"),
            "[Partition]\nType=esp\nLabel=PUNAR-ESP\nFormat=vfat\n",
        )
        .unwrap();
        fs::write(
            definitions.join("install/20-root-a.conf"),
            "[Partition]\nType=root\nCopyBlocks=/run/forbidden.raw\n",
        )
        .unwrap();
        fs::write(
            definitions.join("install/50-data.conf"),
            "[Partition]\nType=linux-generic\nFormat=btrfs\n",
        )
        .unwrap();
        fs::write(
            definitions.join("install-encrypted/50-data.conf"),
            "[Partition]\nType=linux-generic\nFormat=btrfs\nEncrypt=key-file\n",
        )
        .unwrap();
        fs::write(
            definitions.join("install-streaming/20-root-a.conf"),
            "[Partition]\nType=root\nLabel=PUNAR-ROOT-A\n",
        )
        .unwrap();

        let capture = fixture.root.join("repart-capture");
        let fake_repart = fixture.root.join("systemd-repart");
        fs::write(
            &fake_repart,
            format!(
                "#!/bin/sh\nset -eu\n\
                 capture='{}'\n\
                 definitions=''\n\
                 : > \"${{capture}}.args\"\n\
                 for argument in \"$@\"; do\n\
                   printf '%s\\n' \"${{argument}}\" >> \"${{capture}}.args\"\n\
                   case \"${{argument}}\" in\n\
                     --definitions=*) definitions=${{argument#--definitions=}} ;;\n\
                   esac\n\
                 done\n\
                 test -n \"${{definitions}}\"\n\
                 cp \"${{definitions}}/20-root-a.conf\" \"${{capture}}.root-a\"\n\
                 cp \"${{definitions}}/50-data.conf\" \"${{capture}}.data\"\n\
                 wc -c > \"${{capture}}.stdin-bytes\"\n",
                capture.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_repart, fs::Permissions::from_mode(0o755)).unwrap();

        let fake_cryptenroll = fixture.root.join("systemd-cryptenroll");
        fs::write(
            &fake_cryptenroll,
            format!(
                "#!/bin/sh\nset -eu\n\
                 capture='{}'\n\
                 : > \"${{capture}}.cryptenroll.args\"\n\
                 for argument in \"$@\"; do\n\
                   printf '%s\\n' \"${{argument}}\" >> \"${{capture}}.cryptenroll.args\"\n\
                 done\n\
                 wc -c > \"${{capture}}.cryptenroll.stdin-bytes\"\n\
                 printf '%s\\n' '{}'\n",
                capture.display(),
                RECOVERY_KEY,
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_cryptenroll, fs::Permissions::from_mode(0o755)).unwrap();

        let fake_cryptsetup = fixture.root.join("cryptsetup");
        fs::write(
            &fake_cryptsetup,
            format!(
                "#!/bin/sh\nset -eu\n\
                 capture='{}'\n\
                 test -e \"${{capture}}.cryptsetup.args\" || : > \"${{capture}}.cryptsetup.args\"\n\
                 for argument in \"$@\"; do\n\
                   printf '%s\\n' \"${{argument}}\" >> \"${{capture}}.cryptsetup.args\"\n\
                 done\n\
                 case \"$1\" in\n\
                   luksDump) printf '%s\\n' '{{\"tokens\":{{\"0\":{{\"type\":\"systemd-recovery\",\"keyslots\":[\"7\"]}}}}}}' ;;\n\
                   luksUUID) printf '%s\\n' '{}' ;;\n\
                   *) exit 2 ;;\n\
                 esac\n",
                capture.display(),
                LUKS_UUID,
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_cryptsetup, fs::Permissions::from_mode(0o755)).unwrap();

        fixture.sources.repart_path = fake_repart;
        fixture.sources.cryptenroll_path = fake_cryptenroll;
        fixture.sources.cryptsetup_path = fake_cryptsetup;
        fixture.sources.repart_definitions_root = definitions;
        fixture.sources.repart_runtime_root = fixture.root.join("runtime");
        fixture.sources.allow_regular_target_for_tests = true;
        let installer = fixture.installer();
        let result = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        installer
            .start_transaction_status(
                &result.plan_token,
                &result.plan.disk.device,
                result.plan.payload.uncompressed_size_bytes,
            )
            .unwrap();
        installer.enter_phase(InstallPhase::Partition).unwrap();
        let secret = b"correct horse battery staple".to_vec();
        let inputs = InstallApplyInputs {
            passphrase: Some(Zeroizing::new(secret.clone())),
            recovery_output: None,
            oobe_answers: None,
        };

        installer
            .prepare_disk_layout(&result.plan, &inputs)
            .unwrap();

        let args = fs::read_to_string(capture.with_extension("args")).unwrap();
        assert!(args.contains("--dry-run=no"));
        assert!(args.contains("--offline=no"));
        assert!(args.contains("--empty=force"));
        assert!(args.contains("--key-file=/dev/stdin"));
        assert!(args.contains(&fixture.sources.dev_root.join("vda").display().to_string()));
        assert!(
            !args
                .as_bytes()
                .windows(secret.len())
                .any(|bytes| bytes == secret)
        );
        assert_eq!(
            fs::read_to_string(capture.with_extension("stdin-bytes"))
                .unwrap()
                .trim()
                .parse::<usize>()
                .unwrap(),
            secret.len()
        );
        assert!(
            !fs::read_to_string(capture.with_extension("root-a"))
                .unwrap()
                .contains("CopyBlocks=")
        );
        assert!(
            fs::read_to_string(capture.with_extension("data"))
                .unwrap()
                .contains("Encrypt=key-file")
        );
        assert_eq!(installer.status().phase, Some(InstallPhase::Encrypt));
        assert!(
            fs::read_dir(&fixture.sources.repart_runtime_root)
                .unwrap()
                .next()
                .is_none()
        );

        File::create(fixture.sources.dev_root.join("vda4")).unwrap();
        let (recovery_key, identity) = installer
            .enroll_recovery_key(&result.plan, &inputs)
            .unwrap();
        assert_eq!(identity.recovery_keyslot, 7);
        assert_eq!(identity.luks_uuid, LUKS_UUID);
        let cryptenroll_args =
            fs::read_to_string(capture.with_extension("cryptenroll.args")).unwrap();
        assert!(cryptenroll_args.contains("--unlock-key-file=/dev/stdin"));
        assert!(cryptenroll_args.contains("--recovery-key"));
        assert!(
            cryptenroll_args.contains(&fixture.sources.dev_root.join("vda4").display().to_string())
        );
        assert!(!cryptenroll_args.contains(std::str::from_utf8(&secret).unwrap()));
        assert_eq!(
            fs::read_to_string(capture.with_extension("cryptenroll.stdin-bytes"))
                .unwrap()
                .trim()
                .parse::<usize>()
                .unwrap(),
            secret.len()
        );
        let cryptsetup_args =
            fs::read_to_string(capture.with_extension("cryptsetup.args")).unwrap();
        assert!(cryptsetup_args.contains("luksDump"));
        assert!(cryptsetup_args.contains("--dump-json-metadata"));
        assert!(cryptsetup_args.contains("luksUUID"));
        assert!(!cryptsetup_args.contains(RECOVERY_KEY));

        let mut challenge = None;
        installer
            .begin_personal_recovery(
                &result.plan_token,
                recovery_key,
                identity.recovery_keyslot,
                |text, groups| {
                    assert_eq!(text, RECOVERY_KEY);
                    challenge = Some(groups);
                    Ok(())
                },
            )
            .unwrap();
        installer
            .await_recovery_status(InstallAwaiting::RecoveryKeyAck)
            .unwrap();
        let groups = challenge.unwrap();
        let key_groups = RECOVERY_KEY.split('-').collect::<Vec<_>>();
        let response = format!(
            "{} {}",
            key_groups[usize::from(groups[0] - 1)],
            key_groups[usize::from(groups[1] - 1)]
        );
        installer
            .acknowledge_personal_recovery_bytes(&result.plan_token, response.as_bytes())
            .unwrap();
        let confirmation = installer
            .wait_for_personal_recovery(&result.plan_token)
            .unwrap();
        assert!(confirmation.confirmed);
        assert_eq!(confirmation.recovery_keyslot, identity.recovery_keyslot);
        installer.resume_recovery_status().unwrap();
        installer.enter_phase(InstallPhase::Format).unwrap();
        installer.enter_phase(InstallPhase::WriteSlotA).unwrap();
        assert_eq!(installer.status().phase, Some(InstallPhase::WriteSlotA));
        let published_status = fs::read_to_string(&fixture.sources.status_path).unwrap();
        assert!(!published_status.contains(RECOVERY_KEY));
        assert!(!published_status.contains(std::str::from_utf8(&secret).unwrap()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn raspberry_pi_disk_preparation_selects_five_partition_base_and_overlays() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = Fixture::new();
        fixture.configure_raspberry_pi();
        fixture.add_disk("vda", 252, 128_000_000_000, "PI-TARGET-128G");
        let definitions = fixture.root.join("repart.d");
        for directory in [
            "install-raspberry-pi",
            "install-encrypted",
            "install-streaming",
        ] {
            fs::create_dir_all(definitions.join(directory)).unwrap();
        }
        for (name, body) in [
            (
                "10-boot-a.conf",
                "[Partition]\nType=esp\nLabel=PUNAR-BOOT-A\n",
            ),
            (
                "20-root-a.conf",
                "[Partition]\nType=root\nLabel=PUNAR-ROOT-A-BASE\n",
            ),
            (
                "30-boot-b.conf",
                "[Partition]\nType=esp\nLabel=PUNAR-BOOT-B\n",
            ),
            (
                "40-root-b.conf",
                "[Partition]\nType=root\nLabel=PUNAR-ROOT-B\n",
            ),
            (
                "50-data.conf",
                "[Partition]\nType=linux-generic\nLabel=PUNAR-DATA-BASE\n",
            ),
        ] {
            fs::write(definitions.join("install-raspberry-pi").join(name), body).unwrap();
        }
        fs::write(
            definitions.join("install-streaming/20-root-a.conf"),
            "[Partition]\nType=root\nLabel=PUNAR-ROOT-A-STREAMED\n",
        )
        .unwrap();
        fs::write(
            definitions.join("install-encrypted/50-data.conf"),
            "[Partition]\nType=linux-generic\nLabel=PUNAR-DATA\nEncrypt=key-file\n",
        )
        .unwrap();

        let capture = fixture.root.join("pi-repart-capture");
        let fake_repart = fixture.root.join("systemd-repart");
        fs::write(
            &fake_repart,
            format!(
                "#!/bin/sh\nset -eu\n\
                 capture='{}'\n\
                 definitions=''\n\
                 for argument in \"$@\"; do\n\
                   case \"${{argument}}\" in --definitions=*) definitions=${{argument#--definitions=}} ;; esac\n\
                 done\n\
                 test -f \"${{definitions}}/10-boot-a.conf\"\n\
                 test -f \"${{definitions}}/30-boot-b.conf\"\n\
                 test -f \"${{definitions}}/40-root-b.conf\"\n\
                 grep -q 'Label=PUNAR-BOOT-A' \"${{definitions}}/10-boot-a.conf\"\n\
                 grep -q 'Label=PUNAR-BOOT-B' \"${{definitions}}/30-boot-b.conf\"\n\
                 grep -q 'Label=PUNAR-ROOT-A-STREAMED' \"${{definitions}}/20-root-a.conf\"\n\
                 grep -q 'Encrypt=key-file' \"${{definitions}}/50-data.conf\"\n\
                 wc -c > \"${{capture}}.stdin-bytes\"\n",
                capture.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_repart, fs::Permissions::from_mode(0o755)).unwrap();
        fixture.sources.repart_path = fake_repart;
        fixture.sources.repart_definitions_root = definitions;
        fixture.sources.repart_runtime_root = fixture.root.join("run-install");
        fixture.sources.allow_regular_target_for_tests = true;

        let installer = fixture.installer();
        let result = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        installer
            .start_transaction_status(
                &result.plan_token,
                &result.plan.disk.device,
                result.plan.payload.uncompressed_size_bytes,
            )
            .unwrap();
        installer.enter_phase(InstallPhase::Partition).unwrap();
        let passphrase = b"correct horse battery staple".to_vec();
        let inputs = InstallApplyInputs {
            passphrase: Some(Zeroizing::new(passphrase.clone())),
            recovery_output: None,
            oobe_answers: None,
        };
        installer
            .prepare_disk_layout(&result.plan, &inputs)
            .unwrap();
        assert_eq!(
            fs::read_to_string(capture.with_extension("stdin-bytes"))
                .unwrap()
                .trim(),
            passphrase.len().to_string()
        );
        assert_eq!(installer.status().phase, Some(InstallPhase::Encrypt));
    }

    #[test]
    fn disk_preparation_rereads_identity_at_the_destructive_boundary() {
        let mut fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        fixture.sources.allow_regular_target_for_tests = true;
        let installer = fixture.installer();
        let result = installer.plan(&encrypted_params("/dev/vda")).unwrap();
        installer
            .start_transaction_status(
                &result.plan_token,
                &result.plan.disk.device,
                result.plan.payload.uncompressed_size_bytes,
            )
            .unwrap();
        installer.enter_phase(InstallPhase::Partition).unwrap();

        let disk = fixture.sources.dev_root.join("vda");
        let mut changed = fs::OpenOptions::new().write(true).open(&disk).unwrap();
        changed.seek(SeekFrom::Start(0)).unwrap();
        changed.write_all(b"changed-after-verify").unwrap();
        changed.sync_all().unwrap();
        drop(changed);
        let before = first_mib(&disk);
        let inputs = InstallApplyInputs {
            passphrase: Some(Zeroizing::new(b"correct horse battery staple".to_vec())),
            recovery_output: None,
            oobe_answers: None,
        };

        let error = installer
            .prepare_disk_layout(&result.plan, &inputs)
            .unwrap_err();
        assert!(error.to_string().contains("destructive boundary"));
        assert_eq!(first_mib(&disk), before);
        assert_eq!(installer.status().phase, Some(InstallPhase::Partition));
    }

    #[test]
    fn foreign_punar_disk_is_refused_but_target_reinstall_is_allowed() {
        let fixture = Fixture::new();
        fixture.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        fixture.add_disk("vdb", 253, 128_000_000_000, "OTHER-128G");
        fixture.add_partition(
            "vdb",
            1,
            253,
            1,
            Some("PUNAR-ESP"),
            Some(ESP_PARTUUID),
            Some("vfat"),
        );
        let error = fixture
            .installer()
            .plan(&encrypted_params("/dev/vda"))
            .unwrap_err();
        assert!(error.to_string().contains("/dev/vdb"));

        let reinstall = Fixture::new();
        reinstall.add_disk("vda", 252, 128_000_000_000, "TARGET-128G");
        reinstall.add_partition(
            "vda",
            4,
            252,
            4,
            Some("PUNAR-DATA"),
            Some(DATA_PARTUUID),
            Some("crypto_LUKS"),
        );
        let result = reinstall
            .installer()
            .plan(&encrypted_params("/dev/vda"))
            .unwrap();
        assert!(
            result
                .plan
                .warnings
                .iter()
                .any(|warning| warning.contains("already contains"))
        );
    }
}
