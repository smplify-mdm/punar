//! Installer discovery, destructive-plan construction, bounded secret intake,
//! and secret-free status reporting.
//!
//! Nothing in this module writes a block device yet. The public
//! `install.apply` method stays absent until the fixed transaction can carry a
//! verified plan through partition, encrypt, write, re-read, boot, and seed.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};

use punar_common::install::{
    InstallApplyParams, InstallAwaiting, InstallDiskIdentity, InstallEncryption, InstallFailure,
    InstallOverallState, InstallPartitionPlan, InstallPayloadPlan, InstallPhase, InstallPhaseState,
    InstallPlan, InstallPlanParams, InstallPlanResult, InstallRecoveryAckParams,
    InstallRecoveryMode, InstallStatusResult, InstallTarget, InstallTargetPartition,
    InstallTargetsResult, canonical_json,
};
use punar_common::update::{
    Architecture, BootPlatform, ReleaseKeySet, ReleaseManifest, verify_release_manifest,
};
use punar_recovery::{PersonalRecoveryConfirmation, PersonalRecoveryView, SecretRecoveryKey};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::util::{sha256_hex, write_atomic};

pub const ESP_PARTUUID: &str = "8bb56554-b5f1-4058-90ac-8dc91a8e2bd4";
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

const PUNAR_PARTUUIDS: [&str; 4] = [
    ESP_PARTUUID,
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
    /// Test-only seam. Production always verifies exact manifest bytes
    /// against `release_keys_dir` and leaves this `None`.
    pub release_manifest_override: Option<ReleaseManifest>,
    /// Cross-architecture test seam; production derives the compiled target.
    pub architecture_override: Option<Architecture>,
    /// Raspberry Pi media selects this explicitly when its live profile is
    /// assembled. UEFI is the production default for the current ISO.
    pub boot_platform_override: Option<BootPlatform>,
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
            release_manifest_override: None,
            architecture_override: None,
            boot_platform_override: None,
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
        })
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
            self.cancel_personal_recovery(&plan_token);
        }
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
            minimum_disk_bytes: minimum_disk_bytes(512),
            targets,
        })
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
            params.encryption,
        )?;

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

    /// Abandon an active checkpoint on transaction failure. Dropping the
    /// view zeroizes the only in-memory owner of the recovery key.
    pub fn cancel_personal_recovery(&self, plan_token: &str) {
        let mut state = self.recovery.state.lock().unwrap();
        let matches = match &*state {
            RecoveryGateState::Personal {
                plan_token: expected,
                ..
            }
            | RecoveryGateState::Confirmed {
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

            let required = minimum_disk_bytes(logical_sector_bytes);
            let ineligible_reason = if read_only {
                Some("the disk is read-only".to_string())
            } else if size_bytes < required {
                Some(format!(
                    "Punar needs 33 GiB plus partition metadata ({required} bytes), and this disk has {size_bytes} bytes. 17 GiB is the operating system and its rollback copy; 16 GiB is the floor for user data."
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
    file.by_ref()
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
        InstallError::Trust(_) => "release signature or manifest verification failed",
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
    let root_b = root_a + ROOT_SIZE;
    let data = root_b + ROOT_SIZE;
    let data_size = usable_end.checked_sub(data).ok_or_else(|| {
        InstallError::Refused("disk is too small for Punar's fixed A/B layout".into())
    })?;
    if data_size < DATA_MINIMUM {
        return Err(InstallError::Refused(format!(
            "Punar needs 33 GiB plus partition metadata ({} bytes), and this disk has {disk_bytes} bytes. 17 GiB is the operating system and its rollback copy; 16 GiB is the floor for user data.",
            minimum_disk_bytes(sector_bytes)
        )));
    }
    let root_type = match architecture {
        Architecture::X86_64 => X86_ROOT_TYPE_GUID,
        Architecture::Aarch64 => ARM_ROOT_TYPE_GUID,
    };
    Ok((
        vec![
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
        data_size,
    ))
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

fn minimum_disk_bytes(sector_bytes: u64) -> u64 {
    let start = align_up(GPT_LBAS * sector_bytes, ALIGNMENT).unwrap_or(ALIGNMENT);
    start.saturating_add(ESP_SIZE + 2 * ROOT_SIZE + DATA_MINIMUM + GPT_LBAS * sector_bytes)
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

    fn first_mib(path: &Path) -> Vec<u8> {
        let mut bytes = vec![0_u8; 1024 * 1024];
        File::open(path).unwrap().read_exact(&mut bytes).unwrap();
        bytes
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
        installer.cancel_personal_recovery(&token);
        assert!(installer.wait_for_personal_recovery(&token).is_err());
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
        let (partitions, data) =
            partition_plan(size, 512, Architecture::X86_64, InstallEncryption::Luks2).unwrap();
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
        let minimum = minimum_disk_bytes(512);
        assert!(
            partition_plan(
                minimum - 1,
                512,
                Architecture::Aarch64,
                InstallEncryption::None
            )
            .is_err()
        );
        let (parts, _) =
            partition_plan(minimum, 512, Architecture::Aarch64, InstallEncryption::None).unwrap();
        assert_eq!(parts[1].type_guid, ARM_ROOT_TYPE_GUID);
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
        assert_eq!(
            first.plan.payload.uncompressed_digest_sha256,
            "4444444444444444444444444444444444444444444444444444444444444444"
        );

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
