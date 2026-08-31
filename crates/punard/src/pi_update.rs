//! Native Raspberry Pi inactive-slot update transaction.
//!
//! This module is deliberately narrower than a generic disk writer. Release
//! metadata chooses filenames, fixed PARTUUIDs choose destinations, and the
//! firmware's read-only device-tree facts choose the inactive slot. No caller
//! supplies a block-device path or command line.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use punar_common::update::{
    ReleaseKeySet, ReleaseManifest, ReleaseTarget, ReleaseVersion, verify_reader,
    verify_release_manifest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::install::{
    InstallError, PI_BOOT_A_PARTUUID, PI_BOOT_B_PARTUUID, ROOT_A_PARTUUID, ROOT_B_PARTUUID,
    digest_installed_partition, stream_exact_payload, validate_raspberry_pi_autoboot,
    validate_raspberry_pi_boot_filesystem,
};
use crate::util::{sha256_hex, write_atomic_synced};

const DEVICE_TREE_BOOT_PARTITION: &str = "/proc/device-tree/chosen/bootloader/partition";
const DEVICE_TREE_TRYBOOT: &str = "/proc/device-tree/chosen/bootloader/tryboot";
const PI_SELECTOR_PARTITION: u32 = 1;
const PI_AUTOBOOT_MAX_BYTES: u64 = 512;
const PI_HEALTH_REPORT_MAX_BYTES: u64 = 64 * 1024;
const PI_MOUNTINFO_MAX_BYTES: u64 = 4 * 1024 * 1024;
const PI_CMDLINE_MAX_BYTES: u64 = 64 * 1024;
const RELEASE_DOCUMENT_MAX_BYTES: u64 = 1024 * 1024;
const RELEASE_SIGNATURE_BYTES: u64 = 64;

#[derive(Debug, Error)]
pub enum PiUpdateError {
    #[error("Raspberry Pi update I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Raspberry Pi update trust check failed: {0}")]
    Trust(String),
    #[error("Raspberry Pi update input is invalid: {0}")]
    Invalid(String),
    #[error("Raspberry Pi update was refused: {0}")]
    Refused(String),
    #[error("Raspberry Pi update conflicts with device state: {0}")]
    Conflict(String),
    #[error(transparent)]
    Install(#[from] InstallError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiSlot {
    A,
    B,
}

impl PiSlot {
    pub fn from_boot_partition(partition: u32) -> Result<Self, PiUpdateError> {
        match partition {
            2 => Ok(Self::A),
            4 => Ok(Self::B),
            other => Err(PiUpdateError::Refused(format!(
                "firmware reported unsupported boot partition {other}; expected 2 or 4"
            ))),
        }
    }

    pub fn inactive(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    pub fn boot_partition(self) -> u32 {
        match self {
            Self::A => 2,
            Self::B => 4,
        }
    }

    pub fn root_partition(self) -> u32 {
        match self {
            Self::A => 3,
            Self::B => 5,
        }
    }

    pub fn boot_partuuid(self) -> &'static str {
        match self {
            Self::A => PI_BOOT_A_PARTUUID,
            Self::B => PI_BOOT_B_PARTUUID,
        }
    }

    pub fn root_partuuid(self) -> &'static str {
        match self {
            Self::A => ROOT_A_PARTUUID,
            Self::B => ROOT_B_PARTUUID,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PiBootObservation {
    pub slot: PiSlot,
    pub tryboot: bool,
}

impl PiBootObservation {
    pub fn read(partition_path: &Path, tryboot_path: &Path) -> Result<Self, PiUpdateError> {
        let partition = read_device_tree_u32(partition_path, false)?.ok_or_else(|| {
            PiUpdateError::Refused("firmware did not report a boot partition".into())
        })?;
        let tryboot = match read_device_tree_u32(tryboot_path, true)? {
            None | Some(0) => false,
            Some(1) => true,
            Some(other) => {
                return Err(PiUpdateError::Refused(format!(
                    "firmware reported invalid tryboot value {other}"
                )));
            }
        };
        Ok(Self {
            slot: PiSlot::from_boot_partition(partition)?,
            tryboot,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PiUpdateSources {
    pub boot_partition_property: PathBuf,
    pub tryboot_property: PathBuf,
    pub cmdline_path: PathBuf,
    pub mountinfo_path: PathBuf,
    pub health_report: PathBuf,
    pub selector_partition: PathBuf,
    pub boot_a_partition: PathBuf,
    pub root_a_partition: PathBuf,
    pub boot_b_partition: PathBuf,
    pub root_b_partition: PathBuf,
    pub mount_root: PathBuf,
    pub pending_state: PathBuf,
    pub zstd_path: PathBuf,
    #[cfg(test)]
    pub allow_regular_targets: bool,
    #[cfg(test)]
    pub selector_mount_override: Option<PathBuf>,
    #[cfg(test)]
    pub boot_a_mount_override: Option<PathBuf>,
    #[cfg(test)]
    pub boot_b_mount_override: Option<PathBuf>,
}

impl Default for PiUpdateSources {
    fn default() -> Self {
        let by_partuuid = Path::new("/dev/disk/by-partuuid");
        Self {
            boot_partition_property: PathBuf::from(DEVICE_TREE_BOOT_PARTITION),
            tryboot_property: PathBuf::from(DEVICE_TREE_TRYBOOT),
            cmdline_path: PathBuf::from("/proc/cmdline"),
            mountinfo_path: PathBuf::from("/proc/self/mountinfo"),
            health_report: PathBuf::from("/run/punar/update-health.json"),
            selector_partition: by_partuuid.join(crate::install::PI_SELECTOR_PARTUUID),
            boot_a_partition: by_partuuid.join(PI_BOOT_A_PARTUUID),
            root_a_partition: by_partuuid.join(ROOT_A_PARTUUID),
            boot_b_partition: by_partuuid.join(PI_BOOT_B_PARTUUID),
            root_b_partition: by_partuuid.join(ROOT_B_PARTUUID),
            mount_root: PathBuf::from("/run/punard/pi-update"),
            pending_state: PathBuf::from("/var/lib/punar/update/pending-pi.json"),
            zstd_path: PathBuf::from("/usr/bin/zstd"),
            #[cfg(test)]
            allow_regular_targets: false,
            #[cfg(test)]
            selector_mount_override: None,
            #[cfg(test)]
            boot_a_mount_override: None,
            #[cfg(test)]
            boot_b_mount_override: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingPiUpdate {
    pub schema_version: u8,
    pub release_id: String,
    pub version: ReleaseVersion,
    pub previous_slot: PiSlot,
    pub candidate_slot: PiSlot,
    pub candidate_boot_partition: u32,
    pub candidate_root_partition: u32,
    pub candidate_root_partuuid: String,
    pub manifest_sha256: String,
    pub payload_sha256: String,
    pub boot_sha256: String,
    pub staged_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PiStageResult {
    pub release_id: String,
    pub version: ReleaseVersion,
    pub previous_slot: PiSlot,
    pub staged_slot: PiSlot,
    pub bytes_written: u64,
    pub verified: bool,
    pub requires_tryboot_reboot: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PiCommitResult {
    pub version: ReleaseVersion,
    pub blessed_slot: PiSlot,
    pub previous_slot: PiSlot,
    pub selector_committed: bool,
    pub requires_normal_reboot: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PiHealthReport {
    schema_version: u8,
    health: PiHealthSignals,
    waited_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PiHealthSignals {
    boot_completed: bool,
    control_plane_answers: bool,
    desktop_ready: bool,
    capabilities_verified: bool,
}

pub struct PiUpdateEngine {
    sources: PiUpdateSources,
}

impl PiUpdateEngine {
    pub fn new(sources: PiUpdateSources) -> Self {
        Self { sources }
    }

    /// Verify an exact signed bundle before touching either inactive
    /// partition, then stream, fsync, physically re-read, and validate the
    /// boot/root pair. The selector is re-read but never changed here.
    #[cfg(target_os = "linux")]
    pub fn stage_bundle(
        &self,
        release_dir: &Path,
        trusted_key_dir: &Path,
        target: &ReleaseTarget,
        current: ReleaseVersion,
    ) -> Result<PiStageResult, PiUpdateError> {
        if self.sources.pending_state.exists() {
            return Err(PiUpdateError::Conflict(
                "another Raspberry Pi update is already pending".into(),
            ));
        }
        let observation = PiBootObservation::read(
            &self.sources.boot_partition_property,
            &self.sources.tryboot_property,
        )?;
        if observation.tryboot {
            return Err(PiUpdateError::Conflict(
                "the device is already running a one-shot tryboot candidate".into(),
            ));
        }
        let candidate = observation.slot.inactive();
        self.verify_selector(observation.slot, candidate)?;

        let (manifest, manifest_bytes) = load_verified_manifest(release_dir, trusted_key_dir)?;
        manifest
            .admit(target, current, false)
            .map_err(|error| PiUpdateError::Trust(error.to_string()))?;
        let payload_path = release_dir.join(&manifest.payload.filename);
        let boot_path = release_dir.join(&manifest.boot_artifact.filename);
        verify_artifact(
            &payload_path,
            &manifest.payload.digest_sha256,
            manifest.payload.size_bytes,
            "compressed root payload",
        )?;
        verify_artifact(
            &boot_path,
            &manifest.boot_artifact.digest_sha256,
            manifest.boot_artifact.size_bytes,
            "Raspberry Pi boot artifact",
        )?;

        let root_target =
            resolved_partition_path(self.root_target(candidate), self.allow_regular_targets())?;
        let boot_target =
            resolved_partition_path(self.boot_target(candidate), self.allow_regular_targets())?;
        verify_target_capacity(
            &root_target,
            manifest.payload.uncompressed_size_bytes,
            self.allow_regular_targets(),
            "inactive root slot",
        )?;
        verify_target_capacity(
            &boot_target,
            manifest.boot_artifact.size_bytes,
            self.allow_regular_targets(),
            "inactive boot slot",
        )?;

        self.write_root_payload(&payload_path, &root_target, &manifest)?;
        digest_installed_partition(
            &root_target,
            manifest.payload.uncompressed_size_bytes,
            &manifest.payload.uncompressed_digest_sha256,
            self.allow_regular_targets(),
            "inactive Raspberry Pi root slot",
        )?;
        copy_exact_artifact(
            &boot_path,
            &boot_target,
            manifest.boot_artifact.size_bytes,
            &manifest.boot_artifact.digest_sha256,
            self.allow_regular_targets(),
        )?;
        digest_installed_partition(
            &boot_target,
            manifest.boot_artifact.size_bytes,
            &manifest.boot_artifact.digest_sha256,
            self.allow_regular_targets(),
            "inactive Raspberry Pi boot slot",
        )?;
        self.verify_boot_filesystem(candidate)?;
        self.verify_selector(observation.slot, candidate)?;

        let pending = PendingPiUpdate {
            schema_version: 1,
            release_id: manifest.release_id.clone(),
            version: manifest.version,
            previous_slot: observation.slot,
            candidate_slot: candidate,
            candidate_boot_partition: candidate.boot_partition(),
            candidate_root_partition: candidate.root_partition(),
            candidate_root_partuuid: candidate.root_partuuid().to_string(),
            manifest_sha256: sha256_hex(&manifest_bytes),
            payload_sha256: manifest.payload.uncompressed_digest_sha256.clone(),
            boot_sha256: manifest.boot_artifact.digest_sha256.clone(),
            staged_at: punar_common::time::utc_now_rfc3339(),
        };
        let pending_bytes = serde_json::to_vec_pretty(&pending)
            .map_err(|error| PiUpdateError::Invalid(error.to_string()))?;
        if let Some(parent) = self.sources.pending_state.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        }
        write_atomic_synced(&self.sources.pending_state, &pending_bytes, 0o600)?;

        Ok(PiStageResult {
            release_id: manifest.release_id,
            version: manifest.version,
            previous_slot: observation.slot,
            staged_slot: candidate,
            bytes_written: manifest
                .payload
                .uncompressed_size_bytes
                .checked_add(manifest.boot_artifact.size_bytes)
                .ok_or_else(|| PiUpdateError::Invalid("written byte count overflow".into()))?,
            verified: true,
            requires_tryboot_reboot: true,
        })
    }

    /// Bless a one-shot candidate only after firmware, root pairing and the
    /// on-device health report all agree with the durable pending record.
    /// A normal boot, a read-write root, or a partial health result can never
    /// reach the selector write.
    #[cfg(target_os = "linux")]
    pub fn commit_candidate(&self) -> Result<PiCommitResult, PiUpdateError> {
        let pending_bytes = read_bounded(
            &self.sources.pending_state,
            RELEASE_DOCUMENT_MAX_BYTES,
            "pending Raspberry Pi update state",
        )?;
        let pending: PendingPiUpdate = serde_json::from_slice(&pending_bytes)
            .map_err(|error| PiUpdateError::Trust(error.to_string()))?;
        validate_pending_state(&pending)?;

        let observation = PiBootObservation::read(
            &self.sources.boot_partition_property,
            &self.sources.tryboot_property,
        )?;
        if !observation.tryboot || observation.slot != pending.candidate_slot {
            return Err(PiUpdateError::Conflict(
                "the running firmware state is not the pending tryboot candidate".into(),
            ));
        }
        validate_running_root(
            &self.sources.cmdline_path,
            &self.sources.mountinfo_path,
            pending.candidate_slot,
        )?;
        validate_health_report(&self.sources.health_report)?;
        self.verify_boot_filesystem(pending.candidate_slot)?;

        let mounted = self.mount_selector(false)?;
        let autoboot_path = mounted.path.join("autoboot.txt");
        let previous = read_small_regular(
            &autoboot_path,
            PI_AUTOBOOT_MAX_BYTES,
            "Raspberry Pi selector",
        )?;
        let selector_is_uncommitted = validate_raspberry_pi_autoboot(
            &previous,
            u8::try_from(pending.previous_slot.boot_partition()).expect("Pi partition fits u8"),
            u8::try_from(pending.candidate_slot.boot_partition()).expect("Pi partition fits u8"),
        )
        .is_ok();
        if !selector_is_uncommitted {
            validate_raspberry_pi_autoboot(
                &previous,
                u8::try_from(pending.candidate_slot.boot_partition())
                    .expect("Pi partition fits u8"),
                u8::try_from(pending.previous_slot.boot_partition()).expect("Pi partition fits u8"),
            )?;
            let backup = read_small_regular(
                &mounted.path.join("autoboot.previous"),
                PI_AUTOBOOT_MAX_BYTES,
                "previous Raspberry Pi selector",
            )?;
            validate_raspberry_pi_autoboot(
                &backup,
                u8::try_from(pending.previous_slot.boot_partition()).expect("Pi partition fits u8"),
                u8::try_from(pending.candidate_slot.boot_partition())
                    .expect("Pi partition fits u8"),
            )?;
            mounted.finish()?;
            self.remove_pending_state()?;
            return Ok(PiCommitResult {
                version: pending.version,
                blessed_slot: pending.candidate_slot,
                previous_slot: pending.previous_slot,
                selector_committed: true,
                requires_normal_reboot: true,
            });
        }

        // Keep a separately verified prior selector before replacing the
        // active file. FAT rename durability still requires the physical
        // power-loss gate in ADR-006; this copy makes recovery possible
        // without pretending the filesystem is transactional.
        let previous_path = mounted.path.join("autoboot.previous");
        write_atomic_synced(&previous_path, &previous, 0o600)?;
        sync_filesystem(&mounted.path)?;
        let previous_reread = read_small_regular(
            &previous_path,
            PI_AUTOBOOT_MAX_BYTES,
            "previous Raspberry Pi selector",
        )?;
        if previous_reread != previous {
            return Err(PiUpdateError::Trust(
                "the previous Raspberry Pi selector changed after its durable write".into(),
            ));
        }
        validate_raspberry_pi_autoboot(
            &previous_reread,
            u8::try_from(pending.previous_slot.boot_partition()).expect("Pi partition fits u8"),
            u8::try_from(pending.candidate_slot.boot_partition()).expect("Pi partition fits u8"),
        )?;
        let committed = canonical_autoboot(pending.candidate_slot, pending.previous_slot);
        write_atomic_synced(&autoboot_path, &committed, 0o600)?;
        let reread = read_small_regular(
            &autoboot_path,
            PI_AUTOBOOT_MAX_BYTES,
            "committed Raspberry Pi selector",
        )?;
        validate_raspberry_pi_autoboot(
            &reread,
            u8::try_from(pending.candidate_slot.boot_partition()).expect("Pi partition fits u8"),
            u8::try_from(pending.previous_slot.boot_partition()).expect("Pi partition fits u8"),
        )?;
        sync_filesystem(&mounted.path)?;
        mounted.finish()?;

        self.remove_pending_state()?;
        Ok(PiCommitResult {
            version: pending.version,
            blessed_slot: pending.candidate_slot,
            previous_slot: pending.previous_slot,
            selector_committed: true,
            requires_normal_reboot: true,
        })
    }

    fn remove_pending_state(&self) -> Result<(), PiUpdateError> {
        fs::remove_file(&self.sources.pending_state)?;
        if let Some(parent) = self.sources.pending_state.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn write_root_payload(
        &self,
        payload_path: &Path,
        root_target: &Path,
        manifest: &ReleaseManifest,
    ) -> Result<(), PiUpdateError> {
        let payload = open_regular_nofollow(payload_path, "compressed root payload")?;
        let mut destination = open_partition_for_write(
            root_target,
            self.allow_regular_targets(),
            "inactive root slot",
        )?;
        let mut child = Command::new(&self.sources.zstd_path)
            .args(["-dc", "--"])
            .stdin(Stdio::from(payload))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut output = child.stdout.take().ok_or_else(|| {
            PiUpdateError::Io(std::io::Error::other(
                "zstd did not provide its fixed output pipe",
            ))
        })?;
        let copied = stream_exact_payload(
            &mut output,
            &mut destination,
            manifest.payload.uncompressed_size_bytes,
            &manifest.payload.uncompressed_digest_sha256,
            |_| Ok(()),
        );
        drop(output);
        if let Err(error) = copied {
            let _ = child.kill();
            let _ = child.wait();
            let _ = destination.sync_all();
            return Err(error.into());
        }
        if !child.wait()?.success() {
            return Err(PiUpdateError::Trust(
                "zstd refused the signed root payload".into(),
            ));
        }
        destination.sync_all()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_selector(&self, current: PiSlot, candidate: PiSlot) -> Result<(), PiUpdateError> {
        let mounted = self.mount_selector(true)?;
        let bytes = read_small_regular(
            &mounted.path.join("autoboot.txt"),
            PI_AUTOBOOT_MAX_BYTES,
            "Raspberry Pi selector",
        )?;
        validate_raspberry_pi_autoboot(
            &bytes,
            u8::try_from(current.boot_partition()).expect("Pi partition fits u8"),
            u8::try_from(candidate.boot_partition()).expect("Pi partition fits u8"),
        )?;
        mounted.finish()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_boot_filesystem(&self, slot: PiSlot) -> Result<(), PiUpdateError> {
        let mounted = self.mount_boot(slot, true)?;
        validate_raspberry_pi_boot_filesystem(&mounted.path)?;
        mounted.finish()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn mount_selector(&self, read_only: bool) -> Result<MountedPiFs, PiUpdateError> {
        #[cfg(test)]
        if let Some(path) = &self.sources.selector_mount_override {
            return MountedPiFs::borrowed(path);
        }
        self.mount_partition(
            &self.sources.selector_partition,
            format!("selector-{PI_SELECTOR_PARTITION}"),
            read_only,
        )
    }

    #[cfg(target_os = "linux")]
    fn mount_boot(&self, slot: PiSlot, read_only: bool) -> Result<MountedPiFs, PiUpdateError> {
        #[cfg(test)]
        {
            let override_path = match slot {
                PiSlot::A => &self.sources.boot_a_mount_override,
                PiSlot::B => &self.sources.boot_b_mount_override,
            };
            if let Some(path) = override_path {
                return MountedPiFs::borrowed(path);
            }
        }
        self.mount_partition(
            self.boot_target(slot),
            format!("boot-{}", slot.boot_partition()),
            read_only,
        )
    }

    #[cfg(target_os = "linux")]
    fn mount_partition(
        &self,
        source: &Path,
        name: String,
        read_only: bool,
    ) -> Result<MountedPiFs, PiUpdateError> {
        let path = self.sources.mount_root.join(name);
        fs::create_dir_all(&path)?;
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        let mut flags = rustix::mount::MountFlags::NODEV
            | rustix::mount::MountFlags::NOSUID
            | rustix::mount::MountFlags::NOEXEC
            | rustix::mount::MountFlags::NOSYMFOLLOW;
        if read_only {
            flags |= rustix::mount::MountFlags::RDONLY;
        }
        if let Err(error) = rustix::mount::mount(source, &path, "vfat", flags, Some(c"umask=0077"))
        {
            let _ = fs::remove_dir(&path);
            return Err(PiUpdateError::Io(error.into()));
        }
        Ok(MountedPiFs { path, owned: true })
    }

    fn boot_target(&self, slot: PiSlot) -> &Path {
        match slot {
            PiSlot::A => &self.sources.boot_a_partition,
            PiSlot::B => &self.sources.boot_b_partition,
        }
    }

    fn root_target(&self, slot: PiSlot) -> &Path {
        match slot {
            PiSlot::A => &self.sources.root_a_partition,
            PiSlot::B => &self.sources.root_b_partition,
        }
    }

    fn allow_regular_targets(&self) -> bool {
        #[cfg(test)]
        {
            self.sources.allow_regular_targets
        }
        #[cfg(not(test))]
        {
            false
        }
    }
}

#[cfg(target_os = "linux")]
struct MountedPiFs {
    path: PathBuf,
    owned: bool,
}

#[cfg(target_os = "linux")]
impl MountedPiFs {
    #[cfg(test)]
    fn borrowed(path: &Path) -> Result<Self, PiUpdateError> {
        if !fs::symlink_metadata(path)?.file_type().is_dir() {
            return Err(PiUpdateError::Refused(
                "test mount override is not a directory".into(),
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            owned: false,
        })
    }

    fn finish(mut self) -> Result<(), PiUpdateError> {
        if self.owned {
            rustix::mount::unmount(&self.path, rustix::mount::UnmountFlags::empty())
                .map_err(|error| PiUpdateError::Io(error.into()))?;
            fs::remove_dir(&self.path)?;
            self.owned = false;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for MountedPiFs {
    fn drop(&mut self) {
        if self.owned {
            let _ = rustix::mount::unmount(&self.path, rustix::mount::UnmountFlags::DETACH);
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn read_device_tree_u32(path: &Path, optional: bool) -> Result<Option<u32>, PiUpdateError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let value: [u8; 4] = bytes.try_into().map_err(|_| {
        PiUpdateError::Refused(format!(
            "device-tree property {} is not one big-endian u32",
            path.display()
        ))
    })?;
    Ok(Some(u32::from_be_bytes(value)))
}

fn canonical_autoboot(normal: PiSlot, try_slot: PiSlot) -> Vec<u8> {
    format!(
        "[all]\ntryboot_a_b=1\nboot_partition={}\n[tryboot]\nboot_partition={}\n",
        normal.boot_partition(),
        try_slot.boot_partition()
    )
    .into_bytes()
}

fn validate_pending_state(pending: &PendingPiUpdate) -> Result<(), PiUpdateError> {
    if pending.schema_version != 1
        || pending.previous_slot == pending.candidate_slot
        || pending.previous_slot.inactive() != pending.candidate_slot
        || pending.candidate_boot_partition != pending.candidate_slot.boot_partition()
        || pending.candidate_root_partition != pending.candidate_slot.root_partition()
        || pending.candidate_root_partuuid != pending.candidate_slot.root_partuuid()
        || !is_sha256(&pending.manifest_sha256)
        || !is_sha256(&pending.payload_sha256)
        || !is_sha256(&pending.boot_sha256)
        || punar_common::time::unix_seconds_from_rfc3339(&pending.staged_at).is_none()
    {
        return Err(PiUpdateError::Trust(
            "pending Raspberry Pi update state is internally inconsistent".into(),
        ));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_running_root(
    cmdline_path: &Path,
    mountinfo_path: &Path,
    candidate: PiSlot,
) -> Result<(), PiUpdateError> {
    let cmdline = read_bounded(cmdline_path, PI_CMDLINE_MAX_BYTES, "kernel command line")?;
    let cmdline = std::str::from_utf8(&cmdline)
        .map_err(|_| PiUpdateError::Trust("kernel command line is not UTF-8".into()))?;
    let expected_root = format!("root=PARTUUID={}", candidate.root_partuuid());
    let roots = cmdline
        .split_ascii_whitespace()
        .filter(|token| token.starts_with("root="))
        .collect::<Vec<_>>();
    if roots.as_slice() != [expected_root.as_str()]
        || !cmdline.split_ascii_whitespace().any(|token| token == "ro")
    {
        return Err(PiUpdateError::Trust(
            "the running kernel is not bound read-only to the pending root slot".into(),
        ));
    }

    let mountinfo = read_bounded(
        mountinfo_path,
        PI_MOUNTINFO_MAX_BYTES,
        "process mount table",
    )?;
    let mountinfo = std::str::from_utf8(&mountinfo)
        .map_err(|_| PiUpdateError::Trust("process mount table is not UTF-8".into()))?;
    let root = mountinfo.lines().find_map(|line| {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        (fields.len() > 5 && fields[4] == "/").then_some(fields[5])
    });
    if !root.is_some_and(|options| options.split(',').any(|option| option == "ro")) {
        return Err(PiUpdateError::Trust(
            "the pending root filesystem is not mounted read-only".into(),
        ));
    }
    Ok(())
}

fn validate_health_report(path: &Path) -> Result<(), PiUpdateError> {
    let bytes = read_bounded(path, PI_HEALTH_REPORT_MAX_BYTES, "update health report")?;
    let report: PiHealthReport =
        serde_json::from_slice(&bytes).map_err(|error| PiUpdateError::Trust(error.to_string()))?;
    let _ = report.waited_seconds;
    if report.schema_version != 1
        || !report.health.boot_completed
        || !report.health.control_plane_answers
        || !report.health.desktop_ready
        || !report.health.capabilities_verified
    {
        return Err(PiUpdateError::Refused(
            "the tryboot candidate has not passed every required health signal".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sync_filesystem(path: &Path) -> Result<(), PiUpdateError> {
    let filesystem = File::open(path)?;
    rustix::fs::syncfs(&filesystem).map_err(|error| PiUpdateError::Io(error.into()))?;
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64, description: &str) -> Result<Vec<u8>, PiUpdateError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(PiUpdateError::Refused(format!(
            "{description} is not a bounded regular file"
        )));
    }
    let file = open_regular_nofollow(path, description)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(PiUpdateError::Refused(format!(
            "{description} grew beyond its byte limit while it was read"
        )));
    }
    if bytes.len() as u64 != metadata.len() {
        return Err(PiUpdateError::Trust(format!(
            "{description} changed while it was read"
        )));
    }
    Ok(bytes)
}

fn read_small_regular(
    path: &Path,
    maximum: u64,
    description: &str,
) -> Result<Vec<u8>, PiUpdateError> {
    read_bounded(path, maximum, description)
}

fn load_verified_manifest(
    release_dir: &Path,
    trusted_key_dir: &Path,
) -> Result<(ReleaseManifest, Vec<u8>), PiUpdateError> {
    let document = read_bounded(
        &release_dir.join("release.json"),
        RELEASE_DOCUMENT_MAX_BYTES,
        "release manifest",
    )?;
    let signature = read_bounded(
        &release_dir.join("release.json.sig"),
        RELEASE_SIGNATURE_BYTES,
        "release signature",
    )?;
    if signature.len() as u64 != RELEASE_SIGNATURE_BYTES {
        return Err(PiUpdateError::Trust(
            "release signature is not exactly 64 bytes".into(),
        ));
    }
    let keys = ReleaseKeySet::load_dir(trusted_key_dir)
        .map_err(|error| PiUpdateError::Trust(error.to_string()))?;
    let manifest = verify_release_manifest(&document, &signature, &keys)
        .map_err(|error| PiUpdateError::Trust(error.to_string()))?;
    Ok((manifest, document))
}

fn verify_artifact(
    path: &Path,
    digest: &str,
    size: u64,
    description: &str,
) -> Result<(), PiUpdateError> {
    let mut file = open_regular_nofollow(path, description)?;
    verify_reader(&mut file, digest, size).map_err(|error| PiUpdateError::Trust(error.to_string()))
}

#[cfg(target_os = "linux")]
fn open_regular_nofollow(path: &Path, description: &str) -> Result<File, PiUpdateError> {
    use std::os::unix::fs::OpenOptionsExt;

    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(flags.bits()).expect("open flags fit libc::c_int"))
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(PiUpdateError::Refused(format!(
            "{description} is not a regular file"
        )));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn resolved_partition_path(path: &Path, allow_regular: bool) -> Result<PathBuf, PiUpdateError> {
    if allow_regular {
        Ok(path.to_path_buf())
    } else {
        fs::canonicalize(path).map_err(PiUpdateError::Io)
    }
}

#[cfg(target_os = "linux")]
fn verify_target_capacity(
    path: &Path,
    required: u64,
    allow_regular: bool,
    description: &str,
) -> Result<(), PiUpdateError> {
    let mut file = open_partition_for_write(path, allow_regular, description)?;
    let capacity = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;
    if required == 0 || capacity < required {
        return Err(PiUpdateError::Refused(format!(
            "{description} is too small: requires {required} bytes, has {capacity}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_partition_for_write(
    path: &Path,
    allow_regular: bool,
    description: &str,
) -> Result<File, PiUpdateError> {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};

    let resolved = if allow_regular {
        path.to_path_buf()
    } else {
        fs::canonicalize(path)?
    };
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(i32::try_from(flags.bits()).expect("open flags fit libc::c_int"))
        .open(&resolved)?;
    let file_type = file.metadata()?.file_type();
    if !(file_type.is_block_device() || allow_regular && file_type.is_file()) {
        return Err(PiUpdateError::Refused(format!(
            "{description} is not a block device"
        )));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn copy_exact_artifact(
    source: &Path,
    destination: &Path,
    size: u64,
    digest: &str,
    allow_regular: bool,
) -> Result<(), PiUpdateError> {
    let mut source = open_regular_nofollow(source, "Raspberry Pi boot artifact")?;
    let mut destination =
        open_partition_for_write(destination, allow_regular, "inactive boot slot")?;
    destination.seek(SeekFrom::Start(0))?;
    stream_exact_payload(&mut source, &mut destination, size, digest, |_| Ok(()))?;
    destination.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use punar_common::update::{
        Architecture, BootArtifact, BootArtifactKind, PayloadArtifact, ReleaseProvenance,
        ReleaseSecurity, SecuritySeverity, UpdateChannel,
    };
    use std::os::unix::fs::PermissionsExt;

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "punar-{name}-{}-{}",
            std::process::id(),
            punar_common::time::unix_now_millis()
        ))
    }

    fn write_boot_fixture(root: &Path) {
        fs::create_dir_all(root).unwrap();
        fs::write(
            root.join("cmdline-a.txt"),
            format!("root=PARTUUID={ROOT_A_PARTUUID} rootfstype=ext4 ro rootwait quiet\n"),
        )
        .unwrap();
        fs::write(
            root.join("cmdline-b.txt"),
            format!("root=PARTUUID={ROOT_B_PARTUUID} rootfstype=ext4 ro rootwait quiet\n"),
        )
        .unwrap();
        fs::write(
            root.join("config.txt"),
            "[all]\narm_64bit=1\nkernel=kernel8.img\ninitramfs initramfs8 followkernel\n[boot_partition=2]\ncmdline=cmdline-a.txt\n[boot_partition=4]\ncmdline=cmdline-b.txt\n",
        )
        .unwrap();
        fs::write(root.join("kernel8.img"), b"test kernel").unwrap();
        fs::write(root.join("initramfs8"), b"test initramfs").unwrap();
    }

    #[test]
    fn firmware_observation_is_exact_big_endian_and_slot_bounded() {
        let root = temp_root("pi-observation");
        fs::create_dir_all(&root).unwrap();
        let partition = root.join("partition");
        let tryboot = root.join("tryboot");
        fs::write(&partition, 2_u32.to_be_bytes()).unwrap();
        let observed = PiBootObservation::read(&partition, &tryboot).unwrap();
        assert_eq!(observed.slot, PiSlot::A);
        assert!(!observed.tryboot);

        fs::write(&partition, 4_u32.to_be_bytes()).unwrap();
        fs::write(&tryboot, 1_u32.to_be_bytes()).unwrap();
        let observed = PiBootObservation::read(&partition, &tryboot).unwrap();
        assert_eq!(observed.slot, PiSlot::B);
        assert!(observed.tryboot);

        fs::write(&partition, 3_u32.to_be_bytes()).unwrap();
        assert!(PiBootObservation::read(&partition, &tryboot).is_err());
        fs::write(&partition, [0, 0, 2]).unwrap();
        assert!(PiBootObservation::read(&partition, &tryboot).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn slot_pairing_is_total_and_never_targets_the_running_pair() {
        for current in [PiSlot::A, PiSlot::B] {
            let inactive = current.inactive();
            assert_ne!(current, inactive);
            assert_ne!(current.boot_partition(), inactive.boot_partition());
            assert_ne!(current.root_partition(), inactive.root_partition());
            assert_ne!(current.boot_partuuid(), inactive.boot_partuuid());
            assert_ne!(current.root_partuuid(), inactive.root_partuuid());
            assert_eq!(inactive.inactive(), current);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signed_bundle_writes_only_inactive_pair_then_records_pending_state() {
        let root = temp_root("pi-update-stage");
        let release = root.join("release");
        let keys = root.join("keys");
        let selector = root.join("selector");
        let boot_a_mount = root.join("boot-a-mount");
        let boot_b_mount = root.join("boot-b-mount");
        fs::create_dir_all(&release).unwrap();
        fs::create_dir_all(&keys).unwrap();
        fs::create_dir_all(&selector).unwrap();
        write_boot_fixture(&boot_a_mount);
        write_boot_fixture(&boot_b_mount);
        fs::write(
            selector.join("autoboot.txt"),
            b"[all]\ntryboot_a_b=1\nboot_partition=2\n[tryboot]\nboot_partition=4\n",
        )
        .unwrap();

        let partition_property = root.join("partition");
        let tryboot_property = root.join("tryboot");
        fs::write(&partition_property, 2_u32.to_be_bytes()).unwrap();

        let root_payload = vec![0x41; 4096];
        let boot_payload = vec![0x42; 4096];
        let payload_name = "punar-desktop-aarch64-raspberry_pi-2026.08.30.6.root.raw.zst";
        let boot_name = "punar-desktop-aarch64-raspberry_pi-2026.08.30.6.boot.img";
        fs::write(release.join(payload_name), &root_payload).unwrap();
        fs::write(release.join(boot_name), &boot_payload).unwrap();
        let version = "2026.08.30.6".parse::<ReleaseVersion>().unwrap();
        let manifest = ReleaseManifest {
            schema_version: 1,
            release_id: "punar-desktop-stable-aarch64-raspberry_pi-2026.08.30.6".into(),
            image_id: "punar-desktop".into(),
            architecture: Architecture::Aarch64,
            boot_platform: punar_common::update::BootPlatform::RaspberryPi,
            version,
            channel: UpdateChannel::Stable,
            snapshot_pin: "20260820T000000Z+rpi-test".into(),
            overlay_pin: None,
            payload: PayloadArtifact {
                filename: payload_name.into(),
                digest_sha256: sha256_hex(&root_payload),
                size_bytes: root_payload.len() as u64,
                uncompressed_digest_sha256: sha256_hex(&root_payload),
                uncompressed_size_bytes: root_payload.len() as u64,
                compression: "zstd".into(),
            },
            boot_artifact: BootArtifact {
                kind: BootArtifactKind::RaspberryPiBootfs,
                filename: boot_name.into(),
                digest_sha256: sha256_hex(&boot_payload),
                size_bytes: boot_payload.len() as u64,
            },
            min_from: None,
            security: ReleaseSecurity {
                severity: SecuritySeverity::None,
                advisory_ids: Vec::new(),
            },
            provenance: ReleaseProvenance {
                git_commit: "0123456789abcdef0123456789abcdef01234567".into(),
                ci_run_id: "test-pi-update".into(),
                builder_base_digest: format!("sha256:{}", "3".repeat(64)),
                source_date_epoch: 1_787_184_000,
                built_at: "2026-08-30T12:00:00Z".into(),
            },
            sbom: None,
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let signing = SigningKey::from_bytes(&[42; 32]);
        fs::write(release.join("release.json"), &manifest_bytes).unwrap();
        fs::write(
            release.join("release.json.sig"),
            signing.sign(&manifest_bytes).to_bytes(),
        )
        .unwrap();
        fs::write(keys.join("test.pub"), signing.verifying_key().to_bytes()).unwrap();

        let zstd = root.join("fake-zstd");
        fs::write(&zstd, b"#!/bin/sh\nexec /bin/cat\n").unwrap();
        fs::set_permissions(&zstd, PermissionsExt::from_mode(0o755)).unwrap();
        let root_a = root.join("root-a");
        let root_b = root.join("root-b");
        let boot_a = root.join("boot-a");
        let boot_b = root.join("boot-b");
        for path in [&root_a, &root_b, &boot_a, &boot_b] {
            let file = File::create(path).unwrap();
            file.set_len(8192).unwrap();
        }
        fs::write(&root_a, vec![0x11; 8192]).unwrap();
        fs::write(&boot_a, vec![0x22; 8192]).unwrap();

        let pending = root.join("state/pending.json");
        let cmdline = root.join("cmdline");
        let mountinfo = root.join("mountinfo");
        let health = root.join("health.json");
        let engine = PiUpdateEngine::new(PiUpdateSources {
            boot_partition_property: partition_property,
            tryboot_property: tryboot_property.clone(),
            cmdline_path: cmdline.clone(),
            mountinfo_path: mountinfo.clone(),
            health_report: health.clone(),
            selector_partition: root.join("selector-device"),
            boot_a_partition: boot_a.clone(),
            root_a_partition: root_a.clone(),
            boot_b_partition: boot_b.clone(),
            root_b_partition: root_b.clone(),
            mount_root: root.join("mounts"),
            pending_state: pending.clone(),
            zstd_path: zstd,
            allow_regular_targets: true,
            selector_mount_override: Some(selector.clone()),
            boot_a_mount_override: Some(boot_a_mount),
            boot_b_mount_override: Some(boot_b_mount),
        });
        let target = ReleaseTarget {
            image_id: "punar-desktop".into(),
            architecture: Architecture::Aarch64,
            boot_platform: punar_common::update::BootPlatform::RaspberryPi,
            channel: UpdateChannel::Stable,
        };
        let result = engine
            .stage_bundle(&release, &keys, &target, "2026.08.30.5".parse().unwrap())
            .unwrap();
        assert_eq!(result.previous_slot, PiSlot::A);
        assert_eq!(result.staged_slot, PiSlot::B);
        assert!(result.verified);
        assert_eq!(&fs::read(&root_a).unwrap()[..], &vec![0x11; 8192]);
        assert_eq!(&fs::read(&boot_a).unwrap()[..], &vec![0x22; 8192]);
        assert_eq!(&fs::read(&root_b).unwrap()[..4096], &root_payload);
        assert_eq!(&fs::read(&boot_b).unwrap()[..4096], &boot_payload);
        let stored: PendingPiUpdate = serde_json::from_slice(&fs::read(&pending).unwrap()).unwrap();
        assert_eq!(stored.previous_slot, PiSlot::A);
        assert_eq!(stored.candidate_slot, PiSlot::B);
        assert_eq!(stored.candidate_boot_partition, 4);
        assert_eq!(stored.candidate_root_partition, 5);
        assert_eq!(stored.manifest_sha256, sha256_hex(&manifest_bytes));

        let conflict = engine
            .stage_bundle(&release, &keys, &target, "2026.08.30.5".parse().unwrap())
            .unwrap_err();
        assert!(conflict.to_string().contains("already pending"));

        fs::write(&engine.sources.boot_partition_property, 4_u32.to_be_bytes()).unwrap();
        fs::write(&tryboot_property, 1_u32.to_be_bytes()).unwrap();
        fs::write(
            &cmdline,
            format!("root=PARTUUID={ROOT_B_PARTUUID} rootfstype=ext4 ro rootwait\n"),
        )
        .unwrap();
        fs::write(
            &mountinfo,
            "29 23 0:25 / / ro,relatime - ext4 /dev/mmcblk0p5 ro\n",
        )
        .unwrap();
        fs::write(
            &health,
            br#"{"schema_version":1,"health":{"boot_completed":true,"control_plane_answers":true,"desktop_ready":true,"capabilities_verified":true},"waited_seconds":7}"#,
        )
        .unwrap();
        let pending_before_commit = fs::read(&pending).unwrap();
        let commit = engine.commit_candidate().unwrap();
        assert_eq!(commit.blessed_slot, PiSlot::B);
        assert_eq!(commit.previous_slot, PiSlot::A);
        assert!(commit.selector_committed);
        assert!(!pending.exists());
        assert_eq!(
            fs::read(selector.join("autoboot.previous")).unwrap(),
            canonical_autoboot(PiSlot::A, PiSlot::B)
        );
        let committed_selector = fs::read(selector.join("autoboot.txt")).unwrap();
        validate_raspberry_pi_autoboot(&committed_selector, 4, 2).unwrap();

        // Recreate the only durable state left by a crash after the selector
        // commit but before pending-state removal. Retrying must recognize the
        // already committed selector and finish without changing either copy.
        fs::write(&pending, pending_before_commit).unwrap();
        let recovered = engine.commit_candidate().unwrap();
        assert_eq!(recovered.blessed_slot, PiSlot::B);
        assert_eq!(recovered.previous_slot, PiSlot::A);
        assert!(recovered.selector_committed);
        assert!(!pending.exists());
        assert_eq!(
            fs::read(selector.join("autoboot.previous")).unwrap(),
            canonical_autoboot(PiSlot::A, PiSlot::B)
        );
        assert_eq!(
            fs::read(selector.join("autoboot.txt")).unwrap(),
            committed_selector
        );
        fs::remove_dir_all(root).unwrap();
    }
}
