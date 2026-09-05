//! Native UEFI A/B update transaction.
//!
//! The caller supplies no path, URL, slot, artifact, digest, executable or
//! boot selector. The running kernel chooses the active slot, fixed PARTUUIDs
//! choose the inactive destination, and the signed release manifest chooses
//! the exact root/UKI pair. The UKI is installed only after the root payload
//! has been written, fsynced, physically re-read and re-hashed.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use punar_common::update::{
    BootArtifactKind, PayloadArtifact, ReleaseVersion, UpdateApplyResult, UpdateRollbackResult,
    UpdateSlot, verify_reader,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::install::{
    ESP_PARTUUID, ROOT_A_PARTUUID, ROOT_B_PARTUUID, digest_installed_partition,
    stream_exact_payload,
};
use crate::update_check::PreparedRelease;
use crate::util::{sha256_hex, write_atomic_synced};

const SMALL_FILE_MAX: u64 = 64 * 1024;
const RELEASE_DOCUMENT_MAX: u64 = 1024 * 1024;
const ESP_POST_STAGE_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct UpdateTransactionSources {
    pub cmdline: PathBuf,
    pub root_a_partition: PathBuf,
    pub root_b_partition: PathBuf,
    pub esp_partition: PathBuf,
    pub mount_root: PathBuf,
    pub pending_uefi: PathBuf,
    pub zstd_path: PathBuf,
    /// Test-only seam configured directly by contract tests. Production
    /// construction always leaves this false and no environment variable can
    /// alter it.
    pub allow_regular_targets: bool,
    /// Same direct-construction seam for a fake mounted ESP directory.
    pub esp_mount_override: Option<PathBuf>,
}

impl Default for UpdateTransactionSources {
    fn default() -> Self {
        let by_partuuid = Path::new("/dev/disk/by-partuuid");
        Self {
            cmdline: PathBuf::from("/proc/cmdline"),
            root_a_partition: by_partuuid.join(ROOT_A_PARTUUID),
            root_b_partition: by_partuuid.join(ROOT_B_PARTUUID),
            esp_partition: by_partuuid.join(ESP_PARTUUID),
            mount_root: PathBuf::from("/run/punard/update"),
            pending_uefi: PathBuf::from("/var/lib/punar/update/pending-uefi.json"),
            zstd_path: PathBuf::from("/usr/bin/zstd"),
            allow_regular_targets: false,
            esp_mount_override: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingUefiUpdate {
    pub schema_version: u8,
    pub release_id: String,
    pub version: ReleaseVersion,
    pub previous_slot: UpdateSlot,
    pub candidate_slot: UpdateSlot,
    pub previous_default: String,
    pub new_default: String,
    pub manifest_sha256: String,
    pub payload_sha256: String,
    pub uki_sha256: String,
    pub staged_at: String,
}

#[derive(Debug, Error)]
pub enum UpdateTransactionError {
    #[error("update transaction I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("update artifact is not trusted at {stage}: {reason}")]
    Trust { stage: &'static str, reason: String },
    #[error("update could not be applied: {0}")]
    Apply(String),
    #[error("post-write verification failed: {0}")]
    Verify(String),
    #[error("update conflicts with current state: {0}")]
    Conflict(String),
    #[error("rollback target was not found: {0}")]
    NotFound(String),
    #[error("inactive slot has {available_bytes} bytes but {required_bytes} are required")]
    InsufficientSpace {
        required_bytes: u64,
        available_bytes: u64,
    },
    #[error(
        "ESP has {available_bytes} free bytes but staging plus reserve requires {required_bytes}"
    )]
    EspInsufficientSpace {
        required_bytes: u64,
        available_bytes: u64,
    },
}

impl UpdateTransactionError {
    pub fn stage(&self) -> &'static str {
        match self {
            Self::Trust { stage, .. } => stage,
            Self::Verify(_) => "post_write_digest",
            Self::InsufficientSpace { .. } => "inactive_slot_space",
            Self::EspInsufficientSpace { .. } => "esp_space",
            Self::Conflict(_) => "device_state",
            Self::NotFound(_) => "rollback_target",
            Self::Apply(_) => "apply",
            Self::Io(_) => "io",
        }
    }
}

pub struct UpdateTransactionEngine {
    sources: UpdateTransactionSources,
}

impl UpdateTransactionEngine {
    pub fn new(sources: UpdateTransactionSources) -> Self {
        Self { sources }
    }

    pub fn active_slot(&self) -> Result<UpdateSlot, UpdateTransactionError> {
        let bytes = read_bounded(&self.sources.cmdline, SMALL_FILE_MAX, "kernel command line")?;
        let text = std::str::from_utf8(&bytes).map_err(|_| UpdateTransactionError::Trust {
            stage: "active_slot",
            reason: "kernel command line is not UTF-8".into(),
        })?;
        let roots = text
            .split_ascii_whitespace()
            .filter_map(|token| token.strip_prefix("root=PARTUUID="))
            .collect::<Vec<_>>();
        match roots.as_slice() {
            [value] if value.eq_ignore_ascii_case(ROOT_A_PARTUUID) => Ok(UpdateSlot::A),
            [value] if value.eq_ignore_ascii_case(ROOT_B_PARTUUID) => Ok(UpdateSlot::B),
            _ => Err(UpdateTransactionError::Conflict(
                "the running kernel does not identify exactly one Punar root slot".into(),
            )),
        }
    }

    pub fn inactive_slot(&self) -> Result<UpdateSlot, UpdateTransactionError> {
        match self.active_slot()? {
            UpdateSlot::A => Ok(UpdateSlot::B),
            UpdateSlot::B => Ok(UpdateSlot::A),
            UpdateSlot::Unknown => Err(UpdateTransactionError::Conflict(
                "the active root slot is unknown".into(),
            )),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn stage(
        &self,
        release: &PreparedRelease,
    ) -> Result<UpdateApplyResult, UpdateTransactionError> {
        let current = self.active_slot()?;
        let candidate = self.inactive_slot()?;
        if self.sources.pending_uefi.exists() {
            return Err(UpdateTransactionError::Conflict(
                "another UEFI update is already staged".into(),
            ));
        }
        let (payload, boot) = release
            .manifest
            .artifacts_for_slot(candidate)
            .ok_or_else(|| UpdateTransactionError::Trust {
                stage: "slot_artifacts",
                reason: "signed release does not contain the inactive slot pair".into(),
            })?;
        if boot.kind != BootArtifactKind::Uki {
            return Err(UpdateTransactionError::Trust {
                stage: "boot_artifact_kind",
                reason: "UEFI update does not contain a UKI".into(),
            });
        }
        let payload_path = release.release_dir.join(&payload.filename);
        let boot_path = release.release_dir.join(&boot.filename);
        verify_file(
            &payload_path,
            &payload.digest_sha256,
            payload.size_bytes,
            "payload_digest",
        )?;
        verify_file(
            &boot_path,
            &boot.digest_sha256,
            boot.size_bytes,
            "uki_digest",
        )?;
        validate_uki_binding(&boot_path, candidate)?;

        // Admission facts that need no write: the ESP must already hold a
        // last-known-good UKI and room for the candidate. Checking them here,
        // read-only, keeps the factory-recovery retirement below from ever
        // running for an apply the later stage would refuse anyway, so a
        // refused apply can never cost the device its recovery floor.
        {
            let esp = self.mount_esp(true)?;
            let uki_dir = esp.path.join("EFI/Linux");
            let known = match known_uki_versions(&uki_dir) {
                Ok(known) => known,
                Err(UpdateTransactionError::Io(error))
                    if error.kind() == std::io::ErrorKind::NotFound =>
                {
                    Vec::new()
                }
                Err(error) => return Err(error),
            };
            if known.is_empty() {
                return Err(UpdateTransactionError::Conflict(
                    "the ESP contains no last-known-good Punar UKI".into(),
                ));
            }
            require_esp_stage_capacity(&esp.path, boot.size_bytes)?;
            esp.finish()?;
        }

        // The factory recovery UKI points at slot B. It must be durably
        // retired before the first update can overwrite any B byte, and only
        // after an uncounted, preferred A entry proves first-boot blessing.
        // A crash on either side of this boundary therefore leaves A as the
        // bootable fallback; it can never leave a stale UKI aimed at a
        // partially overwritten recovery root.
        self.retire_initial_recovery_before_overwrite(current, candidate)?;

        let target = self.root_target(candidate);
        let mut destination = open_partition_for_write(
            target,
            self.sources.allow_regular_targets,
            "inactive root slot",
        )?;
        let capacity = destination.seek(SeekFrom::End(0))?;
        destination.seek(SeekFrom::Start(0))?;
        if capacity < payload.uncompressed_size_bytes {
            return Err(UpdateTransactionError::InsufficientSpace {
                required_bytes: payload.uncompressed_size_bytes,
                available_bytes: capacity,
            });
        }
        write_root_payload(
            &self.sources.zstd_path,
            &payload_path,
            &mut destination,
            payload,
        )?;
        drop(destination);
        verify_installed_root(
            target,
            payload.uncompressed_size_bytes,
            &payload.uncompressed_digest_sha256,
            self.sources.allow_regular_targets,
        )?;

        let manifest_bytes = read_bounded(
            &release.release_dir.join("release.json"),
            RELEASE_DOCUMENT_MAX,
            "cached release manifest",
        )?;
        let mounted = self.mount_esp(false)?;
        let uki_dir = mounted.path.join("EFI/Linux");
        let loader_dir = mounted.path.join("loader");
        fs::create_dir_all(&uki_dir)?;
        fs::create_dir_all(&loader_dir)?;
        require_esp_stage_capacity(&mounted.path, boot.size_bytes)?;
        let old_ukis = known_uki_versions(&uki_dir)?;
        if old_ukis.is_empty() {
            return Err(UpdateTransactionError::Conflict(
                "the ESP contains no last-known-good Punar UKI".into(),
            ));
        }
        let previous_default =
            read_preferred(&loader_dir.join("loader.conf")).unwrap_or_else(|| "unknown".into());
        let new_name = format!("punar_{}+3-0.efi", release.manifest.version);
        let new_selector = format!("punar_{}*.efi", release.manifest.version);
        copy_verified_atomic(
            &boot_path,
            &uki_dir.join(&new_name),
            boot.size_bytes,
            &boot.digest_sha256,
        )?;
        let pending = PendingUefiUpdate {
            schema_version: 1,
            release_id: release.manifest.release_id.clone(),
            version: release.manifest.version,
            previous_slot: current,
            candidate_slot: candidate,
            previous_default,
            new_default: new_selector.clone(),
            manifest_sha256: sha256_hex(&manifest_bytes),
            payload_sha256: payload.uncompressed_digest_sha256.clone(),
            uki_sha256: boot.digest_sha256.clone(),
            staged_at: punar_common::time::utc_now_rfc3339(),
        };
        let pending_bytes = serde_json::to_vec_pretty(&pending)
            .map_err(|error| UpdateTransactionError::Apply(error.to_string()))?;
        if let Some(parent) = self.sources.pending_uefi.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        write_atomic_synced(&self.sources.pending_uefi, &pending_bytes, 0o600)?;
        let loader = format!("preferred {new_selector}\ntimeout 0\neditor no\n");
        write_atomic_synced(&loader_dir.join("loader.conf"), loader.as_bytes(), 0o600)?;
        sync_filesystem(&mounted.path)?;
        if read_preferred(&loader_dir.join("loader.conf")).as_deref() != Some(&new_selector) {
            return Err(UpdateTransactionError::Verify(
                "the ESP did not retain the new preferred selector".into(),
            ));
        }
        mounted.finish()?;

        Ok(UpdateApplyResult {
            v: 1,
            staged_version: release.manifest.version,
            staged_slot: candidate,
            requires_reboot: true,
            bytes_written: payload
                .uncompressed_size_bytes
                .checked_add(boot.size_bytes)
                .ok_or_else(|| {
                    UpdateTransactionError::Apply("written byte count overflow".into())
                })?,
            verified: true,
        })
    }

    #[cfg(target_os = "linux")]
    fn retire_initial_recovery_before_overwrite(
        &self,
        current: UpdateSlot,
        candidate: UpdateSlot,
    ) -> Result<(), UpdateTransactionError> {
        let mounted = self.mount_esp(false)?;
        let uki_dir = mounted.path.join("EFI/Linux");
        let recovery = recovery_uki_paths(&uki_dir)?;
        if recovery.is_empty() {
            return mounted.finish();
        }
        if candidate == UpdateSlot::A {
            // The device is running from the recovery slot itself: A was
            // damaged and B was selected by hand. This apply rewrites only
            // root A, so the B-bound recovery entry stays exactly as valid as
            // before; retiring it would leave no verified way back into B.
            return mounted.finish();
        }
        if recovery.len() != 1 || current != UpdateSlot::A || candidate != UpdateSlot::B {
            return Err(UpdateTransactionError::Conflict(
                "factory recovery can be retired only while a blessed slot A is running and slot B is the inactive update target"
                    .into(),
            ));
        }
        let loader = mounted.path.join("loader/loader.conf");
        let selector = read_preferred(&loader).ok_or_else(|| {
            UpdateTransactionError::Conflict(
                "factory recovery retirement requires one preferred selector".into(),
            )
        })?;
        let blessed_version = selector_version(&selector).ok_or_else(|| {
            UpdateTransactionError::Conflict(
                "factory recovery retirement requires a versioned slot-A selector".into(),
            )
        })?;
        let blessed_a = uki_dir.join(format!("punar_{blessed_version}.efi"));
        if !blessed_a.is_file() {
            return Err(UpdateTransactionError::Conflict(
                "slot A has not completed health-gated first-boot blessing".into(),
            ));
        }
        validate_uki_binding(&blessed_a, UpdateSlot::A)?;
        validate_uki_binding(&recovery[0], UpdateSlot::B)?;

        fs::remove_file(&recovery[0])?;
        sync_filesystem(&mounted.path)?;
        if recovery[0].exists() || !blessed_a.is_file() {
            return Err(UpdateTransactionError::Verify(
                "the ESP did not retain factory-recovery retirement with blessed A intact".into(),
            ));
        }
        mounted.finish()?;

        // Re-open read-only so a borrowed test mount and a real unmount/remount
        // cross the same visibility check before any root-slot writer opens.
        let reread = self.mount_esp(true)?;
        let reread_recovery = recovery_uki_paths(&reread.path.join("EFI/Linux"))?;
        let reread_a = reread
            .path
            .join("EFI/Linux")
            .join(format!("punar_{blessed_version}.efi"));
        if !reread_recovery.is_empty() || !reread_a.is_file() {
            return Err(UpdateTransactionError::Verify(
                "factory-recovery retirement did not survive an ESP read-only re-open".into(),
            ));
        }
        validate_uki_binding(&reread_a, UpdateSlot::A)?;
        reread.finish()
    }

    #[cfg(not(target_os = "linux"))]
    pub fn stage(
        &self,
        _release: &PreparedRelease,
    ) -> Result<UpdateApplyResult, UpdateTransactionError> {
        Err(UpdateTransactionError::Conflict(
            "system-image updates are available only on Linux".into(),
        ))
    }

    #[cfg(target_os = "linux")]
    pub fn rollback(
        &self,
        requested: Option<ReleaseVersion>,
    ) -> Result<UpdateRollbackResult, UpdateTransactionError> {
        let mounted = self.mount_esp(false)?;
        let loader = mounted.path.join("loader/loader.conf");
        let uki_dir = mounted.path.join("EFI/Linux");
        let current_selector = read_preferred(&loader).unwrap_or_else(|| "unknown".into());
        let current_version = selector_version(&current_selector);
        let versions = known_uki_versions(&uki_dir)?;
        let target = match requested {
            Some(version) => versions
                .iter()
                .find(|(candidate, _)| *candidate == version)
                .cloned()
                .ok_or_else(|| UpdateTransactionError::NotFound(version.to_string()))?,
            None => versions
                .into_iter()
                .filter(|(version, _)| Some(*version) != current_version)
                .max_by_key(|(version, _)| *version)
                .ok_or_else(|| {
                    UpdateTransactionError::Conflict(
                        "no previous blessed UEFI release is present".into(),
                    )
                })?,
        };
        let new_selector = format!("punar_{}*.efi", target.0);
        let contents = format!("preferred {new_selector}\ntimeout 0\neditor no\n");
        write_atomic_synced(&loader, contents.as_bytes(), 0o600)?;
        sync_filesystem(&mounted.path)?;
        if read_preferred(&loader).as_deref() != Some(&new_selector) {
            return Err(UpdateTransactionError::Verify(
                "the ESP did not retain the rollback selector".into(),
            ));
        }
        mounted.finish()?;
        match fs::remove_file(&self.sources.pending_uefi) {
            Ok(()) => {
                if let Some(parent) = self.sources.pending_uefi.parent() {
                    File::open(parent)?.sync_all()?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(UpdateRollbackResult {
            v: 1,
            previous_default: current_selector,
            new_default: new_selector,
            requires_reboot: true,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn rollback(
        &self,
        _requested: Option<ReleaseVersion>,
    ) -> Result<UpdateRollbackResult, UpdateTransactionError> {
        Err(UpdateTransactionError::Conflict(
            "system-image rollback is available only on Linux".into(),
        ))
    }

    fn root_target(&self, slot: UpdateSlot) -> &Path {
        match slot {
            UpdateSlot::A => &self.sources.root_a_partition,
            UpdateSlot::B => &self.sources.root_b_partition,
            UpdateSlot::Unknown => &self.sources.root_a_partition,
        }
    }

    #[cfg(target_os = "linux")]
    fn mount_esp(&self, read_only: bool) -> Result<MountedEsp, UpdateTransactionError> {
        if let Some(path) = &self.sources.esp_mount_override {
            if !fs::symlink_metadata(path)?.file_type().is_dir() {
                return Err(UpdateTransactionError::Conflict(
                    "configured ESP test mount is not a directory".into(),
                ));
            }
            return Ok(MountedEsp::borrowed(path.clone()));
        }
        let path = self.sources.mount_root.join("esp");
        fs::create_dir_all(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let mut flags = rustix::mount::MountFlags::NODEV
            | rustix::mount::MountFlags::NOSUID
            | rustix::mount::MountFlags::NOEXEC
            | rustix::mount::MountFlags::NOSYMFOLLOW;
        if read_only {
            flags |= rustix::mount::MountFlags::RDONLY;
        }
        rustix::mount::mount(
            &self.sources.esp_partition,
            &path,
            "vfat",
            flags,
            Some(c"umask=0077"),
        )
        .map_err(|error| UpdateTransactionError::Io(error.into()))?;
        Ok(MountedEsp { path, owned: true })
    }
}

#[cfg(target_os = "linux")]
struct MountedEsp {
    path: PathBuf,
    owned: bool,
}

#[cfg(target_os = "linux")]
impl MountedEsp {
    fn borrowed(path: PathBuf) -> Self {
        Self { path, owned: false }
    }

    fn finish(mut self) -> Result<(), UpdateTransactionError> {
        if self.owned {
            rustix::mount::unmount(&self.path, rustix::mount::UnmountFlags::empty())
                .map_err(|error| UpdateTransactionError::Io(error.into()))?;
            let _ = fs::remove_dir(&self.path);
            self.owned = false;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for MountedEsp {
    fn drop(&mut self) {
        if self.owned {
            let _ = rustix::mount::unmount(&self.path, rustix::mount::UnmountFlags::DETACH);
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn verify_file(
    path: &Path,
    digest: &str,
    size: u64,
    stage: &'static str,
) -> Result<(), UpdateTransactionError> {
    let mut file = open_regular_nofollow(path, stage)?;
    verify_reader(&mut file, digest, size).map_err(|error| UpdateTransactionError::Trust {
        stage,
        reason: error.to_string(),
    })
}

#[cfg(target_os = "linux")]
fn verify_installed_root(
    path: &Path,
    expected_size: u64,
    expected_digest: &str,
    allow_regular: bool,
) -> Result<(), UpdateTransactionError> {
    if allow_regular {
        let file = open_regular_nofollow(path, "inactive UEFI root slot")?;
        return verify_reader(
            std::io::Read::take(file, expected_size),
            expected_digest,
            expected_size,
        )
        .map_err(|error| {
            UpdateTransactionError::Verify(format!("test target re-read failed: {error}"))
        });
    }
    digest_installed_partition(
        path,
        expected_size,
        expected_digest,
        false,
        "inactive UEFI root slot",
    )
    .map_err(|error| UpdateTransactionError::Verify(error.to_string()))
}

fn open_regular_nofollow(path: &Path, description: &str) -> Result<File, UpdateTransactionError> {
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(flags.bits()).expect("open flags fit libc::c_int"))
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(UpdateTransactionError::Trust {
            stage: "artifact_type",
            reason: format!("{description} is not a regular file"),
        });
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_partition_for_write(
    path: &Path,
    allow_regular: bool,
    description: &str,
) -> Result<File, UpdateTransactionError> {
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
    let kind = file.metadata()?.file_type();
    if !(kind.is_block_device() || allow_regular && kind.is_file()) {
        return Err(UpdateTransactionError::Conflict(format!(
            "{description} is not a block device"
        )));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn write_root_payload(
    zstd: &Path,
    payload_path: &Path,
    destination: &mut File,
    payload: &PayloadArtifact,
) -> Result<(), UpdateTransactionError> {
    let source = open_regular_nofollow(payload_path, "compressed root payload")?;
    let mut child = Command::new(zstd)
        .args(["-dc", "--"])
        .stdin(Stdio::from(source))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut output = child.stdout.take().ok_or_else(|| {
        UpdateTransactionError::Apply("zstd did not expose its fixed output pipe".into())
    })?;
    let copied = stream_exact_payload(
        &mut output,
        destination,
        payload.uncompressed_size_bytes,
        &payload.uncompressed_digest_sha256,
        |_| Ok(()),
    );
    drop(output);
    if let Err(error) = copied {
        let _ = child.kill();
        let _ = child.wait();
        return Err(UpdateTransactionError::Trust {
            stage: "uncompressed_payload",
            reason: error.to_string(),
        });
    }
    if !child.wait()?.success() {
        return Err(UpdateTransactionError::Trust {
            stage: "uncompressed_payload",
            reason: "zstd refused the signed payload".into(),
        });
    }
    destination.sync_all()?;
    Ok(())
}

fn validate_uki_binding(path: &Path, slot: UpdateSlot) -> Result<(), UpdateTransactionError> {
    let expected = match slot {
        UpdateSlot::A => ROOT_A_PARTUUID,
        UpdateSlot::B => ROOT_B_PARTUUID,
        UpdateSlot::Unknown => "",
    };
    let mut file = open_regular_nofollow(path, "UKI")?;
    crate::uki::require_root_partuuid(&mut file, expected).map_err(|reason| {
        UpdateTransactionError::Trust {
            stage: "uki_cmdline",
            reason,
        }
    })
}

fn trust<T>(stage: &'static str, reason: &str) -> Result<T, UpdateTransactionError> {
    Err(UpdateTransactionError::Trust {
        stage,
        reason: reason.into(),
    })
}

fn copy_verified_atomic(
    source: &Path,
    destination: &Path,
    expected_size: u64,
    expected_digest: &str,
) -> Result<(), UpdateTransactionError> {
    let mut input = open_regular_nofollow(source, "UKI")?;
    let temporary = destination.with_extension("efi.new");
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let copied = std::io::copy(&mut input, &mut output)?;
    output.flush()?;
    output.sync_all()?;
    if copied != expected_size {
        let _ = fs::remove_file(&temporary);
        return trust("uki_digest", "UKI changed size while it was copied");
    }
    verify_file(&temporary, expected_digest, expected_size, "uki_digest")?;
    fs::rename(&temporary, destination)?;
    Ok(())
}

fn known_uki_versions(
    directory: &Path,
) -> Result<Vec<(ReleaseVersion, PathBuf)>, UpdateTransactionError> {
    let mut versions = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        // Only uncounted entries are blessed last-known-good candidates.
        let Some(version) = name
            .strip_prefix("punar_")
            .and_then(|name| name.strip_suffix(".efi"))
            .filter(|value| !value.contains('+'))
            .and_then(|value| value.parse::<ReleaseVersion>().ok())
        else {
            continue;
        };
        versions.push((version, entry.path()));
    }
    Ok(versions)
}

fn recovery_uki_paths(directory: &Path) -> Result<Vec<PathBuf>, UpdateTransactionError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !name.starts_with("punar-recovery_") {
            continue;
        }
        if !entry.file_type()?.is_file()
            || name
                .strip_prefix("punar-recovery_")
                .and_then(|value| value.strip_suffix(".efi"))
                .filter(|value| !value.contains('+'))
                .and_then(|value| value.parse::<ReleaseVersion>().ok())
                .is_none()
        {
            return Err(UpdateTransactionError::Conflict(
                "the ESP contains an invalid factory-recovery inventory entry".into(),
            ));
        }
        paths.push(entry.path());
    }
    paths.sort();
    Ok(paths)
}

#[cfg(target_os = "linux")]
fn require_esp_stage_capacity(
    path: &Path,
    candidate_bytes: u64,
) -> Result<(), UpdateTransactionError> {
    let stat = rustix::fs::statvfs(path)
        .map_err(|error| UpdateTransactionError::Io(std::io::Error::from(error)))?;
    let available = stat.f_bavail.saturating_mul(stat.f_frsize);
    let required = candidate_bytes
        .checked_add(ESP_POST_STAGE_RESERVE_BYTES)
        .ok_or_else(|| UpdateTransactionError::Apply("ESP capacity calculation overflow".into()))?;
    if available < required {
        return Err(UpdateTransactionError::EspInsufficientSpace {
            required_bytes: required,
            available_bytes: available,
        });
    }
    Ok(())
}

fn read_preferred(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let mut values = text.lines().filter_map(|line| {
        line.trim()
            .strip_prefix("preferred ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
    });
    let value = values.next()?.to_string();
    values.next().is_none().then_some(value)
}

fn selector_version(selector: &str) -> Option<ReleaseVersion> {
    selector
        .strip_prefix("punar_")
        .and_then(|value| value.strip_suffix("*.efi"))
        .and_then(|value| value.parse().ok())
}

fn read_bounded(
    path: &Path,
    maximum: u64,
    description: &str,
) -> Result<Vec<u8>, UpdateTransactionError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(UpdateTransactionError::Trust {
            stage: "local_evidence",
            reason: format!("{description} is not a bounded regular file"),
        });
    }
    let mut file = open_regular_nofollow(path, description)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return trust("local_evidence", "bounded file changed while it was read");
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn sync_filesystem(path: &Path) -> Result<(), UpdateTransactionError> {
    let file = File::open(path)?;
    rustix::fs::syncfs(&file).map_err(|error| UpdateTransactionError::Io(error.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_parser_accepts_only_the_versioned_preferred_glob() {
        assert_eq!(
            selector_version("punar_2026.09.01.3*.efi")
                .unwrap()
                .to_string(),
            "2026.09.01.3"
        );
        assert!(selector_version("punar_2026.09.01.3+3-0.efi").is_none());
        assert!(selector_version("../punar_2026.09.01.3*.efi").is_none());
    }
}
