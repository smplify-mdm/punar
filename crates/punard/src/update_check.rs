//! Authenticated, fail-closed update-channel discovery.
//!
//! `update.check` accepts only a `force` bit. Origins, paths, keys, target
//! identity and rollout identity all come from root-owned daemon state. The
//! current slice deliberately uses a fixed directory transport so offline CI
//! and removable repository media exercise the real signature/admission/cache
//! path without pretending HTTPS transport is complete.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use punar_common::update::{
    Architecture, BootPlatform, ReleaseKeySet, ReleaseTarget, ReleaseVersion, UpdateChannel,
    UpdateCheckResult, UpdateTrustError, cohort_bucket, verify_channel_metadata,
};
use thiserror::Error;

use crate::update_status::{read_bounded, read_os_release};
use crate::util::write_atomic_synced;

const CHANNEL_DOCUMENT_MAX: u64 = 64 * 1024;
const SIGNATURE_MAX: u64 = 64;
const DEFAULT_CACHE_MAX_AGE: u64 = 15 * 60;

#[derive(Clone, Debug)]
pub struct UpdateCheckSources {
    /// Fixed local transport root. Production network transport is not yet
    /// claimed; a mounted repository exposes `channel.json` and its signature
    /// here without making a caller-supplied path part of the IPC contract.
    pub repository_dir: PathBuf,
    pub trusted_keys_dir: PathBuf,
    pub cached_channel: PathBuf,
    pub cached_signature: PathBuf,
    pub os_release: PathBuf,
    pub pi_boot_partition: PathBuf,
    pub cache_max_age_seconds: u64,
    /// Cross-architecture test seams. Production leaves both unset.
    pub architecture_override: Option<Architecture>,
    pub boot_platform_override: Option<BootPlatform>,
}

impl Default for UpdateCheckSources {
    fn default() -> Self {
        Self {
            repository_dir: PathBuf::from("/run/punar/update-source"),
            trusted_keys_dir: PathBuf::from("/usr/share/punar/release-keys"),
            cached_channel: PathBuf::from("/var/lib/punar/update/verified-channel.json"),
            cached_signature: PathBuf::from("/var/lib/punar/update/verified-channel.json.sig"),
            os_release: PathBuf::from("/etc/os-release"),
            pi_boot_partition: PathBuf::from("/proc/device-tree/chosen/bootloader/partition"),
            cache_max_age_seconds: DEFAULT_CACHE_MAX_AGE,
            architecture_override: None,
            boot_platform_override: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum UpdateCheckError {
    #[error("update source is unavailable: {0}")]
    SourceUnavailable(String),
    #[error("update metadata is not trusted at {stage}: {reason}")]
    Untrusted { stage: &'static str, reason: String },
    #[error("the running release identity is incomplete: {0}")]
    LocalIdentity(String),
    #[error("verified update metadata could not be cached: {0}")]
    Cache(String),
}

impl UpdateCheckError {
    pub fn stage(&self) -> &'static str {
        match self {
            Self::SourceUnavailable(_) => "channel_fetch",
            Self::Untrusted { stage, .. } => stage,
            Self::LocalIdentity(_) => "local_identity",
            Self::Cache(_) => "verified_cache",
        }
    }

    pub fn is_unreachable(&self) -> bool {
        matches!(self, Self::SourceUnavailable(_))
    }

    pub fn is_untrusted(&self) -> bool {
        matches!(self, Self::Untrusted { .. })
    }
}

pub struct UpdateCheckEngine {
    sources: UpdateCheckSources,
}

impl UpdateCheckEngine {
    pub fn new(sources: UpdateCheckSources) -> Self {
        Self { sources }
    }

    pub fn check(
        &self,
        channel: UpdateChannel,
        device_id: &str,
        force: bool,
    ) -> Result<UpdateCheckResult, UpdateCheckError> {
        let current = self.current_version()?;
        let target = self.release_target(channel)?;
        let keys = ReleaseKeySet::load_dir(&self.sources.trusted_keys_dir)
            .map_err(|error| untrusted("trusted_keys", error))?;

        let cached = !force && self.cache_is_fresh();
        let (document, signature, metadata_age_seconds) = if cached {
            let document = read_cache(&self.sources.cached_channel, CHANNEL_DOCUMENT_MAX)
                .map_err(|error| untrusted("cached_metadata", error))?;
            let signature = read_cache(&self.sources.cached_signature, SIGNATURE_MAX)
                .map_err(|error| untrusted("cached_signature", error))?;
            let age = file_age_seconds(&self.sources.cached_channel).unwrap_or(0);
            (document, signature, age)
        } else {
            let document = read_source(
                &self.sources.repository_dir.join("channel.json"),
                CHANNEL_DOCUMENT_MAX,
            )?;
            let signature = read_source(
                &self.sources.repository_dir.join("channel.json.sig"),
                SIGNATURE_MAX,
            )?;
            (document, signature, 0)
        };

        let metadata = verify_channel_metadata(&document, &signature, &keys)
            .map_err(|error| untrusted("channel_signature", error))?;
        // Target binding is a trust property. A validly signed document for a
        // different image, architecture, platform or channel must never enter
        // this device's verified cache.
        require_target(&metadata.image_id, &target.image_id, "image_id")?;
        require_equal(metadata.architecture, target.architecture, "architecture")?;
        require_equal(
            metadata.boot_platform,
            target.boot_platform,
            "boot_platform",
        )?;
        require_equal(metadata.channel, target.channel, "channel")?;

        if !cached {
            // Signature first, then signature file, then document last. A
            // power loss can at worst leave a mismatched pair that re-verifies
            // as untrusted; it cannot make unverified bytes authoritative.
            ensure_private_parent(&self.sources.cached_channel)
                .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
            ensure_private_parent(&self.sources.cached_signature)
                .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
            write_atomic_synced(&self.sources.cached_signature, &signature, 0o600)
                .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
            write_atomic_synced(&self.sources.cached_channel, &document, 0o600)
                .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
        }

        Ok(check_result(
            metadata,
            current,
            device_id,
            metadata_age_seconds,
            cached,
        ))
    }

    fn current_version(&self) -> Result<ReleaseVersion, UpdateCheckError> {
        let release = read_os_release(&self.sources.os_release).ok_or_else(|| {
            UpdateCheckError::LocalIdentity(format!(
                "{} is missing or invalid",
                self.sources.os_release.display()
            ))
        })?;
        release
            .get("IMAGE_VERSION")
            .or_else(|| release.get("VERSION_ID"))
            .ok_or_else(|| {
                UpdateCheckError::LocalIdentity(
                    "IMAGE_VERSION/VERSION_ID is not published".to_string(),
                )
            })?
            .parse()
            .map_err(|error: UpdateTrustError| UpdateCheckError::LocalIdentity(error.to_string()))
    }

    fn release_target(&self, channel: UpdateChannel) -> Result<ReleaseTarget, UpdateCheckError> {
        let release = read_os_release(&self.sources.os_release).ok_or_else(|| {
            UpdateCheckError::LocalIdentity(format!(
                "{} is missing or invalid",
                self.sources.os_release.display()
            ))
        })?;
        let image_id = release
            .get("IMAGE_ID")
            .or_else(|| release.get("ID"))
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| {
                UpdateCheckError::LocalIdentity("IMAGE_ID/ID is not published".to_string())
            })?;
        let architecture = match self.sources.architecture_override {
            Some(value) => value,
            None => host_architecture()?,
        };
        let boot_platform = self.sources.boot_platform_override.unwrap_or_else(|| {
            if self.sources.pi_boot_partition.exists() {
                BootPlatform::RaspberryPi
            } else {
                BootPlatform::Uefi
            }
        });
        Ok(ReleaseTarget {
            image_id,
            architecture,
            boot_platform,
            channel,
        })
    }

    fn cache_is_fresh(&self) -> bool {
        self.sources.cached_channel.is_file()
            && self.sources.cached_signature.is_file()
            && file_age_seconds(&self.sources.cached_channel)
                .is_some_and(|age| age <= self.sources.cache_max_age_seconds)
    }
}

fn check_result(
    metadata: punar_common::update::ChannelMetadata,
    current: ReleaseVersion,
    device_id: &str,
    metadata_age_seconds: u64,
    cached: bool,
) -> UpdateCheckResult {
    let in_cohort = cohort_bucket(device_id, metadata.current) < metadata.rollout_bps;
    let (available, admissible, reason) = if metadata.current <= current {
        (
            None,
            false,
            Some("the running release is already at or newer than the channel head".into()),
        )
    } else if metadata.halted {
        (
            Some(metadata.current),
            false,
            Some("the signed channel is halted; Punar will not stage this release".into()),
        )
    } else if current < metadata.min_supported_version {
        (
            Some(metadata.current),
            false,
            Some("the running release is older than the signed channel minimum".into()),
        )
    } else if !in_cohort {
        (
            Some(metadata.current),
            false,
            Some("this device is outside the current signed rollout cohort".into()),
        )
    } else {
        (Some(metadata.current), true, None)
    };
    UpdateCheckResult {
        v: 1,
        channel: metadata.channel,
        current,
        available,
        in_cohort,
        halted: metadata.halted,
        admissible,
        reason,
        metadata_age_seconds,
        cached,
    }
}

fn host_architecture() -> Result<Architecture, UpdateCheckError> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(Architecture::X86_64),
        "aarch64" => Ok(Architecture::Aarch64),
        other => Err(UpdateCheckError::LocalIdentity(format!(
            "architecture {other:?} is not supported by the update target contract"
        ))),
    }
}

fn read_source(path: &Path, max_bytes: u64) -> Result<Vec<u8>, UpdateCheckError> {
    read_bounded(path, max_bytes).map_err(UpdateCheckError::SourceUnavailable)
}

fn read_cache(path: &Path, max_bytes: u64) -> Result<Vec<u8>, UpdateTrustError> {
    read_bounded(path, max_bytes)
        .map_err(|reason| UpdateTrustError::Io(io::Error::new(io::ErrorKind::InvalidData, reason)))
}

fn untrusted(stage: &'static str, error: UpdateTrustError) -> UpdateCheckError {
    UpdateCheckError::Untrusted {
        stage,
        reason: error.to_string(),
    }
}

fn require_target(
    actual: &str,
    expected: &str,
    field: &'static str,
) -> Result<(), UpdateCheckError> {
    if actual == expected {
        Ok(())
    } else {
        Err(untrusted(
            "channel_target",
            UpdateTrustError::TargetMismatch { field },
        ))
    }
}

fn require_equal<T: Eq>(
    actual: T,
    expected: T,
    field: &'static str,
) -> Result<(), UpdateCheckError> {
    if actual == expected {
        Ok(())
    } else {
        Err(untrusted(
            "channel_target",
            UpdateTrustError::TargetMismatch { field },
        ))
    }
}

fn file_age_seconds(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .elapsed()
        .ok()
        .map(|age| age.as_secs())
}

fn ensure_private_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cache path has no parent"))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "punar-update-check-{name}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn sources(root: &Path) -> UpdateCheckSources {
        UpdateCheckSources {
            repository_dir: root.join("repository"),
            trusted_keys_dir: root.join("keys"),
            cached_channel: root.join("state/verified-channel.json"),
            cached_signature: root.join("state/verified-channel.json.sig"),
            os_release: root.join("os-release"),
            pi_boot_partition: root.join("pi-partition"),
            cache_max_age_seconds: DEFAULT_CACHE_MAX_AGE,
            architecture_override: Some(Architecture::Aarch64),
            boot_platform_override: Some(BootPlatform::Uefi),
        }
    }

    fn fixture(root: &Path) -> (UpdateCheckEngine, SigningKey) {
        let paths = sources(root);
        fs::create_dir_all(&paths.repository_dir).unwrap();
        fs::create_dir_all(&paths.trusted_keys_dir).unwrap();
        fs::write(
            &paths.os_release,
            "IMAGE_ID=punar-desktop\nIMAGE_VERSION=2026.08.20.1\n",
        )
        .unwrap();
        let signing = SigningKey::from_bytes(&[31; 32]);
        fs::write(
            paths.trusted_keys_dir.join("test.pub"),
            signing.verifying_key().to_bytes(),
        )
        .unwrap();
        let document = include_bytes!("../../../fixtures/update/valid/channel-metadata.json");
        fs::write(paths.repository_dir.join("channel.json"), document).unwrap();
        fs::write(
            paths.repository_dir.join("channel.json.sig"),
            signing.sign(document).to_bytes(),
        )
        .unwrap();
        (UpdateCheckEngine::new(paths), signing)
    }

    #[test]
    fn verifies_target_and_caches_only_authenticated_metadata() {
        let root = root("valid");
        let (engine, _) = fixture(&root);
        let first = engine
            .check(UpdateChannel::Stable, "dev_00123", false)
            .unwrap();
        assert!(!first.cached);
        assert_eq!(first.available.unwrap().to_string(), "2026.08.27.1");
        assert!(engine.sources.cached_channel.is_file());
        assert!(engine.sources.cached_signature.is_file());

        fs::remove_file(engine.sources.repository_dir.join("channel.json")).unwrap();
        let cached = engine
            .check(UpdateChannel::Stable, "dev_00123", false)
            .unwrap();
        assert!(cached.cached);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn force_requires_the_source_and_tampering_never_reaches_cache() {
        let root = root("tamper");
        let (engine, _) = fixture(&root);
        let document_path = engine.sources.repository_dir.join("channel.json");
        let mut document = fs::read(&document_path).unwrap();
        document[20] ^= 1;
        fs::write(&document_path, document).unwrap();
        let error = engine
            .check(UpdateChannel::Stable, "dev_00123", true)
            .unwrap_err();
        assert!(error.is_untrusted());
        assert!(!engine.sources.cached_channel.exists());
        assert!(!engine.sources.cached_signature.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cross_channel_document_is_untrusted() {
        let root = root("cross-channel");
        let (engine, _) = fixture(&root);
        let error = engine
            .check(UpdateChannel::Edge, "dev_00123", true)
            .unwrap_err();
        assert!(error.is_untrusted());
        assert_eq!(error.stage(), "channel_target");
        fs::remove_dir_all(root).unwrap();
    }
}
