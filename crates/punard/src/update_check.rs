//! Authenticated, fail-closed update-channel discovery.
//!
//! `update.check` accepts only a `force` bit. Origins, paths, keys, target
//! identity and rollout identity all come from root-owned daemon state. The
//! network source is a root-owned HTTPS base URL. If it is absent, a fixed
//! directory transport remains available for offline recovery media and CI.
//! Neither transport lets the caller choose an origin, path or trust key.
//!
//! The verified cache answers a non-forced check for 15 minutes, and that
//! age is measured on the boot clock (SMP-1405) from the moment the fetch
//! began, never from the file's mtime against the wall clock: a clock stepped
//! back could otherwise keep serving a stale "nothing newer" long after a
//! release shipped. The stamp lives in memory, so a punard restart, a
//! suspend or a reboot simply fetches again.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use punar_common::trusted_time::{BootStamp, BootWindow, SystemClock, TrustedClock, elapsed_ms};
use punar_common::update::{
    Architecture, BootPlatform, ReleaseKeySet, ReleaseManifest, ReleaseTarget, ReleaseVersion,
    UpdateChannel, UpdateCheckResult, UpdateSlot, UpdateTrustError, cohort_bucket,
    verify_channel_metadata, verify_reader, verify_release_manifest,
};
use thiserror::Error;

use crate::fetch::{DEFAULT_FETCH_SOCKET, FetchClient, FetchRequest, validate_https_url};
use crate::update_status::{read_bounded, read_os_release};
use crate::util::write_atomic_synced;

const CHANNEL_DOCUMENT_MAX: u64 = 64 * 1024;
const SIGNATURE_MAX: u64 = 64;
const REPOSITORY_URL_MAX: u64 = 2048;
const DEFAULT_CACHE_MAX_AGE: u64 = 15 * 60;
/// A channel document or signature: the whole transfer, connection included.
const HTTPS_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// A release payload or boot artifact.
const RELEASE_FETCH_TIMEOUT: Duration = Duration::from_secs(3500);
const RELEASE_DOCUMENT_MAX: u64 = 1024 * 1024;
static FETCH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct UpdateCheckSources {
    /// Optional root-owned HTTPS base URL. When present, it is authoritative:
    /// an invalid or unreachable network source never downgrades to local media.
    pub repository_url_file: PathBuf,
    /// Expected owner of `repository_url_file` (root in production; injectable
    /// only so unprivileged contract tests can exercise the same checks).
    pub repository_url_owner_uid: u32,
    /// Fixed local transport root used only when `repository_url_file` is absent.
    pub repository_dir: PathBuf,
    /// The unprivileged download helper's socket (`punar-fetch.socket`).
    /// punard never runs a downloader itself: it hands the helper a private
    /// staging descriptor and verifies what arrives in it (crate::fetch).
    pub fetch_socket: PathBuf,
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
            repository_url_file: PathBuf::from("/etc/punar/update-repository.url"),
            repository_url_owner_uid: 0,
            repository_dir: PathBuf::from("/run/punar/update-source"),
            fetch_socket: PathBuf::from(DEFAULT_FETCH_SOCKET),
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
    #[error(
        "the private update cache has {available_bytes} bytes available but {required_bytes} are required"
    )]
    InsufficientSpace {
        required_bytes: u64,
        available_bytes: u64,
    },
}

impl UpdateCheckError {
    pub fn stage(&self) -> &'static str {
        match self {
            Self::SourceUnavailable(_) => "channel_fetch",
            Self::Untrusted { stage, .. } => stage,
            Self::LocalIdentity(_) => "local_identity",
            Self::Cache(_) => "verified_cache",
            Self::InsufficientSpace { .. } => "release_cache_space",
        }
    }

    pub fn is_unreachable(&self) -> bool {
        matches!(self, Self::SourceUnavailable(_))
    }

    pub fn is_untrusted(&self) -> bool {
        matches!(self, Self::Untrusted { .. })
    }

    pub fn insufficient_space(&self) -> Option<(u64, u64)> {
        match self {
            Self::InsufficientSpace {
                required_bytes,
                available_bytes,
            } => Some((*required_bytes, *available_bytes)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PreparedRelease {
    pub release_dir: PathBuf,
    pub manifest: ReleaseManifest,
}

pub struct UpdateCheckEngine {
    sources: UpdateCheckSources,
    /// The boot clock the cache's age is measured on.
    clock: Arc<dyn TrustedClock>,
    /// When this engine last wrote a verified channel document, on the boot
    /// clock. `None` — never, since this punard started, or the clock could
    /// not be read — means the cache is not fresh and the next check
    /// fetches.
    verified_at: Mutex<Option<BootStamp>>,
}

impl UpdateCheckEngine {
    /// An engine reading the machine's own boot clock.
    pub fn new(sources: UpdateCheckSources) -> Self {
        Self::with_clock(sources, Arc::new(SystemClock::new()))
    }

    /// An engine measuring cache age on `clock` (punard passes its own).
    pub fn with_clock(sources: UpdateCheckSources, clock: Arc<dyn TrustedClock>) -> Self {
        Self {
            sources,
            clock,
            verified_at: Mutex::new(None),
        }
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

        let fresh_age = if force { None } else { self.fresh_cache_age() };
        let cached = fresh_age.is_some();
        // The cache's age starts BEFORE the fetch, not after it: a slow
        // network (up to the downloader's timeout) must not add its own
        // duration to the 15 minutes a "nothing newer" answer is reused for.
        // Stored only once the verified bytes are safely on disk.
        let fetch_started = if cached { None } else { self.clock.now() };
        let (document, signature, metadata_age_seconds) = if let Some(age) = fresh_age {
            let document = read_cache(&self.sources.cached_channel, CHANNEL_DOCUMENT_MAX)
                .map_err(|error| untrusted("cached_metadata", error))?;
            let signature = read_cache(&self.sources.cached_signature, SIGNATURE_MAX)
                .map_err(|error| untrusted("cached_signature", error))?;
            (document, signature, age)
        } else {
            let (document, signature) = self.fetch_fresh(&target)?;
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
            // The previous freshness stamp stops vouching for the files the
            // moment they start to change, so a write that fails halfway
            // leaves the cache stale rather than fresh and mismatched.
            *self.verified_at.lock().unwrap_or_else(|e| e.into_inner()) = None;
            ensure_private_parent(&self.sources.cached_channel)
                .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
            ensure_private_parent(&self.sources.cached_signature)
                .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
            write_atomic_synced(&self.sources.cached_signature, &signature, 0o600)
                .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
            write_atomic_synced(&self.sources.cached_channel, &document, 0o600)
                .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
            *self.verified_at.lock().unwrap_or_else(|e| e.into_inner()) = fetch_started;
        }

        Ok(check_result(
            metadata,
            current,
            device_id,
            metadata_age_seconds,
            cached,
        ))
    }

    /// Resolve and cache the exact release named by the already-verified
    /// channel head. Every origin and path is derived from root-owned state
    /// and signed metadata; the IPC caller contributes only the version it
    /// expects to stage.
    pub fn prepare_release(
        &self,
        channel: UpdateChannel,
        device_id: &str,
        requested: ReleaseVersion,
        allow_downgrade: bool,
        requested_slot: Option<UpdateSlot>,
    ) -> Result<PreparedRelease, UpdateCheckError> {
        let current = self.current_version()?;
        let target = self.release_target(channel)?;
        let keys = ReleaseKeySet::load_dir(&self.sources.trusted_keys_dir)
            .map_err(|error| untrusted("trusted_keys", error))?;
        let channel_document = read_cache(&self.sources.cached_channel, CHANNEL_DOCUMENT_MAX)
            .map_err(|error| untrusted("cached_metadata", error))?;
        let channel_signature = read_cache(&self.sources.cached_signature, SIGNATURE_MAX)
            .map_err(|error| untrusted("cached_signature", error))?;
        let metadata = verify_channel_metadata(&channel_document, &channel_signature, &keys)
            .map_err(|error| untrusted("channel_signature", error))?;
        require_target(&metadata.image_id, &target.image_id, "image_id")?;
        require_equal(metadata.architecture, target.architecture, "architecture")?;
        require_equal(
            metadata.boot_platform,
            target.boot_platform,
            "boot_platform",
        )?;
        require_equal(metadata.channel, target.channel, "channel")?;
        if metadata.current != requested {
            return Err(UpdateCheckError::Untrusted {
                stage: "channel_version",
                reason: "the requested version is not the verified channel head".into(),
            });
        }
        if metadata.halted
            || current < metadata.min_supported_version
            || cohort_bucket(device_id, metadata.current) >= metadata.rollout_bps
            || !allow_downgrade && metadata.current <= current
        {
            return Err(UpdateCheckError::Untrusted {
                stage: "channel_admission",
                reason: "the verified channel does not admit this release on this device".into(),
            });
        }

        let manifest_path = Path::new(&metadata.release_manifest);
        let signature_path = PathBuf::from(format!("{}.sig", metadata.release_manifest));
        let manifest_document = self.fetch_repository_bytes(
            &target,
            manifest_path,
            RELEASE_DOCUMENT_MAX,
            "release manifest",
        )?;
        let manifest_signature = self.fetch_repository_bytes(
            &target,
            &signature_path,
            SIGNATURE_MAX,
            "release signature",
        )?;
        let manifest = verify_release_manifest(&manifest_document, &manifest_signature, &keys)
            .map_err(|error| untrusted("manifest_signature", error))?;
        manifest
            .admit(&target, current, allow_downgrade)
            .map_err(|error| untrusted("manifest_admission", error))?;
        if manifest.version != requested {
            return Err(UpdateCheckError::Untrusted {
                stage: "manifest_version",
                reason: "the signed manifest version does not match the verified channel head"
                    .into(),
            });
        }
        let (payload, boot_artifact) = match manifest.boot_platform {
            BootPlatform::Uefi => manifest
                .artifacts_for_slot(requested_slot.unwrap_or(UpdateSlot::Unknown))
                .ok_or_else(|| UpdateCheckError::Untrusted {
                    stage: "slot_artifacts",
                    reason: "the signed release does not contain the requested UEFI slot pair"
                        .into(),
                })?,
            BootPlatform::RaspberryPi => (&manifest.payload, &manifest.boot_artifact),
        };

        let cache_parent =
            self.sources.cached_channel.parent().ok_or_else(|| {
                UpdateCheckError::Cache("verified channel path has no parent".into())
            })?;
        let release_dir = cache_parent
            .join("releases")
            .join(manifest.version.to_string());
        ensure_private_dir(&release_dir)
            .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
        write_atomic_synced(
            &release_dir.join("release.json.sig"),
            &manifest_signature,
            0o600,
        )
        .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
        write_atomic_synced(&release_dir.join("release.json"), &manifest_document, 0o600)
            .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;

        let required = payload
            .size_bytes
            .checked_add(boot_artifact.size_bytes)
            .ok_or_else(|| UpdateCheckError::Cache("release cache size overflow".into()))?;
        let available = available_bytes(&release_dir)
            .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
        let already_cached = [
            (&payload.filename, payload.size_bytes),
            (&boot_artifact.filename, boot_artifact.size_bytes),
        ]
        .iter()
        .filter_map(|(name, expected)| {
            fs::metadata(release_dir.join(name))
                .ok()
                .filter(|metadata| metadata.file_type().is_file() && metadata.len() == *expected)
                .map(|_| *expected)
        })
        .sum::<u64>();
        let still_required = required.saturating_sub(already_cached);
        if available < still_required {
            return Err(UpdateCheckError::InsufficientSpace {
                required_bytes: still_required,
                available_bytes: available,
            });
        }

        let release_parent = manifest_path.parent().unwrap_or_else(|| Path::new(""));
        self.fetch_verified_artifact(
            &target,
            &release_parent.join(&payload.filename),
            &release_dir.join(&payload.filename),
            &payload.digest_sha256,
            payload.size_bytes,
            "compressed release payload",
        )?;
        self.fetch_verified_artifact(
            &target,
            &release_parent.join(&boot_artifact.filename),
            &release_dir.join(&boot_artifact.filename),
            &boot_artifact.digest_sha256,
            boot_artifact.size_bytes,
            "release boot artifact",
        )?;
        Ok(PreparedRelease {
            release_dir,
            manifest,
        })
    }

    pub(crate) fn current_version(&self) -> Result<ReleaseVersion, UpdateCheckError> {
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

    pub(crate) fn release_target(
        &self,
        channel: UpdateChannel,
    ) -> Result<ReleaseTarget, UpdateCheckError> {
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

    pub(crate) fn trusted_keys_dir(&self) -> &Path {
        &self.sources.trusted_keys_dir
    }

    /// The verified cache's age in whole seconds while it may still answer a
    /// non-forced check, or `None` when it must not: files missing, never
    /// written by this engine, another boot, a clock that went backwards or
    /// cannot be read, or older than `cache_max_age_seconds` less the drift
    /// allowance. All on the boot clock; the wall clock and the files'
    /// mtimes are not inputs.
    fn fresh_cache_age(&self) -> Option<u64> {
        if !self.sources.cached_channel.is_file() || !self.sources.cached_signature.is_file() {
            return None;
        }
        let verified_at = self
            .verified_at
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()?;
        let now = self.clock.now()?;
        let window = BootWindow::of_secs(verified_at.clone(), self.sources.cache_max_age_seconds);
        if !window.is_open(Some(&now)) {
            return None;
        }
        u64::try_from(elapsed_ms(&verified_at, &now)? / 1_000).ok()
    }

    fn fetch_fresh(&self, target: &ReleaseTarget) -> Result<(Vec<u8>, Vec<u8>), UpdateCheckError> {
        match fs::symlink_metadata(&self.sources.repository_url_file) {
            Ok(_) => {
                // Any directory entry is authoritative, including an invalid
                // symlink. `read_repository_base_url` opens with O_NOFOLLOW;
                // treating a broken link as "absent" would silently downgrade
                // a configured device to removable-media transport.
                let base = read_repository_base_url(
                    &self.sources.repository_url_file,
                    self.sources.repository_url_owner_uid,
                )?;
                let prefix = format!(
                    "{base}/{}/{}/{}",
                    target.channel, target.architecture, target.boot_platform
                );
                let document = self.fetch_https(
                    &format!("{prefix}/channel.json"),
                    CHANNEL_DOCUMENT_MAX,
                    "channel metadata",
                )?;
                let signature = self.fetch_https(
                    &format!("{prefix}/channel.json.sig"),
                    SIGNATURE_MAX,
                    "channel signature",
                )?;
                Ok((document, signature))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let document = read_source(
                    &self.sources.repository_dir.join("channel.json"),
                    CHANNEL_DOCUMENT_MAX,
                )?;
                let signature = read_source(
                    &self.sources.repository_dir.join("channel.json.sig"),
                    SIGNATURE_MAX,
                )?;
                Ok((document, signature))
            }
            Err(error) => Err(source_configuration(
                &self.sources.repository_url_file,
                error.to_string(),
            )),
        }
    }

    fn fetch_https(
        &self,
        url: &str,
        max_bytes: u64,
        description: &str,
    ) -> Result<Vec<u8>, UpdateCheckError> {
        ensure_private_parent(&self.sources.cached_channel)
            .map_err(|error| UpdateCheckError::SourceUnavailable(error.to_string()))?;
        let parent = self.sources.cached_channel.parent().ok_or_else(|| {
            UpdateCheckError::SourceUnavailable("update cache path has no parent".to_string())
        })?;
        let temporary = parent.join(format!(
            ".fetch-{}-{}",
            std::process::id(),
            FETCH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let staged = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| {
                UpdateCheckError::SourceUnavailable(format!(
                    "could not create a private HTTPS staging file: {error}"
                ))
            })?;

        let fetched = FetchClient::new(&self.sources.fetch_socket).fetch(
            &FetchRequest::update(url, max_bytes, HTTPS_FETCH_TIMEOUT),
            &staged,
        );
        drop(staged);
        let bytes = match fetched {
            Ok(_) => read_source(&temporary, max_bytes),
            Err(error) => Err(UpdateCheckError::SourceUnavailable(format!(
                "HTTPS {description} download failed: {error}"
            ))),
        };
        let _ = fs::remove_file(&temporary);
        bytes
    }

    fn fetch_repository_bytes(
        &self,
        target: &ReleaseTarget,
        relative: &Path,
        maximum: u64,
        description: &str,
    ) -> Result<Vec<u8>, UpdateCheckError> {
        let relative = relative
            .to_str()
            .ok_or_else(|| UpdateCheckError::Untrusted {
                stage: "repository_path",
                reason: "signed repository path is not UTF-8".into(),
            })?;
        match fs::symlink_metadata(&self.sources.repository_url_file) {
            Ok(_) => {
                let base = read_repository_base_url(
                    &self.sources.repository_url_file,
                    self.sources.repository_url_owner_uid,
                )?;
                let prefix = format!(
                    "{base}/{}/{}/{}",
                    target.channel, target.architecture, target.boot_platform
                );
                self.fetch_https(&format!("{prefix}/{relative}"), maximum, description)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                read_source(&self.sources.repository_dir.join(relative), maximum)
            }
            Err(error) => Err(source_configuration(
                &self.sources.repository_url_file,
                error.to_string(),
            )),
        }
    }

    fn fetch_verified_artifact(
        &self,
        target: &ReleaseTarget,
        relative: &Path,
        destination: &Path,
        digest: &str,
        size: u64,
        description: &str,
    ) -> Result<(), UpdateCheckError> {
        if verify_cached_artifact(destination, digest, size).is_ok() {
            return Ok(());
        }
        let temporary = destination.with_extension(format!(
            "download-{}-{}",
            std::process::id(),
            FETCH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let fetched = match fs::symlink_metadata(&self.sources.repository_url_file) {
            Ok(_) => {
                let base = read_repository_base_url(
                    &self.sources.repository_url_file,
                    self.sources.repository_url_owner_uid,
                )?;
                let relative = relative
                    .to_str()
                    .ok_or_else(|| UpdateCheckError::Untrusted {
                        stage: "repository_path",
                        reason: "signed artifact path is not UTF-8".into(),
                    })?;
                let url = format!(
                    "{base}/{}/{}/{}/{relative}",
                    target.channel, target.architecture, target.boot_platform
                );
                self.fetch_https_file(&url, &temporary, size, description)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => copy_private_file(
                &self.sources.repository_dir.join(relative),
                &temporary,
                size,
            )
            .map_err(|error| UpdateCheckError::SourceUnavailable(error.to_string())),
            Err(error) => Err(source_configuration(
                &self.sources.repository_url_file,
                error.to_string(),
            )),
        };
        if let Err(error) = fetched {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = verify_cached_artifact(&temporary, digest, size) {
            let _ = fs::remove_file(&temporary);
            return Err(untrusted("payload_digest", error));
        }
        fs::rename(&temporary, destination)
            .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
        FileSync::parent(destination).map_err(|error| UpdateCheckError::Cache(error.to_string()))
    }

    fn fetch_https_file(
        &self,
        url: &str,
        destination: &Path,
        size: u64,
        description: &str,
    ) -> Result<(), UpdateCheckError> {
        // The helper must never choose the permissions of a cached release
        // artifact, and it cannot: it receives only this descriptor, opened
        // here with the same private mode as the surrounding cache, on a
        // path that must not already exist.
        let staged = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination)
            .map_err(|error| UpdateCheckError::Cache(error.to_string()))?;
        FetchClient::new(&self.sources.fetch_socket)
            .fetch(
                &FetchRequest::update(url, size, RELEASE_FETCH_TIMEOUT),
                &staged,
            )
            .map(|_| ())
            .map_err(|error| {
                UpdateCheckError::SourceUnavailable(format!(
                    "HTTPS {description} download failed: {error}"
                ))
            })
    }
}

struct FileSync;

impl FileSync {
    fn parent(path: &Path) -> io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("path has no parent"))?;
        fs::File::open(parent)?.sync_all()
    }
}

fn ensure_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn available_bytes(path: &Path) -> io::Result<u64> {
    let stat = rustix::fs::statvfs(path).map_err(io::Error::from)?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

fn verify_cached_artifact(path: &Path, digest: &str, size: u64) -> Result<(), UpdateTrustError> {
    let mut file = fs::File::open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(UpdateTrustError::Io(io::Error::other(
            "cached artifact is not a regular file",
        )));
    }
    verify_reader(&mut file, digest, size)
}

fn copy_private_file(source: &Path, destination: &Path, expected: u64) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(flags.bits()).expect("open flags fit libc::c_int"))
        .open(source)?;
    if !input.metadata()?.file_type().is_file() || input.metadata()?.len() != expected {
        return Err(io::Error::other(
            "repository artifact has the wrong type or size",
        ));
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    io::copy(&mut input, &mut output)?;
    output.flush()?;
    output.sync_all()
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

fn read_repository_base_url(path: &Path, expected_uid: u32) -> Result<String, UpdateCheckError> {
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(flags.bits()).expect("open flags fit libc::c_int"))
        .open(path)
        .map_err(|error| source_configuration(path, error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| source_configuration(path, error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(source_configuration(path, "it is not a regular file"));
    }
    if metadata.uid() != expected_uid || metadata.mode() & 0o022 != 0 {
        return Err(source_configuration(
            path,
            format!("it must be owned by uid {expected_uid} and not be group/other writable"),
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(REPOSITORY_URL_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| source_configuration(path, error.to_string()))?;
    if bytes.len() as u64 > REPOSITORY_URL_MAX {
        return Err(source_configuration(path, "it exceeds 2048 bytes"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| source_configuration(path, "it is not UTF-8"))?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    let line = line.strip_suffix('\r').unwrap_or(line);
    validate_repository_base_url(line).map_err(|reason| source_configuration(path, reason))
}

fn source_configuration(path: &Path, reason: impl Into<String>) -> UpdateCheckError {
    UpdateCheckError::SourceUnavailable(format!(
        "HTTPS repository configuration {} is invalid: {}",
        path.display(),
        reason.into()
    ))
}

/// The base URL is held to the same rule the download helper applies to
/// every update URL beneath it (crate::fetch), so a base punard accepts can
/// never produce a URL the helper refuses.
fn validate_repository_base_url(value: &str) -> Result<String, &'static str> {
    validate_https_url(value)
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

    /// Every engine here downloads through the real helper protocol: a
    /// helper thread runs `crate::fetch::serve`, the function the shipped
    /// `punar-fetch` runs, with `root/curl` as its downloader. Tests write
    /// that fixture downloader; it prints the body on standard output.
    fn sources(root: &Path) -> UpdateCheckSources {
        let fetch_socket = root.join("fetch.sock");
        crate::fetch::testing::spawn_helper(&fetch_socket, &root.join("curl"));
        UpdateCheckSources {
            repository_url_file: root.join("update-repository.url"),
            repository_url_owner_uid: rustix::process::geteuid().as_raw(),
            repository_dir: root.join("repository"),
            fetch_socket,
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

    /// A clock whose raw time is whatever a file says, so a fake downloader
    /// — another process — can let time pass in the middle of a fetch.
    #[derive(Debug)]
    struct FileClock(PathBuf);

    impl TrustedClock for FileClock {
        fn now(&self) -> Option<BootStamp> {
            let raw_bt_ms = fs::read_to_string(&self.0).ok()?.trim().parse().ok()?;
            Some(BootStamp {
                boot_id: "0f2a6c1e-7d3b-4a59-9c8e-1b2d3e4f5a6b".to_string(),
                raw_bt_ms,
                sleep_ms: 0,
                suspends: 0,
            })
        }
    }

    /// The cache's age starts when the fetch STARTS. A fetch that takes 20 s
    /// must not buy the cached answer 20 s more than its 15 minutes, nor
    /// report itself 20 s younger than it is.
    #[test]
    fn the_cache_ages_from_the_start_of_the_fetch() {
        use punar_common::trusted_time::live_budget_ms;

        let root = root("slow-fetch");
        let (engine, _) = fixture(&root);
        let now_file = root.join("raw-bt-ms");
        fs::write(&now_file, "1000").unwrap();
        fs::write(
            &engine.sources.repository_url_file,
            "https://updates.example.test/punar/\n",
        )
        .unwrap();
        fs::set_permissions(
            &engine.sources.repository_url_file,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        // The document download takes 20 s on the boot clock.
        let curl = &root.join("curl");
        fs::write(
            curl,
            format!(
                "#!/bin/sh\nfor url in \"$@\"; do :; done\ncase \"$url\" in\n  *.sig) cat '{}' ;;\n  *.json) echo 21000 > '{}'; cat '{}' ;;\n  *) exit 2 ;;\nesac\n",
                engine
                    .sources
                    .repository_dir
                    .join("channel.json.sig")
                    .display(),
                now_file.display(),
                engine
                    .sources
                    .repository_dir
                    .join("channel.json")
                    .display(),
            ),
        )
        .unwrap();
        fs::set_permissions(curl, fs::Permissions::from_mode(0o755)).unwrap();
        let engine = UpdateCheckEngine::with_clock(
            engine.sources.clone(),
            Arc::new(FileClock(now_file.clone())),
        );

        assert!(
            !engine
                .check(UpdateChannel::Stable, "dev_00123", false)
                .unwrap()
                .cached
        );
        // Just after the fetch returned: already 20 s old.
        let cached = engine
            .check(UpdateChannel::Stable, "dev_00123", false)
            .unwrap();
        assert!(cached.cached);
        assert_eq!(cached.metadata_age_seconds, 20);
        // The window closes at its budget from the START of the fetch.
        let budget = live_budget_ms(DEFAULT_CACHE_MAX_AGE as i64 * 1_000);
        fs::write(&now_file, (1_000 + budget - 1).to_string()).unwrap();
        assert!(
            engine
                .check(UpdateChannel::Stable, "dev_00123", false)
                .unwrap()
                .cached
        );
        fs::write(&now_file, (1_000 + budget).to_string()).unwrap();
        assert!(
            !engine
                .check(UpdateChannel::Stable, "dev_00123", false)
                .unwrap()
                .cached,
            "stale at the budget from the start of the fetch, not its end"
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// The cache's 15 minutes are measured on the boot clock (SMP-1405): the
    /// edge is the drift-shortened budget, and a reboot or an unreadable
    /// clock sends the next check back to the source. The files' mtimes are
    /// not consulted, so stepping the wall clock back revives nothing.
    #[test]
    fn the_cache_ages_on_the_boot_clock_and_not_by_mtime() {
        use punar_common::trusted_time::{ManualClock, live_budget_ms};

        let root = root("boot-clock");
        let (engine, _) = fixture(&root);
        let clock = Arc::new(ManualClock::new(
            "0f2a6c1e-7d3b-4a59-9c8e-1b2d3e4f5a6b",
            1_000,
        ));
        let engine = UpdateCheckEngine::with_clock(engine.sources.clone(), clock.clone());
        let check = || {
            engine
                .check(UpdateChannel::Stable, "dev_00123", false)
                .unwrap()
        };

        assert!(!check().cached, "nothing verified yet in this boot");
        let budget = live_budget_ms(DEFAULT_CACHE_MAX_AGE as i64 * 1_000);
        clock.advance_ms(budget - 1);
        let cached = check();
        assert!(cached.cached);
        assert_eq!(cached.metadata_age_seconds, 899);

        // An mtime from 1970 changes nothing either way.
        let file = fs::File::options()
            .write(true)
            .open(&engine.sources.cached_channel)
            .unwrap();
        file.set_modified(std::time::UNIX_EPOCH).unwrap();
        drop(file);
        assert!(check().cached);

        clock.advance_ms(1);
        assert!(!check().cached, "the budget itself is stale");
        // That check re-fetched and re-stamped the cache.
        assert!(check().cached);

        clock.reboot("9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b", 1_000);
        assert!(
            !check().cached,
            "a cache verified in another boot is not fresh"
        );

        clock.set(None);
        assert!(
            !check().cached,
            "an unreadable clock never serves the cache"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn https_artifact_destination_is_private_before_the_downloader_runs() {
        let root = root("https-mode");
        let paths = sources(&root);
        let curl = root.join("curl");
        fs::write(&curl, "#!/bin/sh\nprintf data\n").unwrap();
        fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();
        let engine = UpdateCheckEngine::new(paths);
        let destination = root.join("artifact.new");
        engine
            .fetch_https_file(
                "https://updates.example.test/artifact",
                &destination,
                4,
                "test artifact",
            )
            .unwrap();
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&destination).unwrap(), b"data");
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

    #[test]
    fn https_source_uses_fixed_privacy_preserving_paths_and_caches_verified_bytes() {
        let root = root("https");
        let (engine, _) = fixture(&root);
        fs::write(
            &engine.sources.repository_url_file,
            "https://updates.example.test/punar/\n",
        )
        .unwrap();
        fs::set_permissions(
            &engine.sources.repository_url_file,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let log = root.join("curl-argv");
        let curl = &root.join("curl");
        fs::write(
            curl,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nfor url in \"$@\"; do :; done\ncase \"$url\" in\n  *.sig) cat '{}' ;;\n  *.json) cat '{}' ;;\n  *) exit 2 ;;\nesac\n",
                log.display(),
                engine
                    .sources
                    .repository_dir
                    .join("channel.json.sig")
                    .display(),
                engine
                    .sources
                    .repository_dir
                    .join("channel.json")
                    .display(),
            ),
        )
        .unwrap();
        fs::set_permissions(curl, fs::Permissions::from_mode(0o755)).unwrap();

        let result = engine
            .check(UpdateChannel::Stable, "dev_00123", true)
            .unwrap();
        assert!(!result.cached);
        assert!(engine.sources.cached_channel.is_file());
        assert!(engine.sources.cached_signature.is_file());
        let argv = fs::read_to_string(log).unwrap();
        assert!(argv.contains("--disable"));
        assert!(argv.contains("--proto\n=https"));
        assert!(argv.contains("--max-redirs\n0"));
        assert!(argv.contains("--tlsv1.2"));
        assert!(
            argv.contains("https://updates.example.test/punar/stable/aarch64/uefi/channel.json\n")
        );
        assert!(
            argv.contains(
                "https://updates.example.test/punar/stable/aarch64/uefi/channel.json.sig\n"
            )
        );
        assert!(!argv.contains("dev_00123"));
        assert!(!argv.contains("2026.08.20.1"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn configured_https_source_never_downgrades_to_local_media() {
        let root = root("https-no-downgrade");
        let (engine, _) = fixture(&root);
        fs::write(
            &engine.sources.repository_url_file,
            "http://updates.example.test/punar\n",
        )
        .unwrap();
        fs::set_permissions(
            &engine.sources.repository_url_file,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let error = engine
            .check(UpdateChannel::Stable, "dev_00123", true)
            .unwrap_err();
        assert!(error.is_unreachable());
        assert!(error.to_string().contains("only an https:// URL"));
        assert!(!engine.sources.cached_channel.exists());
        assert!(!engine.sources.cached_signature.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_repository_symlink_never_downgrades_to_local_media() {
        let root = root("https-symlink-no-downgrade");
        let (engine, _) = fixture(&root);
        std::os::unix::fs::symlink(
            root.join("missing-repository-url"),
            &engine.sources.repository_url_file,
        )
        .unwrap();

        let error = engine
            .check(UpdateChannel::Stable, "dev_00123", true)
            .unwrap_err();
        assert!(error.is_unreachable());
        assert!(error.to_string().contains("configuration"));
        assert!(!engine.sources.cached_channel.exists());
        assert!(!engine.sources.cached_signature.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_https_response_is_refused_before_signature_or_cache() {
        let root = root("https-oversized");
        let (engine, _) = fixture(&root);
        fs::write(
            &engine.sources.repository_url_file,
            "https://updates.example.test\n",
        )
        .unwrap();
        fs::set_permissions(
            &engine.sources.repository_url_file,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let oversized = root.join("oversized");
        fs::write(&oversized, vec![b'x'; CHANNEL_DOCUMENT_MAX as usize + 1]).unwrap();
        let curl = root.join("curl");
        fs::write(&curl, format!("#!/bin/sh\ncat '{}'\n", oversized.display())).unwrap();
        fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();

        let error = engine
            .check(UpdateChannel::Stable, "dev_00123", true)
            .unwrap_err();
        assert!(error.is_unreachable());
        assert!(!engine.sources.cached_channel.exists());
        assert!(!engine.sources.cached_signature.exists());
        assert!(
            !engine
                .sources
                .cached_channel
                .parent()
                .unwrap()
                .read_dir()
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".fetch-"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn repository_url_validation_rejects_ambiguous_and_unsafe_forms() {
        assert_eq!(
            validate_repository_base_url("https://updates.example.test/releases-v1/").unwrap(),
            "https://updates.example.test/releases-v1"
        );
        assert!(validate_repository_base_url("https://updates.example.test:8443").is_ok());
        for invalid in [
            "http://updates.example.test",
            "https://user@updates.example.test",
            "https://updates.example.test?channel=edge",
            "https://updates.example.test/#fragment",
            "https://updates.example.test/%2e%2e",
            "https://updates.example.test/../private",
            "https://updates.example.test//nested",
            "https://[::1]",
            "https://updates.example.test:0",
            "https:// updates.example.test",
            "https://updates.example.test\nhttps://other.example.test",
        ] {
            assert!(
                validate_repository_base_url(invalid).is_err(),
                "unsafe URL was accepted: {invalid:?}"
            );
        }
    }
}
