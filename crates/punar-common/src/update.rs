//! Trust boundary for Punar release and channel metadata.
//!
//! The wire objects mirror `schemas/update/*.json`. Signatures are verified
//! over the exact bytes before JSON is parsed, so a mirror cannot exploit a
//! parser/canonicalization difference. Public keys and signatures are raw
//! Ed25519 bytes: 32 bytes per `.pub`, 64 bytes per detached `.sig`. Devices
//! never hold private release material.

use std::cmp::Ordering;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::str::FromStr;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SHA256_HEX_LEN: usize = 64;
const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum UpdateTrustError {
    #[error("the trusted release-key set is empty")]
    EmptyKeySet,
    #[error("a trusted release key is not exactly 32 raw Ed25519 bytes")]
    InvalidPublicKey,
    #[error("the detached release signature is not exactly 64 raw Ed25519 bytes")]
    InvalidSignatureEncoding,
    #[error("the release signature is not trusted")]
    InvalidSignature,
    #[error("release metadata is invalid: {0}")]
    InvalidMetadata(String),
    #[error("release target mismatch: {field}")]
    TargetMismatch { field: &'static str },
    #[error("the update channel is halted")]
    ChannelHalted,
    #[error("the offered release is not newer than the running release")]
    VersionNotNewer,
    #[error("the running release is older than the channel minimum")]
    BelowMinimumSupported,
    #[error("the running release is older than this release's direct-update minimum")]
    BelowMinimumFrom,
    #[error("this device is outside the current staged-rollout cohort")]
    OutsideRollout,
    #[error("artifact digest mismatch")]
    DigestMismatch,
    #[error("update trust I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootPlatform {
    Uefi,
    RaspberryPi,
}

impl fmt::Display for BootPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Uefi => "uefi",
            Self::RaspberryPi => "raspberry_pi",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateChannel {
    Stable,
    Dev,
    Edge,
}

impl fmt::Display for UpdateChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stable => "stable",
            Self::Dev => "dev",
            Self::Edge => "edge",
        })
    }
}

/// Canonical `YYYY.MM.DD.N` release version, compared component-wise.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReleaseVersion {
    year: u16,
    month: u8,
    day: u8,
    sequence: u64,
}

impl ReleaseVersion {
    pub fn components(self) -> (u16, u8, u8, u64) {
        (self.year, self.month, self.day, self.sequence)
    }
}

impl FromStr for ReleaseVersion {
    type Err = UpdateTrustError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts = value.split('.').collect::<Vec<_>>();
        let invalid = || UpdateTrustError::InvalidMetadata("version must be YYYY.MM.DD.N".into());
        if parts.len() != 4
            || parts[0].len() != 4
            || parts[1].len() != 2
            || parts[2].len() != 2
            || parts
                .iter()
                .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(invalid());
        }
        let year = parts[0].parse::<u16>().map_err(|_| invalid())?;
        let month = parts[1].parse::<u8>().map_err(|_| invalid())?;
        let day = parts[2].parse::<u8>().map_err(|_| invalid())?;
        let sequence = parts[3].parse::<u64>().map_err(|_| invalid())?;
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return Err(invalid());
        }
        Ok(Self {
            year,
            month,
            day,
            sequence,
        })
    }
}

impl Ord for ReleaseVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.year, self.month, self.day, self.sequence).cmp(&(
            other.year,
            other.month,
            other.day,
            other.sequence,
        ))
    }
}

impl PartialOrd for ReleaseVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ReleaseVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}.{:02}.{:02}.{}",
            self.year, self.month, self.day, self.sequence
        )
    }
}

impl Serialize for ReleaseVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ReleaseVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayPin {
    pub channel: String,
    pub snapshot_pin: String,
    pub digest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadArtifact {
    pub filename: String,
    pub digest_sha256: String,
    pub size_bytes: u64,
    pub uncompressed_size_bytes: u64,
    pub compression: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootArtifactKind {
    Uki,
    RaspberryPiBootfs,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootArtifact {
    pub kind: BootArtifactKind,
    pub filename: String,
    pub digest_sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecuritySeverity {
    None,
    Important,
    Critical,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSecurity {
    pub severity: SecuritySeverity,
    pub advisory_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseProvenance {
    pub git_commit: String,
    pub ci_run_id: String,
    pub builder_base_digest: String,
    pub source_date_epoch: u64,
    pub built_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: u8,
    pub release_id: String,
    pub image_id: String,
    pub architecture: Architecture,
    pub boot_platform: BootPlatform,
    pub version: ReleaseVersion,
    pub channel: UpdateChannel,
    pub snapshot_pin: String,
    pub overlay_pin: Option<OverlayPin>,
    pub payload: PayloadArtifact,
    pub boot_artifact: BootArtifact,
    pub min_from: Option<ReleaseVersion>,
    pub security: ReleaseSecurity,
    pub provenance: ReleaseProvenance,
    pub sbom: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelMetadata {
    pub schema_version: u8,
    pub image_id: String,
    pub architecture: Architecture,
    pub boot_platform: BootPlatform,
    pub channel: UpdateChannel,
    pub current: ReleaseVersion,
    pub release_manifest: String,
    pub rollout_bps: u16,
    pub halted: bool,
    pub published_at: String,
    pub min_supported_version: ReleaseVersion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseTarget {
    pub image_id: String,
    pub architecture: Architecture,
    pub boot_platform: BootPlatform,
    pub channel: UpdateChannel,
}

impl ReleaseManifest {
    pub fn validate(&self) -> Result<(), UpdateTrustError> {
        if self.schema_version != 1 {
            return invalid("unsupported release manifest schema_version");
        }
        validate_image_id(&self.image_id)?;
        validate_release_id(&self.release_id)?;
        let expected_release_id = format!(
            "{}-{}-{}-{}-{}",
            self.image_id, self.channel, self.architecture, self.boot_platform, self.version
        );
        if self.release_id != expected_release_id {
            return invalid("release_id does not bind the image, channel, target, and version");
        }
        if !valid_snapshot_pin(&self.snapshot_pin) {
            return invalid("snapshot_pin is invalid");
        }
        if let Some(pin) = &self.overlay_pin {
            if pin.channel != "punar-security" || !valid_snapshot_pin(&pin.snapshot_pin) {
                return invalid("overlay_pin is invalid");
            }
            validate_sha256_hex(&pin.digest_sha256)?;
        }
        validate_filename(&self.payload.filename)?;
        validate_sha256_hex(&self.payload.digest_sha256)?;
        if self.payload.size_bytes == 0
            || self.payload.uncompressed_size_bytes == 0
            || self.payload.compression != "zstd"
        {
            return invalid("payload size or compression is invalid");
        }
        validate_filename(&self.boot_artifact.filename)?;
        validate_sha256_hex(&self.boot_artifact.digest_sha256)?;
        if self.boot_artifact.size_bytes == 0 {
            return invalid("boot artifact is empty");
        }
        let boot_matches = matches!(
            (self.boot_platform, self.boot_artifact.kind),
            (BootPlatform::Uefi, BootArtifactKind::Uki)
                | (
                    BootPlatform::RaspberryPi,
                    BootArtifactKind::RaspberryPiBootfs
                )
        );
        if !boot_matches {
            return invalid("boot artifact kind does not match boot_platform");
        }
        let mut advisory_ids = std::collections::HashSet::new();
        if self.security.advisory_ids.len() > 256
            || self
                .security
                .advisory_ids
                .iter()
                .any(|id| !valid_token(id, 128) || !advisory_ids.insert(id.as_str()))
        {
            return invalid("security advisory id is invalid");
        }
        if !is_lower_hex(&self.provenance.git_commit, 40)
            || !valid_token(&self.provenance.ci_run_id, 128)
            || !self.provenance.builder_base_digest.starts_with("sha256:")
            || validate_sha256_hex(
                self.provenance
                    .builder_base_digest
                    .strip_prefix("sha256:")
                    .unwrap_or_default(),
            )
            .is_err()
            || crate::time::unix_seconds_from_rfc3339(&self.provenance.built_at).is_none()
        {
            return invalid("release provenance is invalid");
        }
        if self
            .sbom
            .as_ref()
            .is_some_and(|path| !valid_relative_path(path))
        {
            return invalid("sbom path is invalid");
        }
        Ok(())
    }

    pub fn admit(
        &self,
        target: &ReleaseTarget,
        current: ReleaseVersion,
        allow_downgrade: bool,
    ) -> Result<(), UpdateTrustError> {
        self.validate()?;
        require_target(self.image_id == target.image_id, "image_id")?;
        require_target(self.architecture == target.architecture, "architecture")?;
        require_target(self.boot_platform == target.boot_platform, "boot_platform")?;
        require_target(self.channel == target.channel, "channel")?;
        if !allow_downgrade && self.version <= current {
            return Err(UpdateTrustError::VersionNotNewer);
        }
        if self.min_from.is_some_and(|minimum| current < minimum) {
            return Err(UpdateTrustError::BelowMinimumFrom);
        }
        Ok(())
    }
}

impl ChannelMetadata {
    pub fn validate(&self) -> Result<(), UpdateTrustError> {
        if self.schema_version != 1 {
            return invalid("unsupported channel metadata schema_version");
        }
        validate_image_id(&self.image_id)?;
        if self.rollout_bps > 10_000 {
            return invalid("rollout_bps exceeds 10000");
        }
        if !valid_relative_path(&self.release_manifest)
            || !self.release_manifest.ends_with("release.json")
            || crate::time::unix_seconds_from_rfc3339(&self.published_at).is_none()
        {
            return invalid("channel path or timestamp is invalid");
        }
        Ok(())
    }

    pub fn admit(
        &self,
        target: &ReleaseTarget,
        current: ReleaseVersion,
        device_id: &str,
    ) -> Result<(), UpdateTrustError> {
        self.validate()?;
        if !valid_device_id(device_id) {
            return invalid("device_id is invalid");
        }
        require_target(self.image_id == target.image_id, "image_id")?;
        require_target(self.architecture == target.architecture, "architecture")?;
        require_target(self.boot_platform == target.boot_platform, "boot_platform")?;
        require_target(self.channel == target.channel, "channel")?;
        if self.halted {
            return Err(UpdateTrustError::ChannelHalted);
        }
        if current < self.min_supported_version {
            return Err(UpdateTrustError::BelowMinimumSupported);
        }
        if self.current <= current {
            return Err(UpdateTrustError::VersionNotNewer);
        }
        if cohort_bucket(device_id, self.current) >= self.rollout_bps {
            return Err(UpdateTrustError::OutsideRollout);
        }
        Ok(())
    }
}

/// A rotation-aware set of trusted release keys loaded from the signed root.
#[derive(Clone, Debug)]
pub struct ReleaseKeySet {
    keys: Vec<VerifyingKey>,
}

impl ReleaseKeySet {
    pub fn from_raw_keys<I, B>(keys: I) -> Result<Self, UpdateTrustError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut parsed = Vec::new();
        for raw in keys {
            let bytes: [u8; ED25519_PUBLIC_KEY_LEN] = raw
                .as_ref()
                .try_into()
                .map_err(|_| UpdateTrustError::InvalidPublicKey)?;
            let key =
                VerifyingKey::from_bytes(&bytes).map_err(|_| UpdateTrustError::InvalidPublicKey)?;
            if !parsed.iter().any(|known: &VerifyingKey| known == &key) {
                parsed.push(key);
            }
        }
        if parsed.is_empty() {
            return Err(UpdateTrustError::EmptyKeySet);
        }
        Ok(Self { keys: parsed })
    }

    pub fn load_dir(path: &Path) -> Result<Self, UpdateTrustError> {
        let mut paths = fs::read_dir(path)?
            .map(|entry| entry.map(|value| value.path()))
            .collect::<Result<Vec<_>, _>>()?;
        paths.retain(|path| path.extension().is_some_and(|ext| ext == "pub"));
        paths.sort();
        let keys = paths.iter().map(fs::read).collect::<Result<Vec<_>, _>>()?;
        Self::from_raw_keys(keys)
    }

    pub fn verify(&self, document: &[u8], signature: &[u8]) -> Result<(), UpdateTrustError> {
        let signature_bytes: [u8; ED25519_SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| UpdateTrustError::InvalidSignatureEncoding)?;
        let signature = Signature::from_bytes(&signature_bytes);
        if self
            .keys
            .iter()
            .any(|key| key.verify_strict(document, &signature).is_ok())
        {
            Ok(())
        } else {
            Err(UpdateTrustError::InvalidSignature)
        }
    }
}

/// Verify before parsing: callers cannot observe untrusted metadata as data.
pub fn verify_release_manifest(
    document: &[u8],
    signature: &[u8],
    keys: &ReleaseKeySet,
) -> Result<ReleaseManifest, UpdateTrustError> {
    keys.verify(document, signature)?;
    let manifest: ReleaseManifest = serde_json::from_slice(document)
        .map_err(|error| UpdateTrustError::InvalidMetadata(error.to_string()))?;
    manifest.validate()?;
    Ok(manifest)
}

/// Verify before parsing, matching [`verify_release_manifest`].
pub fn verify_channel_metadata(
    document: &[u8],
    signature: &[u8],
    keys: &ReleaseKeySet,
) -> Result<ChannelMetadata, UpdateTrustError> {
    keys.verify(document, signature)?;
    let channel: ChannelMetadata = serde_json::from_slice(document)
        .map_err(|error| UpdateTrustError::InvalidMetadata(error.to_string()))?;
    channel.validate()?;
    Ok(channel)
}

/// Privacy-preserving rollout cohort: no device identifier leaves the host.
pub fn cohort_bucket(device_id: &str, version: ReleaseVersion) -> u16 {
    let mut hasher = Sha256::new();
    hasher.update(device_id.as_bytes());
    hasher.update(b":");
    hasher.update(version.to_string().as_bytes());
    let digest = hasher.finalize();
    let prefix = u32::from_be_bytes(digest[..4].try_into().expect("SHA-256 is 32 bytes"));
    (prefix % 10_000) as u16
}

/// Stream an artifact through a fixed-size buffer. The updater never holds a
/// root slot in memory, even when verifying multi-gigabyte payloads.
pub fn sha256_reader(mut reader: impl Read) -> Result<(String, u64), UpdateTrustError> {
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| UpdateTrustError::InvalidMetadata("artifact size overflow".into()))?;
    }
    Ok((hex_lower(&hasher.finalize()), bytes))
}

pub fn verify_reader(
    reader: impl Read,
    expected_digest: &str,
    expected_size: u64,
) -> Result<(), UpdateTrustError> {
    validate_sha256_hex(expected_digest)?;
    let (digest, size) = sha256_reader(reader)?;
    if digest == expected_digest && size == expected_size {
        Ok(())
    } else {
        Err(UpdateTrustError::DigestMismatch)
    }
}

fn validate_release_id(value: &str) -> Result<(), UpdateTrustError> {
    if value.is_empty()
        || value.len() > 192
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        || !value.as_bytes()[0].is_ascii_alphanumeric()
    {
        return invalid("release_id is invalid");
    }
    Ok(())
}

fn validate_image_id(value: &str) -> Result<(), UpdateTrustError> {
    let suffix = value.strip_prefix("punar-").unwrap_or_default();
    if value.len() > 64
        || suffix.is_empty()
        || !suffix.as_bytes()[0].is_ascii_alphanumeric()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return invalid("image_id is invalid");
    }
    Ok(())
}

fn validate_filename(value: &str) -> Result<(), UpdateTrustError> {
    if value.is_empty()
        || value.len() > 255
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return invalid("artifact filename is invalid");
    }
    Ok(())
}

fn valid_snapshot_pin(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'+' | b'-')
        })
}

fn valid_device_id(value: &str) -> bool {
    value.strip_prefix("dev_").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}

fn validate_sha256_hex(value: &str) -> Result<(), UpdateTrustError> {
    if !is_lower_hex(value, SHA256_HEX_LEN) {
        return invalid("SHA-256 digest is invalid");
    }
    Ok(())
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_token(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('/')
        && !value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}

fn require_target(matches: bool, field: &'static str) -> Result<(), UpdateTrustError> {
    if matches {
        Ok(())
    } else {
        Err(UpdateTrustError::TargetMismatch { field })
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, UpdateTrustError> {
    Err(UpdateTrustError::InvalidMetadata(message.into()))
}

fn hex_lower(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(value.len() * 2);
    for byte in value {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::HashSet;

    fn manifest_bytes() -> Vec<u8> {
        include_bytes!("../../../fixtures/update/valid/release-manifest.json").to_vec()
    }

    fn channel_bytes() -> Vec<u8> {
        include_bytes!("../../../fixtures/update/valid/channel-metadata.json").to_vec()
    }

    fn signing_fixture() -> (SigningKey, ReleaseKeySet) {
        let signing = SigningKey::from_bytes(&[42; 32]);
        let keys = ReleaseKeySet::from_raw_keys([signing.verifying_key().to_bytes()]).unwrap();
        (signing, keys)
    }

    fn target() -> ReleaseTarget {
        ReleaseTarget {
            image_id: "punar-desktop".into(),
            architecture: Architecture::Aarch64,
            boot_platform: BootPlatform::Uefi,
            channel: UpdateChannel::Stable,
        }
    }

    #[test]
    fn version_comparison_is_component_wise_integer() {
        let nine: ReleaseVersion = "2026.09.02.9".parse().unwrap();
        let ten: ReleaseVersion = "2026.09.02.10".parse().unwrap();
        assert!(ten > nine);
        assert_eq!(ten.to_string(), "2026.09.02.10");
        for invalid in ["2026.9.02.1", "2026.13.02.1", "2026.09.00.1", "v1"] {
            assert!(invalid.parse::<ReleaseVersion>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn valid_signed_documents_verify_before_they_parse() {
        let (signing, keys) = signing_fixture();
        let manifest = manifest_bytes();
        let signature = signing.sign(&manifest).to_bytes();
        let verified = verify_release_manifest(&manifest, &signature, &keys).unwrap();
        assert_eq!(verified.version.to_string(), "2026.08.27.1");
        verified
            .admit(&target(), "2026.08.20.1".parse().unwrap(), false)
            .unwrap();

        let channel = channel_bytes();
        let signature = signing.sign(&channel).to_bytes();
        let verified = verify_channel_metadata(&channel, &signature, &keys).unwrap();
        assert_eq!(verified.rollout_bps, 1000);
    }

    #[test]
    fn signature_failures_are_closed_and_specific() {
        let (signing, keys) = signing_fixture();
        let mut manifest = manifest_bytes();
        let signature = signing.sign(&manifest).to_bytes();
        manifest[20] ^= 1;
        assert!(matches!(
            verify_release_manifest(&manifest, &signature, &keys),
            Err(UpdateTrustError::InvalidSignature)
        ));
        let wrong = SigningKey::from_bytes(&[7; 32]);
        let signature = wrong.sign(&manifest).to_bytes();
        assert!(matches!(
            verify_release_manifest(&manifest, &signature, &keys),
            Err(UpdateTrustError::InvalidSignature)
        ));
        assert!(matches!(
            keys.verify(&manifest, &signature[..32]),
            Err(UpdateTrustError::InvalidSignatureEncoding)
        ));
        assert!(matches!(
            ReleaseKeySet::from_raw_keys(Vec::<Vec<u8>>::new()),
            Err(UpdateTrustError::EmptyKeySet)
        ));
    }

    #[test]
    fn semantic_target_checks_reject_cross_arch_and_cross_channel_artifacts() {
        let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes()).unwrap();
        let current = "2026.08.20.1".parse().unwrap();
        let mut wrong = target();
        wrong.architecture = Architecture::X86_64;
        assert!(matches!(
            manifest.admit(&wrong, current, false),
            Err(UpdateTrustError::TargetMismatch {
                field: "architecture"
            })
        ));
        wrong = target();
        wrong.channel = UpdateChannel::Edge;
        assert!(matches!(
            manifest.admit(&wrong, current, false),
            Err(UpdateTrustError::TargetMismatch { field: "channel" })
        ));
        assert!(matches!(
            manifest.admit(&target(), "2026.08.27.1".parse().unwrap(), false),
            Err(UpdateTrustError::VersionNotNewer)
        ));
    }

    #[test]
    fn cohort_is_deterministic_well_distributed_and_changes_by_release() {
        let first = "2026.08.27.1".parse().unwrap();
        let second = "2026.08.28.1".parse().unwrap();
        let selected_first = (0..10_000)
            .filter(|id| cohort_bucket(&format!("dev_{id:05}"), first) < 1000)
            .collect::<HashSet<_>>();
        let selected_second = (0..10_000)
            .filter(|id| cohort_bucket(&format!("dev_{id:05}"), second) < 1000)
            .collect::<HashSet<_>>();
        assert!(
            (900..=1100).contains(&selected_first.len()),
            "{}",
            selected_first.len()
        );
        assert!(
            (900..=1100).contains(&selected_second.len()),
            "{}",
            selected_second.len()
        );
        let overlap = selected_first.intersection(&selected_second).count();
        assert!((50..=160).contains(&overlap), "overlap={overlap}");
        assert_eq!(
            cohort_bucket("dev_00123", first),
            cohort_bucket("dev_00123", first)
        );
        // SHA256("dev_00123:2026.08.27.1") begins 36f13f79. Interpreting
        // those four bytes as a big-endian u32 and reducing modulo 10000
        // locks this implementation to update-and-rollback.md section 5.2.
        assert_eq!(cohort_bucket("dev_00123", first), 89);
    }

    #[test]
    fn runtime_validation_matches_schema_edges() {
        let mut manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes()).unwrap();
        manifest.payload.filename = "payload:slot.zst".into();
        assert!(manifest.validate().is_err());

        let mut manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes()).unwrap();
        manifest.snapshot_pin = "pin with spaces".into();
        assert!(manifest.validate().is_err());

        let mut manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes()).unwrap();
        manifest.security.advisory_ids = vec!["CVE-1".into(), "CVE-1".into()];
        assert!(manifest.validate().is_err());

        let channel: ChannelMetadata = serde_json::from_slice(&channel_bytes()).unwrap();
        assert!(
            channel
                .admit(
                    &target(),
                    "2026.08.20.1".parse().unwrap(),
                    "not-a-device-id",
                )
                .is_err()
        );
    }

    #[test]
    fn streaming_digest_checks_bytes_and_size() {
        let bytes = b"a complete slot payload";
        let (digest, size) = sha256_reader(&bytes[..]).unwrap();
        assert_eq!(size, bytes.len() as u64);
        verify_reader(&bytes[..], &digest, size).unwrap();
        assert!(matches!(
            verify_reader(&bytes[..], &digest, size + 1),
            Err(UpdateTrustError::DigestMismatch)
        ));
    }

    #[test]
    fn raw_key_directory_supports_rotation_and_rejects_empty_sets() {
        let path = std::env::temp_dir().join(format!("punar-release-keys-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        assert!(matches!(
            ReleaseKeySet::load_dir(&path),
            Err(UpdateTrustError::EmptyKeySet)
        ));
        let old = SigningKey::from_bytes(&[1; 32]);
        let new = SigningKey::from_bytes(&[2; 32]);
        fs::write(path.join("2026-old.pub"), old.verifying_key().to_bytes()).unwrap();
        fs::write(path.join("2026-new.pub"), new.verifying_key().to_bytes()).unwrap();
        let keys = ReleaseKeySet::load_dir(&path).unwrap();
        let document = b"release";
        keys.verify(document, &old.sign(document).to_bytes())
            .unwrap();
        keys.verify(document, &new.sign(document).to_bytes())
            .unwrap();
        fs::remove_dir_all(path).unwrap();
    }
}
