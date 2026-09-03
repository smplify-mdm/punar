//! Exact-byte signed authorization for unattended destructive installation.
//!
//! An answer document is authorization, not configuration. It contains no
//! passphrase or recovery key. The signature binds one short-lived operation
//! to the exact plan token returned by `install.plan`; that token already
//! commits to the physical disk identity, both GPT edges, fixed layout,
//! release payload and boot artifact. The separate raw-manifest digest also
//! binds fields that do not participate in the install plan (for example
//! provenance and security advisories).

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::install::{InstallEncryption, InstallPlan, InstallRecoveryMode};

pub const INSTALL_ANSWERS_KIND: &str = "punar_unattended_install";
pub const INSTALL_ANSWERS_MAX_BYTES: usize = 64 * 1024;
pub const INSTALL_ANSWERS_SIGNATURE_BYTES: usize = 64;
pub const INSTALL_ANSWERS_MAX_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
const INSTALL_ANSWERS_CLOCK_SKEW_SECONDS: u64 = 5 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnattendedPassphraseSource {
    Generated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnattendedRecoveryAcknowledgement {
    Unattended,
}

/// Strict signed bytes stored as `answers.json` on `PUNAR_ANSWERS` media.
///
/// `confirm_destroy_disk` deliberately repeats `target_serial`: it preserves
/// the same destructive-confirmation grammar as the attended screen while the
/// plan token supplies the stronger whole-plan binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnattendedInstallAnswers {
    pub v: u8,
    pub kind: String,
    pub authorization_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub plan_token: String,
    pub target_serial: String,
    pub confirm_destroy_disk: String,
    pub release_id: String,
    pub release_manifest_sha256: String,
    pub keymap: String,
    pub locale: String,
    pub encryption: InstallEncryption,
    pub recovery_mode: InstallRecoveryMode,
    pub passphrase_source: UnattendedPassphraseSource,
    pub recovery_key_ack: UnattendedRecoveryAcknowledgement,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oobe_answers_sha256: Option<String>,
}

#[derive(Debug, Error)]
pub enum InstallAnswersTrustError {
    #[error("the trusted unattended-install key set is empty")]
    EmptyKeySet,
    #[error(
        "a trusted unattended-install key is neither 32 raw Ed25519 bytes nor 64 lowercase hexadecimal bytes"
    )]
    InvalidPublicKey,
    #[error("the detached unattended-install signature is not exactly 64 raw Ed25519 bytes")]
    InvalidSignatureEncoding,
    #[error("the unattended-install signature is not trusted")]
    InvalidSignature,
    #[error("the unattended-install authorization is invalid: {0}")]
    InvalidDocument(String),
    #[error("the unattended-install authorization does not match this transaction: {0}")]
    Binding(String),
    #[error("could not read unattended-install trust material: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
pub struct InstallAnswersKeySet {
    keys: Vec<VerifyingKey>,
}

impl InstallAnswersKeySet {
    pub fn from_raw_keys<I, B>(keys: I) -> Result<Self, InstallAnswersTrustError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut parsed = Vec::new();
        for raw in keys {
            let bytes: [u8; 32] = raw
                .as_ref()
                .try_into()
                .map_err(|_| InstallAnswersTrustError::InvalidPublicKey)?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| InstallAnswersTrustError::InvalidPublicKey)?;
            if !parsed.iter().any(|known: &VerifyingKey| known == &key) {
                parsed.push(key);
            }
        }
        if parsed.is_empty() {
            return Err(InstallAnswersTrustError::EmptyKeySet);
        }
        Ok(Self { keys: parsed })
    }

    pub fn load_dir(path: &Path) -> Result<Self, InstallAnswersTrustError> {
        let mut paths = fs::read_dir(path)?
            .map(|entry| entry.map(|value| value.path()))
            .collect::<Result<Vec<_>, _>>()?;
        paths.retain(|path| path.extension().is_some_and(|ext| ext == "pub"));
        paths.sort();
        let keys = paths
            .iter()
            .map(fs::read)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|bytes| decode_public_key_file(&bytes))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_raw_keys(keys)
    }

    fn verify(&self, document: &[u8], signature: &[u8]) -> Result<(), InstallAnswersTrustError> {
        let signature_bytes: [u8; INSTALL_ANSWERS_SIGNATURE_BYTES] = signature
            .try_into()
            .map_err(|_| InstallAnswersTrustError::InvalidSignatureEncoding)?;
        let signature = Signature::from_bytes(&signature_bytes);
        if self
            .keys
            .iter()
            .any(|key| key.verify_strict(document, &signature).is_ok())
        {
            Ok(())
        } else {
            Err(InstallAnswersTrustError::InvalidSignature)
        }
    }
}

fn decode_public_key_file(bytes: &[u8]) -> Result<[u8; 32], InstallAnswersTrustError> {
    if let Ok(raw) = <[u8; 32]>::try_from(bytes) {
        return Ok(raw);
    }
    let hexadecimal = bytes
        .strip_suffix(b"\n")
        .and_then(|value| value.strip_suffix(b"\r").or(Some(value)))
        .unwrap_or(bytes);
    if hexadecimal.len() != 64
        || !hexadecimal
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(InstallAnswersTrustError::InvalidPublicKey);
    }
    let mut raw = [0u8; 32];
    for (index, pair) in hexadecimal.chunks_exact(2).enumerate() {
        raw[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(raw)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("hexadecimal encoding was validated"),
    }
}

/// Verify the detached signature over the exact bytes before parsing them.
pub fn verify_unattended_install_answers(
    document: &[u8],
    signature: &[u8],
    keys: &InstallAnswersKeySet,
) -> Result<UnattendedInstallAnswers, InstallAnswersTrustError> {
    if document.is_empty() || document.len() > INSTALL_ANSWERS_MAX_BYTES {
        return Err(InstallAnswersTrustError::InvalidDocument(format!(
            "answers.json must contain 1–{INSTALL_ANSWERS_MAX_BYTES} bytes"
        )));
    }
    keys.verify(document, signature)?;
    let answers: UnattendedInstallAnswers = serde_json::from_slice(document)
        .map_err(|error| InstallAnswersTrustError::InvalidDocument(error.to_string()))?;
    validate_shape(&answers)?;
    Ok(answers)
}

/// Admit one already authenticated answer document against the exact local
/// plan and release. `oobe_answers` are hashed, never interpreted here.
pub fn admit_unattended_install_answers(
    answers: &UnattendedInstallAnswers,
    now_seconds: u64,
    plan: &InstallPlan,
    plan_token: &str,
    release_manifest_sha256: &str,
    locale: &str,
    oobe_answers: Option<&[u8]>,
) -> Result<(), InstallAnswersTrustError> {
    validate_shape(answers)?;
    let issued = crate::time::unix_seconds_from_rfc3339(&answers.issued_at)
        .ok_or_else(|| invalid("issued_at must be one valid RFC 3339 timestamp"))?;
    let expires = crate::time::unix_seconds_from_rfc3339(&answers.expires_at)
        .ok_or_else(|| invalid("expires_at must be one valid RFC 3339 timestamp"))?;
    if issued > expires || expires.saturating_sub(issued) > INSTALL_ANSWERS_MAX_LIFETIME_SECONDS {
        return Err(invalid(
            "the authorization lifetime must be between zero and 24 hours",
        ));
    }
    if issued > now_seconds.saturating_add(INSTALL_ANSWERS_CLOCK_SKEW_SECONDS) {
        return Err(InstallAnswersTrustError::Binding(
            "the authorization is not valid yet".into(),
        ));
    }
    if now_seconds > expires {
        return Err(InstallAnswersTrustError::Binding(
            "the authorization has expired".into(),
        ));
    }
    if answers.plan_token != plan_token {
        return Err(binding("plan_token changed after authorization"));
    }
    if answers.target_serial != plan.disk.serial || answers.confirm_destroy_disk != plan.disk.serial
    {
        return Err(binding(
            "the target serial does not match the authorized disk",
        ));
    }
    if answers.release_id != plan.payload.release_id {
        return Err(binding(
            "the release id does not match the authorized release",
        ));
    }
    if answers.release_manifest_sha256 != release_manifest_sha256 {
        return Err(binding("the exact signed release manifest changed"));
    }
    if answers.keymap != plan.keymap
        || answers.locale != locale
        || answers.encryption != plan.encryption
        || answers.recovery_mode != plan.recovery_mode
    {
        return Err(binding(
            "the requested install choices do not match the authorization",
        ));
    }
    let actual_oobe = oobe_answers.map(sha256_hex);
    if answers.oobe_answers_sha256 != actual_oobe {
        return Err(binding(
            "the OOBE passthrough does not match its authorized digest",
        ));
    }
    Ok(())
}

fn validate_shape(answers: &UnattendedInstallAnswers) -> Result<(), InstallAnswersTrustError> {
    if answers.v != 1 || answers.kind != INSTALL_ANSWERS_KIND {
        return Err(invalid(
            "v/kind is not the supported unattended-install contract",
        ));
    }
    if !lower_hex(&answers.authorization_id, 32) {
        return Err(invalid(
            "authorization_id must be 128 bits of lowercase hex",
        ));
    }
    for (name, value) in [
        ("plan_token", answers.plan_token.as_str()),
        (
            "release_manifest_sha256",
            answers.release_manifest_sha256.as_str(),
        ),
    ] {
        if !lower_hex(value, 64) {
            return Err(invalid(&format!(
                "{name} must be one lowercase SHA-256 digest"
            )));
        }
    }
    if answers
        .oobe_answers_sha256
        .as_deref()
        .is_some_and(|value| !lower_hex(value, 64))
    {
        return Err(invalid(
            "oobe_answers_sha256 must be one lowercase SHA-256 digest",
        ));
    }
    if !bounded_token(&answers.target_serial, 1, 128)
        || !bounded_token(&answers.confirm_destroy_disk, 1, 128)
        || !bounded_token(&answers.release_id, 1, 128)
        || !keymap_token(&answers.keymap, 1, 64)
        || !simple_token(&answers.locale, 1, 64)
    {
        return Err(invalid(
            "one or more bounded identity/locale fields are invalid",
        ));
    }
    if answers.encryption != InstallEncryption::Luks2
        || answers.recovery_mode != InstallRecoveryMode::PersonalCopy
    {
        return Err(invalid(
            "unattended media requires LUKS2 with removable personal recovery custody",
        ));
    }
    Ok(())
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn bounded_token(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:+@=-".contains(&byte))
}

fn keymap_token(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_+-".contains(&byte))
}

fn simple_token(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.@-".contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &str) -> InstallAnswersTrustError {
    InstallAnswersTrustError::InvalidDocument(message.into())
}

fn binding(message: &str) -> InstallAnswersTrustError {
    InstallAnswersTrustError::Binding(message.into())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::install::{
        InstallBootArtifactPlan, InstallDiskIdentity, InstallPayloadPlan, InstallPlan,
    };
    use crate::update::BootArtifactKind;

    fn fixture() -> (UnattendedInstallAnswers, InstallPlan) {
        let plan = InstallPlan {
            schema_version: 1,
            architecture: "x86_64".into(),
            boot_platform: "uefi".into(),
            disk: InstallDiskIdentity {
                device: "/dev/vda".into(),
                model: Some("fixture".into()),
                serial: "PUNAR-CI-TARGET".into(),
                wwn: None,
                size_bytes: 137_438_953_472,
                logical_sector_bytes: 512,
                existing_gpt_sha256: "1".repeat(64),
            },
            keymap: "us".into(),
            encryption: InstallEncryption::Luks2,
            recovery_mode: InstallRecoveryMode::PersonalCopy,
            payload: InstallPayloadPlan {
                release_id: "punar-desktop-2026.09.01.1".into(),
                filename: "slot.raw.zst".into(),
                digest_sha256: "2".repeat(64),
                compressed_size_bytes: 1,
                uncompressed_digest_sha256: "3".repeat(64),
                uncompressed_size_bytes: 2,
            },
            boot_artifact: InstallBootArtifactPlan {
                kind: BootArtifactKind::Uki,
                filename: "slot.efi".into(),
                digest_sha256: "4".repeat(64),
                size_bytes: 3,
            },
            partitions: vec![],
            data_subvolumes: vec!["@var".into()],
            warnings: vec![],
        };
        let answers = UnattendedInstallAnswers {
            v: 1,
            kind: INSTALL_ANSWERS_KIND.into(),
            authorization_id: "a".repeat(32),
            issued_at: "2026-09-01T00:00:00Z".into(),
            expires_at: "2026-09-01T01:00:00Z".into(),
            plan_token: "b".repeat(64),
            target_serial: plan.disk.serial.clone(),
            confirm_destroy_disk: plan.disk.serial.clone(),
            release_id: plan.payload.release_id.clone(),
            release_manifest_sha256: "c".repeat(64),
            keymap: plan.keymap.clone(),
            locale: "C.UTF-8".into(),
            encryption: plan.encryption,
            recovery_mode: plan.recovery_mode,
            passphrase_source: UnattendedPassphraseSource::Generated,
            recovery_key_ack: UnattendedRecoveryAcknowledgement::Unattended,
            oobe_answers_sha256: None,
        };
        (answers, plan)
    }

    #[test]
    fn exact_bytes_are_authenticated_before_the_document_is_admitted() {
        let signing = SigningKey::from_bytes(&[17; 32]);
        let keys =
            InstallAnswersKeySet::from_raw_keys([signing.verifying_key().to_bytes().as_slice()])
                .unwrap();
        let (answers, plan) = fixture();
        let document = serde_json::to_vec(&answers).unwrap();
        let signature = signing.sign(&document).to_bytes();
        let verified = verify_unattended_install_answers(&document, &signature, &keys).unwrap();
        admit_unattended_install_answers(
            &verified,
            crate::time::unix_seconds_from_rfc3339("2026-09-01T00:30:00Z").unwrap(),
            &plan,
            &answers.plan_token,
            &answers.release_manifest_sha256,
            &answers.locale,
            None,
        )
        .unwrap();

        let mut tampered = document;
        let position = tampered.iter().position(|byte| *byte == b'a').unwrap();
        tampered[position] = b'b';
        assert!(matches!(
            verify_unattended_install_answers(&tampered, &signature, &keys),
            Err(InstallAnswersTrustError::InvalidSignature)
        ));
    }

    #[test]
    fn expiry_plan_release_target_and_oobe_bindings_fail_closed() {
        let (answers, plan) = fixture();
        let after_expiry = crate::time::unix_seconds_from_rfc3339("2026-09-01T01:00:01Z").unwrap();
        assert!(
            admit_unattended_install_answers(
                &answers,
                after_expiry,
                &plan,
                &answers.plan_token,
                &answers.release_manifest_sha256,
                &answers.locale,
                None,
            )
            .is_err()
        );

        for (plan_token, manifest, locale, oobe) in [
            (
                "d".repeat(64),
                answers.release_manifest_sha256.clone(),
                answers.locale.clone(),
                None,
            ),
            (
                answers.plan_token.clone(),
                "e".repeat(64),
                answers.locale.clone(),
                None,
            ),
            (
                answers.plan_token.clone(),
                answers.release_manifest_sha256.clone(),
                "fr_FR".into(),
                None,
            ),
            (
                answers.plan_token.clone(),
                answers.release_manifest_sha256.clone(),
                answers.locale.clone(),
                Some(b"not authorized".as_slice()),
            ),
        ] {
            assert!(
                admit_unattended_install_answers(
                    &answers,
                    crate::time::unix_seconds_from_rfc3339("2026-09-01T00:30:00Z").unwrap(),
                    &plan,
                    &plan_token,
                    &manifest,
                    &locale,
                    oobe,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn plaintext_secret_and_wider_modes_are_rejected_by_strict_shape() {
        let (answers, _) = fixture();
        let signing = SigningKey::from_bytes(&[29; 32]);
        let keys =
            InstallAnswersKeySet::from_raw_keys([signing.verifying_key().to_bytes().as_slice()])
                .unwrap();
        let mut value = serde_json::to_value(&answers).unwrap();
        value["passphrase"] = serde_json::json!("must never be accepted");
        let document = serde_json::to_vec(&value).unwrap();
        let signature = signing.sign(&document).to_bytes();
        assert!(matches!(
            verify_unattended_install_answers(&document, &signature, &keys),
            Err(InstallAnswersTrustError::InvalidDocument(_))
        ));

        let mut unencrypted = answers;
        unencrypted.encryption = InstallEncryption::None;
        let document = serde_json::to_vec(&unencrypted).unwrap();
        let signature = signing.sign(&document).to_bytes();
        assert!(matches!(
            verify_unattended_install_answers(&document, &signature, &keys),
            Err(InstallAnswersTrustError::InvalidDocument(_))
        ));
    }

    #[test]
    fn key_directory_accepts_raw_or_lowercase_hex_but_no_loose_text() {
        let root = std::env::temp_dir().join(format!(
            "punar-install-answer-keys-{}-{}",
            std::process::id(),
            crate::time::unix_now_millis()
        ));
        fs::create_dir(&root).unwrap();
        let signing = SigningKey::from_bytes(&[31; 32]);
        let raw = signing.verifying_key().to_bytes();
        let hex = raw
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        fs::write(root.join("ci.pub"), format!("{hex}\n")).unwrap();
        assert!(InstallAnswersKeySet::load_dir(&root).is_ok());
        fs::write(root.join("bad.pub"), "NOT A KEY\n").unwrap();
        assert!(matches!(
            InstallAnswersKeySet::load_dir(&root),
            Err(InstallAnswersTrustError::InvalidPublicKey)
        ));
        fs::remove_file(root.join("bad.pub")).unwrap();
        fs::write(root.join("ci.pub"), raw).unwrap();
        assert!(InstallAnswersKeySet::load_dir(&root).is_ok());
        fs::remove_dir_all(root).unwrap();
    }
}
