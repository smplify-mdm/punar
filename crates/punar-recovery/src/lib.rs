//! Recovery-key custody for Punar's encrypted shared-data volume.
//!
//! This crate is deliberately a library, not a daemon. The installer and a
//! later authenticated rotation flow use the same state machine without
//! adding an idle process. It owns four security boundaries:
//!
//! - normalize systemd's 256-bit `modhex64` recovery key into a zeroizing,
//!   non-serializable value;
//! - wrap that value with one fixed RFC 9180 HPKE suite to a tenant key that
//!   the enrollment chain already authenticated;
//! - bind the ciphertext to organization, device, LUKS UUID and keyslot as
//!   HPKE associated data;
//! - accept an escrow receipt only after an independent Ed25519 signature and
//!   the exact envelope digest both verify.
//!
//! No API returns a recovery key in JSON, and no error or `Debug` value
//! includes secret material. The personal lane owns the key in one
//! non-serializable disclosure session, then zeroizes it when that session is
//! acknowledged or abandoned.

#![forbid(unsafe_code)]

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::{AeadTag, ChaCha20Poly1305},
    inout::InOutBuf,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

/// The only negotiated value does not negotiate: changing it is a protocol
/// version, with new fixtures and a migration plan.
pub const HPKE_SUITE: &str = "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20POLY1305";

const HPKE_INFO: &[u8] = b"smplify.punar.recovery-key-escrow.v1";
const AAD_DOMAIN: &[u8] = b"smplify.punar.recovery-binding.v1";
const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"smplify.punar.recovery-envelope.v1";
const RECEIPT_DOMAIN: &[u8] = b"smplify.punar.recovery-receipt.v1";
const MODHEX_ALPHABET: &str = "cbdefghijklnrtuv";

/// All failures are deliberately value-free. A caller may audit the variant,
/// but never the input that caused it.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    #[error("the recovery key is not a systemd modhex64 key")]
    InvalidRecoveryKey,
    #[error("the recovery binding is invalid")]
    InvalidBinding,
    #[error("the tenant recovery-key document is invalid")]
    InvalidTenantKey,
    #[error("the recovery envelope is invalid")]
    InvalidEnvelope,
    #[error("recovery-key wrapping failed")]
    WrapFailed,
    #[error("recovery-key unwrapping failed")]
    UnwrapFailed,
    #[error("the escrow receipt is invalid")]
    InvalidReceipt,
    #[error("the escrow receipt signature is invalid")]
    InvalidReceiptSignature,
    #[error("the escrow receipt is not bound to this envelope")]
    ReceiptBindingMismatch,
    #[error("secure randomness for the confirmation challenge is unavailable")]
    RandomUnavailable,
    #[error("the recovery-key confirmation did not match")]
    ConfirmationFailed,
    #[error("the recovery key has not been confirmed")]
    NotConfirmed,
}

/// A normalized systemd recovery key. The canonical text is zeroized on drop,
/// is never cloneable or serializable, and debugs as a redaction.
pub struct SecretRecoveryKey(Zeroizing<String>);

impl SecretRecoveryKey {
    /// Accept a formatted or unformatted, case-insensitive modhex64 value and
    /// normalize it to eight lowercase groups of eight characters.
    pub fn parse(value: &str) -> Result<Self, RecoveryError> {
        let mut compact = Zeroizing::new(String::with_capacity(64));
        for character in value.chars() {
            if character == '-' {
                continue;
            }
            let character = character.to_ascii_lowercase();
            if !MODHEX_ALPHABET.contains(character) {
                return Err(RecoveryError::InvalidRecoveryKey);
            }
            compact.push(character);
        }
        if compact.len() != 64 {
            return Err(RecoveryError::InvalidRecoveryKey);
        }

        let mut formatted = Zeroizing::new(String::with_capacity(71));
        for (index, byte) in compact.as_bytes().iter().enumerate() {
            if index > 0 && index % 8 == 0 {
                formatted.push('-');
            }
            formatted.push(char::from(*byte));
        }
        Ok(Self(formatted))
    }

    /// Borrow the canonical value only at the two explicit secret sinks:
    /// the one-time personal receipt and HPKE sealing.
    fn expose(&self) -> &str {
        self.0.as_str()
    }

    /// Move this secret into the unmanaged-device disclosure gate. There is
    /// no serializable intermediate state and no second owner of the key.
    pub fn into_personal_view(
        self,
        recovery_keyslot: u8,
    ) -> Result<PersonalRecoveryView, RecoveryError> {
        PersonalRecoveryView::new(self, recovery_keyslot)
    }

    /// Consume the key at an explicit unlock/recovery delivery boundary.
    /// The borrow cannot outlive the callback and this owner is zeroized
    /// immediately afterwards. The sink is responsible for protecting any
    /// copy it deliberately creates (for example, a one-response portal
    /// release or cryptsetup's stdin).
    pub fn deliver_to_unlock_sink<T>(self, sink: impl FnOnce(&str) -> T) -> T {
        sink(self.expose())
    }
}

impl fmt::Debug for SecretRecoveryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretRecoveryKey([REDACTED])")
    }
}

/// The only personal-device state from which UI code can display or copy the
/// recovery key. It is intentionally non-cloneable and non-serializable. The
/// key is zeroized when the view is acknowledged, cancelled, or crashes.
pub struct PersonalRecoveryView {
    recovery_key: SecretRecoveryKey,
    recovery_keyslot: u8,
    challenge_groups: [u8; 2],
    confirmed: bool,
}

impl PersonalRecoveryView {
    fn new(recovery_key: SecretRecoveryKey, recovery_keyslot: u8) -> Result<Self, RecoveryError> {
        if recovery_keyslot > 31 {
            return Err(RecoveryError::InvalidBinding);
        }

        let mut random = [0_u8; 2];
        let challenge_groups = loop {
            getrandom::fill(&mut random).map_err(|_| RecoveryError::RandomUnavailable)?;
            let mut groups = [(random[0] & 7) + 1, (random[1] & 7) + 1];
            if groups[0] != groups[1] {
                groups.sort_unstable();
                break groups;
            }
        };

        Ok(Self {
            recovery_key,
            recovery_keyslot,
            challenge_groups,
            confirmed: false,
        })
    }

    /// Canonical eight-group text for the active display/copy surface. UI
    /// integrations must keep this inside a protected, paste-once session.
    pub fn recovery_key_text(&self) -> &str {
        self.recovery_key.expose()
    }

    /// One-based group numbers for the two short confirmation fields.
    pub fn confirmation_groups(&self) -> [u8; 2] {
        self.challenge_groups
    }

    /// Confirm the two challenged groups without placing either supplied
    /// value in an error or loggable result.
    pub fn confirm_groups(&mut self, first: &str, second: &str) -> Result<(), RecoveryError> {
        let expected_first = self.group(self.challenge_groups[0]);
        let expected_second = self.group(self.challenge_groups[1]);
        if first.trim().eq_ignore_ascii_case(expected_first)
            && second.trim().eq_ignore_ascii_case(expected_second)
        {
            self.confirmed = true;
            Ok(())
        } else {
            self.confirmed = false;
            Err(RecoveryError::ConfirmationFailed)
        }
    }

    /// Consume and zeroize the disclosure view. The resulting record is safe
    /// to persist because it contains no recovery-key bytes.
    pub fn finish(self) -> Result<PersonalRecoveryConfirmation, RecoveryError> {
        if !self.confirmed {
            return Err(RecoveryError::NotConfirmed);
        }
        Ok(PersonalRecoveryConfirmation {
            v: 1,
            recovery_keyslot: self.recovery_keyslot,
            confirmed: true,
        })
    }

    fn group(&self, one_based_index: u8) -> &str {
        // Construction restricts this to 1..=8 and SecretRecoveryKey always
        // has exactly eight groups.
        self.recovery_key
            .expose()
            .split('-')
            .nth(usize::from(one_based_index - 1))
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn with_challenge_for_test(mut self, challenge_groups: [u8; 2]) -> Self {
        self.challenge_groups = challenge_groups;
        self
    }
}

impl fmt::Debug for PersonalRecoveryView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersonalRecoveryView")
            .field("recovery_key", &"[REDACTED]")
            .field("recovery_keyslot", &self.recovery_keyslot)
            .field("challenge_groups", &self.challenge_groups)
            .field("confirmed", &self.confirmed)
            .finish()
    }
}

/// Non-secret evidence that the personal recovery disclosure gate completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalRecoveryConfirmation {
    pub v: u8,
    pub recovery_keyslot: u8,
    pub confirmed: bool,
}

/// The fields cryptographically authenticated as HPKE associated data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBinding {
    pub organization_id: String,
    pub tenant_key_id: String,
    pub device_id: String,
    pub luks_uuid: String,
    pub recovery_keyslot: u8,
}

impl RecoveryBinding {
    pub fn validate(&self) -> Result<(), RecoveryError> {
        for value in [
            self.organization_id.as_str(),
            self.tenant_key_id.as_str(),
            self.device_id.as_str(),
        ] {
            if !valid_identifier(value) {
                return Err(RecoveryError::InvalidBinding);
            }
        }
        if !valid_uuid(&self.luks_uuid) || self.recovery_keyslot > 31 {
            return Err(RecoveryError::InvalidBinding);
        }
        Ok(())
    }

    fn authenticated_data(&self) -> Result<Vec<u8>, RecoveryError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(160);
        bytes.extend_from_slice(AAD_DOMAIN);
        push_field(&mut bytes, &self.organization_id)?;
        push_field(&mut bytes, &self.tenant_key_id)?;
        push_field(&mut bytes, &self.device_id)?;
        push_field(&mut bytes, &self.luks_uuid)?;
        bytes.push(self.recovery_keyslot);
        Ok(bytes)
    }
}

/// Public material delivered through the authenticated enrollment chain.
/// The HPKE key and receipt-signing key are intentionally distinct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRecoveryKey {
    pub v: u8,
    pub organization_id: String,
    pub key_id: String,
    pub suite: String,
    pub public_key: String,
    pub receipt_signing_public_key: String,
}

impl TenantRecoveryKey {
    pub fn validate(&self) -> Result<(), RecoveryError> {
        if self.v != 1
            || self.suite != HPKE_SUITE
            || !valid_identifier(&self.organization_id)
            || !valid_identifier(&self.key_id)
        {
            return Err(RecoveryError::InvalidTenantKey);
        }
        self.hpke_public_key()?;
        self.receipt_verifying_key()?;
        Ok(())
    }

    fn hpke_public_key(&self) -> Result<<Kem as KemTrait>::PublicKey, RecoveryError> {
        let bytes =
            decode_exact(&self.public_key, 32).map_err(|_| RecoveryError::InvalidTenantKey)?;
        <Kem as KemTrait>::PublicKey::from_bytes(&bytes)
            .map_err(|_| RecoveryError::InvalidTenantKey)
    }

    fn receipt_verifying_key(&self) -> Result<VerifyingKey, RecoveryError> {
        let bytes = decode_exact(&self.receipt_signing_public_key, 32)
            .map_err(|_| RecoveryError::InvalidTenantKey)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| RecoveryError::InvalidTenantKey)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| RecoveryError::InvalidTenantKey)
    }

    /// Seal the recovery key for this tenant. The result contains only public
    /// binding metadata and authenticated ciphertext.
    pub fn seal(
        &self,
        binding: &RecoveryBinding,
        recovery_key: &SecretRecoveryKey,
    ) -> Result<RecoveryEnvelope, RecoveryError> {
        self.validate()?;
        binding.validate()?;
        if binding.organization_id != self.organization_id || binding.tenant_key_id != self.key_id {
            return Err(RecoveryError::InvalidBinding);
        }

        let public_key = self.hpke_public_key()?;
        let aad = binding.authenticated_data()?;
        let (encapsulated, mut sender) =
            hpke::setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &public_key, HPKE_INFO)
                .map_err(|_| RecoveryError::WrapFailed)?;
        let mut ciphertext = Zeroizing::new(recovery_key.expose().as_bytes().to_vec());
        let tag = sender
            .seal_inout_detached(InOutBuf::from(ciphertext.as_mut_slice()), &aad)
            .map_err(|_| RecoveryError::WrapFailed)?;

        Ok(RecoveryEnvelope {
            v: 1,
            suite: HPKE_SUITE.to_string(),
            organization_id: binding.organization_id.clone(),
            tenant_key_id: binding.tenant_key_id.clone(),
            device_id: binding.device_id.clone(),
            luks_uuid: binding.luks_uuid.clone(),
            recovery_keyslot: binding.recovery_keyslot,
            encapsulated_key: URL_SAFE_NO_PAD.encode(encapsulated.to_bytes()),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext.as_slice()),
            tag: URL_SAFE_NO_PAD.encode(tag.to_bytes()),
        })
    }
}

/// The only object sent to Smplify. It cannot contain plaintext recovery
/// material by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEnvelope {
    pub v: u8,
    pub suite: String,
    pub organization_id: String,
    pub tenant_key_id: String,
    pub device_id: String,
    pub luks_uuid: String,
    pub recovery_keyslot: u8,
    pub encapsulated_key: String,
    pub ciphertext: String,
    pub tag: String,
}

impl RecoveryEnvelope {
    pub fn binding(&self) -> RecoveryBinding {
        RecoveryBinding {
            organization_id: self.organization_id.clone(),
            tenant_key_id: self.tenant_key_id.clone(),
            device_id: self.device_id.clone(),
            luks_uuid: self.luks_uuid.clone(),
            recovery_keyslot: self.recovery_keyslot,
        }
    }

    pub fn validate(&self) -> Result<(), RecoveryError> {
        if self.v != 1 || self.suite != HPKE_SUITE {
            return Err(RecoveryError::InvalidEnvelope);
        }
        self.binding()
            .validate()
            .map_err(|_| RecoveryError::InvalidEnvelope)?;
        decode_exact(&self.encapsulated_key, 32).map_err(|_| RecoveryError::InvalidEnvelope)?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&self.ciphertext)
            .map_err(|_| RecoveryError::InvalidEnvelope)?;
        if ciphertext.len() != 71 {
            return Err(RecoveryError::InvalidEnvelope);
        }
        decode_exact(&self.tag, 16).map_err(|_| RecoveryError::InvalidEnvelope)?;
        Ok(())
    }

    /// SHA-256 over a domain-separated, length-prefixed binary encoding.
    /// Receipt verification never relies on JSON map ordering.
    pub fn digest_hex(&self) -> Result<String, RecoveryError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(320);
        bytes.extend_from_slice(ENVELOPE_DIGEST_DOMAIN);
        bytes.push(self.v);
        push_field(&mut bytes, &self.suite).map_err(|_| RecoveryError::InvalidEnvelope)?;
        push_field(&mut bytes, &self.organization_id)
            .map_err(|_| RecoveryError::InvalidEnvelope)?;
        push_field(&mut bytes, &self.tenant_key_id).map_err(|_| RecoveryError::InvalidEnvelope)?;
        push_field(&mut bytes, &self.device_id).map_err(|_| RecoveryError::InvalidEnvelope)?;
        push_field(&mut bytes, &self.luks_uuid).map_err(|_| RecoveryError::InvalidEnvelope)?;
        bytes.push(self.recovery_keyslot);
        for encoded in [&self.encapsulated_key, &self.ciphertext, &self.tag] {
            let decoded = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| RecoveryError::InvalidEnvelope)?;
            push_bytes(&mut bytes, &decoded).map_err(|_| RecoveryError::InvalidEnvelope)?;
        }
        Ok(hex_lower(&Sha256::digest(bytes)))
    }

    /// Recipient-side unwrap. This is used by the Smplify recovery service
    /// and end-to-end tests; the device never has the tenant private key.
    pub fn open_for_recipient(
        &self,
        recipient_private_key: &[u8],
    ) -> Result<SecretRecoveryKey, RecoveryError> {
        self.validate()?;
        let private_key = <Kem as KemTrait>::PrivateKey::from_bytes(recipient_private_key)
            .map_err(|_| RecoveryError::UnwrapFailed)?;
        let encapsulated_bytes =
            decode_exact(&self.encapsulated_key, 32).map_err(|_| RecoveryError::UnwrapFailed)?;
        let encapsulated = <Kem as KemTrait>::EncappedKey::from_bytes(&encapsulated_bytes)
            .map_err(|_| RecoveryError::UnwrapFailed)?;
        let tag_bytes = decode_exact(&self.tag, 16).map_err(|_| RecoveryError::UnwrapFailed)?;
        let tag =
            AeadTag::<Aead>::from_bytes(&tag_bytes).map_err(|_| RecoveryError::UnwrapFailed)?;
        let mut ciphertext = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(&self.ciphertext)
                .map_err(|_| RecoveryError::UnwrapFailed)?,
        );
        let aad = self
            .binding()
            .authenticated_data()
            .map_err(|_| RecoveryError::UnwrapFailed)?;
        let mut receiver = hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &private_key,
            &encapsulated,
            HPKE_INFO,
        )
        .map_err(|_| RecoveryError::UnwrapFailed)?;
        receiver
            .open_inout_detached(InOutBuf::from(ciphertext.as_mut_slice()), &aad, &tag)
            .map_err(|_| RecoveryError::UnwrapFailed)?;
        let text =
            std::str::from_utf8(ciphertext.as_slice()).map_err(|_| RecoveryError::UnwrapFailed)?;
        SecretRecoveryKey::parse(text).map_err(|_| RecoveryError::UnwrapFailed)
    }
}

/// Portal acknowledgement. A successful upload is not an escrow until this
/// signature and every binding field verify locally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowReceipt {
    pub v: u8,
    pub receipt_id: String,
    pub received_at: String,
    pub organization_id: String,
    pub tenant_key_id: String,
    pub device_id: String,
    pub luks_uuid: String,
    pub recovery_keyslot: u8,
    pub envelope_sha256: String,
    pub signature: String,
}

impl EscrowReceipt {
    /// Exact bytes a Smplify tenant receipt key signs.
    pub fn signing_payload(&self) -> Result<Vec<u8>, RecoveryError> {
        if self.v != 1
            || !valid_identifier(&self.receipt_id)
            || !valid_timestamp(&self.received_at)
            || !valid_identifier(&self.organization_id)
            || !valid_identifier(&self.tenant_key_id)
            || !valid_identifier(&self.device_id)
            || !valid_uuid(&self.luks_uuid)
            || self.recovery_keyslot > 31
            || !valid_sha256(&self.envelope_sha256)
        {
            return Err(RecoveryError::InvalidReceipt);
        }
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(RECEIPT_DOMAIN);
        bytes.push(self.v);
        for value in [
            &self.receipt_id,
            &self.received_at,
            &self.organization_id,
            &self.tenant_key_id,
            &self.device_id,
            &self.luks_uuid,
        ] {
            push_field(&mut bytes, value).map_err(|_| RecoveryError::InvalidReceipt)?;
        }
        bytes.push(self.recovery_keyslot);
        push_field(&mut bytes, &self.envelope_sha256).map_err(|_| RecoveryError::InvalidReceipt)?;
        Ok(bytes)
    }

    /// Verify signature, digest, and all device/LUKS/keyslot bindings.
    pub fn verify(
        &self,
        tenant_key: &TenantRecoveryKey,
        envelope: &RecoveryEnvelope,
    ) -> Result<VerifiedEscrowReceipt, RecoveryError> {
        tenant_key.validate()?;
        envelope.validate()?;
        let expected_digest = envelope.digest_hex()?;
        let binding_matches = self.organization_id == envelope.organization_id
            && self.tenant_key_id == envelope.tenant_key_id
            && self.device_id == envelope.device_id
            && self.luks_uuid == envelope.luks_uuid
            && self.recovery_keyslot == envelope.recovery_keyslot
            && self.organization_id == tenant_key.organization_id
            && self.tenant_key_id == tenant_key.key_id
            && self.envelope_sha256 == expected_digest;
        if !binding_matches {
            return Err(RecoveryError::ReceiptBindingMismatch);
        }

        let signature_bytes = decode_exact(&self.signature, 64)
            .map_err(|_| RecoveryError::InvalidReceiptSignature)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| RecoveryError::InvalidReceiptSignature)?;
        tenant_key
            .receipt_verifying_key()?
            .verify_strict(&self.signing_payload()?, &signature)
            .map_err(|_| RecoveryError::InvalidReceiptSignature)?;

        Ok(VerifiedEscrowReceipt {
            receipt_id: self.receipt_id.clone(),
            received_at: self.received_at.clone(),
            envelope_sha256: expected_digest,
        })
    }
}

/// Cannot be constructed through deserialization; possession means local
/// verification completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEscrowReceipt {
    receipt_id: String,
    received_at: String,
    envelope_sha256: String,
}

impl VerifiedEscrowReceipt {
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    pub fn received_at(&self) -> &str {
        &self.received_at
    }

    pub fn envelope_sha256(&self) -> &str {
        &self.envelope_sha256
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn valid_timestamp(value: &str) -> bool {
    value.len() >= 20
        && value.len() <= 40
        && value.is_ascii()
        && value.ends_with('Z')
        && value.contains('T')
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn push_field(target: &mut Vec<u8>, value: &str) -> Result<(), RecoveryError> {
    push_bytes(target, value.as_bytes())
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), RecoveryError> {
    let length = u16::try_from(value.len()).map_err(|_| RecoveryError::InvalidBinding)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn decode_exact(value: &str, expected: usize) -> Result<Vec<u8>, RecoveryError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RecoveryError::InvalidEnvelope)?;
    if decoded.len() != expected {
        return Err(RecoveryError::InvalidEnvelope);
    }
    Ok(decoded)
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

    const KEY: &str = "lhkbicdj-trbuftjv-tviijfck-dfvbknrh-uiulbhui-higltier-kecfhkbk-egrirkui";

    struct Fixture {
        tenant: TenantRecoveryKey,
        recipient_private_key: Vec<u8>,
        receipt_signing_key: SigningKey,
        binding: RecoveryBinding,
    }

    fn fixture() -> Fixture {
        let (private_key, public_key) = Kem::gen_keypair();
        let receipt_signing_key = SigningKey::from_bytes(&[9; 32]);
        Fixture {
            tenant: TenantRecoveryKey {
                v: 1,
                organization_id: "org_acme".into(),
                key_id: "trk_2026_08".into(),
                suite: HPKE_SUITE.into(),
                public_key: URL_SAFE_NO_PAD.encode(public_key.to_bytes()),
                receipt_signing_public_key: URL_SAFE_NO_PAD
                    .encode(receipt_signing_key.verifying_key().to_bytes()),
            },
            recipient_private_key: private_key.to_bytes().to_vec(),
            receipt_signing_key,
            binding: RecoveryBinding {
                organization_id: "org_acme".into(),
                tenant_key_id: "trk_2026_08".into(),
                device_id: "dev_456".into(),
                luks_uuid: "21d4af4f-a19c-4c6a-b4e8-dd50e9f7ecb9".into(),
                recovery_keyslot: 1,
            },
        }
    }

    fn signed_receipt(fixture: &Fixture, envelope: &RecoveryEnvelope) -> EscrowReceipt {
        let mut receipt = EscrowReceipt {
            v: 1,
            receipt_id: "rct_000001".into(),
            received_at: "2026-08-27T21:00:00Z".into(),
            organization_id: envelope.organization_id.clone(),
            tenant_key_id: envelope.tenant_key_id.clone(),
            device_id: envelope.device_id.clone(),
            luks_uuid: envelope.luks_uuid.clone(),
            recovery_keyslot: envelope.recovery_keyslot,
            envelope_sha256: envelope.digest_hex().unwrap(),
            signature: String::new(),
        };
        receipt.signature = URL_SAFE_NO_PAD.encode(
            fixture
                .receipt_signing_key
                .sign(&receipt.signing_payload().unwrap())
                .to_bytes(),
        );
        receipt
    }

    #[test]
    fn systemd_modhex64_is_normalized_and_redacted() {
        let compact = KEY.replace('-', "").to_ascii_uppercase();
        let key = SecretRecoveryKey::parse(&compact).unwrap();
        assert_eq!(key.expose(), KEY);
        assert_eq!(format!("{key:?}"), "SecretRecoveryKey([REDACTED])");
        assert!(SecretRecoveryKey::parse("not-a-recovery-key").is_err());
    }

    #[test]
    fn unlock_sink_borrow_is_explicit_and_consumes_the_owner() {
        let key = SecretRecoveryKey::parse(KEY).unwrap();
        let length = key.deliver_to_unlock_sink(str::len);
        assert_eq!(length, 71);
    }

    #[test]
    fn envelope_round_trip_is_bound_to_the_device_and_luks_slot() {
        let fixture = fixture();
        let secret = SecretRecoveryKey::parse(KEY).unwrap();
        let envelope = fixture.tenant.seal(&fixture.binding, &secret).unwrap();
        let opened = envelope
            .open_for_recipient(&fixture.recipient_private_key)
            .unwrap();
        assert_eq!(opened.expose(), KEY);

        let serialized = serde_json::to_string(&envelope).unwrap();
        assert!(!serialized.contains(KEY));
        assert!(!serialized.contains(&KEY.replace('-', "")));

        let mut moved = envelope;
        moved.device_id = "dev_999".into();
        assert!(matches!(
            moved.open_for_recipient(&fixture.recipient_private_key),
            Err(RecoveryError::UnwrapFailed)
        ));
    }

    #[test]
    fn only_a_signed_exactly_bound_receipt_becomes_verified() {
        let fixture = fixture();
        let secret = SecretRecoveryKey::parse(KEY).unwrap();
        let envelope = fixture.tenant.seal(&fixture.binding, &secret).unwrap();
        let receipt = signed_receipt(&fixture, &envelope);
        let verified = receipt.verify(&fixture.tenant, &envelope).unwrap();
        assert_eq!(verified.receipt_id(), "rct_000001");
        assert_eq!(verified.envelope_sha256(), envelope.digest_hex().unwrap());

        let mut wrong_device = receipt.clone();
        wrong_device.device_id = "dev_999".into();
        assert_eq!(
            wrong_device.verify(&fixture.tenant, &envelope),
            Err(RecoveryError::ReceiptBindingMismatch)
        );

        let mut forged = receipt;
        forged.received_at = "2026-08-27T21:00:01Z".into();
        assert_eq!(
            forged.verify(&fixture.tenant, &envelope),
            Err(RecoveryError::InvalidReceiptSignature)
        );
    }

    #[test]
    fn validation_refuses_suite_downgrade_and_keyslot_overflow() {
        let mut fixture = fixture();
        fixture.tenant.suite = "AES-ECB".into();
        assert_eq!(
            fixture.tenant.validate(),
            Err(RecoveryError::InvalidTenantKey)
        );
        fixture.binding.recovery_keyslot = 32;
        assert_eq!(
            fixture.binding.validate(),
            Err(RecoveryError::InvalidBinding)
        );
    }

    #[test]
    fn personal_view_is_one_owner_and_persists_no_secret() {
        let secret = SecretRecoveryKey::parse(KEY).unwrap();
        let mut view = secret
            .into_personal_view(1)
            .unwrap()
            .with_challenge_for_test([2, 7]);
        assert_eq!(view.confirmation_groups(), [2, 7]);
        assert_eq!(view.recovery_key_text(), KEY);
        assert_eq!(
            view.confirm_groups("wrong", "kecfhkbk"),
            Err(RecoveryError::ConfirmationFailed)
        );
        assert!(matches!(view.finish(), Err(RecoveryError::NotConfirmed)));

        let secret = SecretRecoveryKey::parse(KEY).unwrap();
        let mut view = secret
            .into_personal_view(1)
            .unwrap()
            .with_challenge_for_test([2, 7]);
        view.confirm_groups("TRBUFTJV", " KECFHKBK ").unwrap();
        let confirmation = view.finish().unwrap();
        let serialized = serde_json::to_string(&confirmation).unwrap();
        assert_eq!(
            serialized,
            r#"{"v":1,"recovery_keyslot":1,"confirmed":true}"#
        );
        assert!(!serialized.contains("trbuftjv"));
        assert!(!serialized.contains(KEY));
    }
}
