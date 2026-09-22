//! Integrity-protected, profile/method/filter-bound PIM cursors.
//!
//! A cursor is opaque correlation state, not authority. The service still
//! applies the admitted client's method partition on every request. Signing
//! prevents a client from changing its position or moving a cursor between
//! profiles, methods or filters; it does not encrypt record content, so only
//! fixed-size digests of the profile and canonical filter binding are carried.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::PimMethod;

type HmacSha256 = Hmac<Sha256>;

const CURSOR_VERSION: u8 = 1;
const CURSOR_PREFIX: &str = "pim1";
const MAX_CURSOR_BYTES: usize = 512;
const KEY_BYTES: usize = 32;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CursorError {
    #[error("PIM cursor is invalid for this profile, method or filter")]
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorPosition {
    /// Stable snapshot/change sequence selected when the page started.
    pub snapshot: u64,
    /// Next record/change position within that snapshot.
    pub position: u64,
}

/// Profile-bound HMAC cursor signer. The key is injected by the future
/// service-private state layer; it is never serialized into an IPC message.
pub struct CursorSigner {
    key: [u8; KEY_BYTES],
    profile_digest: String,
}

impl CursorSigner {
    /// Construct from an already-durable private key. An all-zero key is
    /// refused so tests or service wiring cannot accidentally ship a constant.
    pub fn from_key(key: [u8; KEY_BYTES], profile_id: &str) -> Result<Self, CursorError> {
        if key.iter().all(|byte| *byte == 0) || !valid_profile_id(profile_id) {
            return Err(CursorError::Invalid);
        }
        Ok(Self {
            key,
            profile_digest: digest(profile_id.as_bytes()),
        })
    }

    /// Seal one position for an admitted method and a canonical filter/sort
    /// binding. The binding is hashed before it enters the cursor.
    pub fn seal(
        &self,
        method: PimMethod,
        filter_binding: &[u8],
        position: CursorPosition,
    ) -> Result<String, CursorError> {
        let payload = CursorPayload {
            v: CURSOR_VERSION,
            profile: self.profile_digest.clone(),
            method: method.as_str().to_string(),
            filter: digest(filter_binding),
            snapshot: position.snapshot,
            position: position.position,
        };
        let payload = serde_json::to_vec(&payload).map_err(|_| CursorError::Invalid)?;
        let encoded = URL_SAFE_NO_PAD.encode(&payload);
        let signature = self.sign(encoded.as_bytes())?;
        let cursor = format!(
            "{CURSOR_PREFIX}.{encoded}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        );
        if cursor.len() > MAX_CURSOR_BYTES {
            return Err(CursorError::Invalid);
        }
        Ok(cursor)
    }

    /// Verify and open a cursor for the exact profile, method and canonical
    /// filter/sort binding expected by the request.
    pub fn open(
        &self,
        cursor: &str,
        method: PimMethod,
        filter_binding: &[u8],
    ) -> Result<CursorPosition, CursorError> {
        if cursor.is_empty() || cursor.len() > MAX_CURSOR_BYTES {
            return Err(CursorError::Invalid);
        }
        let mut parts = cursor.split('.');
        let (Some(prefix), Some(encoded), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorError::Invalid);
        };
        if prefix != CURSOR_PREFIX || encoded.is_empty() || signature.is_empty() {
            return Err(CursorError::Invalid);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| CursorError::Invalid)?;
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| CursorError::Invalid)?;
        mac.update(encoded.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| CursorError::Invalid)?;

        let payload = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CursorError::Invalid)?;
        let payload: CursorPayload =
            serde_json::from_slice(&payload).map_err(|_| CursorError::Invalid)?;
        if payload.v != CURSOR_VERSION
            || payload.profile != self.profile_digest
            || payload.method != method.as_str()
            || payload.filter != digest(filter_binding)
        {
            return Err(CursorError::Invalid);
        }
        Ok(CursorPosition {
            snapshot: payload.snapshot,
            position: payload.position,
        })
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, CursorError> {
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| CursorError::Invalid)?;
        mac.update(payload);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

impl Drop for CursorSigner {
    fn drop(&mut self) {
        // The service must additionally keep its state non-dumpable and core
        // dumps disabled (ADR-009); key zeroization is one layer, not a
        // substitute for the process boundary.
        self.key.zeroize();
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    v: u8,
    profile: String,
    method: String,
    filter: String,
    snapshot: u64,
    position: u64,
}

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn valid_profile_id(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("profile_") else {
        return false;
    };
    !suffix.is_empty()
        && value.len() <= 80
        && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn test_signer(profile: &str, fill: u8) -> CursorSigner {
        CursorSigner::from_key([fill; KEY_BYTES], profile).unwrap()
    }

    #[test]
    fn round_trip_preserves_only_position_and_snapshot() {
        let signer = test_signer("profile_A1", 7);
        let expected = CursorPosition {
            snapshot: 44,
            position: 12,
        };
        let cursor = signer
            .seal(PimMethod::EventsList, b"calendar=A;sort=start", expected)
            .unwrap();
        assert_eq!(
            signer
                .open(&cursor, PimMethod::EventsList, b"calendar=A;sort=start")
                .unwrap(),
            expected
        );
        assert!(!cursor.contains("profile_A1"));
        assert!(!cursor.contains("calendar=A"));
        assert!(cursor.len() <= MAX_CURSOR_BYTES);
    }

    #[test]
    fn tampered_payload_and_signature_fail_closed() {
        let signer = test_signer("profile_A1", 8);
        let cursor = signer
            .seal(
                PimMethod::ChangesSince,
                b"all",
                CursorPosition {
                    snapshot: 9,
                    position: 3,
                },
            )
            .unwrap();
        let mut payload_tampered = cursor.clone().into_bytes();
        let offset = CURSOR_PREFIX.len() + 2;
        payload_tampered[offset] = if payload_tampered[offset] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert_eq!(
            signer.open(
                std::str::from_utf8(&payload_tampered).unwrap(),
                PimMethod::ChangesSince,
                b"all"
            ),
            Err(CursorError::Invalid)
        );

        let mut signature_tampered = cursor.into_bytes();
        let last = signature_tampered.len() - 1;
        signature_tampered[last] = if signature_tampered[last] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert_eq!(
            signer.open(
                std::str::from_utf8(&signature_tampered).unwrap(),
                PimMethod::ChangesSince,
                b"all"
            ),
            Err(CursorError::Invalid)
        );
    }

    #[test]
    fn cursor_cannot_cross_profile_method_filter_or_key() {
        let signer = test_signer("profile_A1", 9);
        let cursor = signer
            .seal(
                PimMethod::RemindersList,
                b"state=open;sort=due",
                CursorPosition {
                    snapshot: 10,
                    position: 2,
                },
            )
            .unwrap();
        assert!(
            signer
                .open(&cursor, PimMethod::EventsList, b"state=open;sort=due")
                .is_err()
        );
        assert!(
            signer
                .open(&cursor, PimMethod::RemindersList, b"state=all;sort=due")
                .is_err()
        );
        assert!(
            test_signer("profile_B2", 9)
                .open(&cursor, PimMethod::RemindersList, b"state=open;sort=due")
                .is_err()
        );
        assert!(
            test_signer("profile_A1", 10)
                .open(&cursor, PimMethod::RemindersList, b"state=open;sort=due")
                .is_err()
        );
    }

    #[test]
    fn signed_payload_extensions_are_still_rejected() {
        let signer = test_signer("profile_A1", 11);
        let mut payload = serde_json::to_value(CursorPayload {
            v: 1,
            profile: signer.profile_digest.clone(),
            method: PimMethod::CalendarList.as_str().into(),
            filter: digest(b"all"),
            snapshot: 1,
            position: 0,
        })
        .unwrap();
        payload
            .as_object_mut()
            .unwrap()
            .insert("profile_id".into(), json!("profile_B2"));
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let cursor = format!(
            "{CURSOR_PREFIX}.{encoded}.{}",
            URL_SAFE_NO_PAD.encode(signer.sign(encoded.as_bytes()).unwrap())
        );
        assert_eq!(
            signer.open(&cursor, PimMethod::CalendarList, b"all"),
            Err(CursorError::Invalid)
        );
        assert!(matches!(payload, Value::Object(_)));
    }

    #[test]
    fn constant_or_malformed_signer_identity_is_refused() {
        assert!(CursorSigner::from_key([0; KEY_BYTES], "profile_A1").is_err());
        assert!(CursorSigner::from_key([1; KEY_BYTES], "other_A1").is_err());
        assert!(CursorSigner::from_key([1; KEY_BYTES], "profile_").is_err());
    }
}
