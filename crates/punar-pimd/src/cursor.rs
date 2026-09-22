//! Integrity-protected, profile/method/filter-bound PIM cursors.
//!
//! A cursor is opaque correlation state, not authority. The service still
//! applies the admitted client's method partition on every request. Signing
//! prevents a client from changing its position or moving a cursor between
//! profiles, methods or filters; it does not encrypt record content, so only
//! fixed-size digests of the profile and canonical filter binding are carried.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::PimMethod;

type HmacSha256 = Hmac<Sha256>;

const CURSOR_VERSION: u8 = 1;
const CURSOR_PREFIX: &str = "pim1";
const MAX_CURSOR_BYTES: usize = 512;
const KEY_BYTES: usize = 32;
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CursorError {
    #[error("PIM cursor is invalid for this profile, method or filter")]
    Invalid,
}

#[derive(Debug, Error)]
pub enum CursorKeyError {
    #[error("PIM cursor key I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("PIM cursor key state is invalid")]
    Invalid,
    #[error("PIM cursor key entropy is unavailable")]
    Entropy,
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

    /// Load or atomically create the service-private profile key. Existing
    /// malformed, aliased, cross-profile or over-permissive state fails closed
    /// and is never replaced. Concurrent first opens converge on the one file
    /// created with hard-link create-new semantics.
    pub fn load_or_create(path: &Path, profile_id: &str) -> Result<Self, CursorKeyError> {
        if !valid_profile_id(profile_id) {
            return Err(CursorKeyError::Invalid);
        }
        prepare_private_parent(path)?;
        if path.exists() {
            return load_key(path, profile_id);
        }

        let mut key = [0_u8; KEY_BYTES];
        getrandom::fill(&mut key).map_err(|_| CursorKeyError::Entropy)?;
        if key.iter().all(|byte| *byte == 0) {
            key.zeroize();
            return Err(CursorKeyError::Entropy);
        }
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(key));
        let document = CursorKeyDocumentRef {
            v: CURSOR_VERSION,
            profile_id,
            key: &encoded,
        };
        let mut bytes =
            Zeroizing::new(serde_json::to_vec(&document).map_err(|_| CursorKeyError::Invalid)?);
        bytes.push(b'\n');
        match create_private_once(path, &bytes) {
            Ok(()) => CursorSigner::from_key(key, profile_id).map_err(|_| CursorKeyError::Invalid),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                key.zeroize();
                load_key(path, profile_id)
            }
            Err(error) => {
                key.zeroize();
                Err(error.into())
            }
        }
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

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CursorKeyDocumentRef<'a> {
    v: u8,
    profile_id: &'a str,
    key: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorKeyDocument {
    v: u8,
    profile_id: String,
    key: String,
}

fn prepare_private_parent(path: &Path) -> Result<(), CursorKeyError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(CursorKeyError::Invalid)?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != rustix::process::getuid().as_raw()
            {
                return Err(CursorKeyError::Invalid);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(parent)?;
        }
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(parent, fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o777 != PRIVATE_DIR_MODE
    {
        return Err(CursorKeyError::Invalid);
    }
    Ok(())
}

fn load_key(path: &Path, profile_id: &str) -> Result<CursorSigner, CursorKeyError> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let input = File::from(descriptor);
    let metadata = input.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || metadata.len() > 512
    {
        return Err(CursorKeyError::Invalid);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    input.take(513).read_to_end(&mut bytes)?;
    if bytes.len() > 512 {
        return Err(CursorKeyError::Invalid);
    }
    let mut document: CursorKeyDocument =
        serde_json::from_slice(&bytes).map_err(|_| CursorKeyError::Invalid)?;
    bytes.zeroize();
    if document.v != CURSOR_VERSION || document.profile_id != profile_id {
        document.key.zeroize();
        return Err(CursorKeyError::Invalid);
    }
    let mut decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(&document.key)
            .map_err(|_| CursorKeyError::Invalid)?,
    );
    document.key.zeroize();
    if decoded.len() != KEY_BYTES {
        return Err(CursorKeyError::Invalid);
    }
    let mut key = [0_u8; KEY_BYTES];
    key.copy_from_slice(&decoded);
    decoded.zeroize();
    CursorSigner::from_key(key, profile_id).map_err(|_| CursorKeyError::Invalid)
}

fn create_private_once(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cursor key has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid cursor key name"))?;
    let mut suffix = [0_u8; 12];
    getrandom::fill(&mut suffix).map_err(|_| io::Error::other("cursor key entropy unavailable"))?;
    let temporary = parent.join(format!(".{name}.pimd-{}", URL_SAFE_NO_PAD.encode(suffix)));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(&temporary)?;
    let result = (|| {
        output.write_all(bytes)?;
        output.sync_all()?;
        fs::hard_link(&temporary, path)?;
        fs::remove_file(&temporary)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
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
    use std::path::PathBuf;

    struct TempTree(PathBuf);

    impl TempTree {
        fn new() -> Self {
            let mut suffix = [0_u8; 12];
            getrandom::fill(&mut suffix).unwrap();
            Self(std::env::temp_dir().join(format!(
                "punar-pimd-cursor-test-{}",
                URL_SAFE_NO_PAD.encode(suffix)
            )))
        }

        fn key_path(&self) -> PathBuf {
            self.0.join("cursor-key.json")
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

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

    #[test]
    fn private_key_survives_restart_and_keeps_existing_cursors_valid() {
        let tree = TempTree::new();
        let path = tree.key_path();
        let signer = CursorSigner::load_or_create(&path, "profile_A1").unwrap();
        let cursor = signer
            .seal(
                PimMethod::ChangesSince,
                b"all",
                CursorPosition {
                    snapshot: 22,
                    position: 19,
                },
            )
            .unwrap();
        drop(signer);

        let reopened = CursorSigner::load_or_create(&path, "profile_A1").unwrap();
        assert_eq!(
            reopened
                .open(&cursor, PimMethod::ChangesSince, b"all")
                .unwrap(),
            CursorPosition {
                snapshot: 22,
                position: 19,
            }
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_DIR_MODE
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            PRIVATE_FILE_MODE
        );
    }

    #[test]
    fn cross_profile_or_corrupt_key_state_is_not_replaced() {
        let tree = TempTree::new();
        let path = tree.key_path();
        CursorSigner::load_or_create(&path, "profile_A1").unwrap();
        let original = fs::read(&path).unwrap();
        assert!(CursorSigner::load_or_create(&path, "profile_B2").is_err());
        assert_eq!(fs::read(&path).unwrap(), original);

        fs::write(&path, b"{not-json}\n").unwrap();
        let corrupt = fs::read(&path).unwrap();
        assert!(CursorSigner::load_or_create(&path, "profile_A1").is_err());
        assert_eq!(fs::read(&path).unwrap(), corrupt);
    }

    #[test]
    fn permissive_or_aliased_key_file_is_refused() {
        let tree = TempTree::new();
        let path = tree.key_path();
        CursorSigner::load_or_create(&path, "profile_A1").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(CursorSigner::load_or_create(&path, "profile_A1").is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        fs::hard_link(&path, tree.0.join("cursor-key-alias.json")).unwrap();
        assert!(CursorSigner::load_or_create(&path, "profile_A1").is_err());
    }

    #[test]
    fn symbolic_key_path_is_never_followed() {
        use std::os::unix::fs::symlink;

        let tree = TempTree::new();
        fs::create_dir_all(&tree.0).unwrap();
        fs::set_permissions(&tree.0, fs::Permissions::from_mode(PRIVATE_DIR_MODE)).unwrap();
        let target = tree.0.join("target.json");
        fs::write(&target, b"not-a-key\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        let path = tree.key_path();
        symlink(&target, &path).unwrap();

        assert!(CursorSigner::load_or_create(&path, "profile_A1").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"not-a-key\n");
    }
}
