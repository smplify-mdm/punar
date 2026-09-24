//! Service-private persistent credential vault.
//!
//! Credentials are authenticated and encrypted record-by-record with a random
//! XChaCha20-Poly1305 nonce. The associated data binds every ciphertext to its
//! schema, profile, account and credential kind. Opening a vault requires a
//! kernel-observed LUKS2 device-mapper backing for the state directory; file
//! permissions and application claims are not accepted as encryption proof.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use punar_common::storage::{self, StorageSources, luks2_backing};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::credential_entry::{CredentialEntryError, receive_credential};

const VAULT_VERSION: u8 = 1;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_VAULT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_KEY_FILE_BYTES: u64 = 512;
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("PIM credential vault I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("PIM credential vault state is invalid")]
    Invalid,
    #[error("PIM credential vault belongs to a different profile")]
    ProfileMismatch,
    #[error("PIM credentials require verified LUKS2 storage")]
    StorageEncryptionRequired,
    #[error("PIM credential encryption failed")]
    Crypto,
    #[error("PIM credential was not found")]
    NotFound,
    #[error("PIM credential entropy is unavailable")]
    Entropy,
    #[error(transparent)]
    CredentialEntry(#[from] CredentialEntryError),
}

/// Closed credential classes used internally by provider adapters. Values are
/// never serialized into the ordinary PIM IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    IncomingPassword,
    OutgoingPassword,
    OAuthRefreshToken,
}

impl CredentialKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::IncomingPassword => "incoming_password",
            Self::OutgoingPassword => "outgoing_password",
            Self::OAuthRefreshToken => "oauth_refresh_token",
        }
    }
}

/// Evidence that the state directory resolves directly to a LUKS2
/// device-mapper filesystem. Construction is deliberately restricted to the
/// kernel/sysfs inspection below (plus this module's tests).
pub struct EncryptedStorageProof {
    dev: u64,
    device: String,
}

impl EncryptedStorageProof {
    /// Verify the nearest existing ancestor of `state_root` against Linux
    /// sysfs. The device mapper UUID must carry cryptsetup's `CRYPT-LUKS2-`
    /// prefix — on a btrfs subvolume, every member of the pool's must
    /// ([`punar_common::storage`], shared with punard's managed posture). A
    /// missing path, indirection we cannot prove, or plaintext filesystem
    /// fails closed.
    pub fn verify(state_root: &Path) -> Result<Self, VaultError> {
        verify_storage_with_sysfs(state_root, &StorageSources::default())
    }

    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedRecord {
    v: u8,
    profile_id: String,
    account_id: String,
    kind: CredentialKind,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultState {
    v: u8,
    profile_id: String,
    records: BTreeMap<String, EncryptedRecord>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct KeyDocumentRef<'a> {
    v: u8,
    profile_id: &'a str,
    key: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyDocument {
    v: u8,
    profile_id: String,
    key: String,
}

/// Profile-bound vault. It deliberately has no operation that lists or
/// returns credential values to an application caller.
pub struct CredentialVault {
    path: PathBuf,
    profile_id: String,
    key: [u8; KEY_BYTES],
    state: Mutex<VaultState>,
}

impl CredentialVault {
    pub fn open(
        state_root: &Path,
        profile_id: &str,
        proof: &EncryptedStorageProof,
    ) -> Result<Self, VaultError> {
        validate_profile_id(profile_id)?;
        if proof.device.is_empty() || nearest_existing_device(state_root)? != proof.dev {
            return Err(VaultError::StorageEncryptionRequired);
        }
        let path = state_root.join("credentials.json");
        let key_path = state_root.join("credential-key.json");
        prepare_private_parent(&path)?;
        let key = load_or_create_key(&key_path, profile_id)?;
        let state = match read_private(&path, MAX_VAULT_BYTES)? {
            Some(mut bytes) => {
                let decoded = serde_json::from_slice(&bytes).map_err(|_| VaultError::Invalid);
                bytes.zeroize();
                decoded?
            }
            None => {
                let state = VaultState {
                    v: VAULT_VERSION,
                    profile_id: profile_id.to_string(),
                    records: BTreeMap::new(),
                };
                persist_state(&path, &state)?;
                state
            }
        };
        validate_state(&state, profile_id)?;
        Ok(Self {
            path,
            profile_id: profile_id.to_string(),
            key,
            state: Mutex::new(state),
        })
    }

    /// Encrypt and durably replace one credential. The caller's mutable input
    /// is cleared on every success or failure path.
    pub fn store(
        &self,
        account_id: &str,
        kind: CredentialKind,
        secret: &mut [u8],
    ) -> Result<(), VaultError> {
        let result = self.store_inner(account_id, kind, secret);
        secret.zeroize();
        result
    }

    /// Receive a value from the one-use non-dumpable entry helper and move it
    /// directly into the encrypted vault. The normal PIM IPC is not involved.
    pub fn receive_and_store(
        &self,
        account_id: &str,
        kind: CredentialKind,
        channel: OwnedFd,
    ) -> Result<(), VaultError> {
        let mut secret = receive_credential(channel)?;
        self.store(account_id, kind, &mut secret)
    }

    /// Receive one open-protocol password and commit the IMAP and SMTP
    /// credential records together. Many providers issue one app password for
    /// both services; keeping two typed records lets each adapter request only
    /// the credential class it needs without making the entry helper send the
    /// secret twice.
    pub(crate) fn receive_and_store_shared_password(
        &self,
        account_id: &str,
        channel: OwnedFd,
    ) -> Result<(), VaultError> {
        let secret = receive_credential(channel)?;
        validate_account_id(account_id)?;

        let mut state = self.state.lock().unwrap();
        if state
            .records
            .values()
            .any(|record| record.account_id == account_id)
        {
            return Err(VaultError::Invalid);
        }
        let incoming =
            self.encrypt_record(account_id, CredentialKind::IncomingPassword, &secret)?;
        let outgoing =
            self.encrypt_record(account_id, CredentialKind::OutgoingPassword, &secret)?;
        let mut candidate = state.clone();
        candidate.records.insert(
            record_key(account_id, CredentialKind::IncomingPassword),
            incoming,
        );
        candidate.records.insert(
            record_key(account_id, CredentialKind::OutgoingPassword),
            outgoing,
        );
        validate_state(&candidate, &self.profile_id)?;
        persist_state(&self.path, &candidate)?;
        *state = candidate;
        Ok(())
    }

    fn store_inner(
        &self,
        account_id: &str,
        kind: CredentialKind,
        secret: &[u8],
    ) -> Result<(), VaultError> {
        validate_account_id(account_id)?;
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(VaultError::Invalid);
        }
        let record = self.encrypt_record(account_id, kind, secret)?;
        let key = record_key(account_id, kind);
        let mut state = self.state.lock().unwrap();
        let mut candidate = state.clone();
        candidate.records.insert(key, record);
        validate_state(&candidate, &self.profile_id)?;
        persist_state(&self.path, &candidate)?;
        *state = candidate;
        Ok(())
    }

    fn encrypt_record(
        &self,
        account_id: &str,
        kind: CredentialKind,
        secret: &[u8],
    ) -> Result<EncryptedRecord, VaultError> {
        validate_account_id(account_id)?;
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(VaultError::Invalid);
        }
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| VaultError::Entropy)?;
        let aad = associated_data(&self.profile_id, account_id, kind);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| VaultError::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::Crypto)?;
        Ok(EncryptedRecord {
            v: VAULT_VERSION,
            profile_id: self.profile_id.clone(),
            account_id: account_id.to_string(),
            kind,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    /// Use one decrypted value inside the service. The temporary plaintext is
    /// zeroized immediately after the callback returns and cannot be obtained
    /// through the public IPC dispatcher.
    pub(crate) fn with_secret<T>(
        &self,
        account_id: &str,
        kind: CredentialKind,
        use_secret: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, VaultError> {
        validate_account_id(account_id)?;
        let record = {
            let state = self.state.lock().unwrap();
            state
                .records
                .get(&record_key(account_id, kind))
                .cloned()
                .ok_or(VaultError::NotFound)?
        };
        let mut nonce = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(&record.nonce)
                .map_err(|_| VaultError::Invalid)?,
        );
        if nonce.len() != NONCE_BYTES {
            return Err(VaultError::Invalid);
        }
        let ciphertext = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(&record.ciphertext)
                .map_err(|_| VaultError::Invalid)?,
        );
        let aad = associated_data(&self.profile_id, account_id, kind);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| VaultError::Crypto)?;
        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        nonce_bytes.copy_from_slice(&nonce);
        nonce.zeroize();
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce_bytes),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| VaultError::Crypto)?,
        );
        Ok(use_secret(&plaintext))
    }

    /// Remove every credential for an account as one durable local change.
    pub fn remove_account(&self, account_id: &str) -> Result<bool, VaultError> {
        validate_account_id(account_id)?;
        let mut state = self.state.lock().unwrap();
        let mut candidate = state.clone();
        let before = candidate.records.len();
        candidate
            .records
            .retain(|_, record| record.account_id != account_id);
        if candidate.records.len() == before {
            return Ok(false);
        }
        persist_state(&self.path, &candidate)?;
        *state = candidate;
        Ok(true)
    }

    #[must_use]
    pub fn contains(&self, account_id: &str, kind: CredentialKind) -> bool {
        self.state
            .lock()
            .unwrap()
            .records
            .contains_key(&record_key(account_id, kind))
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(state_root: &Path, profile_id: &str) -> Result<Self, VaultError> {
        let proof = EncryptedStorageProof {
            dev: nearest_existing_device(state_root)?,
            device: "test-device".into(),
        };
        Self::open(state_root, profile_id, &proof)
    }
}

impl Drop for CredentialVault {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn verify_storage_with_sysfs(
    state_root: &Path,
    sources: &StorageSources,
) -> Result<EncryptedStorageProof, VaultError> {
    let backing =
        luks2_backing(state_root, sources)?.ok_or(VaultError::StorageEncryptionRequired)?;
    Ok(EncryptedStorageProof {
        dev: backing.dev,
        device: backing.devices.join(","),
    })
}

fn nearest_existing_device(path: &Path) -> Result<u64, VaultError> {
    storage::nearest_existing_device(path)?.ok_or(VaultError::StorageEncryptionRequired)
}

fn associated_data(profile_id: &str, account_id: &str, kind: CredentialKind) -> Vec<u8> {
    format!(
        "punar-pimd-credential-v{VAULT_VERSION}\0{profile_id}\0{account_id}\0{}",
        kind.as_str()
    )
    .into_bytes()
}

fn record_key(account_id: &str, kind: CredentialKind) -> String {
    format!("{account_id}:{}", kind.as_str())
}

fn validate_state(state: &VaultState, profile_id: &str) -> Result<(), VaultError> {
    if state.v != VAULT_VERSION {
        return Err(VaultError::Invalid);
    }
    if state.profile_id != profile_id {
        return Err(VaultError::ProfileMismatch);
    }
    for (key, record) in &state.records {
        validate_account_id(&record.account_id)?;
        if record.v != VAULT_VERSION
            || record.profile_id != profile_id
            || key != &record_key(&record.account_id, record.kind)
        {
            return Err(VaultError::Invalid);
        }
        let nonce = URL_SAFE_NO_PAD
            .decode(&record.nonce)
            .map_err(|_| VaultError::Invalid)?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&record.ciphertext)
            .map_err(|_| VaultError::Invalid)?;
        if nonce.len() != NONCE_BYTES
            || ciphertext.len() <= 16
            || ciphertext.len() > MAX_SECRET_BYTES + 16
        {
            return Err(VaultError::Invalid);
        }
    }
    Ok(())
}

fn validate_profile_id(value: &str) -> Result<(), VaultError> {
    let Some(suffix) = value.strip_prefix("profile_") else {
        return Err(VaultError::Invalid);
    };
    if suffix.is_empty()
        || value.len() > 80
        || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(VaultError::Invalid);
    }
    Ok(())
}

fn validate_account_id(value: &str) -> Result<(), VaultError> {
    let Some(suffix) = value.strip_prefix("acct_") else {
        return Err(VaultError::Invalid);
    };
    if suffix.is_empty()
        || value.len() > 80
        || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(VaultError::Invalid);
    }
    Ok(())
}

fn prepare_private_parent(path: &Path) -> Result<(), VaultError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(VaultError::Invalid)?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != rustix::process::getuid().as_raw()
            {
                return Err(VaultError::Invalid);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(parent)?,
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(parent, fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o777 != PRIVATE_DIR_MODE
    {
        return Err(VaultError::Invalid);
    }
    Ok(())
}

fn read_private(path: &Path, limit: u64) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
    let descriptor = match rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(VaultError::Invalid),
    };
    let input = File::from(descriptor);
    let metadata = input.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || metadata.len() > limit
    {
        return Err(VaultError::Invalid);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    input.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(VaultError::Invalid);
    }
    Ok(Some(bytes))
}

fn load_or_create_key(path: &Path, profile_id: &str) -> Result<[u8; KEY_BYTES], VaultError> {
    if let Some(mut bytes) = read_private(path, MAX_KEY_FILE_BYTES)? {
        let mut document: KeyDocument =
            serde_json::from_slice(&bytes).map_err(|_| VaultError::Invalid)?;
        bytes.zeroize();
        if document.v != VAULT_VERSION || document.profile_id != profile_id {
            document.key.zeroize();
            return Err(VaultError::ProfileMismatch);
        }
        let mut decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(&document.key)
                .map_err(|_| VaultError::Invalid)?,
        );
        document.key.zeroize();
        if decoded.len() != KEY_BYTES || decoded.iter().all(|byte| *byte == 0) {
            return Err(VaultError::Invalid);
        }
        let mut key = [0_u8; KEY_BYTES];
        key.copy_from_slice(&decoded);
        decoded.zeroize();
        return Ok(key);
    }

    let mut key = [0_u8; KEY_BYTES];
    getrandom::fill(&mut key).map_err(|_| VaultError::Entropy)?;
    if key.iter().all(|byte| *byte == 0) {
        key.zeroize();
        return Err(VaultError::Entropy);
    }
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(key));
    let document = KeyDocumentRef {
        v: VAULT_VERSION,
        profile_id,
        key: &encoded,
    };
    let mut bytes = Zeroizing::new(serde_json::to_vec(&document).map_err(|_| VaultError::Invalid)?);
    bytes.push(b'\n');
    match create_private_once(path, &bytes) {
        Ok(()) => Ok(key),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            key.zeroize();
            load_or_create_key(path, profile_id)
        }
        Err(error) => {
            key.zeroize();
            Err(error.into())
        }
    }
}

fn persist_state(path: &Path, state: &VaultState) -> Result<(), VaultError> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(state).map_err(|_| VaultError::Invalid)?);
    bytes.push(b'\n');
    write_atomic_synced(path, &bytes)?;
    Ok(())
}

fn create_private_once(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "vault key has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid vault key name"))?;
    let temporary = parent.join(format!(".{name}.pimd-{}", mint_suffix()?));
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
        sync_parent(path);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_atomic_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "vault has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid vault name"))?;
    for _ in 0..4 {
        let temporary = parent.join(format!(".{name}.pimd-{}", mint_suffix()?));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .open(&temporary)
        {
            Ok(mut output) => {
                let result = (|| {
                    output.write_all(bytes)?;
                    output.sync_all()?;
                    fs::rename(&temporary, path)?;
                    sync_parent(path);
                    Ok(())
                })();
                if result.is_err() {
                    let _ = fs::remove_file(&temporary);
                }
                return result;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other("temporary vault file collision"))
}

fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent()
        && let Ok(directory) = File::open(parent)
    {
        let _ = directory.sync_all();
    }
}

fn mint_suffix() -> io::Result<String> {
    let mut bytes = [0_u8; 12];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other("vault entropy unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct TempTree(PathBuf);

    impl TempTree {
        fn new() -> Self {
            Self(
                std::env::temp_dir()
                    .join(format!("punar-pimd-vault-test-{}", mint_suffix().unwrap())),
            )
        }

        fn state_root(&self) -> PathBuf {
            self.0.join("state")
        }

        fn proof(&self) -> EncryptedStorageProof {
            EncryptedStorageProof {
                dev: nearest_existing_device(&self.state_root()).unwrap(),
                device: "253:0".into(),
            }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn plaintext_never_reaches_disk_and_restart_can_decrypt() {
        let tree = TempTree::new();
        let root = tree.state_root();
        let proof = tree.proof();
        let vault = CredentialVault::open(&root, "profile_A1", &proof).unwrap();
        let mut secret = b"correct horse battery staple".to_vec();
        vault
            .store("acct_A1", CredentialKind::IncomingPassword, &mut secret)
            .unwrap();
        assert!(secret.iter().all(|byte| *byte == 0));
        let disk = fs::read(root.join("credentials.json")).unwrap();
        assert!(!disk.windows(7).any(|window| window == b"correct"));
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            PRIVATE_DIR_MODE
        );
        for file in ["credentials.json", "credential-key.json"] {
            assert_eq!(
                fs::metadata(root.join(file)).unwrap().permissions().mode() & 0o777,
                PRIVATE_FILE_MODE
            );
        }
        drop(vault);

        let reopened = CredentialVault::open(&root, "profile_A1", &proof).unwrap();
        let observed = reopened
            .with_secret("acct_A1", CredentialKind::IncomingPassword, |value| {
                value.to_vec()
            })
            .unwrap();
        assert_eq!(observed, b"correct horse battery staple");
    }

    #[test]
    fn associated_data_and_ciphertext_tampering_fail_closed() {
        let tree = TempTree::new();
        let root = tree.state_root();
        let proof = tree.proof();
        let vault = CredentialVault::open(&root, "profile_A1", &proof).unwrap();
        let mut secret = b"secret-A".to_vec();
        vault
            .store("acct_A1", CredentialKind::IncomingPassword, &mut secret)
            .unwrap();
        let mut state = vault.state.lock().unwrap().clone();
        let key = record_key("acct_A1", CredentialKind::IncomingPassword);
        let mut record = state.records.remove(&key).unwrap();
        record.account_id = "acct_B2".into();
        state.records.insert(
            record_key("acct_B2", CredentialKind::IncomingPassword),
            record,
        );
        persist_state(&root.join("credentials.json"), &state).unwrap();
        drop(vault);
        let reopened = CredentialVault::open(&root, "profile_A1", &proof).unwrap();
        assert!(matches!(
            reopened.with_secret("acct_B2", CredentialKind::IncomingPassword, |_| ()),
            Err(VaultError::Crypto)
        ));
    }

    #[test]
    fn account_removal_is_durable_and_does_not_touch_other_accounts() {
        let tree = TempTree::new();
        let root = tree.state_root();
        let proof = tree.proof();
        let vault = CredentialVault::open(&root, "profile_A1", &proof).unwrap();
        for account in ["acct_A1", "acct_B2"] {
            let mut secret = format!("secret-{account}").into_bytes();
            vault
                .store(account, CredentialKind::IncomingPassword, &mut secret)
                .unwrap();
        }
        assert!(vault.remove_account("acct_A1").unwrap());
        assert!(!vault.contains("acct_A1", CredentialKind::IncomingPassword));
        assert!(vault.contains("acct_B2", CredentialKind::IncomingPassword));
        drop(vault);
        let reopened = CredentialVault::open(&root, "profile_A1", &proof).unwrap();
        assert!(!reopened.contains("acct_A1", CredentialKind::IncomingPassword));
        assert!(reopened.contains("acct_B2", CredentialKind::IncomingPassword));
    }

    #[test]
    fn plaintext_storage_and_unproven_sysfs_are_rejected() {
        let tree = TempTree::new();
        let state_root = tree.state_root();
        fs::create_dir_all(&state_root).unwrap();
        let sysfs = tree.0.join("sys-dev-block");
        let sources = StorageSources {
            sys_dev_block: sysfs.clone(),
            sys_class_block: tree.0.join("sys-class-block"),
            sys_fs_btrfs: tree.0.join("sys-fs-btrfs"),
            mountinfo: tree.0.join("mountinfo"),
        };
        let metadata = fs::metadata(&state_root).unwrap();
        let device = format!(
            "{}:{}",
            rustix::fs::major(metadata.dev()),
            rustix::fs::minor(metadata.dev())
        );
        let dm = sysfs.join(&device).join("dm");
        fs::create_dir_all(&dm).unwrap();
        fs::write(dm.join("uuid"), b"not-encrypted\n").unwrap();
        assert!(matches!(
            verify_storage_with_sysfs(&state_root, &sources),
            Err(VaultError::StorageEncryptionRequired)
        ));
        fs::write(
            dm.join("uuid"),
            b"CRYPT-LUKS2-0123456789abcdef-punar-data\n",
        )
        .unwrap();
        assert_eq!(
            verify_storage_with_sysfs(&state_root, &sources)
                .unwrap()
                .device(),
            device
        );

        let wrong_device = EncryptedStorageProof {
            dev: metadata.dev().wrapping_add(1),
            device: device.clone(),
        };
        assert!(matches!(
            CredentialVault::open(&state_root, "profile_A1", &wrong_device),
            Err(VaultError::StorageEncryptionRequired)
        ));
    }

    #[test]
    fn rejected_secret_input_is_still_zeroized() {
        let tree = TempTree::new();
        let root = tree.state_root();
        let proof = tree.proof();
        let vault = CredentialVault::open(&root, "profile_A1", &proof).unwrap();
        let mut empty = Vec::new();
        assert!(
            vault
                .store("acct_A1", CredentialKind::IncomingPassword, &mut empty)
                .is_err()
        );
        let mut oversized = vec![7_u8; MAX_SECRET_BYTES + 1];
        assert!(
            vault
                .store("acct_A1", CredentialKind::IncomingPassword, &mut oversized)
                .is_err()
        );
        assert!(oversized.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn one_use_entry_channel_moves_a_password_directly_into_the_vault() {
        let tree = TempTree::new();
        let root = tree.state_root();
        let proof = tree.proof();
        let vault = CredentialVault::open(&root, "profile_A1", &proof).unwrap();
        let (helper, service) = crate::credential_entry_pair().unwrap();
        let sender = std::thread::spawn(move || {
            let helper = crate::CredentialEntryHelper::lock_down(helper).unwrap();
            let mut secret = b"one-use-password".to_vec();
            helper.submit(&mut secret).unwrap();
            assert!(secret.iter().all(|byte| *byte == 0));
        });
        vault
            .receive_and_store("acct_A1", CredentialKind::IncomingPassword, service)
            .unwrap();
        sender.join().unwrap();
        vault
            .with_secret("acct_A1", CredentialKind::IncomingPassword, |value| {
                assert_eq!(value, b"one-use-password");
            })
            .unwrap();
        let disk = fs::read(root.join("credentials.json")).unwrap();
        assert!(!disk.windows(7).any(|window| window == b"one-use"));
    }

    #[test]
    fn account_setup_never_replaces_an_existing_password() {
        let tree = TempTree::new();
        let root = tree.state_root();
        let proof = tree.proof();
        let vault = CredentialVault::open(&root, "profile_A1", &proof).unwrap();

        for (password, expected) in [
            (b"original-password".as_slice(), true),
            (b"replacement-password".as_slice(), false),
        ] {
            let (helper, service) = crate::credential_entry_pair().unwrap();
            let password = password.to_vec();
            let sender = std::thread::spawn(move || {
                let helper = crate::CredentialEntryHelper::lock_down(helper).unwrap();
                let mut password = password;
                helper.submit(&mut password).unwrap();
            });
            let result = vault.receive_and_store_shared_password("acct_A1", service);
            sender.join().unwrap();
            assert_eq!(result.is_ok(), expected);
        }

        for kind in [
            CredentialKind::IncomingPassword,
            CredentialKind::OutgoingPassword,
        ] {
            vault
                .with_secret("acct_A1", kind, |value| {
                    assert_eq!(value, b"original-password");
                })
                .unwrap();
        }
    }

    #[test]
    fn linked_or_cross_profile_vault_state_is_not_opened() {
        let tree = TempTree::new();
        let root = tree.state_root();
        let proof = tree.proof();
        let vault = CredentialVault::open(&root, "profile_A1", &proof).unwrap();
        drop(vault);
        let path = root.join("credentials.json");
        let alias = root.join("credentials-alias.json");
        fs::hard_link(&path, &alias).unwrap();
        assert!(CredentialVault::open(&root, "profile_A1", &proof).is_err());
        fs::remove_file(&alias).unwrap();
        assert!(matches!(
            CredentialVault::open(&root, "profile_B2", &proof),
            Err(VaultError::ProfileMismatch)
        ));

        fs::remove_file(&path).unwrap();
        let target = root.join("target.json");
        fs::write(&target, b"do-not-touch\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        symlink(&target, &path).unwrap();
        assert!(CredentialVault::open(&root, "profile_A1", &proof).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"do-not-touch\n");
    }
}
