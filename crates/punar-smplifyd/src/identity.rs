//! The device identity: a P-256 key generated here and never exported, the
//! certificate Smplify signed for it, the CA it presented, and the local
//! device token punard holds. Everything lives 0600 in a 0700 state
//! directory owned by the unprivileged service user; punard never sees the
//! key, and this daemon never sees punard's state.
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use ring::rand::{SecureRandom, SystemRandom};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::http::ClientIdentity;

const DEVICE_JSON: &str = "device.json";
const DEVICE_KEY: &str = "device.key";
const DEVICE_CERT: &str = "device.crt";
const CA_CERT: &str = "ca.crt";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("key generation failed")]
    KeyGen,
    #[error("the stored identity is unreadable")]
    Corrupt,
    #[error("identity storage failed ({0})")]
    Io(std::io::ErrorKind),
}

impl From<std::io::Error> for IdentityError {
    fn from(error: std::io::Error) -> Self {
        IdentityError::Io(error.kind())
    }
}

/// What `device.json` records. No secret: the key is its own file and the
/// device token is stored only as a digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Smplify's id for this device (the `{id}` in every device URL).
    pub device_id: String,
    /// The API origin the organisation published, e.g. `https://api.example`.
    pub server: String,
    pub org_id: String,
    pub org_name: String,
    pub os_identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// The tenant's policy-signing key as Smplify presented it at first
    /// check-in, pinned then and compared afterwards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_public_key: Option<String>,
    /// SHA-256 (hex) of the device token punard holds.
    pub token_sha256: String,
    pub enrolled_at: String,
}

pub struct Store {
    dir: PathBuf,
}

/// A freshly generated key and the CSR that asks Smplify to certify it.
pub struct Csr {
    pub key_pem: Zeroizing<String>,
    pub csr_pem: String,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Store {
        Store { dir: dir.into() }
    }

    pub fn exists(&self) -> bool {
        self.dir.join(DEVICE_JSON).is_file()
    }

    pub fn load(&self) -> Result<Option<Record>, IdentityError> {
        let path = self.dir.join(DEVICE_JSON);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| IdentityError::Corrupt)
    }

    /// Persist a complete identity atomically enough for a single writer:
    /// key first, then certificates, then the record that makes it real.
    pub fn save(
        &self,
        record: &Record,
        key_pem: &Zeroizing<String>,
        cert_pem: &str,
        ca_pem: &str,
    ) -> Result<(), IdentityError> {
        fs::create_dir_all(&self.dir)?;
        fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
        write_private(&self.dir.join(DEVICE_KEY), key_pem.as_bytes())?;
        write_private(&self.dir.join(DEVICE_CERT), cert_pem.as_bytes())?;
        write_private(&self.dir.join(CA_CERT), ca_pem.as_bytes())?;
        let json = serde_json::to_vec_pretty(record).map_err(|_| IdentityError::Corrupt)?;
        write_private(&self.dir.join(DEVICE_JSON), &json)?;
        Ok(())
    }

    pub fn update(&self, record: &Record) -> Result<(), IdentityError> {
        let json = serde_json::to_vec_pretty(record).map_err(|_| IdentityError::Corrupt)?;
        write_private(&self.dir.join(DEVICE_JSON), &json)?;
        Ok(())
    }

    /// Remove every identity file. The record goes first so a crash midway
    /// leaves no half-identity that reads as enrolled.
    pub fn wipe(&self) -> Result<(), IdentityError> {
        for name in [DEVICE_JSON, DEVICE_KEY, DEVICE_CERT, CA_CERT] {
            match fs::remove_file(self.dir.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// The certificate chain and key for the mTLS client.
    pub fn client_identity(&self) -> Result<ClientIdentity, IdentityError> {
        let cert_pem = fs::read(self.dir.join(DEVICE_CERT))?;
        let key_pem = Zeroizing::new(fs::read(self.dir.join(DEVICE_KEY))?);
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<_, _>>()
            .map_err(|_| IdentityError::Corrupt)?;
        if certs.is_empty() {
            return Err(IdentityError::Corrupt);
        }
        let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|_| IdentityError::Corrupt)?;
        Ok(ClientIdentity { certs, key })
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.dir
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        use std::io::Write;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// A new P-256 key and a PKCS#10 request for it. The subject is the fixed
/// `device-pending`: Smplify assigns the device id when it signs, and the
/// hostname is deliberately not a SAN.
pub fn generate_csr() -> Result<Csr, IdentityError> {
    let key =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|_| IdentityError::KeyGen)?;
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| IdentityError::KeyGen)?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "device-pending");
    params.distinguished_name = dn;
    let csr = params
        .serialize_request(&key)
        .map_err(|_| IdentityError::KeyGen)?;
    Ok(Csr {
        key_pem: Zeroizing::new(key.serialize_pem()),
        csr_pem: csr.pem().map_err(|_| IdentityError::KeyGen)?,
    })
}

/// A fresh device token for punard and the digest this daemon keeps.
pub fn new_device_token() -> Result<(Zeroizing<String>, String), IdentityError> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| IdentityError::KeyGen)?;
    let token = Zeroizing::new(hex(&bytes));
    let digest = token_digest(&token);
    Ok((token, digest))
}

pub fn token_digest(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// Constant-time comparison of a presented token against the stored digest:
/// both sides are the fixed-length hex of a SHA-256, so the loop runs the
/// same number of steps whatever was presented.
pub fn token_matches(record: &Record, presented: &str) -> bool {
    let presented = token_digest(presented);
    let (a, b) = (presented.as_bytes(), record.token_sha256.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> Store {
        let dir = std::env::temp_dir().join(format!(
            "punar-smplifyd-id-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Store::new(dir)
    }

    fn record(digest: String) -> Record {
        Record {
            device_id: "dev-1".into(),
            server: "https://api.example".into(),
            org_id: "acme".into(),
            org_name: "Acme".into(),
            os_identifier: "punar".into(),
            not_after: None,
            tenant_public_key: None,
            token_sha256: digest,
            enrolled_at: "2026-09-23T00:00:00Z".into(),
        }
    }

    #[test]
    fn csr_and_key_are_pem_and_the_key_loads_for_tls() {
        let csr = generate_csr().unwrap();
        assert!(
            csr.csr_pem
                .starts_with("-----BEGIN CERTIFICATE REQUEST-----")
        );
        assert!(csr.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(PrivateKeyDer::from_pem_slice(csr.key_pem.as_bytes()).is_ok());
    }

    #[test]
    fn tokens_verify_by_digest_only() {
        let (token, digest) = new_device_token().unwrap();
        assert_eq!(token.len(), 64);
        let rec = record(digest);
        assert!(token_matches(&rec, &token));
        assert!(!token_matches(&rec, "0000"));
    }

    #[test]
    fn store_round_trips_at_0600_and_wipes_cleanly() {
        let store = temp_store();
        let (token, digest) = new_device_token().unwrap();
        let rec = record(digest);
        store
            .save(&rec, &Zeroizing::new("k".into()), "c", "a")
            .unwrap();
        for name in [DEVICE_JSON, DEVICE_KEY, DEVICE_CERT, CA_CERT] {
            let mode = fs::metadata(store.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name}");
        }
        assert_eq!(
            fs::metadata(store.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded, rec);
        assert!(token_matches(&loaded, &token));
        assert!(!serde_json::to_string(&loaded).unwrap().contains(&*token));
        store.wipe().unwrap();
        assert!(store.load().unwrap().is_none());
        let _ = fs::remove_dir_all(store.path());
    }
}
