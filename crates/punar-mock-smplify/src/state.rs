//! What the mock **received** — the side m5-check asserts directly.
//!
//! `StateDirectory=punar-mock-smplify` → `/var/lib/punar-mock-smplify/`
//! (milestone-5.md section 4.5):
//!
//! - `devices.json` — `{device_id: {device_token, registered_at,
//!   attestation}}`, atomic rewrite (tmp + rename), mode 0600;
//! - `received-compliance.jsonl` / `received-inventory.jsonl` —
//!   append-only, one received report per line with `received_at` and the
//!   token-resolved `device_id`.
//!
//! State **persists across restarts** deliberately: the m5-check offline
//! stop→start must not invalidate the device token, and the history kept
//! after unenroll is the honest record that M5 unenrollment is local-only.
//! Tokens are persisted in the clear on the *server* side — the mock is the
//! issuer, the directory is root-owned 0700, and `Redacted` protects
//! `punard`'s client-side copy, not the counterparty's ledger.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use punar_common::time::utc_now_rfc3339;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The literal attestation value this mock issues — nothing is measured,
/// quoted, or verified, and every surface that stores or renders it says so
/// (milestone-5.md section 3).
pub const ATTESTATION_SIMULATED: &str = "simulated";

/// One registered device, as persisted in `devices.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRecord {
    pub device_token: String,
    pub registered_at: String,
    pub attestation: String,
}

/// The received-state store: registered devices in memory + on disk, and
/// the two append-only report logs.
#[derive(Debug)]
pub struct StateStore {
    dir: PathBuf,
    devices: BTreeMap<String, DeviceRecord>,
}

impl StateStore {
    /// Open (creating if needed) the state directory and load any existing
    /// `devices.json`. A corrupt ledger fails loudly — silently starting
    /// empty would un-register devices behind the check's back.
    pub fn open(dir: &Path) -> io::Result<StateStore> {
        std::fs::create_dir_all(dir)?;
        // 0700: received reports are org-side records; nothing but root
        // (the check) reads them. Best-effort — systemd's StateDirectory
        // already owns the mode in the image.
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        let devices_path = dir.join(DEVICES_FILE);
        let devices = if devices_path.exists() {
            let bytes = std::fs::read(&devices_path)?;
            serde_json::from_slice(&bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: corrupt device ledger: {e}", devices_path.display()),
                )
            })?
        } else {
            BTreeMap::new()
        };
        Ok(StateStore {
            dir: dir.to_path_buf(),
            devices,
        })
    }

    /// Register (or re-register) a device: mint a fresh token, record it,
    /// persist atomically, and return the token. Re-registering a known
    /// `device_id` **rotates** the token — idempotent re-enroll, and the
    /// old token stops working (milestone-5.md section 4.3).
    pub fn register(&mut self, device_id: &str) -> io::Result<String> {
        let token = generate_device_token()?;
        self.devices.insert(
            device_id.to_string(),
            DeviceRecord {
                device_token: token.clone(),
                registered_at: utc_now_rfc3339(),
                attestation: ATTESTATION_SIMULATED.to_string(),
            },
        );
        self.save_devices()?;
        Ok(token)
    }

    /// Resolve a presented token to its `device_id`, or `None` when no
    /// registered device carries it. Plain comparison — this mock is not an
    /// authority and does not pretend to constant-time secret handling.
    pub fn device_for_token(&self, token: &str) -> Option<&str> {
        self.devices
            .iter()
            .find(|(_, record)| record.device_token == token)
            .map(|(id, _)| id.as_str())
    }

    /// Number of registered devices (startup log line).
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Append one received compliance report:
    /// `{"received_at", "device_id", "report"}` as a single JSONL line.
    pub fn append_compliance(&self, device_id: &str, report: &Value) -> io::Result<()> {
        self.append_line(
            COMPLIANCE_FILE,
            json!({
                "received_at": utc_now_rfc3339(),
                "device_id": device_id,
                "report": report,
            }),
        )
    }

    /// Append one received inventory report:
    /// `{"received_at", "device_id", "inventory"}` as a single JSONL line.
    pub fn append_inventory(&self, device_id: &str, inventory: &Value) -> io::Result<()> {
        self.append_line(
            INVENTORY_FILE,
            json!({
                "received_at": utc_now_rfc3339(),
                "device_id": device_id,
                "inventory": inventory,
            }),
        )
    }

    /// Atomic rewrite of `devices.json`: tmp file (0600) + rename.
    fn save_devices(&self) -> io::Result<()> {
        let tmp = self.dir.join("devices.json.tmp");
        let mut body = serde_json::to_string_pretty(&self.devices)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        body.push('\n');
        write_new_0600(&tmp, body.as_bytes())?;
        std::fs::rename(&tmp, self.dir.join(DEVICES_FILE))
    }

    fn append_line(&self, file: &str, value: Value) -> io::Result<()> {
        let mut line = value.to_string();
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.dir.join(file))?;
        f.write_all(line.as_bytes())
    }
}

/// `devices.json` file name inside the state directory.
pub const DEVICES_FILE: &str = "devices.json";
/// Received-compliance JSONL file name.
pub const COMPLIANCE_FILE: &str = "received-compliance.jsonl";
/// Received-inventory JSONL file name.
pub const INVENTORY_FILE: &str = "received-inventory.jsonl";

/// Mint `tok_<32 hex>` from `/dev/urandom` (16 random bytes). No `rand`
/// crate: std-only, and the kernel CSPRNG is exactly what a token stub
/// needs.
fn generate_device_token() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut token = String::with_capacity(4 + 32);
    token.push_str("tok_");
    for b in bytes {
        // Infallible: writing hex digits into a String cannot fail.
        let _ = write!(token, "{b:02x}");
    }
    Ok(token)
}

fn write_new_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "punar-mock-state-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn register_persists_and_reloads() {
        let dir = tmp_dir("reload");
        let mut store = StateStore::open(&dir).unwrap();
        let token = store.register("dev_abc").unwrap();
        assert!(token.starts_with("tok_"));
        assert_eq!(token.len(), 4 + 32);
        assert!(token[4..].chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(store.device_for_token(&token), Some("dev_abc"));

        // A second store over the same directory sees the same ledger —
        // the m5-check stop→start must not invalidate the token.
        let reloaded = StateStore::open(&dir).unwrap();
        assert_eq!(reloaded.device_for_token(&token), Some("dev_abc"));
        assert_eq!(reloaded.device_count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reregistration_rotates_the_token() {
        let dir = tmp_dir("rotate");
        let mut store = StateStore::open(&dir).unwrap();
        let first = store.register("dev_abc").unwrap();
        let second = store.register("dev_abc").unwrap();
        assert_ne!(first, second, "re-register mints a fresh token");
        assert_eq!(store.device_for_token(&first), None, "old token is dead");
        assert_eq!(store.device_for_token(&second), Some("dev_abc"));
        assert_eq!(store.device_count(), 1, "still one device");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corrupt_ledger_fails_loudly() {
        let dir = tmp_dir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(DEVICES_FILE), b"{ not json").unwrap();
        let err = StateStore::open(&dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn appends_are_one_json_object_per_line() {
        let dir = tmp_dir("append");
        let store = StateStore::open(&dir).unwrap();
        store
            .append_compliance("dev_abc", &json!({"overall": "compliant"}))
            .unwrap();
        store
            .append_compliance("dev_abc", &json!({"overall": "drifted"}))
            .unwrap();
        let text = std::fs::read_to_string(dir.join(COMPLIANCE_FILE)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["device_id"], "dev_abc");
        assert_eq!(first["report"]["overall"], "compliant");
        assert!(first["received_at"].as_str().unwrap().ends_with('Z'));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
