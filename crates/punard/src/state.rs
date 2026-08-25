//! Persistent daemon state: the desired-state store and the device id
//! (docs/development/milestone-3.md section 3; docs/api/ipc.md section 5.1).

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::Value;

use crate::util::{random_alnum, write_atomic};

/// `/var/lib/punar/desired.json` — capability id → desired state value,
/// mode 0600, atomically rewritten on every change. The only mutable store
/// in the daemon.
pub struct DesiredStore {
    path: PathBuf,
    map: Mutex<BTreeMap<String, Value>>,
}

impl DesiredStore {
    /// Load the store, or start empty when the file does not exist yet.
    /// A corrupt file is an error — silently discarding recorded desired
    /// state would be worse than refusing to start.
    pub fn load(path: &Path) -> io::Result<Self> {
        let map = match fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is corrupt: {e}", path.display()),
                )
            })?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e),
        };
        Ok(DesiredStore {
            path: path.to_path_buf(),
            map: Mutex::new(map),
        })
    }

    pub fn get(&self, capability: &str) -> Option<Value> {
        self.map.lock().unwrap().get(capability).cloned()
    }

    /// Record a desired state and persist the store (0600, atomic).
    pub fn set(&self, capability: &str, desired: Value) -> io::Result<()> {
        let mut map = self.map.lock().unwrap();
        map.insert(capability.to_string(), desired);
        let bytes = serde_json::to_vec_pretty(&*map).expect("BTreeMap<String, Value> serializes");
        write_atomic(&self.path, &bytes, 0o600)
    }

    /// Seed a default without overwriting an existing entry; persists only
    /// when something was actually added. Used at startup.
    pub fn seed(&self, capability: &str, default: Value) -> io::Result<bool> {
        let mut map = self.map.lock().unwrap();
        if map.contains_key(capability) {
            return Ok(false);
        }
        map.insert(capability.to_string(), default);
        let bytes = serde_json::to_vec_pretty(&*map).expect("BTreeMap<String, Value> serializes");
        write_atomic(&self.path, &bytes, 0o600)?;
        Ok(true)
    }
}

/// Load `/var/lib/punar/device-id` or create it on first start:
/// `dev_` + 10 random alphanumerics, mode 0600 (spec section 11.1 "device
/// identity", first slice).
pub fn load_or_create_device_id(path: &Path) -> io::Result<String> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let id = content.trim().to_string();
            if is_valid_device_id(&id) {
                return Ok(id);
            }
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} does not contain a valid device id", path.display()),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let id = format!("dev_{}", random_alnum(10)?);
            write_atomic(path, format!("{id}\n").as_bytes(), 0o600)?;
            Ok(id)
        }
        Err(e) => Err(e),
    }
}

fn is_valid_device_id(id: &str) -> bool {
    id.strip_prefix("dev_")
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("punard-state-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn desired_store_persists_and_reloads() {
        let dir = tmp("store");
        let path = dir.join("desired.json");
        let store = DesiredStore::load(&path).unwrap();
        assert_eq!(store.get("security.firewall"), None);
        store
            .set("security.firewall", Value::String("enabled".into()))
            .unwrap();

        let reloaded = DesiredStore::load(&path).unwrap();
        assert_eq!(
            reloaded.get("security.firewall"),
            Some(Value::String("enabled".into()))
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_does_not_overwrite() {
        let dir = tmp("seed");
        let path = dir.join("desired.json");
        let store = DesiredStore::load(&path).unwrap();
        assert!(store.seed("x.y", Value::String("a".into())).unwrap());
        assert!(!store.seed("x.y", Value::String("b".into())).unwrap());
        assert_eq!(store.get("x.y"), Some(Value::String("a".into())));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_store_refuses_to_load() {
        let dir = tmp("corrupt");
        let path = dir.join("desired.json");
        fs::write(&path, "{oops").unwrap();
        assert!(DesiredStore::load(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_id_is_created_once_and_stable() {
        let dir = tmp("devid");
        let path = dir.join("device-id");
        let first = load_or_create_device_id(&path).unwrap();
        assert!(is_valid_device_id(&first));
        assert_eq!(first.len(), 4 + 10);
        let second = load_or_create_device_id(&path).unwrap();
        assert_eq!(first, second);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_persisted_device_id_is_an_error() {
        let dir = tmp("devid-bad");
        let path = dir.join("device-id");
        fs::write(&path, "not-a-device-id\n").unwrap();
        assert!(load_or_create_device_id(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
