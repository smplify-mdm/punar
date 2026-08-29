//! Relay preference and the explicitly simulated dual-hop model.
//!
//! This module never opens a socket and never changes a packet path. The
//! state is a UI/policy abstraction only until a later milestone provides
//! independently operated hops.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use punar_common::network::RelayPreference;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("relay preference file failed: {0}")]
    Io(#[from] io::Error),
    #[error("relay preference is invalid: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelayHop {
    pub role: &'static str,
    pub knows: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelayStatus {
    pub mode: RelayPreference,
    pub simulated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hops: Vec<RelayHop>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub property_claimed: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub property_not_held: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub real_relay_milestone: Option<&'static str>,
}

impl RelayStatus {
    pub fn for_mode(mode: RelayPreference) -> Self {
        match mode {
            RelayPreference::Direct => Self {
                mode,
                simulated: false,
                hops: vec![],
                property_claimed: None,
                property_not_held: None,
                real_relay_milestone: None,
            },
            RelayPreference::PrivateRelay => Self {
                mode,
                simulated: true,
                hops: vec![
                    RelayHop {
                        role: "ingress",
                        knows: vec!["client_identity", "connect_time"],
                    },
                    RelayHop {
                        role: "egress",
                        knows: vec!["destination", "connect_time"],
                    },
                ],
                property_claimed: Some("no single hop holds both client identity and destination"),
                property_not_held: Some(
                    "both hops are the same process on the same device under one operator; nothing is partitioned across trust boundaries, and a single-operator relay may never claim the section 34 drawing",
                ),
                real_relay_milestone: Some("phase_2"),
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPreference {
    v: u64,
    mode: RelayPreference,
}

#[derive(Debug, Clone)]
pub struct RelayStore {
    path: PathBuf,
    mode: RelayPreference,
}

impl RelayStore {
    pub fn open(path: PathBuf) -> Result<Self, RelayError> {
        let mode = match fs::read_to_string(&path) {
            Ok(body) => {
                let stored: StoredPreference = serde_json::from_str(&body)
                    .map_err(|error| RelayError::Invalid(error.to_string()))?;
                if stored.v != 1 {
                    return Err(RelayError::Invalid(format!(
                        "unsupported version {}",
                        stored.v
                    )));
                }
                stored.mode
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => RelayPreference::Direct,
            Err(error) => return Err(RelayError::Io(error)),
        };
        Ok(Self { path, mode })
    }

    pub fn status(&self) -> RelayStatus {
        RelayStatus::for_mode(self.mode)
    }

    pub fn set(&mut self, mode: RelayPreference) -> Result<RelayStatus, RelayError> {
        let stored = StoredPreference { v: 1, mode };
        let bytes = serde_json::to_vec(&stored).expect("relay preference serializes infallibly");
        write_synced(&self.path, &bytes)?;
        self.mode = mode;
        Ok(self.status())
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "relay file has no name"))?;
    let temporary = parent.join(format!(".{name}.netd-tmp.{}", std::process::id()));
    let create = || {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
    };
    let mut file = match create() {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(&temporary)?;
            create()?
        }
        Err(error) => return Err(error),
    };
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "punar-netd-relay-{}-{}-state.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn private_relay_is_unmistakably_simulated_and_structurally_partitioned() {
        let status = RelayStatus::for_mode(RelayPreference::PrivateRelay);
        assert!(status.simulated);
        assert_eq!(status.hops[0].role, "ingress");
        assert!(!status.hops[0].knows.contains(&"destination"));
        assert_eq!(status.hops[1].role, "egress");
        assert!(!status.hops[1].knows.contains(&"client_identity"));
        assert!(status.property_not_held.unwrap().contains("same process"));
        assert_eq!(status.real_relay_milestone, Some("phase_2"));
    }

    #[test]
    fn preference_defaults_direct_persists_and_rejects_extensions() {
        let path = path();
        let mut store = RelayStore::open(path.clone()).unwrap();
        assert_eq!(store.status().mode, RelayPreference::Direct);
        store.set(RelayPreference::PrivateRelay).unwrap();
        assert_eq!(
            RelayStore::open(path.clone()).unwrap().status().mode,
            RelayPreference::PrivateRelay
        );
        fs::write(
            &path,
            r#"{"v":1,"mode":"direct","secret_destination":"example.com"}"#,
        )
        .unwrap();
        assert!(matches!(
            RelayStore::open(path.clone()),
            Err(RelayError::Invalid(_))
        ));
        fs::remove_file(path).unwrap();
    }
}
