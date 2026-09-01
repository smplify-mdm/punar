//! `system.update_channel` — governed whole-image release cadence.
//!
//! The backend writes one closed vocabulary value and invalidates only the
//! fixed verified-metadata cache. It never invokes a package manager, chooses
//! a release, or performs an update transaction.

use std::fs;
use std::io;
use std::path::PathBuf;

use punar_common::{CapabilityId, Risk};
use serde_json::{Value, json};

use crate::capability::{BackendError, Capability, DescriptorMeta};
use crate::util::{remove_synced, write_atomic_synced};

pub const CAPABILITY_ID: &str = "system.update_channel";
const CHANNELS: [&str; 3] = ["stable", "dev", "edge"];

pub struct UpdateChannelBackend {
    pub channel_file: PathBuf,
    pub verified_metadata_files: Vec<PathBuf>,
}

impl UpdateChannelBackend {
    pub fn new(channel_file: PathBuf, verified_metadata_files: Vec<PathBuf>) -> Self {
        Self {
            channel_file,
            verified_metadata_files,
        }
    }

    fn channel(value: &Value) -> Result<&str, String> {
        let channel = value
            .as_str()
            .ok_or_else(|| "system.update_channel takes a string".to_string())?;
        if CHANNELS.contains(&channel) {
            Ok(channel)
        } else {
            Err(format!(
                "system.update_channel accepts stable, dev, or edge, not {channel:?}"
            ))
        }
    }
}

impl Capability for UpdateChannelBackend {
    fn descriptor(&self) -> DescriptorMeta {
        DescriptorMeta {
            capability: CapabilityId::new(CAPABILITY_ID).expect("static id is valid"),
            risk: Risk::Low,
            verification: "durable-channel-file",
            audit_category: "system",
            state_schema: Some(json!({
                "type": "string",
                "enum": CHANNELS,
            })),
            allowed_desired_states: Some(CHANNELS.into_iter().map(|value| json!(value)).collect()),
        }
    }

    fn validate(&self, desired: &Value) -> Result<(), String> {
        Self::channel(desired).map(|_| ())
    }

    fn observe(&self) -> Result<Value, BackendError> {
        match fs::read_to_string(&self.channel_file) {
            Ok(value) => {
                let channel = value.trim();
                if CHANNELS.contains(&channel) {
                    Ok(json!(channel))
                } else {
                    Ok(json!("unknown"))
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(json!("stable")),
            Err(error) => Err(BackendError::new(format!(
                "reading {} failed: {error}",
                self.channel_file.display()
            ))),
        }
    }

    fn apply(&self, desired: &Value) -> Result<(), BackendError> {
        let channel = Self::channel(desired).map_err(BackendError::new)?;
        let parent = self
            .channel_file
            .parent()
            .ok_or_else(|| BackendError::new("update channel path has no parent"))?;
        fs::create_dir_all(parent).map_err(|error| {
            BackendError::new(format!("creating {} failed: {error}", parent.display()))
        })?;
        fs::set_permissions(parent, std::os::unix::fs::PermissionsExt::from_mode(0o700)).map_err(
            |error| BackendError::new(format!("securing {} failed: {error}", parent.display())),
        )?;
        write_atomic_synced(&self.channel_file, format!("{channel}\n").as_bytes(), 0o600).map_err(
            |error| {
                BackendError::new(format!(
                    "writing {} failed: {error}",
                    self.channel_file.display()
                ))
            },
        )?;
        for cached in &self.verified_metadata_files {
            remove_synced(cached).map_err(|error| {
                BackendError::new(format!("invalidating {} failed: {error}", cached.display()))
            })?;
        }
        Ok(())
    }

    fn default_desired(&self) -> Option<Value> {
        Some(json!("stable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_is_closed_durable_and_invalidates_verified_metadata() {
        let root =
            std::env::temp_dir().join(format!("punard-update-channel-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let channel = root.join("update/channel");
        let cached = root.join("update/verified-channel.json");
        fs::create_dir_all(cached.parent().unwrap()).unwrap();
        fs::write(&cached, b"verified old metadata").unwrap();
        let backend = UpdateChannelBackend::new(channel.clone(), vec![cached.clone()]);

        assert_eq!(backend.observe().unwrap(), json!("stable"));
        for invalid in [json!("nightly"), json!(true), json!("Stable")] {
            assert!(backend.validate(&invalid).is_err());
        }
        backend.apply(&json!("dev")).unwrap();
        assert_eq!(backend.observe().unwrap(), json!("dev"));
        assert_eq!(fs::read_to_string(&channel).unwrap(), "dev\n");
        assert!(!cached.exists());
        assert!(backend.verify(&json!("dev")).unwrap());
        let _ = fs::remove_dir_all(root);
    }
}
