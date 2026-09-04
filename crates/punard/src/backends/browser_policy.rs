//! `browser.policy` — root-owned Chromium managed-policy file backend.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use punar_common::{CapabilityId, Risk};
use serde_json::{Value, json};

use crate::browser_policy::{CAPABILITY_ID, validate_rendered_policy};
use crate::capability::{BackendError, Capability, DescriptorMeta};
use crate::util::{remove_synced, write_atomic_synced};

const MANAGED: &str = "managed";
const UNMANAGED: &str = "unmanaged";
const DRIFTED: &str = "drifted";

pub struct BrowserPolicyBackend {
    /// Root-private, freshly rendered source under `/var/lib/punar`.
    pub rendered_source: PathBuf,
    /// Chromium's root-owned mandatory-policy file.
    pub managed_file: PathBuf,
}

impl BrowserPolicyBackend {
    pub fn new(rendered_source: PathBuf, managed_file: PathBuf) -> Self {
        Self {
            rendered_source,
            managed_file,
        }
    }

    fn state(value: &Value) -> Result<&str, String> {
        match value.as_str() {
            Some(MANAGED) => Ok(MANAGED),
            Some(UNMANAGED) => Ok(UNMANAGED),
            _ => Err("browser.policy accepts only managed or unmanaged".into()),
        }
    }

    fn source_bytes(&self) -> Result<Vec<u8>, BackendError> {
        let bytes = fs::read(&self.rendered_source).map_err(|error| {
            BackendError::new(format!(
                "reading rendered browser policy {} failed: {error}",
                self.rendered_source.display()
            ))
        })?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
            BackendError::new(format!(
                "rendered browser policy {} is invalid JSON: {error}",
                self.rendered_source.display()
            ))
        })?;
        validate_rendered_policy(&value).map_err(|error| BackendError::new(error.to_string()))?;
        canonical_bytes(&value).map_err(|error| BackendError::new(error.to_string()))
    }
}

fn canonical_bytes(value: &Value) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    bytes.push(b'\n');
    Ok(bytes)
}

impl Capability for BrowserPolicyBackend {
    fn descriptor(&self) -> DescriptorMeta {
        DescriptorMeta {
            capability: CapabilityId::new(CAPABILITY_ID).expect("static id is valid"),
            risk: Risk::Medium,
            verification: "file_hash",
            audit_category: "policy",
            state_schema: Some(json!({
                "type": "string",
                "enum": [MANAGED, UNMANAGED, DRIFTED]
            })),
            allowed_desired_states: Some(vec![json!(MANAGED), json!(UNMANAGED)]),
        }
    }

    fn validate(&self, desired: &Value) -> Result<(), String> {
        Self::state(desired).map(|_| ())
    }

    fn observe(&self) -> Result<Value, BackendError> {
        let managed = match fs::read(&self.managed_file) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(BackendError::new(format!(
                    "reading Chromium managed policy {} failed: {error}",
                    self.managed_file.display()
                )));
            }
        };
        let source_exists = self.rendered_source.exists();
        match (managed, source_exists) {
            (None, _) => Ok(json!(UNMANAGED)),
            (Some(_), false) => Ok(json!(DRIFTED)),
            (Some(actual), true) => {
                let expected = self.source_bytes()?;
                if actual == expected {
                    Ok(json!(MANAGED))
                } else {
                    Ok(json!(DRIFTED))
                }
            }
        }
    }

    fn apply(&self, desired: &Value) -> Result<(), BackendError> {
        match Self::state(desired).map_err(BackendError::new)? {
            UNMANAGED => remove_synced(&self.managed_file).map_err(|error| {
                BackendError::new(format!(
                    "removing Chromium managed policy {} failed: {error}",
                    self.managed_file.display()
                ))
            }),
            MANAGED => {
                let bytes = self.source_bytes()?;
                let parent = self.managed_file.parent().ok_or_else(|| {
                    BackendError::new("Chromium managed-policy path has no parent")
                })?;
                fs::create_dir_all(parent).map_err(|error| {
                    BackendError::new(format!("creating {} failed: {error}", parent.display()))
                })?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).map_err(
                    |error| {
                        BackendError::new(format!("securing {} failed: {error}", parent.display()))
                    },
                )?;
                write_atomic_synced(&self.managed_file, &bytes, 0o644).map_err(|error| {
                    BackendError::new(format!(
                        "writing Chromium managed policy {} failed: {error}",
                        self.managed_file.display()
                    ))
                })?;
                fs::set_permissions(&self.managed_file, fs::Permissions::from_mode(0o644)).map_err(
                    |error| {
                        BackendError::new(format!(
                            "securing Chromium managed policy {} failed: {error}",
                            self.managed_file.display()
                        ))
                    },
                )
            }
            _ => unreachable!("closed state parser"),
        }
    }

    fn default_desired(&self) -> Option<Value> {
        Some(json!(UNMANAGED))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_observe_verify_and_drift_are_byte_exact() {
        let root = std::env::temp_dir().join(format!(
            "punard-browser-policy-{}-{:p}",
            std::process::id(),
            &std::process::id() as *const _
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let source = root.join("state/rendered.json");
        let managed = root.join("etc/chromium/policies/managed/punar-managed.json");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(
            &source,
            serde_json::to_vec(&json!({
                "SitePerProcess": true,
                "RemoteDebuggingAllowed": false,
                "SSLErrorOverrideAllowed": false,
                "InsecurePrivateNetworkRequestsAllowed": false
            }))
            .unwrap(),
        )
        .unwrap();
        let backend = BrowserPolicyBackend::new(source, managed.clone());

        assert_eq!(backend.observe().unwrap(), json!(UNMANAGED));
        backend.apply(&json!(MANAGED)).unwrap();
        assert_eq!(backend.observe().unwrap(), json!(MANAGED));
        assert!(backend.verify(&json!(MANAGED)).unwrap());
        assert_eq!(
            fs::metadata(&managed).unwrap().permissions().mode() & 0o777,
            0o644
        );

        fs::write(&managed, b"{}\n").unwrap();
        assert_eq!(backend.observe().unwrap(), json!(DRIFTED));
        backend.apply(&json!(MANAGED)).unwrap();
        assert_eq!(backend.observe().unwrap(), json!(MANAGED));
        backend.apply(&json!(UNMANAGED)).unwrap();
        assert_eq!(backend.observe().unwrap(), json!(UNMANAGED));
        assert!(!managed.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_weakening_source_never_reaches_the_managed_file() {
        let root = std::env::temp_dir().join(format!("punard-browser-weak-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let source = root.join("rendered.json");
        let managed = root.join("managed.json");
        fs::write(&source, br#"{"SitePerProcess":false}"#).unwrap();
        let backend = BrowserPolicyBackend::new(source, managed.clone());
        assert!(backend.apply(&json!(MANAGED)).is_err());
        assert!(!managed.exists());
        let _ = fs::remove_dir_all(root);
    }
}
