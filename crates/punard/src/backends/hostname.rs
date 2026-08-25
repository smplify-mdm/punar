//! `system.hostname` — direct kernel + file backend, no hostnamectl/D-Bus
//! (docs/development/milestone-3.md section 4.2).
//!
//! Observe reads `/proc/sys/kernel/hostname` (canonical) and `/etc/hostname`;
//! apply writes `/etc/hostname` atomically then the proc file; verify
//! re-reads both. Paths are injected so tests run against a tempdir.

use std::fs;
use std::path::{Path, PathBuf};

use punar_common::CapabilityId;
use serde_json::{Value, json};

use crate::capability::{BackendError, Capability, DescriptorMeta};
use crate::util::write_atomic;

pub const CAPABILITY_ID: &str = "system.hostname";

/// RFC 1123 label pattern enforced on desired states
/// (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`).
pub fn validate_hostname(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    let ok_char = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let valid = !bytes.is_empty()
        && bytes.len() <= 63
        && ok_char(bytes[0])
        && ok_char(bytes[bytes.len() - 1])
        && bytes.iter().all(|c| ok_char(*c) || *c == b'-');
    if valid {
        Ok(())
    } else {
        Err(format!(
            "{name:?} is not a valid hostname: use 1-63 lowercase letters, digits, or hyphens, \
             starting and ending with a letter or digit (RFC 1123 label)"
        ))
    }
}

pub struct HostnameBackend {
    /// `/etc/hostname` in the image.
    pub etc_hostname: PathBuf,
    /// `/proc/sys/kernel/hostname` in the image.
    pub proc_hostname: PathBuf,
}

impl HostnameBackend {
    pub fn new(etc_hostname: PathBuf, proc_hostname: PathBuf) -> Self {
        HostnameBackend {
            etc_hostname,
            proc_hostname,
        }
    }

    fn read_trimmed(&self, which: &Path) -> Result<String, BackendError> {
        fs::read_to_string(which)
            .map(|s| s.trim().to_string())
            .map_err(|e| BackendError::new(format!("reading {} failed: {e}", which.display())))
    }
}

impl Capability for HostnameBackend {
    fn descriptor(&self) -> DescriptorMeta {
        DescriptorMeta {
            capability: CapabilityId::new(CAPABILITY_ID).expect("static id is valid"),
            risk: "low",
            verification: "kernel+file",
            audit_category: "system",
            state_schema: Some(json!({
                "type": "string",
                "pattern": "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
            })),
            // Open value space: allowed_desired_states deliberately absent
            // (the descriptor schema allows omission).
            allowed_desired_states: None,
        }
    }

    fn validate(&self, desired: &Value) -> Result<(), String> {
        let name = desired
            .as_str()
            .ok_or_else(|| "system.hostname takes a string".to_string())?;
        validate_hostname(name)
    }

    fn observe(&self) -> Result<Value, BackendError> {
        // The kernel value is the canonical current state; /etc/hostname
        // divergence shows up as verify/drift, not here.
        Ok(Value::String(self.read_trimmed(&self.proc_hostname)?))
    }

    fn apply(&self, desired: &Value) -> Result<(), BackendError> {
        let name = desired
            .as_str()
            .ok_or_else(|| BackendError::new("desired hostname is not a string"))?;
        write_atomic(&self.etc_hostname, format!("{name}\n").as_bytes(), 0o644).map_err(|e| {
            BackendError::new(format!(
                "writing {} failed: {e}",
                self.etc_hostname.display()
            ))
        })?;
        // procfs entries cannot be renamed over; plain write is the contract.
        fs::write(&self.proc_hostname, name).map_err(|e| {
            BackendError::new(format!(
                "writing {} failed: {e}",
                self.proc_hostname.display()
            ))
        })
    }

    fn verify(&self, desired: &Value) -> Result<bool, BackendError> {
        let Some(name) = desired.as_str() else {
            return Ok(false);
        };
        Ok(self.read_trimmed(&self.proc_hostname)? == name
            && self.read_trimmed(&self.etc_hostname)? == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_validation_accepts_rfc1123_labels() {
        for ok in ["a", "punar-m3", "host42", "0x", "a-b-c"] {
            assert!(validate_hostname(ok).is_ok(), "{ok}");
        }
        let max = "a".repeat(63);
        assert!(validate_hostname(&max).is_ok());
    }

    #[test]
    fn hostname_validation_rejects_bad_labels() {
        let too_long = "a".repeat(64);
        for bad in [
            "",
            "-lead",
            "trail-",
            "UPPER",
            "under_score",
            "dot.ted",
            "sp ace",
            "unicodé",
            too_long.as_str(),
        ] {
            assert!(validate_hostname(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn apply_and_verify_round_trip_on_tempdir() {
        let dir = std::env::temp_dir().join(format!("punard-hostname-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let etc = dir.join("hostname");
        let proc = dir.join("proc-hostname");
        fs::write(&proc, "old\n").unwrap();
        fs::write(&etc, "old\n").unwrap();

        let b = HostnameBackend::new(etc.clone(), proc.clone());
        assert_eq!(b.observe().unwrap(), json!("old"));

        b.apply(&json!("punar-m3")).unwrap();
        assert!(b.verify(&json!("punar-m3")).unwrap());
        assert_eq!(fs::read_to_string(&etc).unwrap(), "punar-m3\n");
        assert_eq!(fs::read_to_string(&proc).unwrap(), "punar-m3");

        // etc/kernel mismatch → verify false.
        fs::write(&etc, "other\n").unwrap();
        assert!(!b.verify(&json!("punar-m3")).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }
}
