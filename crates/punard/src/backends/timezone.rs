//! `time.timezone` — `/etc/localtime` symlink backend
//! (docs/development/milestone-3.md section 4.3).
//!
//! Observe = `readlink` normalized against the zoneinfo tree; apply = create
//! a temp symlink and `rename(2)` over `/etc/localtime` (atomic); validation
//! is a strict traversal guard (no `..`, no absolute names, must exist under
//! the zoneinfo dir) enforced **before** any filesystem write.

use std::fs;
use std::path::PathBuf;

use punar_common::{CapabilityId, Risk};
use serde_json::{Value, json};

use crate::capability::{BackendError, Capability, DescriptorMeta};

pub const CAPABILITY_ID: &str = "time.timezone";

/// Syntactic guard for timezone names such as `UTC`, `Europe/Berlin`,
/// `Etc/GMT+5`: `/`-joined segments of `[A-Za-z0-9_+-]`, no empty segments
/// (which also bans leading/trailing `/`), no `.` at all (which bans `..`
/// traversal by construction).
pub fn validate_timezone_name(name: &str) -> Result<(), String> {
    let err = || {
        format!(
            "{name:?} is not a valid timezone name: use zoneinfo names like \"UTC\" or \
             \"Europe/Berlin\" (letters, digits, '_', '+', '-', joined by '/')"
        )
    };
    if name.is_empty() || name.len() > 128 {
        return Err(err());
    }
    for segment in name.split('/') {
        if segment.is_empty()
            || !segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-'))
        {
            return Err(err());
        }
    }
    Ok(())
}

pub struct TimezoneBackend {
    /// `/etc/localtime` in the image.
    pub localtime: PathBuf,
    /// `/usr/share/zoneinfo` in the image.
    pub zoneinfo_dir: PathBuf,
    /// systemd-networkd drop-ins written after an explicit manual choice.
    /// Empty in host tests that do not model the network stack.
    pub network_timezone_dropins: Vec<PathBuf>,
}

impl TimezoneBackend {
    pub fn new(localtime: PathBuf, zoneinfo_dir: PathBuf) -> Self {
        TimezoneBackend {
            localtime,
            zoneinfo_dir,
            network_timezone_dropins: Vec::new(),
        }
    }

    pub fn with_network_timezone_dropins(mut self, paths: Vec<PathBuf>) -> Self {
        self.network_timezone_dropins = paths;
        self
    }

    fn disable_network_timezone(&self) -> Result<(), BackendError> {
        const CONTENT: &[u8] = b"[DHCPv4]\nUseTimezone=no\n";
        for path in &self.network_timezone_dropins {
            let parent = path
                .parent()
                .ok_or_else(|| BackendError::new("network timezone drop-in has no parent"))?;
            fs::create_dir_all(parent).map_err(|e| {
                BackendError::new(format!("creating {} failed: {e}", parent.display()))
            })?;
            let tmp = parent.join(format!(".punar-timezone.{}", std::process::id()));
            let _ = fs::remove_file(&tmp);
            fs::write(&tmp, CONTENT)
                .map_err(|e| BackendError::new(format!("writing {} failed: {e}", tmp.display())))?;
            if let Err(error) = fs::rename(&tmp, path) {
                let _ = fs::remove_file(&tmp);
                return Err(BackendError::new(format!(
                    "installing {} failed: {error}",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    /// Normalize a symlink target to a zoneinfo name, tolerating absolute
    /// and relative link forms; `None` for out-of-tree or invalid targets.
    fn name_from_target(&self, target: &str) -> Option<String> {
        // Accept ".../zoneinfo/<Name>" wherever the zoneinfo tree lives
        // (covers "/usr/share/zoneinfo/UTC" and "../usr/share/zoneinfo/UTC").
        let name = target
            .strip_prefix(&format!("{}/", self.zoneinfo_dir.display()))
            .map(str::to_string)
            .or_else(|| {
                target
                    .rfind("/zoneinfo/")
                    .map(|pos| target[pos + "/zoneinfo/".len()..].to_string())
            })?;
        validate_timezone_name(&name).ok().map(|_| name)
    }
}

impl Capability for TimezoneBackend {
    fn descriptor(&self) -> DescriptorMeta {
        DescriptorMeta {
            capability: CapabilityId::new(CAPABILITY_ID).expect("static id is valid"),
            risk: Risk::Low,
            verification: "symlink",
            audit_category: "system",
            state_schema: Some(json!({
                "type": "string",
                "pattern": "^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$"
            })),
            allowed_desired_states: None,
        }
    }

    fn validate(&self, desired: &Value) -> Result<(), String> {
        let name = desired
            .as_str()
            .ok_or_else(|| "time.timezone takes a string".to_string())?;
        validate_timezone_name(name)?;
        // Existence is part of validity: an unknown zone is invalid_params,
        // not apply_failed (docs/api/ipc.md section 4).
        let candidate = self.zoneinfo_dir.join(name);
        if candidate.is_file() {
            Ok(())
        } else {
            Err(format!(
                "unknown timezone {name:?}: no such file under {}",
                self.zoneinfo_dir.display()
            ))
        }
    }

    fn observe(&self) -> Result<Value, BackendError> {
        let meta = match fs::symlink_metadata(&self.localtime) {
            Ok(m) => m,
            // Missing or unreadable /etc/localtime: state unknown.
            Err(_) => return Ok(json!("unknown")),
        };
        if !meta.file_type().is_symlink() {
            return Ok(json!("unknown"));
        }
        let target = match fs::read_link(&self.localtime) {
            Ok(t) => t,
            Err(_) => return Ok(json!("unknown")),
        };
        match target.to_str().and_then(|t| self.name_from_target(t)) {
            Some(name) => Ok(Value::String(name)),
            None => Ok(json!("unknown")),
        }
    }

    fn apply(&self, desired: &Value) -> Result<(), BackendError> {
        let name = desired
            .as_str()
            .ok_or_else(|| BackendError::new("desired timezone is not a string"))?;
        // Defense in depth: re-run the traversal guard even though the
        // server validates before authorizing.
        validate_timezone_name(name).map_err(BackendError::new)?;
        let src = self.zoneinfo_dir.join(name);
        if !src.is_file() {
            return Err(BackendError::new(format!(
                "zoneinfo file missing: {}",
                src.display()
            )));
        }
        // An explicit capability write is a manual choice. Disable future
        // RFC 4833 DHCP timezone updates before changing /etc/localtime so
        // the selected zone cannot be silently replaced on lease renewal.
        self.disable_network_timezone()?;
        let parent = self
            .localtime
            .parent()
            .ok_or_else(|| BackendError::new("localtime path has no parent directory"))?;
        let tmp = parent.join(format!(".punar-localtime.{}", std::process::id()));
        let _ = fs::remove_file(&tmp);
        std::os::unix::fs::symlink(&src, &tmp)
            .map_err(|e| BackendError::new(format!("creating symlink failed: {e}")))?;
        fs::rename(&tmp, &self.localtime).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            BackendError::new(format!(
                "renaming over {} failed: {e}",
                self.localtime.display()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timezone_names_validate() {
        for ok in [
            "UTC",
            "Europe/Berlin",
            "America/Argentina/Ushuaia",
            "Etc/GMT+5",
        ] {
            assert!(validate_timezone_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "/UTC",
            "UTC/",
            "Europe//Berlin",
            "../../../etc/shadow",
            "Europe/..",
            "Europe/Ber lin",
            "Zona/Horária",
            "a/./b",
        ] {
            assert!(validate_timezone_name(bad).is_err(), "{bad:?}");
        }
    }

    fn fixture() -> (PathBuf, TimezoneBackend) {
        let dir = std::env::temp_dir().join(format!(
            "punard-tz-{}-{:p}",
            std::process::id(),
            &std::process::id() as *const _
        ));
        let zoneinfo = dir.join("zoneinfo");
        fs::create_dir_all(zoneinfo.join("Europe")).unwrap();
        fs::write(zoneinfo.join("UTC"), b"TZif-utc").unwrap();
        fs::write(zoneinfo.join("Europe/Berlin"), b"TZif-berlin").unwrap();
        let etc = dir.join("etc");
        fs::create_dir_all(&etc).unwrap();
        let backend = TimezoneBackend::new(etc.join("localtime"), zoneinfo);
        (dir, backend)
    }

    #[test]
    fn observe_apply_verify_round_trip() {
        let (dir, b) = fixture();
        // No localtime yet → unknown.
        assert_eq!(b.observe().unwrap(), json!("unknown"));

        b.apply(&json!("UTC")).unwrap();
        assert_eq!(b.observe().unwrap(), json!("UTC"));
        assert!(b.verify(&json!("UTC")).unwrap());

        // Atomic replace over the existing link.
        b.apply(&json!("Europe/Berlin")).unwrap();
        assert_eq!(b.observe().unwrap(), json!("Europe/Berlin"));
        assert!(!b.verify(&json!("UTC")).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn manual_choice_disables_network_timezone_updates() {
        let (dir, backend) = fixture();
        let wired = dir.join("etc/systemd/network/50-punar-dhcp.network.d/90-punar-timezone.conf");
        let wifi = dir.join("etc/systemd/network/60-punar-wifi.network.d/90-punar-timezone.conf");
        let backend = backend.with_network_timezone_dropins(vec![wired.clone(), wifi.clone()]);

        backend.apply(&json!("Europe/Berlin")).unwrap();
        assert_eq!(
            fs::read_to_string(wired).unwrap(),
            "[DHCPv4]\nUseTimezone=no\n"
        );
        assert_eq!(
            fs::read_to_string(wifi).unwrap(),
            "[DHCPv4]\nUseTimezone=no\n"
        );
        assert_eq!(backend.observe().unwrap(), json!("Europe/Berlin"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_unknown_and_traversal_zones() {
        let (dir, b) = fixture();
        assert!(b.validate(&json!("UTC")).is_ok());
        assert!(b.validate(&json!("Mars/Olympus")).is_err());
        assert!(b.validate(&json!("../shadow")).is_err());
        assert!(b.validate(&json!(42)).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_symlink_localtime_observes_unknown() {
        let (dir, b) = fixture();
        fs::write(&b.localtime, b"plain file").unwrap();
        assert_eq!(b.observe().unwrap(), json!("unknown"));
        let _ = fs::remove_dir_all(&dir);
    }
}
