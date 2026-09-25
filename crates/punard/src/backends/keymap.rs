//! `system.keymap` — the device's keyboard layout (SMP-1405 WP-02; designed
//! in docs/development/milestone-13.md section 5.3 and
//! docs/design/onboarding.md section 2.1).
//!
//! Observe reads `XKBLAYOUT`/`XKBVARIANT` from `/etc/vconsole.conf`; apply
//! rewrites those lines atomically. Validation is the shared grammar in
//! [`punar_common::keymap`]: syntax first, then the image's own XKB list, so
//! only a layout the keyboard stack can load ever reaches the file. The file
//! is data read by systemd-vconsole-setup and by the session's renderer
//! (`punarctl keyboard layout render`); nothing evaluates it.
//!
//! **Who may set it** is decided in `server::m9`: root, a grant holder, or
//! the person in the active local session. A keyboard layout is the
//! person's own tool, not a security setting, and asking for an
//! administrator to change it would put a password prompt between someone
//! and typing. It is still a typed, audited capability, still refused to an
//! agent, and still pinnable by an organization.
//!
//! **The installer's choice is the first default.** When the install seed
//! (`/var/lib/punar/install/seed.json`) names a valid layout, that is the OS
//! default the first boot reconciles to; otherwise the first observation is.

use std::fs;
use std::path::PathBuf;

use punar_common::keymap::{self, Catalog};
use punar_common::{CapabilityId, Risk};
use serde_json::{Value, json};

use crate::capability::{BackendError, Capability, DescriptorMeta};
use crate::util::write_atomic;

/// A literal, so tests/desktop/system-control-parity-contract-test.sh finds
/// it and holds the shell to a label for it; the test below holds it to the
/// shared grammar's constant.
pub const CAPABILITY_ID: &str = "system.keymap";

/// The install seed punard's installer writes onto the target's `/var`.
pub const INSTALL_SEED: &str = "/var/lib/punar/install/seed.json";

pub struct KeymapBackend {
    /// `/etc/vconsole.conf` in the image.
    pub vconsole: PathBuf,
    /// The XKB rules list values are checked against.
    pub xkb_list: PathBuf,
    /// The install seed whose `keymap` is the first default.
    pub install_seed: PathBuf,
}

impl KeymapBackend {
    pub fn new(vconsole: PathBuf, xkb_list: PathBuf, install_seed: PathBuf) -> Self {
        KeymapBackend {
            vconsole,
            xkb_list,
            install_seed,
        }
    }

    pub fn for_image() -> Self {
        KeymapBackend::new(
            PathBuf::from(keymap::VCONSOLE),
            PathBuf::from(keymap::XKB_LIST),
            PathBuf::from(INSTALL_SEED),
        )
    }

    fn catalog(&self) -> Result<Catalog, String> {
        let catalog = Catalog::load(&self.xkb_list).map_err(|e| {
            format!(
                "the installed keyboard layout list {} could not be read ({e})",
                self.xkb_list.display()
            )
        })?;
        if catalog.layouts.is_empty() {
            return Err(format!(
                "the installed keyboard layout list {} names no layouts",
                self.xkb_list.display()
            ));
        }
        Ok(catalog)
    }
}

impl Capability for KeymapBackend {
    fn descriptor(&self) -> DescriptorMeta {
        DescriptorMeta {
            capability: CapabilityId::new(CAPABILITY_ID).expect("static id is valid"),
            risk: Risk::Low,
            verification: "file",
            audit_category: "system",
            state_schema: Some(json!({
                "type": "string",
                "pattern": "^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}(\\+[A-Za-z0-9_][A-Za-z0-9_-]{0,31})?(,[A-Za-z0-9_][A-Za-z0-9_-]{0,31}(\\+[A-Za-z0-9_][A-Za-z0-9_-]{0,31})?){0,3}$"
            })),
            // Open value space, closed by the installed XKB list at
            // validation time rather than by a copy of it here.
            allowed_desired_states: None,
        }
    }

    fn validate(&self, desired: &Value) -> Result<(), String> {
        let value = desired
            .as_str()
            .ok_or_else(|| "system.keymap takes a string, like \"de\" or \"us,ru\"".to_string())?;
        // Syntax before the list: a malformed value is refused even on a
        // machine whose list cannot be read.
        keymap::parse(value).map_err(|e| e.to_string())?;
        self.catalog()?
            .validate(value)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn observe(&self) -> Result<Value, BackendError> {
        let text = match fs::read_to_string(&self.vconsole) {
            Ok(text) => text,
            // No file: the console, and every renderer, use the default.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(json!(keymap::DEFAULT));
            }
            Err(_) => return Ok(json!("unknown")),
        };
        match keymap::from_vconsole(&text) {
            Ok(Some(value)) => Ok(Value::String(value)),
            Ok(None) => Ok(json!(keymap::DEFAULT)),
            Err(_) => Ok(json!("unknown")),
        }
    }

    fn apply(&self, desired: &Value) -> Result<(), BackendError> {
        let value = desired
            .as_str()
            .ok_or_else(|| BackendError::new("desired keymap is not a string"))?;
        // Defense in depth: the server validated before authorizing, and the
        // list is read again here so a value can never be written unchecked.
        let layouts = self
            .catalog()
            .map_err(BackendError::new)?
            .validate(value)
            .map_err(|e| BackendError::new(e.to_string()))?;
        let existing = fs::read_to_string(&self.vconsole).unwrap_or_default();
        let rendered = keymap::render_vconsole(&existing, &layouts);
        write_atomic(&self.vconsole, rendered.as_bytes(), 0o644).map_err(|e| {
            BackendError::new(format!("writing {} failed: {e}", self.vconsole.display()))
        })
    }

    /// The installer's choice, when it left one this device can load.
    fn default_desired(&self) -> Option<Value> {
        let seed: Value = serde_json::from_slice(&fs::read(&self.install_seed).ok()?).ok()?;
        let chosen = seed.get("keymap")?.as_str()?;
        let layouts = self.catalog().ok()?.validate(chosen).ok()?;
        Some(Value::String(keymap::format(&layouts)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "! layout\n  us  English (US)\n  de  German\n  ru  Russian\n\
                        ! variant\n  nodeadkeys  de: German (no dead keys)\n";

    fn fixture(name: &str) -> (PathBuf, KeymapBackend) {
        let dir = std::env::temp_dir().join(format!("punard-keymap-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("evdev.lst"), LIST).unwrap();
        let backend = KeymapBackend::new(
            dir.join("etc/vconsole.conf"),
            dir.join("evdev.lst"),
            dir.join("seed.json"),
        );
        (dir, backend)
    }

    #[test]
    fn the_id_is_the_shared_grammars() {
        assert_eq!(CAPABILITY_ID, keymap::CAPABILITY_ID);
    }

    #[test]
    fn observe_apply_verify_round_trip() {
        let (dir, backend) = fixture("round-trip");
        assert_eq!(
            backend.observe().unwrap(),
            json!("us"),
            "no file is the default"
        );
        fs::write(&backend.vconsole, "FONT=ter-v16n\n").unwrap();
        assert_eq!(backend.observe().unwrap(), json!("us"));

        backend.apply(&json!("de+nodeadkeys,us")).unwrap();
        assert_eq!(backend.observe().unwrap(), json!("de+nodeadkeys,us"));
        assert!(backend.verify(&json!("de+nodeadkeys,us")).unwrap());
        let written = fs::read_to_string(&backend.vconsole).unwrap();
        assert!(written.contains("FONT=ter-v16n"), "{written}");

        backend.apply(&json!("ru")).unwrap();
        assert_eq!(backend.observe().unwrap(), json!("ru"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn validation_is_the_grammar_then_the_installed_list() {
        let (dir, backend) = fixture("validate");
        assert!(backend.validate(&json!("de+nodeadkeys")).is_ok());
        assert!(backend.validate(&json!("us,ru")).is_ok());
        for bad in [
            json!("fr"),
            json!("us+intl"),
            json!("us\nKEYMAP=evil"),
            json!("us\"; os.execute(\"x\")"),
            json!(42),
            json!(""),
        ] {
            assert!(backend.validate(&bad).is_err(), "{bad}");
        }
        // apply re-checks, whatever the caller did first.
        assert!(backend.apply(&json!("fr")).is_err());
        assert!(!backend.vconsole.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_list_refuses_everything_but_malformed_values_first() {
        let (dir, backend) = fixture("no-list");
        fs::remove_file(&backend.xkb_list).unwrap();
        let reason = backend.validate(&json!("us")).unwrap_err();
        assert!(reason.contains("could not be read"), "{reason}");
        let reason = backend.validate(&json!("u s")).unwrap_err();
        assert!(reason.contains("is not a keyboard layout"), "{reason}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_hand_edited_file_that_names_no_layout_observes_unknown() {
        let (dir, backend) = fixture("unknown");
        fs::write(&backend.vconsole, "XKBLAYOUT=us;reboot\n").unwrap();
        assert_eq!(backend.observe().unwrap(), json!("unknown"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_install_seed_is_the_first_default_when_it_is_loadable() {
        let (dir, backend) = fixture("seed");
        assert_eq!(backend.default_desired(), None);
        fs::write(&backend.install_seed, r#"{"v":1,"keymap":"de+nodeadkeys"}"#).unwrap();
        assert_eq!(backend.default_desired(), Some(json!("de+nodeadkeys")));
        fs::write(&backend.install_seed, r#"{"v":1,"keymap":"fr"}"#).unwrap();
        assert_eq!(backend.default_desired(), None, "not installed");
        fs::write(&backend.install_seed, "not json").unwrap();
        assert_eq!(backend.default_desired(), None);
        let _ = fs::remove_dir_all(&dir);
    }
}
