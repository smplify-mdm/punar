//! `security.credential_isolation` — does this device's credential store keep
//! applications apart?
//!
//! WHY THIS EXISTS, AND WHY IT IS NOT SETTABLE. Punar ships a freedesktop
//! Secret Service so that applications can store passwords at all; without one
//! the catalogue's own mail client re-prompts every launch, and applications
//! that cannot reach a keyring do not stop storing credentials — they store
//! them worse, in files beside their config. But the Secret Service protocol
//! has NO per-application access control: any process holding the bus name can
//! read every item in an unlocked collection. One application's compromise is
//! every application's credentials.
//!
//! That is a real weakness, it was documented in prose, and prose is not a
//! mechanism. An organization enrolling a Punar fleet has to be TOLD, by the
//! device, in the report it already reads — which is what this capability is
//! for. It is observed and never applied: which provider owns
//! `org.freedesktop.secrets` is a property of the image, so
//! [`Capability::mutable`] is false and the reconcile loop reports the drift
//! as alert-only instead of retrying an apply that could never succeed.
//!
//! WHAT IT OBSERVES. The D-Bus activation file for `org.freedesktop.secrets` —
//! the one that decides which program actually answers when an application asks
//! for a secret. Reading the file rather than the running session is
//! deliberate: punard is a system daemon with no session bus, the answer must
//! be the same whether or not anyone is logged in, and the file is what governs
//! every future session rather than the state of one.
//!
//! THE THREE STATES, and each says something different:
//!
//!   * `per_application` — a provider that scopes callers to their own
//!     collection owns the name. This is the intended state and the desired
//!     value; nothing ships it yet.
//!   * `shared` — a provider owns the name and does not scope callers. Every
//!     application that can reach the bus reads every stored secret.
//!   * `none` — nothing owns the name. No application can store a credential
//!     through the desktop at all, which is not a safer state: it is the state
//!     in which applications fall back to their own files.

use std::fs;
use std::path::{Path, PathBuf};

use punar_common::{CapabilityId, Risk};
use serde_json::{Value, json};

use crate::capability::{BackendError, Capability, DescriptorMeta};

pub const CAPABILITY_ID: &str = "security.credential_isolation";

/// The state Punar intends, and therefore the desired value. It is not the
/// observed value on any image that ships today, and that gap is the entire
/// point: an enrolled device reports `non_compliant` until it closes.
pub const DESIRED: &str = "per_application";

/// Providers known to scope callers to their own collection. Empty today —
/// `punar-keyringd` joins it when it exists, and the emptiness is why every
/// current image observes `shared`.
const PER_APPLICATION_PROVIDERS: &[&str] = &[];

pub struct CredentialIsolationBackend {
    /// The D-Bus session activation directory holding
    /// `org.freedesktop.secrets.service`. Injected so tests need no image.
    service_dirs: Vec<PathBuf>,
}

impl Default for CredentialIsolationBackend {
    fn default() -> Self {
        Self::new(vec![
            // Order matters and mirrors D-Bus's own search order: an
            // administrator's /etc entry wins over the vendor one, so a
            // provider swapped in locally is observed rather than missed.
            PathBuf::from("/etc/dbus-1/services"),
            PathBuf::from("/usr/local/share/dbus-1/services"),
            PathBuf::from("/usr/share/dbus-1/services"),
        ])
    }
}

impl CredentialIsolationBackend {
    pub fn new(service_dirs: Vec<PathBuf>) -> Self {
        Self { service_dirs }
    }

    /// The `Exec=` line of the first activation file that claims the name, or
    /// `None` when nothing does.
    fn provider_exec(&self) -> Option<String> {
        for dir in &self.service_dirs {
            let path = dir.join("org.freedesktop.secrets.service");
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            for line in text.lines() {
                let line = line.trim();
                if let Some(exec) = line.strip_prefix("Exec=") {
                    return Some(exec.trim().to_string());
                }
            }
            // The file exists and names no Exec. Something owns the name and
            // this backend cannot tell what — which is not the same as nothing
            // owning it, and must not be reported as `none`.
            return Some(String::new());
        }
        None
    }

    fn state(&self) -> &'static str {
        match self.provider_exec() {
            None => "none",
            Some(exec) => {
                let program = exec
                    .split_whitespace()
                    .next()
                    .and_then(|p| Path::new(p).file_name())
                    .and_then(|p| p.to_str())
                    .unwrap_or_default()
                    .to_string();
                if PER_APPLICATION_PROVIDERS.contains(&program.as_str()) {
                    "per_application"
                } else {
                    // UNKNOWN PROVIDERS ARE `shared`, NOT `per_application`.
                    // The failure directions are not symmetric: calling an
                    // isolating store shared understates the device, while
                    // calling a shared store isolating tells an organization
                    // something false about where its credentials are.
                    "shared"
                }
            }
        }
    }
}

impl Capability for CredentialIsolationBackend {
    fn descriptor(&self) -> DescriptorMeta {
        DescriptorMeta {
            capability: CapabilityId::new(CAPABILITY_ID).expect("static id is valid"),
            risk: Risk::High,
            verification: "dbus-activation-file",
            audit_category: "security",
            state_schema: None,
            allowed_desired_states: Some(vec![
                json!("per_application"),
                json!("shared"),
                json!("none"),
            ]),
        }
    }

    fn mutable(&self) -> bool {
        false
    }

    fn validate(&self, desired: &Value) -> Result<(), String> {
        match desired.as_str() {
            Some("per_application") | Some("shared") | Some("none") => Ok(()),
            _ => Err(
                "credential isolation is observed, not set: it is decided by which provider the \
                 image ships for org.freedesktop.secrets"
                    .to_string(),
            ),
        }
    }

    fn observe(&self) -> Result<Value, BackendError> {
        Ok(json!(self.state()))
    }

    fn apply(&self, _desired: &Value) -> Result<(), BackendError> {
        Err(BackendError::new(
            "credential isolation cannot be changed on a running device: it is decided by which \
             provider the image ships for org.freedesktop.secrets",
        ))
    }

    fn verify(&self, desired: &Value) -> Result<bool, BackendError> {
        Ok(self.observe()? == *desired)
    }

    fn default_desired(&self) -> Option<Value> {
        Some(json!(DESIRED))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("punard-credisol-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_service(d: &Path, exec: &str) {
        fs::write(
            d.join("org.freedesktop.secrets.service"),
            format!("[D-BUS Service]\nName=org.freedesktop.secrets\nExec={exec}\n"),
        )
        .unwrap();
    }

    #[test]
    fn no_provider_is_none_and_a_provider_we_do_not_know_is_shared() {
        let d = dir("states");
        let backend = CredentialIsolationBackend::new(vec![d.clone()]);
        assert_eq!(backend.observe().unwrap(), json!("none"));

        write_service(&d, "/usr/bin/gnome-keyring-daemon --start --foreground");
        assert_eq!(backend.observe().unwrap(), json!("shared"));
        let _ = fs::remove_dir_all(&d);
    }

    /// The asymmetry that matters. Understating isolation costs a device
    /// nothing; overstating it tells an organization something false about
    /// where its credentials are, so an unrecognised provider must land on
    /// `shared` rather than being given the benefit of the doubt.
    #[test]
    fn an_unrecognised_provider_is_never_reported_as_isolating() {
        let d = dir("unknown");
        let backend = CredentialIsolationBackend::new(vec![d.clone()]);
        for exec in [
            "/usr/bin/some-new-keyring",
            "/usr/libexec/vendor-secrets --foreground",
            "",
        ] {
            write_service(&d, exec);
            assert_eq!(
                backend.observe().unwrap(),
                json!("shared"),
                "unrecognised provider {exec:?} must not be reported as isolating"
            );
        }
        let _ = fs::remove_dir_all(&d);
    }

    /// An administrator's /etc entry wins over the vendor one, because D-Bus
    /// resolves it that way — a provider swapped in locally must be observed,
    /// not missed.
    #[test]
    fn the_first_directory_that_claims_the_name_decides() {
        let etc = dir("etc");
        let usr = dir("usr");
        write_service(&usr, "/usr/bin/gnome-keyring-daemon");
        let backend = CredentialIsolationBackend::new(vec![etc.clone(), usr.clone()]);
        assert_eq!(backend.observe().unwrap(), json!("shared"));

        // Nothing in /etc yet, so /usr decided. Now /etc claims it with a file
        // naming no Exec: something owns the name and this backend cannot tell
        // what, which is `shared`, never `none`.
        fs::write(
            etc.join("org.freedesktop.secrets.service"),
            "[D-BUS Service]\nName=org.freedesktop.secrets\n",
        )
        .unwrap();
        assert_eq!(backend.observe().unwrap(), json!("shared"));
        let _ = fs::remove_dir_all(&etc);
        let _ = fs::remove_dir_all(&usr);
    }

    /// It is not settable, and both halves say so: apply refuses, and the
    /// descriptor tells every surface before anyone tries.
    #[test]
    fn it_is_observed_and_never_applied() {
        let d = dir("readonly");
        let backend = CredentialIsolationBackend::new(vec![d.clone()]);
        assert!(!backend.mutable());
        let err = backend.apply(&json!("per_application")).unwrap_err();
        assert!(err.to_string().contains("cannot be changed"), "{err}");

        // And the desired state is the one Punar intends, so a device that has
        // not got there reports drift rather than reporting itself compliant
        // with whatever it happens to be.
        assert_eq!(backend.default_desired(), Some(json!(DESIRED)));
        assert_ne!(backend.observe().unwrap(), json!(DESIRED));
        let _ = fs::remove_dir_all(&d);
    }
}
