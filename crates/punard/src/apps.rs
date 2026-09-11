//! Typed application catalog and application installer.
//!
//! Application installation is privileged, but it is not generic execution:
//! callers name a catalog id, this module selects a build-time source for the
//! observed architecture, and every subprocess receives a fixed argv derived
//! only from the validated catalog. Flatpak metadata is re-read at the pinned
//! commit before installation. Vendor Debian packages are downloaded only on
//! demand, verified against a digest promoted in the signed catalog, and only
//! their data archive is extracted: maintainer scripts are never executed.

use crate::util::SpawnBusyRetry;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::util::{run_with_timeout, sha256_hex};

const INSPECT_TIMEOUT: Duration = Duration::from_secs(30);
// Reading or copying a compressed member from a pinned vendor package can be
// substantially slower on low-power ARM hardware and inside a VM. Keep this
// bounded, but do not apply the small-metadata timeout to a several-hundred-MB
// payload that has already passed its byte-size and SHA-256 checks.
const VENDOR_ARCHIVE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const REMOVE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Configuring a remote writes a local config file and fetches the GPG key
/// named by the repo file. It is not a download of app bytes and must not be
/// given an install-sized budget: a minute is generous, and failing fast here
/// leaves a person with a real error instead of a half-hour of nothing.
const REMOTE_ADD_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_VENDOR_PACKAGE_BYTES: u64 = 600 * 1024 * 1024;
const VENDOR_HOME_PERMISSIONS: &[&str] = &[
    "Network access",
    "Wayland display",
    "Audio playback",
    "Isolated app home",
    "Files selected through the desktop portal",
    "Desktop portal and notification services",
];

#[derive(Debug, Error)]
pub enum AppError {
    #[error("application catalog is invalid: {0}")]
    InvalidCatalog(String),
    #[error("application {0:?} is not in the Punar catalog")]
    NotFound(String),
    #[error("application {app:?} has no supported source for {arch}")]
    Unsupported { app: String, arch: String },
    #[error("application metadata verification failed: {0}")]
    Verification(String),
    #[error("application policy refused the request: {0}")]
    Policy(String),
    #[error("the application backend failed: {0}")]
    Backend(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Catalog {
    v: u64,
    catalog_version: String,
    generated_at: String,
    remotes: Vec<Remote>,
    apps: Vec<App>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Remote {
    id: String,
    repo_file: PathBuf,
    url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Disclosure {
    id: String,
    text: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct App {
    id: String,
    name: String,
    #[serde(default)]
    icon: String,
    #[serde(default)]
    featured: bool,
    category: String,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    window_app_ids: Vec<String>,
    /// Custom URL schemes the upstream desktop application owns, without
    /// the trailing colon (for example `claude`).  This is signed catalog
    /// data, not something a caller may choose at launch time.
    #[serde(default)]
    uri_schemes: Vec<String>,
    summary: String,
    trust_tier: String,
    license: String,
    publisher: String,
    bundled_updater: String,
    disclosures: Vec<Disclosure>,
    sources: Vec<Source>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
enum Source {
    Flatpak {
        architectures: Vec<String>,
        remote: String,
        app_id: String,
        r#ref: String,
        commit: String,
        runtime: String,
        metadata_sha256: String,
    },
    Web {
        architectures: Vec<String>,
        url: String,
        browser: String,
    },
    #[serde(rename = "vendor_deb")]
    VendorDeb {
        architectures: Vec<String>,
        url: String,
        sha256: String,
        byte_size: u64,
        package_name: String,
        version: String,
        data_member: String,
        payload_root: String,
        executable: String,
        icon_path: String,
        desktop_id: String,
    },
}

impl Source {
    fn architectures(&self) -> &[String] {
        match self {
            Source::Flatpak { architectures, .. }
            | Source::Web { architectures, .. }
            | Source::VendorDeb { architectures, .. } => architectures,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Containment {
    Sandboxed,
    Bypass,
}

#[derive(Debug, Clone, Serialize)]
struct Inspection {
    verified: bool,
    commit: String,
    runtime: String,
    metadata_sha256: String,
    containment: Containment,
    permissions: Vec<String>,
    /// Second-person sentences, one per reason this app escapes its sandbox.
    /// Empty for a sandboxed app. The surfaces render these verbatim rather
    /// than composing their own, so a warning cannot drift from the rule that
    /// produced it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    host_access: Vec<String>,
}

/// Immutable catalog view held by the daemon.
#[derive(Clone)]
pub struct AppManager {
    catalog: Catalog,
    flatpak_bin: PathBuf,
    curl_bin: PathBuf,
    bsdtar_bin: PathBuf,
    vendor_root: PathBuf,
    vendor_desktop_dir: PathBuf,
    vendor_config_dir: PathBuf,
    arch: String,
}

impl AppManager {
    /// Load the shipped catalog. `None` gives tests and non-desktop builds
    /// an empty catalog without granting a second install path.
    pub fn load(catalog_path: Option<&Path>, flatpak_bin: PathBuf) -> Result<Self, AppError> {
        Self::load_for_arch(catalog_path, flatpak_bin, None)
    }

    /// Test/image-adapter seam for exercising architecture selection on a
    /// cross-architecture builder. Production passes `None` and observes the
    /// compiled target architecture.
    pub fn load_for_arch(
        catalog_path: Option<&Path>,
        flatpak_bin: PathBuf,
        arch_override: Option<&str>,
    ) -> Result<Self, AppError> {
        let catalog = match catalog_path {
            Some(path) => {
                let bytes = fs::read(path).map_err(|e| {
                    AppError::InvalidCatalog(format!("could not read {}: {e}", path.display()))
                })?;
                serde_json::from_slice(&bytes).map_err(|e| {
                    AppError::InvalidCatalog(format!("could not parse {}: {e}", path.display()))
                })?
            }
            None => Catalog {
                v: 1,
                catalog_version: "disabled".to_string(),
                generated_at: "1970-01-01T00:00:00Z".to_string(),
                remotes: Vec::new(),
                apps: Vec::new(),
            },
        };
        validate_catalog(&catalog)?;
        let arch = arch_override.unwrap_or(std::env::consts::ARCH);
        if !matches!(arch, "x86_64" | "aarch64") {
            return Err(AppError::InvalidCatalog(format!(
                "unsupported application architecture {arch:?}"
            )));
        }
        Ok(Self {
            catalog,
            flatpak_bin,
            curl_bin: PathBuf::from("/usr/bin/curl"),
            bsdtar_bin: PathBuf::from("/usr/bin/bsdtar"),
            vendor_root: PathBuf::from("/var/lib/punar-apps"),
            // XDG_DATA_DIRS entries are data roots; desktop files live in
            // their `applications/` child.  Keeping the root itself here was
            // enough for Punar's catalog view but not for freedesktop URI
            // activation or every standards-compliant application index.
            vendor_desktop_dir: PathBuf::from("/var/lib/punar-applications/applications"),
            vendor_config_dir: PathBuf::from("/var/lib/punar-applications/config"),
            arch: arch.to_string(),
        })
    }

    /// The device's package architecture, as the catalogue's `architectures`
    /// arrays spell it. Published in the shell summary so a surface can decline
    /// to OFFER an application this machine could never install, rather than
    /// letting the person discover it from a refusal.
    pub fn architecture(&self) -> &str {
        &self.arch
    }

    #[cfg(test)]
    fn with_arch(mut self, arch: &str) -> Self {
        self.arch = arch.to_string();
        self
    }

    #[cfg(test)]
    fn with_vendor_paths(
        mut self,
        curl_bin: PathBuf,
        bsdtar_bin: PathBuf,
        vendor_root: PathBuf,
        desktop_dir: PathBuf,
        config_dir: PathBuf,
    ) -> Self {
        self.curl_bin = curl_bin;
        self.bsdtar_bin = bsdtar_bin;
        self.vendor_root = vendor_root;
        self.vendor_desktop_dir = desktop_dir;
        self.vendor_config_dir = config_dir;
        self
    }

    /// Search local catalog data, or inspect one exact app. Inspection is
    /// intentionally live and may take a network round trip to the configured
    /// Flatpak remote.
    pub fn catalog(&self, id: Option<&str>, query: Option<&str>) -> Result<Value, AppError> {
        if let Some(id) = id {
            let app = self.app(id)?;
            return Ok(json!({ "app": self.detail(app)? }));
        }

        let needle = query.unwrap_or_default().trim().to_ascii_lowercase();
        let apps: Vec<Value> = self
            .catalog
            .apps
            .iter()
            .filter(|app| {
                if needle.is_empty() {
                    return true;
                }
                let searchable = format!(
                    "{} {} {} {} {}",
                    app.id,
                    app.name,
                    app.category,
                    app.summary,
                    app.keywords.join(" ")
                )
                .to_ascii_lowercase();
                needle
                    .split_ascii_whitespace()
                    .all(|term| searchable.contains(term))
            })
            .filter_map(|app| self.summary(app).ok())
            .collect();
        Ok(json!({
            "catalog_version": self.catalog.catalog_version,
            "generated_at": self.catalog.generated_at,
            "architecture": self.arch,
            "apps": apps,
        }))
    }

    /// List catalog apps and the observed native installation state.
    pub fn list(&self) -> Result<Value, AppError> {
        let installed = self.installed_flatpaks()?;
        let mut apps = Vec::new();
        for app in &self.catalog.apps {
            let Ok(source) = self.select_source(app) else {
                continue;
            };
            let (installed_now, commit, target, update_available) = match source {
                Source::Flatpak { app_id, commit, .. } => installed.get(app_id).map_or(
                    (false, Value::Null, json!(commit), false),
                    |observed| {
                        // `observed` is abbreviated here — see
                        // `installed_flatpaks`. The grid is a display, and one
                        // subprocess per installed app to un-abbreviate it
                        // would buy nothing: a prefix test answers "is an
                        // update waiting" exactly as well.
                        (
                            true,
                            json!(observed),
                            json!(commit),
                            !commit_is_pinned(observed, commit),
                        )
                    },
                ),
                Source::VendorDeb { sha256, .. } => {
                    let digest = self.installed_vendor_digest(&app.id)?;
                    let update_available = digest.as_deref().is_some_and(|value| value != sha256);
                    (
                        digest.is_some(),
                        digest.map_or(Value::Null, Value::String),
                        json!(sha256),
                        update_available,
                    )
                }
                Source::Web { .. } => (false, Value::Null, Value::Null, false),
            };
            apps.push(json!({
                "id": app.id,
                "name": app.name,
                "source": source_kind(source),
                "installed": installed_now,
                "installed_commit": commit,
                "target_commit": target,
                "update_available": update_available,
            }));
        }
        let updates_available = apps
            .iter()
            .filter(|app| app["update_available"] == true)
            .count();
        Ok(json!({
            "architecture": self.arch,
            "updates_available": updates_available,
            "apps": apps,
        }))
    }

    /// Installed native catalog ids eligible for Punar-owned updates. Web
    /// applications are services rather than local packages and therefore do
    /// not enter this path.
    pub fn update_candidates(&self, id: Option<&str>) -> Result<Vec<String>, AppError> {
        let installed_flatpaks = self.installed_flatpaks()?;
        let apps: Vec<&App> = match id {
            Some(id) => vec![self.app(id)?],
            None => self.catalog.apps.iter().collect(),
        };
        let mut candidates = Vec::new();
        for app in apps {
            match self.select_source(app)? {
                Source::Flatpak { app_id, .. } if installed_flatpaks.contains_key(app_id) => {
                    candidates.push(app.id.clone());
                }
                Source::VendorDeb { .. } if self.installed_vendor_digest(&app.id)?.is_some() => {
                    candidates.push(app.id.clone());
                }
                Source::Flatpak { .. } | Source::VendorDeb { .. } | Source::Web { .. } => {}
            }
        }
        Ok(candidates)
    }

    /// Update one already-installed application to the identity pinned in the
    /// signed catalog. No digest, ref, URL, or version is accepted from the
    /// caller; this is intentionally narrower than a package-manager update.
    pub fn update(&self, id: &str) -> Result<Value, AppError> {
        let app = self.app(id)?;
        let source = self.select_source(app)?;
        match source {
            Source::Flatpak {
                app_id,
                commit,
                metadata_sha256,
                ..
            } => {
                let Some(before) = self.installed_commit(app_id)? else {
                    return Ok(json!({
                        "id": id,
                        "name": app.name,
                        "installed": false,
                        "changed": false,
                        "status": "not_installed",
                    }));
                };
                if before.as_str() == commit {
                    return Ok(json!({
                        "id": id,
                        "name": app.name,
                        "installed": true,
                        "changed": false,
                        "status": "current",
                        "commit": commit,
                    }));
                }
                // Reconcile is desired-state: an administrator or the device's
                // own policy already decided this app belongs here, and there is
                // no person at a card to acknowledge anything. The consent gate
                // is a UI affordance for an interactive install, not a second
                // authorisation, so it is satisfied here rather than turning
                // every managed rollout into a refusal nobody can clear.
                let mut result = self.install(id, metadata_sha256, true)?;
                result["status"] = json!("updated");
                result["previous_commit"] = json!(before);
                Ok(result)
            }
            Source::VendorDeb { sha256, .. } => {
                let Some(before) = self.installed_vendor_digest(id)? else {
                    return Ok(json!({
                        "id": id,
                        "name": app.name,
                        "installed": false,
                        "changed": false,
                        "status": "not_installed",
                    }));
                };
                if before.as_str() == sha256 {
                    return Ok(json!({
                        "id": id,
                        "name": app.name,
                        "installed": true,
                        "changed": false,
                        "status": "current",
                        "commit": sha256,
                    }));
                }
                let mut result = self.install_vendor_deb(app, source, sha256)?;
                result["status"] = json!("updated");
                result["previous_commit"] = json!(before);
                Ok(result)
            }
            Source::Web { .. } => Err(AppError::Unsupported {
                app: id.to_string(),
                arch: format!("{} (the web service updates in the browser)", self.arch),
            }),
        }
    }

    /// Install the exact package identity whose metadata the caller saw.
    /// Install one catalogue app.
    ///
    /// `acknowledge_host_access` is the caller stating that the person saw what
    /// this app can reach outside its sandbox and chose to continue. It is
    /// ignored for a sandboxed app, and required for one that is not; see the
    /// gate below for why a refusal was the wrong shape.
    pub fn install(
        &self,
        id: &str,
        confirmed_digest: &str,
        acknowledge_host_access: bool,
    ) -> Result<Value, AppError> {
        let app = self.app(id)?;
        let source = self.select_source(app)?;
        if matches!(source, Source::VendorDeb { .. }) {
            return self.install_vendor_deb(app, source, confirmed_digest);
        }
        let Source::Flatpak {
            remote,
            app_id,
            r#ref,
            commit,
            metadata_sha256,
            ..
        } = source
        else {
            return Err(AppError::Unsupported {
                app: id.to_string(),
                arch: format!("{} (use the web app)", self.arch),
            });
        };

        let inspection = self.inspect_flatpak(source)?;
        if inspection.metadata_sha256 != metadata_sha256.as_str()
            || inspection.metadata_sha256 != confirmed_digest
        {
            return Err(AppError::Verification(
                "the signed metadata no longer matches the catalog and the install card; refresh the catalog before retrying".to_string(),
            ));
        }
        // THE CONSENT GATE, which this build previously did not have — and whose
        // absence refused 46 of the 57 Flatpaks in the shipped catalogue.
        // Firefox, VS Code, LibreOffice, GIMP, Wireshark, Neovim and most of the
        // rest declare `devices=all`, `features=devel` or a broad filesystem, so
        // the store listed apps it could not install and told the user they
        // "need a security review" — naming a cause that did not exist.
        //
        // docs/design/app-catalog.md section 1.6 never called for a refusal. It
        // called for a card that says, in the second person, what the app can
        // reach, and an install that proceeds once the person has seen it. A
        // refusal is not a stricter version of that; it is a different product,
        // and it is the one where the app store does not work.
        //
        // The acknowledgement is per-install and carries the exact digest the
        // sentences were derived from, so consent cannot be replayed against a
        // different version of the app. Refusal is reserved for the case the
        // design does name: the permissions changed under us.
        if inspection.containment == Containment::Bypass && !acknowledge_host_access {
            return Err(AppError::Policy(format!(
                "this app is not confined by its sandbox and the request did not acknowledge it: {}",
                inspection.host_access.join(" ")
            )));
        }

        let before = self.installed_commit(app_id)?;
        if before.as_deref() == Some(commit.as_str()) {
            return Ok(json!({
                "id": id,
                "name": app.name,
                "installed": true,
                "changed": false,
                "commit": commit,
            }));
        }

        // THE REMOTE HAS TO EXIST, AND ON A FRESH DEVICE IT DOES NOT.
        //
        // mkosi.postinst.chroot runs `flatpak remote-add --system` at BUILD
        // time, which writes /var/lib/flatpak/repo/config into the root slot.
        // At boot, PUNAR-DATA's @var subvolume is mounted over /var
        // (repart.d/install/50-data.conf) and shadows it — deliberately, so an
        // A/B OS swap neither duplicates nor loses installed app bytes. The
        // consequence nobody drew: /var/lib/flatpak is EMPTY on a fresh
        // machine, so no remote exists and every install in the catalogue
        // failed with "flatpak exited with exit status: 1" before touching the
        // network. Verified on a real device: the connection table showed NTP
        // and LLMNR and no TCP to Flathub at all.
        //
        // Adding it in a call rather than a boot unit keeps the enabled-unit
        // manifest unchanged and puts the repair where the need is known. It is
        // idempotent, the repo file is the signed one named by the catalogue,
        // and a failure is reported rather than swallowed: an install about to
        // fail for a missing remote should say THAT. `inspect_flatpak` above
        // has already made the guarantee for this install; it is restated here
        // because the install is a separate promise and reconcile may reach it
        // by a path that skipped the card.
        self.ensure_remote(remote)?;

        // TWO COMMANDS, BECAUSE FLATPAK HAS NO INSTALL-TIME COMMIT FLAG.
        //
        // This used to pass `--commit=` to `flatpak install`, which does not
        // accept it — only `flatpak update` does. flatpak rejected the whole
        // command with "error: Unknown option --commit=…", so EVERY catalogue
        // install failed, and the pin the card promised was never applied by
        // that flag. Verified against flatpak 1.16.6: `install --help` lists
        // --no-deploy, --noninteractive and --or-update and no --commit;
        // `update --help` lists `--commit=COMMIT  Commit to deploy`.
        //
        // So: install the ref, then deploy the pinned commit onto it. When the
        // remote's head already IS the pin — the normal case, since the
        // catalogue is re-pinned against Flathub — the second command is a
        // no-op. When it is not, the second command moves the deployment back
        // to the bytes the person was shown.
        //
        // THE HONEST GAP, stated because it is real: between the two commands
        // the remote's head is deployed, and it may not be the pinned commit.
        // flatpak offers no way to close that window — there is no
        // install-a-specific-commit verb — so the pin is enforced by the
        // deploy below and the verification after it, not by the install.
        run_quiet_with_timeout(
            &self.flatpak_bin,
            &[
                "install",
                "--system",
                "--noninteractive",
                "--or-update",
                remote,
                r#ref,
            ],
            INSTALL_TIMEOUT,
        )?;
        let commit_arg = format!("--commit={commit}");
        run_quiet_with_timeout(
            &self.flatpak_bin,
            &["update", "--system", "--noninteractive", &commit_arg, r#ref],
            INSTALL_TIMEOUT,
        )?;
        // THE WHOLE CHECKSUM, not the listing's twelve-character abbreviation:
        // this is the comparison the card's promise rests on, so it compares
        // every byte of the pin. A checksum flatpak will not report is treated
        // exactly like a wrong one — an unverifiable pin is not a pin.
        let verdict = match self.deployed_commit(app_id) {
            Ok(observed) if observed == *commit => Ok(()),
            Ok(observed) => Err(format!(
                "{app_id} is deployed at {observed} instead of the pinned {commit}"
            )),
            Err(error) => Err(format!(
                "{app_id} was installed but flatpak would not say which commit is deployed, so the pin could not be confirmed: {error}"
            )),
        };
        if let Err(reason) = verdict {
            // FAIL CLOSED. The card said Punar pins the exact bytes; bytes are
            // deployed that are not those bytes, and leaving them installed
            // while returning an error would make the promise false in the one
            // case it exists for. Removal is best-effort — if it also fails the
            // verification error still stands, and it names both facts.
            let removed = run_quiet_with_timeout(
                &self.flatpak_bin,
                &["uninstall", "--system", "--noninteractive", app_id],
                REMOVE_TIMEOUT,
            );
            return Err(AppError::Verification(format!(
                "Flatpak reported success, but {reason}{}",
                match removed {
                    Ok(()) => "; the unpinned copy was removed",
                    Err(_) => "; the unpinned copy could NOT be removed and is still installed",
                }
            )));
        }
        Ok(json!({
            "id": id,
            "name": app.name,
            "installed": true,
            "changed": true,
            "commit": commit,
        }))
    }

    pub fn remove(&self, id: &str) -> Result<Value, AppError> {
        let app = self.app(id)?;
        let source = self.select_source(app)?;
        if matches!(source, Source::VendorDeb { .. }) {
            return self.remove_vendor_deb(app);
        }
        let Source::Flatpak { app_id, .. } = source else {
            return Err(AppError::Unsupported {
                app: id.to_string(),
                arch: format!("{} (the web app has no local package)", self.arch),
            });
        };
        if self.installed_commit(app_id)?.is_none() {
            return Ok(json!({
                "id": id,
                "name": app.name,
                "installed": false,
                "changed": false,
            }));
        }
        run_quiet_with_timeout(
            &self.flatpak_bin,
            &["uninstall", "--system", "--noninteractive", app_id],
            REMOVE_TIMEOUT,
        )?;
        if self.installed_commit(app_id)?.is_some() {
            return Err(AppError::Verification(format!(
                "Flatpak reported success, but {app_id} remains installed"
            )));
        }
        Ok(json!({
            "id": id,
            "name": app.name,
            "installed": false,
            "changed": true,
        }))
    }

    fn app(&self, id: &str) -> Result<&App, AppError> {
        self.catalog
            .apps
            .iter()
            .find(|app| app.id == id)
            .ok_or_else(|| AppError::NotFound(id.to_string()))
    }

    /// Ensure the catalogue's named remote is configured in the system Flatpak
    /// installation, using the repo file the signed catalogue points at.
    ///
    /// `--if-not-exists` makes this a no-op on every boot after the first, and
    /// the argv is fixed: the only caller-influenced value is a remote id that
    /// was validated against the catalogue when it loaded.
    fn ensure_remote(&self, remote_id: &str) -> Result<(), AppError> {
        let Some(remote) = self
            .catalog
            .remotes
            .iter()
            .find(|candidate| candidate.id == remote_id)
        else {
            return Err(AppError::Backend(format!(
                "the catalogue names no remote {remote_id:?}, so this application cannot be fetched"
            )));
        };
        let repo_file = remote.repo_file.to_string_lossy().into_owned();
        run_quiet_with_timeout(
            &self.flatpak_bin,
            &[
                "remote-add",
                "--system",
                "--if-not-exists",
                "--from",
                &remote.id,
                &repo_file,
            ],
            REMOTE_ADD_TIMEOUT,
        )
    }

    fn select_source<'a>(&self, app: &'a App) -> Result<&'a Source, AppError> {
        app.sources
            .iter()
            .filter(|source| source.architectures().iter().any(|a| a == &self.arch))
            .min_by_key(|source| match source {
                Source::Flatpak { .. } => 0,
                Source::VendorDeb { .. } => 1,
                Source::Web { .. } => 2,
            })
            .ok_or_else(|| AppError::Unsupported {
                app: app.id.clone(),
                arch: self.arch.clone(),
            })
    }

    fn summary(&self, app: &App) -> Result<Value, AppError> {
        let source = self.select_source(app)?;
        Ok(json!({
            "id": app.id,
            "name": app.name,
            "icon": app.icon,
            "featured": app.featured,
            "category": app.category,
            "window_app_ids": app.window_app_ids,
            "uri_schemes": app.uri_schemes,
            "summary": app.summary,
            "trust_tier": app.trust_tier,
            "license": app.license,
            "publisher": app.publisher,
            "source": source_kind(source),
        }))
    }

    fn detail(&self, app: &App) -> Result<Value, AppError> {
        let source = self.select_source(app)?;
        let mut detail = self.summary(app)?;
        let object = detail.as_object_mut().expect("summary is an object");
        object.insert("bundled_updater".to_string(), json!(app.bundled_updater));
        object.insert("disclosures".to_string(), json!(app.disclosures));
        match source {
            Source::Flatpak { app_id, .. } => {
                let inspection = self.inspect_flatpak(source)?;
                object.insert("app_id".to_string(), json!(app_id));
                object.insert(
                    "installed".to_string(),
                    json!(self.installed_commit(app_id)?.is_some()),
                );
                object.insert("inspection".to_string(), json!(inspection));
            }
            Source::Web { url, browser, .. } => {
                object.insert("installed".to_string(), json!(false));
                object.insert("url".to_string(), json!(url));
                object.insert("browser".to_string(), json!(browser));
                object.insert("action".to_string(), json!("open"));
            }
            Source::VendorDeb {
                sha256,
                byte_size,
                package_name,
                version,
                executable,
                desktop_id,
                ..
            } => {
                let installed = self.installed_vendor_digest(&app.id)?;
                object.insert("installed".to_string(), json!(installed.is_some()));
                object.insert("installed_digest".to_string(), json!(installed));
                object.insert("desktop_id".to_string(), json!(desktop_id));
                object.insert("version".to_string(), json!(version));
                object.insert("package_name".to_string(), json!(package_name));
                object.insert("download_bytes".to_string(), json!(byte_size));
                object.insert(
                    "launch_executable".to_string(),
                    json!(self.vendor_launch_executable(&app.id, executable)),
                );
                object.insert(
                    "inspection".to_string(),
                    json!({
                        "pinned": true,
                        "verified_on_install": true,
                        "package_sha256": sha256,
                        "containment": "hardened_native",
                        "permissions": VENDOR_HOME_PERMISSIONS,
                    }),
                );
            }
        }
        Ok(detail)
    }

    fn install_vendor_deb(
        &self,
        app: &App,
        source: &Source,
        confirmed_digest: &str,
    ) -> Result<Value, AppError> {
        let Source::VendorDeb {
            architectures,
            url,
            sha256,
            byte_size,
            package_name,
            version,
            data_member,
            payload_root,
            executable,
            icon_path,
            ..
        } = source
        else {
            unreachable!("install_vendor_deb called for another source")
        };
        if confirmed_digest != sha256 {
            return Err(AppError::Verification(
                "the package digest no longer matches the signed catalog and install card; refresh the catalog before retrying".to_string(),
            ));
        }
        if self.installed_vendor_digest(&app.id)?.as_deref() == Some(sha256) {
            // An OS update may improve desktop integration while preserving
            // the already-verified payload in /var.  Repairing the launcher
            // and URI index on a no-op install avoids requiring a 160+ MB
            // re-download merely to pick up that integration.
            self.write_vendor_desktop_integration(app, source)?;
            self.refresh_vendor_desktop_indexes()?;
            return Ok(json!({
                "id": app.id,
                "name": app.name,
                "installed": true,
                "changed": false,
                "version": version,
                "package_sha256": sha256,
            }));
        }

        fs::create_dir_all(&self.vendor_root).map_err(backend_io)?;
        fs::create_dir_all(&self.vendor_desktop_dir).map_err(backend_io)?;
        let staging = self
            .vendor_root
            .join(format!(".staging-{}-{}", app.id, std::process::id()));
        if staging.exists() {
            fs::remove_dir_all(&staging).map_err(backend_io)?;
        }
        fs::create_dir(&staging).map_err(backend_io)?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).map_err(backend_io)?;
        let outcome = (|| {
            let package = staging.join("package.deb");
            let max_size = byte_size.to_string();
            let output = package.to_string_lossy().into_owned();
            let result = run_with_timeout(
                &self.curl_bin,
                &[
                    "--fail",
                    "--location",
                    "--silent",
                    "--show-error",
                    "--proto",
                    "=https",
                    "--proto-redir",
                    "=https",
                    "--max-filesize",
                    &max_size,
                    "--output",
                    &output,
                    url,
                ],
                INSTALL_TIMEOUT,
            )
            .map_err(backend_io)?;
            if !result.success {
                return Err(AppError::Backend(clean_backend_error(&result.stderr)));
            }
            let observed_size = fs::metadata(&package).map_err(backend_io)?.len();
            if observed_size != *byte_size {
                return Err(AppError::Verification(format!(
                    "downloaded {observed_size} bytes, expected the catalog-pinned {byte_size} bytes"
                )));
            }
            let observed_digest = sha256_file(&package).map_err(backend_io)?;
            if &observed_digest != sha256 {
                return Err(AppError::Verification(format!(
                    "download digest {observed_digest} does not match the signed catalog digest {sha256}"
                )));
            }

            let members = archive_list(&self.bsdtar_bin, &package, VENDOR_ARCHIVE_TIMEOUT)?;
            if members
                .iter()
                .filter(|member| member.as_str() == data_member)
                .count()
                != 1
            {
                return Err(AppError::Verification(format!(
                    "{package_name} does not contain exactly one {data_member} member"
                )));
            }
            if members
                .iter()
                .filter(|member| member.as_str() == "control.tar.xz")
                .count()
                != 1
            {
                return Err(AppError::Verification(format!(
                    "{package_name} does not contain exactly one control.tar.xz member"
                )));
            }
            if members.iter().any(|member| !safe_archive_member(member)) {
                return Err(AppError::Verification(
                    "the Debian package contains an unsafe outer archive path".to_string(),
                ));
            }

            let control_archive = staging.join("control.tar.xz");
            extract_member_to_file(
                &self.bsdtar_bin,
                &package,
                "control.tar.xz",
                &control_archive,
                INSPECT_TIMEOUT,
            )?;
            let control_members =
                archive_list(&self.bsdtar_bin, &control_archive, INSPECT_TIMEOUT)?;
            let control_member = control_members
                .iter()
                .find(|member| normalize_archive_path(member).as_deref() == Some("control"))
                .ok_or_else(|| {
                    AppError::Verification(
                        "the Debian control archive has no control document".to_string(),
                    )
                })?;
            let control = extract_text_member(
                &self.bsdtar_bin,
                &control_archive,
                control_member,
                INSPECT_TIMEOUT,
            )?;
            let expected_debian_arch = match architectures[0].as_str() {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                _ => unreachable!("catalog validation closed the architecture set"),
            };
            verify_debian_control(&control, package_name, version, expected_debian_arch)?;

            let data_archive = staging.join(data_member);
            extract_member_to_file(
                &self.bsdtar_bin,
                &package,
                data_member,
                &data_archive,
                VENDOR_ARCHIVE_TIMEOUT,
            )?;
            let payload_members =
                archive_list(&self.bsdtar_bin, &data_archive, VENDOR_ARCHIVE_TIMEOUT)?;
            if payload_members
                .iter()
                .any(|member| !safe_archive_member(member))
            {
                return Err(AppError::Verification(
                    "the application payload contains an unsafe path".to_string(),
                ));
            }
            let normalized_payload = normalize_archive_path(payload_root).ok_or_else(|| {
                AppError::InvalidCatalog(format!("app {:?} has an unsafe payload root", app.id))
            })?;
            let normalized_icon = normalize_archive_path(icon_path).ok_or_else(|| {
                AppError::InvalidCatalog(format!("app {:?} has an unsafe icon path", app.id))
            })?;
            let has_payload = payload_members.iter().any(|member| {
                normalize_archive_path(member).is_some_and(|path| {
                    path == normalized_payload
                        || path.starts_with(&format!("{normalized_payload}/"))
                })
            });
            if !has_payload
                || !payload_members.iter().any(|member| {
                    normalize_archive_path(member).as_deref() == Some(&normalized_icon)
                })
            {
                return Err(AppError::Verification(
                    "the verified package is missing its declared application payload or icon"
                        .to_string(),
                ));
            }

            let root = staging.join("root");
            fs::create_dir(&root).map_err(backend_io)?;
            extract_payload(
                &self.bsdtar_bin,
                &data_archive,
                &root,
                payload_root,
                icon_path,
                INSTALL_TIMEOUT,
            )?;
            validate_extracted_tree(&root)?;
            clear_privileged_mode_bits(&root)?;
            let executable_path = root.join(executable);
            if !executable_path.is_file()
                || fs::metadata(&executable_path)
                    .map_err(backend_io)?
                    .permissions()
                    .mode()
                    & 0o111
                    == 0
            {
                return Err(AppError::Verification(
                    "the verified package is missing its declared executable".to_string(),
                ));
            }
            if !root.join(icon_path).is_file() {
                return Err(AppError::Verification(
                    "the verified package is missing its declared icon".to_string(),
                ));
            }

            let manifest = json!({
                "v": 1,
                "id": app.id,
                "package_name": package_name,
                "version": version,
                "package_sha256": sha256,
                "source": "vendor_deb",
                "maintainer_scripts_executed": false,
                "privileged_mode_bits_preserved": false,
            });
            fs::write(
                root.join("install.json"),
                serde_json::to_vec_pretty(&manifest).expect("vendor manifest serializes"),
            )
            .map_err(backend_io)?;

            let app_dir = self.vendor_root.join(&app.id);
            fs::create_dir_all(&app_dir).map_err(backend_io)?;
            let version_dir = app_dir.join(sha256);
            if version_dir.exists() {
                fs::remove_dir_all(&version_dir).map_err(backend_io)?;
            }
            fs::rename(&root, &version_dir).map_err(backend_io)?;
            let current_tmp = app_dir.join(format!(".current-{}", std::process::id()));
            let _ = fs::remove_file(&current_tmp);
            symlink(sha256, &current_tmp).map_err(backend_io)?;
            fs::rename(&current_tmp, app_dir.join("current")).map_err(backend_io)?;

            self.write_vendor_desktop_integration(app, source)?;
            for entry in fs::read_dir(&app_dir).map_err(backend_io)? {
                let entry = entry.map_err(backend_io)?;
                let path = entry.path();
                if entry.file_name() != sha256.as_str()
                    && entry.file_name() != "current"
                    && path.is_dir()
                {
                    fs::remove_dir_all(path).map_err(backend_io)?;
                }
            }
            Ok(())
        })();
        let _ = fs::remove_dir_all(&staging);
        outcome?;
        self.refresh_vendor_desktop_indexes()?;
        Ok(json!({
            "id": app.id,
            "name": app.name,
            "installed": true,
            "changed": true,
            "version": version,
            "package_sha256": sha256,
        }))
    }

    fn remove_vendor_deb(&self, app: &App) -> Result<Value, AppError> {
        let app_dir = self.vendor_root.join(&app.id);
        let source = self.select_source(app)?;
        let Source::VendorDeb { desktop_id, .. } = source else {
            unreachable!("remove_vendor_deb called for another source")
        };
        let desktop = self
            .vendor_desktop_dir
            .join(format!("{desktop_id}.desktop"));
        let existed = app_dir.exists() || desktop.exists();
        if app_dir.exists() {
            fs::remove_dir_all(&app_dir).map_err(backend_io)?;
        }
        crate::util::remove_synced(&desktop).map_err(backend_io)?;
        // Remove the pre-fix location too.  It was directly below the XDG
        // data root instead of its required applications/ child.
        if let Some(data_root) = self.vendor_desktop_dir.parent() {
            crate::util::remove_synced(&data_root.join(format!("{desktop_id}.desktop")))
                .map_err(backend_io)?;
        }
        self.refresh_vendor_desktop_indexes()?;
        Ok(json!({
            "id": app.id,
            "name": app.name,
            "installed": false,
            "changed": existed,
        }))
    }

    /// Rebuild the standards-facing launchers and URI indexes from installed
    /// manifests. Called once at daemon startup so an A/B OS update repairs
    /// existing application state without touching its isolated user data.
    pub(crate) fn reconcile_vendor_desktop_integration(&self) -> Result<(), AppError> {
        if !self.vendor_root.exists() {
            return Ok(());
        }
        fs::create_dir_all(&self.vendor_desktop_dir).map_err(backend_io)?;
        fs::create_dir_all(&self.vendor_config_dir).map_err(backend_io)?;
        for app in &self.catalog.apps {
            let Ok(source) = self.select_source(app) else {
                continue;
            };
            if matches!(source, Source::VendorDeb { .. })
                && self.installed_vendor_digest(&app.id)?.is_some()
            {
                self.write_vendor_desktop_integration(app, source)?;
            }
        }
        self.refresh_vendor_desktop_indexes()
    }

    fn write_vendor_desktop_integration(&self, app: &App, source: &Source) -> Result<(), AppError> {
        let Source::VendorDeb {
            icon_path,
            desktop_id,
            ..
        } = source
        else {
            unreachable!("vendor desktop integration requested for another source")
        };
        let icon = self
            .vendor_root
            .join(&app.id)
            .join("current")
            .join(icon_path);
        if !icon.is_file() {
            return Err(AppError::Verification(format!(
                "installed app {:?} is missing its declared icon",
                app.id
            )));
        }
        fs::create_dir_all(&self.vendor_desktop_dir).map_err(backend_io)?;
        let desktop = vendor_desktop_entry(app, desktop_id, &icon);
        crate::util::write_atomic_synced(
            &self
                .vendor_desktop_dir
                .join(format!("{desktop_id}.desktop")),
            desktop.as_bytes(),
            0o644,
        )
        .map_err(backend_io)?;
        if let Some(data_root) = self.vendor_desktop_dir.parent() {
            crate::util::remove_synced(&data_root.join(format!("{desktop_id}.desktop")))
                .map_err(backend_io)?;
        }
        Ok(())
    }

    fn refresh_vendor_desktop_indexes(&self) -> Result<(), AppError> {
        let mut handlers: BTreeMap<String, String> = BTreeMap::new();
        for app in &self.catalog.apps {
            if app.uri_schemes.is_empty() || self.installed_vendor_digest(&app.id)?.is_none() {
                continue;
            }
            let Ok(Source::VendorDeb { desktop_id, .. }) = self.select_source(app) else {
                continue;
            };
            for scheme in &app.uri_schemes {
                handlers.insert(scheme.clone(), format!("{desktop_id}.desktop"));
            }
        }

        fs::create_dir_all(&self.vendor_desktop_dir).map_err(backend_io)?;
        fs::create_dir_all(&self.vendor_config_dir).map_err(backend_io)?;
        let mimeapps_path = self.vendor_config_dir.join("mimeapps.list");
        let mimeinfo_path = self.vendor_desktop_dir.join("mimeinfo.cache");
        if handlers.is_empty() {
            crate::util::remove_synced(&mimeapps_path).map_err(backend_io)?;
            crate::util::remove_synced(&mimeinfo_path).map_err(backend_io)?;
            return Ok(());
        }

        let mut defaults = String::from("[Default Applications]\n");
        let mut associations = String::from("[Added Associations]\n");
        let mut cache = String::from("[MIME Cache]\n");
        for (scheme, desktop) in handlers {
            let mime = format!("x-scheme-handler/{scheme}");
            defaults.push_str(&format!("{mime}={desktop};\n"));
            associations.push_str(&format!("{mime}={desktop};\n"));
            cache.push_str(&format!("{mime}={desktop};\n"));
        }
        defaults.push('\n');
        defaults.push_str(&associations);
        crate::util::write_atomic_synced(&mimeapps_path, defaults.as_bytes(), 0o644)
            .map_err(backend_io)?;
        crate::util::write_atomic_synced(&mimeinfo_path, cache.as_bytes(), 0o644)
            .map_err(backend_io)
    }

    fn installed_vendor_digest(&self, id: &str) -> Result<Option<String>, AppError> {
        let manifest = self.vendor_root.join(id).join("current/install.json");
        let bytes = match fs::read(&manifest) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(backend_io(error)),
        };
        let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
            AppError::Verification(format!("installed app manifest is invalid: {error}"))
        })?;
        let digest = value
            .get("package_sha256")
            .and_then(Value::as_str)
            .filter(|value| is_sha256(value))
            .ok_or_else(|| {
                AppError::Verification("installed app manifest has no valid digest".to_string())
            })?;
        Ok(Some(digest.to_string()))
    }

    fn vendor_launch_executable(&self, id: &str, executable: &str) -> String {
        self.vendor_root
            .join(id)
            .join("current")
            .join(executable)
            .to_string_lossy()
            .into_owned()
    }

    fn inspect_flatpak(&self, source: &Source) -> Result<Inspection, AppError> {
        let Source::Flatpak {
            remote,
            r#ref,
            commit,
            runtime,
            metadata_sha256,
            ..
        } = source
        else {
            unreachable!("inspect_flatpak called for a web source")
        };
        // THE REMOTE HAS TO EXIST BEFORE THIS LINE, NOT BEFORE THE INSTALL.
        //
        // `remote-info` resolves the ref through a configured remote, so on a
        // fresh device — where PUNAR-DATA's @var subvolume shadows the empty
        // /var/lib/flatpak the image build populated — the very first card a
        // person opens fails before it can draw a single permission sentence.
        // The repair used to sit further down `install`, which meant it only
        // ever ran after an inspection that had already failed; it appeared to
        // work in testing solely because a failed install had added the remote
        // on the way past, so the SECOND attempt found one. Putting it here
        // covers the card, the install and reconcile with one idempotent call.
        self.ensure_remote(remote)?;
        let commit_arg = format!("--commit={commit}");
        let arch_arg = format!("--arch={}", self.arch);
        let result = run_with_timeout(
            &self.flatpak_bin,
            &[
                "remote-info",
                "--system",
                &arch_arg,
                &commit_arg,
                "--show-metadata",
                remote,
                r#ref,
            ],
            INSPECT_TIMEOUT,
        )
        .map_err(|e| AppError::Backend(e.to_string()))?;
        if !result.success {
            return Err(AppError::Backend(clean_backend_error(&result.stderr)));
        }
        let observed_digest = sha256_hex(result.stdout.as_bytes());
        if &observed_digest != metadata_sha256 {
            return Err(AppError::Verification(format!(
                "metadata digest {observed_digest} does not match the pinned catalog digest {metadata_sha256}"
            )));
        }
        let (containment, permissions, host_access) = inspect_permissions(&result.stdout);
        Ok(Inspection {
            verified: true,
            commit: commit.clone(),
            runtime: runtime.clone(),
            metadata_sha256: observed_digest,
            containment,
            permissions,
            host_access,
        })
    }

    /// The installed system apps, mapped to the checksum of the active
    /// deployment AS `flatpak list` RENDERS IT — which is abbreviated.
    ///
    /// This is the cheap enumeration: one subprocess for the whole set. It
    /// answers "is it installed" exactly, and "which bytes" only to twelve
    /// characters. Anything comparing against a catalogue pin wants
    /// [`Self::deployed_commit`] instead.
    fn installed_flatpaks(&self) -> Result<BTreeMap<String, String>, AppError> {
        if self.catalog.apps.is_empty() {
            return Ok(BTreeMap::new());
        }
        let result = run_with_timeout(
            &self.flatpak_bin,
            // Flatpak names the active deployment checksum `active` in the
            // list-column API (including Debian's 1.18.x build). `commit` is
            // accepted by `remote-info`, but is not a list column.
            &["list", "--system", "--app", "--columns=application,active"],
            INSPECT_TIMEOUT,
        )
        .map_err(|e| AppError::Backend(e.to_string()))?;
        if !result.success {
            return Err(AppError::Backend(clean_backend_error(&result.stderr)));
        }
        Ok(result
            .stdout
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .map(|(id, commit)| (id.to_string(), commit.to_string()))
            .collect())
    }

    /// The FULL checksum of the deployment currently active for `app_id`.
    ///
    /// THE ABBREVIATION IS WHY THIS EXISTS. `flatpak list --columns=…,active`
    /// prints the checksum ellipsized to twelve characters, and the catalogue
    /// pins all sixty-four. Comparing the two with `!=` can never be equal, so
    /// the post-install verification rejected installs that had in fact landed
    /// on exactly the pinned commit and — failing closed, as it should when the
    /// bytes really are wrong — uninstalled them. Evolution reported
    /// `Some("4b6430b6e8b6")` "instead of the pinned commit" whose first twelve
    /// characters are `4b6430b6e8b6`.
    ///
    /// `flatpak info --show-commit` is the only interface that reports the
    /// whole checksum. A single `--show-` option prints the bare value; more
    /// than one prints `Label: value` lines, so the last whitespace-separated
    /// token is taken and then required to be a full checksum. An
    /// unrecognisable answer is an error, never a shrug: a pin that cannot be
    /// read is a pin that cannot be enforced.
    fn deployed_commit(&self, app_id: &str) -> Result<String, AppError> {
        let result = run_with_timeout(
            &self.flatpak_bin,
            &["info", "--system", "--show-commit", app_id],
            INSPECT_TIMEOUT,
        )
        .map_err(|e| AppError::Backend(e.to_string()))?;
        if !result.success {
            return Err(AppError::Backend(clean_backend_error(&result.stderr)));
        }
        let commit = result
            .stdout
            .split_whitespace()
            .next_back()
            .unwrap_or_default();
        // An ostree commit checksum has the shape of any other sha256.
        if !is_sha256(commit) {
            return Err(AppError::Backend(format!(
                "flatpak reported the deployed commit of {app_id} as {commit:?}, which is not a checksum"
            )));
        }
        Ok(commit.to_string())
    }

    /// The full checksum of `app_id`, or `None` when it is not installed.
    fn installed_commit(&self, app_id: &str) -> Result<Option<String>, AppError> {
        if !self.installed_flatpaks()?.contains_key(app_id) {
            return Ok(None);
        }
        self.deployed_commit(app_id).map(Some)
    }
}

/// Whether the deployment `observed` is the catalogue's pinned `commit`.
///
/// `observed` is full whenever it came from [`AppManager::deployed_commit`],
/// and the twelve-character abbreviation when it came from the cheap listing;
/// a prefix test is equality for the first and the strongest available answer
/// for the second. The abbreviated form is only ever used to render "an update
/// is available" in the app grid — never to decide that installed bytes are
/// the bytes a person was shown, which is [`AppManager::install`]'s job and
/// compares full checksums.
fn commit_is_pinned(observed: &str, pinned: &str) -> bool {
    observed.len() >= 12 && pinned.starts_with(observed)
}

fn source_kind(source: &Source) -> &'static str {
    match source {
        Source::Flatpak { .. } => "flatpak",
        Source::Web { .. } => "web",
        Source::VendorDeb { .. } => "vendor_deb",
    }
}

fn backend_io(error: std::io::Error) -> AppError {
    AppError::Backend(error.to_string())
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn archive_list(bin: &Path, archive: &Path, timeout: Duration) -> Result<Vec<String>, AppError> {
    let archive_arg = archive.to_string_lossy().into_owned();
    let result = run_capture_with_timeout(bin, &["-tf", &archive_arg], timeout)?;
    if !result.success {
        return Err(AppError::Verification(format!(
            "the package archive could not be read: {}",
            clean_backend_error(&result.stderr)
        )));
    }
    if result.stdout.len() > 16 * 1024 * 1024 {
        return Err(AppError::Verification(
            "the package archive has an unreasonable number of entries".to_string(),
        ));
    }
    Ok(result
        .stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

fn run_capture_with_timeout(
    bin: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<crate::util::CommandResult, AppError> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_busy_retry()
        .map_err(backend_io)?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes);
        bytes
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.take(64 * 1024 + 1).read_to_end(&mut bytes);
        bytes
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(AppError::Backend(format!(
                    "{} timed out after {timeout:?}",
                    bin.display()
                )));
            }
            Err(error) => return Err(backend_io(error)),
        }
    };
    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    Ok(crate::util::CommandResult {
        success: status.success(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

fn extract_member_to_file(
    bin: &Path,
    archive: &Path,
    member: &str,
    output: &Path,
    timeout: Duration,
) -> Result<(), AppError> {
    let archive_arg = archive.to_string_lossy().into_owned();
    let file = File::create(output).map_err(backend_io)?;
    let mut child = Command::new(bin)
        .args(["-xOf", &archive_arg, member])
        .stdin(Stdio::null())
        .stdout(Stdio::from(file))
        .stderr(Stdio::null())
        .spawn_busy_retry()
        .map_err(backend_io)?;
    wait_quiet_child(bin, &mut child, timeout, None)
}

fn extract_text_member(
    bin: &Path,
    archive: &Path,
    member: &str,
    timeout: Duration,
) -> Result<String, AppError> {
    let archive_arg = archive.to_string_lossy().into_owned();
    let result = run_capture_with_timeout(bin, &["-xOf", &archive_arg, member], timeout)?;
    if !result.success {
        return Err(AppError::Verification(format!(
            "the package control document could not be read: {}",
            clean_backend_error(&result.stderr)
        )));
    }
    if result.stdout.len() > 64 * 1024 {
        return Err(AppError::Verification(
            "the package control document is unreasonably large".to_string(),
        ));
    }
    Ok(result.stdout)
}

fn verify_debian_control(
    control: &str,
    package_name: &str,
    version: &str,
    architecture: &str,
) -> Result<(), AppError> {
    let mut fields = BTreeMap::new();
    for line in control.lines() {
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            fields.insert(key.trim(), value.trim());
        }
    }
    for (field, expected) in [
        ("Package", package_name),
        ("Version", version),
        ("Architecture", architecture),
    ] {
        let observed = fields.get(field).copied().unwrap_or("missing");
        if observed != expected {
            return Err(AppError::Verification(format!(
                "Debian control field {field} is {observed:?}, expected {expected:?}"
            )));
        }
    }
    Ok(())
}

fn extract_payload(
    bin: &Path,
    archive: &Path,
    destination: &Path,
    payload_root: &str,
    icon_path: &str,
    timeout: Duration,
) -> Result<(), AppError> {
    let archive_arg = archive.to_string_lossy().into_owned();
    let destination_arg = destination.to_string_lossy().into_owned();
    let mut child = Command::new(bin)
        .args([
            "-xf",
            &archive_arg,
            "-C",
            &destination_arg,
            "--no-same-owner",
            "--no-same-permissions",
            "--no-xattrs",
            "--no-acls",
            "--no-fflags",
            payload_root,
            icon_path,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn_busy_retry()
        .map_err(backend_io)?;
    wait_quiet_child(bin, &mut child, timeout, None)
}

/// Wait for a fixed-argv backend child, and — when `capture` names a file its
/// stderr was redirected to — say what it said.
///
/// STDERR USED TO GO TO /dev/null on every caller, and the cost was paid by a
/// person rather than a log: a failed install produced exactly
/// "/usr/bin/flatpak exited with exit status: 1" on the install card, and
/// punard's own next-step text had to GUESS at the cause ("check network
/// connectivity and `flatpak remotes`") because the daemon had discarded the
/// one sentence that knew.
fn wait_quiet_child(
    bin: &Path,
    child: &mut std::process::Child,
    timeout: Duration,
    capture: Option<&Path>,
) -> Result<(), AppError> {
    // Read at most this much back: enough for any real diagnostic, bounded so a
    // runaway backend cannot make the daemon allocate on its behalf.
    const MAX_CAPTURE: u64 = 64 * 1024;
    let detail = |capture: Option<&Path>| -> String {
        let Some(path) = capture else {
            return String::new();
        };
        let mut text = String::new();
        if let Ok(file) = File::open(path) {
            let _ = file.take(MAX_CAPTURE).read_to_string(&mut text);
        }
        let _ = fs::remove_file(path);
        backend_failure_detail(&text)
    };
    let discard = |capture: Option<&Path>| {
        if let Some(path) = capture {
            let _ = fs::remove_file(path);
        }
    };

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                discard(capture);
                return Ok(());
            }
            Ok(Some(status)) => {
                let said = detail(capture);
                return Err(AppError::Backend(if said.is_empty() {
                    format!("{} exited with {status}", bin.display())
                } else {
                    format!("{} exited with {status}: {said}", bin.display())
                }));
            }
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let said = detail(capture);
                return Err(AppError::Backend(if said.is_empty() {
                    format!("{} timed out after {timeout:?}", bin.display())
                } else {
                    format!(
                        "{} timed out after {timeout:?}; last said: {said}",
                        bin.display()
                    )
                }));
            }
            Err(error) => {
                discard(capture);
                return Err(backend_io(error));
            }
        }
    }
}

fn normalize_archive_path(value: &str) -> Option<String> {
    let value = value.strip_prefix("./").unwrap_or(value);
    if value.is_empty() || value.len() > 4096 || value.starts_with('/') {
        return None;
    }
    let mut parts = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ if part.bytes().any(|byte| byte < 0x20 || byte == 0x7f) => return None,
            _ => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn safe_archive_member(value: &str) -> bool {
    matches!(value, "." | "./") || normalize_archive_path(value).is_some()
}

fn validate_extracted_tree(root: &Path) -> Result<(), AppError> {
    fn visit(root: &Path, path: &Path) -> Result<(), AppError> {
        for entry in fs::read_dir(path).map_err(backend_io)? {
            let entry = entry.map_err(backend_io)?;
            let entry_path = entry.path();
            let metadata = fs::symlink_metadata(&entry_path).map_err(backend_io)?;
            let kind = metadata.file_type();
            if kind.is_dir() {
                visit(root, &entry_path)?;
            } else if kind.is_symlink() {
                let target = fs::read_link(&entry_path).map_err(backend_io)?;
                if target.is_absolute() {
                    return Err(AppError::Verification(
                        "the application payload contains an absolute symlink".to_string(),
                    ));
                }
                let relative_parent = entry_path
                    .parent()
                    .and_then(|parent| parent.strip_prefix(root).ok())
                    .unwrap_or(Path::new(""));
                let resolved = relative_parent.join(target);
                if normalize_archive_path(&resolved.to_string_lossy()).is_none() {
                    return Err(AppError::Verification(
                        "the application payload contains an escaping symlink".to_string(),
                    ));
                }
            } else if !kind.is_file() {
                return Err(AppError::Verification(
                    "the application payload contains a device, socket, or FIFO".to_string(),
                ));
            }
        }
        Ok(())
    }
    visit(root, root)
}

fn clear_privileged_mode_bits(root: &Path) -> Result<(), AppError> {
    fn visit(path: &Path) -> Result<(), AppError> {
        for entry in fs::read_dir(path).map_err(backend_io)? {
            let entry = entry.map_err(backend_io)?;
            let entry_path = entry.path();
            let metadata = fs::symlink_metadata(&entry_path).map_err(backend_io)?;
            if metadata.is_dir() {
                visit(&entry_path)?;
            }
            if !metadata.file_type().is_symlink() {
                let mut permissions = metadata.permissions();
                let mode = permissions.mode() & !0o6000;
                permissions.set_mode(mode);
                fs::set_permissions(&entry_path, permissions).map_err(backend_io)?;
            }
        }
        Ok(())
    }
    visit(root)
}

fn vendor_desktop_entry(app: &App, desktop_id: &str, icon: &Path) -> String {
    let category = match app.category.as_str() {
        "productivity" => "Office",
        "communication" => "Network;Chat",
        "media" => "AudioVideo",
        "developer" | "editors" => "Development",
        "files" => "System;FileTools;FileManager",
        "security" => "Security",
        "writing" => "Office;TextEditor",
        _ => "Utility",
    };
    let startup_class = app
        .window_app_ids
        .first()
        .map_or(desktop_id, String::as_str);
    let uri_placeholder = if app.uri_schemes.is_empty() {
        ""
    } else {
        " %U"
    };
    let mime_types = if app.uri_schemes.is_empty() {
        String::new()
    } else {
        format!(
            "MimeType={};\n",
            app.uri_schemes
                .iter()
                .map(|scheme| format!("x-scheme-handler/{scheme}"))
                .collect::<Vec<_>>()
                .join(";")
        )
    };
    format!(
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName={}\nComment={}\nExec=punarctl app open {}{}\nIcon={}\nTerminal=false\nCategories={};\nStartupNotify=true\nStartupWMClass={}\n{}",
        app.name,
        app.summary,
        app.id,
        uri_placeholder,
        icon.display(),
        category,
        startup_class,
        mime_types,
    )
}

fn validate_catalog(catalog: &Catalog) -> Result<(), AppError> {
    if catalog.v != 1 {
        return Err(AppError::InvalidCatalog(format!(
            "unsupported version {}",
            catalog.v
        )));
    }
    let remotes: BTreeSet<&str> = catalog.remotes.iter().map(|r| r.id.as_str()).collect();
    if remotes.len() != catalog.remotes.len() {
        return Err(AppError::InvalidCatalog("duplicate remote id".to_string()));
    }
    for remote in &catalog.remotes {
        if !remote.repo_file.is_absolute() || !remote.url.starts_with("https://") {
            return Err(AppError::InvalidCatalog(format!(
                "remote {:?} is not an absolute HTTPS definition",
                remote.id
            )));
        }
    }
    let mut ids = BTreeSet::new();
    let mut uri_owners: BTreeMap<&str, &str> = BTreeMap::new();
    for app in &catalog.apps {
        if app.id.is_empty()
            || app.id.len() > 64
            || !app
                .id
                .bytes()
                .enumerate()
                .all(|(i, b)| b.is_ascii_lowercase() || b.is_ascii_digit() || (i > 0 && b == b'-'))
        {
            return Err(AppError::InvalidCatalog(format!(
                "app id {:?} is not lower-kebab-case",
                app.id
            )));
        }
        if !ids.insert(app.id.as_str()) {
            return Err(AppError::InvalidCatalog(format!(
                "duplicate app id {:?}",
                app.id
            )));
        }
        if !is_safe_icon_basename(&app.icon) {
            return Err(AppError::InvalidCatalog(format!(
                "app {:?} has an unsafe icon basename",
                app.id
            )));
        }
        if !is_desktop_text(&app.name) || !is_desktop_text(&app.summary) {
            return Err(AppError::InvalidCatalog(format!(
                "app {:?} contains unsafe desktop-entry text",
                app.id
            )));
        }
        if app.keywords.len() > 16
            || app.keywords.iter().any(|keyword| {
                keyword.is_empty()
                    || keyword.len() > 40
                    || keyword.trim() != keyword
                    || !keyword.bytes().enumerate().all(|(index, byte)| {
                        byte.is_ascii_alphanumeric() || (index > 0 && b" .+#_-".contains(&byte))
                    })
            })
        {
            return Err(AppError::InvalidCatalog(format!(
                "app {:?} has invalid search keywords",
                app.id
            )));
        }
        if app.window_app_ids.len() > 8
            || app.window_app_ids.iter().collect::<BTreeSet<_>>().len() != app.window_app_ids.len()
            || app.window_app_ids.iter().any(|id| {
                id.is_empty()
                    || id.len() > 128
                    || !id.bytes().enumerate().all(|(index, byte)| {
                        byte.is_ascii_alphanumeric()
                            || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
                    })
            })
        {
            return Err(AppError::InvalidCatalog(format!(
                "app {:?} has invalid runtime window ids",
                app.id
            )));
        }
        if app.uri_schemes.len() > 8
            || app.uri_schemes.iter().collect::<BTreeSet<_>>().len() != app.uri_schemes.len()
            || app.uri_schemes.iter().any(|scheme| {
                scheme.is_empty()
                    || scheme.len() > 32
                    || !scheme.bytes().enumerate().all(|(index, byte)| {
                        (index == 0 && byte.is_ascii_lowercase())
                            || (index > 0
                                && (byte.is_ascii_lowercase()
                                    || byte.is_ascii_digit()
                                    || matches!(byte, b'+' | b'.' | b'-')))
                    })
                    || matches!(
                        scheme.as_str(),
                        "data" | "file" | "ftp" | "http" | "https" | "javascript" | "mailto"
                    )
            })
        {
            return Err(AppError::InvalidCatalog(format!(
                "app {:?} has invalid or reserved URI schemes",
                app.id
            )));
        }
        for scheme in &app.uri_schemes {
            if let Some(owner) = uri_owners.insert(scheme, &app.id) {
                return Err(AppError::InvalidCatalog(format!(
                    "URI scheme {scheme:?} is claimed by both {owner:?} and {:?}",
                    app.id
                )));
            }
        }
        let mut has_vendor_source = false;
        for source in &app.sources {
            if let Source::Flatpak {
                remote,
                app_id,
                r#ref,
                commit,
                metadata_sha256,
                ..
            } = source
            {
                if !remotes.contains(remote.as_str()) {
                    return Err(AppError::InvalidCatalog(format!(
                        "app {:?} refers to unknown remote {:?}",
                        app.id, remote
                    )));
                }
                if !is_sha256(commit) || !is_sha256(metadata_sha256) {
                    return Err(AppError::InvalidCatalog(format!(
                        "app {:?} has a malformed pinned digest",
                        app.id
                    )));
                }
                if !r#ref.starts_with(&format!("app/{app_id}/")) {
                    return Err(AppError::InvalidCatalog(format!(
                        "app {:?} has a ref that does not match its Flatpak id",
                        app.id
                    )));
                }
            } else if let Source::Web { url, browser, .. } = source {
                if browser != "chromium" || !url.starts_with("https://") {
                    return Err(AppError::InvalidCatalog(format!(
                        "app {:?} has an unsupported web launch contract",
                        app.id
                    )));
                }
            } else if let Source::VendorDeb {
                architectures,
                url,
                sha256,
                byte_size,
                package_name,
                version,
                data_member,
                payload_root,
                executable,
                icon_path,
                desktop_id,
            } = source
            {
                has_vendor_source = true;
                let allowed_origin = url
                    .starts_with("https://persistent.oaistatic.com/codex-app-prod/linux/deb/")
                    || url.starts_with(
                        "https://downloads.claude.ai/claude-desktop/apt/stable/pool/main/",
                    )
                    || url.starts_with(
                        "https://downloads.slack-edge.com/desktop-releases/linux/x64/",
                    );
                let normalized_payload = normalize_archive_path(payload_root);
                let normalized_executable = normalize_archive_path(executable);
                let normalized_icon = normalize_archive_path(icon_path);
                let valid_payload = normalized_payload
                    .as_deref()
                    .is_some_and(|path| path.starts_with("usr/lib/"));
                let executable_inside_payload = normalized_payload
                    .as_deref()
                    .zip(normalized_executable.as_deref())
                    .is_some_and(|(root, path)| path.starts_with(&format!("{root}/")));
                let valid_icon = normalized_icon.as_deref().is_some_and(|path| {
                    path.starts_with("usr/share/pixmaps/") || path.starts_with("usr/share/icons/")
                });
                if architectures.len() != 1
                    || !allowed_origin
                    || !is_sha256(sha256)
                    || *byte_size == 0
                    || *byte_size > MAX_VENDOR_PACKAGE_BYTES
                    || package_name.is_empty()
                    || package_name.len() > 80
                    || !package_name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-')
                    })
                    || version.is_empty()
                    || version.len() > 80
                    || !version.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || matches!(byte, b'.' | b'+' | b':' | b'~' | b'-')
                    })
                    || data_member != "data.tar.xz"
                    || !valid_payload
                    || !executable_inside_payload
                    || !valid_icon
                    || desktop_id != &format!("punar-{}", app.id)
                {
                    return Err(AppError::InvalidCatalog(format!(
                        "app {:?} has an unsafe vendor package contract",
                        app.id
                    )));
                }
            }
        }
        if !app.uri_schemes.is_empty() && !has_vendor_source {
            return Err(AppError::InvalidCatalog(format!(
                "app {:?} declares URI schemes without a Punar-generated vendor launcher",
                app.id
            )));
        }
    }
    Ok(())
}

fn is_safe_icon_basename(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let Some(stem) = value
        .strip_suffix(".svg")
        .or_else(|| value.strip_suffix(".png"))
    else {
        return false;
    };
    !stem.is_empty()
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_desktop_text(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn inspect_permissions(metadata: &str) -> (Containment, Vec<String>, Vec<String>) {
    let mut section = "";
    let mut values: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut session_bus = BTreeSet::new();
    for line in metadata.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if section == "Context" {
            values.entry(key.to_string()).or_default().extend(
                value
                    .split(';')
                    .filter(|item| !item.is_empty())
                    .map(str::to_string),
            );
        } else if section == "Session Bus Policy" {
            session_bus.insert(key.to_string());
        }
    }

    let has = |key: &str, item: &str| values.get(key).is_some_and(|set| set.contains(item));
    let filesystems = values.get("filesystems").cloned().unwrap_or_default();
    let broad_fs = filesystems.iter().any(|item| {
        matches!(
            item.split(':').next().unwrap_or_default(),
            "host" | "home" | "host-os" | "host-etc"
        )
    });
    let broad_bus = session_bus
        .iter()
        .any(|name| name == "org.freedesktop.Flatpak" || name == "*" || name.starts_with("!"));
    let x11_without_wayland =
        (has("sockets", "x11") || has("sockets", "fallback-x11")) && !has("sockets", "wayland");
    // WHICH TRIGGER FIRED DECIDES WHAT THE SURFACE MAY SAY, and collapsing them
    // into one boolean made the card wrong in both directions. Firefox's
    // filesystems are all narrow — xdg-download, a speech socket, a read-only
    // gtk config — and it trips this rule on `devices=all; features=devel;`. A
    // card that told someone Firefox "can read every file in your home
    // directory" would be false, and the design's own worked example lists
    // Firefox as the app whose row must read honestly.
    let mut host_access: Vec<String> = Vec::new();
    if broad_fs {
        host_access.push(
            "This app can read and write every file in your home directory. Its sandbox does not constrain your files."
                .to_string(),
        );
    }
    if broad_bus {
        host_access.push(
            "This app can ask the desktop to run programs outside its sandbox, which is not a boundary it stays inside."
                .to_string(),
        );
    }
    // THE UNFILTERED SESSION BUS, which app-catalog.md section 8 lists as a
    // bypass trigger and this function did not implement. It matters more than
    // the others because it silently invalidates them: `sockets=session-bus`
    // bind-mounts the REAL bus socket into the sandbox and attaches no
    // xdg-dbus-proxy, so the app's own [Session Bus Policy] block — every line
    // this card renders from it — is decorative. Without this trigger the card
    // showed a tidy list of bus permissions for an app bound by none of them.
    if has("sockets", "session-bus") {
        host_access.push(
            "This app reaches the desktop's message bus without a filter, so the desktop permissions listed for it are not enforced on it."
                .to_string(),
        );
    }
    if has("devices", "all") {
        host_access.push(
            "This app can reach every device on this machine, including cameras, microphones and USB hardware."
                .to_string(),
        );
    }
    if has("features", "devel") {
        host_access.push(
            "This app can use development interfaces that let it inspect and change other running processes."
                .to_string(),
        );
    }
    if x11_without_wayland {
        host_access.push(
            "This app draws through X11, where any window can read another window's keystrokes. Wayland's isolation does not apply."
                .to_string(),
        );
    }

    let mut permissions = Vec::new();
    if has("shared", "network") {
        permissions.push("Network access".to_string());
    }
    if has("sockets", "pulseaudio") {
        permissions.push("Audio playback".to_string());
    }
    if has("sockets", "wayland") {
        permissions.push("Wayland display".to_string());
    }
    if has("devices", "dri") {
        permissions.push("Graphics acceleration".to_string());
    }
    for item in filesystems {
        let (path, mode) = item.split_once(':').unwrap_or((&item, "read/write"));
        let access = if mode == "ro" { "read-only" } else { mode };
        permissions.push(format!("{path} files ({access})"));
    }
    // NAME THE BUS, DO NOT PARAPHRASE IT. Every entry in [Session Bus Policy]
    // used to collapse into the single string "Desktop media controls", which
    // was wrong for almost every application that has one and catastrophically
    // wrong for the one that matters most: an app declaring
    // `org.freedesktop.secrets=talk` can read and write EVERY saved password on
    // this device, and the card said it wanted media controls.
    //
    // That line is the whole of Punar's answer to "who can read my
    // credentials". The Secret Service protocol has no per-application access
    // control — anything holding the bus name reads anything unlocked — so the
    // sandbox declaration, shown before the person agrees, is the enforcement
    // point. It has to be legible.
    for name in &session_bus {
        permissions.push(match name.as_str() {
            // THE CONSEQUENCE, NOT THE PERMISSION NAME. "Your saved passwords"
            // reads as though this app is asking about its own, and it is not:
            // the Secret Service protocol has no per-application separation, so
            // one grant is a grant over every password every other application
            // has saved. A person agreeing to this is agreeing to that.
            "org.freedesktop.secrets" | "org.gnome.keyring.SystemPrompter" => {
                "Every password saved by every app on this device (read and write) — the desktop's password service has no per-app separation".to_string()
            }
            "org.freedesktop.Notifications" => "Send notifications".to_string(),
            "org.freedesktop.portal.Desktop" => "Desktop portals".to_string(),
            "org.gnome.OnlineAccounts" => "Your configured online accounts".to_string(),
            "org.a11y.Bus" => "Accessibility services".to_string(),
            "org.mpris.MediaPlayer2.*" | "org.mpris.MediaPlayer2" => {
                "Desktop media controls".to_string()
            }
            other => format!("Desktop service {other}"),
        });
    }
    // Sockets that are access, not display. None of these was rendered at all,
    // so a smartcard reader and a printer queue were invisible on a card whose
    // entire purpose is to show what an application asked for.
    if has("sockets", "pcsc") {
        permissions.push("Smartcards and security keys".to_string());
    }
    if has("sockets", "cups") {
        permissions.push("Printers".to_string());
    }
    if has("shared", "ipc") {
        permissions.push("Shared IPC with the desktop".to_string());
    }
    permissions.sort();
    permissions.dedup();
    (
        if host_access.is_empty() {
            Containment::Sandboxed
        } else {
            Containment::Bypass
        },
        permissions,
        host_access,
    )
}

fn clean_backend_error(stderr: &str) -> String {
    let one_line = stderr
        .lines()
        .next()
        .unwrap_or("unknown backend error")
        .trim();
    if one_line.is_empty() {
        "unknown backend error".to_string()
    } else {
        one_line.chars().take(240).collect()
    }
}

/// Distinguishes concurrent captures. Two installs cannot share a file, and a
/// pid alone would collide with itself across sequential calls in one process.
static BACKEND_CAPTURE_SEQ: AtomicUsize = AtomicUsize::new(0);

/// The most informative line of a backend's stderr.
///
/// [`clean_backend_error`] takes the FIRST line, which is right for the tools
/// that lead with their complaint. flatpak does not: it narrates progress and
/// puts the reason last, prefixed `error:`. Taking the first line there yields
/// a download counter.
fn backend_failure_detail(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let chosen = lines
        .iter()
        .rev()
        .find(|line| line.to_ascii_lowercase().starts_with("error:"))
        .or_else(|| lines.last())
        .copied()
        .unwrap_or_default();
    chosen.chars().take(240).collect()
}

/// Run a fixed-argv backend command, and — on failure — say what it said.
///
/// STDERR USED TO GO TO /dev/null, and the cost of that was paid by a person
/// rather than a log. An install that failed produced exactly
/// "/usr/bin/flatpak exited with exit status: 1" on the card, and punard's own
/// next-step text had to GUESS at the cause ("check network connectivity and
/// `flatpak remotes`") because the daemon had thrown away the one sentence that
/// knew. The two operations behind this function, install and uninstall, are
/// the ones most likely to fail for a reason worth reading.
///
/// A FILE AND NOT A PIPE, deliberately. This function polls `try_wait` in a
/// loop and never reads the child's output; with a pipe, a backend chatty
/// enough to fill the buffer would block on write while this loop waited for it
/// to exit, and an install would hang until the timeout instead of failing. A
/// file cannot deadlock. It is read only on failure, and bounded.
fn run_quiet_with_timeout(bin: &Path, args: &[&str], timeout: Duration) -> Result<(), AppError> {
    // A FILE AND NOT A PIPE, deliberately. The wait loop polls `try_wait` and
    // never reads the child's output; with a pipe, a backend chatty enough to
    // fill the buffer would block on write while the loop waited for it to
    // exit, so an install would hang until the timeout instead of failing. A
    // file cannot deadlock, and it is read only on failure.
    let capture_path = std::env::temp_dir().join(format!(
        "punard-backend-{}-{}.err",
        std::process::id(),
        BACKEND_CAPTURE_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let stderr_target = match File::create(&capture_path) {
        Ok(file) => Stdio::from(file),
        // A capture we cannot open must never stop the operation it was only
        // going to describe.
        Err(_) => Stdio::null(),
    };
    let capture = capture_path.exists().then_some(capture_path.as_path());

    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr_target)
        .spawn_busy_retry()
        .map_err(|e| AppError::Backend(e.to_string()))?;
    wait_quiet_child(bin, &mut child, timeout, capture)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture(metadata: &str) -> (PathBuf, PathBuf, String) {
        let dir = std::env::temp_dir().join(format!(
            "punard-apps-{}-{}",
            std::process::id(),
            crate::util::random_alnum(8).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("flatpak");
        let metadata_path = dir.join("metadata");
        fs::write(&metadata_path, metadata).unwrap();
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\nremote-add) : ;;\nremote-info) cat '{}' ;;\nlist) [ \"$4\" = '--columns=application,active' ] || {{ echo 'unexpected list columns' >&2; exit 2; }}; exit 0 ;;\ninfo) exit 1 ;;\n*) exit 1 ;;\nesac\n",
            metadata_path.display()
        );
        fs::write(&bin, script).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        (dir, bin, sha256_hex(metadata.as_bytes()))
    }

    fn write_catalog(dir: &Path, digest: &str) -> PathBuf {
        let path = dir.join("catalog.json");
        let doc = json!({
            "v": 1,
            "catalogVersion": "test",
            "generatedAt": "2026-08-27T00:00:00Z",
            "remotes": [{
                "id": "flathub",
                "repoFile": "/usr/share/punar/catalog/remotes/flathub.flatpakrepo",
                "url": "https://dl.flathub.org/repo/"
            }],
            "apps": [{
                "id": "spotify", "name": "Spotify", "icon": "spotify.svg",
                "featured": true, "category": "media",
                "keywords": ["music", "audio", "podcasts"],
                "summary": "Music", "trustTier": "community", "license": "proprietary",
                "publisher": "flathub", "bundledUpdater": "disabled-by-packaging",
                "disclosures": [],
                "sources": [{
                    "kind": "flatpak", "architectures": ["x86_64"], "remote": "flathub",
                    "appId": "com.spotify.Client", "ref": "app/com.spotify.Client/x86_64/stable",
                    "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "runtime": "org.freedesktop.Platform/x86_64/25.08", "metadataSha256": digest
                }, {
                    "kind": "web", "architectures": ["aarch64"],
                    "url": "https://open.spotify.com/", "browser": "chromium"
                }]
            }]
        });
        fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        path
    }

    #[test]
    fn live_metadata_drives_verified_containment() {
        let metadata = "[Context]\nshared=network;ipc;\nsockets=wayland;fallback-x11;pulseaudio;\ndevices=dri;\nfilesystems=xdg-music:ro;xdg-pictures:ro;\n[Session Bus Policy]\norg.mpris.MediaPlayer2.spotify=own\n";
        let (dir, bin, digest) = fixture(metadata);
        let catalog = write_catalog(&dir, &digest);
        let manager = AppManager::load(Some(&catalog), bin)
            .unwrap()
            .with_arch("x86_64");
        let result = manager.catalog(Some("spotify"), None).unwrap();
        assert_eq!(result["app"]["icon"], "spotify.svg");
        assert_eq!(result["app"]["featured"], true);
        assert_eq!(result["app"]["inspection"]["verified"], true);
        assert_eq!(result["app"]["inspection"]["containment"], "sandboxed");
        assert!(
            result["app"]["inspection"]["permissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == "Network access")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn catalog_rejects_an_icon_path_instead_of_a_local_basename() {
        let (dir, bin, digest) = fixture("unused");
        let catalog_path = write_catalog(&dir, &digest);
        let mut catalog: serde_json::Value =
            serde_json::from_slice(&fs::read(&catalog_path).unwrap()).unwrap();
        catalog["apps"][0]["icon"] = json!("../spotify.svg");
        fs::write(&catalog_path, serde_json::to_vec_pretty(&catalog).unwrap()).unwrap();

        assert!(matches!(
            AppManager::load(Some(&catalog_path), bin),
            Err(AppError::InvalidCatalog(_))
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn catalog_accepts_local_png_icons_but_not_arbitrary_formats() {
        let (dir, bin, digest) = fixture("unused");
        let catalog_path = write_catalog(&dir, &digest);
        let mut catalog: serde_json::Value =
            serde_json::from_slice(&fs::read(&catalog_path).unwrap()).unwrap();
        catalog["apps"][0]["icon"] = json!("spotify.png");
        fs::write(&catalog_path, serde_json::to_vec_pretty(&catalog).unwrap()).unwrap();
        assert!(AppManager::load(Some(&catalog_path), bin.clone()).is_ok());

        catalog["apps"][0]["icon"] = json!("spotify.webp");
        fs::write(&catalog_path, serde_json::to_vec_pretty(&catalog).unwrap()).unwrap();
        assert!(matches!(
            AppManager::load(Some(&catalog_path), bin),
            Err(AppError::InvalidCatalog(_))
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn arm_selects_web_without_invoking_flatpak() {
        let (dir, bin, digest) = fixture("unused");
        let catalog = write_catalog(&dir, &digest);
        let manager = AppManager::load(Some(&catalog), bin)
            .unwrap()
            .with_arch("aarch64");
        let result = manager.catalog(Some("spotify"), None).unwrap();
        assert_eq!(result["app"]["source"], "web");
        assert_eq!(result["app"]["action"], "open");
        assert!(result["app"].get("inspection").is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn catalog_search_matches_keywords_category_and_multiple_terms() {
        let (dir, bin, digest) = fixture("unused");
        let catalog = write_catalog(&dir, &digest);
        let manager = AppManager::load(Some(&catalog), bin)
            .unwrap()
            .with_arch("aarch64");

        for query in ["audio", "media", "spotify podcasts"] {
            let result = manager.catalog(None, Some(query)).unwrap();
            assert_eq!(result["apps"].as_array().unwrap().len(), 1, "{query}");
            assert_eq!(result["apps"][0]["id"], "spotify", "{query}");
        }
        assert!(
            manager.catalog(None, Some("spotify browser")).unwrap()["apps"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn metadata_digest_mismatch_fails_closed() {
        let (dir, bin, _digest) = fixture("[Context]\nshared=network;\n");
        let catalog = write_catalog(
            &dir,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let manager = AppManager::load(Some(&catalog), bin)
            .unwrap()
            .with_arch("x86_64");
        assert!(matches!(
            manager.catalog(Some("spotify"), None),
            Err(AppError::Verification(_))
        ));
        let _ = fs::remove_dir_all(dir);
    }

    /// THE TEST WHOSE ABSENCE SHIPPED A STORE THAT COULD NOT INSTALL.
    ///
    /// Every metadata fixture in this file was narrow — Spotify-shaped, a couple
    /// of read-only xdg directories — so nothing ever exercised the containment
    /// rule against what real Flatpaks actually declare. Measured against the
    /// live Flathub metadata for the shipped catalogue, 46 of 57 entries were
    /// refused outright: Firefox, VS Code, LibreOffice, GIMP, Wireshark, Neovim,
    /// IntelliJ and most of the rest declare `devices=all`, `features=devel` or
    /// a broad filesystem. The store listed them and could install none of them.
    #[test]
    fn a_real_world_permission_set_is_installable_once_acknowledged() {
        // Firefox's actual Context, abbreviated: note the filesystems are all
        // NARROW. It is unconfined because of devices and devel, not because it
        // can read your home — which is why the reasons are reported separately.
        let firefox = "[Context]\nshared=network;ipc;\nsockets=wayland;fallback-x11;pulseaudio;\ndevices=all;\nfeatures=devel;\nfilesystems=xdg-download;xdg-config/gtk-3.0:ro;\n";
        let (containment, _permissions, host_access) = inspect_permissions(firefox);
        assert_eq!(containment, Containment::Bypass);
        assert!(
            host_access.iter().any(|s| s.contains("every device")),
            "devices=all must be named"
        );
        assert!(
            host_access
                .iter()
                .any(|s| s.contains("development interfaces")),
            "features=devel must be named"
        );
        assert!(
            !host_access.iter().any(|s| s.contains("home directory")),
            "Firefox's filesystems are narrow; claiming it reads your home would be false"
        );
    }

    /// An application that can read every saved password must SAY so on the
    /// card, in those words.
    ///
    /// This is Evolution's real metadata, and it is the case that made the bug
    /// worth fixing: `org.freedesktop.secrets=talk` used to render as "Desktop
    /// media controls". The Secret Service protocol has no per-application
    /// access control, so this declaration — shown before a person agrees — is
    /// the entire enforcement point Punar has over who reads credentials. A
    /// wrong word here is not a cosmetic defect.
    #[test]
    fn an_app_that_can_read_every_saved_password_says_so() {
        let evolution = "[Context]\nshared=network;ipc;\nsockets=x11;wayland;pulseaudio;fallback-x11;pcsc;\ndevices=dri;\nfilesystems=~/.gnupg;\n[Session Bus Policy]\norg.freedesktop.Notifications=talk\norg.gnome.keyring.SystemPrompter=talk\norg.gnome.OnlineAccounts=talk\norg.freedesktop.secrets=talk\n";
        let (_containment, permissions, _host_access) = inspect_permissions(evolution);
        assert!(
            permissions
                .iter()
                .any(|p| p.contains("Every password saved by every app")),
            "the card must name the shared pot, not merely the permission: {permissions:?}"
        );
        assert!(
            !permissions.iter().any(|p| p == "Desktop media controls"),
            "this app asked for no media controls; claiming it did was the bug: {permissions:?}"
        );
        assert!(
            permissions.iter().any(|p| p.contains("Smartcards")),
            "sockets=pcsc was rendered nowhere at all: {permissions:?}"
        );
        assert!(
            permissions.iter().any(|p| p.contains("online accounts")),
            "org.gnome.OnlineAccounts must be named: {permissions:?}"
        );
        assert!(
            permissions.iter().any(|p| p.contains("Send notifications")),
            "org.freedesktop.Notifications must be named: {permissions:?}"
        );
    }

    /// `sockets=session-bus` invalidates every bus permission the card renders,
    /// so it has to be a bypass trigger rather than a quiet extra socket.
    ///
    /// flatpak bind-mounts the real session-bus socket for this and attaches no
    /// filtering proxy, so the app's own [Session Bus Policy] block binds
    /// nothing. Before this, such an app was drawn with a tidy list of bus
    /// permissions it was not actually held to — which is worse than showing
    /// nothing, because a list reads as a limit.
    #[test]
    fn an_unfiltered_session_bus_is_a_bypass_and_not_a_permission() {
        let unfiltered = "[Context]\nshared=network;\nsockets=wayland;session-bus;\n[Session Bus Policy]\norg.freedesktop.Notifications=talk\n";
        let (containment, _permissions, host_access) = inspect_permissions(unfiltered);
        assert_eq!(
            containment,
            Containment::Bypass,
            "an unfiltered session bus is not a sandboxed app"
        );
        assert!(
            host_access.iter().any(|s| s.contains("without a filter")),
            "the reason must be named: {host_access:?}"
        );

        // The ordinary case is unchanged: the same declaration WITHOUT the raw
        // socket stays sandboxed, so this trigger cannot quietly reclassify
        // every app that talks to the bus at all.
        let filtered = "[Context]\nshared=network;\nsockets=wayland;\n[Session Bus Policy]\norg.freedesktop.Notifications=talk\n";
        let (containment, _permissions, host_access) = inspect_permissions(filtered);
        assert_eq!(containment, Containment::Sandboxed);
        assert!(host_access.is_empty(), "{host_access:?}");
    }

    /// flatpak narrates progress and puts its reason LAST, prefixed `error:`.
    /// Taking the first line — which is right for tools that lead with their
    /// complaint — yields a download counter, so the selection has to prefer
    /// the `error:` line.
    #[test]
    fn a_backend_failure_quotes_the_line_that_explains_it() {
        let flatpak = "Looking for matches…\n                       Required runtime for org.gnome.Calendar/aarch64/stable\n                       Downloading… 12%\n                       error: Unable to load summary from remote flathub: Failed to fetch\n";
        assert_eq!(
            backend_failure_detail(flatpak),
            "error: Unable to load summary from remote flathub: Failed to fetch"
        );

        // No `error:` line: the last thing said is better than the first, which
        // in a progress-narrating tool is always noise.
        assert_eq!(
            backend_failure_detail("Looking for matches…\nsomething went wrong\n"),
            "something went wrong"
        );

        // Nothing at all is not a crash and not a fake explanation.
        assert_eq!(backend_failure_detail(""), "");
        assert_eq!(backend_failure_detail("\n  \n"), "");

        // Bounded, so a runaway backend cannot dictate the size of an error.
        let huge = format!("error: {}", "x".repeat(4096));
        assert_eq!(backend_failure_detail(&huge).chars().count(), 240);
    }

    /// The other direction: an app that really can read everything says so, and
    /// says nothing about devices it cannot touch.
    #[test]
    fn broad_filesystem_access_is_named_for_what_it_is() {
        let libreoffice =
            "[Context]\nshared=network;\nsockets=wayland;\nfilesystems=host;xdg-documents;\n";
        let (containment, _permissions, host_access) = inspect_permissions(libreoffice);
        assert_eq!(containment, Containment::Bypass);
        assert!(host_access.iter().any(|s| s.contains("home directory")));
        assert!(!host_access.iter().any(|s| s.contains("every device")));
    }

    /// A confined app asks nothing, so the card must have nothing to show.
    #[test]
    fn a_sandboxed_app_raises_no_host_access_question() {
        let narrow = "[Context]\nshared=network;\nsockets=wayland;pulseaudio;\ndevices=dri;\nfilesystems=xdg-music:ro;\n";
        let (containment, _permissions, host_access) = inspect_permissions(narrow);
        assert_eq!(containment, Containment::Sandboxed);
        assert!(host_access.is_empty());
    }

    /// The grid's "an update is waiting" hint reads an abbreviated checksum
    /// and must not mistake it for drift.
    #[test]
    fn an_abbreviated_checksum_still_recognises_its_own_pin() {
        let pin = "4b6430b6e8b6d4a6cc0714379037059eb7b6c444fedc021fd60ea145a011eedc";
        assert!(
            commit_is_pinned("4b6430b6e8b6", pin),
            "flatpak's own listing"
        );
        assert!(commit_is_pinned(pin, pin), "and the whole checksum");
        assert!(!commit_is_pinned("4b6430b6e8b7", pin), "one character out");
        // A short prefix is not evidence. Twelve characters is what flatpak
        // prints; anything shorter is refused rather than charitably matched.
        assert!(!commit_is_pinned("4b6430b6e8b", pin));
        assert!(!commit_is_pinned("", pin));
    }

    #[test]
    fn install_requires_the_displayed_digest_and_verifies_the_pinned_commit() {
        let metadata = "[Context]\nshared=network;\nsockets=wayland;\n";
        let (dir, _unused_bin, digest) = fixture(metadata);
        let metadata_path = dir.join("metadata");
        let state_path = dir.join("state");
        let argv_path = dir.join("argv");
        let bin = dir.join("stateful-flatpak");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$1\" in\nremote-info) cat '{}' ;;\nlist) [ \"$4\" = '--columns=application,active' ] || {{ echo 'unexpected list columns' >&2; exit 2; }}; if [ -f '{}' ]; then printf 'com.spotify.Client\\t%.12s\\n' \"$(cat '{}')\"; fi ;;\ninfo) [ \"$3\" = '--show-commit' ] || {{ echo 'unexpected info options' >&2; exit 2; }}; [ -f '{}' ] && cat '{}' || exit 1 ;;\nremote-add) : ;;\nupdate) for a in \"$@\"; do case \"$a\" in --commit=*) printf '%s\\n' \"${{a#--commit=}}\" > '{}' ;; esac; done ;;\ninstall) printf '%s\\n' '{}' > '{}' ;;\nuninstall) rm -f '{}' ;;\n*) exit 1 ;;\nesac\n",
            argv_path.display(),
            metadata_path.display(),
            state_path.display(),
            state_path.display(),
            state_path.display(),
            state_path.display(),
            // the `update --commit=` arm writes the commit it was given
            state_path.display(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            state_path.display(),
            state_path.display(),
        );
        fs::write(&bin, script).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let catalog = write_catalog(&dir, &digest);
        let manager = AppManager::load(Some(&catalog), bin)
            .unwrap()
            .with_arch("x86_64");

        assert!(matches!(
            manager.install(
                "spotify",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                false,
            ),
            Err(AppError::Verification(_))
        ));
        assert!(!state_path.exists(), "a stale card installed nothing");

        let installed = manager.install("spotify", &digest, false).unwrap();
        // THE REMOTE IS CONFIGURED BEFORE THE INSTALL, and this asserts it
        // through the recorded argv rather than trusting the call site. On a
        // real device /var is a separate subvolume that shadows what the image
        // build wrote, so without this every catalogue install fails before it
        // reaches the network.
        let argv = fs::read_to_string(&argv_path).unwrap();
        let remote_add_line = argv
            .lines()
            .position(|line| line.starts_with("remote-add "))
            .expect("the install path configures the remote");
        let install_line = argv
            .lines()
            .position(|line| line.starts_with("install "))
            .expect("the install ran");
        assert!(
            remote_add_line < install_line,
            "the remote must be configured BEFORE the install, got:\n{argv}"
        );
        // AND BEFORE THE INSPECTION, which is the earlier need and the one
        // that was missed. `remote-info` resolves the ref through a configured
        // remote, so on a fresh device the permission card itself failed —
        // never reaching the install whose repair would have fixed it. That
        // read as working only because a failed first attempt left the remote
        // behind for the second.
        let remote_info_line = argv
            .lines()
            .position(|line| line.starts_with("remote-info "))
            .expect("the card inspects the remote metadata");
        assert!(
            remote_add_line < remote_info_line,
            "the remote must be configured BEFORE the metadata is read, got:\n{argv}"
        );
        assert!(
            argv.lines().any(|line| line.starts_with("remote-add ")
                && line.contains("--if-not-exists")
                && line.contains("flathub.flatpakrepo")),
            "remote-add must be idempotent and use the catalogue's signed repo file:\n{argv}"
        );
        assert_eq!(installed["changed"], true);
        assert_eq!(
            fs::read_to_string(&state_path).unwrap().trim(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        let argv = fs::read_to_string(&argv_path).unwrap();
        // THIS ASSERTION USED TO PIN AN INVALID COMMAND. It required
        // `install … --or-update --commit=aaaaaaaa`, and `flatpak install` has
        // no --commit option — only `flatpak update` does. flatpak rejected the
        // whole command with "Unknown option --commit=…", so every catalogue
        // install failed on a real machine while this test passed: the double's
        // `install)` arm ignores arguments it does not recognise, exactly as a
        // stub does and the real program does not.
        //
        // So the shape is asserted as two commands, in order, and the pin is
        // asserted through the STATE the double writes from `--commit=` rather
        // than through the argv alone.
        assert!(
            argv.contains("install --system --noninteractive --or-update flathub app/"),
            "install must carry no --commit; flatpak rejects it:\n{argv}"
        );
        assert!(
            !argv
                .lines()
                .any(|line| line.starts_with("install ") && line.contains("--commit")),
            "no install line may carry --commit:\n{argv}"
        );
        assert!(
            argv.contains("update --system --noninteractive --commit=aaaaaaaa"),
            "the pinned commit is deployed by `update`, which is the verb that accepts it:\n{argv}"
        );
        let install_at = argv
            .lines()
            .position(|l| l.starts_with("install "))
            .unwrap();
        let update_at = argv.lines().position(|l| l.starts_with("update ")).unwrap();
        assert!(
            install_at < update_at,
            "the ref must exist before a commit can be deployed onto it:\n{argv}"
        );
        assert!(!argv.contains("sh -c"));

        // THE ABBREVIATION IS THE POINT OF THIS BLOCK. `flatpak list
        // --columns=…,active` ellipsizes the checksum to twelve characters
        // while the catalogue pins sixty-four, so a listing value compared to a
        // pin with `!=` is unequal even when the right bytes are deployed —
        // which is how a successful Evolution install got verified as wrong and
        // then uninstalled. The double abbreviates exactly as flatpak does, so
        // reintroducing that comparison fails the install assertions above
        // rather than passing here and failing on the person's machine.
        let listed = manager.installed_flatpaks().unwrap();
        assert_eq!(
            listed.get("com.spotify.Client").map(String::as_str),
            Some("aaaaaaaaaaaa"),
            "the listing abbreviates, as flatpak does"
        );
        assert_eq!(
            manager.installed_commit("com.spotify.Client").unwrap(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            "the pin comparison reads the whole checksum"
        );
        assert!(
            argv.lines()
                .any(|line| line.starts_with("info ") && line.contains("--show-commit")),
            "the full checksum comes from `flatpak info --show-commit`:\n{argv}"
        );

        fs::write(
            &state_path,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n",
        )
        .unwrap();
        let list = manager.list().unwrap();
        assert_eq!(list["updates_available"], 1);
        assert_eq!(list["apps"][0]["installed"], true);
        assert_eq!(list["apps"][0]["update_available"], true);
        assert_eq!(
            manager.update_candidates(None).unwrap(),
            vec!["spotify".to_string()]
        );
        let updated = manager.update("spotify").unwrap();
        assert_eq!(updated["changed"], true);
        assert_eq!(updated["status"], "updated");
        assert_eq!(
            updated["previous_commit"],
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        let current = manager.update("spotify").unwrap();
        assert_eq!(current["changed"], false);
        assert_eq!(current["status"], "current");
        let _ = fs::remove_dir_all(dir);
    }

    fn write_vendor_catalog(dir: &Path, digest: &str, byte_size: u64) -> PathBuf {
        let path = dir.join("vendor-catalog.json");
        let document = json!({
            "v": 1,
            "catalogVersion": "vendor-test",
            "generatedAt": "2026-08-29T00:00:00Z",
            "remotes": [],
            "apps": [{
                "id": "chatgpt-desktop",
                "name": "ChatGPT Desktop (preview)",
                "icon": "chatgpt.svg",
                "featured": true,
                "category": "productivity",
                "keywords": ["AI", "OpenAI", "native"],
                "summary": "Native preview",
                "trustTier": "curated",
                "license": "proprietary",
                "publisher": "upstream",
                "bundledUpdater": "disabled-by-packaging",
                "disclosures": [],
                "sources": [{
                    "kind": "vendor_deb",
                    "architectures": ["x86_64"],
                    "url": "https://persistent.oaistatic.com/codex-app-prod/linux/deb/latest/chatgpt_amd64.deb",
                    "sha256": digest,
                    "byteSize": byte_size,
                    "packageName": "chatgpt",
                    "version": "26.825.32147",
                    "dataMember": "data.tar.xz",
                    "payloadRoot": "./usr/lib/chatgpt",
                    "executable": "usr/lib/chatgpt/ChatGPT",
                    "iconPath": "./usr/share/pixmaps/chatgpt.png",
                    "desktopId": "punar-chatgpt-desktop"
                }]
            }]
        });
        fs::write(&path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
        path
    }

    fn vendor_fixture() -> (PathBuf, PathBuf, PathBuf, String, u64) {
        let dir = std::env::temp_dir().join(format!(
            "punard-vendor-apps-{}-{}",
            std::process::id(),
            crate::util::random_alnum(8).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let package = dir.join("upstream.deb");
        fs::write(&package, b"verified vendor package fixture\n").unwrap();
        let digest = sha256_file(&package).unwrap();
        let byte_size = fs::metadata(&package).unwrap().len();
        let data = dir.join("fixture-data.tar.xz");
        fs::write(&data, b"fixture data archive\n").unwrap();
        let control = dir.join("fixture-control");
        fs::write(
            &control,
            b"Package: chatgpt\nVersion: 26.825.32147\nArchitecture: amd64\nDescription: fixture\n",
        )
        .unwrap();
        let curl_log = dir.join("curl-argv");

        let curl = dir.join("curl");
        fs::write(
            &curl,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\nout=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = '--output' ]; then shift; out=$1; fi\n  shift\ndone\ncp '{}' \"$out\"\n",
                curl_log.display(),
                package.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();

        let bsdtar = dir.join("bsdtar");
        fs::write(
            &bsdtar,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  -tf)\n    case \"$2\" in\n      *package.deb) printf 'debian-binary\\ncontrol.tar.xz\\ndata.tar.xz\\n' ;;\n      *control.tar.xz) printf './control\\n./postinst\\n' ;;\n      *) printf './usr/lib/chatgpt/\\n./usr/lib/chatgpt/ChatGPT\\n./usr/lib/chatgpt/chrome-sandbox\\n./usr/share/pixmaps/chatgpt.png\\n' ;;\n    esac ;;\n  -xOf)\n    case \"$2:$3\" in\n      *control.tar.xz:./control) cat '{}' ;;\n      *:control.tar.xz) printf 'control archive fixture\\n' ;;\n      *) cat '{}' ;;\n    esac ;;\n  -xf)\n    while [ \"$1\" != '-C' ]; do shift; done\n    shift; dest=$1\n    mkdir -p \"$dest/usr/lib/chatgpt\" \"$dest/usr/share/pixmaps\"\n    printf '#!/bin/sh\\nexit 0\\n' > \"$dest/usr/lib/chatgpt/ChatGPT\"\n    chmod 0755 \"$dest/usr/lib/chatgpt/ChatGPT\"\n    printf 'sandbox' > \"$dest/usr/lib/chatgpt/chrome-sandbox\"\n    chmod 4755 \"$dest/usr/lib/chatgpt/chrome-sandbox\"\n    printf 'png' > \"$dest/usr/share/pixmaps/chatgpt.png\" ;;\n  *) exit 2 ;;\nesac\n",
                control.display(),
                data.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&bsdtar, fs::Permissions::from_mode(0o755)).unwrap();
        (dir, curl, bsdtar, digest, byte_size)
    }

    #[test]
    fn archive_root_member_is_safe_but_traversal_is_not() {
        assert!(safe_archive_member("."));
        assert!(safe_archive_member("./"));
        assert!(safe_archive_member("./usr/lib/app"));
        for unsafe_member in [
            "",
            "/",
            "../escape",
            "./../../escape",
            "usr/../../../escape",
        ] {
            assert!(!safe_archive_member(unsafe_member), "{unsafe_member:?}");
        }
    }

    #[test]
    fn vendor_package_install_is_digest_pinned_scriptless_and_drops_setuid() {
        let (dir, curl, bsdtar, digest, byte_size) = vendor_fixture();
        let catalog = write_vendor_catalog(&dir, &digest, byte_size);
        let vendor_root = dir.join("installed");
        let desktop_dir = dir.join("share/applications");
        let config_dir = dir.join("config");
        let manager = AppManager::load(Some(&catalog), PathBuf::from("/bin/false"))
            .unwrap()
            .with_arch("x86_64")
            .with_vendor_paths(
                curl,
                bsdtar,
                vendor_root.clone(),
                desktop_dir.clone(),
                config_dir.clone(),
            );

        let detail = manager.catalog(Some("chatgpt-desktop"), None).unwrap();
        assert_eq!(detail["app"]["source"], "vendor_deb");
        assert_eq!(detail["app"]["inspection"]["pinned"], true);
        assert_eq!(
            detail["app"]["inspection"]["containment"],
            "hardened_native"
        );
        assert!(!detail["app"]["installed"].as_bool().unwrap());

        assert!(matches!(
            manager.install(
                "chatgpt-desktop",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                false,
            ),
            Err(AppError::Verification(_))
        ));
        assert!(!dir.join("curl-argv").exists());

        let installed = manager.install("chatgpt-desktop", &digest, false).unwrap();
        assert_eq!(installed["changed"], true);
        let root = vendor_root.join("chatgpt-desktop/current");
        assert!(root.join("usr/lib/chatgpt/ChatGPT").is_file());
        assert_eq!(
            fs::metadata(root.join("usr/lib/chatgpt/chrome-sandbox"))
                .unwrap()
                .permissions()
                .mode()
                & 0o6000,
            0,
            "vendor setuid/setgid bits must never survive extraction"
        );
        let manifest = fs::read_to_string(root.join("install.json")).unwrap();
        assert!(manifest.contains("\"maintainer_scripts_executed\": false"));
        let desktop =
            fs::read_to_string(desktop_dir.join("punar-chatgpt-desktop.desktop")).unwrap();
        assert!(desktop.contains("Exec=punarctl app open chatgpt-desktop"));
        let argv = fs::read_to_string(dir.join("curl-argv")).unwrap();
        assert!(argv.contains("--proto =https"));
        assert!(!argv.contains("sh -c"));

        let unchanged = manager.install("chatgpt-desktop", &digest, false).unwrap();
        assert_eq!(unchanged["changed"], false);
        let removed = manager.remove("chatgpt-desktop").unwrap();
        assert_eq!(removed["changed"], true);
        assert!(!vendor_root.join("chatgpt-desktop").exists());
        assert!(!desktop_dir.join("punar-chatgpt-desktop.desktop").exists());
        assert!(!config_dir.join("mimeapps.list").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn vendor_custom_uri_scheme_is_registered_only_while_installed() {
        let (dir, curl, bsdtar, digest, byte_size) = vendor_fixture();
        let catalog = write_vendor_catalog(&dir, &digest, byte_size);
        let mut document: Value = serde_json::from_slice(&fs::read(&catalog).unwrap()).unwrap();
        document["apps"][0]["uriSchemes"] = json!(["claude"]);
        document["apps"][0]["windowAppIds"] = json!(["com.anthropic.Claude"]);
        fs::write(&catalog, serde_json::to_vec_pretty(&document).unwrap()).unwrap();

        let vendor_root = dir.join("installed");
        let desktop_dir = dir.join("share/applications");
        let config_dir = dir.join("config");
        let manager = AppManager::load(Some(&catalog), PathBuf::from("/bin/false"))
            .unwrap()
            .with_arch("x86_64")
            .with_vendor_paths(
                curl,
                bsdtar,
                vendor_root,
                desktop_dir.clone(),
                config_dir.clone(),
            );

        manager.install("chatgpt-desktop", &digest, false).unwrap();
        let desktop =
            fs::read_to_string(desktop_dir.join("punar-chatgpt-desktop.desktop")).unwrap();
        assert!(desktop.contains("Exec=punarctl app open chatgpt-desktop %U"));
        assert!(desktop.contains("MimeType=x-scheme-handler/claude;"));
        assert!(desktop.contains("StartupWMClass=com.anthropic.Claude"));
        let defaults = fs::read_to_string(config_dir.join("mimeapps.list")).unwrap();
        assert!(defaults.contains("x-scheme-handler/claude=punar-chatgpt-desktop.desktop"));
        let cache = fs::read_to_string(desktop_dir.join("mimeinfo.cache")).unwrap();
        assert!(cache.contains("x-scheme-handler/claude=punar-chatgpt-desktop.desktop;"));

        manager.remove("chatgpt-desktop").unwrap();
        assert!(!config_dir.join("mimeapps.list").exists());
        assert!(!desktop_dir.join("mimeinfo.cache").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn catalog_rejects_reserved_or_nonvendor_uri_handlers() {
        let (dir, _curl, _bsdtar, digest, byte_size) = vendor_fixture();
        let catalog = write_vendor_catalog(&dir, &digest, byte_size);
        let original: Value = serde_json::from_slice(&fs::read(&catalog).unwrap()).unwrap();

        let mut reserved = original.clone();
        reserved["apps"][0]["uriSchemes"] = json!(["https"]);
        fs::write(&catalog, serde_json::to_vec_pretty(&reserved).unwrap()).unwrap();
        assert!(matches!(
            AppManager::load(Some(&catalog), PathBuf::from("/bin/false")),
            Err(AppError::InvalidCatalog(_))
        ));

        let mut web = original;
        web["apps"][0]["uriSchemes"] = json!(["claude"]);
        web["apps"][0]["sources"] = json!([{
            "kind": "web",
            "architectures": ["x86_64"],
            "url": "https://claude.ai/",
            "browser": "chromium"
        }]);
        fs::write(&catalog, serde_json::to_vec_pretty(&web).unwrap()).unwrap();
        assert!(matches!(
            AppManager::load(Some(&catalog), PathBuf::from("/bin/false")),
            Err(AppError::InvalidCatalog(_))
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn vendor_catalog_refuses_arbitrary_origins_and_escaping_paths() {
        let (dir, _curl, _bsdtar, digest, byte_size) = vendor_fixture();
        let catalog_path = write_vendor_catalog(&dir, &digest, byte_size);
        let mut catalog: Value = serde_json::from_slice(&fs::read(&catalog_path).unwrap()).unwrap();
        catalog["apps"][0]["sources"][0]["url"] = json!("https://example.test/app.deb");
        catalog["apps"][0]["sources"][0]["executable"] = json!("../../usr/lib/chatgpt/ChatGPT");
        fs::write(&catalog_path, serde_json::to_vec_pretty(&catalog).unwrap()).unwrap();
        assert!(matches!(
            AppManager::load(Some(&catalog_path), PathBuf::from("/bin/false")),
            Err(AppError::InvalidCatalog(_))
        ));
        let _ = fs::remove_dir_all(dir);
    }
}
