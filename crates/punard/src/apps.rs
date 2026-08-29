//! Typed application catalog and application installer.
//!
//! Application installation is privileged, but it is not generic execution:
//! callers name a catalog id, this module selects a build-time source for the
//! observed architecture, and every subprocess receives a fixed argv derived
//! only from the validated catalog. Flatpak metadata is re-read at the pinned
//! commit before installation. Vendor Debian packages are downloaded only on
//! demand, verified against a digest promoted in the signed catalog, and only
//! their data archive is extracted: maintainer scripts are never executed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::util::{run_with_timeout, sha256_hex};

const INSPECT_TIMEOUT: Duration = Duration::from_secs(30);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const REMOVE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
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
            vendor_desktop_dir: PathBuf::from("/var/lib/punar-applications"),
            arch: arch.to_string(),
        })
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
    ) -> Self {
        self.curl_bin = curl_bin;
        self.bsdtar_bin = bsdtar_bin;
        self.vendor_root = vendor_root;
        self.vendor_desktop_dir = desktop_dir;
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
            let (installed_now, commit) = match source {
                Source::Flatpak { app_id, .. } => installed
                    .get(app_id)
                    .map_or((false, Value::Null), |c| (true, json!(c))),
                Source::VendorDeb { .. } => {
                    let digest = self.installed_vendor_digest(&app.id)?;
                    (digest.is_some(), digest.map_or(Value::Null, Value::String))
                }
                Source::Web { .. } => (false, Value::Null),
            };
            apps.push(json!({
                "id": app.id,
                "name": app.name,
                "source": source_kind(source),
                "installed": installed_now,
                "installed_commit": commit,
            }));
        }
        Ok(json!({ "architecture": self.arch, "apps": apps }))
    }

    /// Install the exact package identity whose metadata the caller saw.
    pub fn install(&self, id: &str, confirmed_digest: &str) -> Result<Value, AppError> {
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
        if inspection.containment == Containment::Bypass {
            return Err(AppError::Policy(
                "the verified package metadata requests broad host access and this build has no separate bypass-consent gate".to_string(),
            ));
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

        let commit_arg = format!("--commit={commit}");
        run_quiet_with_timeout(
            &self.flatpak_bin,
            &[
                "install",
                "--system",
                "--noninteractive",
                "--or-update",
                &commit_arg,
                remote,
                r#ref,
            ],
            INSTALL_TIMEOUT,
        )?;
        let observed = self.installed_commit(app_id)?;
        if observed.as_deref() != Some(commit.as_str()) {
            return Err(AppError::Verification(format!(
                "Flatpak reported success, but {app_id} is at {:?} instead of the pinned commit",
                observed
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
            desktop_id,
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

            let members = archive_list(&self.bsdtar_bin, &package, INSPECT_TIMEOUT)?;
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
                INSPECT_TIMEOUT,
            )?;
            let payload_members = archive_list(&self.bsdtar_bin, &data_archive, INSPECT_TIMEOUT)?;
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

            let icon = version_dir.join(icon_path);
            let desktop = vendor_desktop_entry(app, desktop_id, &icon);
            crate::util::write_atomic_synced(
                &self
                    .vendor_desktop_dir
                    .join(format!("{desktop_id}.desktop")),
                desktop.as_bytes(),
                0o644,
            )
            .map_err(backend_io)?;
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
        let desktop = self
            .vendor_desktop_dir
            .join(format!("punar-{}.desktop", app.id));
        let existed = app_dir.exists() || desktop.exists();
        if app_dir.exists() {
            fs::remove_dir_all(&app_dir).map_err(backend_io)?;
        }
        crate::util::remove_synced(&desktop).map_err(backend_io)?;
        Ok(json!({
            "id": app.id,
            "name": app.name,
            "installed": false,
            "changed": existed,
        }))
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
        let (containment, permissions) = inspect_permissions(&result.stdout);
        Ok(Inspection {
            verified: true,
            commit: commit.clone(),
            runtime: runtime.clone(),
            metadata_sha256: observed_digest,
            containment,
            permissions,
        })
    }

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

    fn installed_commit(&self, app_id: &str) -> Result<Option<String>, AppError> {
        Ok(self.installed_flatpaks()?.remove(app_id))
    }
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
        .spawn()
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
        .spawn()
        .map_err(backend_io)?;
    wait_quiet_child(bin, &mut child, timeout)
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
        .spawn()
        .map_err(backend_io)?;
    wait_quiet_child(bin, &mut child, timeout)
}

fn wait_quiet_child(
    bin: &Path,
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<(), AppError> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(AppError::Backend(format!(
                    "{} exited with {status}",
                    bin.display()
                )));
            }
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(AppError::Backend(format!(
                    "{} timed out after {timeout:?}",
                    bin.display()
                )));
            }
            Err(error) => return Err(backend_io(error)),
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
    normalize_archive_path(value).is_some()
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
    format!(
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName={}\nComment={}\nExec=punarctl app open {}\nIcon={}\nTerminal=false\nCategories={};\nStartupNotify=true\nStartupWMClass={}\n",
        app.name,
        app.summary,
        app.id,
        icon.display(),
        category,
        desktop_id,
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

fn inspect_permissions(metadata: &str) -> (Containment, Vec<String>) {
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
    let bypass = broad_fs
        || broad_bus
        || has("devices", "all")
        || has("features", "devel")
        || x11_without_wayland;

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
    if !session_bus.is_empty() {
        permissions.push("Desktop media controls".to_string());
    }
    permissions.sort();
    permissions.dedup();
    (
        if bypass {
            Containment::Bypass
        } else {
            Containment::Sandboxed
        },
        permissions,
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

fn run_quiet_with_timeout(bin: &Path, args: &[&str], timeout: Duration) -> Result<(), AppError> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| AppError::Backend(e.to_string()))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(AppError::Backend(format!(
                    "{} exited with {status}",
                    bin.display()
                )));
            }
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(AppError::Backend(format!(
                    "{} timed out after {timeout:?}",
                    bin.display()
                )));
            }
            Err(e) => return Err(AppError::Backend(e.to_string())),
        }
    }
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
            "#!/bin/sh\ncase \"$1\" in\nremote-info) cat '{}' ;;\nlist) [ \"$4\" = '--columns=application,active' ] || {{ echo 'unexpected list columns' >&2; exit 2; }}; exit 0 ;;\ninfo) exit 1 ;;\n*) exit 1 ;;\nesac\n",
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

    #[test]
    fn install_requires_the_displayed_digest_and_verifies_the_pinned_commit() {
        let metadata = "[Context]\nshared=network;\nsockets=wayland;\n";
        let (dir, _unused_bin, digest) = fixture(metadata);
        let metadata_path = dir.join("metadata");
        let state_path = dir.join("state");
        let argv_path = dir.join("argv");
        let bin = dir.join("stateful-flatpak");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$1\" in\nremote-info) cat '{}' ;;\nlist) [ \"$4\" = '--columns=application,active' ] || {{ echo 'unexpected list columns' >&2; exit 2; }}; if [ -f '{}' ]; then printf 'com.spotify.Client\\t%s\\n' \"$(cat '{}')\"; fi ;;\ninfo) [ -f '{}' ] && cat '{}' || exit 1 ;;\ninstall) printf '%s\\n' '{}' > '{}' ;;\nuninstall) rm -f '{}' ;;\n*) exit 1 ;;\nesac\n",
            argv_path.display(),
            metadata_path.display(),
            state_path.display(),
            state_path.display(),
            state_path.display(),
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
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ),
            Err(AppError::Verification(_))
        ));
        assert!(!state_path.exists(), "a stale card installed nothing");

        let installed = manager.install("spotify", &digest).unwrap();
        assert_eq!(installed["changed"], true);
        assert_eq!(
            fs::read_to_string(&state_path).unwrap().trim(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        let argv = fs::read_to_string(&argv_path).unwrap();
        assert!(argv.contains("install --system --noninteractive --or-update --commit=aaaaaaaa"));
        assert!(!argv.contains("sh -c"));
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
    fn vendor_package_install_is_digest_pinned_scriptless_and_drops_setuid() {
        let (dir, curl, bsdtar, digest, byte_size) = vendor_fixture();
        let catalog = write_vendor_catalog(&dir, &digest, byte_size);
        let vendor_root = dir.join("installed");
        let desktop_dir = dir.join("applications");
        let manager = AppManager::load(Some(&catalog), PathBuf::from("/bin/false"))
            .unwrap()
            .with_arch("x86_64")
            .with_vendor_paths(curl, bsdtar, vendor_root.clone(), desktop_dir.clone());

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
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ),
            Err(AppError::Verification(_))
        ));
        assert!(!dir.join("curl-argv").exists());

        let installed = manager.install("chatgpt-desktop", &digest).unwrap();
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

        let unchanged = manager.install("chatgpt-desktop", &digest).unwrap();
        assert_eq!(unchanged["changed"], false);
        let removed = manager.remove("chatgpt-desktop").unwrap();
        assert_eq!(removed["changed"], true);
        assert!(!vendor_root.join("chatgpt-desktop").exists());
        assert!(!desktop_dir.join("punar-chatgpt-desktop.desktop").exists());
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
