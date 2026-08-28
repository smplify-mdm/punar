//! Typed application catalog and Flatpak installer.
//!
//! Application installation is privileged, but it is not generic execution:
//! callers name a catalog id, this module selects a build-time source for the
//! observed architecture, and every subprocess receives a fixed argv derived
//! only from the validated catalog. Flatpak metadata is re-read at the pinned
//! commit before installation; its digest and permissions are never copied
//! into UI code.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::util::{run_with_timeout, sha256_hex};

const INSPECT_TIMEOUT: Duration = Duration::from_secs(30);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const REMOVE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

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
}

impl Source {
    fn architectures(&self) -> &[String] {
        match self {
            Source::Flatpak { architectures, .. } | Source::Web { architectures, .. } => {
                architectures
            }
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
            arch: arch.to_string(),
        })
    }

    #[cfg(test)]
    fn with_arch(mut self, arch: &str) -> Self {
        self.arch = arch.to_string();
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
        let apps: Vec<Value> = self
            .catalog
            .apps
            .iter()
            .filter_map(|app| {
                let source = self.select_source(app).ok()?;
                let (installed_now, commit) = match source {
                    Source::Flatpak { app_id, .. } => installed
                        .get(app_id)
                        .map_or((false, Value::Null), |c| (true, json!(c))),
                    Source::Web { .. } => (false, Value::Null),
                };
                Some(json!({
                    "id": app.id,
                    "name": app.name,
                    "source": source_kind(source),
                    "installed": installed_now,
                    "installed_commit": commit,
                }))
            })
            .collect();
        Ok(json!({ "architecture": self.arch, "apps": apps }))
    }

    /// Install the exact Flatpak commit whose metadata the caller saw.
    pub fn install(&self, id: &str, confirmed_digest: &str) -> Result<Value, AppError> {
        let app = self.app(id)?;
        let source = self.select_source(app)?;
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
                Source::Web { .. } => 1,
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
        }
        Ok(detail)
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
    }
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
            }
        }
    }
    Ok(())
}

fn is_safe_icon_basename(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let Some(stem) = value.strip_suffix(".svg") else {
        return false;
    };
    !stem.is_empty()
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
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
}
