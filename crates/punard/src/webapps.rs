//! Root-owned inventory for user-created web apps and browser contexts.
//!
//! The daemon stores only typed records. User-home launchers, icons and
//! Chromium profile directories are derived artifacts returned to
//! `punarctl`, which materializes them as the connected user. No method in
//! this module executes Chromium or accepts a command line.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use punar_common::time::utc_now_rfc3339;
use punar_common::webapp::{
    BrowserContext, MAX_ICON_BYTES, WebAppArtifacts, WebAppEnforcement, WebAppIcon, WebAppIconKind,
    WebAppIconRequest, WebAppInstallResult, WebAppInstallSource, WebAppInstalledBy, WebAppManifest,
    WebAppRecord, origin_from_start_url, personal_context, render_monogram_png,
    validate_context_id, validate_display_name, validate_id, validate_manifest,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::util::{remove_synced, write_atomic_synced};

const DIR_MODE: u32 = 0o700;
const RECORD_MODE: u32 = 0o600;
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

#[derive(Debug, Error)]
pub enum WebAppError {
    #[error("invalid web application: {0}")]
    Invalid(String),
    #[error("web application or browser context was not found: {0}")]
    NotFound(String),
    #[error("web application or browser context conflicts with existing state: {0}")]
    Conflict(String),
    #[error("browser context cannot be changed: {0}")]
    Denied(String),
    #[error("web application state could not be persisted: {0}")]
    Io(#[from] io::Error),
}

/// Files returned with one record. `artifacts` is omitted unless the caller
/// explicitly asked for it, keeping ordinary inventory responses compact.
#[derive(Debug, Clone, Serialize)]
pub struct WebAppView {
    #[serde(flatten)]
    pub app: WebAppRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<WebAppArtifacts>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebAppsLocalList {
    pub apps: Vec<WebAppView>,
    pub contexts: Vec<BrowserContext>,
}

#[derive(Clone)]
pub struct WebAppManager {
    root: PathBuf,
    trusted_fixture_root: PathBuf,
}

impl WebAppManager {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            trusted_fixture_root: PathBuf::from("/usr/share/punar/fixtures/webapps"),
        }
    }

    #[cfg(test)]
    fn with_fixture_root(mut self, root: PathBuf) -> Self {
        self.trusted_fixture_root = root;
        self
    }

    pub fn list(&self, uid: u32, include_artifacts: bool) -> Result<WebAppsLocalList, WebAppError> {
        self.ensure_personal(uid)?;
        let mut apps = Vec::new();
        for path in json_files(&self.apps_dir(uid))? {
            let app: WebAppRecord = read_record(&path)?;
            validate_stored_record(&app)?;
            let artifacts = if include_artifacts {
                Some(self.artifacts_for(uid, &app)?)
            } else {
                None
            };
            apps.push(WebAppView { app, artifacts });
        }
        apps.sort_by(|a, b| a.app.id.cmp(&b.app.id));

        let mut contexts = Vec::new();
        for path in json_files(&self.contexts_dir(uid))? {
            let context: BrowserContext = read_record(&path)?;
            validate_stored_context(&context)?;
            contexts.push(context);
        }
        contexts.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(WebAppsLocalList { apps, contexts })
    }

    pub fn get(
        &self,
        uid: u32,
        id: &str,
        include_artifacts: bool,
    ) -> Result<WebAppView, WebAppError> {
        validate_id(id, "web-app id").map_err(WebAppError::Invalid)?;
        self.ensure_personal(uid)?;
        let app: WebAppRecord = read_record(&self.app_path(uid, id)).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                WebAppError::NotFound(id.to_string())
            } else {
                WebAppError::Io(error)
            }
        })?;
        validate_stored_record(&app)?;
        let artifacts = if include_artifacts {
            Some(self.artifacts_for(uid, &app)?)
        } else {
            None
        };
        Ok(WebAppView { app, artifacts })
    }

    pub fn install(
        &self,
        uid: u32,
        manifest: &WebAppManifest,
        policy_ids: Vec<String>,
        managed: bool,
        policy_file_managed: bool,
        derived_context: bool,
    ) -> Result<WebAppInstallResult, WebAppError> {
        validate_manifest(manifest).map_err(WebAppError::Invalid)?;
        self.ensure_personal(uid)?;
        if !self.context_path(uid, &manifest.context).exists() && !derived_context {
            return Err(WebAppError::NotFound(format!(
                "browser context {:?}",
                manifest.context
            )));
        }
        let path = self.app_path(uid, &manifest.id);
        let existing = if path.exists() {
            let existing: WebAppRecord = read_record(&path)?;
            validate_stored_record(&existing)?;
            if !managed {
                return Err(WebAppError::Conflict(format!(
                    "web app {:?} is already installed",
                    manifest.id
                )));
            }
            if !record_matches_manifest(&existing, manifest) {
                return Err(WebAppError::Conflict(format!(
                    "web app {:?} is already installed with a different identity",
                    manifest.id
                )));
            }
            Some(existing)
        } else {
            None
        };

        let origin = origin_from_start_url(&manifest.start_url).map_err(WebAppError::Invalid)?;
        let (kind, icon_png) = match &manifest.icon {
            WebAppIconRequest::Generated => (
                WebAppIconKind::Generated,
                render_monogram_png(&manifest.name, &origin),
            ),
            WebAppIconRequest::File { path } => (
                WebAppIconKind::File,
                self.read_caller_icon(uid, Path::new(path))?,
            ),
        };
        let icon_path_rel = format!(
            "icons/hicolor/256x256/apps/punar-webapp-{}.png",
            manifest.id
        );
        let icon_sha256 = sha256_hex(&icon_png);
        let app = WebAppRecord {
            v: manifest.v,
            id: manifest.id.clone(),
            name: manifest.name.clone(),
            start_url: manifest.start_url.clone(),
            origin,
            context: manifest.context.clone(),
            icon: WebAppIcon {
                kind,
                sha256: icon_sha256.clone(),
                path_rel: icon_path_rel.clone(),
            },
            workspace: manifest.workspace.clone(),
            installed_at: existing
                .as_ref()
                .map(|record| record.installed_at.clone())
                .unwrap_or_else(utc_now_rfc3339),
            installed_by: WebAppInstalledBy {
                uid,
                source: if managed {
                    WebAppInstallSource::Policy
                } else {
                    WebAppInstallSource::Cli
                },
            },
            policy_ids,
            managed,
        };
        validate_stored_record(&app)?;
        create_private_dir(&self.icons_dir(uid))?;
        write_atomic_synced(
            &self.icon_blob_path(uid, &icon_sha256),
            &icon_png,
            RECORD_MODE,
        )?;
        write_json(&path, &app)?;
        if let Some(previous) = existing
            && previous.icon.sha256 != icon_sha256
        {
            let previous_still_used = self
                .list(uid, false)?
                .apps
                .iter()
                .any(|candidate| candidate.app.icon.sha256 == previous.icon.sha256);
            if !previous_still_used {
                remove_synced(&self.icon_blob_path(uid, &previous.icon.sha256))?;
            }
        }
        let artifacts = self.artifacts_for_bytes(&app, &icon_png);
        Ok(WebAppInstallResult {
            app,
            artifacts,
            enforcement: WebAppEnforcement {
                point: "policy_file".into(),
                managed: policy_file_managed,
                note: if policy_file_managed {
                    "Chromium enforces the root-owned managed policy file.".into()
                } else {
                    "This check is advisory on an unmanaged device.".into()
                },
            },
        })
    }

    pub fn uninstall(&self, uid: u32, id: &str, purge_data: bool) -> Result<Value, WebAppError> {
        let view = self.get(uid, id, false)?;
        remove_synced(&self.app_path(uid, id))?;
        let icon_digest = view.app.icon.sha256.clone();
        let icon_still_used = self
            .list(uid, false)?
            .apps
            .iter()
            .any(|candidate| candidate.app.icon.sha256 == icon_digest);
        if !icon_still_used {
            remove_synced(&self.icon_blob_path(uid, &icon_digest))?;
        }
        let profile_path_rel = format!("punar/browser/contexts/{}", view.app.context);
        if purge_data && view.app.context != "personal" {
            let still_used = self
                .list(uid, false)?
                .apps
                .iter()
                .any(|candidate| candidate.app.context == view.app.context);
            if !still_used {
                remove_synced(&self.context_path(uid, &view.app.context))?;
                return Ok(json!({
                    "removed": view.app,
                    "purged": {"profile_path_rel": profile_path_rel}
                }));
            }
        }
        Ok(json!({
            "removed": view.app,
            "kept": {"profile_path_rel": profile_path_rel, "reason": "shared"}
        }))
    }

    pub fn context_create(
        &self,
        uid: u32,
        id: &str,
        name: &str,
    ) -> Result<BrowserContext, WebAppError> {
        validate_context_id(id).map_err(WebAppError::Invalid)?;
        validate_display_name(name, "browser context name").map_err(WebAppError::Invalid)?;
        if id == "personal" || id.starts_with("org-") {
            return Err(WebAppError::Invalid(
                "personal and org-* browser context ids are reserved".into(),
            ));
        }
        self.ensure_personal(uid)?;
        let path = self.context_path(uid, id);
        if path.exists() {
            return Err(WebAppError::Conflict(format!(
                "browser context {id:?} already exists"
            )));
        }
        let context = context_record(id, name, true);
        write_json(&path, &context)?;
        Ok(context)
    }

    pub fn context_delete(
        &self,
        uid: u32,
        id: &str,
        purge_data: bool,
    ) -> Result<Value, WebAppError> {
        validate_context_id(id).map_err(WebAppError::Invalid)?;
        if id == "personal" {
            return Err(WebAppError::Denied(
                "the personal browser context always exists".into(),
            ));
        }
        if id.starts_with("org-") {
            return Err(WebAppError::Denied(
                "organization contexts are derived from enrollment; unenroll to remove one".into(),
            ));
        }
        self.ensure_personal(uid)?;
        let path = self.context_path(uid, id);
        let context: BrowserContext = read_record(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                WebAppError::NotFound(id.to_string())
            } else {
                WebAppError::Io(error)
            }
        })?;
        let referencing: Vec<String> = self
            .list(uid, false)?
            .apps
            .into_iter()
            .filter(|app| app.app.context == id)
            .map(|app| app.app.id)
            .collect();
        if !referencing.is_empty() {
            return Err(WebAppError::Conflict(format!(
                "browser context {id:?} is still used by {}",
                referencing.join(", ")
            )));
        }
        remove_synced(&path)?;
        Ok(json!({
            "context": context,
            "purge_data": purge_data,
            "profile_path_rel": format!("punar/browser/contexts/{id}")
        }))
    }

    fn ensure_personal(&self, uid: u32) -> Result<(), WebAppError> {
        create_private_dir(&self.apps_dir(uid))?;
        create_private_dir(&self.contexts_dir(uid))?;
        create_private_dir(&self.icons_dir(uid))?;
        let path = self.context_path(uid, "personal");
        if !path.exists() {
            write_json(&path, &personal_context())?;
        }
        Ok(())
    }

    fn artifacts_for(&self, uid: u32, app: &WebAppRecord) -> Result<WebAppArtifacts, WebAppError> {
        let icon = fs::read(self.icon_blob_path(uid, &app.icon.sha256))?;
        if sha256_hex(&icon) != app.icon.sha256 {
            return Err(WebAppError::Invalid(
                "stored icon bytes do not match the inventory digest".into(),
            ));
        }
        Ok(self.artifacts_for_bytes(app, &icon))
    }

    fn artifacts_for_bytes(&self, app: &WebAppRecord, icon: &[u8]) -> WebAppArtifacts {
        WebAppArtifacts {
            desktop_entry: desktop_entry(app),
            desktop_path_rel: format!("applications/punar-webapp-{}.desktop", app.id),
            icon_png_b64: base64_encode(icon),
            icon_path_rel: app.icon.path_rel.clone(),
            window_rule: format!(
                "windowrule = match:class ^(punar-webapp-{})$, workspace name:{}",
                app.id, app.workspace
            ),
        }
    }

    fn read_caller_icon(&self, uid: u32, path: &Path) -> Result<Vec<u8>, WebAppError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(|error| WebAppError::Invalid(format!("icon could not be opened: {error}")))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_ICON_BYTES {
            return Err(WebAppError::Invalid(format!(
                "icon must be a regular PNG no larger than {MAX_ICON_BYTES} bytes"
            )));
        }
        let opened_path = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .unwrap_or_else(|_| path.to_path_buf());
        let trusted_fixture = opened_path.starts_with(&self.trusted_fixture_root);
        if metadata.uid() != uid && !(metadata.uid() == 0 && trusted_fixture) {
            return Err(WebAppError::Invalid(
                "icon must be owned by the caller or come from Punar's signed fixture tree".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.by_ref()
            .take(MAX_ICON_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_ICON_BYTES {
            return Err(WebAppError::Invalid(format!(
                "icon must be no larger than {MAX_ICON_BYTES} bytes"
            )));
        }
        let (width, height) = validate_png(&bytes).map_err(WebAppError::Invalid)?;
        if width == 0 || height == 0 || width > 1024 || height > 1024 {
            return Err(WebAppError::Invalid(
                "icon dimensions must be between 1 and 1024 pixels".into(),
            ));
        }
        Ok(bytes)
    }

    fn uid_dir(&self, uid: u32) -> PathBuf {
        self.root.join(uid.to_string())
    }

    fn apps_dir(&self, uid: u32) -> PathBuf {
        self.uid_dir(uid).join("apps")
    }

    fn contexts_dir(&self, uid: u32) -> PathBuf {
        self.uid_dir(uid).join("contexts")
    }

    fn icons_dir(&self, uid: u32) -> PathBuf {
        self.uid_dir(uid).join("icons")
    }

    fn app_path(&self, uid: u32, id: &str) -> PathBuf {
        self.apps_dir(uid).join(format!("{id}.json"))
    }

    fn context_path(&self, uid: u32, id: &str) -> PathBuf {
        self.contexts_dir(uid).join(format!("{id}.json"))
    }

    fn icon_blob_path(&self, uid: u32, digest: &str) -> PathBuf {
        self.icons_dir(uid).join(format!("{digest}.png"))
    }
}

fn validate_stored_record(record: &WebAppRecord) -> Result<(), WebAppError> {
    let manifest = WebAppManifest {
        v: record.v,
        id: record.id.clone(),
        name: record.name.clone(),
        start_url: record.start_url.clone(),
        context: record.context.clone(),
        workspace: record.workspace.clone(),
        icon: WebAppIconRequest::Generated,
    };
    validate_manifest(&manifest).map_err(WebAppError::Invalid)?;
    if origin_from_start_url(&record.start_url).map_err(WebAppError::Invalid)? != record.origin {
        return Err(WebAppError::Invalid(
            "stored origin does not match the start URL".into(),
        ));
    }
    if record.icon.sha256.len() != 64
        || !record
            .icon
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(WebAppError::Invalid("stored icon digest is invalid".into()));
    }
    Ok(())
}

fn record_matches_manifest(record: &WebAppRecord, manifest: &WebAppManifest) -> bool {
    record.v == manifest.v
        && record.id == manifest.id
        && record.name == manifest.name
        && record.start_url == manifest.start_url
        && record.context == manifest.context
        && record.workspace == manifest.workspace
}

fn validate_stored_context(context: &BrowserContext) -> Result<(), WebAppError> {
    validate_context_id(&context.id).map_err(WebAppError::Invalid)?;
    validate_display_name(&context.name, "browser context name").map_err(WebAppError::Invalid)?;
    let expected = format!("punar/browser/contexts/{}", context.id);
    if context.profile_path_rel != expected {
        return Err(WebAppError::Invalid(
            "stored browser context profile path is not derived from its id".into(),
        ));
    }
    Ok(())
}

fn context_record(id: &str, name: &str, deletable: bool) -> BrowserContext {
    BrowserContext {
        id: id.into(),
        name: name.into(),
        derived: false,
        deletable,
        isolates: vec![
            "cookies".into(),
            "storage".into(),
            "sign_ins".into(),
            "history".into(),
            "extensions".into(),
        ],
        profile_path_rel: format!("punar/browser/contexts/{id}"),
        simulated: Vec::new(),
        not_yet_observed: Vec::new(),
        source: None,
    }
}

fn desktop_entry(app: &WebAppRecord) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Version=1.5\n\
         Name={}\n\
         Comment=Punar web app · context {}\n\
         Exec=punarctl web-apps launch {}\n\
         Icon=punar-webapp-{}\n\
         Terminal=false\n\
         StartupNotify=true\n\
         StartupWMClass=punar-webapp-{}\n\
         Categories=Network;\n\
         X-Punar-WebApp-Id={}\n\
         X-Punar-WebApp-Context={}\n",
        app.name, app.context, app.id, app.id, app.id, app.id, app.context
    )
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(DIR_MODE))
}

fn write_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    bytes.push(b'\n');
    write_atomic_synced(path, &bytes, RECORD_MODE)
}

fn read_record<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.mode() & 0o777 != RECORD_MODE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a private regular record", path.display()),
        ));
    }
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn json_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(value & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

/// Parse the complete PNG chunk envelope before accepting bytes into the
/// root-owned store. The daemon never decodes pixels, but it still refuses
/// truncated files, corrupt chunk checksums, missing image data, trailing
/// payloads and malformed IHDR/IEND records.
fn validate_png(bytes: &[u8]) -> Result<(u32, u32), String> {
    if bytes.len() < PNG_SIGNATURE.len() || &bytes[..PNG_SIGNATURE.len()] != PNG_SIGNATURE {
        return Err("icon is not a PNG".into());
    }
    let mut offset = PNG_SIGNATURE.len();
    let mut dimensions = None;
    let mut saw_idat = false;
    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err("icon has a truncated PNG chunk".into());
        }
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("slice size checked"),
        ) as usize;
        let data_start = offset + 8;
        let data_end = data_start
            .checked_add(length)
            .ok_or_else(|| "icon PNG chunk length overflowed".to_string())?;
        let chunk_end = data_end
            .checked_add(4)
            .ok_or_else(|| "icon PNG chunk length overflowed".to_string())?;
        if chunk_end > bytes.len() {
            return Err("icon has a truncated PNG chunk".into());
        }
        let kind: &[u8; 4] = bytes[offset + 4..offset + 8]
            .try_into()
            .expect("slice size checked");
        let expected_crc = u32::from_be_bytes(
            bytes[data_end..chunk_end]
                .try_into()
                .expect("slice size checked"),
        );
        if png_crc32(&bytes[offset + 4..data_end]) != expected_crc {
            return Err("icon has a PNG chunk checksum mismatch".into());
        }
        match kind {
            b"IHDR" => {
                if offset != PNG_SIGNATURE.len() || length != 13 || dimensions.is_some() {
                    return Err("icon has a malformed PNG IHDR".into());
                }
                dimensions = Some((
                    u32::from_be_bytes(
                        bytes[data_start..data_start + 4]
                            .try_into()
                            .expect("slice size checked"),
                    ),
                    u32::from_be_bytes(
                        bytes[data_start + 4..data_start + 8]
                            .try_into()
                            .expect("slice size checked"),
                    ),
                ));
            }
            b"IDAT" => saw_idat = true,
            b"IEND" => {
                if length != 0 || !saw_idat || chunk_end != bytes.len() {
                    return Err("icon has a malformed PNG ending".into());
                }
                return dimensions.ok_or_else(|| "icon has no PNG IHDR".into());
            }
            _ => {}
        }
        offset = chunk_end;
    }
    Err("icon has no PNG IEND".into())
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn temp_root() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "punar-webapps-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn manifest(context: &str) -> WebAppManifest {
        WebAppManifest {
            v: 1,
            id: "notes".into(),
            name: "Notes".into(),
            start_url: "file:///usr/share/punar/fixtures/webapps/notes/index.html".into(),
            context: context.into(),
            workspace: "notes".into(),
            icon: WebAppIconRequest::Generated,
        }
    }

    fn one_pixel_png() -> Vec<u8> {
        fn chunk(output: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
            output.extend_from_slice(&(data.len() as u32).to_be_bytes());
            output.extend_from_slice(kind);
            output.extend_from_slice(data);
            let mut checked = Vec::from(*kind);
            checked.extend_from_slice(data);
            output.extend_from_slice(&png_crc32(&checked).to_be_bytes());
        }

        let raw = [0_u8, 0xfa, 0xf9, 0xf6];
        let mut zlib = vec![0x78, 0x01, 0x01, 0x04, 0x00, 0xfb, 0xff];
        zlib.extend_from_slice(&raw);
        let mut a = 1_u32;
        let mut b = 0_u32;
        for byte in raw {
            a = (a + u32::from(byte)) % 65_521;
            b = (b + a) % 65_521;
        }
        zlib.extend_from_slice(&((b << 16) | a).to_be_bytes());

        let mut png = PNG_SIGNATURE.to_vec();
        chunk(&mut png, b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]);
        chunk(&mut png, b"IDAT", &zlib);
        chunk(&mut png, b"IEND", &[]);
        png
    }

    #[test]
    fn generated_install_is_private_uid_scoped_and_rebuildable() {
        let root = temp_root();
        let manager = WebAppManager::new(root.join("web-apps"));
        let result = manager
            .install(
                1000,
                &manifest("personal"),
                vec!["personal-defaults".into()],
                false,
                false,
                false,
            )
            .unwrap();
        assert_eq!(result.app.origin, "file://");
        assert_eq!(result.app.installed_by.uid, 1000);
        assert!(
            result
                .artifacts
                .desktop_entry
                .contains("Exec=punarctl web-apps launch notes")
        );
        assert!(!result.artifacts.desktop_entry.contains("chromium"));
        assert!(result.artifacts.icon_png_b64.starts_with("iVBORw0KGgo"));
        assert_eq!(
            fs::metadata(manager.app_path(1000, "notes"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert!(manager.list(2000, false).unwrap().apps.is_empty());
        let rebuilt = manager.get(1000, "notes", true).unwrap();
        assert_eq!(
            rebuilt.artifacts.unwrap().desktop_entry,
            result.artifacts.desktop_entry
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn contexts_refuse_reserved_names_and_delete_only_when_unused() {
        let root = temp_root();
        let manager = WebAppManager::new(root.join("web-apps"));
        manager.context_create(1000, "atlas", "Atlas").unwrap();
        manager
            .install(
                1000,
                &manifest("atlas"),
                vec!["personal-defaults".into()],
                false,
                false,
                false,
            )
            .unwrap();
        assert!(matches!(
            manager.context_delete(1000, "atlas", true),
            Err(WebAppError::Conflict(_))
        ));
        assert!(matches!(
            manager.context_delete(1000, "personal", true),
            Err(WebAppError::Denied(_))
        ));
        manager.uninstall(1000, "notes", false).unwrap();
        manager.context_delete(1000, "atlas", true).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn matching_user_app_is_adopted_by_policy_without_replacing_its_identity() {
        let root = temp_root();
        let manager = WebAppManager::new(root.join("web-apps"));
        let manifest = manifest("personal");
        let personal = manager
            .install(
                1000,
                &manifest,
                vec!["personal-defaults".into()],
                false,
                false,
                false,
            )
            .unwrap();

        let adopted = manager
            .install(
                1000,
                &manifest,
                vec!["org-required-notes".into()],
                true,
                true,
                false,
            )
            .unwrap();
        assert!(adopted.app.managed);
        assert_eq!(adopted.app.installed_at, personal.app.installed_at);
        assert_eq!(adopted.app.icon.sha256, personal.app.icon.sha256);
        assert_eq!(adopted.app.installed_by.source, WebAppInstallSource::Policy);
        assert_eq!(adopted.app.policy_ids, ["org-required-notes"]);
        assert!(adopted.enforcement.managed);

        let mut conflicting = manifest;
        conflicting.name = "Different Notes".into();
        assert!(matches!(
            manager.install(
                1000,
                &conflicting,
                vec!["org-required-notes".into()],
                true,
                true,
                false,
            ),
            Err(WebAppError::Conflict(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn supplied_icons_are_bounded_pngs_owned_by_caller_or_signed_fixture() {
        let root = temp_root();
        let fixture = root.join("fixtures");
        fs::create_dir_all(&fixture).unwrap();
        let icon = fixture.join("icon.png");
        let one_pixel_png = one_pixel_png();
        fs::write(&icon, &one_pixel_png).unwrap();
        let manager = WebAppManager::new(root.join("web-apps")).with_fixture_root(fixture);
        let mut app = manifest("personal");
        app.icon = WebAppIconRequest::File {
            path: icon.to_string_lossy().into_owned(),
        };
        manager
            .install(1000, &app, vec![], false, false, false)
            .unwrap();
        fs::write(&icon, &one_pixel_png[..one_pixel_png.len() - 5]).unwrap();
        app.id = "broken".into();
        assert!(matches!(
            manager.install(1000, &app, vec![], false, false, false),
            Err(WebAppError::Invalid(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
