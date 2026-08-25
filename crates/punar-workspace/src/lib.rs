//! `punar-workspace` — project workspace and window-context manager (SPEC
//! section 11.5).
//!
//! Milestone 2 scope: the **typed contract** for the workspace state file
//! `~/.local/state/punar/workspaces.json` (SPEC sections 13.5, 14.1, 14.3;
//! decisions in `docs/development/milestone-2.md` section 6). The JSON Schema
//! twin lives at `schemas/workspace/workspace-state.json`.
//!
//! **Who writes the file:** in Milestone 2 the *shell* (punar-shell QML, via
//! `FileView` with atomic tmp+rename writes) is the only writer, debounced on
//! `renameworkspace` events and layout-preset changes. This crate runs
//! nothing at M2 — no daemon, no timer, no process. The `punar-workspace`
//! daemon takes over ownership of the file in Milestone 3+ (SPEC section
//! 11.5), consuming these exact types unchanged.
//!
//! - [`WorkspacesFile`] — the whole state file (schema `version` 1).
//! - [`WorkspaceState`] — one persisted workspace entry.
//! - [`LayoutPreset`] — the six SPEC section 13.5 preset names plus
//!   [`LayoutPreset::Custom`].
//! - [`WorkspacesFile::load`] / [`WorkspacesFile::save`] — tolerant load and
//!   validating atomic save.

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current schema version of the workspace state file. Readers reject files
/// declaring a *newer* version; older-or-equal versions parse tolerantly
/// (unknown fields are ignored for forward compatibility).
pub const STATE_VERSION: u32 = 1;

/// The workspace-name rule from `docs/development/milestone-2.md` section 6,
/// as a regex: 1–32 characters, ASCII alphanumeric first character, then
/// ASCII alphanumerics, spaces, underscores, or hyphens. Commas are excluded
/// because Hyprland's socket2 `renameworkspace` event frames as `ID,NAME`.
/// Additionally (outside this pattern) a name must not begin with `special`,
/// the prefix Hyprland reserves for special workspaces.
pub const WORKSPACE_NAME_PATTERN: &str = "^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$";

/// Milestone-2 decision-record name for [`WorkspacesFile`]
/// (`docs/development/milestone-2.md` section 6).
pub type WorkspaceStateFile = WorkspacesFile;

/// Milestone-2 decision-record name for [`WorkspaceState`]
/// (`docs/development/milestone-2.md` section 6).
pub type WorkspaceName = WorkspaceState;

/// Layout preset vocabulary: the six example presets of SPEC section 13.5
/// plus `custom`.
///
/// Serialized values are lowercase (`"balanced"`, …, `"custom"`). Milestone 2
/// ships five presets (`balanced`, `columns`, `rows`, `focus`, `stack`);
/// `grid` is a SPEC 13.5 name with no shipped mapping in M2 (Hyprland 0.56.2
/// has no native grid algorithm), and `custom` is reserved for layouts the
/// user has diverged from a preset — neither is emitted by the M2 writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutPreset {
    /// Even BSP splits (M2 mapping: Hyprland `dwindle`). The default.
    #[default]
    Balanced,
    /// Every window a column, viewport scrolls (M2 mapping: `scrolling`).
    Columns,
    /// Hero row on top, rest share the bottom (M2 mapping: `master`, orientation top).
    Rows,
    /// One large focused window with a side stack (M2 mapping: `master`, orientation left).
    Focus,
    /// One window at a time, rest behind (M2 mapping: `monocle`).
    Stack,
    /// SPEC 13.5 name without an M2 mapping; never written by the M2 shell.
    Grid,
    /// Reserved: layout diverged from any preset. Never written by the M2 shell.
    Custom,
}

impl LayoutPreset {
    /// All seven values, in declaration order.
    pub const ALL: [LayoutPreset; 7] = [
        LayoutPreset::Balanced,
        LayoutPreset::Columns,
        LayoutPreset::Rows,
        LayoutPreset::Focus,
        LayoutPreset::Stack,
        LayoutPreset::Grid,
        LayoutPreset::Custom,
    ];

    /// The lowercase wire name (the serde serialization of this value).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            LayoutPreset::Balanced => "balanced",
            LayoutPreset::Columns => "columns",
            LayoutPreset::Rows => "rows",
            LayoutPreset::Focus => "focus",
            LayoutPreset::Stack => "stack",
            LayoutPreset::Grid => "grid",
            LayoutPreset::Custom => "custom",
        }
    }
}

/// One persisted workspace entry: a named project workspace (SPEC section 14).
///
/// Wire shape (schema version 1): `{ "id": 1, "name": "atlas" }`, with two
/// optional fields reserved for the Milestone 3+ daemon and never written by
/// the Milestone 2 shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceState {
    /// Workspace number (Hyprland workspace id), `>= 1`. Special workspaces
    /// (negative ids / `special:` names) are never persisted.
    pub id: i64,
    /// Project workspace name; must satisfy [`is_valid_workspace_name`].
    pub name: String,
    /// Reserved (M3+): per-workspace preset override. Layout presets are
    /// global in Milestone 2 (`docs/development/milestone-2.md` section 2),
    /// so the M2 shell never writes this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout_preset: Option<LayoutPreset>,
    /// Reserved (M3+): monitor the workspace was last on (SPEC section 15
    /// monitor memory is out of M2 scope). The M2 shell never writes this
    /// field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor: Option<String>,
}

impl WorkspaceState {
    /// A minimal entry with just an id and a name (the only fields the
    /// Milestone 2 shell writes).
    #[must_use]
    pub fn new(id: i64, name: impl Into<String>) -> Self {
        WorkspaceState {
            id,
            name: name.into(),
            layout_preset: None,
            monitor: None,
        }
    }

    /// Validate this entry against the milestone-2 section 6 rules.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidId`] when `id < 1` and
    /// [`ValidationError::InvalidName`] when the name fails
    /// [`is_valid_workspace_name`].
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.id < 1 {
            return Err(ValidationError::InvalidId { id: self.id });
        }
        if !is_valid_workspace_name(&self.name) {
            return Err(ValidationError::InvalidName {
                name: self.name.clone(),
            });
        }
        if matches!(&self.monitor, Some(monitor) if monitor.is_empty()) {
            return Err(ValidationError::EmptyMonitor { id: self.id });
        }
        Ok(())
    }
}

/// The whole workspace state file, schema version 1.
///
/// Exact wire shape (`docs/development/milestone-2.md` section 6):
///
/// ```json
/// {
///   "version": 1,
///   "updated": "2026-08-25T09:30:00Z",
///   "layoutPreset": "balanced",
///   "workspaces": [
///     { "id": 1, "name": "atlas" },
///     { "id": 2, "name": "punar" }
///   ]
/// }
/// ```
///
/// `workspaces` is sorted by strictly ascending `id` and holds entries only
/// for workspaces with non-empty names. `layoutPreset` (note: the one
/// camelCase key, fixed by the decision record and asserted by CI) is the
/// *global* active preset; presets are global in Milestone 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspacesFile {
    /// Schema version; [`STATE_VERSION`] (= 1) for files this crate writes.
    pub version: u32,
    /// RFC 3339 timestamp of the last write, e.g. `2026-08-25T09:30:00Z`.
    pub updated: String,
    /// Global active layout preset (SPEC section 13.5).
    #[serde(rename = "layoutPreset")]
    pub layout_preset: LayoutPreset,
    /// Named workspaces, sorted by strictly ascending id.
    pub workspaces: Vec<WorkspaceState>,
}

impl Default for WorkspacesFile {
    /// The "no state persisted yet" file: version 1, epoch timestamp,
    /// `balanced` preset, no named workspaces. This is what [`load`]
    /// returns when the state file does not exist.
    ///
    /// [`load`]: WorkspacesFile::load
    fn default() -> Self {
        WorkspacesFile {
            version: STATE_VERSION,
            updated: String::from("1970-01-01T00:00:00Z"),
            layout_preset: LayoutPreset::default(),
            workspaces: Vec::new(),
        }
    }
}

impl WorkspacesFile {
    /// Tolerantly load the state file at `path`.
    ///
    /// - Missing file → `Ok(Self::default())` (first boot is not an error).
    /// - Unknown JSON fields → ignored (forward compatibility; alpha
    ///   contracts add fields compatibly).
    /// - This does **not** run [`validate`](Self::validate): reading is
    ///   tolerant, writing is strict.
    ///
    /// # Errors
    ///
    /// - [`Error::Corrupt`] when the file exists but is not valid JSON for
    ///   this shape.
    /// - [`Error::UnsupportedVersion`] when `version` is newer than
    ///   [`STATE_VERSION`] (readers reject files from the future).
    /// - [`Error::Io`] for any other I/O failure.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => return Err(Error::Io(err)),
        };
        let file: Self = serde_json::from_str(&text).map_err(Error::Corrupt)?;
        if file.version > STATE_VERSION {
            return Err(Error::UnsupportedVersion {
                found: file.version,
            });
        }
        Ok(file)
    }

    /// Validate the file against the milestone-2 section 6 rules: `version`
    /// exactly [`STATE_VERSION`], `updated` an RFC 3339 timestamp, every
    /// entry valid per [`WorkspaceState::validate`], and `workspaces` sorted
    /// by strictly ascending id (which also forbids duplicates).
    ///
    /// # Errors
    ///
    /// Returns the first [`ValidationError`] encountered.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.version != STATE_VERSION {
            return Err(ValidationError::WrongVersion {
                found: self.version,
            });
        }
        if !is_rfc3339_timestamp(&self.updated) {
            return Err(ValidationError::InvalidTimestamp {
                updated: self.updated.clone(),
            });
        }
        let mut previous_id: Option<i64> = None;
        for entry in &self.workspaces {
            entry.validate()?;
            if matches!(previous_id, Some(prev) if entry.id <= prev) {
                return Err(ValidationError::NotSortedById { id: entry.id });
            }
            previous_id = Some(entry.id);
        }
        Ok(())
    }

    /// Validate, then atomically write the file to `path`: parent
    /// directories are created, the JSON is written to a `.tmp` sibling,
    /// synced, and renamed over `path` (the same tmp+rename discipline the
    /// M2 shell's `FileView { atomicWrites: true }` uses). Assumes a single
    /// writer, which the milestone-2 contract guarantees.
    ///
    /// # Errors
    ///
    /// - [`Error::Invalid`] when [`validate`](Self::validate) fails — an
    ///   invalid state is never persisted.
    /// - [`Error::Io`] on any filesystem failure.
    /// - [`Error::Serialize`] if JSON serialization fails (not expected for
    ///   these types).
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        self.validate()?;
        match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => fs::create_dir_all(parent)?,
            _ => {}
        }
        let mut file_name = path
            .file_name()
            .ok_or_else(|| {
                Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("state path has no file name: {}", path.display()),
                ))
            })?
            .to_os_string();
        file_name.push(".tmp");
        let tmp = path.with_file_name(file_name);
        let json = serde_json::to_string_pretty(self).map_err(Error::Serialize)?;
        {
            let mut out = fs::File::create(&tmp)?;
            out.write_all(json.as_bytes())?;
            out.write_all(b"\n")?;
            out.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// Whether `name` is a valid persisted workspace name
/// (`docs/development/milestone-2.md` section 6): matches
/// [`WORKSPACE_NAME_PATTERN`] and does not begin with `special` (Hyprland's
/// reserved special-workspace prefix). The comma exclusion matters because
/// Hyprland's socket2 rename event frames as `ID,NAME`.
#[must_use]
pub fn is_valid_workspace_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    if !bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b' ' || b == b'_' || b == b'-')
    {
        return false;
    }
    !name.starts_with("special")
}

/// Whether `value` is an RFC 3339 timestamp, mirroring the pattern asserted
/// by `schemas/common/defs.json#/$defs/timestamp`:
/// `^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$`.
/// Structural only — field ranges (month 1–12 etc.) are not checked, exactly
/// as in the schema.
#[must_use]
pub fn is_rfc3339_timestamp(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() < 20 {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| b[range].iter().all(u8::is_ascii_digit);
    let date_time_ok = digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && (b[10] == b'T' || b[10] == b't')
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19);
    if !date_time_ok {
        return false;
    }
    let mut i = 19;
    if b[i] == b'.' {
        let first_frac = i + 1;
        i = first_frac;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == first_frac {
            return false;
        }
    }
    match b.get(i) {
        Some(b'Z' | b'z') => i + 1 == b.len(),
        Some(b'+' | b'-') => {
            b.len() == i + 6 && digits(i + 1..i + 3) && b[i + 3] == b':' && digits(i + 4..i + 6)
        }
        _ => false,
    }
}

/// A rule violation in a [`WorkspacesFile`] (milestone-2 section 6 rules).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    /// `version` is not [`STATE_VERSION`]; files being written must be
    /// exactly the current version.
    #[error("workspace state version must be {STATE_VERSION} to write, found {found}")]
    WrongVersion {
        /// The version the file declared.
        found: u32,
    },
    /// `updated` is not an RFC 3339 timestamp.
    #[error("'updated' is not an RFC 3339 timestamp: {updated:?}")]
    InvalidTimestamp {
        /// The rejected `updated` value.
        updated: String,
    },
    /// A workspace id is below 1 (special workspaces are never persisted).
    #[error("workspace id must be >= 1, found {id}")]
    InvalidId {
        /// The rejected id.
        id: i64,
    },
    /// A workspace name fails [`is_valid_workspace_name`].
    #[error(
        "invalid workspace name {name:?}: must match {WORKSPACE_NAME_PATTERN} \
         and not begin with 'special'"
    )]
    InvalidName {
        /// The rejected name.
        name: String,
    },
    /// A present `monitor` value is empty.
    #[error("workspace {id}: 'monitor', when present, must be non-empty")]
    EmptyMonitor {
        /// Id of the offending entry.
        id: i64,
    },
    /// `workspaces` is not sorted by strictly ascending id (also raised for
    /// duplicate ids).
    #[error("workspaces must be sorted by strictly ascending id; {id} is out of order")]
    NotSortedById {
        /// Id of the out-of-order entry.
        id: i64,
    },
}

/// Errors from [`WorkspacesFile::load`] and [`WorkspacesFile::save`].
#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem failure while reading or writing the state file.
    #[error("workspace state I/O error: {0}")]
    Io(#[from] io::Error),
    /// The file exists but is not valid JSON for the contract shape.
    #[error("corrupt workspace state file: {0}")]
    Corrupt(#[source] serde_json::Error),
    /// The file declares a schema version newer than [`STATE_VERSION`].
    #[error("workspace state file version {found} is newer than supported version {STATE_VERSION}")]
    UnsupportedVersion {
        /// The version the file declared.
        found: u32,
    },
    /// JSON serialization failed while saving (not expected for these types).
    #[error("failed to serialize workspace state: {0}")]
    Serialize(#[source] serde_json::Error),
    /// The in-memory state violates the contract rules; nothing was written.
    #[error(transparent)]
    Invalid(#[from] ValidationError),
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    /// The valid fixture is the shared round-trip vector: the exact
    /// milestone-2 section 6 example shape, also validated against
    /// `schemas/workspace/workspace-state.json` by `tools/validate-schemas.sh`.
    const VALID_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/workspace/valid/workspace-state.v1.json"
    ));

    const RESERVED_FIELDS_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/workspace/valid/workspace-state.reserved-fields.json"
    ));

    fn scratch_dir() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "punar-workspace-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    fn example_file() -> WorkspacesFile {
        WorkspacesFile {
            version: 1,
            updated: String::from("2026-08-25T09:30:00Z"),
            layout_preset: LayoutPreset::Balanced,
            workspaces: vec![
                WorkspaceState::new(1, "atlas"),
                WorkspaceState::new(2, "punar"),
            ],
        }
    }

    #[test]
    fn fixture_round_trips() {
        let parsed: WorkspacesFile =
            serde_json::from_str(VALID_FIXTURE).expect("valid fixture parses");
        parsed.validate().expect("valid fixture validates");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.layout_preset, LayoutPreset::Rows);
        assert_eq!(parsed.workspaces, vec![WorkspaceState::new(1, "atlas")]);

        let reserialized = serde_json::to_value(&parsed).expect("serialize");
        let original: serde_json::Value =
            serde_json::from_str(VALID_FIXTURE).expect("fixture is JSON");
        assert_eq!(reserialized, original, "round trip is lossless");
    }

    #[test]
    fn reserved_fields_fixture_round_trips() {
        let parsed: WorkspacesFile =
            serde_json::from_str(RESERVED_FIELDS_FIXTURE).expect("fixture parses");
        parsed.validate().expect("fixture validates");
        let entry = &parsed.workspaces[0];
        assert_eq!(entry.layout_preset, Some(LayoutPreset::Custom));
        assert_eq!(entry.monitor.as_deref(), Some("DP-1"));

        let reserialized = serde_json::to_value(&parsed).expect("serialize");
        let original: serde_json::Value =
            serde_json::from_str(RESERVED_FIELDS_FIXTURE).expect("fixture is JSON");
        assert_eq!(reserialized, original, "reserved fields survive round trip");
    }

    #[test]
    fn milestone_example_shape_is_exact() {
        let json = serde_json::to_value(example_file()).expect("serialize");
        let expected: serde_json::Value = serde_json::from_str(
            r#"{
                "version": 1,
                "updated": "2026-08-25T09:30:00Z",
                "layoutPreset": "balanced",
                "workspaces": [
                    { "id": 1, "name": "atlas" },
                    { "id": 2, "name": "punar" }
                ]
            }"#,
        )
        .expect("expected JSON");
        assert_eq!(json, expected);
    }

    #[test]
    fn optional_fields_are_omitted_when_none() {
        let json = serde_json::to_value(WorkspaceState::new(1, "atlas")).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!({ "id": 1, "name": "atlas" }),
            "reserved M3+ fields must not appear in M2 output"
        );
    }

    #[test]
    fn preset_wire_names() {
        for preset in LayoutPreset::ALL {
            let value = serde_json::to_value(preset).expect("serialize");
            assert_eq!(value, serde_json::Value::String(preset.as_str().to_owned()));
        }
        assert_eq!(LayoutPreset::Balanced.as_str(), "balanced");
        assert_eq!(LayoutPreset::Custom.as_str(), "custom");
        assert_eq!(LayoutPreset::default(), LayoutPreset::Balanced);
    }

    #[test]
    fn load_missing_file_is_default() {
        let path = scratch_dir().join("does-not-exist.json");
        let file = WorkspacesFile::load(&path).expect("missing file loads as default");
        assert_eq!(file, WorkspacesFile::default());
        assert_eq!(file.version, STATE_VERSION);
        assert_eq!(file.layout_preset, LayoutPreset::Balanced);
        assert!(file.workspaces.is_empty());
        file.validate().expect("default file is valid");
    }

    #[test]
    fn load_corrupt_file_is_error() {
        let dir = scratch_dir();
        for garbage in ["not json at all {", "42", r#"{"version": "one"}"#] {
            let path = dir.join("workspaces.json");
            fs::write(&path, garbage).expect("write garbage");
            let err = WorkspacesFile::load(&path).expect_err("corrupt input must error");
            assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        }
    }

    #[test]
    fn load_rejects_newer_version() {
        let dir = scratch_dir();
        let path = dir.join("workspaces.json");
        fs::write(
            &path,
            r#"{"version": 2, "updated": "2026-08-25T09:30:00Z", "layoutPreset": "balanced", "workspaces": []}"#,
        )
        .expect("write");
        let err = WorkspacesFile::load(&path).expect_err("future version must be rejected");
        assert!(matches!(err, Error::UnsupportedVersion { found: 2 }));
    }

    #[test]
    fn load_ignores_unknown_fields() {
        let dir = scratch_dir();
        let path = dir.join("workspaces.json");
        fs::write(
            &path,
            r#"{
                "version": 1,
                "updated": "2026-08-25T09:30:00Z",
                "layoutPreset": "stack",
                "workspaces": [{ "id": 3, "name": "research", "future_field": true }],
                "future_top_level": { "nested": [1, 2, 3] }
            }"#,
        )
        .expect("write");
        let file = WorkspacesFile::load(&path).expect("unknown fields are ignored");
        assert_eq!(file.layout_preset, LayoutPreset::Stack);
        assert_eq!(file.workspaces, vec![WorkspaceState::new(3, "research")]);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = scratch_dir();
        // Nested path proves parent-directory creation (FileView mkpath parity).
        let path = dir.join("state/punar/workspaces.json");
        let original = example_file();
        original.save(&path).expect("save succeeds");
        assert!(
            !path.with_file_name("workspaces.json.tmp").exists(),
            "tmp file must be renamed away"
        );
        let reloaded = WorkspacesFile::load(&path).expect("reload");
        assert_eq!(reloaded, original);
    }

    #[test]
    fn save_refuses_invalid_state() {
        let dir = scratch_dir();
        let path = dir.join("workspaces.json");

        let cases: Vec<(WorkspacesFile, ValidationError)> = vec![
            (
                WorkspacesFile {
                    version: 2,
                    ..WorkspacesFile::default()
                },
                ValidationError::WrongVersion { found: 2 },
            ),
            (
                WorkspacesFile {
                    updated: String::from("yesterday"),
                    ..WorkspacesFile::default()
                },
                ValidationError::InvalidTimestamp {
                    updated: String::from("yesterday"),
                },
            ),
            (
                WorkspacesFile {
                    workspaces: vec![WorkspaceState::new(0, "atlas")],
                    ..WorkspacesFile::default()
                },
                ValidationError::InvalidId { id: 0 },
            ),
            (
                WorkspacesFile {
                    workspaces: vec![WorkspaceState::new(1, "atlas,dev")],
                    ..WorkspacesFile::default()
                },
                ValidationError::InvalidName {
                    name: String::from("atlas,dev"),
                },
            ),
            (
                WorkspacesFile {
                    workspaces: vec![
                        WorkspaceState::new(2, "punar"),
                        WorkspaceState::new(1, "atlas"),
                    ],
                    ..WorkspacesFile::default()
                },
                ValidationError::NotSortedById { id: 1 },
            ),
            (
                WorkspacesFile {
                    workspaces: vec![
                        WorkspaceState::new(1, "atlas"),
                        WorkspaceState::new(1, "punar"),
                    ],
                    ..WorkspacesFile::default()
                },
                ValidationError::NotSortedById { id: 1 },
            ),
            (
                WorkspacesFile {
                    workspaces: vec![WorkspaceState {
                        monitor: Some(String::new()),
                        ..WorkspaceState::new(1, "atlas")
                    }],
                    ..WorkspacesFile::default()
                },
                ValidationError::EmptyMonitor { id: 1 },
            ),
        ];

        for (state, expected) in cases {
            let err = state.save(&path).expect_err("invalid state must not save");
            match err {
                Error::Invalid(v) => assert_eq!(v, expected),
                other => panic!("expected validation error, got {other:?}"),
            }
            assert!(!path.exists(), "invalid state must never reach disk");
        }
    }

    #[test]
    fn workspace_name_rules() {
        for good in [
            "atlas",
            "Atlas 2",
            "a",
            "punar-os_build",
            "Specialist", // 'special' prefix rule is lowercase, per the decision record
            "0numeric first",
            "exactly-32-chars-long-name-here5",
        ] {
            assert!(is_valid_workspace_name(good), "{good:?} should be valid");
        }
        for bad in [
            "",
            " leading-space",
            "-leading-dash",
            "atlas,dev",                         // comma breaks socket2 event framing
            "special",                           // reserved Hyprland prefix
            "special:notes",                     // reserved prefix + illegal colon
            "specialized",                       // still the reserved prefix
            "tab\tname",                         // control characters
            "unicode-café",                      // non-ASCII
            "a-name-that-is-thirty-three-chars", // 33 chars
        ] {
            assert!(!is_valid_workspace_name(bad), "{bad:?} should be invalid");
        }
        assert_eq!("exactly-32-chars-long-name-here5".len(), 32);
        assert_eq!("a-name-that-is-thirty-three-chars".len(), 33);
    }

    #[test]
    fn timestamp_rules() {
        for good in [
            "2026-08-25T09:30:00Z",
            "1970-01-01T00:00:00Z",
            "2026-08-25t09:30:00z",
            "2026-08-25T09:30:00.123Z",
            "2026-08-25T09:30:00+05:30",
            "2026-08-25T09:30:00.5-08:00",
        ] {
            assert!(is_rfc3339_timestamp(good), "{good:?} should be valid");
        }
        for bad in [
            "",
            "yesterday",
            "2026-08-25",
            "2026-08-25 09:30:00Z",  // space instead of T
            "2026-08-25T09:30:00",   // missing zone
            "2026-08-25T09:30:00.Z", // empty fraction
            "2026-08-25T09:30:00+0530",
            "26-08-25T09:30:00Z",
        ] {
            assert!(!is_rfc3339_timestamp(bad), "{bad:?} should be invalid");
        }
    }

    #[test]
    fn decision_record_type_aliases_resolve() {
        // milestone-2.md section 6 names these types WorkspaceStateFile /
        // WorkspaceName; keep both spellings compiling.
        let file: WorkspaceStateFile = WorkspacesFile::default();
        let entry: WorkspaceName = WorkspaceState::new(1, "atlas");
        assert_eq!(file.version, STATE_VERSION);
        assert_eq!(entry.name, "atlas");
    }
}
