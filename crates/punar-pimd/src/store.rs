//! Crash-durable, fixture-free local Calendar and Reminders store.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use punar_common::time::{is_rfc3339_timestamp, unix_seconds_from_rfc3339, utc_now_rfc3339};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Calendar, CalendarEvent, CalendarEventKind, CalendarKind, ChangeEvent, ChangeEventKind,
    ChangeOperation, EntityKind, EventInput, EventWhen, Reminder, ReminderDue, ReminderInput,
    ReminderKind, ReminderList, ReminderListKind, SyncMetadata,
};

const STORE_VERSION: u32 = 1;
const MAX_CHANGES: usize = 4096;
const MAX_CHANGE_PAGE: usize = 1000;
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("PIM store I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("PIM store is corrupt: {0}")]
    Corrupt(String),
    #[error("PIM store version {found} is newer than supported version {supported}")]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("PIM store belongs to a different profile")]
    ProfileMismatch,
    #[error("invalid PIM value: {0}")]
    Invalid(String),
    #[error("PIM resource was not found")]
    NotFound,
    #[error("PIM record changed; current revision is {current_revision}")]
    Conflict { current_revision: u64 },
    #[error("change cursor is older than retained history")]
    CursorExpired,
}

/// Whether a local mutation remains only on this device or is queued for a
/// future provider adapter. The store persists offline intent before success
/// is returned; no caller has to remember an in-memory retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationMode {
    LocalOnly,
    QueueForSync { offline: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub profile_id: String,
    pub profile_uid: u32,
    pub revision: u64,
    pub calendars: Vec<Calendar>,
    pub events: Vec<CalendarEvent>,
    pub reminder_lists: Vec<ReminderList>,
    pub reminders: Vec<Reminder>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePage {
    pub changes: Vec<ChangeEvent>,
    /// Internal durable sequence. The future IPC layer integrity-protects and
    /// binds this value before exposing an opaque cursor to an application.
    pub next_sequence: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredChange {
    sequence: u64,
    event: ChangeEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema_version: u32,
    profile_id: String,
    profile_uid: u32,
    revision: u64,
    calendars: BTreeMap<String, Calendar>,
    events: BTreeMap<String, CalendarEvent>,
    reminder_lists: BTreeMap<String, ReminderList>,
    reminders: BTreeMap<String, Reminder>,
    changes: Vec<StoredChange>,
}

/// Unshipped development format accepted only to prove one-way migration.
/// It did not carry a change stream; migration therefore starts a fresh
/// cursor rather than manufacturing events that never occurred.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateV0 {
    schema_version: u32,
    profile_id: String,
    profile_uid: u32,
    calendars: BTreeMap<String, Calendar>,
    events: BTreeMap<String, CalendarEvent>,
    reminder_lists: BTreeMap<String, ReminderList>,
    reminders: BTreeMap<String, Reminder>,
}

pub struct PimStore {
    path: PathBuf,
    state: Mutex<State>,
}

impl PimStore {
    /// Open a profile-bound store. A missing file is initialized with blank
    /// local containers. Corrupt, over-permissive, future-version and
    /// cross-profile files fail closed and are never overwritten.
    pub fn open(path: &Path, profile_id: &str, profile_uid: u32) -> Result<Self, StoreError> {
        validate_profile_id(profile_id)?;
        prepare_private_parent(path)?;

        let state = match read_private(path)? {
            None => {
                let state = State::fresh(profile_id, profile_uid)?;
                persist(path, &state)?;
                state
            }
            Some(bytes) => load_or_migrate(path, &bytes, profile_id, profile_uid)?,
        };
        state.validate(profile_id, profile_uid)?;
        Ok(Self {
            path: path.to_path_buf(),
            state: Mutex::new(state),
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().unwrap();
        Snapshot {
            profile_id: state.profile_id.clone(),
            profile_uid: state.profile_uid,
            revision: state.revision,
            calendars: state.calendars.values().cloned().collect(),
            events: state.events.values().cloned().collect(),
            reminder_lists: state.reminder_lists.values().cloned().collect(),
            reminders: state.reminders.values().cloned().collect(),
        }
    }

    pub fn create_event(
        &self,
        input: EventInput,
        mode: MutationMode,
        now: &str,
    ) -> Result<CalendarEvent, StoreError> {
        validate_timestamp(now)?;
        validate_event_input(&input)?;
        let event_id = mint_id("event")?;
        self.commit(|state| {
            let calendar = state
                .calendars
                .get(&input.calendar_id)
                .ok_or(StoreError::NotFound)?;
            if calendar.read_only {
                return Err(StoreError::Invalid("calendar is read-only".into()));
            }
            let mut sync = SyncMetadata::local(now);
            apply_mode(&mut sync, mode, now);
            let event = CalendarEvent {
                kind: CalendarEventKind::CalendarEvent,
                event_id: event_id.clone(),
                calendar_id: input.calendar_id,
                title: input.title,
                when: input.when,
                location: input.location,
                description: input.description,
                recurrence_rule: input.recurrence_rule,
                attendees: input.attendees,
                sync,
            };
            state.events.insert(event_id.clone(), event.clone());
            state.record_change(
                EntityKind::CalendarEvent,
                ChangeOperation::Upsert,
                &event_id,
                event.sync.local_revision,
                now,
            )?;
            Ok(event)
        })
    }

    pub fn update_event(
        &self,
        event_id: &str,
        if_revision: u64,
        input: EventInput,
        mode: MutationMode,
        now: &str,
    ) -> Result<CalendarEvent, StoreError> {
        validate_timestamp(now)?;
        validate_event_input(&input)?;
        let event_id = event_id.to_string();
        self.commit(|state| {
            let calendar = state
                .calendars
                .get(&input.calendar_id)
                .ok_or(StoreError::NotFound)?;
            if calendar.read_only {
                return Err(StoreError::Invalid("calendar is read-only".into()));
            }
            let (record, revision) = {
                let event = state
                    .events
                    .get_mut(&event_id)
                    .ok_or(StoreError::NotFound)?;
                require_revision(event.sync.local_revision, if_revision)?;
                event.calendar_id = input.calendar_id;
                event.title = input.title;
                event.when = input.when;
                event.location = input.location;
                event.description = input.description;
                event.recurrence_rule = input.recurrence_rule;
                event.attendees = input.attendees;
                event.sync.advance(mode, now);
                (event.clone(), event.sync.local_revision)
            };
            state.record_change(
                EntityKind::CalendarEvent,
                ChangeOperation::Upsert,
                &event_id,
                revision,
                now,
            )?;
            Ok(record)
        })
    }

    pub fn delete_event(
        &self,
        event_id: &str,
        if_revision: u64,
        now: &str,
    ) -> Result<(), StoreError> {
        validate_timestamp(now)?;
        let event_id = event_id.to_string();
        self.commit(|state| {
            let revision = state
                .events
                .get(&event_id)
                .ok_or(StoreError::NotFound)?
                .sync
                .local_revision;
            require_revision(revision, if_revision)?;
            state.events.remove(&event_id);
            state.record_change(
                EntityKind::CalendarEvent,
                ChangeOperation::Delete,
                &event_id,
                revision + 1,
                now,
            )?;
            Ok(())
        })
    }

    pub fn create_reminder(
        &self,
        input: ReminderInput,
        mode: MutationMode,
        now: &str,
    ) -> Result<Reminder, StoreError> {
        validate_timestamp(now)?;
        validate_reminder_input(&input)?;
        let reminder_id = mint_id("reminder")?;
        self.commit(|state| {
            state
                .reminder_lists
                .get(&input.list_id)
                .ok_or(StoreError::NotFound)?;
            let mut sync = SyncMetadata::local(now);
            apply_mode(&mut sync, mode, now);
            let reminder = Reminder {
                kind: ReminderKind::Reminder,
                reminder_id: reminder_id.clone(),
                list_id: input.list_id,
                title: input.title,
                notes: input.notes,
                due: input.due,
                recurrence_rule: input.recurrence_rule,
                completed_at: None,
                sync,
            };
            state
                .reminders
                .insert(reminder_id.clone(), reminder.clone());
            state.record_change(
                EntityKind::Reminder,
                ChangeOperation::Upsert,
                &reminder_id,
                reminder.sync.local_revision,
                now,
            )?;
            Ok(reminder)
        })
    }

    pub fn update_reminder(
        &self,
        reminder_id: &str,
        if_revision: u64,
        input: ReminderInput,
        mode: MutationMode,
        now: &str,
    ) -> Result<Reminder, StoreError> {
        validate_timestamp(now)?;
        validate_reminder_input(&input)?;
        let reminder_id = reminder_id.to_string();
        self.commit(|state| {
            state
                .reminder_lists
                .get(&input.list_id)
                .ok_or(StoreError::NotFound)?;
            let (record, revision) = {
                let reminder = state
                    .reminders
                    .get_mut(&reminder_id)
                    .ok_or(StoreError::NotFound)?;
                require_revision(reminder.sync.local_revision, if_revision)?;
                reminder.list_id = input.list_id;
                reminder.title = input.title;
                reminder.notes = input.notes;
                reminder.due = input.due;
                reminder.recurrence_rule = input.recurrence_rule;
                reminder.sync.advance(mode, now);
                (reminder.clone(), reminder.sync.local_revision)
            };
            state.record_change(
                EntityKind::Reminder,
                ChangeOperation::Upsert,
                &reminder_id,
                revision,
                now,
            )?;
            Ok(record)
        })
    }

    pub fn complete_reminder(
        &self,
        reminder_id: &str,
        if_revision: u64,
        completed: bool,
        mode: MutationMode,
        now: &str,
    ) -> Result<Reminder, StoreError> {
        validate_timestamp(now)?;
        let reminder_id = reminder_id.to_string();
        self.commit(|state| {
            let (record, revision) = {
                let reminder = state
                    .reminders
                    .get_mut(&reminder_id)
                    .ok_or(StoreError::NotFound)?;
                require_revision(reminder.sync.local_revision, if_revision)?;
                reminder.completed_at = completed.then(|| now.to_string());
                reminder.sync.advance(mode, now);
                (reminder.clone(), reminder.sync.local_revision)
            };
            state.record_change(
                EntityKind::Reminder,
                ChangeOperation::Upsert,
                &reminder_id,
                revision,
                now,
            )?;
            Ok(record)
        })
    }

    pub fn delete_reminder(
        &self,
        reminder_id: &str,
        if_revision: u64,
        now: &str,
    ) -> Result<(), StoreError> {
        validate_timestamp(now)?;
        let reminder_id = reminder_id.to_string();
        self.commit(|state| {
            let revision = state
                .reminders
                .get(&reminder_id)
                .ok_or(StoreError::NotFound)?
                .sync
                .local_revision;
            require_revision(revision, if_revision)?;
            state.reminders.remove(&reminder_id);
            state.record_change(
                EntityKind::Reminder,
                ChangeOperation::Delete,
                &reminder_id,
                revision + 1,
                now,
            )?;
            Ok(())
        })
    }

    /// Return ordered changes after `sequence`. The value is internal and
    /// never the application-facing cursor from the public IPC contract.
    pub fn changes_since(&self, sequence: u64, limit: usize) -> Result<ChangePage, StoreError> {
        if limit == 0 || limit > MAX_CHANGE_PAGE {
            return Err(StoreError::Invalid(format!(
                "change page limit must be 1..={MAX_CHANGE_PAGE}"
            )));
        }
        let state = self.state.lock().unwrap();
        if let Some(first) = state.changes.first()
            && sequence.saturating_add(1) < first.sequence
        {
            return Err(StoreError::CursorExpired);
        }
        let mut matching = state
            .changes
            .iter()
            .filter(|change| change.sequence > sequence);
        let page: Vec<_> = matching
            .by_ref()
            .take(limit)
            .map(|change| change.event.clone())
            .collect();
        let has_more = matching.next().is_some();
        let next_sequence = page
            .last()
            .and_then(|event| {
                state
                    .changes
                    .iter()
                    .find(|change| change.event.change_id == event.change_id)
                    .map(|change| change.sequence)
            })
            .unwrap_or(sequence);
        Ok(ChangePage {
            changes: page,
            next_sequence,
            has_more,
        })
    }

    fn commit<T>(
        &self,
        change: impl FnOnce(&mut State) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut locked = self.state.lock().unwrap();
        let mut candidate = locked.clone();
        let result = change(&mut candidate)?;
        candidate.validate(&locked.profile_id, locked.profile_uid)?;
        persist(&self.path, &candidate)?;
        *locked = candidate;
        Ok(result)
    }
}

impl State {
    fn fresh(profile_id: &str, profile_uid: u32) -> Result<Self, StoreError> {
        let now = utc_now_rfc3339();
        let calendar_id = mint_id("calendar")?;
        let list_id = mint_id("list")?;
        let calendar = Calendar {
            kind: CalendarKind::Calendar,
            calendar_id: calendar_id.clone(),
            account_id: None,
            title: "Personal".to_string(),
            color: "#7C5CFC".to_string(),
            read_only: false,
            sync: SyncMetadata::local(&now),
        };
        let list = ReminderList {
            kind: ReminderListKind::ReminderList,
            list_id: list_id.clone(),
            account_id: None,
            title: "Reminders".to_string(),
            color: "#FF7A68".to_string(),
            sync: SyncMetadata::local(&now),
        };
        Ok(Self {
            schema_version: STORE_VERSION,
            profile_id: profile_id.to_string(),
            profile_uid,
            revision: 0,
            calendars: BTreeMap::from([(calendar_id, calendar)]),
            events: BTreeMap::new(),
            reminder_lists: BTreeMap::from([(list_id, list)]),
            reminders: BTreeMap::new(),
            changes: Vec::new(),
        })
    }

    fn validate(&self, profile_id: &str, profile_uid: u32) -> Result<(), StoreError> {
        if self.schema_version != STORE_VERSION {
            return Err(StoreError::UnsupportedVersion {
                found: self.schema_version,
                supported: STORE_VERSION,
            });
        }
        if self.profile_id != profile_id || self.profile_uid != profile_uid {
            return Err(StoreError::ProfileMismatch);
        }
        validate_profile_id(&self.profile_id)?;
        validate_keyed_records(&self.calendars, |record| &record.calendar_id, "calendar")?;
        validate_keyed_records(&self.events, |record| &record.event_id, "event")?;
        validate_keyed_records(&self.reminder_lists, |record| &record.list_id, "list")?;
        validate_keyed_records(&self.reminders, |record| &record.reminder_id, "reminder")?;
        for calendar in self.calendars.values() {
            validate_calendar(calendar)?;
        }
        for list in self.reminder_lists.values() {
            validate_reminder_list(list)?;
        }
        for event in self.events.values() {
            if !self.calendars.contains_key(&event.calendar_id) {
                return Err(StoreError::Corrupt(
                    "event references missing calendar".into(),
                ));
            }
            validate_event(event)?;
        }
        for reminder in self.reminders.values() {
            if !self.reminder_lists.contains_key(&reminder.list_id) {
                return Err(StoreError::Corrupt(
                    "reminder references missing reminder list".into(),
                ));
            }
            validate_reminder(reminder)?;
        }
        if self.changes.len() > MAX_CHANGES {
            return Err(StoreError::Corrupt("change history exceeds bound".into()));
        }
        let mut prior = None;
        for change in &self.changes {
            if change.sequence == 0 || change.sequence > self.revision {
                return Err(StoreError::Corrupt("invalid change sequence".into()));
            }
            if matches!(prior, Some(previous) if change.sequence <= previous) {
                return Err(StoreError::Corrupt("change history is not ordered".into()));
            }
            validate_opaque_id(&change.event.change_id)?;
            validate_opaque_id(&change.event.entity_id)?;
            validate_timestamp(&change.event.changed_at)?;
            if change.event.revision == 0 {
                return Err(StoreError::Corrupt(
                    "change record revision must be positive".into(),
                ));
            }
            prior = Some(change.sequence);
        }
        if self
            .changes
            .last()
            .is_some_and(|change| change.sequence != self.revision)
        {
            return Err(StoreError::Corrupt(
                "change history does not reach store revision".into(),
            ));
        }
        Ok(())
    }

    fn record_change(
        &mut self,
        entity_kind: EntityKind,
        operation: ChangeOperation,
        entity_id: &str,
        revision: u64,
        now: &str,
    ) -> Result<(), StoreError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Invalid("store revision exhausted".into()))?;
        let event = ChangeEvent {
            kind: ChangeEventKind::ChangeEvent,
            change_id: mint_id("change")?,
            entity_kind,
            operation,
            entity_id: entity_id.to_string(),
            revision,
            changed_at: now.to_string(),
        };
        self.changes.push(StoredChange {
            sequence: self.revision,
            event,
        });
        if self.changes.len() > MAX_CHANGES {
            let remove = self.changes.len() - MAX_CHANGES;
            self.changes.drain(0..remove);
        }
        Ok(())
    }
}

fn apply_mode(sync: &mut SyncMetadata, mode: MutationMode, now: &str) {
    if mode != MutationMode::LocalOnly {
        sync.advance(mode, now);
        // Creation starts at revision 1 regardless of its upload posture.
        sync.local_revision = 1;
    }
}

fn require_revision(current: u64, supplied: u64) -> Result<(), StoreError> {
    if current == supplied {
        Ok(())
    } else {
        Err(StoreError::Conflict {
            current_revision: current,
        })
    }
}

fn load_or_migrate(
    path: &Path,
    bytes: &[u8],
    profile_id: &str,
    profile_uid: u32,
) -> Result<State, StoreError> {
    let header: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| StoreError::Corrupt(error.to_string()))?;
    let version = header
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| StoreError::Corrupt("missing integer schema_version".into()))?;
    match version {
        1 => serde_json::from_slice(bytes).map_err(|error| StoreError::Corrupt(error.to_string())),
        0 => migrate_v0(path, bytes, profile_id, profile_uid),
        found => Err(StoreError::UnsupportedVersion {
            found: u32::try_from(found).unwrap_or(u32::MAX),
            supported: STORE_VERSION,
        }),
    }
}

fn migrate_v0(
    path: &Path,
    bytes: &[u8],
    profile_id: &str,
    profile_uid: u32,
) -> Result<State, StoreError> {
    let old: StateV0 =
        serde_json::from_slice(bytes).map_err(|error| StoreError::Corrupt(error.to_string()))?;
    if old.schema_version != 0 {
        return Err(StoreError::Corrupt("invalid v0 marker".into()));
    }
    if old.profile_id != profile_id || old.profile_uid != profile_uid {
        return Err(StoreError::ProfileMismatch);
    }
    let state = State {
        schema_version: STORE_VERSION,
        profile_id: old.profile_id,
        profile_uid: old.profile_uid,
        revision: 0,
        calendars: old.calendars,
        events: old.events,
        reminder_lists: old.reminder_lists,
        reminders: old.reminders,
        changes: Vec::new(),
    };
    state.validate(profile_id, profile_uid)?;
    persist_backup(path, bytes)?;
    persist(path, &state)?;
    Ok(state)
}

fn prepare_private_parent(path: &Path) -> Result<(), StoreError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| StoreError::Invalid("store path has no parent".into()))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    Ok(())
}

fn read_private(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() {
        return Err(StoreError::Corrupt(
            "state path is not a regular file".into(),
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StoreError::Corrupt(
            "state file is readable or writable by another user".into(),
        ));
    }
    Ok(Some(fs::read(path)?))
}

fn persist(path: &Path, state: &State) -> Result<(), StoreError> {
    let mut bytes =
        serde_json::to_vec_pretty(state).map_err(|error| StoreError::Corrupt(error.to_string()))?;
    bytes.push(b'\n');
    write_atomic_synced(path, &bytes)?;
    Ok(())
}

fn persist_backup(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| StoreError::Invalid("store path has no UTF-8 file name".into()))?;
    let backup = path.with_file_name(format!("{file_name}.pre-v1"));
    match fs::read(&backup) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) => {
            return Err(StoreError::Corrupt(
                "migration backup exists with different contents".into(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(&backup)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    sync_parent(&backup);
    Ok(())
}

fn write_atomic_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "state path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid state file name"))?;
    let mut last_collision = None;
    for _ in 0..4 {
        let temp = parent.join(format!(".{name}.pimd-{}", mint_suffix()?));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .open(&temp)
        {
            Ok(mut output) => {
                let result = (|| {
                    output.write_all(bytes)?;
                    output.sync_all()?;
                    fs::set_permissions(&temp, fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
                    fs::rename(&temp, path)?;
                    sync_parent(path);
                    Ok(())
                })();
                if result.is_err() {
                    let _ = fs::remove_file(&temp);
                }
                return result;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_collision.unwrap_or_else(|| io::Error::other("temporary file collision")))
}

fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent()
        && let Ok(directory) = File::open(parent)
    {
        let _ = directory.sync_all();
    }
}

fn mint_id(prefix: &str) -> Result<String, StoreError> {
    Ok(format!("{prefix}_{}", mint_suffix()?))
}

fn mint_suffix() -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other("kernel randomness unavailable"))?;
    let mut output = String::with_capacity(32);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(output)
}

fn validate_profile_id(value: &str) -> Result<(), StoreError> {
    let suffix = value
        .strip_prefix("profile_")
        .ok_or_else(|| StoreError::Invalid("profile id must begin with 'profile_'".into()))?;
    if suffix.is_empty()
        || suffix.len() > 64
        || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(StoreError::Invalid(
            "profile id has invalid characters".into(),
        ));
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<(), StoreError> {
    if is_rfc3339_timestamp(value) {
        Ok(())
    } else {
        Err(StoreError::Invalid("timestamp is not RFC 3339".into()))
    }
}

fn validate_date(value: &str) -> Result<(), StoreError> {
    let bytes = value.as_bytes();
    if bytes.len() == 10
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
    {
        let year = value[0..4].parse::<u32>().unwrap_or(0);
        let month = value[5..7].parse::<u32>().unwrap_or(0);
        let day = value[8..10].parse::<u32>().unwrap_or(0);
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let max_day = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => 0,
        };
        if year > 0 && day > 0 && day <= max_day {
            return Ok(());
        }
    }
    Err(StoreError::Invalid(
        "date must be a real YYYY-MM-DD date".into(),
    ))
}

fn validate_when(value: &EventWhen) -> Result<(), StoreError> {
    match value {
        EventWhen::Date {
            start_date,
            end_date,
            timezone,
        } => {
            validate_date(start_date)?;
            validate_date(end_date)?;
            if end_date <= start_date {
                return Err(StoreError::Invalid(
                    "all-day event end must be after start".into(),
                ));
            }
            bounded_nonempty(timezone, 128, "timezone")
        }
        EventWhen::DateTime {
            starts_at,
            ends_at,
            timezone,
        } => {
            validate_timestamp(starts_at)?;
            validate_timestamp(ends_at)?;
            let start = unix_seconds_from_rfc3339(starts_at)
                .ok_or_else(|| StoreError::Invalid("event start is not a real timestamp".into()))?;
            let end = unix_seconds_from_rfc3339(ends_at)
                .ok_or_else(|| StoreError::Invalid("event end is not a real timestamp".into()))?;
            if end <= start {
                return Err(StoreError::Invalid("event end must be after start".into()));
            }
            bounded_nonempty(timezone, 128, "timezone")
        }
    }
}

fn validate_due(value: &ReminderDue) -> Result<(), StoreError> {
    match value {
        ReminderDue::Date { date, timezone } => {
            validate_date(date)?;
            bounded_nonempty(timezone, 128, "timezone")
        }
        ReminderDue::DateTime { at, timezone } => {
            validate_timestamp(at)?;
            bounded_nonempty(timezone, 128, "timezone")
        }
    }
}

fn validate_event_input(input: &EventInput) -> Result<(), StoreError> {
    validate_opaque_id(&input.calendar_id)?;
    bounded_nonempty(&input.title, 4096, "event title")?;
    validate_when(&input.when)?;
    bounded_optional(&input.location, 4096, "event location")?;
    bounded_optional(&input.description, 65_536, "event description")?;
    bounded_optional(&input.recurrence_rule, 4096, "recurrence rule")?;
    if input.attendees.len() > 1000 {
        return Err(StoreError::Invalid("too many attendees".into()));
    }
    for attendee in &input.attendees {
        validate_email(&attendee.address)?;
    }
    Ok(())
}

fn validate_reminder_input(input: &ReminderInput) -> Result<(), StoreError> {
    validate_opaque_id(&input.list_id)?;
    bounded_nonempty(&input.title, 4096, "reminder title")?;
    bounded_optional(&input.notes, 65_536, "reminder notes")?;
    bounded_optional(&input.recurrence_rule, 4096, "recurrence rule")?;
    if let Some(due) = &input.due {
        validate_due(due)?;
    }
    Ok(())
}

fn validate_calendar(calendar: &Calendar) -> Result<(), StoreError> {
    validate_opaque_id(&calendar.calendar_id)?;
    if let Some(account_id) = &calendar.account_id {
        validate_account_id(account_id)?;
    }
    bounded_nonempty(&calendar.title, 256, "calendar title")?;
    validate_color(&calendar.color)?;
    validate_sync(&calendar.sync)
}

fn validate_reminder_list(list: &ReminderList) -> Result<(), StoreError> {
    validate_opaque_id(&list.list_id)?;
    if let Some(account_id) = &list.account_id {
        validate_account_id(account_id)?;
    }
    bounded_nonempty(&list.title, 256, "reminder list title")?;
    validate_color(&list.color)?;
    validate_sync(&list.sync)
}

fn validate_event(event: &CalendarEvent) -> Result<(), StoreError> {
    validate_event_input(&EventInput {
        calendar_id: event.calendar_id.clone(),
        title: event.title.clone(),
        when: event.when.clone(),
        location: event.location.clone(),
        description: event.description.clone(),
        recurrence_rule: event.recurrence_rule.clone(),
        attendees: event.attendees.clone(),
    })?;
    validate_sync(&event.sync)
}

fn validate_reminder(reminder: &Reminder) -> Result<(), StoreError> {
    validate_reminder_input(&ReminderInput {
        list_id: reminder.list_id.clone(),
        title: reminder.title.clone(),
        notes: reminder.notes.clone(),
        due: reminder.due.clone(),
        recurrence_rule: reminder.recurrence_rule.clone(),
    })?;
    if let Some(completed_at) = &reminder.completed_at {
        validate_timestamp(completed_at)?;
    }
    validate_sync(&reminder.sync)
}

fn validate_sync(sync: &SyncMetadata) -> Result<(), StoreError> {
    if sync.local_revision == 0 {
        return Err(StoreError::Corrupt(
            "record revision must be positive".into(),
        ));
    }
    validate_timestamp(&sync.updated_at)?;
    if matches!(sync.state, crate::SyncState::Conflict) != sync.conflict.is_some() {
        return Err(StoreError::Corrupt(
            "conflict state and details disagree".into(),
        ));
    }
    if let Some(error) = &sync.last_error {
        validate_timestamp(&error.occurred_at)?;
    }
    if let Some(conflict) = &sync.conflict {
        validate_opaque_id(&conflict.conflict_id)?;
        validate_timestamp(&conflict.detected_at)?;
        if conflict.fields.is_empty()
            || conflict.fields.len() > 32
            || conflict.resolution_options.is_empty()
            || conflict.resolution_options.len() > 3
        {
            return Err(StoreError::Corrupt("conflict details are invalid".into()));
        }
    }
    Ok(())
}

fn validate_opaque_id(value: &str) -> Result<(), StoreError> {
    let Some((prefix, suffix)) = value.rsplit_once('_') else {
        return Err(StoreError::Invalid("record id has no type prefix".into()));
    };
    let prefix_valid = (2..=32).contains(&prefix.len())
        && prefix.as_bytes()[0].is_ascii_lowercase()
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    let suffix_valid =
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric());
    if value.len() <= 128 && prefix_valid && suffix_valid {
        Ok(())
    } else {
        Err(StoreError::Invalid("record id has invalid shape".into()))
    }
}

fn validate_account_id(value: &str) -> Result<(), StoreError> {
    let suffix = value
        .strip_prefix("acct_")
        .ok_or_else(|| StoreError::Invalid("account id has invalid prefix".into()))?;
    if value.len() <= 80
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        Ok(())
    } else {
        Err(StoreError::Invalid("account id has invalid shape".into()))
    }
}

fn validate_color(value: &str) -> Result<(), StoreError> {
    if value.len() == 7
        && value.starts_with('#')
        && value[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err(StoreError::Invalid("color must be #RRGGBB".into()))
    }
}

fn validate_email(value: &crate::EmailAddress) -> Result<(), StoreError> {
    if value
        .name
        .as_ref()
        .is_some_and(|name| name.chars().count() > 256)
    {
        return Err(StoreError::Invalid("email display name is too long".into()));
    }
    if value.address.len() < 3
        || value.address.len() > 320
        || value.address.contains(char::is_whitespace)
    {
        return Err(StoreError::Invalid(
            "email address has invalid shape".into(),
        ));
    }
    let Some((local, domain)) = value.address.split_once('@') else {
        return Err(StoreError::Invalid(
            "email address has invalid shape".into(),
        ));
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(StoreError::Invalid(
            "email address has invalid shape".into(),
        ));
    }
    Ok(())
}

fn validate_keyed_records<T>(
    records: &BTreeMap<String, T>,
    id: impl Fn(&T) -> &String,
    kind: &str,
) -> Result<(), StoreError> {
    for (key, value) in records {
        if key != id(value) {
            return Err(StoreError::Corrupt(format!(
                "{kind} index does not match record id"
            )));
        }
    }
    Ok(())
}

fn bounded_nonempty(value: &str, max: usize, field: &str) -> Result<(), StoreError> {
    let count = value.chars().count();
    if count == 0 || count > max {
        Err(StoreError::Invalid(format!(
            "{field} must contain 1..={max} characters"
        )))
    } else {
        Ok(())
    }
}

fn bounded_optional(value: &Option<String>, max: usize, field: &str) -> Result<(), StoreError> {
    if value
        .as_ref()
        .is_some_and(|value| value.chars().count() > max)
    {
        Err(StoreError::Invalid(format!(
            "{field} exceeds {max} characters"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const NOW: &str = "2026-09-22T16:00:00Z";

    fn temp_store(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("punar-pimd-{name}-{}-{nonce}", std::process::id()))
            .join("state.json")
    }

    fn open(path: &Path) -> PimStore {
        PimStore::open(path, "profile_alice", 1000).unwrap()
    }

    fn reminder_input(snapshot: &Snapshot, title: &str) -> ReminderInput {
        ReminderInput {
            list_id: snapshot.reminder_lists[0].list_id.clone(),
            title: title.to_string(),
            notes: None,
            due: None,
            recurrence_rule: None,
        }
    }

    fn event_input(snapshot: &Snapshot, title: &str) -> EventInput {
        EventInput {
            calendar_id: snapshot.calendars[0].calendar_id.clone(),
            title: title.to_string(),
            when: EventWhen::DateTime {
                starts_at: "2026-09-23T14:00:00Z".into(),
                ends_at: "2026-09-23T14:30:00Z".into(),
                timezone: "America/Toronto".into(),
            },
            location: None,
            description: None,
            recurrence_rule: None,
            attendees: Vec::new(),
        }
    }

    #[test]
    fn fresh_store_has_only_blank_structural_containers() {
        let path = temp_store("empty");
        let snapshot = open(&path).snapshot();
        assert_eq!(snapshot.calendars.len(), 1);
        assert_eq!(snapshot.reminder_lists.len(), 1);
        assert!(snapshot.events.is_empty());
        assert!(snapshot.reminders.is_empty());
        assert_eq!(snapshot.revision, 0);
        let text = fs::read_to_string(&path).unwrap();
        for forbidden in [
            "refresh_token",
            "access_token",
            "password",
            "authorization_code",
            "client_secret",
            "demo",
            "fixture",
        ] {
            assert!(!text.contains(forbidden), "persisted {forbidden}");
        }
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn calendar_and_reminder_survive_restart() {
        let path = temp_store("restart");
        let store = open(&path);
        let initial = store.snapshot();
        let event = store
            .create_event(
                event_input(&initial, "Design review"),
                MutationMode::LocalOnly,
                NOW,
            )
            .unwrap();
        let reminder = store
            .create_reminder(
                reminder_input(&initial, "Review recovery proof"),
                MutationMode::LocalOnly,
                NOW,
            )
            .unwrap();
        drop(store);

        let reopened = open(&path).snapshot();
        assert_eq!(reopened.events, vec![event]);
        assert_eq!(reopened.reminders, vec![reminder]);
        assert_eq!(reopened.revision, 2);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn stale_update_is_rejected_without_overwriting_disk() {
        let path = temp_store("conflict");
        let store = open(&path);
        let initial = store.snapshot();
        let reminder = store
            .create_reminder(
                reminder_input(&initial, "First"),
                MutationMode::LocalOnly,
                NOW,
            )
            .unwrap();
        let before = fs::read(&path).unwrap();
        let error = store
            .update_reminder(
                &reminder.reminder_id,
                99,
                reminder_input(&initial, "Wrong"),
                MutationMode::LocalOnly,
                "2026-09-22T16:01:00Z",
            )
            .unwrap_err();
        assert!(matches!(
            error,
            StoreError::Conflict {
                current_revision: 1
            }
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(store.snapshot().reminders[0].title, "First");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn offline_queue_state_is_durable() {
        let path = temp_store("offline");
        let store = open(&path);
        let reminder = store
            .create_reminder(
                reminder_input(&store.snapshot(), "Send later"),
                MutationMode::QueueForSync { offline: true },
                NOW,
            )
            .unwrap();
        assert_eq!(reminder.sync.state, crate::SyncState::Offline);
        drop(store);
        let reopened = open(&path).snapshot();
        assert_eq!(reopened.reminders[0].sync.state, crate::SyncState::Offline);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn delete_emits_a_durable_tombstone_change() {
        let path = temp_store("delete");
        let store = open(&path);
        let reminder = store
            .create_reminder(
                reminder_input(&store.snapshot(), "Temporary"),
                MutationMode::LocalOnly,
                NOW,
            )
            .unwrap();
        store
            .delete_reminder(
                &reminder.reminder_id,
                reminder.sync.local_revision,
                "2026-09-22T16:02:00Z",
            )
            .unwrap();
        let page = store.changes_since(0, 10).unwrap();
        assert_eq!(page.changes.len(), 2);
        assert_eq!(page.changes[1].operation, ChangeOperation::Delete);
        assert_eq!(page.changes[1].entity_id, reminder.reminder_id);
        drop(store);
        let reopened = open(&path);
        assert!(reopened.snapshot().reminders.is_empty());
        assert_eq!(reopened.changes_since(0, 10).unwrap().changes.len(), 2);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn corrupt_store_fails_closed_and_is_not_replaced() {
        let path = temp_store("corrupt");
        open(&path);
        fs::write(&path, b"not json\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = match PimStore::open(&path, "profile_alice", 1000) {
            Ok(_) => panic!("corrupt store must not open"),
            Err(error) => error,
        };
        assert!(matches!(error, StoreError::Corrupt(_)));
        assert_eq!(fs::read(&path).unwrap(), b"not json\n");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn cross_profile_open_is_refused_without_rewriting() {
        let path = temp_store("profile");
        open(&path);
        let before = fs::read(&path).unwrap();
        let error = match PimStore::open(&path, "profile_bob", 1001) {
            Ok(_) => panic!("cross-profile store must not open"),
            Err(error) => error,
        };
        assert!(matches!(error, StoreError::ProfileMismatch));
        assert_eq!(fs::read(&path).unwrap(), before);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn over_permissive_store_is_refused() {
        let path = temp_store("mode");
        open(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = match PimStore::open(&path, "profile_alice", 1000) {
            Ok(_) => panic!("public store must not open"),
            Err(error) => error,
        };
        assert!(matches!(error, StoreError::Corrupt(_)));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn v0_migration_is_backed_up_and_idempotent() {
        let path = temp_store("migration");
        let original = open(&path).snapshot();
        let calendars = BTreeMap::from([(
            original.calendars[0].calendar_id.clone(),
            original.calendars[0].clone(),
        )]);
        let reminder_lists = BTreeMap::from([(
            original.reminder_lists[0].list_id.clone(),
            original.reminder_lists[0].clone(),
        )]);
        let v0 = serde_json::json!({
            "schema_version": 0,
            "profile_id": "profile_alice",
            "profile_uid": 1000,
            "calendars": calendars,
            "events": {},
            "reminder_lists": reminder_lists,
            "reminders": {}
        });
        let bytes = serde_json::to_vec_pretty(&v0).unwrap();
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let migrated = open(&path).snapshot();
        assert_eq!(migrated.revision, 0);
        let backup = path.with_file_name("state.json.pre-v1");
        assert_eq!(fs::read(&backup).unwrap(), bytes);
        drop(open(&path));
        assert_eq!(fs::read(&backup).unwrap(), bytes);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn future_version_is_refused_without_rewriting() {
        let path = temp_store("future");
        open(&path);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["schema_version"] = serde_json::json!(2);
        let bytes = serde_json::to_vec_pretty(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = match PimStore::open(&path, "profile_alice", 1000) {
            Ok(_) => panic!("future store must not open"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StoreError::UnsupportedVersion {
                found: 2,
                supported: 1
            }
        ));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
