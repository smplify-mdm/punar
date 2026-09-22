//! `punar-pimd` — profile-scoped personal-information data service.
//!
//! This first implementation slice deliberately contains only the durable,
//! local Calendar and Reminders core. It has no network client, credential
//! field, provider adapter, socket or resident background loop. That keeps the
//! production authorization boundary honest while the local data semantics are
//! exercised independently. The executable and socket activation arrive only
//! after ADR-008's hostile same-UID caller gate has a proven mechanism.
//!
//! A newly opened store contains one blank local calendar and one blank local
//! reminder list. Those are structural containers, not demo content: accounts,
//! events and reminders are empty.

#![forbid(unsafe_code)]

mod store;

pub use store::{ChangePage, MutationMode, PimStore, Snapshot, StoreError};

use serde::{Deserialize, Serialize};

/// Synchronization posture carried by every mutable provider-neutral record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    LocalOnly,
    Synced,
    Pending,
    Offline,
    Conflict,
    Error,
}

/// A bounded provider failure. Provider response bodies and credential values
/// are intentionally not representable here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncError {
    pub code: SyncErrorCode,
    pub retryable: bool,
    pub occurred_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncErrorCode {
    Offline,
    UpstreamAuthRequired,
    UpstreamUnreachable,
    RateLimited,
    MalformedRemoteData,
    UnsupportedRemoteState,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    pub conflict_id: String,
    pub fields: Vec<String>,
    pub detected_at: String,
    pub resolution_options: Vec<ConflictResolution>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    KeepLocal,
    UseRemote,
    Merge,
}

/// Provider-neutral synchronization metadata from `schemas/pim/records.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncMetadata {
    pub state: SyncState,
    pub local_revision: u64,
    pub remote_revision: Option<String>,
    pub updated_at: String,
    pub last_error: Option<SyncError>,
    pub conflict: Option<Conflict>,
}

impl SyncMetadata {
    fn local(now: &str) -> Self {
        Self {
            state: SyncState::LocalOnly,
            local_revision: 1,
            remote_revision: None,
            updated_at: now.to_string(),
            last_error: None,
            conflict: None,
        }
    }

    fn advance(&mut self, mode: MutationMode, now: &str) {
        self.local_revision += 1;
        self.state = match mode {
            MutationMode::LocalOnly => SyncState::LocalOnly,
            MutationMode::QueueForSync { offline: false } => SyncState::Pending,
            MutationMode::QueueForSync { offline: true } => SyncState::Offline,
        };
        self.updated_at = now.to_string();
        self.last_error = None;
        self.conflict = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Calendar {
    pub kind: CalendarKind,
    pub calendar_id: String,
    pub account_id: Option<String>,
    pub title: String,
    pub color: String,
    pub read_only: bool,
    pub sync: SyncMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarKind {
    Calendar,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventWhen {
    Date {
        start_date: String,
        end_date: String,
        timezone: String,
    },
    DateTime {
        starts_at: String,
        ends_at: String,
        timezone: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailAddress {
    pub name: Option<String>,
    pub address: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttendeeRole {
    Organizer,
    Required,
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttendeeResponse {
    NeedsAction,
    Accepted,
    Declined,
    Tentative,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attendee {
    pub address: EmailAddress,
    pub role: AttendeeRole,
    pub response: AttendeeResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarEvent {
    pub kind: CalendarEventKind,
    pub event_id: String,
    pub calendar_id: String,
    pub title: String,
    pub when: EventWhen,
    pub location: Option<String>,
    pub description: Option<String>,
    pub recurrence_rule: Option<String>,
    pub attendees: Vec<Attendee>,
    pub sync: SyncMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarEventKind {
    CalendarEvent,
}

/// Caller-supplied event fields. Identity and synchronization metadata are
/// always minted by the service, never accepted from an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventInput {
    pub calendar_id: String,
    pub title: String,
    pub when: EventWhen,
    pub location: Option<String>,
    pub description: Option<String>,
    pub recurrence_rule: Option<String>,
    pub attendees: Vec<Attendee>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReminderList {
    pub kind: ReminderListKind,
    pub list_id: String,
    pub account_id: Option<String>,
    pub title: String,
    pub color: String,
    pub sync: SyncMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReminderListKind {
    ReminderList,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReminderDue {
    Date { date: String, timezone: String },
    DateTime { at: String, timezone: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reminder {
    pub kind: ReminderKind,
    pub reminder_id: String,
    pub list_id: String,
    pub title: String,
    pub notes: Option<String>,
    pub due: Option<ReminderDue>,
    pub recurrence_rule: Option<String>,
    pub completed_at: Option<String>,
    pub sync: SyncMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReminderKind {
    Reminder,
}

/// Caller-supplied reminder fields. Identity, completion state and sync
/// metadata are service-owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReminderInput {
    pub list_id: String,
    pub title: String,
    pub notes: Option<String>,
    pub due: Option<ReminderDue>,
    pub recurrence_rule: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Calendar,
    CalendarEvent,
    ReminderList,
    Reminder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOperation {
    Upsert,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeEvent {
    pub kind: ChangeEventKind,
    pub change_id: String,
    pub entity_kind: EntityKind,
    pub operation: ChangeOperation,
    pub entity_id: String,
    pub revision: u64,
    pub changed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeEventKind {
    ChangeEvent,
}
