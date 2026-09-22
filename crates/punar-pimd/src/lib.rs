//! `punar-pimd` — profile-scoped personal-information data service.
//!
//! The implementation contains durable local Calendar/Reminders and Mail
//! record stores plus a LUKS-gated service-private encrypted credential vault
//! and an unnamed, one-use entry channel that moves a password from a locked-down
//! helper into that vault. It now has unstaged TLS-only IMAP/SMTP account
//! verification and a bounded read-only INBOX synchronizer, but still has no
//! application listener or resident background loop. That keeps the
//! production authorization boundary honest while durability and credential
//! custody are exercised independently. The executable and socket activation
//! arrive only after ADR-008's hostile same-UID caller gate has a proven
//! mechanism.
//!
//! A newly opened store contains one blank local calendar and one blank local
//! reminder list. Those are structural containers, not demo content: accounts,
//! events and reminders are empty.

#![forbid(unsafe_code)]

mod account_entry;
mod account_setup;
mod channel;
mod connection;
mod credential_entry;
mod cursor;
mod dispatcher;
mod mail_ingest;
mod mail_store;
mod open_protocol_provider;
mod open_protocol_sync;
mod pager;
mod process_security;
mod protocol;
mod service;
mod setup_runtime;
mod store;
mod sync_runtime;
mod vault;

pub use account_entry::{
    AccountEntryCode, AccountEntryError, AccountEntryHelper, AccountEntryOutcome,
    OpenProtocolSetup, account_entry_pair, complete_account_entry,
};
pub use account_setup::{
    AccountCoordinator, AccountLifecycle, AccountLifecycleError, AccountSetupError,
    OpenProtocolAccountInput, OpenProtocolVerifier, ProviderCheckError,
    VerifiedOpenProtocolIdentity,
};
pub use channel::{
    AdmissionError, ClientGrant, GrantedChannel, PimClient, client_channel_pair,
    control_channel_pair, receive_client_channel, send_client_channel,
};
pub use connection::{ConnectionError, serve_granted_channel};
pub use credential_entry::{CredentialEntryError, CredentialEntryHelper, credential_entry_pair};
pub use cursor::{CursorError, CursorKeyError, CursorPosition, CursorSigner};
pub use dispatcher::LocalDispatcher;
pub use mail_ingest::{MailIngestError, MailIngestInput, ParsedMail, ingest_message};
pub use mail_store::{
    MailBatchItem, MailStore, MailStoreError, MailSummaryPage, MailSyncCursor, MailThreadPage,
};
pub use open_protocol_provider::NetworkOpenProtocolVerifier;
pub use open_protocol_sync::{MailSyncReport, OpenProtocolMailSynchronizer, OpenProtocolSyncError};
pub use pager::{PageError, PagedValues, SnapshotPager};
pub use process_security::{ProcessSecurityError, lock_down_current_process};
pub use protocol::{
    ErrorCode, ErrorDetails, FrameError, PimMethod, PimProtocolError, PimRequest, RequestFailure,
    decode_request, encode_error, encode_request_error, encode_success, read_request_frame,
    write_response_frame,
};
pub use service::{PimService, PimServiceError};
pub use setup_runtime::{
    AccountConnectError, AccountConnectLifecycle, AccountEntryRunner, AccountSetupStage,
    AccountSetupStatus, OpenProtocolEntryRunner, SetupSessionCoordinator,
};
pub use store::{ChangePage, MutationMode, PimStore, Snapshot, StoreError};
pub use sync_runtime::{
    AcceptedSync, AccountRemovalPermit, MailSyncRunner, OpenProtocolSyncRunner, SyncCoordinator,
    SyncFailure, SyncQuiesceError, SyncTriggerError,
};
pub use vault::{CredentialKind, CredentialVault, EncryptedStorageProof, VaultError};

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

    fn synced(now: &str, remote_revision: String) -> Self {
        Self {
            state: SyncState::Synced,
            local_revision: 1,
            remote_revision: Some(remote_revision),
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
pub enum AccountKind {
    Account,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    OpenProtocols,
    Google,
    Microsoft,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountCapability {
    Mail,
    Calendar,
    Reminders,
    Contacts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountAuthState {
    Ready,
    ActionRequired,
    Revoked,
    Removing,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Connectivity {
    Online,
    Offline,
    Limited,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub kind: AccountKind,
    pub account_id: String,
    pub provider_type: ProviderType,
    pub display_name: String,
    pub primary_address: Option<EmailAddress>,
    pub capabilities: Vec<AccountCapability>,
    pub auth_state: AccountAuthState,
    pub connectivity: Connectivity,
    pub last_sync_at: Option<String>,
    pub next_retry_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailServerSecurity {
    Tls,
    StartTls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailServerConfig {
    pub host: String,
    pub port: u16,
    pub security: MailServerSecurity,
}

/// Service-private, non-secret configuration for an open-protocol account.
/// It never appears in application records or normal PIM IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenProtocolConfig {
    pub username: String,
    pub imap: MailServerConfig,
    pub smtp: MailServerConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailSummaryKind {
    MailSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailSummary {
    pub kind: MailSummaryKind,
    pub thread_id: String,
    pub account_id: String,
    pub subject: String,
    pub correspondents: Vec<EmailAddress>,
    pub preview: String,
    pub received_at: String,
    pub unread: bool,
    pub starred: bool,
    pub attachments_count: u32,
    pub labels: Vec<String>,
    pub sync: SyncMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentQuarantineState {
    NotDownloaded,
    Quarantined,
    Released,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub attachment_id: String,
    pub filename: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub quarantine_state: AttachmentQuarantineState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailMessage {
    pub message_id: String,
    pub sender: EmailAddress,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub sent_at: String,
    pub plain_text: String,
    pub body_complete: bool,
    pub remote_content_blocked: bool,
    pub attachments: Vec<Attachment>,
    pub attachments_complete: bool,
    pub sync: SyncMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailThreadKind {
    MailThread,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailThread {
    pub kind: MailThreadKind,
    pub thread_id: String,
    pub account_id: String,
    pub subject: String,
    pub messages: Vec<MailMessage>,
    pub next_cursor: Option<String>,
    pub snapshot_cursor: String,
    pub sync: SyncMetadata,
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
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
    Account,
    MailSummary,
    MailThread,
    MailDraft,
    Calendar,
    CalendarEvent,
    ReminderList,
    Reminder,
    Contact,
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
