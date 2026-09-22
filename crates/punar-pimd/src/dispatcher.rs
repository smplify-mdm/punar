//! Store-backed dispatch for local Calendar/Reminders and read-only Mail.
//!
//! This is deliberately not a complete PIM service: account lifecycle, Mail
//! mutation/send, contacts, event filtering and reminder filtering remain
//! closed until their semantics are implemented. The methods below prove that
//! admitted capability channels can reach durable local mutations, stable
//! structural lists, revision-consistent Mail pages and the bounded change
//! stream without accepting profile or credential fields from an application.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::store::validate_account_id;
use crate::{
    AccountCapability, AccountConnectError, AccountConnectLifecycle, AccountLifecycle,
    AccountLifecycleError, AccountSetupStage, ClientGrant, CursorPosition, CursorSigner, ErrorCode,
    ErrorDetails, EventInput, MailStore, MailStoreError, MutationMode, PageError, PagedValues,
    PimMethod, PimProtocolError, PimRequest, PimStore, ProviderType, ReminderInput, SnapshotPager,
    StoreError, SyncCoordinator, SyncTriggerError,
};

const DEFAULT_PAGE_LIMIT: usize = 50;
const CALENDAR_LIST_BINDING: &[u8] = b"calendar.list:calendar_id:v1";
const REMINDER_LIST_BINDING: &[u8] = b"reminder_lists.list:list_id:v1";
const ACCOUNT_LIST_BINDING: &[u8] = b"accounts.list:account_id:v1";
const MAIL_CURSOR_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_MAIL_CURSORS: usize = 1024;

pub struct LocalDispatcher {
    store: Arc<PimStore>,
    mail_store: Arc<MailStore>,
    pager: SnapshotPager,
    mail_cursors: Mutex<HashMap<u64, MailCursorState>>,
    sync: Option<Arc<SyncCoordinator>>,
    account_lifecycle: Option<Arc<dyn AccountLifecycle>>,
    account_connect: Option<Arc<dyn AccountConnectLifecycle>>,
}

struct MailCursorState {
    before: String,
    last_used: Instant,
}

impl LocalDispatcher {
    #[must_use]
    pub fn new(store: PimStore, mail_store: MailStore, signer: CursorSigner) -> Self {
        Self::from_shared(
            Arc::new(store),
            Arc::new(mail_store),
            signer,
            None,
            None,
            None,
        )
    }

    #[must_use]
    pub fn with_sync(
        store: Arc<PimStore>,
        mail_store: Arc<MailStore>,
        signer: CursorSigner,
        sync: Arc<SyncCoordinator>,
    ) -> Self {
        Self::from_shared(store, mail_store, signer, Some(sync), None, None)
    }

    #[must_use]
    pub fn with_runtime(
        store: Arc<PimStore>,
        mail_store: Arc<MailStore>,
        signer: CursorSigner,
        sync: Arc<SyncCoordinator>,
        account_lifecycle: Arc<dyn AccountLifecycle>,
        account_connect: Arc<dyn AccountConnectLifecycle>,
    ) -> Self {
        Self::from_shared(
            store,
            mail_store,
            signer,
            Some(sync),
            Some(account_lifecycle),
            Some(account_connect),
        )
    }

    fn from_shared(
        store: Arc<PimStore>,
        mail_store: Arc<MailStore>,
        signer: CursorSigner,
        sync: Option<Arc<SyncCoordinator>>,
        account_lifecycle: Option<Arc<dyn AccountLifecycle>>,
        account_connect: Option<Arc<dyn AccountConnectLifecycle>>,
    ) -> Self {
        Self {
            store,
            mail_store,
            pager: SnapshotPager::new(signer),
            mail_cursors: Mutex::new(HashMap::new()),
            sync,
            account_lifecycle,
            account_connect,
        }
    }

    /// Dispatch the locally implemented method subset. The trusted grant uid
    /// is checked against the bound store on every call as defense in depth.
    pub fn dispatch(
        &self,
        grant: &ClientGrant,
        request: &PimRequest,
    ) -> Result<Value, PimProtocolError> {
        let snapshot = self.store.snapshot();
        if grant.profile_uid != snapshot.profile_uid {
            return Err(PimProtocolError::new(
                ErrorCode::Denied,
                "This channel belongs to another profile.",
            ));
        }
        match request.method {
            PimMethod::ServiceStatus => {
                request.parse_params::<EmptyParams>()?;
                Ok(json!({
                    "kind": "service_status",
                    "protocol_version": 1,
                    "service_version": env!("CARGO_PKG_VERSION"),
                    "profile_id": snapshot.profile_id,
                    "profile_uid": snapshot.profile_uid,
                    "storage_encryption": "unverified",
                    "connectivity": "unknown",
                    "accounts": snapshot.accounts.len(),
                    "last_change_cursor": self.pager.seal_change_cursor(snapshot.revision).map_err(map_page_error)?,
                }))
            }
            PimMethod::AccountsList => {
                let params = request.parse_params::<PageParams>()?;
                let page = self.page(
                    request.method,
                    ACCOUNT_LIST_BINDING,
                    snapshot.revision,
                    &snapshot.accounts,
                    params,
                )?;
                Ok(page_result("account_page", page))
            }
            PimMethod::AccountsBeginConnect => {
                let params = request.parse_params::<BeginConnectParams>()?;
                let lifecycle = self.account_connect.as_ref().ok_or_else(internal)?;
                let setup = lifecycle
                    .begin(params.provider_type)
                    .map_err(map_account_connect_error)?;
                Ok(json!({
                    "kind": "account_setup",
                    "setup_id": setup.setup_id,
                    "provider_type": setup.provider_type,
                    "state": match setup.state {
                        AccountSetupStage::AwaitingCredentials => "awaiting_credentials",
                        AccountSetupStage::Discovering => "discovering",
                    },
                }))
            }
            PimMethod::AccountsCancelConnect => {
                let params = request.parse_params::<CancelConnectParams>()?;
                let lifecycle = self.account_connect.as_ref().ok_or_else(internal)?;
                lifecycle
                    .cancel(&params.setup_id)
                    .map_err(map_account_connect_error)?;
                self.completed_operation(&params.setup_id)
            }
            PimMethod::AccountsRemove => {
                let params = request.parse_params::<RemoveAccountParams>()?;
                validate_account_id(&params.account_id).map_err(map_store_error)?;
                let lifecycle = self.account_lifecycle.as_ref().ok_or_else(internal)?;
                lifecycle
                    .remove_account(&params.account_id, params.delete_local_data)
                    .map_err(map_account_lifecycle_error)?;
                self.completed_operation(&params.account_id)
            }
            PimMethod::CalendarList => {
                let params = request.parse_params::<PageParams>()?;
                let page = self.page(
                    request.method,
                    CALENDAR_LIST_BINDING,
                    snapshot.revision,
                    &snapshot.calendars,
                    params,
                )?;
                Ok(page_result("calendar_page", page))
            }
            PimMethod::ReminderListsList => {
                let params = request.parse_params::<PageParams>()?;
                let page = self.page(
                    request.method,
                    REMINDER_LIST_BINDING,
                    snapshot.revision,
                    &snapshot.reminder_lists,
                    params,
                )?;
                Ok(page_result("reminder_list_page", page))
            }
            PimMethod::MailList => {
                let params = request.parse_params::<MailListParams>()?;
                self.mail_list(&snapshot, params)
            }
            PimMethod::MailThread => {
                let params = request.parse_params::<MailThreadParams>()?;
                self.mail_thread(params)
            }
            PimMethod::SyncTrigger => {
                let params = request.parse_params::<SyncParams>()?;
                let account_id = params.account_id.ok_or_else(invalid_params)?;
                validate_account_id(&account_id).map_err(map_store_error)?;
                let sync = self.sync.as_ref().ok_or_else(internal)?;
                let accepted = sync.trigger(&account_id).map_err(map_sync_trigger_error)?;
                Ok(json!({
                    "kind": "operation",
                    "operation_id": accepted.operation_id,
                    "state": "accepted",
                    "resource_id": accepted.account_id,
                    "change_cursor": self.pager
                        .seal_change_cursor(snapshot.revision)
                        .map_err(map_page_error)?,
                }))
            }
            PimMethod::EventsCreate => {
                let params = request.parse_params::<EventCreateParams>()?;
                let record = self
                    .store
                    .create_event(params.event, MutationMode::LocalOnly, &now())
                    .map_err(map_store_error)?;
                serde_json::to_value(record).map_err(|_| internal())
            }
            PimMethod::EventsUpdate => {
                let params = request.parse_params::<EventUpdateParams>()?;
                require_revision(params.if_revision)?;
                let record = self
                    .store
                    .update_event(
                        &params.event_id,
                        params.if_revision,
                        params.event,
                        MutationMode::LocalOnly,
                        &now(),
                    )
                    .map_err(map_store_error)?;
                serde_json::to_value(record).map_err(|_| internal())
            }
            PimMethod::EventsDelete => {
                let params = request.parse_params::<EventRevisionParams>()?;
                require_revision(params.if_revision)?;
                self.store
                    .delete_event(&params.event_id, params.if_revision, &now())
                    .map_err(map_store_error)?;
                self.completed_operation(&params.event_id)
            }
            PimMethod::RemindersCreate => {
                let params = request.parse_params::<ReminderCreateParams>()?;
                let record = self
                    .store
                    .create_reminder(params.reminder, MutationMode::LocalOnly, &now())
                    .map_err(map_store_error)?;
                serde_json::to_value(record).map_err(|_| internal())
            }
            PimMethod::RemindersUpdate => {
                let params = request.parse_params::<ReminderUpdateParams>()?;
                require_revision(params.if_revision)?;
                let record = self
                    .store
                    .update_reminder(
                        &params.reminder_id,
                        params.if_revision,
                        params.reminder,
                        MutationMode::LocalOnly,
                        &now(),
                    )
                    .map_err(map_store_error)?;
                serde_json::to_value(record).map_err(|_| internal())
            }
            PimMethod::RemindersComplete => {
                let params = request.parse_params::<ReminderCompleteParams>()?;
                require_revision(params.if_revision)?;
                let record = self
                    .store
                    .complete_reminder(
                        &params.reminder_id,
                        params.if_revision,
                        params.completed,
                        MutationMode::LocalOnly,
                        &now(),
                    )
                    .map_err(map_store_error)?;
                serde_json::to_value(record).map_err(|_| internal())
            }
            PimMethod::RemindersDelete => {
                let params = request.parse_params::<ReminderRevisionParams>()?;
                require_revision(params.if_revision)?;
                self.store
                    .delete_reminder(&params.reminder_id, params.if_revision, &now())
                    .map_err(map_store_error)?;
                self.completed_operation(&params.reminder_id)
            }
            PimMethod::ChangesSince => {
                let params = request.parse_params::<ChangesParams>()?;
                if params.limit == 0 || params.limit > 1000 {
                    return Err(invalid_params());
                }
                let sequence = match params.cursor {
                    Some(cursor) => self
                        .pager
                        .open_change_cursor(&cursor)
                        .map_err(map_page_error)?,
                    None => 0,
                };
                let page = self
                    .store
                    .changes_since(sequence, params.limit)
                    .map_err(map_store_error)?;
                Ok(json!({
                    "kind": "change_page",
                    "items": page.changes,
                    "next_cursor": self.pager.seal_change_cursor(page.next_sequence).map_err(map_page_error)?,
                    "has_more": page.has_more,
                }))
            }
            _ => Err(PimProtocolError::new(
                ErrorCode::Internal,
                "This PIM method is not staged in the local dispatcher yet.",
            )),
        }
    }

    fn page<T: serde::Serialize>(
        &self,
        method: PimMethod,
        binding: &[u8],
        revision: u64,
        items: &[T],
        params: PageParams,
    ) -> Result<PagedValues, PimProtocolError> {
        match params.cursor {
            Some(cursor) => self
                .pager
                .next(method, binding, &cursor, params.limit)
                .map_err(map_page_error),
            None => self
                .pager
                .start(method, binding, revision, items, params.limit)
                .map_err(map_page_error),
        }
    }

    fn completed_operation(&self, resource_id: &str) -> Result<Value, PimProtocolError> {
        let revision = self.store.snapshot().revision;
        Ok(json!({
            "kind": "operation",
            "operation_id": mint_operation_id().map_err(|_| internal())?,
            "state": "completed",
            "resource_id": resource_id,
            "change_cursor": self.pager.seal_change_cursor(revision).map_err(map_page_error)?,
        }))
    }

    fn mail_list(
        &self,
        snapshot: &crate::Snapshot,
        params: MailListParams,
    ) -> Result<Value, PimProtocolError> {
        if params.view != MailView::Inbox || params.query.is_some() {
            return Err(invalid_params());
        }
        let account_id = params.account_id.ok_or_else(invalid_params)?;
        validate_account_id(&account_id).map_err(map_store_error)?;
        let account = snapshot
            .accounts
            .iter()
            .find(|account| account.account_id == account_id)
            .ok_or_else(|| {
                PimProtocolError::new(ErrorCode::NotFound, "The Mail account was not found.")
            })?;
        if !account.capabilities.contains(&AccountCapability::Mail) {
            return Err(invalid_params());
        }

        let page_binding = mail_list_binding(&account_id, false);
        let snapshot_binding = mail_list_binding(&account_id, true);
        let (before, expected_revision) = match params.cursor {
            Some(cursor) => {
                let position = self
                    .pager
                    .open_position(&cursor, PimMethod::MailList, &page_binding)
                    .map_err(map_page_error)?;
                let before = self.mail_cursor_before(position.position)?;
                (Some(before), Some(position.snapshot))
            }
            None => (None, None),
        };
        let page = self
            .mail_store
            .list_summaries_at(
                &account_id,
                before.as_deref(),
                params.limit,
                expected_revision,
            )
            .map_err(map_mail_store_error)?;
        let next_cursor = page
            .next_before
            .as_deref()
            .map(|before| {
                let token = self.remember_mail_cursor(before)?;
                self.pager
                    .seal_position(
                        PimMethod::MailList,
                        &page_binding,
                        CursorPosition {
                            snapshot: page.revision,
                            position: token,
                        },
                    )
                    .map_err(map_page_error)
            })
            .transpose()?;
        let snapshot_cursor = self
            .pager
            .seal_position(
                PimMethod::MailList,
                &snapshot_binding,
                CursorPosition {
                    snapshot: page.revision,
                    position: 0,
                },
            )
            .map_err(map_page_error)?;
        Ok(json!({
            "kind": "mail_page",
            "items": page.summaries,
            "page": {
                "next_cursor": next_cursor,
                "snapshot_cursor": snapshot_cursor,
            },
        }))
    }

    fn mail_thread(&self, params: MailThreadParams) -> Result<Value, PimProtocolError> {
        let page_binding = mail_thread_binding(&params.thread_id, false);
        let snapshot_binding = mail_thread_binding(&params.thread_id, true);
        let (offset, expected_revision) = match params.cursor {
            Some(cursor) => {
                let position = self
                    .pager
                    .open_position(&cursor, PimMethod::MailThread, &page_binding)
                    .map_err(map_page_error)?;
                let offset = usize::try_from(position.position).map_err(|_| invalid_params())?;
                (offset, Some(position.snapshot))
            }
            None => (0, None),
        };
        let page = self
            .mail_store
            .thread_for_profile(&params.thread_id, offset, params.limit, expected_revision)
            .map_err(map_mail_store_error)?;
        let next_cursor = page
            .next_offset
            .map(|offset| {
                self.pager
                    .seal_position(
                        PimMethod::MailThread,
                        &page_binding,
                        CursorPosition {
                            snapshot: page.revision,
                            position: u64::try_from(offset).map_err(|_| invalid_params())?,
                        },
                    )
                    .map_err(map_page_error)
            })
            .transpose()?;
        let snapshot_cursor = self
            .pager
            .seal_position(
                PimMethod::MailThread,
                &snapshot_binding,
                CursorPosition {
                    snapshot: page.revision,
                    position: 0,
                },
            )
            .map_err(map_page_error)?;
        Ok(json!({
            "kind": "mail_thread",
            "thread_id": page.thread_id,
            "account_id": page.account_id,
            "subject": page.subject,
            "messages": page.messages,
            "next_cursor": next_cursor,
            "snapshot_cursor": snapshot_cursor,
            "sync": page.sync,
        }))
    }

    fn remember_mail_cursor(&self, before: &str) -> Result<u64, PimProtocolError> {
        let now = Instant::now();
        let mut cursors = self.mail_cursors.lock().unwrap();
        cursors.retain(|_, state| {
            now.checked_duration_since(state.last_used)
                .is_none_or(|age| age < MAIL_CURSOR_TTL)
        });
        if cursors.len() >= MAX_MAIL_CURSORS
            && let Some(oldest) = cursors
                .iter()
                .min_by_key(|(_, state)| state.last_used)
                .map(|(token, _)| *token)
        {
            cursors.remove(&oldest);
        }
        for _ in 0..8 {
            let mut bytes = [0_u8; 8];
            getrandom::fill(&mut bytes).map_err(|_| internal())?;
            let token = u64::from_le_bytes(bytes);
            if token != 0 && !cursors.contains_key(&token) {
                cursors.insert(
                    token,
                    MailCursorState {
                        before: before.to_string(),
                        last_used: now,
                    },
                );
                return Ok(token);
            }
        }
        Err(internal())
    }

    fn mail_cursor_before(&self, token: u64) -> Result<String, PimProtocolError> {
        let now = Instant::now();
        let mut cursors = self.mail_cursors.lock().unwrap();
        cursors.retain(|_, state| {
            now.checked_duration_since(state.last_used)
                .is_none_or(|age| age < MAIL_CURSOR_TTL)
        });
        let state = cursors.get_mut(&token).ok_or_else(|| {
            PimProtocolError::new(
                ErrorCode::CursorExpired,
                "The Mail page snapshot expired; refresh the inbox.",
            )
        })?;
        state.last_used = now;
        Ok(state.before.clone())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageParams {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default = "default_page_limit")]
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveAccountParams {
    account_id: String,
    delete_local_data: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BeginConnectParams {
    provider_type: ProviderType,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelConnectParams {
    setup_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MailView {
    Inbox,
    Starred,
    Attachments,
    Drafts,
    Sent,
    Archive,
    Junk,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MailListParams {
    account_id: Option<String>,
    view: MailView,
    query: Option<String>,
    cursor: Option<String>,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MailThreadParams {
    thread_id: String,
    cursor: Option<String>,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncParams {
    account_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventCreateParams {
    event: EventInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventUpdateParams {
    event_id: String,
    if_revision: u64,
    event: EventInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventRevisionParams {
    event_id: String,
    if_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReminderCreateParams {
    reminder: ReminderInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReminderUpdateParams {
    reminder_id: String,
    if_revision: u64,
    reminder: ReminderInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReminderCompleteParams {
    reminder_id: String,
    if_revision: u64,
    completed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReminderRevisionParams {
    reminder_id: String,
    if_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangesParams {
    cursor: Option<String>,
    limit: usize,
}

fn default_page_limit() -> usize {
    DEFAULT_PAGE_LIMIT
}

fn page_result(kind: &str, page: PagedValues) -> Value {
    json!({
        "kind": kind,
        "items": page.items,
        "page": {
            "next_cursor": page.next_cursor,
            "snapshot_cursor": page.snapshot_cursor,
        }
    })
}

fn require_revision(revision: u64) -> Result<(), PimProtocolError> {
    if revision == 0 {
        Err(invalid_params())
    } else {
        Ok(())
    }
}

fn map_page_error(error: PageError) -> PimProtocolError {
    match error {
        PageError::InvalidLimit => invalid_params(),
        PageError::InvalidCursor => PimProtocolError::new(
            ErrorCode::InvalidCursor,
            "The page cursor is invalid for this request.",
        ),
        PageError::CursorExpired => PimProtocolError::new(
            ErrorCode::CursorExpired,
            "The page snapshot expired; refresh the list.",
        ),
        PageError::SnapshotTooLarge => PimProtocolError::new(
            ErrorCode::RateLimited,
            "The result set exceeds the stable paging budget.",
        ),
        PageError::Encode => internal(),
    }
}

fn map_store_error(error: StoreError) -> PimProtocolError {
    match error {
        StoreError::Invalid(_) => invalid_params(),
        StoreError::NotFound => {
            PimProtocolError::new(ErrorCode::NotFound, "The requested record was not found.")
        }
        StoreError::Conflict { current_revision } => PimProtocolError {
            code: ErrorCode::Conflict,
            message: "The record changed; refresh it before trying again.".into(),
            details: ErrorDetails {
                current_revision: Some(current_revision),
                ..ErrorDetails::default()
            },
        },
        StoreError::CursorExpired => PimProtocolError::new(
            ErrorCode::CursorExpired,
            "The change cursor expired; refresh a full snapshot.",
        ),
        StoreError::ProfileMismatch => PimProtocolError::new(
            ErrorCode::Denied,
            "The local store belongs to another profile.",
        ),
        StoreError::Io(_) | StoreError::Corrupt(_) | StoreError::UnsupportedVersion { .. } => {
            internal()
        }
    }
}

fn map_mail_store_error(error: MailStoreError) -> PimProtocolError {
    match error {
        MailStoreError::Invalid(_) => invalid_params(),
        MailStoreError::NotFound => PimProtocolError::new(
            ErrorCode::NotFound,
            "The requested Mail record was not found.",
        ),
        MailStoreError::CursorExpired => PimProtocolError::new(
            ErrorCode::CursorExpired,
            "The Mail snapshot changed; refresh the inbox.",
        ),
        MailStoreError::ProfileMismatch => PimProtocolError::new(
            ErrorCode::Denied,
            "The Mail store belongs to another profile.",
        ),
        MailStoreError::Io(_) | MailStoreError::Database | MailStoreError::Corrupt(_) => internal(),
    }
}

fn map_sync_trigger_error(error: SyncTriggerError) -> PimProtocolError {
    match error {
        SyncTriggerError::NotFound => {
            PimProtocolError::new(ErrorCode::NotFound, "The Mail account was not found.")
        }
        SyncTriggerError::UnsupportedAccount => PimProtocolError::new(
            ErrorCode::UnsupportedProvider,
            "This account does not support Mail synchronization.",
        ),
        SyncTriggerError::AuthRequired => PimProtocolError::new(
            ErrorCode::UpstreamAuthRequired,
            "The Mail account needs attention before it can synchronize.",
        ),
        SyncTriggerError::AccountRemoving => {
            PimProtocolError::new(ErrorCode::Conflict, "The Mail account is being removed.")
        }
        SyncTriggerError::RateLimited => PimProtocolError::new(
            ErrorCode::RateLimited,
            "Too many Mail accounts are synchronizing; try again shortly.",
        ),
        SyncTriggerError::Runtime => internal(),
    }
}

fn map_account_lifecycle_error(error: AccountLifecycleError) -> PimProtocolError {
    match error {
        AccountLifecycleError::NotFound => {
            PimProtocolError::new(ErrorCode::NotFound, "The Mail account was not found.")
        }
        AccountLifecycleError::Busy => PimProtocolError::new(
            ErrorCode::Conflict,
            "The Mail account is still finishing another operation.",
        ),
        AccountLifecycleError::LocalDataDeletionRequired => PimProtocolError::new(
            ErrorCode::InvalidParams,
            "Removing this account must delete its local private data.",
        ),
        AccountLifecycleError::StorageEncryptionRequired => PimProtocolError::new(
            ErrorCode::StorageEncryptionRequired,
            "Verified storage encryption is required for Mail accounts.",
        ),
        AccountLifecycleError::Internal => internal(),
    }
}

fn map_account_connect_error(error: AccountConnectError) -> PimProtocolError {
    match error {
        AccountConnectError::UnsupportedProvider => PimProtocolError::new(
            ErrorCode::UnsupportedProvider,
            "This account provider is not available yet.",
        ),
        AccountConnectError::RateLimited => PimProtocolError::new(
            ErrorCode::RateLimited,
            "Too many account setup sessions are active; try again shortly.",
        ),
        AccountConnectError::NotFound => PimProtocolError::new(
            ErrorCode::NotFound,
            "The account setup session was not found.",
        ),
        AccountConnectError::Runtime => internal(),
    }
}

fn mail_list_binding(account_id: &str, snapshot: bool) -> Vec<u8> {
    format!(
        "mail.list:v1\0{account_id}\0inbox\0{}",
        if snapshot { "snapshot" } else { "page" }
    )
    .into_bytes()
}

fn mail_thread_binding(thread_id: &str, snapshot: bool) -> Vec<u8> {
    format!(
        "mail.thread:v1\0{thread_id}\0{}",
        if snapshot { "snapshot" } else { "page" }
    )
    .into_bytes()
}

fn invalid_params() -> PimProtocolError {
    PimProtocolError::new(
        ErrorCode::InvalidParams,
        "The request parameters do not match this method.",
    )
}

fn internal() -> PimProtocolError {
    PimProtocolError::new(
        ErrorCode::Internal,
        "The local PIM service could not complete the request.",
    )
}

fn now() -> String {
    punar_common::time::utc_now_rfc3339()
}

fn mint_operation_id() -> Result<String, ()> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ())?;
    let mut suffix = String::with_capacity(32);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        suffix.push(HEX[(byte >> 4) as usize] as char);
        suffix.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(format!("op_{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Account, AccountAuthState, AccountKind, Connectivity, EmailAddress, MailBatchItem,
        MailIngestInput, MailServerConfig, MailServerSecurity, MailSyncReport, MailSyncRunner,
        OpenProtocolConfig, PimClient, ProviderType, SyncCoordinator, SyncFailure, decode_request,
        ingest_message,
    };
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    struct Fixture {
        root: PathBuf,
        dispatcher: LocalDispatcher,
    }

    impl Fixture {
        fn new() -> Self {
            Self::build(false)
        }

        fn with_mail() -> Self {
            Self::build(true)
        }

        fn with_sync() -> Self {
            let mut suffix = [0_u8; 12];
            getrandom::fill(&mut suffix).unwrap();
            let suffix = suffix
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let root = std::env::temp_dir().join(format!("punar-pimd-dispatch-test-{suffix}"));
            let store =
                Arc::new(PimStore::open(&root.join("store.json"), "profile_A1", 1000).unwrap());
            store
                .register_open_protocol_account(
                    account("acct_A1", "Alice"),
                    provider_config("alice@example.com"),
                    "2026-09-22T17:00:00Z",
                )
                .unwrap();
            let mail_store =
                Arc::new(MailStore::open(&root.join("mail.redb"), "profile_A1", 1000).unwrap());
            let runner: Arc<dyn MailSyncRunner> = Arc::new(ImmediateSync);
            let sync = SyncCoordinator::new(Arc::clone(&store), runner);
            let signer = CursorSigner::from_key([9; 32], "profile_A1").unwrap();
            Self {
                root,
                dispatcher: LocalDispatcher::with_sync(store, mail_store, signer, sync),
            }
        }

        fn with_lifecycle(lifecycle: Arc<dyn AccountLifecycle>) -> Self {
            let connect: Arc<dyn AccountConnectLifecycle> = Arc::new(RecordingConnect::default());
            Self::with_account_runtime(lifecycle, connect)
        }

        fn with_account_runtime(
            lifecycle: Arc<dyn AccountLifecycle>,
            connect: Arc<dyn AccountConnectLifecycle>,
        ) -> Self {
            let mut suffix = [0_u8; 12];
            getrandom::fill(&mut suffix).unwrap();
            let suffix = suffix
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let root = std::env::temp_dir().join(format!("punar-pimd-dispatch-test-{suffix}"));
            let store =
                Arc::new(PimStore::open(&root.join("store.json"), "profile_A1", 1000).unwrap());
            store
                .register_open_protocol_account(
                    account("acct_A1", "Alice"),
                    provider_config("alice@example.com"),
                    "2026-09-22T17:00:00Z",
                )
                .unwrap();
            let mail_store =
                Arc::new(MailStore::open(&root.join("mail.redb"), "profile_A1", 1000).unwrap());
            let runner: Arc<dyn MailSyncRunner> = Arc::new(ImmediateSync);
            let sync = SyncCoordinator::new(Arc::clone(&store), runner);
            let signer = CursorSigner::from_key([9; 32], "profile_A1").unwrap();
            Self {
                root,
                dispatcher: LocalDispatcher::with_runtime(
                    store, mail_store, signer, sync, lifecycle, connect,
                ),
            }
        }

        fn build(with_mail: bool) -> Self {
            let mut suffix = [0_u8; 12];
            getrandom::fill(&mut suffix).unwrap();
            let suffix = suffix
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let root = std::env::temp_dir().join(format!("punar-pimd-dispatch-test-{suffix}"));
            let store = PimStore::open(&root.join("store.json"), "profile_A1", 1000).unwrap();
            let mail_store = MailStore::open(&root.join("mail.redb"), "profile_A1", 1000).unwrap();
            if with_mail {
                store
                    .register_open_protocol_account(
                        account("acct_A1", "Alice"),
                        provider_config("alice@example.com"),
                        "2026-09-22T17:00:00Z",
                    )
                    .unwrap();
                store
                    .register_open_protocol_account(
                        account("acct_B2", "Bob"),
                        provider_config("bob@example.com"),
                        "2026-09-22T17:00:00Z",
                    )
                    .unwrap();
                mail_store
                    .store_batch(
                        "acct_A1",
                        "INBOX",
                        7,
                        vec![mail_item(1, "First", "One"), mail_item(2, "Second", "Two")],
                        2,
                    )
                    .unwrap();
            }
            let signer = CursorSigner::from_key([9; 32], "profile_A1").unwrap();
            Self {
                root,
                dispatcher: LocalDispatcher::new(store, mail_store, signer),
            }
        }

        fn call(
            &self,
            client: PimClient,
            method: &str,
            params: Value,
        ) -> Result<Value, PimProtocolError> {
            let frame = serde_json::to_vec(&json!({
                "v": 1,
                "id": "test-1",
                "method": method,
                "params": params,
            }))
            .unwrap();
            let request = decode_request(client, &frame).unwrap();
            self.dispatcher
                .dispatch(&ClientGrant::new("grant_A1", 1000, client), &request)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn status_and_structural_lists_are_fixture_free() {
        let fixture = Fixture::new();
        let status = fixture
            .call(PimClient::Calendar, "service.status", json!({}))
            .unwrap();
        assert_eq!(status["storage_encryption"], "unverified");
        assert_eq!(status["accounts"], 0);

        let calendars = fixture
            .call(PimClient::Calendar, "calendar.list", json!({}))
            .unwrap();
        assert_eq!(calendars["items"].as_array().unwrap().len(), 1);
        assert_eq!(calendars["items"][0]["title"], "Personal");
        assert!(!calendars.to_string().contains("demo"));
    }

    #[test]
    fn calendar_mutation_is_durable_and_visible_in_the_change_stream() {
        let fixture = Fixture::new();
        let calendar_id = fixture
            .call(PimClient::Calendar, "calendar.list", json!({}))
            .unwrap()["items"][0]["calendar_id"]
            .as_str()
            .unwrap()
            .to_string();
        let event = fixture
            .call(
                PimClient::Calendar,
                "events.create",
                json!({"event": {
                    "calendar_id": calendar_id,
                    "title": "Design review",
                    "when": {
                        "kind": "date_time",
                        "starts_at": "2026-09-22T18:00:00Z",
                        "ends_at": "2026-09-22T18:30:00Z",
                        "timezone": "UTC"
                    },
                    "location": null,
                    "description": null,
                    "recurrence_rule": null,
                    "attendees": []
                }}),
            )
            .unwrap();
        assert_eq!(event["title"], "Design review");
        let changes = fixture
            .call(
                PimClient::Calendar,
                "changes.since",
                json!({"cursor":null,"limit":10}),
            )
            .unwrap();
        assert_eq!(changes["items"].as_array().unwrap().len(), 1);
        assert_eq!(changes["items"][0]["operation"], "upsert");
    }

    #[test]
    fn stale_revision_returns_typed_conflict_without_rewrite() {
        let fixture = Fixture::new();
        let list_id = fixture
            .call(PimClient::Reminders, "reminder_lists.list", json!({}))
            .unwrap()["items"][0]["list_id"]
            .as_str()
            .unwrap()
            .to_string();
        let reminder = fixture
            .call(
                PimClient::Reminders,
                "reminders.create",
                json!({"reminder": {
                    "list_id": list_id,
                    "title": "Review release",
                    "notes": null,
                    "due": null,
                    "recurrence_rule": null
                }}),
            )
            .unwrap();
        let error = fixture
            .call(
                PimClient::Reminders,
                "reminders.complete",
                json!({
                    "reminder_id": reminder["reminder_id"],
                    "if_revision": 7,
                    "completed": true
                }),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(error.details.current_revision, Some(1));
    }

    #[test]
    fn grant_uid_mismatch_is_denied_before_params_are_parsed() {
        let fixture = Fixture::new();
        let frame = br#"{"v":1,"id":"test-1","method":"events.create","params":{"password":"never inspect"}}"#;
        let request = decode_request(PimClient::Calendar, frame).unwrap();
        let error = fixture
            .dispatcher
            .dispatch(
                &ClientGrant::new("grant_A1", 1001, PimClient::Calendar),
                &request,
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Denied);
    }

    #[test]
    fn malformed_record_ids_are_invalid_params_not_resource_probes() {
        let fixture = Fixture::new();
        let error = fixture
            .call(
                PimClient::Calendar,
                "events.delete",
                json!({"event_id":"../../etc/shadow","if_revision":1}),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
        assert!(error.details.resource_id.is_none());
    }

    #[test]
    fn mail_pages_and_threads_are_real_store_records_without_fixture_fallbacks() {
        let fixture = Fixture::with_mail();
        let first = fixture
            .call(
                PimClient::Mail,
                "mail.list",
                json!({
                    "account_id":"acct_A1",
                    "view":"inbox",
                    "query":null,
                    "cursor":null,
                    "limit":1
                }),
            )
            .unwrap();
        assert_eq!(first["kind"], "mail_page");
        assert_eq!(first["items"].as_array().unwrap().len(), 1);
        assert!(first["page"]["next_cursor"].is_string());
        assert!(!first.to_string().to_lowercase().contains("fixture"));
        assert!(!first.to_string().to_lowercase().contains("demo"));

        let second = fixture
            .call(
                PimClient::Mail,
                "mail.list",
                json!({
                    "account_id":"acct_A1",
                    "view":"inbox",
                    "query":null,
                    "cursor":first["page"]["next_cursor"],
                    "limit":1
                }),
            )
            .unwrap();
        assert_eq!(second["items"].as_array().unwrap().len(), 1);
        assert_ne!(
            first["items"][0]["thread_id"],
            second["items"][0]["thread_id"]
        );

        let thread = fixture
            .call(
                PimClient::Mail,
                "mail.thread",
                json!({
                    "thread_id":first["items"][0]["thread_id"],
                    "cursor":null,
                    "limit":20
                }),
            )
            .unwrap();
        assert_eq!(thread["kind"], "mail_thread");
        assert_eq!(thread["account_id"], "acct_A1");
        assert_eq!(thread["messages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn mail_cursor_cannot_cross_accounts_or_survive_a_sync_revision() {
        let fixture = Fixture::with_mail();
        let first = fixture
            .call(
                PimClient::Mail,
                "mail.list",
                json!({
                    "account_id":"acct_A1",
                    "view":"inbox",
                    "query":null,
                    "cursor":null,
                    "limit":1
                }),
            )
            .unwrap();
        let cursor = first["page"]["next_cursor"].clone();
        let cross_account = fixture
            .call(
                PimClient::Mail,
                "mail.list",
                json!({
                    "account_id":"acct_B2",
                    "view":"inbox",
                    "query":null,
                    "cursor":cursor,
                    "limit":1
                }),
            )
            .unwrap_err();
        assert_eq!(cross_account.code, ErrorCode::InvalidCursor);

        fixture
            .dispatcher
            .mail_store
            .store_batch(
                "acct_A1",
                "INBOX",
                7,
                vec![mail_item(3, "Third", "Three")],
                3,
            )
            .unwrap();
        let stale = fixture
            .call(
                PimClient::Mail,
                "mail.list",
                json!({
                    "account_id":"acct_A1",
                    "view":"inbox",
                    "query":null,
                    "cursor":first["page"]["next_cursor"],
                    "limit":1
                }),
            )
            .unwrap_err();
        assert_eq!(stale.code, ErrorCode::CursorExpired);
    }

    #[test]
    fn malformed_mail_params_are_rejected_before_store_access() {
        let fixture = Fixture::with_mail();
        let error = fixture
            .call(
                PimClient::Mail,
                "mail.list",
                json!({
                    "account_id":"acct_A1",
                    "view":"inbox",
                    "query":null,
                    "cursor":null,
                    "limit":20,
                    "password":"must never be accepted"
                }),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
    }

    #[test]
    fn settings_sync_trigger_returns_an_accepted_operation_without_network_blocking() {
        let fixture = Fixture::with_sync();
        let operation = fixture
            .call(
                PimClient::Settings,
                "sync.trigger",
                json!({"account_id":"acct_A1"}),
            )
            .unwrap();
        assert_eq!(operation["kind"], "operation");
        assert_eq!(operation["state"], "accepted");
        assert_eq!(operation["resource_id"], "acct_A1");
        assert!(
            operation["operation_id"]
                .as_str()
                .unwrap()
                .starts_with("op_")
        );
        let started = Instant::now();
        while fixture.dispatcher.store.snapshot().accounts[0]
            .last_sync_at
            .is_none()
        {
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::yield_now();
        }
    }

    #[test]
    fn settings_account_removal_uses_only_the_guarded_lifecycle() {
        let lifecycle = Arc::new(RecordingLifecycle::default());
        let lifecycle_trait: Arc<dyn AccountLifecycle> = lifecycle.clone();
        let fixture = Fixture::with_lifecycle(lifecycle_trait);
        let operation = fixture
            .call(
                PimClient::Settings,
                "accounts.remove",
                json!({"account_id":"acct_A1","delete_local_data":true}),
            )
            .unwrap();
        assert_eq!(operation["kind"], "operation");
        assert_eq!(operation["state"], "completed");
        assert_eq!(operation["resource_id"], "acct_A1");
        assert_eq!(
            lifecycle.calls.lock().unwrap().as_slice(),
            &[("acct_A1".to_string(), true)]
        );

        let error = fixture
            .call(
                PimClient::Settings,
                "accounts.remove",
                json!({"account_id":"acct_A1","delete_local_data":false}),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);

        let error = fixture
            .call(
                PimClient::Settings,
                "accounts.remove",
                json!({"account_id":"../../vault","delete_local_data":true}),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
        assert_eq!(lifecycle.calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn settings_account_setup_is_opaque_bounded_and_cancellable() {
        let lifecycle: Arc<dyn AccountLifecycle> = Arc::new(RecordingLifecycle::default());
        let connect = Arc::new(RecordingConnect::default());
        let connect_trait: Arc<dyn AccountConnectLifecycle> = connect.clone();
        let fixture = Fixture::with_account_runtime(lifecycle, connect_trait);

        let setup = fixture
            .call(
                PimClient::Settings,
                "accounts.begin_connect",
                json!({"provider_type":"open_protocols"}),
            )
            .unwrap();
        assert_eq!(setup["kind"], "account_setup");
        assert_eq!(setup["setup_id"], "setup_A1");
        assert_eq!(setup["provider_type"], "open_protocols");
        assert_eq!(setup["state"], "awaiting_credentials");
        assert_eq!(
            connect.begins.lock().unwrap().as_slice(),
            &[ProviderType::OpenProtocols]
        );

        let operation = fixture
            .call(
                PimClient::Settings,
                "accounts.cancel_connect",
                json!({"setup_id":"setup_A1"}),
            )
            .unwrap();
        assert_eq!(operation["state"], "completed");
        assert_eq!(operation["resource_id"], "setup_A1");
        assert_eq!(connect.cancels.lock().unwrap().as_slice(), &["setup_A1"]);

        let unsupported = fixture
            .call(
                PimClient::Settings,
                "accounts.begin_connect",
                json!({"provider_type":"google"}),
            )
            .unwrap_err();
        assert_eq!(unsupported.code, ErrorCode::UnsupportedProvider);

        let secret = fixture
            .call(
                PimClient::Settings,
                "accounts.begin_connect",
                json!({"provider_type":"open_protocols","password":"never accepted"}),
            )
            .unwrap_err();
        assert_eq!(secret.code, ErrorCode::InvalidParams);
    }

    #[derive(Default)]
    struct RecordingLifecycle {
        calls: Mutex<Vec<(String, bool)>>,
    }

    impl AccountLifecycle for RecordingLifecycle {
        fn remove_account(
            &self,
            account_id: &str,
            delete_local_data: bool,
        ) -> Result<(), AccountLifecycleError> {
            self.calls
                .lock()
                .unwrap()
                .push((account_id.to_string(), delete_local_data));
            if delete_local_data {
                Ok(())
            } else {
                Err(AccountLifecycleError::LocalDataDeletionRequired)
            }
        }
    }

    #[derive(Default)]
    struct RecordingConnect {
        begins: Mutex<Vec<ProviderType>>,
        cancels: Mutex<Vec<String>>,
    }

    impl AccountConnectLifecycle for RecordingConnect {
        fn begin(
            &self,
            provider_type: ProviderType,
        ) -> Result<crate::AccountSetupStatus, AccountConnectError> {
            self.begins.lock().unwrap().push(provider_type);
            if provider_type != ProviderType::OpenProtocols {
                return Err(AccountConnectError::UnsupportedProvider);
            }
            Ok(crate::AccountSetupStatus {
                setup_id: "setup_A1".into(),
                provider_type,
                state: AccountSetupStage::AwaitingCredentials,
            })
        }

        fn cancel(&self, setup_id: &str) -> Result<(), AccountConnectError> {
            self.cancels.lock().unwrap().push(setup_id.to_string());
            Ok(())
        }
    }

    struct ImmediateSync;

    impl MailSyncRunner for ImmediateSync {
        fn sync_account(&self, _account_id: &str) -> Result<MailSyncReport, SyncFailure> {
            Ok(MailSyncReport {
                uid_validity: 7,
                last_uid: 1,
                fetched: 1,
                skipped_malformed: 0,
            })
        }
    }

    fn account(account_id: &str, display_name: &str) -> Account {
        Account {
            kind: AccountKind::Account,
            account_id: account_id.into(),
            provider_type: ProviderType::OpenProtocols,
            display_name: display_name.into(),
            primary_address: Some(EmailAddress {
                name: Some(display_name.into()),
                address: format!("{}@example.com", display_name.to_lowercase()),
            }),
            capabilities: vec![AccountCapability::Mail],
            auth_state: AccountAuthState::Ready,
            connectivity: Connectivity::Online,
            last_sync_at: None,
            next_retry_at: None,
        }
    }

    fn provider_config(username: &str) -> OpenProtocolConfig {
        OpenProtocolConfig {
            username: username.into(),
            imap: MailServerConfig {
                host: "imap.example.com".into(),
                port: 993,
                security: MailServerSecurity::Tls,
            },
            smtp: MailServerConfig {
                host: "smtp.example.com".into(),
                port: 465,
                security: MailServerSecurity::Tls,
            },
        }
    }

    fn mail_item(uid: u32, subject: &str, body: &str) -> MailBatchItem {
        let raw = format!(
            "From: Sender {uid} <sender{uid}@example.com>\r\nTo: Alice <alice@example.com>\r\nMessage-ID: <dispatch-{uid}@example.com>\r\nDate: Mon, 22 Sep 2026 16:00:0{uid} +0000\r\nSubject: {subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}"
        );
        MailBatchItem {
            uid,
            parsed: ingest_message(MailIngestInput {
                account_id: "acct_A1",
                mailbox_id: "INBOX",
                uid_validity: 7,
                uid,
                received_at: "2026-09-22T16:00:00Z",
                unread: true,
                starred: false,
                labels: &["Inbox".into()],
                raw_message: raw.as_bytes(),
            })
            .unwrap(),
        }
    }
}
