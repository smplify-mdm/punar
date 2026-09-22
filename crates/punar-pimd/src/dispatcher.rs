//! Store-backed dispatch for the provider-free Calendar/Reminders slice.
//!
//! This is deliberately not a complete PIM service: provider accounts, mail,
//! contacts, event filtering and reminder filtering remain closed until their
//! semantics are implemented. The methods below prove that admitted
//! capability channels can reach durable local mutations, stable structural
//! lists and the bounded change stream without accepting profile or credential
//! fields from an application.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    ClientGrant, CursorSigner, ErrorCode, ErrorDetails, EventInput, MutationMode, PageError,
    PagedValues, PimMethod, PimProtocolError, PimRequest, PimStore, ReminderInput, SnapshotPager,
    StoreError,
};

const DEFAULT_PAGE_LIMIT: usize = 50;
const CALENDAR_LIST_BINDING: &[u8] = b"calendar.list:calendar_id:v1";
const REMINDER_LIST_BINDING: &[u8] = b"reminder_lists.list:list_id:v1";
const ACCOUNT_LIST_BINDING: &[u8] = b"accounts.list:account_id:v1";

pub struct LocalDispatcher {
    store: PimStore,
    pager: SnapshotPager,
}

impl LocalDispatcher {
    #[must_use]
    pub fn new(store: PimStore, signer: CursorSigner) -> Self {
        Self {
            store,
            pager: SnapshotPager::new(signer),
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
                    "accounts": 0,
                    "last_change_cursor": self.pager.seal_change_cursor(snapshot.revision).map_err(map_page_error)?,
                }))
            }
            PimMethod::AccountsList => {
                let params = request.parse_params::<PageParams>()?;
                let page = self.page(
                    request.method,
                    ACCOUNT_LIST_BINDING,
                    snapshot.revision,
                    &Vec::<Value>::new(),
                    params,
                )?;
                Ok(page_result("account_page", page))
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
    use crate::{PimClient, decode_request};
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    struct Fixture {
        root: PathBuf,
        dispatcher: LocalDispatcher,
    }

    impl Fixture {
        fn new() -> Self {
            let mut suffix = [0_u8; 12];
            getrandom::fill(&mut suffix).unwrap();
            let suffix = suffix
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let root = std::env::temp_dir().join(format!("punar-pimd-dispatch-test-{suffix}"));
            let store = PimStore::open(&root.join("store.json"), "profile_A1", 1000).unwrap();
            let signer = CursorSigner::from_key([9; 32], "profile_A1").unwrap();
            Self {
                root,
                dispatcher: LocalDispatcher::new(store, signer),
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
}
