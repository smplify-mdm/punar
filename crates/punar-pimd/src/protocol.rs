//! Strict, bounded v1 application protocol parsing for `punar-pimd`.
//!
//! This is deliberately transport-agnostic. The future socket-activated
//! service hands one already-admitted capability channel to these functions;
//! there is no listener here. Admission chooses the [`PimClient`] first, then
//! `decode_request` applies its closed method table before method-specific
//! parameters can be deserialized.

use std::io::{self, BufRead, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use thiserror::Error;

use crate::PimClient;

const PROTOCOL_VERSION: u64 = 1;
pub(crate) const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 64;
const MAX_METHOD_BYTES: usize = 96;

/// Closed PIM method table. There is no generic execution, filesystem,
/// provider, network or secret operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PimMethod {
    ServiceStatus,
    AccountsList,
    AccountsBeginConnect,
    AccountsCancelConnect,
    AccountsRemove,
    SyncTrigger,
    MailList,
    MailThread,
    MailMessageBody,
    MailDraftCreate,
    MailDraftUpdate,
    MailSend,
    MailArchive,
    MailDelete,
    CalendarList,
    EventsList,
    EventsCreate,
    EventsUpdate,
    EventsDelete,
    EventsRespond,
    ReminderListsList,
    RemindersList,
    RemindersCreate,
    RemindersUpdate,
    RemindersComplete,
    RemindersDelete,
    ContactsSearch,
    ChangesSince,
}

impl PimMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ServiceStatus => "service.status",
            Self::AccountsList => "accounts.list",
            Self::AccountsBeginConnect => "accounts.begin_connect",
            Self::AccountsCancelConnect => "accounts.cancel_connect",
            Self::AccountsRemove => "accounts.remove",
            Self::SyncTrigger => "sync.trigger",
            Self::MailList => "mail.list",
            Self::MailThread => "mail.thread",
            Self::MailMessageBody => "mail.message_body",
            Self::MailDraftCreate => "mail.draft_create",
            Self::MailDraftUpdate => "mail.draft_update",
            Self::MailSend => "mail.send",
            Self::MailArchive => "mail.archive",
            Self::MailDelete => "mail.delete",
            Self::CalendarList => "calendar.list",
            Self::EventsList => "events.list",
            Self::EventsCreate => "events.create",
            Self::EventsUpdate => "events.update",
            Self::EventsDelete => "events.delete",
            Self::EventsRespond => "events.respond",
            Self::ReminderListsList => "reminder_lists.list",
            Self::RemindersList => "reminders.list",
            Self::RemindersCreate => "reminders.create",
            Self::RemindersUpdate => "reminders.update",
            Self::RemindersComplete => "reminders.complete",
            Self::RemindersDelete => "reminders.delete",
            Self::ContactsSearch => "contacts.search",
            Self::ChangesSince => "changes.since",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "service.status" => Self::ServiceStatus,
            "accounts.list" => Self::AccountsList,
            "accounts.begin_connect" => Self::AccountsBeginConnect,
            "accounts.cancel_connect" => Self::AccountsCancelConnect,
            "accounts.remove" => Self::AccountsRemove,
            "sync.trigger" => Self::SyncTrigger,
            "mail.list" => Self::MailList,
            "mail.thread" => Self::MailThread,
            "mail.message_body" => Self::MailMessageBody,
            "mail.draft_create" => Self::MailDraftCreate,
            "mail.draft_update" => Self::MailDraftUpdate,
            "mail.send" => Self::MailSend,
            "mail.archive" => Self::MailArchive,
            "mail.delete" => Self::MailDelete,
            "calendar.list" => Self::CalendarList,
            "events.list" => Self::EventsList,
            "events.create" => Self::EventsCreate,
            "events.update" => Self::EventsUpdate,
            "events.delete" => Self::EventsDelete,
            "events.respond" => Self::EventsRespond,
            "reminder_lists.list" => Self::ReminderListsList,
            "reminders.list" => Self::RemindersList,
            "reminders.create" => Self::RemindersCreate,
            "reminders.update" => Self::RemindersUpdate,
            "reminders.complete" => Self::RemindersComplete,
            "reminders.delete" => Self::RemindersDelete,
            "contacts.search" => Self::ContactsSearch,
            "changes.since" => Self::ChangesSince,
            _ => return None,
        })
    }
}

/// An envelope that has passed size, syntax, version, id, closed-method and
/// per-client authorization checks. Method-specific code may now parse params.
#[derive(Debug, Clone, PartialEq)]
pub struct PimRequest {
    pub id: String,
    pub method: PimMethod,
    params: Value,
}

impl PimRequest {
    /// Deserialize a method's closed parameter object. Unknown properties
    /// must be rejected by the target type with `deny_unknown_fields`.
    pub fn parse_params<T: DeserializeOwned>(&self) -> Result<T, PimProtocolError> {
        serde_json::from_value(self.params.clone()).map_err(|_| {
            PimProtocolError::new(
                ErrorCode::InvalidParams,
                "The request parameters do not match this method.",
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    MalformedRequest,
    UnsupportedVersion,
    UnknownMethod,
    InvalidParams,
    Denied,
    NotFound,
    Conflict,
    Offline,
    InvalidCursor,
    CursorExpired,
    RateLimited,
    StorageEncryptionRequired,
    UpstreamAuthRequired,
    UpstreamUnreachable,
    UnsupportedProvider,
    Internal,
}

/// Small safe error metadata. Provider responses, URLs, headers, file paths
/// and credential material are intentionally not representable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_versions: Option<Vec<u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PimProtocolError {
    pub code: ErrorCode,
    pub message: String,
    pub details: ErrorDetails,
}

impl PimProtocolError {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: ErrorDetails::default(),
        }
    }
}

/// A rejected request may be answered only when both correlation fields were
/// independently validated. Otherwise the connection layer closes the
/// channel rather than inventing an id or reflecting attacker-controlled text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFailure {
    pub id: Option<String>,
    pub method: Option<String>,
    pub error: Box<PimProtocolError>,
}

impl RequestFailure {
    fn bare(error: PimProtocolError) -> Self {
        Self {
            id: None,
            method: None,
            error: Box::new(error),
        }
    }

    fn with_context(id: Option<String>, method: Option<String>, error: PimProtocolError) -> Self {
        Self {
            id,
            method,
            error: Box::new(error),
        }
    }
}

/// Parse one newline-free request payload. The admitted client identity is
/// required up front; a cross-client method is denied before typed params are
/// touched.
pub fn decode_request(client: PimClient, frame: &[u8]) -> Result<PimRequest, RequestFailure> {
    if frame.len() > MAX_REQUEST_BYTES {
        return Err(RequestFailure::bare(PimProtocolError::new(
            ErrorCode::MalformedRequest,
            "The request exceeds the maximum frame size.",
        )));
    }
    let value: Value = serde_json::from_slice(frame).map_err(|_| {
        RequestFailure::bare(PimProtocolError::new(
            ErrorCode::MalformedRequest,
            "The request is not valid UTF-8 JSON.",
        ))
    })?;
    let object = value.as_object().ok_or_else(|| {
        RequestFailure::bare(PimProtocolError::new(
            ErrorCode::MalformedRequest,
            "The request envelope must be an object.",
        ))
    })?;

    let id = object
        .get("id")
        .and_then(Value::as_str)
        .and_then(|value| valid_request_id(value).then(|| value.to_string()));
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .and_then(|value| valid_method_name(value).then(|| value.to_string()));

    const KEYS: [&str; 4] = ["v", "id", "method", "params"];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(RequestFailure::with_context(
            id,
            method,
            PimProtocolError::new(
                ErrorCode::MalformedRequest,
                "The request envelope has missing or unknown fields.",
            ),
        ));
    }
    let Some(id) = id else {
        return Err(RequestFailure::bare(PimProtocolError::new(
            ErrorCode::MalformedRequest,
            "The request id is missing or invalid.",
        )));
    };
    let Some(method_name) = method else {
        return Err(RequestFailure::with_context(
            Some(id),
            None,
            PimProtocolError::new(
                ErrorCode::MalformedRequest,
                "The request method name is missing or invalid.",
            ),
        ));
    };
    if object.get("v").and_then(Value::as_u64) != Some(PROTOCOL_VERSION) {
        let mut error = PimProtocolError::new(
            ErrorCode::UnsupportedVersion,
            "This PIM protocol version is not supported.",
        );
        error.details.supported_versions = Some(vec![PROTOCOL_VERSION]);
        return Err(RequestFailure::with_context(
            Some(id),
            Some(method_name),
            error,
        ));
    }
    let Some(method) = PimMethod::parse(&method_name) else {
        return Err(RequestFailure::with_context(
            Some(id),
            Some(method_name),
            PimProtocolError::new(
                ErrorCode::UnknownMethod,
                "The requested method does not exist.",
            ),
        ));
    };
    if !client.allows_method(method.as_str()) {
        return Err(RequestFailure::with_context(
            Some(id),
            Some(method_name),
            PimProtocolError::new(
                ErrorCode::Denied,
                "This application is not allowed to use the requested method.",
            ),
        ));
    }
    let params = object.get("params").expect("closed envelope checked");
    if !params.is_object() {
        return Err(RequestFailure::with_context(
            Some(id),
            Some(method_name),
            PimProtocolError::new(
                ErrorCode::InvalidParams,
                "The request parameters must be an object.",
            ),
        ));
    }
    Ok(PimRequest {
        id,
        method,
        params: params.clone(),
    })
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_method_name(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_METHOD_BYTES
        || value.starts_with('.')
        || value.ends_with('.')
    {
        return false;
    }
    let mut dot = false;
    for byte in value.bytes() {
        match byte {
            b'.' => dot = true,
            b'a'..=b'z' | b'0'..=b'9' | b'_' => {}
            _ => return false,
        }
    }
    dot
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SuccessEnvelope<'a, T> {
    v: u64,
    id: &'a str,
    method: &'a str,
    result: T,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ErrorEnvelope<'a> {
    v: u64,
    id: &'a str,
    method: &'a str,
    error: &'a PimProtocolError,
}

/// Encode a successful response payload without its terminating newline.
pub fn encode_success<T: Serialize>(
    request: &PimRequest,
    result: T,
) -> Result<Vec<u8>, FrameError> {
    encode(&SuccessEnvelope {
        v: PROTOCOL_VERSION,
        id: &request.id,
        method: request.method.as_str(),
        result,
    })
}

/// Encode an error response when a rejected request carried safe correlation
/// fields. `None` tells the connection layer to close without reflection.
pub fn encode_error(failure: &RequestFailure) -> Result<Option<Vec<u8>>, FrameError> {
    let (Some(id), Some(method)) = (&failure.id, &failure.method) else {
        return Ok(None);
    };
    Ok(Some(encode(&ErrorEnvelope {
        v: PROTOCOL_VERSION,
        id,
        method,
        error: &failure.error,
    })?))
}

/// Encode a method-level error after an admitted request reached its typed
/// dispatcher. Unlike [`encode_error`], the request correlation fields have
/// already passed the closed envelope checks.
pub fn encode_request_error(
    request: &PimRequest,
    error: &PimProtocolError,
) -> Result<Vec<u8>, FrameError> {
    encode(&ErrorEnvelope {
        v: PROTOCOL_VERSION,
        id: &request.id,
        method: request.method.as_str(),
        error,
    })
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, FrameError> {
    let bytes = serde_json::to_vec(value).map_err(FrameError::Encode)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(FrameError::ResponseTooLarge);
    }
    Ok(bytes)
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("PIM channel I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("PIM request frame exceeds {MAX_REQUEST_BYTES} bytes")]
    RequestTooLarge,
    #[error("PIM request channel closed mid-frame")]
    UnterminatedRequest,
    #[error("PIM response frame exceeds {MAX_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
    #[error("PIM response encoding failed: {0}")]
    Encode(serde_json::Error),
}

/// Read one newline-delimited request with a hard allocation bound. Any frame
/// error is connection-fatal so bytes after an oversized/truncated message are
/// never reinterpreted as a new request.
pub fn read_request_frame(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, FrameError> {
    let mut frame = Vec::new();
    let mut bounded = io::Read::take(reader, (MAX_REQUEST_BYTES + 2) as u64);
    let read = bounded.read_until(b'\n', &mut frame)?;
    if read == 0 {
        return Ok(None);
    }
    if frame.last() != Some(&b'\n') {
        return Err(if frame.len() > MAX_REQUEST_BYTES {
            FrameError::RequestTooLarge
        } else {
            FrameError::UnterminatedRequest
        });
    }
    frame.pop();
    if frame.last() == Some(&b'\r') {
        frame.pop();
    }
    if frame.len() > MAX_REQUEST_BYTES {
        return Err(FrameError::RequestTooLarge);
    }
    Ok(Some(frame))
}

/// Write one bounded response and its newline in a single buffered operation.
pub fn write_response_frame(writer: &mut impl Write, frame: &[u8]) -> Result<(), FrameError> {
    if frame.len() > MAX_RESPONSE_BYTES {
        return Err(FrameError::ResponseTooLarge);
    }
    writer.write_all(frame)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::{Map, json};
    use std::io::{BufReader, Cursor};

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct CompleteParams {
        reminder_id: String,
        if_revision: u64,
        completed: bool,
    }

    fn request(
        client: PimClient,
        method: &str,
        params: Value,
    ) -> Result<PimRequest, RequestFailure> {
        let frame = serde_json::to_vec(&json!({
            "v": 1,
            "id": "request-1",
            "method": method,
            "params": params,
        }))
        .unwrap();
        decode_request(client, &frame)
    }

    #[test]
    fn authorized_request_parses_params_only_after_admission() {
        let decoded = request(
            PimClient::Reminders,
            "reminders.complete",
            json!({"reminder_id":"reminder_A1","if_revision":7,"completed":true}),
        )
        .unwrap();
        assert_eq!(decoded.method, PimMethod::RemindersComplete);
        assert_eq!(
            decoded.parse_params::<CompleteParams>().unwrap(),
            CompleteParams {
                reminder_id: "reminder_A1".into(),
                if_revision: 7,
                completed: true,
            }
        );
    }

    #[test]
    fn cross_client_method_is_denied_before_malformed_params_are_touched() {
        let denied = request(
            PimClient::Mail,
            "reminders.complete",
            json!({"password":"must never be inspected","completed":"not-a-boolean"}),
        )
        .unwrap_err();
        assert_eq!(denied.error.code, ErrorCode::Denied);
    }

    #[test]
    fn generic_execution_and_secret_methods_are_outside_the_table() {
        for method in ["system.exec", "secrets.get", "provider.raw_request"] {
            let failure = request(PimClient::Settings, method, json!({})).unwrap_err();
            assert_eq!(failure.error.code, ErrorCode::UnknownMethod);
            let encoded = encode_error(&failure).unwrap().unwrap();
            let response: Value = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(response["method"], method);
            assert_eq!(response["error"]["code"], "unknown_method");
            assert!(response.get("result").is_none());
        }
    }

    #[test]
    fn closed_envelope_and_params_reject_extensions() {
        let top_level = br#"{"v":1,"id":"x","method":"service.status","params":{},"profile_id":"profile_other"}"#;
        let failure = decode_request(PimClient::Settings, top_level).unwrap_err();
        assert_eq!(failure.error.code, ErrorCode::MalformedRequest);

        let request = request(
            PimClient::Reminders,
            "reminders.complete",
            json!({
                "reminder_id":"reminder_A1",
                "if_revision":7,
                "completed":true,
                "profile_id":"profile_other"
            }),
        )
        .unwrap();
        assert_eq!(
            request.parse_params::<CompleteParams>().unwrap_err().code,
            ErrorCode::InvalidParams
        );
    }

    #[test]
    fn unsupported_version_reports_only_the_closed_supported_set() {
        let frame = br#"{"v":2,"id":"x","method":"service.status","params":{}}"#;
        let failure = decode_request(PimClient::Settings, frame).unwrap_err();
        assert_eq!(failure.error.code, ErrorCode::UnsupportedVersion);
        assert_eq!(failure.error.details.supported_versions, Some(vec![1]));
    }

    #[test]
    fn unsafe_correlation_fields_are_not_reflected() {
        let frame = br#"{"v":1,"id":"<script>","method":"service.status","params":{}}"#;
        let failure = decode_request(PimClient::Settings, frame).unwrap_err();
        assert!(failure.id.is_none());
        assert!(encode_error(&failure).unwrap().is_none());
    }

    #[test]
    fn success_and_error_envelopes_have_exactly_one_body() {
        let decoded = request(PimClient::Settings, "service.status", json!({})).unwrap();
        let success = encode_success(&decoded, json!({"kind":"service_status"})).unwrap();
        let success: Value = serde_json::from_slice(&success).unwrap();
        assert!(success.get("result").is_some());
        assert!(success.get("error").is_none());

        let failure = request(PimClient::Mail, "events.delete", json!({})).unwrap_err();
        let error = encode_error(&failure).unwrap().unwrap();
        let error: Value = serde_json::from_slice(&error).unwrap();
        assert!(error.get("result").is_none());
        assert!(error.get("error").is_some());
    }

    #[test]
    fn newline_frames_are_bounded_and_crlf_is_accepted() {
        let mut reader = BufReader::new(Cursor::new(b"one\r\ntwo\n"));
        assert_eq!(
            read_request_frame(&mut reader).unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(
            read_request_frame(&mut reader).unwrap(),
            Some(b"two".to_vec())
        );
        assert_eq!(read_request_frame(&mut reader).unwrap(), None);

        let oversized = vec![b'x'; MAX_REQUEST_BYTES + 1];
        let mut reader = BufReader::new(Cursor::new(oversized));
        assert!(matches!(
            read_request_frame(&mut reader),
            Err(FrameError::RequestTooLarge)
        ));
    }

    #[test]
    fn unterminated_frames_fail_and_responses_end_in_one_newline() {
        let mut reader = BufReader::new(Cursor::new(b"{}"));
        assert!(matches!(
            read_request_frame(&mut reader),
            Err(FrameError::UnterminatedRequest)
        ));

        let mut output = Vec::new();
        write_response_frame(&mut output, br#"{"v":1}"#).unwrap();
        assert_eq!(output, b"{\"v\":1}\n");
    }

    #[test]
    fn every_typed_method_matches_the_client_partition_spelling() {
        let methods = [
            PimMethod::ServiceStatus,
            PimMethod::AccountsList,
            PimMethod::AccountsBeginConnect,
            PimMethod::AccountsCancelConnect,
            PimMethod::AccountsRemove,
            PimMethod::SyncTrigger,
            PimMethod::MailList,
            PimMethod::MailThread,
            PimMethod::MailMessageBody,
            PimMethod::MailDraftCreate,
            PimMethod::MailDraftUpdate,
            PimMethod::MailSend,
            PimMethod::MailArchive,
            PimMethod::MailDelete,
            PimMethod::CalendarList,
            PimMethod::EventsList,
            PimMethod::EventsCreate,
            PimMethod::EventsUpdate,
            PimMethod::EventsDelete,
            PimMethod::EventsRespond,
            PimMethod::ReminderListsList,
            PimMethod::RemindersList,
            PimMethod::RemindersCreate,
            PimMethod::RemindersUpdate,
            PimMethod::RemindersComplete,
            PimMethod::RemindersDelete,
            PimMethod::ContactsSearch,
            PimMethod::ChangesSince,
        ];
        for method in methods {
            assert_eq!(PimMethod::parse(method.as_str()), Some(method));
            assert!(
                [
                    PimClient::Mail,
                    PimClient::Calendar,
                    PimClient::Reminders,
                    PimClient::Settings,
                    PimClient::AccountConnect,
                    PimClient::AccountManager,
                ]
                .into_iter()
                .any(|client| client.allows_method(method.as_str()))
            );
        }
    }

    #[test]
    fn response_size_is_checked_before_writing() {
        let mut output = Vec::new();
        let oversized = vec![0_u8; MAX_RESPONSE_BYTES + 1];
        assert!(matches!(
            write_response_frame(&mut output, &oversized),
            Err(FrameError::ResponseTooLarge)
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn envelope_object_is_not_mutated_during_decode() {
        let mut original = Map::new();
        original.insert("v".into(), json!(1));
        original.insert("id".into(), json!("x"));
        original.insert("method".into(), json!("service.status"));
        original.insert("params".into(), json!({}));
        let bytes = serde_json::to_vec(&original).unwrap();
        decode_request(PimClient::Settings, &bytes).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            Value::Object(original)
        );
    }
}
