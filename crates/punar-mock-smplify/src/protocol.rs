//! NDJSON envelope handling — the `docs/api/ipc.md` sections 2/3 framing
//! verbatim, with the mock's own (closed) error-code vocabulary.
//!
//! The request side reuses `punar_common::ipc` wholesale: the strict
//! [`RequestEnvelope`], [`PROTOCOL_VERSION`], the 4096-byte line limit, and
//! the staged parse pipeline mirrored from `Request::parse_json_line`
//! (length → JSON shape → version → strict envelope → id bounds). Only the
//! last stage differs: the mock dispatches on its own method table
//! (`crate::server`), not `punard`'s closed [`Method`] enum — the two
//! protocols share framing, not methods.
//!
//! The error vocabulary is the mock's own because the control-plane hop has
//! a failure `punard`'s local IPC deliberately lacks: [`unauthorized`]
//! (unknown `device_token`), standing in for production mTLS/device-auth
//! rejection so `punard`'s error path is testable (milestone-5.md section
//! 4.2). The rest of the set matches ipc.md section 4 spellings so nobody
//! learns two dialects.
//!
//! [`Method`]: punar_common::ipc::Method
//! [`unauthorized`]: ErrorCode::Unauthorized

use punar_common::ipc::{
    MAX_REQUEST_LINE_BYTES, PROTOCOL_VERSION, REQUEST_ID_MAX_CHARS, REQUEST_ID_MIN_CHARS,
    RequestEnvelope,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The mock control-plane's closed error-code set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Line not valid JSON / envelope fields missing or mistyped / line
    /// over [`MAX_REQUEST_LINE_BYTES`]. Closes the connection.
    MalformedRequest,
    /// `v` != [`PROTOCOL_VERSION`]; `details.supported` lists `[1]`.
    UnsupportedVersion,
    /// Method not in the mock's table — including `admin.devices` /
    /// `admin.device`, reserved for Milestone 10 (SPEC section 51).
    UnknownMethod,
    /// Params missing/extra/mis-shaped, or a bootstrap secret that fails
    /// the ≥32-hex-chars shape check.
    InvalidParams,
    /// `device_token` not recognized. The mock-protocol stand-in for
    /// production device-auth failure (no such code exists on `punard`'s
    /// local IPC surface).
    Unauthorized,
    /// `org.discover` for a domain the fixture set does not carry.
    NotFound,
    /// Mock bug or I/O error (token generation, state persistence).
    Internal,
}

impl ErrorCode {
    /// The wire spelling (snake_case).
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::MalformedRequest => "malformed_request",
            ErrorCode::UnsupportedVersion => "unsupported_version",
            ErrorCode::UnknownMethod => "unknown_method",
            ErrorCode::InvalidParams => "invalid_params",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Internal => "internal",
        }
    }

    /// Only framing violations close the connection (ipc.md section 2).
    pub fn closes_connection(self) -> bool {
        self == ErrorCode::MalformedRequest
    }
}

/// A wire error: `code` + human `message` + optional machine `details`.
#[derive(Debug, Clone, PartialEq)]
pub struct MockError {
    pub code: ErrorCode,
    pub message: String,
    pub details: Option<Value>,
}

impl MockError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> MockError {
        MockError {
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(code: ErrorCode, message: impl Into<String>, details: Value) -> MockError {
        MockError {
            code,
            message: message.into(),
            details: Some(details),
        }
    }
}

/// A parsed request the server can dispatch: raw method + raw params. The
/// method table lives in `crate::server`, so `unknown_method` can carry the
/// reserved-name message for `admin.*`.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedRequest {
    pub id: String,
    pub method: String,
    pub params: Option<Value>,
}

/// A rejected request line: the error to send, plus the request id when one
/// could be salvaged for echoing (`None` serializes as `id: null`).
#[derive(Debug)]
pub struct Reject {
    pub id: Option<String>,
    pub error: MockError,
}

/// One success response as an NDJSON line (terminator included).
pub fn result_line(id: &str, result: &Value) -> String {
    let mut line = json!({"v": PROTOCOL_VERSION, "id": id, "result": result}).to_string();
    line.push('\n');
    line
}

/// One error response as an NDJSON line (terminator included).
pub fn error_line(id: Option<&str>, error: &MockError) -> String {
    let mut body = json!({"code": error.code.as_str(), "message": error.message});
    if let (Some(map), Some(details)) = (body.as_object_mut(), &error.details) {
        map.insert("details".to_string(), details.clone());
    }
    let id_value = match id {
        Some(id) => Value::String(id.to_string()),
        None => Value::Null,
    };
    let mut line = json!({"v": PROTOCOL_VERSION, "id": id_value, "error": body}).to_string();
    line.push('\n');
    line
}

/// Parse one request line (without its trailing `\n`) through the staged
/// pipeline of ipc.md section 4, mirrored from
/// `punar_common::ipc::Request::parse_json_line`.
pub fn parse_request_line(line: &str) -> Result<ParsedRequest, Reject> {
    // 1. Length bound (the connection loop also bounds reads; this guards
    // direct callers).
    if line.len() > MAX_REQUEST_LINE_BYTES {
        return Err(Reject {
            id: None,
            error: MockError::new(
                ErrorCode::MalformedRequest,
                format!(
                    "The request line exceeds the {MAX_REQUEST_LINE_BYTES}-byte limit. \
                     Next step: no mock control-plane method needs a longer line."
                ),
            ),
        });
    }

    // 2. Generic JSON parse, so `id` can be echoed even for envelopes that
    // fail strict validation.
    let value: Value = serde_json::from_str(line).map_err(|err| Reject {
        id: None,
        error: MockError::new(
            ErrorCode::MalformedRequest,
            format!(
                "The request line is not valid JSON: {err}. Next step: send one \
                 JSON object per line (docs/api/ipc.md section 2 framing)."
            ),
        ),
    })?;
    let Some(object) = value.as_object() else {
        return Err(Reject {
            id: None,
            error: MockError::new(
                ErrorCode::MalformedRequest,
                "The request line must be a JSON object envelope \
                 {\"v\":1,\"id\":…,\"method\":…}."
                    .to_string(),
            ),
        });
    };
    let echo_id = object
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| id_length_ok(id))
        .map(str::to_string);
    let reject = |error: MockError| Reject {
        id: echo_id.clone(),
        error,
    };

    // 3. Version, before strict field checks — a well-formed future-version
    // frame gets the version error, not a field nitpick.
    match object.get("v") {
        None => {
            return Err(reject(MockError::new(
                ErrorCode::MalformedRequest,
                "The envelope field \"v\" is required and must be the integer 1.".to_string(),
            )));
        }
        Some(v) => match v.as_u64() {
            Some(version) if version == PROTOCOL_VERSION => {}
            Some(version) => {
                return Err(reject(MockError::with_details(
                    ErrorCode::UnsupportedVersion,
                    format!(
                        "This mock control plane speaks protocol version \
                         {PROTOCOL_VERSION}; the request asked for version {version}."
                    ),
                    json!({ "supported": [PROTOCOL_VERSION] }),
                )));
            }
            None => {
                return Err(reject(MockError::new(
                    ErrorCode::MalformedRequest,
                    "The envelope field \"v\" must be the integer 1.".to_string(),
                )));
            }
        },
    }

    // 4. Strict typed envelope (rejects unknown/mistyped fields) — the
    // shared punar_common frame, so both protocols stay envelope-identical.
    let envelope: RequestEnvelope = serde_json::from_value(value.clone()).map_err(|err| {
        reject(MockError::new(
            ErrorCode::MalformedRequest,
            format!(
                "The request envelope is invalid: {err}. Next step: the envelope \
                 fields are exactly v, id, method, params (docs/api/ipc.md)."
            ),
        ))
    })?;

    // 5. Id bounds.
    if !id_length_ok(&envelope.id) {
        return Err(reject(MockError::new(
            ErrorCode::MalformedRequest,
            format!(
                "The envelope field \"id\" must be a string of \
                 {REQUEST_ID_MIN_CHARS} to {REQUEST_ID_MAX_CHARS} characters."
            ),
        )));
    }

    Ok(ParsedRequest {
        id: envelope.id,
        method: envelope.method,
        params: envelope.params,
    })
}

fn id_length_ok(id: &str) -> bool {
    let chars = id.chars().count();
    (REQUEST_ID_MIN_CHARS..=REQUEST_ID_MAX_CHARS).contains(&chars)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_request() {
        let parsed = parse_request_line(
            r#"{"v":1,"id":"r-1","method":"org.discover","params":{"domain":"acme.com"}}"#,
        )
        .expect("well-formed request parses");
        assert_eq!(parsed.id, "r-1");
        assert_eq!(parsed.method, "org.discover");
        assert_eq!(parsed.params, Some(json!({"domain": "acme.com"})));
    }

    #[test]
    fn rejects_non_json_with_null_id() {
        let reject = parse_request_line("not json").unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::MalformedRequest);
        assert!(reject.id.is_none());
        assert!(reject.error.code.closes_connection());
    }

    #[test]
    fn rejects_wrong_version_but_echoes_id() {
        let reject =
            parse_request_line(r#"{"v":2,"id":"r-9","method":"org.discover"}"#).unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::UnsupportedVersion);
        assert_eq!(reject.id.as_deref(), Some("r-9"));
        assert_eq!(
            reject.error.details,
            Some(json!({"supported": [PROTOCOL_VERSION]}))
        );
        assert!(!reject.error.code.closes_connection());
    }

    #[test]
    fn rejects_unknown_envelope_fields() {
        let reject =
            parse_request_line(r#"{"v":1,"id":"r-2","method":"x","extra":true}"#).unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::MalformedRequest);
        assert_eq!(reject.id.as_deref(), Some("r-2"));
    }

    #[test]
    fn error_line_serializes_null_id_and_optional_details() {
        let bare = error_line(None, &MockError::new(ErrorCode::Internal, "boom"));
        let value: Value = serde_json::from_str(bare.trim_end()).unwrap();
        assert_eq!(value["id"], Value::Null);
        assert_eq!(value["error"]["code"], "internal");
        assert!(value["error"].get("details").is_none());

        let detailed = error_line(
            Some("r-3"),
            &MockError::with_details(ErrorCode::NotFound, "nope", json!({"domain": "x"})),
        );
        let value: Value = serde_json::from_str(detailed.trim_end()).unwrap();
        assert_eq!(value["id"], "r-3");
        assert_eq!(value["error"]["details"]["domain"], "x");
    }
}
