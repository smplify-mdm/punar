//! The NDJSON envelope punard speaks to its control plane (docs/api/ipc.md
//! section 3, verbatim): one request line, one answer line, `result` xor
//! `error`. This is the same wire shape `punar-mock-smplify` serves in CI, so
//! punard needs no transport change to talk to the real thing.
use punar_common::ipc::{PROTOCOL_VERSION, RequestEnvelope};
use serde_json::{Value, json};

/// Error codes on the wire. punard turns any `error` line into a structured
/// refusal keyed on this string, so the set is shared with the mock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    MalformedRequest,
    UnsupportedVersion,
    UnknownMethod,
    InvalidParams,
    Unauthorized,
    NotFound,
    Denied,
    OutOfScope,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::MalformedRequest => "malformed_request",
            ErrorCode::UnsupportedVersion => "unsupported_version",
            ErrorCode::UnknownMethod => "unknown_method",
            ErrorCode::InvalidParams => "invalid_params",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Denied => "denied",
            ErrorCode::OutOfScope => "out_of_scope",
            ErrorCode::Internal => "internal",
        }
    }
}

/// A refusal the daemon can put on the wire. The message is written for the
/// person running `punarctl`, never for a log parser, and never carries a
/// secret.
#[derive(Debug)]
pub struct CallError {
    pub code: ErrorCode,
    pub message: String,
}

impl CallError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> CallError {
        CallError {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug)]
pub struct ParsedRequest {
    pub id: String,
    pub method: String,
    pub params: Option<Value>,
}

/// Parse one request line. Unknown fields, a bad version, an empty or
/// over-long id, or a method that is not dotted lowercase are refused.
pub fn parse_request_line(line: &str) -> Result<ParsedRequest, CallError> {
    let envelope: RequestEnvelope = serde_json::from_str(line)
        .map_err(|_| CallError::new(ErrorCode::MalformedRequest, "not a request envelope"))?;
    if envelope.v != PROTOCOL_VERSION {
        return Err(CallError::new(
            ErrorCode::UnsupportedVersion,
            format!("protocol version {} is not served", envelope.v),
        ));
    }
    if envelope.id.is_empty() || envelope.id.len() > 64 {
        return Err(CallError::new(
            ErrorCode::MalformedRequest,
            "id must be 1-64 characters",
        ));
    }
    if envelope.method.is_empty()
        || !envelope
            .method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_' || b.is_ascii_digit())
    {
        return Err(CallError::new(
            ErrorCode::MalformedRequest,
            "method is not dotted lowercase",
        ));
    }
    Ok(ParsedRequest {
        id: envelope.id,
        method: envelope.method,
        params: envelope.params,
    })
}

pub fn result_line(id: &str, result: &Value) -> String {
    let mut line = json!({ "v": PROTOCOL_VERSION, "id": id, "result": result }).to_string();
    line.push('\n');
    line
}

pub fn error_line(id: Option<&str>, error: &CallError) -> String {
    let mut line = json!({
        "v": PROTOCOL_VERSION,
        "id": id,
        "error": { "code": error.code.as_str(), "message": error.message },
    })
    .to_string();
    line.push('\n');
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_established_envelope() {
        let parsed = parse_request_line(
            r#"{"v":1,"id":"r-1","method":"org.discover","params":{"domain":"acme.com"}}"#,
        )
        .unwrap();
        assert_eq!(parsed.method, "org.discover");
        assert_eq!(parsed.params, Some(json!({"domain": "acme.com"})));
    }

    #[test]
    fn refuses_wrong_version_unknown_fields_and_bad_ids() {
        let e = parse_request_line(r#"{"v":2,"id":"r-9","method":"org.discover"}"#).unwrap_err();
        assert_eq!(e.code, ErrorCode::UnsupportedVersion);
        let e =
            parse_request_line(r#"{"v":1,"id":"r-9","method":"org.discover","x":1}"#).unwrap_err();
        assert_eq!(e.code, ErrorCode::MalformedRequest);
        let e = parse_request_line(r#"{"v":1,"id":"","method":"org.discover"}"#).unwrap_err();
        assert_eq!(e.code, ErrorCode::MalformedRequest);
        let e = parse_request_line(r#"{"v":1,"id":"r","method":"Org.Discover"}"#).unwrap_err();
        assert_eq!(e.code, ErrorCode::MalformedRequest);
    }

    #[test]
    fn lines_carry_result_xor_error() {
        let ok: Value = serde_json::from_str(&result_line("r-1", &json!({"a": 1}))).unwrap();
        assert_eq!(ok["result"]["a"], 1);
        assert!(ok.get("error").is_none());
        let err: Value = serde_json::from_str(&error_line(
            Some("r-1"),
            &CallError::new(ErrorCode::Unauthorized, "no"),
        ))
        .unwrap();
        assert_eq!(err["error"]["code"], "unauthorized");
        assert!(err.get("result").is_none());
    }
}
