//! NDJSON wire envelope for the punard IPC (docs/api/ipc.md sections 2–4).
//!
//! INTERFACE NOTE (for the M3 integrate agent): the plan gives `punar-common`
//! an `ipc` module (shared with `punarctl`), being written concurrently.
//! These types implement the ipc.md contract exactly — `Request`,
//! `Response`, `WireError`, `ErrorCode`, `PROTOCOL_VERSION`,
//! `MAX_LINE_BYTES`, `parse_request_line` — so when `punar_common::ipc`
//! lands with the same contract, this module should be deleted and its
//! consumers re-pointed (`server.rs`, `tests/daemon.rs`). Nothing here is
//! punard-private by design.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The only protocol version this server speaks (ipc.md section 3.3).
pub const PROTOCOL_VERSION: u64 = 1;

/// Maximum request line length in bytes, newline included (ipc.md section 2).
pub const MAX_LINE_BYTES: usize = 4096;

/// Error codes of the v1 envelope (ipc.md section 4). Closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    MalformedRequest,
    UnsupportedVersion,
    UnknownMethod,
    InvalidParams,
    Denied,
    NotFound,
    ApplyFailed,
    VerifyFailed,
    Internal,
}

/// The `error` object of a response (ipc.md section 3.2).
///
/// `message` is human prose in the SPEC section 73 voice (what happened, why,
/// which policy, next step) — never a bare errno. `details` is the optional
/// machine layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl WireError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        WireError {
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// A parsed, envelope-valid request (ipc.md section 3.1).
#[derive(Debug, Clone)]
pub struct Request {
    /// Client correlation id, 1–64 characters, echoed verbatim.
    pub id: String,
    /// Dotted lowercase method name; membership in the method table is the
    /// dispatcher's decision, not the envelope's.
    pub method: String,
    /// Method params; `None` when omitted. Unknown fields inside are
    /// rejected per-method (`invalid_params`, strict).
    pub params: Option<Map<String, Value>>,
}

/// A response envelope. Exactly one of `result` / `error` is set (enforced
/// by the two constructors — there is no other way to build one).
#[derive(Debug, Serialize)]
pub struct Response {
    pub v: u64,
    /// `None` serializes as `id: null` — used when no id could be parsed
    /// from a malformed line (ipc.md section 4).
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<WireError>,
}

impl Response {
    pub fn ok(id: impl Into<String>, result: Value) -> Self {
        Response {
            v: PROTOCOL_VERSION,
            id: Some(id.into()),
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Option<String>, error: WireError) -> Self {
        Response {
            v: PROTOCOL_VERSION,
            id,
            result: None,
            error: Some(error),
        }
    }
}

fn malformed(reason: &str) -> WireError {
    WireError::new(
        ErrorCode::MalformedRequest,
        format!(
            "The request was not a valid punard protocol message: {reason}.\n\
             Policy: os default — punard speaks newline-delimited JSON envelopes \
             {{v, id, method, params}} (docs/api/ipc.md).\n\
             Next step: use punarctl instead of hand-writing requests."
        ),
    )
}

/// Parse and validate one request line against the v1 envelope.
///
/// On failure, returns the best-effort request id (for error attribution;
/// `None` when unparsable) alongside the typed error. Strictness rules per
/// ipc.md section 3.1: `v` required and integer `1`; `id` a 1–64 char
/// string; `method` a non-empty string; `params` an object when present;
/// unknown envelope fields rejected.
pub fn parse_request_line(line: &str) -> Result<Request, (Option<String>, WireError)> {
    let value: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Err((None, malformed("the line is not valid JSON"))),
    };
    let obj = match value.as_object() {
        Some(o) => o,
        None => return Err((None, malformed("the line is not a JSON object"))),
    };

    // Best-effort id for attributing errors found after this point.
    let salvaged_id = obj
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 64)
        .map(str::to_owned);

    for key in obj.keys() {
        if !matches!(key.as_str(), "v" | "id" | "method" | "params") {
            return Err((
                salvaged_id,
                malformed(&format!("unknown envelope field {key:?}")),
            ));
        }
    }

    let v = match obj.get("v").and_then(Value::as_u64) {
        Some(v) => v,
        None => {
            return Err((
                salvaged_id,
                malformed("the required field \"v\" is missing or not a non-negative integer"),
            ));
        }
    };
    if v != PROTOCOL_VERSION {
        return Err((
            salvaged_id,
            WireError::new(
                ErrorCode::UnsupportedVersion,
                format!(
                    "This punard speaks protocol version {PROTOCOL_VERSION}; the request asked for version {v}.\n\
                     Policy: os default — the envelope version is fixed per OS release (docs/api/ipc.md section 3.3).\n\
                     Next step: use the punarctl shipped with this OS image."
                ),
            )
            .with_details(serde_json::json!({ "supported": [PROTOCOL_VERSION] })),
        ));
    }

    let id = match obj.get("id").and_then(Value::as_str) {
        Some(s) if !s.is_empty() && s.len() <= 64 => s.to_owned(),
        _ => {
            return Err((
                salvaged_id,
                malformed("the required field \"id\" must be a string of 1-64 characters"),
            ));
        }
    };

    let method = match obj.get("method").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => {
            return Err((
                Some(id),
                malformed("the required field \"method\" must be a non-empty string"),
            ));
        }
    };

    let params = match obj.get("params") {
        None => None,
        Some(Value::Object(map)) => Some(map.clone()),
        Some(_) => {
            return Err((
                Some(id),
                malformed("the field \"params\" must be a JSON object when present"),
            ));
        }
    };

    Ok(Request { id, method, params })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_valid_request() {
        let req = parse_request_line(r#"{"v":1,"id":"req-1","method":"status"}"#).unwrap();
        assert_eq!(req.id, "req-1");
        assert_eq!(req.method, "status");
        assert!(req.params.is_none());
    }

    #[test]
    fn parses_params_object() {
        let req = parse_request_line(
            r#"{"v":1,"id":"a","method":"capabilities.get","params":{"capability":"security.firewall"}}"#,
        )
        .unwrap();
        assert_eq!(
            req.params.unwrap().get("capability").unwrap(),
            "security.firewall"
        );
    }

    #[test]
    fn rejects_invalid_json_with_null_id() {
        let (id, err) = parse_request_line("{not json").unwrap_err();
        assert_eq!(id, None);
        assert_eq!(err.code, ErrorCode::MalformedRequest);
    }

    #[test]
    fn rejects_missing_v_and_bad_v_type() {
        for line in [
            r#"{"id":"x","method":"status"}"#,
            r#"{"v":"1","id":"x","method":"status"}"#,
            r#"{"v":1.5,"id":"x","method":"status"}"#,
            r#"{"v":-1,"id":"x","method":"status"}"#,
        ] {
            let (id, err) = parse_request_line(line).unwrap_err();
            assert_eq!(err.code, ErrorCode::MalformedRequest, "{line}");
            assert_eq!(id.as_deref(), Some("x"));
        }
    }

    #[test]
    fn rejects_wrong_version_as_unsupported_with_details() {
        let (id, err) = parse_request_line(r#"{"v":2,"id":"x","method":"status"}"#).unwrap_err();
        assert_eq!(id.as_deref(), Some("x"));
        assert_eq!(err.code, ErrorCode::UnsupportedVersion);
        assert_eq!(
            err.details.unwrap(),
            serde_json::json!({ "supported": [1] })
        );
    }

    #[test]
    fn rejects_bad_ids() {
        let long = "x".repeat(65);
        for line in [
            r#"{"v":1,"method":"status"}"#.to_string(),
            r#"{"v":1,"id":"","method":"status"}"#.to_string(),
            format!(r#"{{"v":1,"id":"{long}","method":"status"}}"#),
            r#"{"v":1,"id":7,"method":"status"}"#.to_string(),
        ] {
            let (_, err) = parse_request_line(&line).unwrap_err();
            assert_eq!(err.code, ErrorCode::MalformedRequest, "{line}");
        }
    }

    #[test]
    fn rejects_unknown_envelope_fields() {
        let (id, err) =
            parse_request_line(r#"{"v":1,"id":"x","method":"status","extra":true}"#).unwrap_err();
        assert_eq!(id.as_deref(), Some("x"));
        assert_eq!(err.code, ErrorCode::MalformedRequest);
        assert!(err.message.contains("extra"));
    }

    #[test]
    fn rejects_non_object_params() {
        let (_, err) =
            parse_request_line(r#"{"v":1,"id":"x","method":"status","params":[1]}"#).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedRequest);
    }

    #[test]
    fn responses_serialize_with_exactly_one_of_result_error() {
        let ok = serde_json::to_value(Response::ok("a", serde_json::json!({"n": 1}))).unwrap();
        assert_eq!(ok["v"], 1);
        assert_eq!(ok["id"], "a");
        assert!(ok.get("result").is_some());
        assert!(ok.get("error").is_none());

        let err = serde_json::to_value(Response::err(
            None,
            WireError::new(ErrorCode::Internal, "boom"),
        ))
        .unwrap();
        assert_eq!(err["id"], Value::Null);
        assert!(err.get("result").is_none());
        assert_eq!(err["error"]["code"], "internal");
    }

    #[test]
    fn error_codes_serialize_snake_case() {
        for (code, name) in [
            (ErrorCode::MalformedRequest, "malformed_request"),
            (ErrorCode::UnsupportedVersion, "unsupported_version"),
            (ErrorCode::UnknownMethod, "unknown_method"),
            (ErrorCode::InvalidParams, "invalid_params"),
            (ErrorCode::Denied, "denied"),
            (ErrorCode::NotFound, "not_found"),
            (ErrorCode::ApplyFailed, "apply_failed"),
            (ErrorCode::VerifyFailed, "verify_failed"),
            (ErrorCode::Internal, "internal"),
        ] {
            assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{name}\""));
        }
    }
}
