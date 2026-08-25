//! The **closed** `credential.*` method table of the broker socket
//! (docs/api/ipc.md section 16.2).
//!
//! Transport, framing, envelope, versioning, timeouts and error codes are
//! `punar_common::ipc` verbatim — a third socket, not a third protocol.
//! Stages 1–5 of the request pipeline are the shared
//! [`punar_common::ipc::parse_envelope_line`]; stage 6, the method table,
//! is here.
//!
//! # The section 60 guarantee, restated for the broker
//!
//! [`CredentialMethod`] is a closed enum with five variants and no
//! wildcard arm. There is no method that runs a command, and — the rule
//! that makes this daemon different from every other secret store — **no
//! method that returns an issued token a second time**. `credential.show`,
//! `credential.export`, `credential.list`, `secrets.dump`, `system.exec`
//! and `shell.run` are `unknown_method` forever, and the reason is
//! structural rather than a policy setting: after issuance the broker
//! holds only `sha256(token)`, so it *cannot* produce the value again.
//!
//! # Secrets never travel on argv, and never into an error message
//!
//! `credential.validate` and `credential.revoke` carry a token **value** in
//! their params (the CLI reads it from stdin, never a flag — see ipc.md
//! section 16.4). Two consequences are enforced here:
//!
//! 1. the value is lifted into [`punar_common::Redacted`] the moment it is
//!    parsed, so nothing downstream can `{:?}` it into a log; and
//! 2. a params-parse failure on those two methods returns a **fixed**
//!    message with no serde detail attached, because `serde_json`'s error
//!    text quotes offending scalars and would happily echo a token back
//!    into a message a client prints.

use punar_common::Redacted;
use punar_common::ipc::{ErrorCode, IpcError, RequestReject, parse_envelope_line};
use serde::Deserialize;
use serde_json::Value;

/// Broker socket path (ipc.md section 16.1). Its directory is
/// `0750 root:punar`; the socket itself `0660 root:punar`.
pub const SECRETS_SOCKET_PATH: &str = "/run/punar-secrets/secrets.sock";
/// Runtime directory (tmpfiles: `d /run/punar-secrets 0750 root punar -`).
pub const SECRETS_RUNTIME_DIR: &str = "/run/punar-secrets";
/// The credential-class catalog the image installs (milestone-9.md 6.1).
pub const CLASSES_PATH: &str = "/usr/share/punar/secrets/classes.yaml";
/// The AI authority document Milestone 9 ships (plan section 5.2).
pub const AI_DEFAULTS_PATH: &str = "/usr/share/punar/policy/ai-defaults.yaml";
/// Organization AI authority layers, when a device has any.
pub const AI_POLICY_DIR: &str = "/var/lib/punar/policy.d/ai";
/// `user_id` on broker-initiated audit events (the `USER_ID_DAEMON`
/// convention, for the third daemon).
pub const USER_ID_SECRETS: &str = "punar-secrets";

/// Audit actions this daemon emits (ipc.md sections 16.3, 16.5).
pub const ACTION_CREDENTIAL_REQUEST: &str = "credential.request";
pub const ACTION_CREDENTIAL_EXPIRE: &str = "credential.expire";
pub const ACTION_CREDENTIAL_REVOKE: &str = "credential.revoke";

/// Audit `result` words the broker adds to the open set.
pub const RESULT_ISSUED: &str = "issued";
pub const RESULT_PENDING: &str = "pending";
pub const RESULT_DENIED: &str = "denied";
pub const RESULT_EXPIRED: &str = "expired";
pub const RESULT_REVOKED: &str = "revoked";
/// The approval engine could not be reached, so a `request`-policy class
/// issued **nothing** (fail closed, ipc.md section 16.1).
pub const RESULT_UPSTREAM_UNREACHABLE: &str = "upstream_unreachable";
/// Live issuance bound reached — see [`crate::store::MAX_LIVE_TOKENS`].
pub const RESULT_ISSUANCE_FLOOD: &str = "issuance_flood";

/// The five methods, and nothing else.
#[derive(Debug)]
pub enum CredentialMethod {
    /// Broker health and honesty labels. Not audited.
    Status,
    /// The class catalog with each class's effective policy decision.
    Classes,
    Request(CredentialRequestParams),
    Validate(CredentialValidateParams),
    Revoke(CredentialRevokeParams),
}

impl CredentialMethod {
    /// The wire name.
    pub fn name(&self) -> &'static str {
        match self {
            CredentialMethod::Status => "status",
            CredentialMethod::Classes => "credential.classes",
            CredentialMethod::Request(_) => ACTION_CREDENTIAL_REQUEST,
            CredentialMethod::Validate(_) => "credential.validate",
            CredentialMethod::Revoke(_) => ACTION_CREDENTIAL_REVOKE,
        }
    }

    /// Every method name, for the `unknown_method` message and the tests.
    pub const NAMES: [&'static str; 5] = [
        "status",
        "credential.classes",
        "credential.request",
        "credential.validate",
        "credential.revoke",
    ];

    /// Stage 6 of the parse pipeline: the method table.
    pub fn from_wire(method: &str, params: Option<Value>) -> Result<CredentialMethod, IpcError> {
        match method {
            "status" => no_params(method, params).map(|()| CredentialMethod::Status),
            "credential.classes" => no_params(method, params).map(|()| CredentialMethod::Classes),
            "credential.request" => {
                let raw: RequestParamsRaw = parse_params(method, params)?;
                Ok(CredentialMethod::Request(CredentialRequestParams {
                    credential: raw.credential,
                    ttl: raw.ttl,
                }))
            }
            // The two secret-bearing methods: no serde detail escapes.
            "credential.validate" => {
                let raw: ValidateParamsRaw = parse_secret_params(method, params)?;
                Ok(CredentialMethod::Validate(CredentialValidateParams {
                    credential: raw.credential,
                    value: Redacted::new(raw.value),
                }))
            }
            "credential.revoke" => {
                let raw: RevokeParamsRaw = parse_secret_params(method, params)?;
                Ok(CredentialMethod::Revoke(CredentialRevokeParams {
                    value: Redacted::new(raw.value),
                }))
            }
            other => Err(unknown_method(other)),
        }
    }
}

/// Params for `credential.request` (ipc.md section 16.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRequestParams {
    /// Kebab-case class id.
    pub credential: String,
    /// Requested lifetime in seconds; clamped to the class's range.
    pub ttl: Option<u64>,
}

/// Params for `credential.validate`. The value never leaves
/// [`Redacted`] except at the one comparison site in
/// [`crate::store`].
#[derive(Debug)]
pub struct CredentialValidateParams {
    pub credential: Option<String>,
    pub value: Redacted<String>,
}

/// Params for `credential.revoke`.
#[derive(Debug)]
pub struct CredentialRevokeParams {
    pub value: Redacted<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestParamsRaw {
    credential: String,
    #[serde(default)]
    ttl: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateParamsRaw {
    #[serde(default)]
    credential: Option<String>,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeParamsRaw {
    value: String,
}

/// The permanent answer to every probe (SPEC sections 10, 60, 74.4).
pub fn unknown_method(method: &str) -> IpcError {
    IpcError::new(
        ErrorCode::UnknownMethod,
        format!(
            "This daemon has no method {method:?}.\n\
             Policy: os hard constraint — the broker's method table is closed \
             (docs/api/ipc.md section 16.2): {}.\n\
             There is no method that returns an issued token a second time; after \
             issuance the broker keeps only a hash of it, so it could not produce \
             one if it were asked.\n\
             Next step: `punarctl secrets list` shows what this device can issue.",
            CredentialMethod::NAMES.join(", ")
        ),
    )
}

fn no_params(method: &str, params: Option<Value>) -> Result<(), IpcError> {
    match params {
        None => Ok(()),
        Some(Value::Object(map)) if map.is_empty() => Ok(()),
        Some(_) => Err(IpcError::new(
            ErrorCode::InvalidParams,
            format!("{method} takes no params. Next step: send the envelope without params."),
        )),
    }
}

fn parse_params<T: for<'de> Deserialize<'de>>(
    method: &str,
    params: Option<Value>,
) -> Result<T, IpcError> {
    let value = params.unwrap_or(Value::Object(Default::default()));
    serde_json::from_value(value).map_err(|e| {
        IpcError::new(
            ErrorCode::InvalidParams,
            format!(
                "The params for {method} are invalid: {e}.\n\
                 Next step: see docs/api/ipc.md section 16."
            ),
        )
    })
}

/// Params parse for the two methods whose params carry a **secret**.
///
/// Identical to [`parse_params`] except that the serde error is dropped on
/// the floor: `serde_json` quotes offending scalar values in its messages,
/// and a message that echoed a token back to a client (which may print it,
/// pipe it, or log it) would defeat the whole point of not accepting
/// secrets on argv.
fn parse_secret_params<T: for<'de> Deserialize<'de>>(
    method: &str,
    params: Option<Value>,
) -> Result<T, IpcError> {
    let value = params.unwrap_or(Value::Object(Default::default()));
    serde_json::from_value(value).map_err(|_| {
        IpcError::new(
            ErrorCode::InvalidParams,
            format!(
                "The params for {method} are invalid.\n\
                 Policy: os default — this method's params carry a credential value, so \
                 Punar does not quote them back, not even to explain the mistake \
                 (SPEC section 53).\n\
                 Next step: params are {{\"value\": \"<token>\"}}{}; the value \
                 reaches punarctl on stdin, never on argv.",
                if method == "credential.validate" {
                    " with an optional \"credential\""
                } else {
                    ""
                }
            ),
        )
    })
}

/// A parsed request for this socket.
#[derive(Debug)]
pub struct SecretsRequest {
    pub id: String,
    pub method: CredentialMethod,
}

impl SecretsRequest {
    /// Parse one NDJSON request line: the shared envelope pipeline, then
    /// this crate's method table.
    pub fn parse_json_line(line: &str) -> Result<SecretsRequest, RequestReject> {
        let envelope = parse_envelope_line(line)?;
        let method =
            CredentialMethod::from_wire(&envelope.method, envelope.params).map_err(|error| {
                RequestReject {
                    id: Some(envelope.id.clone()),
                    error,
                }
            })?;
        Ok(SecretsRequest {
            id: envelope.id,
            method,
        })
    }
}

#[cfg(test)]
mod tests {
    use punar_common::REDACTED_PLACEHOLDER;

    use super::*;

    const TOKEN: &str = "punar-mock-github-3sJk1p2QoVvV0mRHq8YQnbLQ3Zt7mHkQxq9pOaGZ0c";

    fn parse(line: &str) -> Result<SecretsRequest, RequestReject> {
        SecretsRequest::parse_json_line(line)
    }

    #[test]
    fn the_five_methods_parse() {
        assert!(matches!(
            parse(r#"{"v":1,"id":"1","method":"status"}"#)
                .unwrap()
                .method,
            CredentialMethod::Status
        ));
        assert!(matches!(
            parse(r#"{"v":1,"id":"1","method":"credential.classes"}"#)
                .unwrap()
                .method,
            CredentialMethod::Classes
        ));
        let request = parse(
            r#"{"v":1,"id":"1","method":"credential.request","params":{"credential":"aws-dev","ttl":60}}"#,
        )
        .unwrap();
        match request.method {
            CredentialMethod::Request(params) => {
                assert_eq!(params.credential, "aws-dev");
                assert_eq!(params.ttl, Some(60));
            }
            other => panic!("wrong method: {other:?}"),
        }
        assert!(matches!(
            parse(&format!(
                r#"{{"v":1,"id":"1","method":"credential.validate","params":{{"value":"{TOKEN}"}}}}"#
            ))
            .unwrap()
            .method,
            CredentialMethod::Validate(_)
        ));
        assert!(matches!(
            parse(&format!(
                r#"{{"v":1,"id":"1","method":"credential.revoke","params":{{"value":"{TOKEN}"}}}}"#
            ))
            .unwrap()
            .method,
            CredentialMethod::Revoke(_)
        ));
    }

    /// SPEC sections 10, 60, 74.4: the probes have one permanent answer.
    #[test]
    fn every_generic_execution_probe_is_unknown_method() {
        for method in [
            "credential.show",
            "credential.export",
            "credential.list",
            "secrets.dump",
            "system.exec",
            "shell.run",
            "capabilities.set",
            "approvals.resolve",
        ] {
            let reject = parse(&format!(r#"{{"v":1,"id":"1","method":"{method}"}}"#))
                .expect_err("must not dispatch");
            assert_eq!(reject.error.code, ErrorCode::UnknownMethod, "{method}");
            assert!(reject.error.message.contains("closed"));
        }
    }

    /// The whole reason `credential.validate` params are parsed without
    /// serde's error text.
    #[test]
    fn a_malformed_secret_bearing_params_object_never_echoes_the_value() {
        let reject = parse(&format!(
            r#"{{"v":1,"id":"1","method":"credential.validate","params":{{"value":"{TOKEN}","bogus":1}}}}"#
        ))
        .expect_err("unknown field is invalid params");
        assert_eq!(reject.error.code, ErrorCode::InvalidParams);
        assert!(
            !reject.error.message.contains(TOKEN),
            "the message must not carry the value: {}",
            reject.error.message
        );
        assert!(!reject.error.message.contains("bogus"));

        // A wrong-typed value is the case serde would quote back verbatim.
        let reject = parse(r#"{"v":1,"id":"1","method":"credential.revoke","params":{"value":["punar-mock-aws-dev-LEAK"]}}"#)
            .expect_err("wrong type is invalid params");
        assert!(!reject.error.message.contains("LEAK"));
    }

    /// A non-secret method still gets the helpful serde detail.
    #[test]
    fn ordinary_params_errors_still_explain_themselves() {
        let reject = parse(r#"{"v":1,"id":"1","method":"credential.request","params":{"nope":1}}"#)
            .expect_err("unknown field");
        assert_eq!(reject.error.code, ErrorCode::InvalidParams);
        assert!(reject.error.message.contains("nope"));
    }

    #[test]
    fn a_parsed_token_is_redacted_from_the_moment_it_exists() {
        let request = parse(&format!(
            r#"{{"v":1,"id":"1","method":"credential.validate","params":{{"credential":"github","value":"{TOKEN}"}}}}"#
        ))
        .unwrap();
        let debug = format!("{request:?}");
        assert!(debug.contains(REDACTED_PLACEHOLDER));
        assert!(
            !debug.contains(TOKEN),
            "a derived Debug on the request must not leak the value: {debug}"
        );
    }

    #[test]
    fn methods_that_take_no_params_reject_params() {
        let reject = parse(r#"{"v":1,"id":"1","method":"status","params":{"n":1}}"#).unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::InvalidParams);
        // An explicitly empty object is accepted: some clients always send one.
        assert!(parse(r#"{"v":1,"id":"1","method":"status","params":{}}"#).is_ok());
    }

    /// The shared envelope pipeline is genuinely shared (stages 1-5).
    #[test]
    fn the_envelope_contract_is_the_shared_one() {
        let reject = parse(r#"{"v":2,"id":"1","method":"status"}"#).unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::UnsupportedVersion);
        let reject = parse("not json").unwrap_err();
        assert_eq!(reject.error.code, ErrorCode::MalformedRequest);
    }
}
