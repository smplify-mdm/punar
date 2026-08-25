//! The broker's **client** side of the approval engine (ipc.md sections
//! 14.2, 14.7, 16.3).
//!
//! # Direction of the dependency, and why it only goes this way
//!
//! `punar-secrets` dials punard; punard never dials `punar-secrets`
//! (milestone-9.md section 3.3). That is what keeps a plaintext token out
//! of the daemon that writes `/etc` and shells out to `nft`, and it is why
//! there is no cycle between the two services even though one gates the
//! other. Execution ownership follows capability ownership: punard owns
//! approvals, so it stores and resolves them; the broker owns issuance, so
//! it — and only it — turns an approved `credential_request` into a token,
//! by calling [`ApprovalClient::consume`].
//!
//! # Fail closed when the engine is unreachable
//!
//! `punar-secrets.service` is ordered `After=punard.service` with no
//! `Wants`/`Requires`. If punard is not answering, a `request`-policy class
//! **issues nothing** and the caller gets `upstream_unreachable`; `allow`
//! and `deny` classes still answer, because neither needs an approval.
//! An unreachable approval engine must never become an implicit yes.
//!
//! # Wire-shape coupling, stated
//!
//! Requests are built from the **shared** typed params in
//! `punar_common::ipc` ([`ApprovalsCreateParams`], [`ApprovalIdParams`]),
//! so the broker and punard cannot drift apart about what
//! `approvals.create` takes: a change to the struct breaks both sides at
//! compile time, which is the review point.
//!
//! Results are read **leniently**, with `#[serde(default)]` on every
//! sibling — the client half of ipc.md section 3.3 ("clients must tolerate
//! unknown result fields"), and the same posture `punarctl`'s model takes.
//! A field the broker actually needs and cannot find is a protocol error
//! that refuses to issue; it is never a guess.

use std::io::{BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use punar_common::approval::{
    APPROVAL_TTL_DEFAULT_SECS, ApprovalKind, ApprovalRequest, ApprovalStatus, PolicyCitation,
    Requester, RequesterPeer,
};
use punar_common::ipc::{
    ApprovalIdParams, ApprovalsCreateParams, CLIENT_CONNECT_TIMEOUT, CLIENT_RESPONSE_TIMEOUT,
    IpcError, LineRead, MAX_REQUEST_LINE_BYTES, PROTOCOL_VERSION, RequestEnvelope, Response,
    ResponseBody, read_line_bounded,
};
use punar_common::{PrincipalKind, Risk};
use serde::Deserialize;
use serde_json::{Value, json};

/// punard's socket (ipc.md section 1.1).
pub const PUNARD_SOCKET_PATH: &str = punar_common::ipc::SOCKET_PATH;

/// What went wrong talking to the approval engine.
#[derive(Debug)]
pub enum ApprovalError {
    /// Could not connect, write, or read — punard is not there.
    Unreachable(String),
    /// punard answered with a wire error (`denied` on an approval flood,
    /// `conflict` on an already-consumed approval, …).
    Refused(IpcError),
    /// punard answered, but not in a shape this client can trust.
    Protocol(String),
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalError::Unreachable(detail) => {
                write!(f, "approval engine unreachable: {detail}")
            }
            ApprovalError::Refused(err) => write!(f, "approval engine refused: {err}"),
            ApprovalError::Protocol(detail) => write!(f, "approval engine protocol: {detail}"),
        }
    }
}

/// The facts an approval needs about a credential request.
#[derive(Debug, Clone)]
pub struct CreateArgs<'a> {
    /// Kebab-case class id — the approval's `resource`.
    pub credential: &'a str,
    /// Human label, for the composed reason line.
    pub display: &'a str,
    pub risk: Risk,
    /// The person the approval is routed to.
    pub user: &'a str,
    pub requester_kind: PrincipalKind,
    /// `agt_…` for an agent, the username for a human.
    pub requester_id: &'a str,
    pub requester_uid: u32,
    pub agent_session_id: Option<&'a str>,
    pub policy_name: &'a str,
    pub policy_id: &'a str,
    /// The TTL the caller asked the broker for, recorded verbatim in the
    /// approval's `request.params` so a resolver sees the real request.
    pub requested_ttl: Option<u64>,
}

/// A created, pending approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedApproval {
    pub approval_id: String,
    pub expires_at: String,
}

/// One approved `credential_request` this broker could spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub approval_id: String,
    pub resource: String,
    pub requester_id: String,
}

/// A thin NDJSON client for punard's socket.
#[derive(Debug, Clone)]
pub struct ApprovalClient {
    socket: PathBuf,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl ApprovalClient {
    pub fn new(socket: impl Into<PathBuf>) -> ApprovalClient {
        ApprovalClient {
            socket: socket.into(),
            connect_timeout: CLIENT_CONNECT_TIMEOUT,
            io_timeout: CLIENT_RESPONSE_TIMEOUT,
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Shorter timeouts (tests).
    pub fn with_timeouts(mut self, connect: Duration, io: Duration) -> ApprovalClient {
        self.connect_timeout = connect;
        self.io_timeout = io;
        self
    }

    /// `approvals.create` for a `credential_request` (ipc.md section 16.3).
    ///
    /// The `reason` is **composed by the broker**, not taken from the
    /// caller: `credential.request` has no reason parameter (ipc.md section
    /// 16.3), and inventing a free-text field the requester could fill
    /// would put requester-authored prose on the approval overlay with
    /// nothing behind it. What the human is shown here is a statement of
    /// fact — which class, asked for by whom — in the system's own voice.
    pub fn create(&self, args: &CreateArgs<'_>) -> Result<CreatedApproval, ApprovalError> {
        let mut request_params = json!({ "credential": args.credential });
        if let (Some(map), Some(ttl)) = (request_params.as_object_mut(), args.requested_ttl) {
            map.insert("ttl".to_string(), json!(ttl));
        }
        let params = ApprovalsCreateParams {
            kind: ApprovalKind::CredentialRequest,
            capability: "credential.request".to_string(),
            resource: args.credential.to_string(),
            reason: compose_reason(args.display, args.requester_id),
            risk: args.risk,
            user: args.user.to_string(),
            requester: Requester {
                kind: args.requester_kind,
                id: args.requester_id.to_string(),
            },
            // The broker asks for the policy-owned default; a shorter TTL
            // here would shorten the *human's* window to answer, which is
            // not the requester's to shorten.
            ttl: Some(APPROVAL_TTL_DEFAULT_SECS),
            contract: Some(contract_line(args.credential)),
            // punard cannot re-derive these: the request arrived at a
            // different socket, and this is the peer the broker itself
            // terminated (ipc.md section 14.2).
            requester_peer: Some(RequesterPeer {
                uid: args.requester_uid,
                agent_session_id: args.agent_session_id.map(str::to_string),
            }),
            // The broker evaluated the policy, so the broker names it —
            // punard would otherwise have to guess whether `aws_dev:
            // request` came from the personal defaults or an org baseline.
            policy: Some(PolicyCitation {
                name: args.policy_name.to_string(),
                policy_id: args.policy_id.to_string(),
            }),
            request: Some(ApprovalRequest {
                method: "credential.request".to_string(),
                params: request_params,
            }),
        };
        let params = serde_json::to_value(&params)
            .map_err(|e| ApprovalError::Protocol(format!("create params: {e}")))?;

        let result = self.call("approvals.create", Some(params))?;
        let listed = ListedApproval::from_result(&result)?;
        Ok(CreatedApproval {
            expires_at: listed.approval.expires_at,
            approval_id: listed.approval.approval_id,
        })
    }

    /// Approved, unspent `credential_request` approvals for this class and
    /// requester, newest last (the order punard lists them in).
    ///
    /// A row that carries `consumed_at` is skipped here, and a row that
    /// does not is still only a *candidate*: single use is enforced by
    /// [`ApprovalClient::consume`] on the server side, never by this
    /// filter. The filter exists to avoid pointless calls, not to make the
    /// authorization decision.
    pub fn candidates(
        &self,
        credential: &str,
        requester_id: &str,
    ) -> Result<Vec<Candidate>, ApprovalError> {
        let result = self.call("approvals.list", None)?;
        let listed: ListResult = serde_json::from_value(result)
            .map_err(|e| ApprovalError::Protocol(format!("list result: {e}")))?;
        Ok(listed
            .approvals
            .into_iter()
            .filter(|row| row.kind.as_deref() == Some(ApprovalKind::CredentialRequest.as_str()))
            .filter(|row| row.approval.status.as_deref() == Some(ApprovalStatus::Approved.as_str()))
            .filter(|row| row.consumed_at.is_none())
            .filter(|row| row.approval.resource == credential)
            .filter(|row| row.approval.requester.id == requester_id)
            .map(|row| Candidate {
                approval_id: row.approval.approval_id,
                resource: row.approval.resource,
                requester_id: row.approval.requester.id,
            })
            .collect())
    }

    /// `approvals.consume` — spend an approved approval **once** (ipc.md
    /// section 14.7). `conflict` (already consumed) and `expired` come back
    /// as [`ApprovalError::Refused`]; the caller treats both as "this
    /// approval is not usable" and moves on, because a yes is not a
    /// standing grant.
    pub fn consume(&self, approval_id: &str) -> Result<String, ApprovalError> {
        let params = serde_json::to_value(ApprovalIdParams {
            approval_id: approval_id.to_string(),
        })
        .map_err(|e| ApprovalError::Protocol(format!("consume params: {e}")))?;
        let result = self.call("approvals.consume", Some(params))?;
        let consumed_at = result
            .get("consumed_at")
            .and_then(Value::as_str)
            .or_else(|| {
                result
                    .get("approval")
                    .and_then(|a| a.get("consumed_at"))
                    .and_then(Value::as_str)
            })
            .unwrap_or_default()
            .to_string();
        Ok(consumed_at)
    }

    fn call(&self, method: &str, params: Option<Value>) -> Result<Value, ApprovalError> {
        let envelope = RequestEnvelope {
            v: PROTOCOL_VERSION,
            id: request_id(),
            method: method.to_string(),
            params,
        };
        let line = envelope.to_json_line();
        if line.len() > MAX_REQUEST_LINE_BYTES {
            return Err(ApprovalError::Protocol(format!(
                "the {method} request line would exceed the {MAX_REQUEST_LINE_BYTES}-byte \
                 framing bound"
            )));
        }

        let mut stream = connect(&self.socket, self.connect_timeout)
            .map_err(|e| ApprovalError::Unreachable(e.to_string()))?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.io_timeout)))
            .map_err(|e| ApprovalError::Unreachable(e.to_string()))?;
        stream
            .write_all(line.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|e| ApprovalError::Unreachable(e.to_string()))?;

        let reader_stream = stream
            .try_clone()
            .map_err(|e| ApprovalError::Unreachable(e.to_string()))?;
        let mut reader = BufReader::with_capacity(MAX_REQUEST_LINE_BYTES, reader_stream);
        // A response may legitimately be longer than a request line (an
        // approvals.list of eight approvals), so the read bound here is the
        // client's own, generous, and still finite.
        let line = match read_line_bounded(&mut reader, 64 * 1024) {
            Ok(LineRead::Line(line)) => line,
            Ok(LineRead::Eof) => {
                return Err(ApprovalError::Unreachable(
                    "the approval engine closed the connection without answering".to_string(),
                ));
            }
            Ok(LineRead::TooLong) => {
                return Err(ApprovalError::Protocol(
                    "the approval engine's answer exceeded 64 KiB".to_string(),
                ));
            }
            Err(e) => return Err(ApprovalError::Unreachable(e.to_string())),
        };

        let response = Response::parse_json_line(&line)
            .map_err(|e| ApprovalError::Protocol(format!("unparsable answer: {e}")))?;
        match response.body {
            ResponseBody::Result(result) => Ok(result),
            ResponseBody::Error(err) => Err(ApprovalError::Refused(err)),
        }
    }
}

fn connect(path: &Path, timeout: Duration) -> std::io::Result<UnixStream> {
    // std has no connect-with-timeout for UDS; a local connect either
    // succeeds or fails immediately, and the read/write timeouts below
    // bound everything after it. The parameter is kept so the shape
    // matches punarctl's client and so a future runtime can honour it.
    let _ = timeout;
    UnixStream::connect(path)
}

/// The broker's composed approval reason (see [`ApprovalClient::create`]).
pub fn compose_reason(display: &str, requester_id: &str) -> String {
    let reason = format!("{display} credential requested by {requester_id}");
    // punar_common::approval::validate_reason bounds this at 512 bytes with
    // no control characters; the inputs are a catalog display name and an
    // attested id, so the only bound worth defending here is length.
    reason.chars().take(200).collect()
}

/// The Plate D-003 contract line for a credential approval.
pub fn contract_line(credential: &str) -> String {
    format!("RequestCredential({credential})")
}

/// A correlation id that is unique per call within this process.
fn request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!("sec-{}", SEQ.fetch_add(1, Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// Lenient result shapes (ipc.md section 3.3: clients tolerate what they do
// not know)
// ---------------------------------------------------------------------------

/// The `approvals.list` result, read for exactly the fields the broker
/// acts on.
#[derive(Debug, Deserialize)]
struct ListResult {
    #[serde(default)]
    approvals: Vec<ListedApproval>,
}

/// One approval envelope, leniently.
#[derive(Debug, Deserialize)]
struct ListedApproval {
    approval: ListedDoc,
    /// Read as a string rather than the typed enum on purpose: a `kind`
    /// or `status` this build does not know must fall out of the filter,
    /// not fail the whole read — and above all must never compare equal
    /// to `approved`. Forward compatibility never widens authority.
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    consumed_at: Option<String>,
}

/// The section 28 document, leniently. An unknown `status` string is
/// simply not `"approved"`.
#[derive(Debug, Deserialize)]
struct ListedDoc {
    #[serde(default)]
    approval_id: String,
    #[serde(default)]
    requester: ListedRequester,
    #[serde(default)]
    resource: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    expires_at: String,
}

#[derive(Debug, Default, Deserialize)]
struct ListedRequester {
    #[serde(default)]
    id: String,
}

impl ListedApproval {
    /// Read one envelope out of a result that either *is* the envelope
    /// (ipc.md section 14.3) or wraps it in an `approval` member.
    fn from_result(result: &Value) -> Result<ListedApproval, ApprovalError> {
        // Both attempts can *parse* — every field here is lenient — so the
        // test is whether the parse actually found an approval id. A
        // wrapper shape read as the envelope yields an empty id, which is
        // not an approval and must not be treated as one.
        let named = |value: &Value| {
            serde_json::from_value::<ListedApproval>(value.clone())
                .ok()
                .filter(|listed| !listed.approval.approval_id.is_empty())
        };
        named(result)
            .or_else(|| result.get("approval").and_then(named))
            .ok_or_else(|| {
                ApprovalError::Protocol(
                    "the answer carries no approval this client can read".to_string(),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The create/consume answer is read whether punard returns the
    /// envelope itself (ipc.md section 14.3) or wraps it — and an answer
    /// that carries neither is a protocol error, never a default.
    #[test]
    fn an_envelope_is_read_from_either_shape_and_from_nothing_else() {
        let envelope = json!({
            "v": 1,
            "approval": {"approval_id": "apr_1", "resource": "aws-dev",
                         "status": "approved", "expires_at": "T",
                         "requester": {"type": "ai_agent", "id": "agt_1"}},
            "kind": "credential_request"
        });
        let direct = ListedApproval::from_result(&envelope).unwrap();
        assert_eq!(direct.approval.approval_id, "apr_1");
        assert_eq!(direct.approval.status.as_deref(), Some("approved"));
        assert_eq!(
            direct.kind.as_deref(),
            Some(ApprovalKind::CredentialRequest.as_str())
        );

        let wrapped = ListedApproval::from_result(&json!({"approval": envelope})).unwrap();
        assert_eq!(wrapped.approval.approval_id, "apr_1");

        assert!(matches!(
            ListedApproval::from_result(&json!({"other": 1})),
            Err(ApprovalError::Protocol(_))
        ));
    }

    /// A status this build does not know is not "approved". Forward
    /// compatibility must never widen authority.
    #[test]
    fn an_unknown_status_is_never_treated_as_approved() {
        let listed = ListedApproval::from_result(&json!({
            "approval": {"approval_id": "apr_1", "resource": "aws-dev",
                         "status": "half_approved", "expires_at": "T",
                         "requester": {"type": "human", "id": "punar"}},
            "kind": "credential_request"
        }))
        .unwrap();
        assert_ne!(
            listed.approval.status.as_deref(),
            Some(ApprovalStatus::Approved.as_str())
        );
    }

    #[test]
    fn the_composed_reason_is_factual_bounded_and_single_line() {
        let reason = compose_reason("AWS development (mock)", "agt_4f21c09ab3e1");
        assert!(punar_common::approval::validate_reason(&reason).is_ok());
        assert!(reason.contains("AWS development (mock)"));
        assert!(reason.contains("agt_4f21c09ab3e1"));
        assert!(!reason.contains('\n'));

        let long = compose_reason(&"x".repeat(1000), "agt_1");
        assert!(punar_common::approval::validate_reason(&long).is_ok());
    }

    #[test]
    fn the_contract_line_reads_as_the_plate_d003_block() {
        assert_eq!(contract_line("aws-dev"), "RequestCredential(aws-dev)");
    }

    #[test]
    fn an_absent_engine_is_unreachable_never_an_implicit_yes() {
        let client = ApprovalClient::new("/nonexistent/punard.sock")
            .with_timeouts(Duration::from_millis(50), Duration::from_millis(50));
        let err = client.candidates("aws-dev", "agt_1").unwrap_err();
        assert!(matches!(err, ApprovalError::Unreachable(_)), "{err}");
    }

    /// The candidate filter and single-use consumption, driven against a
    /// mock engine over a real socket — not against a copy of the filter.
    #[test]
    fn candidates_are_filtered_and_an_approval_can_be_spent_only_once() {
        let dir = crate::testsupport::temp_dir("approvals-client");
        let punard = crate::testsupport::MockPunard::start(&dir);
        let client = ApprovalClient::new(punard.socket());

        let args = |credential: &'static str, who: &'static str| CreateArgs {
            credential,
            display: "AWS development (mock)",
            risk: Risk::Medium,
            user: "punar",
            requester_kind: PrincipalKind::AiAgent,
            requester_id: who,
            requester_uid: 1000,
            agent_session_id: Some(who),
            policy_name: "Personal defaults",
            policy_id: "personal-defaults",
            requested_ttl: Some(60),
        };

        let mine = client.create(&args("aws-dev", "agt_1")).unwrap();
        let other_class = client.create(&args("github", "agt_1")).unwrap();
        let other_agent = client.create(&args("aws-dev", "agt_2")).unwrap();
        assert!(mine.approval_id.starts_with("apr_"));

        // Pending approvals are not candidates: only a human's yes is.
        assert!(client.candidates("aws-dev", "agt_1").unwrap().is_empty());

        punard.approve(&mine.approval_id);
        punard.approve(&other_class.approval_id);
        punard.approve(&other_agent.approval_id);

        let candidates = client.candidates("aws-dev", "agt_1").unwrap();
        assert_eq!(candidates.len(), 1, "class and requester both filter");
        assert_eq!(candidates[0].approval_id, mine.approval_id);

        // Single use is enforced by the engine; the second consume fails.
        assert!(!client.consume(&mine.approval_id).unwrap().is_empty());
        assert!(matches!(
            client.consume(&mine.approval_id),
            Err(ApprovalError::Refused(_))
        ));
        assert!(
            client.candidates("aws-dev", "agt_1").unwrap().is_empty(),
            "a spent approval is no longer a candidate"
        );

        // The envelope the broker asked punard to store is the section
        // 14.3 shape, with the class as `resource` and no value anywhere.
        let envelope = &punard.envelopes()[0];
        assert_eq!(envelope["kind"], json!("credential_request"));
        assert_eq!(envelope["approval"]["resource"], json!("aws-dev"));
        assert_eq!(envelope["contract"], json!("RequestCredential(aws-dev)"));

        punard.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
