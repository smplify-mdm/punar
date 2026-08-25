//! The one inter-daemon client in Punar: `punard` → `punar-agentd`
//! (`docs/development/milestone-10.md` sections 3.3, 7.3).
//!
//! # Why this edge exists, and why it points this way
//!
//! Milestone 7 declined to open a `punard → punar-agentd` client, with a
//! good reason: "an IPC edge between daemons for a capability the milestone
//! does not claim". M10 claims it. The remote-query path needs a courier
//! (punard holds the device token, the enrollment state and the offline
//! logic — M5's law) and a data owner (punar-agentd holds the registry, the
//! ledger and the detections — M7/M8's law), and the two must speak.
//!
//! **The graph stays a DAG.** This is the only inter-daemon call in the
//! system, and it is one-directional: `punar-agentd` never calls `punard`.
//! Its relationship to punard's data is reading an append-only file (M8
//! section 4.4), which is not a call. `punar-agentd.service` therefore
//! gains no `After=` / `Requires=` on `punard`: a call that fails because
//! the peer is not up is a non-fatal retry on the next pass, not a boot
//! ordering problem.
//!
//! # The law this file must not break (law 2)
//!
//! **The transport is not the authority.** Nothing here decides anything.
//! [`AgentdClient::query_answer`] hands over the question exactly as it was
//! fetched and returns the daemon's answer **as an opaque
//! [`serde_json::Value`]**, which the caller posts back byte-identical.
//! punard does not deserialize the answer into a typed struct, does not
//! reshape it, does not merge anything into it, and never reads a ledger
//! itself.
//!
//! And the corollary, which is the part worth defending in review: **when
//! agentd cannot be reached or answers with an error frame, punard produces
//! nothing.** There is no fallback answer, no "assume refused", no
//! synthesized refusal posted on the daemon's behalf. An unanswered query
//! stays pending on the control plane and is retried on the next sync pass.
//! A courier that can compose a message is not a courier.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use punar_common::query::{METHOD_QUERY_ANSWER, PendingQuery};
use serde_json::{Value, json};

/// The sibling daemon's socket (docs/api/ipc.md section 10.1).
pub const DEFAULT_AGENTD_SOCKET: &str = punar_common::agent::AGENTD_SOCKET_PATH;

/// Environment override for the agentd socket path (host tests point it at
/// a temp socket, exactly like `PUNAR_CONTROL_PLANE_SOCKET`).
pub const AGENTD_SOCKET_ENV: &str = "PUNAR_AGENTD_SOCKET";

/// Budget for `query.answer`: the data owner may have to drain an audit
/// tail and project a ledger. Generous, but bounded — the sync hook runs
/// inside a reconcile pass and must not become unbounded because a sibling
/// daemon is busy.
pub const QUERY_ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// Budget for the opportunistic `agents.scan` on an enrollment transition
/// (section 3.3): fire-and-forget, 2 s, non-fatal. A missed opportunistic
/// scan costs at most one timer period of freshness, and **enrollment must
/// never fail because a bookkeeping daemon was busy.**
pub const SCAN_TRIGGER_TIMEOUT: Duration = Duration::from_secs(2);

/// Why a call to the data owner produced no decision. Every variant means
/// the same thing to the caller: *there is no answer to relay*.
#[derive(Debug)]
pub enum AgentdError {
    /// Could not connect, or the daemon went silent. The message never
    /// contains payload bytes.
    Unreachable(String),
    /// The daemon answered with a structured error frame. Note that a
    /// **refusal is not an error**: an out-of-scope query comes back as a
    /// successful result carrying `authorization_decision: "deny"`. An
    /// error frame here means the call itself did not happen (the method is
    /// not implemented on this build, the peer was not admitted, the params
    /// were rejected) — so there is nothing to post back.
    Refused { code: String, message: String },
}

impl std::fmt::Display for AgentdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentdError::Unreachable(why) => write!(f, "unreachable: {why}"),
            AgentdError::Refused { code, message } => write!(f, "{code}: {message}"),
        }
    }
}

/// One-call-per-connection NDJSON client for the `punar-agentd` socket —
/// the same envelope and the same discipline as the control-plane client
/// next door, so the image carries one client shape, not two.
pub struct AgentdClient {
    socket: PathBuf,
}

impl AgentdClient {
    pub fn new(socket: impl Into<PathBuf>) -> AgentdClient {
        AgentdClient {
            socket: socket.into(),
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, AgentdError> {
        let stream = UnixStream::connect(&self.socket).map_err(|e| transport("connect", &e))?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        let mut line = serde_json::to_string(&json!({
            "v": 1,
            "id": format!("punard-{}-{method}", std::process::id()),
            "method": method,
            "params": params,
        }))
        .expect("agentd requests serialize infallibly");
        line.push('\n');

        let mut writer = &stream;
        writer
            .write_all(line.as_bytes())
            .map_err(|e| transport("send", &e))?;

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        let read = reader
            .read_line(&mut response)
            .map_err(|e| transport("no answer", &e))?;
        if read == 0 {
            return Err(AgentdError::Unreachable(
                "punar-agentd closed the connection without answering".to_string(),
            ));
        }
        let value: Value = serde_json::from_str(response.trim_end()).map_err(|_| {
            AgentdError::Unreachable("punar-agentd answered with a malformed line".into())
        })?;
        if value.get("v") != Some(&json!(1)) {
            return Err(AgentdError::Unreachable(
                "punar-agentd answered with an unsupported protocol version".into(),
            ));
        }
        if let Some(error) = value.get("error") {
            return Err(AgentdError::Refused {
                code: error
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("(no message)")
                    .to_string(),
            });
        }
        value.get("result").cloned().ok_or_else(|| {
            AgentdError::Unreachable("punar-agentd answered with neither result nor error".into())
        })
    }

    /// Hand one **fetched** query to the data owner and return its decision
    /// verbatim (contract section 13.1: root peer only, server-side).
    ///
    /// Note what is *not* in the params: no scope grant, no role, no
    /// organization policy, no token — nothing an administrator or a
    /// compromised control plane could set to widen what comes back. The
    /// data owner reads `org_granted` from its own `enrollment.json`
    /// (SPEC section 59.4, milestone-10.md section 9.2), and this call has
    /// no field through which that could be overridden.
    pub fn query_answer(&self, query: &PendingQuery) -> Result<Value, AgentdError> {
        let params = serde_json::to_value(query).expect("PendingQuery serializes infallibly");
        self.call(METHOD_QUERY_ANSWER, params, QUERY_ANSWER_TIMEOUT)
    }

    /// Ask the data owner to run one detection pass now, because something
    /// changed that affects what may be asked about this device
    /// (milestone-10.md section 3.3 trigger 3).
    ///
    /// Fire-and-forget: the result is discarded and every failure is
    /// non-fatal. Enrolling changes what an organization may ask; answering
    /// its first query with a view assembled before enrollment would be
    /// sloppy, and answering it with a stale view after unenrollment would
    /// be worse — but neither is worth failing an enrollment over.
    pub fn scan_on_enrollment_transition(&self, trigger: &str) {
        match self.call(
            "agents.scan",
            json!({ "trigger": trigger }),
            SCAN_TRIGGER_TIMEOUT,
        ) {
            Ok(_) => {}
            Err(e) => eprintln!(
                "punard: opportunistic agents.scan (trigger {trigger}) did not run: {e} \
                 — the periodic pass covers it"
            ),
        }
    }
}

fn transport(what: &str, err: &io::Error) -> AgentdError {
    AgentdError::Unreachable(format!("{what} failed ({})", err.kind()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> PendingQuery {
        PendingQuery {
            query_id: "qry_1".into(),
            requesting_admin: "cio@acme.com".into(),
            organization: "acme.com".into(),
            requested_scope: "inventory".into(),
            session_id: None,
            received_at: "2026-08-25T14:02:09Z".into(),
        }
    }

    #[test]
    fn a_missing_agentd_socket_is_unreachable_and_never_an_answer() {
        let client = AgentdClient::new("/nonexistent/punar-agentd/agentd.sock");
        match client.query_answer(&query()) {
            Err(AgentdError::Unreachable(why)) => assert!(why.contains("connect"), "{why}"),
            other => panic!("expected Unreachable, got {other:?}"),
        }
        // And the fire-and-forget trigger swallows the same failure.
        client.scan_on_enrollment_transition("enroll");
    }

    /// Law 2 in a unit test: the params punard sends carry the question and
    /// nothing that could widen the answer.
    #[test]
    fn the_handover_params_carry_no_grant_no_role_and_no_token() {
        let params = serde_json::to_value(query()).unwrap();
        let keys: Vec<&str> = params
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for forbidden in [
            "granted_scope",
            "org_granted",
            "remote_query_scopes",
            "role",
            "device_token",
            "policy",
            "allow",
        ] {
            assert!(
                !keys.contains(&forbidden),
                "a courier that can widen its own authority is not a courier: {forbidden}"
            );
        }
        assert!(keys.contains(&"requested_scope"));
        assert!(keys.contains(&"requesting_admin"));
    }
}
