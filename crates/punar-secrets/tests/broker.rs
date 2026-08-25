//! Integration tests: a real broker on a tempdir socket, driven over the
//! wire exactly as `punarctl` will drive it (docs/api/ipc.md section 16),
//! against a mock approval engine that speaks punard's `approvals.*`
//! shapes.
//!
//! The last test in this file is the one the milestone is named for: a
//! **redaction sweep** that takes every token this suite caused to exist
//! and greps the audit trail, every file the daemon could have touched,
//! every response body, and the daemon's own `Debug` output for it. One
//! hit is a failure.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use punar_common::ipc::EXIT_APPROVAL_REQUIRED;
use punar_secrets::attribution::{Peer, PeerSource};
use punar_secrets::server::{Clock, Daemon, DaemonHandle, SecretsConfig};
use punar_secrets::testsupport::{
    MockPunard, fake_agent_proc, temp_dir, write_ai_defaults, write_catalog, write_nss_files,
};
use serde_json::{Value, json};

/// Where every test's clock starts. Each broker gets its **own** clock,
/// so tests running in parallel cannot move each other's expiries.
const T0: u64 = 1_760_000_000;

struct TestBroker {
    dir: PathBuf,
    socket: PathBuf,
    audit: PathBuf,
    punard: Option<MockPunard>,
    clock: Arc<AtomicU64>,
    handle: Option<DaemonHandle>,
}

impl TestBroker {
    fn start(peer: PeerSource) -> TestBroker {
        TestBroker::start_with(peer, |_cfg| {})
    }

    /// Start a broker whose peer identity is `peer`, after `tweak` has had
    /// a chance to adjust the config (a fixture `/proc`, a dead approval
    /// engine, …).
    fn start_with(peer: PeerSource, tweak: impl FnOnce(&mut SecretsConfig)) -> TestBroker {
        let dir = temp_dir("broker");
        let (group_file, passwd_file) = write_nss_files(&dir);
        let classes = write_catalog(&dir);
        let ai_defaults = write_ai_defaults(&dir);
        let punard = MockPunard::start(&dir);
        let socket = dir.join("secrets.sock");
        let audit = dir.join("audit.jsonl");

        let mut cfg = SecretsConfig::new(socket.clone(), classes, ai_defaults, audit.clone());
        cfg.ai_policy_dir = dir.join("policy.d-ai");
        cfg.state_dir = dir.join("state");
        std::fs::create_dir_all(&cfg.state_dir).unwrap();
        std::fs::write(cfg.state_dir.join("device-id"), "dev_test0001\n").unwrap();
        cfg.punard_socket = punard.socket().to_path_buf();
        cfg.group_file = group_file;
        cfg.passwd_file = passwd_file;
        cfg.peer_source = peer;
        let clock = Arc::new(AtomicU64::new(T0));
        cfg.clock = Clock::Fixed(Arc::clone(&clock));
        tweak(&mut cfg);

        let daemon = Daemon::new(cfg).expect("broker starts");
        let handle = daemon.spawn().expect("broker binds");
        TestBroker {
            dir,
            socket,
            audit,
            punard: Some(punard),
            clock,
            handle: Some(handle),
        }
    }

    /// The mock approval engine behind this broker.
    fn punard(&self) -> &MockPunard {
        self.punard.as_ref().expect("the mock engine is alive")
    }

    /// Move this broker's clock forward by `secs`.
    fn advance(&self, secs: u64) {
        self.clock.fetch_add(secs, Ordering::SeqCst);
    }

    /// One request, one response, one connection.
    fn call(&self, method: &str, params: Option<Value>) -> Value {
        call_on(&self.socket, method, params)
    }

    fn ok(&self, method: &str, params: Option<Value>) -> Value {
        let response = self.call(method, params);
        assert!(
            response.get("result").is_some(),
            "expected a result for {method}: {response}"
        );
        response["result"].clone()
    }

    fn err(&self, method: &str, params: Option<Value>) -> Value {
        let response = self.call(method, params);
        assert!(
            response.get("error").is_some(),
            "expected an error for {method}: {response}"
        );
        response["error"].clone()
    }

    /// Every audit event written so far.
    fn events(&self) -> Vec<Value> {
        let Ok(text) = std::fs::read_to_string(&self.audit) else {
            return Vec::new();
        };
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("audit lines are JSON"))
            .collect()
    }

    fn events_for(&self, action: &str) -> Vec<Value> {
        self.events()
            .into_iter()
            .filter(|e| e["action"] == json!(action))
            .collect()
    }
}

impl Drop for TestBroker {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
        // Order matters: the mock engine is shut down while its socket
        // still exists, because that socket is how its accept loop is
        // woken. Deleting the directory first would leave a thread parked
        // in `accept(2)` with nothing able to reach it.
        drop(self.punard.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn call_on(socket: &Path, method: &str, params: Option<Value>) -> Value {
    let mut stream = UnixStream::connect(socket).expect("broker socket connects");
    let mut envelope = json!({"v": 1, "id": "t1", "method": method});
    if let (Some(map), Some(params)) = (envelope.as_object_mut(), params) {
        map.insert("params".to_string(), params);
    }
    stream
        .write_all(format!("{envelope}\n").as_bytes())
        .and_then(|()| stream.flush())
        .expect("request writes");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("response reads");
    serde_json::from_str(&line).expect("response is JSON")
}

/// The value of an issuance result, as a plain string. Only tests that
/// need to *use* the token call this; the redaction sweep asserts about it.
fn value_of(result: &Value) -> String {
    result["value"]
        .as_str()
        .expect("an issuance carries a value")
        .to_string()
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

#[test]
fn status_says_what_the_broker_is_and_admits_it_is_simulated() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    let result = broker.ok("status", None);
    assert_eq!(result["protocol"], json!(1));
    assert_eq!(result["provider"], json!("mock"));
    assert_eq!(result["attestation"], json!("simulated"));
    assert_eq!(result["classes"], json!(3));
    assert_eq!(result["issued"], json!(0));
    assert_eq!(
        result["persisted"],
        json!(false),
        "the broker has no state directory and says so"
    );
    assert!(broker.events().is_empty(), "a read is not an audit event");
}

#[test]
fn the_class_list_carries_each_classs_effective_decision_and_citation() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    let result = broker.ok("credential.classes", None);
    let classes = result["classes"].as_array().unwrap();
    assert_eq!(classes.len(), 3);

    let by_id = |id: &str| {
        classes
            .iter()
            .find(|c| c["id"] == json!(id))
            .unwrap_or_else(|| panic!("class {id} is listed"))
            .clone()
    };
    assert_eq!(by_id("github")["decision"], json!("allow"));
    assert_eq!(by_id("aws-dev")["decision"], json!("request"));
    assert_eq!(by_id("aws-prod")["decision"], json!("deny"));
    assert_eq!(by_id("aws-dev")["risk"], json!("medium"));
    assert_eq!(
        by_id("aws-dev")["policy"]["policy_id"],
        json!("personal-defaults")
    );
    // The kebab-case wire spelling, pinned: the ledger reads this string.
    assert!(classes.iter().any(|c| c["id"] == json!("aws-dev")));
    assert!(!result.to_string().contains("aws_dev"));
}

// ---------------------------------------------------------------------------
// allow: issue, validate, expire, revoke
// ---------------------------------------------------------------------------

#[test]
fn an_allowed_class_issues_a_marked_mock_token_and_audits_the_class_only() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    let result = broker.ok("credential.request", Some(json!({"credential": "github"})));
    let token = value_of(&result);

    assert_eq!(result["credential"], json!("github"));
    assert_eq!(result["provider"], json!("mock"));
    assert_eq!(result["attestation"], json!("simulated"));
    assert_eq!(result["ttl"], json!(3600));
    assert!(token.starts_with("punar-mock-github-"), "{token}");

    let events = broker.events_for("credential.request");
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["decision"], json!("allow"));
    assert_eq!(event["result"], json!("issued"));
    assert_eq!(event["resource"], json!("github"));
    assert_eq!(event["user_id"], json!("punar"));
    assert_eq!(event["source"], json!("human"));
    assert_eq!(event["agent_session_id"], json!("agt_none"));
    assert_eq!(event["policy_ids"], json!(["personal-defaults"]));
    assert_eq!(event["event_id"], result["audit_event_id"]);
    assert!(
        !serde_json::to_string(event).unwrap().contains(&token),
        "the audit event must never carry the value"
    );
}

#[test]
fn a_requested_ttl_is_honoured_and_a_greedy_one_is_clamped() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    let short = broker.ok(
        "credential.request",
        Some(json!({"credential": "github", "ttl": 5})),
    );
    assert_eq!(short["ttl"], json!(5));

    let greedy = broker.ok(
        "credential.request",
        Some(json!({"credential": "github", "ttl": 999_999})),
    );
    assert_eq!(greedy["ttl"], json!(3600), "the maximum is policy-owned");
}

#[test]
fn a_token_validates_until_its_ttl_lapses_then_expires_exactly_once() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    let issued = broker.ok(
        "credential.request",
        Some(json!({"credential": "github", "ttl": 5})),
    );
    let token = value_of(&issued);

    let valid = broker.ok(
        "credential.validate",
        Some(json!({"credential": "github", "value": token})),
    );
    assert_eq!(valid["valid"], json!(true));
    assert_eq!(valid["credential"], json!("github"));
    assert_eq!(valid["expires_in"], json!(5));
    assert!(
        broker.events_for("credential.expire").is_empty(),
        "a successful validate is not audited (spec 6.4)"
    );

    // Move past the TTL. No sleep, no timer: expiry is a comparison.
    broker.advance(6);
    let error = broker.err("credential.validate", Some(json!({"value": token})));
    assert_eq!(error["code"], json!("expired"));
    assert!(error["message"].as_str().unwrap().contains("short-lived"));
    assert_eq!(error["details"]["credential"], json!("github"));

    let expiries = broker.events_for("credential.expire");
    assert_eq!(expiries.len(), 1, "audited once, on first observation");
    assert_eq!(expiries[0]["resource"], json!("github"));
    assert_eq!(expiries[0]["result"], json!("expired"));
    assert_eq!(
        expiries[0]["decision"],
        json!("allow"),
        "a lapse is a lifecycle fact, not a denied access"
    );

    // The entry is gone: a second presentation is simply unknown, and
    // unknown is never audited.
    let error = broker.err("credential.validate", Some(json!({"value": token})));
    assert_eq!(error["code"], json!("not_found"));
    assert_eq!(broker.events_for("credential.expire").len(), 1);
}

#[test]
fn revoking_drops_a_token_immediately_and_audits_the_class() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    let issued = broker.ok(
        "credential.request",
        Some(json!({"credential": "github", "ttl": 3600})),
    );
    let token = value_of(&issued);

    let revoked = broker.ok("credential.revoke", Some(json!({"value": token})));
    assert_eq!(revoked["revoked"], json!(true));
    assert_eq!(revoked["credential"], json!("github"));

    let events = broker.events_for("credential.revoke");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["result"], json!("revoked"));
    assert_eq!(events[0]["resource"], json!("github"));

    let error = broker.err("credential.validate", Some(json!({"value": token})));
    assert_eq!(error["code"], json!("not_found"));

    // Revoking again is not an event: there is nothing left to revoke.
    let error = broker.err("credential.revoke", Some(json!({"value": token})));
    assert_eq!(error["code"], json!("not_found"));
    assert_eq!(broker.events_for("credential.revoke").len(), 1);
}

#[test]
fn an_unknown_token_is_never_audited() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    for _ in 0..5 {
        let error = broker.err(
            "credential.validate",
            Some(json!({"value": "punar-mock-github-not-a-real-token"})),
        );
        assert_eq!(error["code"], json!("not_found"));
    }
    assert!(
        broker.events().is_empty(),
        "auditing unknown tokens would be an audit-flood primitive (spec 6.4)"
    );
}

// ---------------------------------------------------------------------------
// deny
// ---------------------------------------------------------------------------

#[test]
fn a_denied_class_refuses_in_the_section_73_voice_and_records_the_refusal() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    let error = broker.err(
        "credential.request",
        Some(json!({"credential": "aws-prod"})),
    );
    assert_eq!(error["code"], json!("denied"));

    let message = error["message"].as_str().unwrap();
    // The four beats: what happened, why, which policy, what next — plus
    // whether approval is possible, which section 73 requires of a refusal
    // an agent will read.
    assert!(message.contains("AWS production (mock) credentials are not issued"));
    assert!(message.contains("Personal defaults"));
    assert!(message.contains("you made this rule"));
    assert!(message.contains("punarctl policy effective --ai"));
    assert!(message.contains("Approval is not available for this class"));

    let events = broker.events_for("credential.request");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["decision"], json!("deny"));
    assert_eq!(events[0]["result"], json!("denied"));
    assert_eq!(events[0]["resource"], json!("aws-prod"));
    // The message quotes the event it was recorded as: the agent's
    // transcript and the audit trail name the same fact.
    assert!(message.contains(events[0]["event_id"].as_str().unwrap()));
    // Nothing was issued.
    assert_eq!(broker.ok("status", None)["issued"], json!(0));
}

/// **A yes for one class buys nothing for another.** The adversarial shape
/// of the closed table (ipc.md section 16.2): there are five methods, none
/// of them takes an approval id from the caller, and the only path from an
/// approval to a token runs through `gated_request` — which is reached only
/// on a `request` grant, and matches candidates on the class *and* the
/// requester. A `deny` class never gets that far, and `aws-prod` could not
/// be issued even if it did: `max_ttl: 0` is a refusal in the catalog that
/// no policy setting can outrank.
#[test]
fn an_approval_for_one_class_cannot_buy_a_denied_one() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));

    // A live, approved, unspent approval exists — for aws-dev.
    broker.err("credential.request", Some(json!({"credential": "aws-dev"})));
    let approved = broker.punard().approve_all();
    assert_eq!(approved.len(), 1);

    // It does not make the denied class issuable, and the denial does not
    // even reach the approval engine: the policy arm returns first.
    let calls_before = broker.punard().calls().len();
    let error = broker.err(
        "credential.request",
        Some(json!({"credential": "aws-prod"})),
    );
    assert_eq!(error["code"], json!("denied"));
    assert_eq!(
        broker.punard().calls().len(),
        calls_before,
        "a denied class must not consult the approval engine at all"
    );

    // The aws-dev approval is still there, unspent — nothing was consumed
    // on behalf of a class it was not raised for.
    assert_eq!(broker.ok("status", None)["issued"], json!(0));
    let issued = broker.ok("credential.request", Some(json!({"credential": "aws-dev"})));
    assert_eq!(issued["credential"], json!("aws-dev"));
    assert_eq!(issued["approval_id"], json!(approved[0]));

    // And with that approval now spent, aws-prod is still denied.
    assert_eq!(
        broker.err(
            "credential.request",
            Some(json!({"credential": "aws-prod"}))
        )["code"],
        json!("denied")
    );
    assert_eq!(broker.ok("status", None)["issued"], json!(1));
}

#[test]
fn a_class_that_does_not_exist_says_what_does() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    let error = broker.err(
        "credential.request",
        Some(json!({"credential": "gcp-prod"})),
    );
    assert_eq!(error["code"], json!("not_found"));
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("github, aws-dev, aws-prod"));
    assert!(broker.events().is_empty(), "a typo is not a security event");
}

// ---------------------------------------------------------------------------
// request: the approval gate
// ---------------------------------------------------------------------------

#[test]
fn a_request_class_creates_an_approval_and_issues_nothing() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    let error = broker.err(
        "credential.request",
        Some(json!({"credential": "aws-dev", "ttl": 60})),
    );

    assert_eq!(error["code"], json!("approval_required"));
    assert_eq!(
        punar_common::ipc::ErrorCode::ApprovalRequired.suggested_exit_code(),
        EXIT_APPROVAL_REQUIRED,
        "the gate is exit code 4, reserved for it since M3"
    );
    let details = &error["details"];
    assert!(details["approval_id"].as_str().unwrap().starts_with("apr_"));
    assert_eq!(details["decision"], json!("approval_required"));
    assert_eq!(details["resource"], json!("aws-dev"));
    assert_eq!(details["capability"], json!("credential.request"));
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("Nothing has been issued")
    );

    // Nothing was issued, and the pending fact is in the trail.
    assert_eq!(broker.ok("status", None)["issued"], json!(0));
    let events = broker.events_for("credential.request");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["decision"], json!("approval_required"));
    assert_eq!(events[0]["result"], json!("pending"));
    assert_eq!(events[0]["resource"], json!("aws-dev"));

    // The approval punard was asked to store is a well-formed envelope.
    let envelopes = broker.punard().envelopes();
    assert_eq!(envelopes.len(), 1);
    let envelope = &envelopes[0];
    assert_eq!(envelope["kind"], json!("credential_request"));
    assert_eq!(
        envelope["approval"]["capability"],
        json!("credential.request")
    );
    assert_eq!(envelope["approval"]["resource"], json!("aws-dev"));
    assert_eq!(envelope["approval"]["risk"], json!("medium"));
    assert_eq!(envelope["approval"]["user"], json!("punar"));
    assert_eq!(envelope["approval"]["requester"]["type"], json!("human"));
    assert_eq!(envelope["contract"], json!("RequestCredential(aws-dev)"));
    assert_eq!(envelope["request"]["method"], json!("credential.request"));
    assert_eq!(envelope["request"]["params"]["ttl"], json!(60));
    let reason = envelope["approval"]["reason"].as_str().unwrap();
    assert!(punar_common::approval::validate_reason(reason).is_ok());
}

#[test]
fn an_approved_approval_is_spent_once_and_the_next_request_raises_a_new_one() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    broker.err("credential.request", Some(json!({"credential": "aws-dev"})));
    let approved = broker.punard().approve_all();
    assert_eq!(approved.len(), 1);

    // Second ask: the approval is consumed and a token is issued.
    let result = broker.ok("credential.request", Some(json!({"credential": "aws-dev"})));
    let token = value_of(&result);
    assert!(token.starts_with("punar-mock-aws-dev-"));
    assert_eq!(result["approval_id"], json!(approved[0]));
    let envelope = &broker.punard().envelopes()[0];
    assert_eq!(
        envelope["consumed_at"],
        json!("2026-08-25T10:02:00Z"),
        "the approval is marked consumed"
    );
    assert_eq!(
        envelope["approval"]["status"],
        json!("approved"),
        "consumption is a sibling field, never a fifth status"
    );

    // Third ask: a yes is not a standing grant.
    let error = broker.err("credential.request", Some(json!({"credential": "aws-dev"})));
    assert_eq!(error["code"], json!("approval_required"));
    assert_ne!(error["details"]["approval_id"], json!(approved[0]));
    assert_eq!(broker.punard().envelopes().len(), 2);

    // Exactly one issuance, two pendings.
    let events = broker.events_for("credential.request");
    let issued: Vec<&Value> = events
        .iter()
        .filter(|e| e["result"] == json!("issued"))
        .collect();
    let pending: Vec<&Value> = events
        .iter()
        .filter(|e| e["result"] == json!("pending"))
        .collect();
    assert_eq!(issued.len(), 1);
    assert_eq!(pending.len(), 2);
}

#[test]
fn an_unreachable_approval_engine_issues_nothing_and_says_so() {
    let broker = TestBroker::start_with(PeerSource::Fixed(Peer::user(1000)), |cfg| {
        cfg.punard_socket = PathBuf::from("/nonexistent/punard.sock");
    });

    // The gated class fails closed…
    let error = broker.err("credential.request", Some(json!({"credential": "aws-dev"})));
    assert_eq!(error["code"], json!("upstream_unreachable"));
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("refuses rather than assuming a yes")
    );
    assert_eq!(error["details"]["stage"], json!("approvals"));
    assert_eq!(broker.ok("status", None)["issued"], json!(0));

    // …while classes that need no approval still answer.
    assert!(
        broker.ok("credential.request", Some(json!({"credential": "github"})))["value"].is_string()
    );
    assert_eq!(
        broker.err(
            "credential.request",
            Some(json!({"credential": "aws-prod"}))
        )["code"],
        json!("denied")
    );
}

#[test]
fn an_engine_that_refuses_to_record_the_request_passes_its_refusal_through() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    broker
        .punard()
        .refuse_create("denied", "Too many approvals are already waiting.");
    let error = broker.err("credential.request", Some(json!({"credential": "aws-dev"})));
    assert_eq!(error["code"], json!("denied"));
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("already waiting")
    );
    assert_eq!(broker.ok("status", None)["issued"], json!(0));
}

// ---------------------------------------------------------------------------
// Attribution
// ---------------------------------------------------------------------------

#[test]
fn a_request_from_inside_an_agent_scope_is_attributed_to_that_session() {
    let dir_holder = temp_dir("attrib");
    let proc_root = fake_agent_proc(&dir_holder, 4242, "agt_4f21c09ab3e1");
    let broker = TestBroker::start_with(
        PeerSource::Fixed(Peer {
            uid: 1000,
            gid: 1000,
            pid: Some(4242),
        }),
        |cfg| cfg.proc_root = proc_root.clone(),
    );

    let result = broker.ok("credential.request", Some(json!({"credential": "github"})));
    assert_eq!(result["agent_session_id"], json!("agt_4f21c09ab3e1"));

    let events = broker.events_for("credential.request");
    assert_eq!(events[0]["agent_session_id"], json!("agt_4f21c09ab3e1"));
    assert_eq!(
        events[0]["source"],
        json!("ai_agent"),
        "the proximate actor was the agent — this is what fills the M8 ledger"
    );
    assert_eq!(
        events[0]["user_id"],
        json!("punar"),
        "the human still owns the session"
    );
    assert_eq!(events[0]["project_id"], json!("system"));

    // The approval an agent raises names the agent as requester.
    broker.err("credential.request", Some(json!({"credential": "aws-dev"})));
    let envelope = &broker.punard().envelopes()[0];
    assert_eq!(envelope["approval"]["requester"]["type"], json!("ai_agent"));
    assert_eq!(
        envelope["approval"]["requester"]["id"],
        json!("agt_4f21c09ab3e1")
    );
    assert_eq!(
        envelope["approval"]["user"],
        json!("punar"),
        "the approval is routed to the human, not to the agent"
    );
    let _ = std::fs::remove_dir_all(&dir_holder);
}

// ---------------------------------------------------------------------------
// The closed method table
// ---------------------------------------------------------------------------

#[test]
fn the_probes_answer_unknown_method_over_the_wire() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    for method in [
        "credential.show",
        "credential.export",
        "credential.list",
        "secrets.dump",
        "system.exec",
        "shell.run",
    ] {
        let error = broker.err(method, None);
        assert_eq!(error["code"], json!("unknown_method"), "{method}");
    }
    assert!(broker.events().is_empty());
}

// ---------------------------------------------------------------------------
// The headline: redaction
// ---------------------------------------------------------------------------

/// Every token this test causes to exist is searched for in every place
/// Punar could have put it. This is the crate-level form of the in-VM
/// `m9-check` sweep, and it fails on a single hit.
#[test]
fn no_token_value_reaches_any_persisted_or_emitted_structure() {
    let dir_holder = temp_dir("redaction");
    let proc_root = fake_agent_proc(&dir_holder, 777, "agt_redact01");
    let broker = TestBroker::start_with(
        PeerSource::Fixed(Peer {
            uid: 1000,
            gid: 1000,
            pid: Some(777),
        }),
        |cfg| cfg.proc_root = proc_root.clone(),
    );

    let mut tokens: Vec<String> = Vec::new();

    // 1. An allowed class.
    let issued = broker.ok(
        "credential.request",
        Some(json!({"credential": "github", "ttl": 5})),
    );
    tokens.push(value_of(&issued));

    // 2. A gated class, approved and spent.
    broker.err("credential.request", Some(json!({"credential": "aws-dev"})));
    broker.punard().approve_all();
    let issued = broker.ok("credential.request", Some(json!({"credential": "aws-dev"})));
    tokens.push(value_of(&issued));

    // 3. A denial, an expiry, a revocation and a validate of each token —
    // every code path that touches a value.
    broker.err(
        "credential.request",
        Some(json!({"credential": "aws-prod"})),
    );
    for token in &tokens {
        broker.ok("credential.validate", Some(json!({"value": token})));
    }
    broker.advance(10);
    broker.err("credential.validate", Some(json!({"value": tokens[0]})));
    broker.ok("credential.revoke", Some(json!({"value": tokens[1]})));

    // A malformed params object carrying a token must not be echoed back.
    let echoed = broker.err(
        "credential.validate",
        Some(json!({"value": tokens[0], "bogus": 1})),
    );

    // ---- the sweep --------------------------------------------------
    let mut searched = 0usize;
    for token in &tokens {
        assert!(token.starts_with("punar-mock-"), "{token}");

        // Every file the daemon could have written, anywhere under its
        // tree: the audit trail, and whatever else might appear.
        for path in walk(&broker.dir) {
            let bytes = std::fs::read(&path).unwrap_or_default();
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains(token.as_str()),
                "{} contains a credential value",
                path.display()
            );
            searched += 1;
        }

        // The audit trail, parsed — including its `resource` fields.
        for event in broker.events() {
            let json = serde_json::to_string(&event).unwrap();
            assert!(!json.contains(token.as_str()), "audit event: {json}");
        }

        // Live responses that are not the issuance itself.
        for response in [
            broker.call("status", None),
            broker.call("credential.classes", None),
            broker.call("credential.validate", Some(json!({"value": token}))),
        ] {
            assert!(
                !response.to_string().contains(token.as_str()),
                "a response leaked a value: {response}"
            );
        }

        // The invalid-params answer for a secret-bearing method.
        assert!(!echoed.to_string().contains(token.as_str()));

        // The approval engine — an approval names a class, never a value.
        for envelope in broker.punard().envelopes() {
            assert!(!envelope.to_string().contains(token.as_str()));
        }
    }
    assert!(searched > 0, "the sweep must actually have read files");

    // ---- the negative control ---------------------------------------
    // If the grep above could not find anything, it would pass vacuously.
    // The class names *are* in the trail, so the search works.
    let trail = std::fs::read_to_string(&broker.audit).unwrap();
    assert!(trail.contains("github"), "the class name is recorded");
    assert!(trail.contains("aws-dev"), "the class name is recorded");
    assert!(trail.contains("aws-prod"), "the refused class is recorded");
    assert!(trail.contains("agt_redact01"), "attribution is recorded");
    assert!(
        !trail.contains("aws_dev"),
        "the ledger-facing spelling is kebab-case"
    );

    let _ = std::fs::remove_dir_all(&dir_holder);
}

/// **The swapped-argument mistake**, which is the one way a value reaches a
/// field that is not declared secret: `punarctl secrets get "$TOKEN"` instead
/// of `punarctl secrets get github`, or the same slip in the `credential`
/// hint of `validate`. Both are caller-authored strings that the broker
/// would otherwise quote back — into a message punarctl prints on stderr and
/// a script may be capturing.
///
/// The rule this pins (`server::unknown_class`): the broker quotes a
/// requested class name back **only when it is shaped like a class id**, and
/// a value never is. Nothing about the mistake is audited either: a typo is
/// not a security event, and an audit `resource` is the one field where a
/// caller-authored string would become a permanent record.
#[test]
fn a_value_pasted_where_a_class_name_belongs_is_neither_quoted_back_nor_recorded() {
    let broker = TestBroker::start(PeerSource::Fixed(Peer::user(1000)));
    let issued = broker.ok(
        "credential.request",
        Some(json!({"credential": "github", "ttl": 60})),
    );
    let token = value_of(&issued);
    let before = broker.events().len();

    // 1. The value where the class name goes.
    let error = broker.err("credential.request", Some(json!({"credential": token})));
    assert_eq!(error["code"], json!("not_found"));
    assert!(
        !error.to_string().contains(&token),
        "the refusal repeated the value: {error}"
    );
    assert!(
        error["message"].as_str().unwrap().contains("github"),
        "the refusal must still say what this device can issue: {error}"
    );

    // 2. The same slip in validate's class hint. (`value` is deliberately
    //    the token too, so a leak from either field would show.)
    let error = broker.err(
        "credential.validate",
        Some(json!({"credential": token, "value": token})),
    );
    assert!(
        !error.to_string().contains(&token),
        "the validate refusal repeated the value: {error}"
    );

    // 3. An id-shaped name is still quoted back — the message stays useful
    //    for the mistake it is actually for.
    let error = broker.err(
        "credential.request",
        Some(json!({"credential": "gcp-prod"})),
    );
    assert!(error["message"].as_str().unwrap().contains("gcp-prod"));

    // 4. Nothing above reached the trail, or any file the broker owns.
    assert_eq!(
        broker.events().len(),
        before,
        "a typo is not a security event, and an audit resource is forever"
    );
    for path in walk(&broker.dir) {
        let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap_or_default()).to_string();
        assert!(
            !text.contains(&token),
            "{} contains a credential value",
            path.display()
        );
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else if path.is_file() {
            found.push(path);
        }
    }
    found
}
