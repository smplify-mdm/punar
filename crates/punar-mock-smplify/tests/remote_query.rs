//! Milestone 10 integration tests for the mock's admin surface and the
//! pull-based query queue — a real mock on a tempdir socket, driven over
//! the wire exactly as an administrator's client and a device will drive it
//! (`docs/development/milestone-10.md` sections 7, 9.1, 12, 13.3).
//!
//! Fixture data is the **real** repo tree (`fixtures/organizations/acme/`,
//! including the new `admins.json`), so a fixture drift that would break
//! the in-VM `m10-check` breaks these host tests first.
//!
//! The load-bearing assertion in this file is not any single method: it is
//! `nothing_in_the_mock_can_reach_a_device`. Every other test here would
//! still pass if the mock pushed queries at devices; that one would not.

use std::fs;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use punar_mock_smplify::config::MockConfig;
use punar_mock_smplify::server::{MockHandle, MockServer};
use serde_json::{Value, json};

static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

const BOOTSTRAP: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const DEVICE: &str = "dev_m10test";

const HELPDESK: &str = "helpdesk@acme.com";
const CIO: &str = "cio@acme.com";
const SECOPS: &str = "secops@acme.com";

fn repo_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/organizations/acme")
}

struct TestMock {
    dir: PathBuf,
    handle: Option<MockHandle>,
}

impl TestMock {
    fn start(tag: &str) -> TestMock {
        let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("punar-mock-m10-{tag}-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut mock = TestMock { dir, handle: None };
        mock.spawn_server();
        mock
    }

    fn cfg(&self) -> MockConfig {
        MockConfig {
            socket: self.socket(),
            fixtures_dir: repo_fixtures(),
            state_dir: self.state_dir(),
        }
    }

    fn spawn_server(&mut self) {
        let server = MockServer::new(self.cfg()).expect("mock startup against the real fixtures");
        self.handle = Some(server.spawn().expect("bind tempdir socket"));
    }

    fn socket(&self) -> PathBuf {
        self.dir.join("api.sock")
    }

    fn state_dir(&self) -> PathBuf {
        self.dir.join("state")
    }

    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
    }

    fn restart(&mut self) {
        self.stop();
        self.spawn_server();
    }

    fn call(&self, method: &str, params: Value) -> Value {
        let line =
            json!({"v": 1, "id": "t-1", "method": method, "params": params}).to_string() + "\n";
        let mut stream = UnixStream::connect(self.socket()).expect("connect to mock socket");
        stream.write_all(line.as_bytes()).unwrap();
        let mut reader = std::io::BufReader::new(stream);
        let mut response = String::new();
        std::io::BufRead::read_line(&mut reader, &mut response).unwrap();
        serde_json::from_str(response.trim_end()).expect("one JSON response line")
    }

    fn call_ok(&self, method: &str, params: Value) -> Value {
        let response = self.call(method, params);
        assert!(
            response.get("error").is_none(),
            "expected success from {method}: {response}"
        );
        response["result"].clone()
    }

    fn call_err(&self, method: &str, params: Value, code: &str) -> Value {
        let response = self.call(method, params);
        assert!(
            response.get("result").is_none(),
            "expected {code} from {method}: {response}"
        );
        assert_eq!(response["error"]["code"], code, "response: {response}");
        response["error"].clone()
    }

    /// Register the test device and report once, so the admin surface has
    /// something honest to render.
    fn enrolled_device(&self) -> String {
        let token = self.call_ok(
            "enroll.register",
            json!({"device_id": DEVICE, "bootstrap": BOOTSTRAP}),
        )["device_token"]
            .as_str()
            .unwrap()
            .to_string();
        self.call_ok(
            "compliance.report",
            json!({"device_token": token, "report": {"overall": "compliant", "categories": []}}),
        );
        token
    }
}

impl Drop for TestMock {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The device's own answer document, as `punar-agentd` would produce it.
/// Labelled here rather than assumed: in these tests the device side is a
/// literal, because this file is about the **mock**; the punard suite
/// exercises the real courier path.
fn inventory_answer(query_id: &str) -> Value {
    json!({
        "query_id": query_id,
        "authorization_decision": "allow",
        "granted_scope": "inventory",
        "result_category": "answered",
        "payload": {
            "query_id": query_id,
            "device_id": DEVICE,
            "scope": "inventory",
            "answered_at": "2026-08-25T14:02:11Z",
            "counts": {"managed": 1, "observed": 0, "unknown": 1},
            "sessions": [{"session_id": "agt_4f21c09ab3e1", "agent": "claude-code",
                          "classification": "managed", "status": "active",
                          "started_at": "2026-08-25T13:44:02Z"}],
            "detections": [{"signature_id": "sig_9b02aa11cc22", "agent": "foo-agent",
                            "classification": "unknown", "suspected": true,
                            "zone": "downloads", "first_seen": "2026-08-25T13:59:41Z",
                            "live": true}],
            "not_yet_observed": [{"level": 3, "category": "mcp_servers",
                                  "milestone": "M11+",
                                  "reason": "no tool or MCP gateway mediates MCP traffic yet"}]
        },
        "audit_event_id": "evt_610"
    })
}

// ---------------------------------------------------------------------------
// Law 1 — Punar is not a server, and this crate cannot make it one
// ---------------------------------------------------------------------------

/// The structural assertion behind milestone-10.md law 1, made where the
/// temptation would live: **the control plane has no way to reach a
/// device.** A query is enqueued and simply sits there. No connection is
/// attempted, no address is stored, and the answer appears only after the
/// device dials in and asks.
#[test]
fn nothing_in_the_mock_can_reach_a_device() {
    let mock = TestMock::start("no-push");
    let token = mock.enrolled_device();

    let enqueued = mock.call_ok(
        "admin.ai_query",
        json!({"admin": CIO, "device_id": DEVICE, "scope": "inventory"}),
    );
    let query_id = enqueued["query_id"].as_str().unwrap().to_string();
    assert_eq!(enqueued["status"], "pending");
    assert!(
        enqueued["note"]
            .as_str()
            .unwrap()
            .contains("nothing is pushed"),
        "the latency and the mechanism are stated on the surface: {enqueued}"
    );

    // Time passes on the administrator's side. Nothing happens, because
    // nothing can happen: the mock has no device address and no client.
    for _ in 0..3 {
        let result = mock.call_ok(
            "admin.query_result",
            json!({"admin": CIO, "query_id": query_id}),
        );
        assert_eq!(result["status"], "pending", "no push exists: {result}");
    }

    // The mock's persisted state carries no endpoint, port, host or URL for
    // the device — there is nothing to dial even by accident.
    let queue = fs::read_to_string(mock.state_dir().join("queries.json")).unwrap();
    for probe in [
        "socket", "endpoint", "host", "port", "url", "callback", "push",
    ] {
        assert!(
            !queue.to_lowercase().contains(probe),
            "the queue must carry no way to reach a device ({probe}): {queue}"
        );
    }

    // Only when the device comes and asks does the question move.
    let pending = mock.call_ok("queries.pending", json!({"device_token": token}));
    assert_eq!(pending["queries"].as_array().unwrap().len(), 1);
    assert_eq!(pending["queries"][0]["query_id"], query_id.as_str());
}

// ---------------------------------------------------------------------------
// The lifecycle
// ---------------------------------------------------------------------------

#[test]
fn the_full_query_lifecycle_runs_over_the_device_pull() {
    let mut mock = TestMock::start("lifecycle");
    let token = mock.enrolled_device();

    let query_id = mock.call_ok(
        "admin.ai_query",
        json!({"admin": CIO, "device_id": DEVICE, "scope": "inventory"}),
    )["query_id"]
        .as_str()
        .unwrap()
        .to_string();

    // The device pulls. The pending shape is exactly the section 13.3 one —
    // and nothing more: no filter, no path, no expression.
    let pending = mock.call_ok("queries.pending", json!({"device_token": token}));
    let query = &pending["queries"][0];
    let mut keys: Vec<&str> = query
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "organization",
            "query_id",
            "received_at",
            "requested_scope",
            "requesting_admin"
        ],
        "the pulled question carries these five fields and no others"
    );
    assert_eq!(query["requesting_admin"], CIO);
    assert_eq!(query["organization"], "acme.com");
    assert_eq!(query["requested_scope"], "inventory");

    // The device answers. The mock stores it verbatim.
    let answer = inventory_answer(&query_id);
    assert_eq!(
        mock.call_ok(
            "queries.answer",
            json!({"device_token": token, "query_id": query_id, "answer": answer}),
        )["accepted"],
        true
    );

    // The administrator's poll now returns it, unedited.
    let result = mock.call_ok(
        "admin.query_result",
        json!({"admin": CIO, "query_id": query_id}),
    );
    assert_eq!(result["status"], "answered");
    assert_eq!(result["answer"], answer, "stored and served verbatim");
    assert_eq!(result["identity_verified"], false);

    // Answering closes the question: the device is not asked again.
    let after = mock.call_ok("queries.pending", json!({"device_token": token}));
    assert!(after["queries"].as_array().unwrap().is_empty());

    // Everything survives a restart — the same posture as the device
    // ledger, for the same reason (the check stops and starts the mock).
    mock.restart();
    let reloaded = mock.call_ok(
        "admin.query_result",
        json!({"admin": CIO, "query_id": query_id}),
    );
    assert_eq!(reloaded["answer"], answer);

    // And the append-only received log has the answer too.
    let answers = fs::read_to_string(mock.state_dir().join("received-answers.jsonl")).unwrap();
    assert_eq!(answers.lines().count(), 1);
}

#[test]
fn a_device_may_only_see_and_answer_its_own_questions() {
    let mock = TestMock::start("own-queue");
    let token = mock.enrolled_device();
    // A second device with its own token.
    let other = mock.call_ok(
        "enroll.register",
        json!({"device_id": "dev_other", "bootstrap": BOOTSTRAP}),
    )["device_token"]
        .as_str()
        .unwrap()
        .to_string();

    let mine = mock.call_ok(
        "admin.ai_query",
        json!({"admin": CIO, "device_id": DEVICE, "scope": "inventory"}),
    )["query_id"]
        .as_str()
        .unwrap()
        .to_string();

    let theirs = mock.call_ok("queries.pending", json!({"device_token": other}));
    assert!(
        theirs["queries"].as_array().unwrap().is_empty(),
        "one device's question is not another's: {theirs}"
    );
    mock.call_err(
        "queries.answer",
        json!({"device_token": other, "query_id": mine, "answer": inventory_answer(&mine)}),
        "not_found",
    );

    let unknown_token = mock.call_err(
        "queries.pending",
        json!({"device_token": "tok_notatoken"}),
        "unauthorized",
    );
    assert!(unknown_token["message"].as_str().unwrap().contains("token"));
    let _ = token;
}

// ---------------------------------------------------------------------------
// RBAC — the org-side half of SPEC section 24.1
// ---------------------------------------------------------------------------

/// A role that may not ask does not get to ask. The query is refused
/// **before** enqueuing, so the device never sees it — which is why the
/// device's own query log stays empty and the two checks are provably
/// independent (milestone-10.md section 16 group 8).
#[test]
fn a_role_that_may_not_ask_never_enqueues_anything() {
    let mock = TestMock::start("rbac");
    let token = mock.enrolled_device();

    let error = mock.call_err(
        "admin.ai_query",
        json!({"admin": HELPDESK, "device_id": DEVICE, "scope": "security_events"}),
        "denied",
    );
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("helpdesk"), "{message}");
    assert!(
        message.contains("inventory"),
        "names what is permitted: {message}"
    );
    assert!(
        message.contains("no device will ever see it"),
        "the refusal states that nothing was enqueued: {message}"
    );

    // Proof that nothing was enqueued: the device's pull is empty.
    let pending = mock.call_ok("queries.pending", json!({"device_token": token}));
    assert!(pending["queries"].as_array().unwrap().is_empty());
    let queue = mock.state_dir().join("queries.json");
    assert!(
        !queue.exists()
            || !fs::read_to_string(&queue)
                .unwrap()
                .contains("security_events"),
        "a refused role must leave no queue entry"
    );

    // helpdesk may still ask what its role carries.
    assert_eq!(
        mock.call_ok(
            "admin.ai_query",
            json!({"admin": HELPDESK, "device_id": DEVICE, "scope": "inventory"}),
        )["status"],
        "pending"
    );
}

/// The scope vocabulary is closed at the mock as well as at the device.
/// `everything` is not answered best-effort anywhere.
#[test]
fn a_scope_outside_the_closed_vocabulary_is_refused_at_the_mock() {
    let mock = TestMock::start("vocab");
    mock.enrolled_device();
    for probe in ["everything", "all", "*", "inventory ", "INVENTORY"] {
        let error = mock.call_err(
            "admin.ai_query",
            json!({"admin": SECOPS, "device_id": DEVICE, "scope": probe}),
            "out_of_scope",
        );
        let message = error["message"].as_str().unwrap();
        assert!(message.contains("vocabulary is closed"), "{message}");
        assert!(message.contains("no wildcard"), "{message}");
    }
}

#[test]
fn one_administrators_query_is_not_anothers_answer() {
    let mock = TestMock::start("crossread");
    mock.enrolled_device();
    let query_id = mock.call_ok(
        "admin.ai_query",
        json!({"admin": CIO, "device_id": DEVICE, "scope": "inventory"}),
    )["query_id"]
        .as_str()
        .unwrap()
        .to_string();
    mock.call_err(
        "admin.query_result",
        json!({"admin": SECOPS, "query_id": query_id}),
        "denied",
    );
    mock.call_err(
        "admin.query_result",
        json!({"admin": CIO, "query_id": "qry_nothing"}),
        "not_found",
    );
}

#[test]
fn the_admin_inventory_surface_renders_only_states_it_received() {
    let mock = TestMock::start("devices");
    mock.enrolled_device();

    let devices = mock.call_ok("admin.devices", json!({"admin": HELPDESK}));
    let row = &devices["devices"][0];
    assert_eq!(row["device_id"], DEVICE);
    assert_eq!(row["compliance_state"], "compliant");
    assert_eq!(row["attestation"], "simulated");
    assert!(row["last_sync"].is_string());
    assert_eq!(devices["identity_verified"], false);

    let device = mock.call_ok("admin.device", json!({"admin": CIO, "device_id": DEVICE}));
    // Compliance is category **states only** — the M5 privacy rule, not
    // relaxed by an admin surface (SPEC sections 24, 54).
    assert_eq!(device["compliance"]["overall"], "compliant");
    assert!(device["compliance"].get("values").is_none());
    // Nothing was ever reported as inventory in this test, so the field is
    // null — an absence, not a fabricated empty object.
    assert!(device["inventory"].is_null());
    assert!(device["queries"].as_array().unwrap().is_empty());

    mock.call_err(
        "admin.device",
        json!({"admin": CIO, "device_id": "dev_ghost"}),
        "not_found",
    );
}

// ---------------------------------------------------------------------------
// Fleet — the `—` vs `0` rule (milestone-10.md section 12)
// ---------------------------------------------------------------------------

#[test]
fn the_fleet_view_is_role_gated_and_never_claims_a_zero_it_cannot_back() {
    let mock = TestMock::start("fleet");
    let token = mock.enrolled_device();

    // helpdesk may not read the fleet view.
    mock.call_err("admin.fleet", json!({"admin": HELPDESK}), "denied");

    // Before anything is answered, every derived row is an absence.
    let before = mock.call_ok("admin.fleet", json!({"admin": CIO}));
    let fleet = &before["fleet"];
    assert_eq!(fleet["devices_enrolled"], 1);
    for row in fleet["agents"].as_array().unwrap() {
        assert_eq!(row["value"], "—", "nobody answered: {row}");
    }
    assert_eq!(fleet["findings"][2]["value"], "—");

    // Answer one inventory query, and only the inventory-derived rows move.
    let query_id = mock.call_ok(
        "admin.ai_query",
        json!({"admin": CIO, "device_id": DEVICE, "scope": "inventory"}),
    )["query_id"]
        .as_str()
        .unwrap()
        .to_string();
    mock.call_ok("queries.pending", json!({"device_token": token}));
    mock.call_ok(
        "queries.answer",
        json!({"device_token": token, "query_id": query_id,
               "answer": inventory_answer(&query_id)}),
    );

    let after = mock.call_ok("admin.fleet", json!({"admin": SECOPS}));
    let fleet = &after["fleet"];
    assert_eq!(fleet["agents"][0]["value"], 1); // Claude Code
    assert_eq!(fleet["agents"][1]["value"], 0); // Codex — a real, backed 0
    assert_eq!(fleet["agents"][3]["value"], 1); // Unknown
    assert_eq!(fleet["shadow_ai"]["distinct_signatures"], 1);
    // Still nothing at resource_summary, so the finding rows are still
    // absences. An inventory answer is not evidence about repositories.
    assert_eq!(fleet["findings"][0]["value"], "—");
    assert_eq!(fleet["findings"][2]["value"], "—");
}

/// `punar-mock-smplify --fleet` is a reader: it prints the aggregate and
/// binds nothing. The check greps this text (milestone-10.md section 16
/// group 12), so the exact honest strings are asserted here.
#[test]
fn the_fleet_binary_prints_dashes_and_never_zero_production_credentials() {
    let mock = TestMock::start("fleet-cli");
    let token = mock.enrolled_device();
    let query_id = mock.call_ok(
        "admin.ai_query",
        json!({"admin": CIO, "device_id": DEVICE, "scope": "inventory"}),
    )["query_id"]
        .as_str()
        .unwrap()
        .to_string();
    mock.call_ok("queries.pending", json!({"device_token": token}));
    mock.call_ok(
        "queries.answer",
        json!({"device_token": token, "query_id": query_id,
               "answer": inventory_answer(&query_id)}),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_punar-mock-smplify"))
        .arg("--fleet")
        .arg("--state-dir")
        .arg(mock.state_dir())
        .arg("--fixtures")
        .arg(repo_fixtures())
        .output()
        .expect("run the mock binary");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();

    assert!(
        text.contains("dev/CI mock — not a product component"),
        "{text}"
    );
    assert!(text.contains("Unknown"), "{text}");
    assert!(
        text.contains("1 unmanaged agent · 1 device · 1 distinct signature"),
        "{text}"
    );
    assert!(text.contains("accessing source repositories"), "{text}");
    assert!(text.contains("production credentials"), "{text}");
    assert!(text.contains('—'), "{text}");
    // The single most dangerous available dishonesty (section 12.2).
    assert!(!text.contains("0 production credentials"), "{text}");
    assert!(!text.contains("0 accessing source repositories"), "{text}");
    assert!(
        text.contains("not observable before M12"),
        "the row names its owning milestone: {text}"
    );
}

/// With no device having answered anything, the whole panel is dashes —
/// including on a mock that has never even seen a device.
#[test]
fn an_empty_fleet_prints_no_numbers_it_did_not_earn() {
    let mock = TestMock::start("fleet-empty");
    let output = Command::new(env!("CARGO_BIN_EXE_punar-mock-smplify"))
        .arg("--fleet")
        .arg("--state-dir")
        .arg(mock.state_dir())
        .arg("--fixtures")
        .arg(repo_fixtures())
        .output()
        .expect("run the mock binary");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("no device has answered a query yet"),
        "{text}"
    );
    assert!(!text.contains("0 production credentials"), "{text}");
    assert!(
        text.contains("— means nobody answered"),
        "the rule is printed with the table: {text}"
    );
}
