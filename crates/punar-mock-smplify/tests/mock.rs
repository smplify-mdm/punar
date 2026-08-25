//! Integration tests: a real mock control plane on a tempdir socket,
//! driven over the wire exactly as `punard`'s enrollment client will drive
//! it (NDJSON, docs/api/ipc.md sections 2/3 framing).
//!
//! Fixture data is the **real** repo tree
//! (`fixtures/organizations/acme/`, path-relative to the crate) — the same
//! bytes `container-build.sh` stages into the image, so a fixture drift
//! that would break the in-VM m5-check breaks these host tests first.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use punar_mock_smplify::config::MockConfig;
use punar_mock_smplify::server::{MockHandle, MockServer};
use serde_json::{Value, json};

static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

/// A bootstrap secret of the shape `punard` sends: 32 random bytes,
/// hex-encoded (64 hex chars). Fixed here — the mock only shape-checks.
const BOOTSTRAP: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// The real Acme fixture tree, path-relative to this crate.
fn repo_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/organizations/acme")
}

fn read_fixture_json(name: &str) -> Value {
    let path = repo_fixtures().join(name);
    serde_json::from_slice(&fs::read(&path).expect("fixture file readable"))
        .expect("fixture file is valid JSON")
}

struct TestMock {
    dir: PathBuf,
    handle: Option<MockHandle>,
}

impl TestMock {
    fn start(tag: &str) -> TestMock {
        let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("punar-mock-it-{tag}-{}-{seq}", std::process::id()));
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
        assert!(self.handle.is_none(), "server already running");
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

    /// Stop and start again over the same state directory — the m5-check
    /// offline stop→start, in miniature.
    fn restart(&mut self) {
        self.stop();
        self.spawn_server();
    }

    /// One request, one connection (how `punarctl`/`punard` use the wire).
    fn call(&self, method: &str, params: Value) -> Value {
        self.raw_line(&json!({"v": 1, "id": "t-1", "method": method, "params": params}).to_string())
            .expect("server answers one line")
    }

    /// The `result` of a call that must succeed.
    fn call_ok(&self, method: &str, params: Value) -> Value {
        let response = self.call(method, params);
        assert_eq!(response["id"], "t-1", "id echoed: {response}");
        assert!(
            response.get("error").is_none(),
            "expected success from {method}: {response}"
        );
        response["result"].clone()
    }

    /// The `error` of a call that must fail; asserts the code.
    fn call_err(&self, method: &str, params: Value, code: &str) -> Value {
        let response = self.call(method, params);
        assert!(
            response.get("result").is_none(),
            "expected {code} from {method}: {response}"
        );
        assert_eq!(response["error"]["code"], code, "response: {response}");
        response["error"].clone()
    }

    /// Send one raw line, read back one response line (None on EOF).
    fn raw_line(&self, line: &str) -> Option<Value> {
        let mut stream = UnixStream::connect(self.socket()).expect("connect to mock socket");
        stream.write_all(line.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        read_response(&mut stream)
    }

    /// Register the standard test device; returns its token.
    fn enroll(&self) -> String {
        let result = self.call_ok(
            "enroll.register",
            json!({"device_id": "dev_it01", "bootstrap": BOOTSTRAP}),
        );
        result["device_token"].as_str().expect("token").to_string()
    }
}

impl Drop for TestMock {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn read_response(stream: &mut UnixStream) -> Option<Value> {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    let n = reader.read_line(&mut line).unwrap();
    if n == 0 {
        return None;
    }
    Some(serde_json::from_str(line.trim_end()).expect("response is one JSON object"))
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    if !path.exists() {
        return Vec::new();
    }
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("jsonl line parses"))
        .collect()
}

// ---------------------------------------------------------------------------
// Fixture loading against the real tree
// ---------------------------------------------------------------------------

#[test]
fn fixtures_load_and_compose_from_the_real_tree() {
    let set = punar_mock_smplify::fixtures::load(&repo_fixtures()).expect("real tree loads");
    assert_eq!(set.org_id, "acme");
    assert_eq!(set.domain, "acme.com");
    assert_eq!(set.organization, read_fixture_json("org.json"), "verbatim");

    // Baseline only (milestone-5.md section 4.4): one composed envelope.
    assert_eq!(set.policies.len(), 1);
    let policy = &set.policies[0];
    // Envelope fields verbatim…
    assert_eq!(policy["policy_id"], "eng-baseline-v12");
    assert_eq!(policy["source_kind"], "organization_baseline");
    assert_eq!(policy["precedence_rank"], 2);
    assert_eq!(policy["source_name"], "Acme Engineering Baseline");
    // …plus exactly one mechanical composition: the embedded payload.
    assert_eq!(
        policy["policy"],
        read_fixture_json("desired-state-eng-baseline-v12.json"),
        "embedded payload is the desired-state file, verbatim"
    );
    let envelope_fields: Vec<&String> = policy.as_object().unwrap().keys().collect();
    assert_eq!(
        envelope_fields.len(),
        5,
        "no invented fields: {envelope_fields:?}"
    );
}

#[test]
fn fixture_loading_fails_loudly_on_a_broken_tree() {
    let dir = std::env::temp_dir().join(format!("punar-mock-badfixtures-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    // No org.json at all.
    let err = punar_mock_smplify::fixtures::load(&dir).unwrap_err();
    assert!(err.to_string().contains("org.json"), "{err}");
    // org.json pointing at a payload that does not exist.
    fs::write(
        dir.join("org.json"),
        serde_json::to_vec(&json!({
            "id": "x", "name": "X",
            "discovery": {"domain": "x.test"},
            "enrollment": {"baseline_policy_id": "p1", "desired_state_file": "missing.json"}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("policy-source-p1.json"),
        serde_json::to_vec(&json!({"policy_id": "p1", "source_kind": "organization_baseline", "precedence_rank": 2}))
            .unwrap(),
    )
    .unwrap();
    let err = punar_mock_smplify::fixtures::load(&dir).unwrap_err();
    assert!(err.to_string().contains("missing.json"), "{err}");
    fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// org.discover
// ---------------------------------------------------------------------------

#[test]
fn org_discover_serves_the_org_fixture_verbatim() {
    let mock = TestMock::start("discover");
    let result = mock.call_ok("org.discover", json!({"domain": "acme.com"}));
    assert_eq!(result["organization"], read_fixture_json("org.json"));
    // DNS names are case-insensitive; normalization must not 404.
    let result = mock.call_ok("org.discover", json!({"domain": "ACME.com"}));
    assert_eq!(result["organization"]["id"], "acme");
}

#[test]
fn org_discover_unknown_domain_is_not_found() {
    let mock = TestMock::start("discover-404");
    let error = mock.call_err("org.discover", json!({"domain": "globex.com"}), "not_found");
    assert_eq!(error["details"]["domain"], "globex.com");
}

#[test]
fn org_discover_rejects_bad_params() {
    let mock = TestMock::start("discover-params");
    mock.call_err("org.discover", json!({}), "invalid_params");
    mock.call_err(
        "org.discover",
        json!({"domain": "acme.com", "extra": 1}),
        "invalid_params",
    );
}

// ---------------------------------------------------------------------------
// enroll.register
// ---------------------------------------------------------------------------

#[test]
fn enroll_register_issues_a_token_and_records_the_device() {
    let mock = TestMock::start("register");
    let result = mock.call_ok(
        "enroll.register",
        json!({"device_id": "dev_it01", "bootstrap": BOOTSTRAP}),
    );
    let token = result["device_token"].as_str().unwrap();
    assert!(token.starts_with("tok_"), "token shape: {token}");
    assert_eq!(token.len(), 36, "tok_ + 32 hex chars");
    assert!(token[4..].chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(result["attestation"], "simulated", "labeled, always");
    assert_eq!(result["organization"], read_fixture_json("org.json"));

    // The received side: devices.json carries the record.
    let devices: Value = serde_json::from_slice(
        &fs::read(mock.state_dir().join("devices.json")).expect("devices.json written"),
    )
    .unwrap();
    assert_eq!(devices["dev_it01"]["device_token"], token);
    assert_eq!(devices["dev_it01"]["attestation"], "simulated");
    let registered_at = devices["dev_it01"]["registered_at"].as_str().unwrap();
    assert!(
        punar_common::time::is_rfc3339_timestamp(registered_at),
        "registered_at is RFC 3339: {registered_at}"
    );
}

#[test]
fn enroll_register_shape_checks_the_bootstrap() {
    let mock = TestMock::start("register-bootstrap");
    // Too short.
    let error = mock.call_err(
        "enroll.register",
        json!({"device_id": "dev_it01", "bootstrap": "abcd1234"}),
        "invalid_params",
    );
    assert_eq!(error["details"]["param"], "bootstrap");
    // Long enough but not hex.
    mock.call_err(
        "enroll.register",
        json!({"device_id": "dev_it01", "bootstrap": "zz112233445566778899aabbccddeeff"}),
        "invalid_params",
    );
    // Empty device_id.
    mock.call_err(
        "enroll.register",
        json!({"device_id": "", "bootstrap": BOOTSTRAP}),
        "invalid_params",
    );
    assert!(
        !mock.state_dir().join("devices.json").exists(),
        "nothing recorded for rejected registrations"
    );
}

#[test]
fn reregistration_rotates_the_token() {
    let mock = TestMock::start("rotate");
    let first = mock.enroll();
    let second = mock.enroll();
    assert_ne!(first, second, "idempotent re-enroll mints a fresh token");
    mock.call_err(
        "policy.fetch",
        json!({"device_token": first}),
        "unauthorized",
    );
    mock.call_ok("policy.fetch", json!({"device_token": second}));
}

// ---------------------------------------------------------------------------
// policy.fetch
// ---------------------------------------------------------------------------

#[test]
fn policy_fetch_serves_the_composed_baseline() {
    let mock = TestMock::start("fetch");
    let token = mock.enroll();
    let result = mock.call_ok("policy.fetch", json!({"device_token": token}));
    let policies = result["policies"].as_array().unwrap();
    assert_eq!(
        policies.len(),
        1,
        "baseline only (eng-ai-v3 stays host-side)"
    );
    assert_eq!(policies[0]["policy_id"], "eng-baseline-v12");
    assert_eq!(policies[0]["precedence_rank"], 2);
    assert_eq!(
        policies[0]["policy"],
        read_fixture_json("desired-state-eng-baseline-v12.json")
    );
}

#[test]
fn policy_fetch_rejects_a_bad_token() {
    let mock = TestMock::start("fetch-badtoken");
    mock.enroll();
    let error = mock.call_err(
        "policy.fetch",
        json!({"device_token": "tok_00000000000000000000000000000000"}),
        "unauthorized",
    );
    assert!(
        error["message"].as_str().unwrap().contains("re-enroll"),
        "next step named: {error}"
    );
}

// ---------------------------------------------------------------------------
// compliance.report / inventory.report
// ---------------------------------------------------------------------------

#[test]
fn compliance_reports_append_to_the_received_log() {
    let mock = TestMock::start("compliance");
    let token = mock.enroll();
    let report = json!({
        "overall": "compliant",
        "capabilities": [
            {"capability": "security.firewall", "state": "compliant"},
        ],
    });
    let result = mock.call_ok(
        "compliance.report",
        json!({"device_token": token, "report": report}),
    );
    assert_eq!(result["accepted"], true);

    let lines = read_jsonl(&mock.state_dir().join("received-compliance.jsonl"));
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["device_id"], "dev_it01", "token-resolved id");
    assert_eq!(lines[0]["report"], report, "report stored verbatim");
    assert!(punar_common::time::is_rfc3339_timestamp(
        lines[0]["received_at"].as_str().unwrap()
    ));

    // Appends accumulate — one line per received report.
    mock.call_ok(
        "compliance.report",
        json!({"device_token": token, "report": {"overall": "drifted"}}),
    );
    let lines = read_jsonl(&mock.state_dir().join("received-compliance.jsonl"));
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1]["report"]["overall"], "drifted");
}

#[test]
fn compliance_report_requires_a_valid_token_and_object_report() {
    let mock = TestMock::start("compliance-guard");
    let token = mock.enroll();
    mock.call_err(
        "compliance.report",
        json!({"device_token": "tok_ffffffffffffffffffffffffffffffff", "report": {}}),
        "unauthorized",
    );
    mock.call_err(
        "compliance.report",
        json!({"device_token": token, "report": "not an object"}),
        "invalid_params",
    );
    assert!(
        read_jsonl(&mock.state_dir().join("received-compliance.jsonl")).is_empty(),
        "rejected reports are not recorded"
    );
}

#[test]
fn inventory_reports_append_to_their_own_log() {
    let mock = TestMock::start("inventory");
    let token = mock.enroll();
    let inventory = json!({
        "os": {"id": "punar", "version_id": "0.5"},
        "kernel": "6.12.0",
        "hostname": "punar-m5",
        "capabilities": [
            {"capability": "security.firewall", "supported": true, "current_state": "enabled"},
        ],
    });
    let result = mock.call_ok(
        "inventory.report",
        json!({"device_token": token, "inventory": inventory}),
    );
    assert_eq!(result["accepted"], true);

    let lines = read_jsonl(&mock.state_dir().join("received-inventory.jsonl"));
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["device_id"], "dev_it01");
    assert_eq!(lines[0]["inventory"], inventory, "stored verbatim");

    mock.call_err(
        "inventory.report",
        json!({"device_token": "tok_ffffffffffffffffffffffffffffffff", "inventory": {}}),
        "unauthorized",
    );
    assert_eq!(
        read_jsonl(&mock.state_dir().join("received-inventory.jsonl")).len(),
        1,
        "unauthorized reports are not recorded"
    );
}

// ---------------------------------------------------------------------------
// Method table edges
// ---------------------------------------------------------------------------

#[test]
fn admin_methods_are_reserved_for_m10() {
    let mock = TestMock::start("admin");
    for method in ["admin.devices", "admin.device"] {
        let error = mock.call_err(method, json!({}), "unknown_method");
        assert_eq!(error["details"]["method"], method);
        assert_eq!(error["details"]["reserved_for"], "M10");
        assert!(
            error["message"].as_str().unwrap().contains("Milestone 10"),
            "reserved-name message: {error}"
        );
    }
}

#[test]
fn unknown_methods_are_refused() {
    let mock = TestMock::start("unknown");
    for method in ["system.exec", "shell.run", "status"] {
        let error = mock.call_err(method, json!({}), "unknown_method");
        assert_eq!(error["details"]["method"], method);
    }
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

#[test]
fn malformed_json_answers_null_id_and_closes_the_connection() {
    let mock = TestMock::start("malformed");
    let mut stream = UnixStream::connect(mock.socket()).unwrap();
    stream.write_all(b"this is not json\n").unwrap();
    let response = read_response(&mut stream).expect("error response before close");
    assert_eq!(response["id"], Value::Null);
    assert_eq!(response["error"]["code"], "malformed_request");
    // Connection is closed: the next read is EOF.
    assert!(read_response(&mut stream).is_none());
}

#[test]
fn oversized_lines_are_a_framing_violation() {
    let mock = TestMock::start("oversize");
    let mut stream = UnixStream::connect(mock.socket()).unwrap();
    let huge = format!(
        r#"{{"v":1,"id":"t-big","method":"org.discover","params":{{"domain":"{}"}}}}"#,
        "a".repeat(5000)
    );
    stream.write_all(huge.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let response = read_response(&mut stream).expect("error response before close");
    assert_eq!(response["error"]["code"], "malformed_request");
    assert!(read_response(&mut stream).is_none(), "connection closed");
}

#[test]
fn wrong_protocol_version_is_refused_without_closing() {
    let mock = TestMock::start("version");
    let mut stream = UnixStream::connect(mock.socket()).unwrap();
    stream
        .write_all(b"{\"v\":2,\"id\":\"t-v2\",\"method\":\"org.discover\",\"params\":{\"domain\":\"acme.com\"}}\n")
        .unwrap();
    let response = read_response(&mut stream).expect("version error");
    assert_eq!(response["id"], "t-v2");
    assert_eq!(response["error"]["code"], "unsupported_version");
    assert_eq!(response["error"]["details"]["supported"], json!([1]));
    // Same connection still serves the corrected request (only framing
    // violations close).
    stream
        .write_all(b"{\"v\":1,\"id\":\"t-ok\",\"method\":\"org.discover\",\"params\":{\"domain\":\"acme.com\"}}\n")
        .unwrap();
    let response = read_response(&mut stream).expect("second response on one connection");
    assert_eq!(response["id"], "t-ok");
    assert_eq!(response["result"]["organization"]["id"], "acme");
}

#[test]
fn requests_on_one_connection_are_served_sequentially() {
    let mock = TestMock::start("sequential");
    let mut stream = UnixStream::connect(mock.socket()).unwrap();
    stream
        .write_all(b"{\"v\":1,\"id\":\"s-1\",\"method\":\"org.discover\",\"params\":{\"domain\":\"acme.com\"}}\n{\"v\":1,\"id\":\"s-2\",\"method\":\"org.discover\",\"params\":{\"domain\":\"acme.com\"}}\n")
        .unwrap();
    let first = read_response(&mut stream).unwrap();
    let second = read_response(&mut stream).unwrap();
    assert_eq!(first["id"], "s-1");
    assert_eq!(second["id"], "s-2");
}

// ---------------------------------------------------------------------------
// Transport posture and persistence
// ---------------------------------------------------------------------------

#[test]
fn socket_is_mode_0600() {
    let mock = TestMock::start("perms");
    let mode = fs::metadata(mock.socket()).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "root-only filesystem admission (milestone-5.md section 4.2)"
    );
}

#[test]
fn state_survives_a_restart() {
    let mut mock = TestMock::start("restart");
    let token = mock.enroll();
    mock.call_ok(
        "compliance.report",
        json!({"device_token": token, "report": {"overall": "compliant"}}),
    );

    mock.restart();

    // The token still authorizes — the m5-check offline stop→start must
    // not invalidate the device (milestone-5.md section 4.5).
    mock.call_ok("policy.fetch", json!({"device_token": token}));
    mock.call_ok(
        "compliance.report",
        json!({"device_token": token, "report": {"overall": "compliant"}}),
    );
    let lines = read_jsonl(&mock.state_dir().join("received-compliance.jsonl"));
    assert_eq!(lines.len(), 2, "append-only history spans restarts");
}

#[test]
fn stopped_mock_refuses_connections() {
    let mut mock = TestMock::start("stopped");
    mock.stop();
    assert!(
        UnixStream::connect(mock.socket()).is_err(),
        "socket removed on stop — the m5-check offline phase relies on this"
    );
}

// ---------------------------------------------------------------------------
// The binary itself
// ---------------------------------------------------------------------------

#[test]
fn binary_help_carries_the_dev_ci_banner() {
    let output = Command::new(env!("CARGO_BIN_EXE_punar-mock-smplify"))
        .arg("--help")
        .output()
        .expect("run punar-mock-smplify --help");
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains("dev/CI mock — not a product component"),
        "--help must carry the banner (milestone-5.md section 4.1), got:\n{help}"
    );
}

#[test]
fn binary_refuses_to_start_on_a_broken_fixture_dir() {
    let dir = std::env::temp_dir().join(format!("punar-mock-nofixtures-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_punar-mock-smplify"))
        .arg("--socket")
        .arg(dir.join("api.sock"))
        .arg("--fixtures")
        .arg(dir.join("empty"))
        .arg("--state-dir")
        .arg(dir.join("state"))
        .output()
        .expect("run punar-mock-smplify");
    assert!(!output.status.success(), "must fail loudly");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("startup failed"), "stderr: {stderr}");
    fs::remove_dir_all(&dir).unwrap();
}
