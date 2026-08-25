//! Integration tests: a real daemon on a tempdir socket, driven over the
//! wire exactly as punarctl will drive it (docs/api/ipc.md).
//!
//! The registry is the scriptable `MockCapability`; peer identity uses the
//! test-only `PeerSource::Fixed` hook (root vs non-root), plus one
//! Linux-only test of the real `SO_PEERCRED` path.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use punard::authz::{Peer, PeerSource};
use punard::capability::Registry;
use punard::capability::mock::MockCapability;
use punard::server::{Daemon, DaemonConfig, DaemonHandle};
use serde_json::{Value, json};

static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

struct TestDaemon {
    dir: PathBuf,
    handle: Option<DaemonHandle>,
    mock: MockCapability,
}

impl TestDaemon {
    fn start(peer: PeerSource) -> Self {
        let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("punard-it-{}-{seq}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        // /etc/{group,passwd} substitutes so username resolution is
        // deterministic regardless of the host.
        let group_file = dir.join("group");
        fs::write(&group_file, "root:x:0:\npunar:x:970:\n").unwrap();
        let passwd_file = dir.join("passwd");
        fs::write(
            &passwd_file,
            "root:x:0:0::/root:/bin/bash\npunar:x:1000:1000::/home/punar:/bin/nologin\n",
        )
        .unwrap();

        let mock = MockCapability::new("mock.widget", json!("off"));
        let registry = Registry::new(vec![Box::new(mock.clone())]);
        let cfg = DaemonConfig {
            group_file,
            passwd_file,
            peer_source: peer,
            io_timeout: Duration::from_secs(5),
            ..DaemonConfig::new(
                dir.join("punard.sock"),
                dir.join("state"),
                dir.join("audit.jsonl"),
            )
        };
        let daemon = Daemon::new(cfg, registry).unwrap();
        let handle = daemon.spawn().unwrap();
        TestDaemon {
            dir,
            handle: Some(handle),
            mock,
        }
    }

    fn start_as_root() -> Self {
        Self::start(PeerSource::Fixed(Peer::root()))
    }

    fn start_as_uid(uid: u32) -> Self {
        Self::start(PeerSource::Fixed(Peer {
            uid,
            gid: uid,
            pid: None,
        }))
    }

    fn connect(&self) -> UnixStream {
        let stream = UnixStream::connect(self.handle.as_ref().unwrap().socket_path()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
    }

    /// One request per connection, like punarctl.
    fn call(&self, method: &str, params: Option<Value>) -> Value {
        let mut req = json!({ "v": 1, "id": "t-1", "method": method });
        if let Some(p) = params {
            req["params"] = p;
        }
        self.raw(&format!("{req}"))
    }

    /// Send a raw line, read one response line.
    fn raw(&self, line: &str) -> Value {
        let mut stream = self.connect();
        stream.write_all(line.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        serde_json::from_str(&response).unwrap()
    }

    fn audit_lines(&self) -> Vec<Value> {
        match fs::read_to_string(self.dir.join("audit.jsonl")) {
            Ok(content) => content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str(l).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

const AUDIT_REQUIRED_KEYS: [&str; 12] = [
    "event_id",
    "timestamp",
    "device_id",
    "user_id",
    "agent_session_id",
    "project_id",
    "source",
    "action",
    "resource",
    "decision",
    "policy_ids",
    "result",
];

fn assert_schema_shaped(event: &Value) {
    let obj = event.as_object().unwrap();
    for key in AUDIT_REQUIRED_KEYS {
        assert!(obj.contains_key(key), "audit event missing {key}: {event}");
    }
    assert_eq!(obj.len(), 12, "additionalProperties: false — {event}");
    assert!(obj["event_id"].as_str().unwrap().starts_with("evt_"));
    assert!(obj["device_id"].as_str().unwrap().starts_with("dev_"));
    assert!(
        obj["agent_session_id"]
            .as_str()
            .unwrap()
            .starts_with("agt_")
    );
    let decision = obj["decision"].as_str().unwrap();
    assert!(matches!(decision, "allow" | "deny" | "approval_required"));
    let ts = obj["timestamp"].as_str().unwrap();
    assert_eq!(ts.len(), 20, "RFC3339 Z-form: {ts}");
    assert!(ts.ends_with('Z'));
}

#[test]
fn status_reports_personal_mode() {
    let td = TestDaemon::start_as_root();
    let resp = td.call("status", None);
    assert_eq!(resp["v"], 1);
    assert_eq!(resp["id"], "t-1");
    let result = &resp["result"];
    assert_eq!(result["protocol_version"], 1);
    assert_eq!(result["mode"], "personal");
    assert_eq!(result["enrolled"], false);
    assert!(result["device_id"].as_str().unwrap().starts_with("dev_"));
    assert_eq!(result["capabilities_total"], 1);
    assert!(result.get("audit").is_some());
    // Design section 8: no org fields exist in personal mode.
    assert!(result.get("org").is_none());
    assert!(result.get("organization").is_none());
}

#[test]
fn capabilities_list_returns_schema_shaped_descriptors() {
    let td = TestDaemon::start_as_root();
    let resp = td.call("capabilities.list", None);
    let caps = resp["result"]["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 1);
    let d = &caps[0];
    assert_eq!(d["capability"], "mock.widget");
    assert_eq!(d["supported"], true);
    assert_eq!(d["mutable"], true);
    assert_eq!(d["requires_reboot"], false);
    assert_eq!(d["managed_by"], "local");
    assert_eq!(d["privilege_required"], "root");
    assert_eq!(d["approval_requirement"], "allow");
    assert_eq!(d["current_state"], "off");
}

#[test]
fn set_as_root_applies_verifies_and_audits() {
    let td = TestDaemon::start_as_root();
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    assert!(resp.get("error").is_none(), "{resp}");
    assert_eq!(resp["result"]["changed"], true);
    assert_eq!(resp["result"]["descriptor"]["current_state"], "on");
    assert_eq!(td.mock.state(), json!("on"));
    assert_eq!(td.mock.apply_calls(), 1);

    let audit = td.audit_lines();
    let ev = audit.last().unwrap();
    assert_schema_shaped(ev);
    assert_eq!(ev["action"], "capabilities.set");
    assert_eq!(ev["resource"], "mock.widget");
    assert_eq!(ev["decision"], "allow");
    assert_eq!(ev["result"], "success");
    assert_eq!(ev["user_id"], "root");
    assert_eq!(ev["source"], "human");
    assert_eq!(ev["policy_ids"], json!(["personal-defaults"]));

    // Desired state was recorded.
    let desired: Value = serde_json::from_str(
        &fs::read_to_string(td.dir.join("state").join("desired.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(desired["mock.widget"], "on");
}

#[test]
fn set_as_non_root_is_denied_audited_and_does_not_mutate() {
    let td = TestDaemon::start_as_uid(1000);
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    let error = &resp["error"];
    assert_eq!(error["code"], "denied");
    // SPEC section 73 voice — the m3-check greps for these two markers.
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("administrator"), "{message}");
    assert!(message.contains("personal defaults"), "{message}");
    assert_eq!(error["details"]["capability"], "mock.widget");
    assert_eq!(error["details"]["policy_ids"], json!(["personal-defaults"]));

    // No mutation happened.
    assert_eq!(td.mock.state(), json!("off"));
    assert_eq!(td.mock.apply_calls(), 0);

    // The denial is audited.
    let audit = td.audit_lines();
    let ev = audit.last().unwrap();
    assert_schema_shaped(ev);
    assert_eq!(ev["decision"], "deny");
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["user_id"], "punar");
    assert_eq!(ev["policy_ids"], json!(["personal-defaults"]));
}

#[test]
fn reads_are_open_to_non_root_peers() {
    let td = TestDaemon::start_as_uid(1000);
    assert!(td.call("status", None).get("error").is_none());
    assert!(td.call("capabilities.list", None).get("error").is_none());
    assert!(
        td.call("audit.tail", Some(json!({ "n": 5 })))
            .get("error")
            .is_none()
    );
    // Reads are not audited in M3.
    assert!(td.audit_lines().is_empty());
}

#[test]
fn reconcile_reports_drift_but_never_remediates() {
    let td = TestDaemon::start_as_root();
    // Set desired = "on" (audited apply), then simulate external drift.
    td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    let applies_before = td.mock.apply_calls();
    td.mock.set_state(json!("tampered"));

    let resp = td.call("reconcile", None);
    let result = &resp["result"];
    assert_eq!(result["drift_count"], 1);
    let entry = &result["capabilities"][0];
    assert_eq!(entry["capability"], "mock.widget");
    assert_eq!(entry["desired_state"], "on");
    assert_eq!(entry["current_state"], "tampered");
    assert_eq!(entry["drift"], true);
    assert_eq!(entry["verified"], true);

    // Report only: no apply happened, state untouched.
    assert_eq!(td.mock.apply_calls(), applies_before);
    assert_eq!(td.mock.state(), json!("tampered"));

    let ev = td.audit_lines().pop().unwrap();
    assert_schema_shaped(&ev);
    assert_eq!(ev["action"], "reconcile");
    assert_eq!(ev["resource"], "capability_registry");
    assert_eq!(ev["result"], "drift_detected");

    // Fix the drift; a second reconcile is clean.
    td.mock.set_state(json!("on"));
    let resp = td.call("reconcile", None);
    assert_eq!(resp["result"]["drift_count"], 0);
    assert_eq!(td.audit_lines().pop().unwrap()["result"], "clean");
}

#[test]
fn reconcile_is_root_only_and_denials_are_audited() {
    let td = TestDaemon::start_as_uid(1000);
    let resp = td.call("reconcile", None);
    assert_eq!(resp["error"]["code"], "denied");
    let ev = td.audit_lines().pop().unwrap();
    assert_schema_shaped(&ev);
    assert_eq!(ev["action"], "reconcile");
    assert_eq!(ev["decision"], "deny");
}

#[test]
fn audit_tail_returns_newest_last_and_clamps() {
    let td = TestDaemon::start_as_root();
    for state in ["a1", "a2", "a3"] {
        td.call(
            "capabilities.set",
            Some(json!({ "capability": "mock.widget", "desired_state": state })),
        );
    }
    let resp = td.call("audit.tail", Some(json!({ "n": 2 })));
    let events = resp["result"]["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    for event in events {
        assert_schema_shaped(event);
    }
    // n over the cap is clamped, not an error.
    let resp = td.call("audit.tail", Some(json!({ "n": 100000 })));
    assert!(resp.get("error").is_none());
    // Default n.
    let resp = td.call("audit.tail", None);
    assert_eq!(resp["result"]["events"].as_array().unwrap().len(), 3);
}

#[test]
fn set_is_idempotent_with_noop_audit() {
    let td = TestDaemon::start_as_root();
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "off" })),
    );
    assert_eq!(resp["result"]["changed"], false);
    assert_eq!(td.mock.apply_calls(), 0);
    let ev = td.audit_lines().pop().unwrap();
    assert_schema_shaped(&ev);
    assert_eq!(ev["result"], "noop");
}

#[test]
fn apply_failures_are_typed_and_audited() {
    let td = TestDaemon::start_as_root();
    td.mock.fail_next_applies(true);
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    assert_eq!(resp["error"]["code"], "apply_failed");
    assert_eq!(resp["error"]["details"]["stage"], "apply");
    assert_eq!(td.audit_lines().pop().unwrap()["result"], "failure");
}

#[test]
fn verify_failures_are_typed_and_audited() {
    let td = TestDaemon::start_as_root();
    td.mock.force_verify_false(true);
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    assert_eq!(resp["error"]["code"], "verify_failed");
    assert_eq!(resp["error"]["details"]["expected"], "on");
    assert_eq!(td.audit_lines().pop().unwrap()["result"], "verify_failed");
}

#[test]
fn unknown_capability_is_not_found() {
    let td = TestDaemon::start_as_root();
    let resp = td.call(
        "capabilities.get",
        Some(json!({ "capability": "no.such_thing" })),
    );
    assert_eq!(resp["error"]["code"], "not_found");
    assert_eq!(resp["error"]["details"]["capability"], "no.such_thing");
}

#[test]
fn malformed_json_gets_typed_error_with_null_id_and_closes() {
    let td = TestDaemon::start_as_root();
    let mut stream = td.connect();
    stream.write_all(b"this is not json\n").unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["error"]["code"], "malformed_request");
    assert_eq!(resp["id"], Value::Null);
    // The connection is closed after a malformed request.
    line.clear();
    assert_eq!(reader.read_line(&mut line).unwrap(), 0);
}

#[test]
fn oversized_line_is_malformed_request() {
    let td = TestDaemon::start_as_root();
    let big = format!(
        r#"{{"v":1,"id":"big","method":"status","params":{{"x":"{}"}}}}"#,
        "y".repeat(8192)
    );
    let resp = td.raw(&big);
    assert_eq!(resp["error"]["code"], "malformed_request");
    assert!(
        resp["error"]["message"].as_str().unwrap().contains("4096"),
        "{resp}"
    );
}

#[test]
fn unsupported_version_is_rejected_with_supported_list() {
    let td = TestDaemon::start_as_root();
    let resp = td.raw(r#"{"v":2,"id":"vv","method":"status"}"#);
    assert_eq!(resp["error"]["code"], "unsupported_version");
    assert_eq!(resp["error"]["details"]["supported"], json!([1]));
    assert_eq!(resp["id"], "vv");
}

#[test]
fn no_exec_like_method_exists() {
    // SPEC sections 10, 60: the method table is closed; every generic
    // execution probe gets unknown_method — root included.
    let td = TestDaemon::start_as_root();
    for probe in [
        "system.exec",
        "shell.run",
        "exec",
        "run",
        "system.run_as_root",
        "debug.exec",
        "capabilities.exec",
    ] {
        let resp = td.call(probe, Some(json!({ "command": "id" })));
        assert_eq!(resp["error"]["code"], "unknown_method", "probe {probe}");
        assert_eq!(resp["error"]["details"]["method"], probe);
        assert!(
            resp["error"]["message"]
                .as_str()
                .unwrap()
                .contains("does not exist"),
            "{resp}"
        );
    }
}

#[test]
fn unknown_params_are_rejected_strictly() {
    let td = TestDaemon::start_as_root();
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on", "force": true })),
    );
    assert_eq!(resp["error"]["code"], "invalid_params");

    let resp = td.call("status", Some(json!({ "verbose": true })));
    assert_eq!(resp["error"]["code"], "invalid_params");
}

#[test]
fn invalid_desired_state_is_invalid_params() {
    let td = TestDaemon::start_as_root();
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": 42 })),
    );
    assert_eq!(resp["error"]["code"], "invalid_params");
    assert_eq!(resp["error"]["details"]["param"], "desired_state");
}

#[test]
fn multiple_requests_on_one_connection_are_sequential() {
    let td = TestDaemon::start_as_root();
    let mut stream = td.connect();
    stream
        .write_all(
            b"{\"v\":1,\"id\":\"a\",\"method\":\"status\"}\n{\"v\":1,\"id\":\"b\",\"method\":\"capabilities.list\"}\n",
        )
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let first: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(first["id"], "a");
    line.clear();
    reader.read_line(&mut line).unwrap();
    let second: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(second["id"], "b");
}

#[test]
fn device_id_is_stable_across_restarts() {
    let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("punard-devid-{}-{seq}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let make = || {
        let mock = MockCapability::new("mock.widget", json!("off"));
        let cfg = DaemonConfig {
            peer_source: PeerSource::Fixed(Peer::root()),
            ..DaemonConfig::new(
                dir.join("punard.sock"),
                dir.join("state"),
                dir.join("audit.jsonl"),
            )
        };
        Daemon::new(cfg, Registry::new(vec![Box::new(mock)]))
            .unwrap()
            .spawn()
            .unwrap()
    };

    let handle = make();
    let stream = UnixStream::connect(handle.socket_path()).unwrap();
    let first_id = status_device_id(stream);
    handle.stop();

    let handle = make();
    let stream = UnixStream::connect(handle.socket_path()).unwrap();
    let second_id = status_device_id(stream);
    handle.stop();

    assert_eq!(first_id, second_id);
    let _ = fs::remove_dir_all(&dir);
}

fn status_device_id(mut stream: UnixStream) -> String {
    stream
        .write_all(b"{\"v\":1,\"id\":\"s\",\"method\":\"status\"}\n")
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let resp: Value = serde_json::from_str(&line).unwrap();
    resp["result"]["device_id"].as_str().unwrap().to_string()
}

/// The real SO_PEERCRED path (Linux only, which is where `cargo test` runs
/// in CI — docker rust:1). Whether we are root decides which side of the
/// authz matrix we exercise; both sides assert *consistency* between the
/// peercred-derived decision and our actual uid.
#[cfg(target_os = "linux")]
#[test]
fn peercred_path_matches_actual_uid() {
    use std::os::unix::fs::MetadataExt;

    let td = TestDaemon::start(PeerSource::SoPeercred);
    // Our effective uid, read from a file we own.
    let probe = td.dir.join("uid-probe");
    fs::write(&probe, b"x").unwrap();
    let my_uid = fs::metadata(&probe).unwrap().uid();

    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    if my_uid == 0 {
        assert!(resp.get("error").is_none(), "{resp}");
        assert_eq!(td.mock.state(), json!("on"));
    } else {
        assert_eq!(resp["error"]["code"], "denied");
        assert_eq!(td.mock.state(), json!("off"));
    }
    // Reads work either way.
    assert!(td.call("status", None).get("error").is_none());
}
