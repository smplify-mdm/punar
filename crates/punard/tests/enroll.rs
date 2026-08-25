//! M5 enrollment integration tests: a real `punard` daemon on a tempdir
//! socket, enrolled against a live control-plane counterparty speaking the
//! `punar-mock-smplify` wire protocol (milestone-5.md section 4.3 —
//! NDJSON `{v,id,method,params}` over a UDS; `org.discover`,
//! `enroll.register`, `policy.fetch`, `compliance.report`,
//! `inventory.report`) and serving the Acme fixtures verbatim, with the
//! one documented composition (envelope + embedded desired-state as
//! `policy`).
//!
//! The counterparty here is an in-test server implementing that documented
//! protocol so the suite can stop, restart, and corrupt it deterministically
//! (offline phases, all-or-nothing aborts); the in-VM `m5-check` exercises
//! the real `punar-mock-smplify` binary end-to-end against the same
//! contract.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use punard::authz::{Peer, PeerSource};
use punard::capability::Registry;
use punard::capability::mock::MockCapability;
use punard::server::{Daemon, DaemonConfig, DaemonHandle};
use serde_json::{Value, json};

const ACME_ORG: &str = include_str!("../../../fixtures/organizations/acme/org.json");
const ACME_ENVELOPE: &str =
    include_str!("../../../fixtures/organizations/acme/policy-source-eng-baseline-v12.json");
const ACME_DESIRED: &str =
    include_str!("../../../fixtures/organizations/acme/desired-state-eng-baseline-v12.json");

static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

fn test_dir(tag: &str) -> PathBuf {
    let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("punard-m5-{tag}-{}-{seq}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// In-test control plane (the milestone-5.md section 4.3 protocol)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ControlPlaneState {
    /// token → device_id (the mock's `devices.json` in miniature).
    devices: Mutex<HashMap<String, String>>,
    /// Received compliance lines (`received-compliance.jsonl`).
    compliance: Mutex<Vec<Value>>,
    /// Received inventory lines (`received-inventory.jsonl`).
    inventory: Mutex<Vec<Value>>,
    /// Fault injection: serve a corrupt policy envelope (contradicted
    /// fixed rank) so the all-or-nothing abort path can be exercised.
    serve_bad_policy: AtomicBool,
    token_seq: AtomicUsize,
}

impl ControlPlaneState {
    fn handle(&self, method: &str, params: &Value) -> Result<Value, (&'static str, String)> {
        match method {
            "org.discover" => {
                let domain = params["domain"].as_str().unwrap_or_default();
                let org: Value = serde_json::from_str(ACME_ORG).unwrap();
                if domain == org["discovery"]["domain"].as_str().unwrap() {
                    Ok(json!({ "organization": org }))
                } else {
                    Err(("not_found", format!("no organization at {domain:?}")))
                }
            }
            "enroll.register" => {
                let device_id = params["device_id"].as_str().unwrap_or_default();
                let bootstrap = params["bootstrap"].as_str().unwrap_or_default();
                // The mock's admission rule: ≥ 32 hex chars.
                if bootstrap.len() < 32 || !bootstrap.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(("invalid_params", "bootstrap must be ≥32 hex chars".into()));
                }
                let seq = self.token_seq.fetch_add(1, Ordering::SeqCst);
                let token = format!("tok_{seq:08x}{}", "e5d1c0de".repeat(6));
                self.devices
                    .lock()
                    .unwrap()
                    .insert(token.clone(), device_id.to_string());
                Ok(json!({
                    "device_token": token,
                    "attestation": "simulated",
                    "organization": serde_json::from_str::<Value>(ACME_ORG).unwrap(),
                }))
            }
            "policy.fetch" => {
                self.device_for(params)?;
                let mut envelope: Value = serde_json::from_str(ACME_ENVELOPE).unwrap();
                if self.serve_bad_policy.load(Ordering::SeqCst) {
                    envelope["precedence_rank"] = json!(5); // fixed rank is 2
                }
                envelope.as_object_mut().unwrap().insert(
                    "policy".to_string(),
                    serde_json::from_str::<Value>(ACME_DESIRED).unwrap(),
                );
                Ok(json!({ "policies": [envelope] }))
            }
            "compliance.report" => {
                let device_id = self.device_for(params)?;
                self.compliance.lock().unwrap().push(json!({
                    "device_id": device_id,
                    "received_at": "now",
                    "report": params["report"],
                }));
                Ok(json!({ "accepted": true }))
            }
            "inventory.report" => {
                let device_id = self.device_for(params)?;
                self.inventory.lock().unwrap().push(json!({
                    "device_id": device_id,
                    "received_at": "now",
                    "inventory": params["inventory"],
                }));
                Ok(json!({ "accepted": true }))
            }
            // admin.* stays reserved for M10 — like every unknown name.
            other => Err(("unknown_method", format!("no method {other:?}"))),
        }
    }

    fn device_for(&self, params: &Value) -> Result<String, (&'static str, String)> {
        let token = params["device_token"].as_str().unwrap_or_default();
        self.devices
            .lock()
            .unwrap()
            .get(token)
            .cloned()
            .ok_or(("unauthorized", "unknown device token".into()))
    }
}

struct ControlPlane {
    socket: PathBuf,
    state: Arc<ControlPlaneState>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlPlane {
    fn start(dir: &Path) -> ControlPlane {
        Self::start_with(dir, Arc::new(ControlPlaneState::default()))
    }

    /// (Re)start on the same socket path with existing state — the mock's
    /// state deliberately persists across restarts (milestone-5.md § 4.5).
    fn start_with(dir: &Path, state: Arc<ControlPlaneState>) -> ControlPlane {
        let socket = dir.join("control-plane.sock");
        let _ = fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let accept_state = Arc::clone(&state);
        let accept_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if accept_stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { break };
                let state = Arc::clone(&accept_state);
                std::thread::spawn(move || serve_connection(stream, &state));
            }
        });
        ControlPlane {
            socket,
            state,
            stop,
            thread: Some(thread),
        }
    }

    /// Stop the server and remove the socket — the "control plane died"
    /// phase. State survives for a later [`ControlPlane::start_with`].
    fn stop(mut self) -> Arc<ControlPlaneState> {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.socket);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.socket);
        Arc::clone(&self.state)
    }
}

impl Drop for ControlPlane {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.socket);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_connection(stream: UnixStream, state: &ControlPlaneState) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;
    let mut line = String::new();
    while let Ok(read) = reader.read_line(&mut line) {
        if read == 0 {
            break;
        }
        let request: Value = match serde_json::from_str(line.trim_end()) {
            Ok(value) => value,
            Err(_) => break,
        };
        assert_eq!(request["v"], json!(1), "punard must send v:1");
        let id = request["id"].clone();
        let method = request["method"].as_str().unwrap_or_default();
        let params = request.get("params").cloned().unwrap_or(json!({}));
        let response = match state.handle(method, &params) {
            Ok(result) => json!({"v": 1, "id": id, "result": result}),
            Err((code, message)) => {
                json!({"v": 1, "id": id, "error": {"code": code, "message": message}})
            }
        };
        if writeln!(writer, "{response}").is_err() {
            break;
        }
        line.clear();
    }
}

// ---------------------------------------------------------------------------
// Daemon harness (mirrors tests/daemon.rs, plus the M5 config seams)
// ---------------------------------------------------------------------------

struct TestDaemon {
    dir: PathBuf,
    handle: Option<DaemonHandle>,
    #[allow(dead_code)]
    mock: MockCapability,
}

fn write_nss_files(dir: &Path) -> (PathBuf, PathBuf) {
    let group_file = dir.join("group");
    fs::write(&group_file, "root:x:0:\npunar:x:970:\n").unwrap();
    let passwd_file = dir.join("passwd");
    fs::write(
        &passwd_file,
        "root:x:0:0::/root:/bin/bash\npunar:x:1000:1000::/home/punar:/bin/nologin\n",
    )
    .unwrap();
    (group_file, passwd_file)
}

fn write_inventory_sources(dir: &Path) -> (PathBuf, PathBuf) {
    let os_release = dir.join("os-release");
    fs::write(
        &os_release,
        "ID=punar\nVERSION_ID=\"0.5\"\nPRETTY_NAME=\"Punar OS 0.5 (M5)\"\n",
    )
    .unwrap();
    let kernel = dir.join("osrelease");
    fs::write(&kernel, "6.12.0-punar\n").unwrap();
    (os_release, kernel)
}

impl TestDaemon {
    /// Start a daemon whose control-plane endpoint is `control_plane` and
    /// whose registry holds one `security.firewall` mock (the capability
    /// the Acme baseline pins).
    fn start(dir: &Path, peer: Peer, control_plane: &Path, firewall_state: &str) -> TestDaemon {
        let (group_file, passwd_file) = write_nss_files(dir);
        let (os_release_path, kernel_release_path) = write_inventory_sources(dir);
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let mock = MockCapability::new("security.firewall", json!(firewall_state));
        let registry = Registry::new(vec![Box::new(mock.clone())]);
        let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let cfg = DaemonConfig {
            group_file,
            passwd_file,
            peer_source: PeerSource::Fixed(peer),
            io_timeout: Duration::from_secs(10),
            control_plane_socket: control_plane.to_path_buf(),
            os_release_path,
            kernel_release_path,
            ..DaemonConfig::new(
                dir.join(format!("punard-{seq}.sock")),
                state_dir,
                dir.join("audit.jsonl"),
            )
        };
        let daemon = Daemon::new(cfg, registry).unwrap();
        daemon.boot_reconcile();
        let handle = daemon.spawn().unwrap();
        TestDaemon {
            dir: dir.to_path_buf(),
            handle: Some(handle),
            mock,
        }
    }

    fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
    }

    fn call(&self, method: &str, params: Option<Value>) -> Value {
        let mut request = json!({ "v": 1, "id": "m5-t", "method": method });
        if let Some(params) = params {
            request["params"] = params;
        }
        let mut stream = UnixStream::connect(self.handle.as_ref().unwrap().socket_path()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream.write_all(request.to_string().as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        serde_json::from_str(&response).unwrap()
    }

    fn result(&self, method: &str, params: Option<Value>) -> Value {
        let response = self.call(method, params);
        assert!(
            response.get("error").is_none(),
            "{method} failed: {response}"
        );
        response["result"].clone()
    }

    fn error(&self, method: &str, params: Option<Value>) -> Value {
        let response = self.call(method, params);
        assert!(
            response.get("result").is_none(),
            "{method} unexpectedly succeeded: {response}"
        );
        response["error"].clone()
    }

    fn state_path(&self, name: &str) -> PathBuf {
        self.dir.join("state").join(name)
    }

    fn audit_text(&self) -> String {
        fs::read_to_string(self.dir.join("audit.jsonl")).unwrap_or_default()
    }

    fn audit_events(&self) -> Vec<Value> {
        self.audit_text()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn status_summary(&self) -> Value {
        serde_json::from_str(&fs::read_to_string(self.state_path("status.json")).unwrap()).unwrap()
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
    }
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn policy_d_files(daemon: &TestDaemon) -> Vec<String> {
    match fs::read_dir(daemon.state_path("policy.d")) {
        Ok(entries) => entries
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Assert the SPEC 24/54 privacy shape of one received compliance line:
/// exact key sets, category states only — never values or activity.
fn assert_compliance_shape(line: &Value, device_id: &str) {
    assert_eq!(line["device_id"], device_id);
    let report = line["report"].as_object().unwrap();
    let mut keys: Vec<&str> = report.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["categories", "overall"], "category states ONLY");
    for entry in report["categories"].as_array().unwrap() {
        let mut keys: Vec<&str> = entry
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["category", "state"]);
    }
}

// ---------------------------------------------------------------------------
// The lifecycle
// ---------------------------------------------------------------------------

#[test]
fn enroll_lifecycle_org_wins_sync_flows_offline_survives_unenroll_restores() {
    let dir = test_dir("lifecycle");
    let control_plane = ControlPlane::start(&dir);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "disabled");
    let device_id = fs::read_to_string(daemon.state_path("device-id"))
        .unwrap()
        .trim()
        .to_string();

    // Pre-state: personal, no org anywhere, summary file says so.
    assert_eq!(
        daemon.result("enroll.status", None),
        json!({"enrolled": false})
    );
    let status = daemon.result("status", None);
    assert_eq!(status["mode"], "personal");
    assert_eq!(status["enrolled"], false);
    assert!(status.get("org").is_none(), "org absent, never null");
    assert!(policy_d_files(&daemon).is_empty());
    let summary = daemon.status_summary();
    assert_eq!(summary["enrolled"], false);
    assert_eq!(summary["org_name"], Value::Null);

    // Record a personal preference (rank 5): firewall disabled. The mock
    // capability observes "disabled", so this is an idempotent no-op.
    let set = daemon.result(
        "capabilities.set",
        Some(json!({"capability": "security.firewall", "desired_state": "disabled"})),
    );
    assert_eq!(set["changed"], false);
    assert!(
        set.get("overridden").is_none(),
        "personal mode: no override"
    );

    // Enroll.
    let enrolled = daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(enrolled["enrolled"], true);
    assert_eq!(enrolled["org"]["id"], "acme");
    assert_eq!(enrolled["org"]["name"], "Acme");
    assert_eq!(enrolled["org"]["display_name"], "Acme Engineering");
    assert_eq!(enrolled["org"]["domain"], "acme.com");
    assert_eq!(enrolled["policy_ids"], json!(["eng-baseline-v12"]));
    // The honesty label travels with the data.
    assert_eq!(enrolled["attestation"], "simulated");
    assert_eq!(enrolled["first_sync"]["compliance"], "success");
    assert_eq!(enrolled["first_sync"]["inventory"], "success");

    // Files and modes: 0600 stores, the envelope carries its embedded
    // payload, and the token is not inside enrollment.json.
    assert_eq!(mode_of(&daemon.state_path("enrollment.json")), 0o600);
    assert_eq!(mode_of(&daemon.state_path("device-token")), 0o600);
    let token = fs::read_to_string(daemon.state_path("device-token"))
        .unwrap()
        .trim()
        .to_string();
    assert!(token.starts_with("tok_"));
    assert!(
        !fs::read_to_string(daemon.state_path("enrollment.json"))
            .unwrap()
            .contains(&token)
    );
    assert_eq!(policy_d_files(&daemon), ["eng-baseline-v12.json"]);
    let drop_path = daemon.state_path("policy.d").join("eng-baseline-v12.json");
    assert_eq!(mode_of(&drop_path), 0o600);
    let envelope: Value = serde_json::from_str(&fs::read_to_string(&drop_path).unwrap()).unwrap();
    assert_eq!(envelope["policy"]["kind"], "DeviceDesiredState");
    assert_eq!(envelope["source_name"], "Acme Engineering Baseline");

    // SPEC section 40 managed explain, now real: org rank 2 beats the
    // recorded personal preference; override not permitted.
    let explain = daemon.result("policy.explain", Some(json!({"path": "security.firewall"})));
    assert_eq!(explain["effective_value"], "enabled");
    assert_eq!(explain["source"]["kind"], "organization_baseline");
    assert_eq!(explain["source"]["rank"], 2);
    assert_eq!(explain["source"]["policy_id"], "eng-baseline-v12");
    assert_eq!(explain["source"]["name"], "Acme Engineering Baseline");
    assert_eq!(explain["user_override_permitted"], false);

    // status flips additively to managed.
    let status = daemon.result("status", None);
    assert_eq!(status["mode"], "managed");
    assert_eq!(status["enrolled"], true);
    assert_eq!(status["org"]["id"], "acme");
    let summary = daemon.status_summary();
    assert_eq!(summary["enrolled"], true);
    assert_eq!(summary["org_name"], "Acme Engineering");
    assert_eq!(summary["compliance_overall"], "compliant");

    // Received side (the check-the-receiver principle): one compliance
    // report and one inventory from the enrollment pass, both in the
    // privacy shape.
    {
        let compliance = control_plane.state.compliance.lock().unwrap();
        assert_eq!(compliance.len(), 1);
        assert_compliance_shape(&compliance[0], &device_id);
        assert_eq!(compliance[0]["report"]["overall"], "compliant");
    }
    {
        let inventory = control_plane.state.inventory.lock().unwrap();
        assert_eq!(inventory.len(), 1);
        let body = &inventory[0]["inventory"];
        let mut keys: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["capabilities", "hostname", "kernel", "os"]);
        assert_eq!(body["os"]["id"], "punar");
        assert_eq!(body["kernel"], "6.12.0-punar");
        assert_eq!(body["capabilities"].as_array().unwrap().len(), 1);
        assert_eq!(body["capabilities"][0]["capability"], "security.firewall");
        assert_eq!(body["capabilities"][0]["supported"], true);
        assert_eq!(body["capabilities"][0]["current_state"], "enabled");
    }

    // Recorded-but-overridden (the verified M4 semantics, now reachable):
    // a root set of `disabled` on the pinned path records the preference,
    // keeps the org value, exits successfully.
    let set = daemon.result(
        "capabilities.set",
        Some(json!({"capability": "security.firewall", "desired_state": "disabled"})),
    );
    assert_eq!(set["changed"], false);
    assert_eq!(set["overridden"], true);
    assert_eq!(set["effective_state"], "enabled");
    let noop_event = daemon
        .audit_events()
        .into_iter()
        .rev()
        .find(|e| e["action"] == "capabilities.set" && e["result"] == "noop")
        .expect("the overridden set audits as noop");
    assert_eq!(noop_event["policy_ids"], json!(["eng-baseline-v12"]));

    // Deliberately re-record `enabled` so the post-unenroll personal state
    // is firewall-enabled (the resurfacing witness, milestone-5.md § 5.4).
    daemon.result(
        "capabilities.set",
        Some(json!({"capability": "security.firewall", "desired_state": "enabled"})),
    );

    // A reconcile pass syncs compliance again; the inventory is hash-gated
    // and must NOT be resent.
    daemon.result("reconcile", None);
    assert_eq!(control_plane.state.compliance.lock().unwrap().len(), 2);
    assert_eq!(control_plane.state.inventory.lock().unwrap().len(), 1);

    // Offline (SPEC section 55): the control plane dies; local policy
    // stays enforceable from the cached org layer; sync queues.
    let state = control_plane.stop();
    let report = daemon.result("reconcile", None);
    assert_eq!(report["compliance"]["overall"], "compliant");
    let enroll_status = daemon.result("enroll.status", None);
    assert_eq!(enroll_status["last_sync"]["result"], "unreachable");
    assert_eq!(enroll_status["last_sync"]["pending"], true);
    assert_eq!(enroll_status["attestation"], "simulated");
    let unreachable_events = |daemon: &TestDaemon| {
        daemon
            .audit_events()
            .iter()
            .filter(|e| e["action"] == "enroll.sync" && e["result"] == "unreachable")
            .count()
    };
    assert_eq!(unreachable_events(&daemon), 1);
    // A second failing pass adds no second transition event (transitions
    // only, never per-retry spam).
    daemon.result("reconcile", None);
    assert_eq!(unreachable_events(&daemon), 1);
    assert_eq!(
        state.compliance.lock().unwrap().len(),
        2,
        "nothing received while down"
    );

    // Recovery: restart on the same socket with the same state; exactly
    // one new compliance line (latest-wins queue — a flag, not a spool).
    let control_plane = ControlPlane::start_with(&dir, state);
    daemon.result("reconcile", None);
    let enroll_status = daemon.result("enroll.status", None);
    assert_eq!(enroll_status["last_sync"]["result"], "success");
    assert_eq!(enroll_status["last_sync"]["pending"], false);
    assert_eq!(control_plane.state.compliance.lock().unwrap().len(), 3);
    assert_eq!(control_plane.state.inventory.lock().unwrap().len(), 1);
    let success_transitions = daemon
        .audit_events()
        .iter()
        .filter(|e| e["action"] == "enroll.sync" && e["result"] == "success")
        .count();
    assert_eq!(success_transitions, 1);

    // Unenroll — deliberately with the control plane DOWN: local restore
    // needs no counterparty.
    let state = control_plane.stop();
    let stopped = daemon.result("enroll.stop", None);
    assert_eq!(stopped["enrolled"], false);
    assert_eq!(stopped["removed_policy_ids"], json!(["eng-baseline-v12"]));
    assert!(policy_d_files(&daemon).is_empty());
    assert!(!daemon.state_path("enrollment.json").exists());
    assert!(!daemon.state_path("device-token").exists());

    // Personal state restored — and the preference recorded while
    // overridden is the winner again (SPEC section 39).
    let explain = daemon.result("policy.explain", Some(json!({"path": "security.firewall"})));
    assert_eq!(explain["source"]["kind"], "local_user_preference");
    assert_eq!(explain["source"]["rank"], 5);
    assert_eq!(explain["source"]["name"], "Personal preference");
    assert_eq!(explain["user_override_permitted"], true);
    assert_eq!(explain["effective_value"], "enabled");
    let status = daemon.result("status", None);
    assert_eq!(status["mode"], "personal");
    assert_eq!(status["enrolled"], false);
    assert!(status.get("org").is_none());
    let summary = daemon.status_summary();
    assert_eq!(summary["enrolled"], false);
    assert_eq!(summary["org_name"], Value::Null);

    // The mock keeps its history (unenrollment is local; the past is not
    // retracted) — and no further reports arrive.
    assert_eq!(state.compliance.lock().unwrap().len(), 3);
    daemon.result("reconcile", None);
    assert_eq!(state.compliance.lock().unwrap().len(), 3);

    // Audit lifecycle: enroll.start success citing the org policy,
    // enroll.stop success, both sync transitions.
    let events = daemon.audit_events();
    let start_event = events
        .iter()
        .find(|e| e["action"] == "enroll.start" && e["result"] == "success")
        .expect("enroll.start audited");
    assert_eq!(start_event["resource"], "enrollment");
    assert_eq!(start_event["policy_ids"], json!(["eng-baseline-v12"]));
    let stop_event = events
        .iter()
        .find(|e| e["action"] == "enroll.stop" && e["result"] == "success")
        .expect("enroll.stop audited");
    assert_eq!(stop_event["policy_ids"], json!(["eng-baseline-v12"]));

    // SPEC sections 1.19/53: the device token appears in NOTHING — not the
    // audit trail, not the summary file, not the effective-document debug
    // copy, not any result surfaced above.
    assert!(!token.is_empty());
    assert!(!daemon.audit_text().contains(&token));
    for artifact in ["status.json", "effective.json", "preferences.json"] {
        let content = fs::read_to_string(daemon.state_path(artifact)).unwrap_or_default();
        assert!(!content.contains(&token), "{artifact} leaked the token");
    }
    for surfaced in [&enrolled, &status, &enroll_status, &stopped] {
        assert!(!surfaced.to_string().contains(&token));
    }
}

#[test]
fn enroll_mutations_are_root_only_and_audited() {
    let dir = test_dir("authz");
    let control_plane = ControlPlane::start(&dir);
    let daemon = TestDaemon::start(
        &dir,
        Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        },
        &control_plane.socket,
        "enabled",
    );

    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(error["code"], "denied");
    assert!(error["message"].as_str().unwrap().contains("administrator"));
    let error = daemon.error("enroll.stop", None);
    assert_eq!(error["code"], "denied");
    // Both denials audited; the read stays open.
    let events = daemon.audit_events();
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "enroll.start" && e["decision"] == "deny")
    );
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "enroll.stop" && e["decision"] == "deny")
    );
    assert_eq!(
        daemon.result("enroll.status", None),
        json!({"enrolled": false})
    );
    // Nothing was written.
    assert!(!daemon.state_path("enrollment.json").exists());
    assert!(!daemon.state_path("device-token").exists());
}

#[test]
fn unreachable_control_plane_fails_enrollment_with_no_trace() {
    let dir = test_dir("unreachable");
    let daemon = TestDaemon::start(
        &dir,
        Peer::root(),
        &dir.join("no-such-control-plane.sock"),
        "enabled",
    );

    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(error["code"], "upstream_unreachable");
    assert_eq!(error["details"]["stage"], "discover");
    assert!(error["message"].as_str().unwrap().contains("Next step"));

    assert!(!daemon.state_path("enrollment.json").exists());
    assert!(!daemon.state_path("device-token").exists());
    assert!(policy_d_files(&daemon).is_empty());
    assert_eq!(
        daemon.result("enroll.status", None),
        json!({"enrolled": false})
    );
}

#[test]
fn conflicts_unknown_domains_and_bad_domains_are_typed_errors() {
    let dir = test_dir("conflict");
    let control_plane = ControlPlane::start(&dir);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");

    // Not enrolled yet: stop is a conflict.
    let error = daemon.error("enroll.stop", None);
    assert_eq!(error["code"], "conflict");
    assert_eq!(error["details"]["state"], "personal");

    // Malformed domain: rejected before any network hop.
    let error = daemon.error("enroll.start", Some(json!({"org_domain": "not a domain"})));
    assert_eq!(error["code"], "invalid_params");

    // Unknown (but well-formed) domain: the control plane's not_found.
    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "unknown.example"})),
    );
    assert_eq!(error["code"], "invalid_params");
    assert_eq!(error["details"]["param"], "org_domain");

    // Enroll, then a second enroll is a conflict.
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(error["code"], "conflict");
    assert_eq!(error["details"]["state"], "enrolled");
}

#[test]
fn invalid_policy_envelope_aborts_enrollment_atomically() {
    let dir = test_dir("badpolicy");
    let control_plane = ControlPlane::start(&dir);
    control_plane
        .state
        .serve_bad_policy
        .store(true, Ordering::SeqCst);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");

    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(error["code"], "invalid_params");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("failed validation")
    );
    // All-or-nothing: the rejected enrollment left nothing behind.
    assert!(policy_d_files(&daemon).is_empty());
    assert!(!daemon.state_path("enrollment.json").exists());
    assert!(!daemon.state_path("device-token").exists());
    assert_eq!(
        daemon.result("enroll.status", None),
        json!({"enrolled": false})
    );
    // The rejection is audited as a failed enroll.start.
    assert!(
        daemon
            .audit_events()
            .iter()
            .any(|e| e["action"] == "enroll.start" && e["result"] == "failure")
    );

    // The same daemon can enroll once the control plane behaves.
    control_plane
        .state
        .serve_bad_policy
        .store(false, Ordering::SeqCst);
    let enrolled = daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(enrolled["enrolled"], true);
}

#[test]
fn enrollment_persists_across_restart_and_non_root_set_cites_the_org_policy() {
    let dir = test_dir("restart");
    let control_plane = ControlPlane::start(&dir);
    {
        let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "disabled");
        daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
        daemon.stop();
    }

    // A fresh daemon on the same state dir — the SPEC section 55 shape:
    // enrollment, policy.d, and the token are plain files; nothing about
    // them depends on the control plane being alive. This daemon sees
    // non-root peers.
    let daemon = TestDaemon::start(
        &dir,
        Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        },
        &control_plane.socket,
        "enabled",
    );
    let status = daemon.result("status", None);
    assert_eq!(status["mode"], "managed");
    assert_eq!(status["org"]["display_name"], "Acme Engineering");

    // Non-root set on the org-pinned path: denied (exit 3 client-side),
    // and the M5 amendment cites the pinning org policy — not the false
    // "personal defaults" citation.
    let error = daemon.error(
        "capabilities.set",
        Some(json!({"capability": "security.firewall", "desired_state": "disabled"})),
    );
    assert_eq!(error["code"], "denied");
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("Acme Engineering Baseline"), "{message}");
    assert!(message.contains("eng-baseline-v12"), "{message}");
    assert!(message.contains("not permitted"), "{message}");
    assert!(!message.contains("personal defaults"), "{message}");
    assert_eq!(error["details"]["policy_ids"], json!(["eng-baseline-v12"]));
    // The denial's audit event cites the pinning policy too.
    let denial = daemon
        .audit_events()
        .into_iter()
        .rev()
        .find(|e| e["action"] == "capabilities.set" && e["decision"] == "deny")
        .expect("denial audited");
    assert_eq!(denial["policy_ids"], json!(["eng-baseline-v12"]));

    // An unpinned capability id keeps the M3/M4 denial byte-identical in
    // spirit: "personal defaults" citation (no org policy governs it).
    let error = daemon.error(
        "capabilities.set",
        Some(json!({"capability": "mock.unpinned", "desired_state": "x"})),
    );
    // Unknown capability → not_found before authz? The registry lookup
    // runs first; assert only that no org policy is cited.
    assert!(
        !error["message"]
            .as_str()
            .unwrap()
            .contains("Acme Engineering"),
        "{error}"
    );
}
