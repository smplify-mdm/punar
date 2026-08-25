//! Milestone 10 — the pull-based remote query, end to end
//! (`docs/development/milestone-10.md` sections 7, 9, 11).
//!
//! Three real processes-worth of parts, on tempdir sockets:
//!
//! - a **real `punar-mock-smplify`** instance (the binary the image ships,
//!   not a second in-test copy of the protocol) as the control plane;
//! - a **real `punard` daemon** as the courier;
//! - an in-test **stand-in for `punar-agentd`**, because the data owner's
//!   `query.answer` handler belongs to another cluster of this milestone.
//!
//! The stand-in is labelled everywhere it appears, per SPEC section 1.22,
//! and it is deliberately not a mock in the "returns a canned value" sense:
//! it calls [`punar_common::query::authorize`] against the **real**
//! `enrollment.json` that this daemon wrote, so the authorization tests
//! below exercise the shipped intersection over shipped state. What it
//! stands in for is the *projection* — building an inventory or a ledger
//! payload — which is `punar-agentd`'s work and not this cluster's.
//!
//! The two assertions worth reading first are
//! `punard_opens_no_listening_socket_for_admin_traffic` (law 1) and
//! `a_personal_device_fetches_nothing_and_connects_to_nothing` (section 11
//! gate A). Everything else here would still pass on a design that listened.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use punar_common::query::{
    AuthorizationDecision, QueryScope, ResultCategory, authorize, read_org_granted_scopes,
};
use punar_mock_smplify::config::MockConfig;
use punar_mock_smplify::server::{MockHandle, MockServer};
use punard::authz::{Peer, PeerSource};
use punard::capability::Registry;
use punard::capability::mock::MockCapability;
use punard::server::{Daemon, DaemonConfig, DaemonHandle};
use serde_json::{Value, json};

static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

const CIO: &str = "cio@acme.com";
const SECOPS: &str = "secops@acme.com";
const HELPDESK: &str = "helpdesk@acme.com";

fn repo_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/organizations/acme")
}

fn test_dir(tag: &str) -> PathBuf {
    let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("punard-m10-{tag}-{}-{seq}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// The control plane: the real dev/CI mock
// ---------------------------------------------------------------------------

struct ControlPlane {
    socket: PathBuf,
    state_dir: PathBuf,
    handle: Option<MockHandle>,
}

impl ControlPlane {
    fn start(dir: &Path) -> ControlPlane {
        let socket = dir.join("control-plane.sock");
        let state_dir = dir.join("mock-state");
        let server = MockServer::new(MockConfig {
            socket: socket.clone(),
            fixtures_dir: repo_fixtures(),
            state_dir: state_dir.clone(),
        })
        .expect("mock startup against the real Acme fixtures");
        ControlPlane {
            socket,
            state_dir,
            handle: Some(server.spawn().expect("bind tempdir socket")),
        }
    }

    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
    }

    fn call(&self, method: &str, params: Value) -> Value {
        let line =
            json!({"v": 1, "id": "m10-t", "method": method, "params": params}).to_string() + "\n";
        let mut stream = UnixStream::connect(&self.socket).expect("connect to the mock");
        // A wedged counterparty must fail this test, never hang it.
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        stream.write_all(line.as_bytes()).unwrap();
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        serde_json::from_str(response.trim_end()).unwrap()
    }

    fn result(&self, method: &str, params: Value) -> Value {
        let response = self.call(method, params);
        assert!(
            response.get("error").is_none(),
            "{method} failed: {response}"
        );
        response["result"].clone()
    }

    /// Enqueue one admin question and return its id.
    fn ask(&self, admin: &str, device_id: &str, scope: &str) -> String {
        self.result(
            "admin.ai_query",
            json!({"admin": admin, "device_id": device_id, "scope": scope}),
        )["query_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn query_result(&self, admin: &str, query_id: &str) -> Value {
        self.result(
            "admin.query_result",
            json!({"admin": admin, "query_id": query_id}),
        )
    }

    /// How many times a device has connected and reported — read from the
    /// mock's own received logs, which is the only honest way to ask
    /// "did this device talk to the control plane?".
    fn received_lines(&self) -> usize {
        [
            "received-compliance.jsonl",
            "received-inventory.jsonl",
            "received-answers.jsonl",
        ]
        .iter()
        .map(|f| {
            fs::read_to_string(self.state_dir.join(f))
                .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
                .unwrap_or(0)
        })
        .sum()
    }
}

impl Drop for ControlPlane {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// The data owner: an in-test STAND-IN for punar-agentd (labelled, SPEC 1.22)
// ---------------------------------------------------------------------------

/// A stand-in for `punar-agentd`'s `query.answer` handler.
///
/// **What is real here:** the authorization. It calls the shipped
/// [`authorize`] against the **real** `enrollment.json` the daemon under
/// test wrote, so "the data owner re-evaluates from local state" is
/// exercised, not asserted.
///
/// **What is simulated here:** the projection. Building an inventory answer
/// or a ledger summary is `punar-agentd`'s work and another cluster's code;
/// this stand-in returns a fixed, deliberately tiny payload so the courier
/// path can be tested without it. Nothing about the *decision* is faked.
struct AgentdStandIn {
    /// The `enrollment.json` the daemon under test writes. Read afresh on
    /// every call — that is the point of the test.
    enrollment_path: PathBuf,
    calls: AtomicUsize,
    /// Last params punard handed over, for the "no grant travels with the
    /// request" assertion.
    last_params: Mutex<Option<Value>>,
    scans: Mutex<Vec<String>>,
}

impl AgentdStandIn {
    fn handle(&self, method: &str, params: &Value) -> Result<Value, (&'static str, String)> {
        match method {
            "agents.scan" => {
                self.scans.lock().unwrap().push(
                    params
                        .get("trigger")
                        .and_then(Value::as_str)
                        .unwrap_or("manual")
                        .to_string(),
                );
                Ok(json!({"scanned": true}))
            }
            "query.answer" => {
                self.calls.fetch_add(1, Ordering::SeqCst);
                *self.last_params.lock().unwrap() = Some(params.clone());

                // THE authority step, run for real: org_granted is read
                // from the local file, never from `params`.
                let grant = read_org_granted_scopes(&self.enrollment_path);
                let requested = params
                    .get("requested_scope")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let auth = authorize(requested, &grant);
                let query_id = params
                    .get("query_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();

                if !auth.is_allowed() {
                    return Ok(json!({
                        "query_id": query_id,
                        "authorization_decision": auth.decision.as_str(),
                        "result_category": ResultCategory::Refused.as_str(),
                        "refusal_reason": auth.refusal_reason,
                        "refusal_message": auth.message,
                        "audit_event_id": "evt_stand_in",
                    }));
                }
                Ok(json!({
                    "query_id": query_id,
                    "authorization_decision": AuthorizationDecision::Allow.as_str(),
                    "granted_scope": auth.granted_scope.map(QueryScope::as_str),
                    "result_category": ResultCategory::Answered.as_str(),
                    "payload": {
                        "query_id": query_id,
                        "scope": requested,
                        "counts": {"managed": 0, "observed": 0, "unknown": 0},
                        "sessions": [],
                        "detections": [],
                        "_stand_in": "projection simulated in this test; the real \
                                      payload is punar-agentd's",
                    },
                    "audit_event_id": "evt_stand_in",
                }))
            }
            other => Err(("unknown_method", format!("no method {other:?}"))),
        }
    }
}

struct Agentd {
    socket: PathBuf,
    state: Arc<AgentdStandIn>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Agentd {
    fn start(dir: &Path, enrollment_path: PathBuf) -> Agentd {
        let socket = dir.join("agentd.sock");
        let _ = fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        let state = Arc::new(AgentdStandIn {
            enrollment_path,
            calls: AtomicUsize::new(0),
            last_params: Mutex::new(None),
            scans: Mutex::new(Vec::new()),
        });
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
                std::thread::spawn(move || serve_agentd(stream, &state));
            }
        });
        Agentd {
            socket,
            state,
            stop,
            thread: Some(thread),
        }
    }

    /// Idempotent, and it has to be: `punard_never_answers_on_the_data_owners_behalf`
    /// stops this server and then starts a **new one on the same path**, so
    /// the old value's `Drop` runs after the new socket already exists. A
    /// second stop that still unlinked the path would delete the new
    /// server's socket out from under it — and then the new server's own
    /// stop could never wake its `accept(2)`, which hangs the suite rather
    /// than failing it.
    fn stop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.socket);
        let _ = thread.join();
        let _ = fs::remove_file(&self.socket);
    }
}

impl Drop for Agentd {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve_agentd(stream: UnixStream, state: &AgentdStandIn) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;
    let mut line = String::new();
    while let Ok(read) = reader.read_line(&mut line) {
        if read == 0 {
            break;
        }
        let Ok(request) = serde_json::from_str::<Value>(line.trim_end()) else {
            break;
        };
        assert_eq!(request["v"], json!(1), "punard must send v:1 to agentd");
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
// The daemon under test
// ---------------------------------------------------------------------------

struct TestDaemon {
    dir: PathBuf,
    handle: Option<DaemonHandle>,
    #[allow(dead_code)]
    mock: MockCapability,
}

impl TestDaemon {
    fn start(dir: &Path, control_plane: &Path, agentd_socket: &Path) -> TestDaemon {
        let group_file = dir.join("group");
        fs::write(&group_file, "root:x:0:\npunar:x:970:\n").unwrap();
        let passwd_file = dir.join("passwd");
        fs::write(
            &passwd_file,
            "root:x:0:0::/root:/bin/bash\npunar:x:1000:1000::/home/punar:/bin/nologin\n",
        )
        .unwrap();
        let os_release = dir.join("os-release");
        fs::write(&os_release, "ID=punar\nVERSION_ID=\"0.10\"\n").unwrap();
        let kernel = dir.join("osrelease");
        fs::write(&kernel, "6.12.0-punar\n").unwrap();

        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let mock = MockCapability::new("security.firewall", json!("enabled"));
        let registry = Registry::new(vec![Box::new(mock.clone())]);
        let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let cfg = DaemonConfig {
            group_file,
            passwd_file,
            peer_source: PeerSource::Fixed(Peer::root()),
            io_timeout: Duration::from_secs(10),
            control_plane_socket: control_plane.to_path_buf(),
            agentd_socket: agentd_socket.to_path_buf(),
            os_release_path: os_release,
            kernel_release_path: kernel,
            ..DaemonConfig::new(
                dir.join(format!("punard-{seq}.sock")),
                state_dir,
                dir.join("audit.jsonl"),
            )
        };
        let daemon = Daemon::new(cfg, registry).unwrap();
        daemon.boot_reconcile();
        TestDaemon {
            dir: dir.to_path_buf(),
            handle: Some(daemon.spawn().unwrap()),
            mock,
        }
    }

    fn call(&self, method: &str, params: Option<Value>) -> Value {
        let mut request = json!({ "v": 1, "id": "m10-t", "method": method });
        if let Some(params) = params {
            request["params"] = params;
        }
        let mut stream = UnixStream::connect(self.handle.as_ref().unwrap().socket_path()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
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

    fn enrollment_path(&self) -> PathBuf {
        self.dir.join("state").join("enrollment.json")
    }

    fn device_id(&self) -> String {
        fs::read_to_string(self.dir.join("state").join("device-id"))
            .unwrap()
            .trim()
            .to_string()
    }
}

impl TestDaemon {
    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The whole rig, wired the way the image wires it.
struct Rig {
    dir: PathBuf,
    cp: ControlPlane,
    agentd: Agentd,
    daemon: TestDaemon,
}

fn rig(tag: &str) -> Rig {
    let dir = test_dir(tag);
    let cp = ControlPlane::start(&dir);
    let agentd = Agentd::start(&dir, dir.join("state").join("enrollment.json"));
    let daemon = TestDaemon::start(&dir, &cp.socket, &agentd.socket);
    Rig {
        dir,
        cp,
        agentd,
        daemon,
    }
}

impl Rig {
    fn enroll(&self) -> String {
        let result = self
            .daemon
            .result("enroll.start", Some(json!({ "org_domain": "acme.com" })));
        assert_eq!(result["enrolled"], true, "{result}");
        self.daemon.device_id()
    }

    /// One reconcile pass — the sync piggyback the query pull rides.
    fn reconcile(&self) {
        self.daemon.result("reconcile", None);
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        // Order matters and is the kind of thing that costs an afternoon:
        // every server here shuts its accept loop down by connecting to its
        // own socket to wake `accept(2)`. Removing the directory first
        // deletes those socket files, the nudge connect fails, and the join
        // blocks forever. Stop the servers, *then* sweep the tempdir.
        self.daemon.stop();
        self.agentd.stop();
        self.cp.stop();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// Law 1 — no inbound socket, port or listener for admin traffic
// ---------------------------------------------------------------------------

/// The structural assertion behind milestone-10.md law 1.
///
/// Two halves, because either alone is weak. **Source-structural:** the
/// only listener punard constructs anywhere is its own local IPC socket,
/// and no TCP type appears in the crate at all. **Runtime:** with the whole
/// query path live and a query just answered, this process holds no TCP
/// socket in `LISTEN` state, and the only listening Unix sockets it holds
/// are the three tempdir sockets this test itself created.
#[test]
fn punard_opens_no_listening_socket_for_admin_traffic() {
    // --- half one: the code cannot grow one by accident ---
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut listener_sites: Vec<String> = Vec::new();
    let mut walk = vec![src.clone()];
    while let Some(path) = walk.pop() {
        for entry in fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                walk.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            let rel = path.strip_prefix(&src).unwrap().display().to_string();
            for forbidden in [
                "TcpListener",
                "TcpStream",
                "SocketAddrV4",
                "AF_INET",
                "bind_tcp",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{rel} names {forbidden}: punar opens no network surface (law 1)"
                );
            }
            for (n, line) in text.lines().enumerate() {
                if line.contains("UnixListener::bind") || line.contains("net::listen(") {
                    listener_sites.push(format!("{rel}:{}", n + 1));
                }
            }
        }
    }
    assert_eq!(
        listener_sites.len(),
        1,
        "punard constructs exactly one listener — its own local IPC socket. \
         Found: {listener_sites:?}"
    );
    assert!(
        listener_sites[0].starts_with("server.rs"),
        "the one listener is the local IPC server, not a query endpoint: {listener_sites:?}"
    );

    // --- half two: and at runtime, with the query path live, none exists ---
    let rig = rig("no-listener");
    let device = rig.enroll();
    let query_id = rig.cp.ask(CIO, &device, "inventory");
    rig.reconcile();
    assert_eq!(
        rig.cp.query_result(CIO, &query_id)["status"],
        "answered",
        "the path is live for this assertion to mean anything"
    );

    if let Ok(tcp) = fs::read_to_string("/proc/self/net/tcp") {
        // st == 0A is TCP_LISTEN.
        for line in tcp.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert_ne!(
                fields.get(3).copied(),
                Some("0A"),
                "a TCP listener exists in this process: {line}"
            );
        }
    }
    if let Ok(unix) = fs::read_to_string("/proc/self/net/unix") {
        let ours = rig.dir.display().to_string();
        for line in unix.lines().skip(1) {
            // A listening UDS has st == 01 and a path in the last column.
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.get(5).copied() != Some("01") {
                continue;
            }
            let Some(path) = fields.get(7) else { continue };
            if !path.starts_with(&ours) {
                continue;
            }
            assert!(
                path.ends_with("punard-0.sock")
                    || path.ends_with("punard-2.sock")
                    || path.contains("punard-")
                    || path.ends_with("control-plane.sock")
                    || path.ends_with("agentd.sock"),
                "an unexpected listening socket exists in the rig: {path}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The lifecycle (milestone-10.md sections 7.2, 16 group 7)
// ---------------------------------------------------------------------------

#[test]
fn an_enrolled_device_answers_an_authorized_query_within_one_reconcile_pass() {
    let rig = rig("answer");
    let device = rig.enroll();

    // The grant is what the org document asked for, persisted locally.
    let status = rig.daemon.result("enroll.status", None);
    assert_eq!(
        status["remote_query_scopes"],
        json!(["inventory", "authority"]),
        "{status}"
    );

    let query_id = rig.cp.ask(CIO, &device, "inventory");
    assert_eq!(rig.cp.query_result(CIO, &query_id)["status"], "pending");

    // One pass. No timer of its own, no listener, no push.
    rig.reconcile();

    let result = rig.cp.query_result(CIO, &query_id);
    assert_eq!(result["status"], "answered", "{result}");
    assert_eq!(result["answer"]["authorization_decision"], "allow");
    assert_eq!(result["answer"]["granted_scope"], "inventory");

    // `enroll.status` shows the metadata, and never the payload.
    let status = rig.daemon.result("enroll.status", None);
    assert_eq!(status["last_query"]["scope"], "inventory");
    assert_eq!(status["last_query"]["decision"], "allow");
    assert!(status.to_string().find("payload").is_none(), "{status}");
}

/// The answer that reaches the control plane is the data owner's bytes.
/// punard is a courier: it has no field in which it could edit one.
#[test]
fn the_answer_is_posted_back_verbatim() {
    let rig = rig("verbatim");
    let device = rig.enroll();
    let query_id = rig.cp.ask(CIO, &device, "inventory");
    rig.reconcile();

    let posted = rig.cp.query_result(CIO, &query_id)["answer"].clone();
    // The stand-in's marker survives untouched — punard neither read nor
    // rewrote the payload.
    assert_eq!(
        posted["payload"]["_stand_in"],
        "projection simulated in this test; the real payload is punar-agentd's"
    );
    assert_eq!(posted["audit_event_id"], "evt_stand_in");

    // And the handover carried no grant, role, token or policy — nothing
    // through which a courier could widen its own authority (SPEC 59.4).
    let handed = rig
        .agentd
        .state
        .last_params
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    let keys: Vec<&str> = handed
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    for forbidden in [
        "granted_scope",
        "org_granted",
        "remote_query_scopes",
        "device_token",
        "role",
        "policy",
    ] {
        assert!(!keys.contains(&forbidden), "handover carried {forbidden}");
    }
    assert_eq!(handed["requested_scope"], "inventory");
    assert_eq!(handed["requesting_admin"], CIO);
}

// ---------------------------------------------------------------------------
// Scope enforcement (milestone-10.md sections 9.2, 16 group 8)
// ---------------------------------------------------------------------------

/// The device refuses a scope its own enrollment never granted — even
/// though the *role* that asked is permitted to ask for it. This is the
/// case that proves the two checks are independent and that the device's is
/// the one that decides.
#[test]
fn an_out_of_scope_query_is_refused_by_the_device_in_section_73_voice() {
    let rig = rig("out-of-scope");
    let device = rig.enroll();

    // secops' role permits resource_summary; the device's grant does not.
    let query_id = rig.cp.ask(SECOPS, &device, "resource_summary");
    rig.reconcile();

    let result = rig.cp.query_result(SECOPS, &query_id);
    assert_eq!(result["status"], "refused", "{result}");
    let answer = &result["answer"];
    assert_eq!(answer["authorization_decision"], "deny");
    assert_eq!(answer["result_category"], "refused");
    assert_eq!(answer["refusal_reason"], "out_of_scope");
    assert!(answer.get("payload").is_none(), "a refusal carries no data");

    // SPEC section 73: what was asked, what is permitted, which policy, and
    // the next step — never a bare error code.
    let message = answer["refusal_message"].as_str().unwrap();
    assert!(
        message.starts_with("Refused · resource_summary"),
        "{message}"
    );
    assert!(message.contains("inventory and authority"), "{message}");
    assert!(message.contains("Acme Engineering"), "{message}");
    assert!(message.contains("remote_query_scopes"), "{message}");
    assert!(message.contains("Next step ·"), "{message}");
    assert!(
        message.contains("neither can an administrator"),
        "{message}"
    );
}

/// The mock's RBAC gate and the device's grant are independent: a role
/// that may not ask never reaches the device at all, so the courier is
/// never invoked and there is nothing for the device to refuse.
#[test]
fn a_query_the_role_may_not_ask_never_reaches_the_device() {
    let rig = rig("rbac");
    let device = rig.enroll();
    let before = rig.agentd.state.calls.load(Ordering::SeqCst);

    let refused = rig.cp.call(
        "admin.ai_query",
        json!({"admin": HELPDESK, "device_id": device, "scope": "security_events"}),
    );
    assert_eq!(refused["error"]["code"], "denied", "{refused}");

    rig.reconcile();
    assert_eq!(
        rig.agentd.state.calls.load(Ordering::SeqCst),
        before,
        "a query refused by the org's own RBAC never reaches the data owner"
    );
}

/// SPEC section 59.4, over the real wire: the grant is narrowed **locally**
/// while the identical question is in flight, and the answer changes. The
/// request never carried the grant, so there was nothing in it to forge —
/// which is the design, not the accident.
#[test]
fn a_locally_revoked_grant_is_refused_although_the_request_is_unchanged() {
    let rig = rig("revoke");
    let device = rig.enroll();

    // First, with `authority` granted: allowed.
    let first = rig.cp.ask(CIO, &device, "authority");
    rig.reconcile();
    assert_eq!(rig.cp.query_result(CIO, &first)["status"], "answered");

    // Now the grant is narrowed on this device. Nothing about the question
    // changes, and the control plane is not told.
    let path = rig.daemon.enrollment_path();
    let mut enrollment: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    enrollment["remote_query_scopes"] = json!(["inventory"]);
    fs::write(&path, enrollment.to_string()).unwrap();

    let second = rig.cp.ask(CIO, &device, "authority");
    rig.reconcile();
    let result = rig.cp.query_result(CIO, &second);
    assert_eq!(result["status"], "refused", "{result}");
    assert_eq!(result["answer"]["refusal_reason"], "out_of_scope");
    assert!(
        result["answer"]["refusal_message"]
            .as_str()
            .unwrap()
            .contains("This device answers inventory queries"),
        "{result}"
    );

    // And with the grant file removed entirely — the strongest form —
    // nothing is answerable at all (gate B).
    fs::remove_file(&path).unwrap();
    let grant = read_org_granted_scopes(&path);
    for scope in QueryScope::ALL {
        assert_eq!(
            authorize(scope.as_str(), &grant).decision,
            AuthorizationDecision::Deny
        );
    }
}

// ---------------------------------------------------------------------------
// The courier never answers on the data owner's behalf
// ---------------------------------------------------------------------------

/// If `punar-agentd` cannot be reached, punard posts **nothing**. No
/// synthesized refusal, no "assume denied", no partial answer. The query
/// stays pending and is retried on the next pass — which is exactly what
/// happens here when the daemon comes back.
#[test]
fn punard_never_answers_on_the_data_owners_behalf() {
    let mut rig = rig("courier");
    let device = rig.enroll();
    let query_id = rig.cp.ask(CIO, &device, "inventory");

    rig.agentd.stop();
    rig.reconcile();
    let stuck = rig.cp.query_result(CIO, &query_id);
    assert_eq!(
        stuck["status"], "pending",
        "with the data owner down, nothing may be answered: {stuck}"
    );
    assert!(stuck["answer"].is_null());

    // The data owner returns; the next pass answers, unprompted.
    rig.agentd = Agentd::start(&rig.dir, rig.daemon.enrollment_path());
    rig.reconcile();
    assert_eq!(rig.cp.query_result(CIO, &query_id)["status"], "answered");
}

// ---------------------------------------------------------------------------
// Unmanaged-first (milestone-10.md section 11, gates A and B)
// ---------------------------------------------------------------------------

/// **Gate A.** On a personal device the pull never runs, because the sync
/// hook that carries it never runs. Not a hidden UI, not a suppressed
/// button: no control-plane call of any kind happens, so there is nothing
/// to fetch and no code path that fetches it.
#[test]
fn a_personal_device_fetches_nothing_and_connects_to_nothing() {
    let rig = rig("personal");

    // Enrol, queue a question, then unenrol — so the queue is non-empty and
    // the device is personal, which is the only interesting shape.
    let device = rig.enroll();
    let query_id = rig.cp.ask(CIO, &device, "inventory");
    // `enroll.stop` takes no params (contract section 5.11).
    rig.daemon.result("enroll.stop", None);
    assert!(!rig.daemon.enrollment_path().exists());

    let calls_before = rig.agentd.state.calls.load(Ordering::SeqCst);
    let received_before = rig.cp.received_lines();

    // Three passes. On a personal device each one is silent.
    for _ in 0..3 {
        rig.reconcile();
    }

    assert_eq!(
        rig.cp.query_result(CIO, &query_id)["status"],
        "pending",
        "an unenrolled device answers nothing"
    );
    assert_eq!(
        rig.cp.received_lines(),
        received_before,
        "an unenrolled device connects to nothing: the mock received no new line"
    );
    assert_eq!(
        rig.agentd.state.calls.load(Ordering::SeqCst),
        calls_before,
        "an unenrolled device does not even ask its own data owner"
    );

    // `enroll.status` carries no grant at all — the absence of the concept,
    // not an empty grant that something could widen.
    let status = rig.daemon.result("enroll.status", None);
    assert_eq!(status["enrolled"], false);
    assert!(status.get("remote_query_scopes").is_none(), "{status}");
    assert!(status.get("last_query").is_none(), "{status}");
}

/// **Gate B**, forced directly and independently of gate A: even if a
/// courier were coaxed into handing a well-formed query to the data owner
/// on a personal device, the answer is a refusal, because `org_granted` is
/// read from a file that is not there.
#[test]
fn gate_b_holds_even_when_gate_a_is_bypassed() {
    let rig = rig("gate-b");
    let path = rig.daemon.enrollment_path();
    assert!(!path.exists(), "this device is personal");

    let response = {
        let line = json!({
            "v": 1, "id": "gate-b", "method": "query.answer",
            "params": {
                "query_id": "qry_forced",
                "requesting_admin": "attacker@evil.example",
                "organization": "evil.example",
                "requested_scope": "inventory",
                "received_at": "2026-08-25T14:02:09Z"
            }
        })
        .to_string()
            + "\n";
        let mut stream = UnixStream::connect(&rig.agentd.socket).unwrap();
        stream.write_all(line.as_bytes()).unwrap();
        let mut reader = BufReader::new(stream);
        let mut buf = String::new();
        reader.read_line(&mut buf).unwrap();
        serde_json::from_str::<Value>(buf.trim_end()).unwrap()
    };
    let answer = &response["result"];
    assert_eq!(answer["authorization_decision"], "deny");
    assert_eq!(answer["refusal_reason"], "out_of_scope");
    assert!(answer.get("payload").is_none());
    assert!(
        answer["refusal_message"]
            .as_str()
            .unwrap()
            .contains("no organization is enrolled"),
        "{answer}"
    );
}

// ---------------------------------------------------------------------------
// The single inter-daemon edge (milestone-10.md section 3.3)
// ---------------------------------------------------------------------------

#[test]
fn enrollment_transitions_ask_the_data_owner_for_a_fresh_pass() {
    let rig = rig("triggers");
    rig.enroll();
    // `enroll.stop` takes no params (contract section 5.11).
    rig.daemon.result("enroll.stop", None);
    let scans = rig.agentd.state.scans.lock().unwrap().clone();
    assert_eq!(
        scans,
        vec!["enroll".to_string(), "enroll".to_string()],
        "one opportunistic pass per transition, carrying the trigger"
    );
}

/// The trigger is fire-and-forget: with the data owner down, enrolling
/// still succeeds. Enrollment must never fail because a bookkeeping daemon
/// was busy.
#[test]
fn a_down_data_owner_does_not_fail_an_enrollment() {
    let mut rig = rig("trigger-down");
    rig.agentd.stop();
    let result = rig
        .daemon
        .result("enroll.start", Some(json!({ "org_domain": "acme.com" })));
    assert_eq!(result["enrolled"], true, "{result}");
}
