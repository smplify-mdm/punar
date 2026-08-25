//! Integration tests: a real `punar-agentd` on a tempdir socket, driven
//! over the wire exactly as `punar-env` and `punarctl` will drive it
//! (docs/api/ipc.md section 10).
//!
//! Everything the daemon touches is injected — the socket, the state
//! directory, the audit trail, the adapter and signature data, `/etc/passwd`
//! and, crucially, `/proc`. The fixture `/proc` is what makes attribution
//! testable: a process "inside a managed scope" is a `cgroup` file naming
//! `punar-agent-<id>.scope`, which is exactly what the kernel would show for
//! a `systemd-run --scope` launch.
//!
//! Peer identity uses the test-only `PeerSource::Fixed` hook (a `punar`
//! user, or root), so the tests exercise the real authorization decisions
//! without needing multiple uids.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use punar_agentd::authz::{Peer, PeerSource};
use punar_agentd::server::{AgentdConfig, Daemon, DaemonHandle};
use punar_agentd::testsupport::{
    FIXTURE_BOOT_ID, FIXTURE_BTIME, fake_process, fixture_adapters, fixture_nss,
    fixture_proc_system, fixture_suspected, kill_process, managed_cgroup,
};
use serde_json::{Value, json};

const PUNAR_UID: u32 = 1000;
const SESSION: &str = "agt_4f21c09ab3e1";

struct TestDaemon {
    dir: PathBuf,
    proc_root: PathBuf,
    stale_after: Duration,
    socket_seq: u32,
    handle: Option<DaemonHandle>,
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn test_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "punar-agentd-it-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

impl TestDaemon {
    /// Start a daemon whose `/proc` the caller has already populated.
    fn start(tag: &str, peer: Peer, stale_after: Duration, prepare: impl FnOnce(&Path)) -> Self {
        let dir = test_dir(tag);
        let proc_root = dir.join("proc");
        fs::create_dir_all(&proc_root).unwrap();
        // The two system-wide files M10's detection identity reads, so
        // these tests drive the shipping construction rather than its
        // degraded fallback.
        fixture_proc_system(&proc_root, FIXTURE_BOOT_ID, FIXTURE_BTIME);
        prepare(&proc_root);
        fixture_nss(&dir);
        fixture_adapters(&dir);
        fixture_suspected(&dir);
        fs::create_dir_all(dir.join("state")).unwrap();

        let mut daemon = TestDaemon {
            dir,
            proc_root,
            stale_after,
            socket_seq: 0,
            handle: None,
        };
        daemon.launch(peer);
        daemon
    }

    /// Stop the running daemon and start a fresh one on the **same state**
    /// — the restart path (and, with a different peer, the "another user
    /// connects" path).
    fn restart_as(&mut self, peer: Peer) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
        self.launch(peer);
    }

    fn launch(&mut self, peer: Peer) {
        self.socket_seq += 1;
        let cfg = AgentdConfig {
            adapters_dir: self.dir.join("adapters"),
            suspected_path: self.dir.join("suspected.json"),
            proc_root: self.proc_root.clone(),
            group_file: self.dir.join("group"),
            passwd_file: self.dir.join("passwd"),
            peer_source: PeerSource::Fixed(peer),
            io_timeout: Duration::from_secs(5),
            scan_stale_after: self.stale_after,
            ..AgentdConfig::new(
                self.dir.join(format!("agentd-{}.sock", self.socket_seq)),
                self.dir.join("state"),
                self.dir.join("audit.jsonl"),
            )
        };
        self.handle = Some(Daemon::new(cfg).unwrap().spawn().unwrap());
    }

    fn socket(&self) -> &Path {
        self.handle.as_ref().unwrap().socket_path()
    }

    /// One request/response round trip over the wire.
    fn call(&self, method: &str, params: Option<Value>) -> Value {
        let mut request = json!({"v": 1, "id": "t1", "method": method});
        if let Some(params) = params {
            request["params"] = params;
        }
        self.raw(&format!("{request}\n"))
    }

    fn raw(&self, line: &str) -> Value {
        let mut stream = UnixStream::connect(self.socket()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(line.as_bytes()).unwrap();
        stream.flush().unwrap();
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

    fn error_code(&self, method: &str, params: Option<Value>) -> String {
        let response = self.call(method, params);
        response["error"]["code"]
            .as_str()
            .unwrap_or_else(|| panic!("expected an error from {method}, got {response}"))
            .to_string()
    }

    fn registry_lines(&self) -> Vec<Value> {
        match fs::read_to_string(self.dir.join("state/agents/registry.jsonl")) {
            Ok(text) => text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn agents_json(&self) -> Value {
        let text = fs::read_to_string(self.dir.join("state/agents.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn audit_lines(&self) -> Vec<Value> {
        match fs::read_to_string(self.dir.join("audit.jsonl")) {
            Ok(text) => text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

fn register_params(session: &str, pid: u32) -> Value {
    json!({
        "session_id": session,
        "agent": "claude-code",
        "version": "mock",
        "process_id": pid,
        "project": "atlas",
        "environment": "host",
        "authority": {
            "policy_citation": "personal-defaults",
            "rows": [
                {"zone": "filesystem.project", "decision": "read_write",
                 "enforcement": "declared · M9"},
                {"zone": "network.internet", "decision": "allow",
                 "enforcement": "declared · M12"}
            ]
        }
    })
}

/// The managed launch, end to end: register a process that really is in its
/// scope, see it classified `managed`, listed, inspectable, summarized for
/// the panel, ended, and recorded as two schema-exact lines.
#[test]
fn a_managed_session_lives_and_ends() {
    let daemon = TestDaemon::start(
        "lifecycle",
        Peer::user(PUNAR_UID),
        Duration::from_secs(30),
        |proc| {
            fake_process(
                proc,
                2143,
                "punar-mock-agen",
                "/usr/lib/punar/punar-mock-agent",
                &["/usr/lib/punar/punar-mock-agent"],
                PUNAR_UID,
                &managed_cgroup(SESSION),
            );
        },
    );

    let result = daemon.result("agents.register", Some(register_params(SESSION, 2143)));
    assert_eq!(result["classification"], "managed");
    let session = &result["session"];
    assert_eq!(session["session_id"], SESSION);
    assert_eq!(session["status"], "active");
    // Daemon-stamped, never taken from params.
    assert_eq!(session["user"], "punar");
    assert!(session["started_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(
        session["scope_unit"],
        format!("punar-agent-{SESSION}.scope")
    );

    // agents.list shows exactly the ten record fields per session, plus
    // the M8 counts-only ledger fingerprint (docs/api/ipc.md section
    // 12.4) — and nothing else.
    let list = daemon.result("agents.list", None);
    assert_eq!(list["sessions"].as_array().unwrap().len(), 1);
    let mut keys: Vec<&str> = list["sessions"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "agent",
            "classification",
            "environment",
            "ledger",
            "process_id",
            "project",
            "session_id",
            "started_at",
            "status",
            "user",
            "version"
        ]
    );
    // The fingerprint is numbers plus one timestamp: no class names, no
    // `evt_` ids, no zones (they need `agents.access` and its ownership
    // check).
    let fingerprint = list["sessions"][0]["ledger"].as_object().unwrap();
    let mut fingerprint_keys: Vec<&str> = fingerprint.keys().map(String::as_str).collect();
    fingerprint_keys.sort_unstable();
    assert_eq!(
        fingerprint_keys,
        vec![
            "process_classes",
            "resources",
            "security_events",
            "updated_at"
        ]
    );
    for numeric in ["process_classes", "resources", "security_events"] {
        assert!(fingerprint[numeric].is_u64(), "{numeric}");
    }

    // agents.get carries the launcher's authority block for the panel and
    // `punarctl agents inspect`, labels intact.
    let got = daemon.result("agents.get", Some(json!({"session_id": SESSION})));
    let authority = &got["session"]["authority"];
    assert_eq!(authority["policy_citation"], "personal-defaults");
    assert_eq!(authority["rows"][0]["enforcement"], "declared · M9");
    assert_eq!(authority["rows"][1]["enforcement"], "declared · M12");

    // The panel file exists, cites the policy, and counts the session.
    let summary = daemon.agents_json();
    assert_eq!(summary["v"], 1);
    assert_eq!(summary["policy_citation"], "personal-defaults");
    assert_eq!(summary["counts"]["managed"], 1);
    assert_eq!(summary["sessions"][0]["session_id"], SESSION);

    // End it.
    let ended = daemon.result("agents.end", Some(json!({"session_id": SESSION})));
    assert_eq!(ended["session"]["status"], "ended");
    // Ending twice is a stated conflict, not a silent success.
    assert_eq!(
        daemon.error_code("agents.end", Some(json!({"session_id": SESSION}))),
        "conflict"
    );

    // Two schema-exact lines: active, then ended.
    let lines = daemon.registry_lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0]["status"], "active");
    assert_eq!(lines[1]["status"], "ended");
    assert_eq!(lines[1]["session_id"], SESSION);
    for line in &lines {
        assert_eq!(line.as_object().unwrap().len(), 10);
        assert_eq!(line["classification"], "managed");
    }

    // An ended session is still listable (this boot's history), and no
    // longer counted as running.
    let list = daemon.result("agents.list", None);
    assert_eq!(list["sessions"][0]["status"], "ended");
    assert_eq!(daemon.agents_json()["counts"]["managed"], 0);

    // Audit: real agt_ ids on both lifecycle events (the sentinel's
    // purpose, fulfilled).
    let audit = daemon.audit_lines();
    let register = audit
        .iter()
        .find(|e| e["action"] == "agents.register")
        .expect("register audited");
    assert_eq!(register["agent_session_id"], SESSION);
    assert_eq!(register["decision"], "allow");
    assert_eq!(register["result"], "success");
    assert_eq!(register["source"], "human");
    assert_eq!(register["user_id"], "punar");
    assert_eq!(register["resource"], "claude-code");
    assert_eq!(register["project_id"], "atlas");
    let end = audit
        .iter()
        .find(|e| e["action"] == "agents.end")
        .expect("end audited");
    assert_eq!(end["agent_session_id"], SESSION);
    // Reads are not audited.
    assert!(audit.iter().all(|e| e["action"] != "agents.list"));
}

/// Attribution is checked, never claimed (spec section 22).
#[test]
fn registration_verifies_the_process_before_believing_the_launcher() {
    let daemon = TestDaemon::start(
        "verify",
        Peer::user(PUNAR_UID),
        Duration::from_secs(30),
        |proc| {
            // In its scope: the honest managed case.
            fake_process(
                proc,
                2143,
                "punar-mock-agen",
                "/usr/lib/punar/punar-mock-agent",
                &["/usr/lib/punar/punar-mock-agent"],
                PUNAR_UID,
                &managed_cgroup(SESSION),
            );
            // Root's process — a non-root peer must not be able to claim it.
            fake_process(
                proc,
                42,
                "sshd",
                "/usr/sbin/sshd",
                &["/usr/sbin/sshd"],
                0,
                "/system.slice/sshd.service",
            );
            // A known agent running outside any managed scope.
            fake_process(
                proc,
                3001,
                "claude",
                "/usr/bin/claude",
                &["/usr/bin/claude"],
                PUNAR_UID,
                "/user.slice/session-3.scope",
            );
            // An ordinary process with no scope and no signature.
            fake_process(
                proc,
                3100,
                "bash",
                "/bin/bash",
                &["/bin/bash"],
                PUNAR_UID,
                "/user.slice/session-3.scope",
            );
        },
    );

    // Claiming root's process is denied — and audited as a denial.
    assert_eq!(
        daemon.error_code(
            "agents.register",
            Some(register_params("agt_c1a1med00001", 42))
        ),
        "denied"
    );
    let denial = daemon
        .audit_lines()
        .into_iter()
        .find(|e| e["decision"] == "deny")
        .expect("denials are always audited");
    assert_eq!(denial["action"], "agents.register");
    assert_eq!(denial["result"], "denied");

    // A process that is neither scoped nor recognizable cannot be
    // registered at all: the launch path is broken, and the daemon says so
    // instead of inventing a classification.
    assert_eq!(
        daemon.error_code(
            "agents.register",
            Some(register_params("agt_b0gus0000001", 3100))
        ),
        "invalid_params"
    );

    // A known agent outside its scope registers, but is honestly
    // downgraded to `observed` — the launcher can surface that.
    let result = daemon.result(
        "agents.register",
        Some(register_params("agt_0b5erved0001", 3001)),
    );
    assert_eq!(result["classification"], "observed");
    assert!(result["session"].get("scope_unit").is_none());

    // Ids are validated, and never reused.
    assert_eq!(
        daemon.error_code("agents.register", Some(register_params("session-1", 2143))),
        "invalid_params"
    );
    daemon.result("agents.register", Some(register_params(SESSION, 2143)));
    assert_eq!(
        daemon.error_code("agents.register", Some(register_params(SESSION, 2143))),
        "invalid_params"
    );
    // A process that does not exist cannot be registered.
    assert_eq!(
        daemon.error_code(
            "agents.register",
            Some(register_params("agt_gh05t0000001", 61234))
        ),
        "invalid_params"
    );
}

/// The shadow-AI half: a suspected process is found, reported as
/// *suspected*, and cleared when it goes away — with only the transitions
/// audited.
#[test]
fn detection_finds_reports_and_clears_a_suspect() {
    let daemon = TestDaemon::start(
        "detect",
        Peer::user(PUNAR_UID),
        Duration::from_secs(30),
        |proc| {
            fake_process(
                proc,
                2410,
                "foo-agent",
                "/usr/bin/dash",
                &["/bin/sh", "/home/punar/Downloads/foo-agent"],
                PUNAR_UID,
                "/user.slice/user-1000.slice/session-3.scope",
            );
        },
    );

    let list = daemon.result("agents.list", None);
    let detections = list["detections"].as_array().unwrap();
    assert_eq!(detections.len(), 1, "{list}");
    let detection = &detections[0];
    assert_eq!(detection["classification"], "unknown");
    assert_eq!(detection["agent"], "foo-agent");
    assert_eq!(detection["suspected"], true);
    assert_eq!(detection["executable"], "/home/punar/Downloads/foo-agent");
    assert_eq!(detection["signature_id"], "downloads-foo-agent");
    // Sentinels, not guesses.
    assert_eq!(detection["version"], "unknown");
    assert_eq!(detection["project"], "unknown");
    assert_eq!(detection["environment"], "host");
    let session_id = detection["session_id"].as_str().unwrap().to_string();

    // Detections are inspectable by the same id the panel shows...
    let got = daemon.result("agents.get", Some(json!({"session_id": session_id})));
    assert_eq!(got["session"]["suspected"], true);
    // ...and never written to the registry log.
    assert!(daemon.registry_lines().is_empty());

    // The panel file carries the suspicion label and no process ids.
    let summary = daemon.agents_json();
    assert_eq!(summary["counts"]["unknown"], 1);
    assert_eq!(summary["detections"][0]["suspected"], true);
    let raw = fs::read_to_string(daemon.dir.join("state/agents.json")).unwrap();
    for forbidden in ["process_id", "2410", "cmdline"] {
        assert!(!raw.contains(forbidden), "{forbidden} leaked: {raw}");
    }

    // One "detected" transition, and repeated scans add nothing.
    let detected = daemon
        .audit_lines()
        .into_iter()
        .filter(|e| e["action"] == "agents.scan" && e["result"] == "detected")
        .count();
    assert_eq!(detected, 1);
    daemon.result("agents.scan", None);
    daemon.result("agents.scan", None);
    assert_eq!(
        daemon
            .audit_lines()
            .into_iter()
            .filter(|e| e["action"] == "agents.scan")
            .count(),
        1,
        "a pass that changes nothing is not an event"
    );

    // The process goes away: the row clears, and that is a transition.
    kill_process(&daemon.proc_root, 2410);
    let after = daemon.result("agents.scan", None);
    assert!(after["detections"].as_array().unwrap().is_empty());
    let cleared = daemon
        .audit_lines()
        .into_iter()
        .find(|e| e["result"] == "cleared")
        .expect("the disappearance is audited");
    assert_eq!(cleared["action"], "agents.scan");
    assert_eq!(cleared["agent_session_id"], session_id);
    assert_eq!(cleared["source"], "service");
    assert_eq!(cleared["user_id"], "punar-agentd");
    assert_eq!(daemon.agents_json()["counts"]["unknown"], 0);
}

/// A session whose process dies without `agents.end` is closed by the next
/// pass — no exit status is invented, and the honesty is on the record.
#[test]
fn a_crashed_session_is_reaped_not_left_pretending() {
    let daemon = TestDaemon::start(
        "reap",
        Peer::user(PUNAR_UID),
        Duration::from_secs(30),
        |proc| {
            fake_process(
                proc,
                2143,
                "punar-mock-agen",
                "/usr/lib/punar/punar-mock-agent",
                &["/usr/lib/punar/punar-mock-agent"],
                PUNAR_UID,
                &managed_cgroup(SESSION),
            );
        },
    );
    daemon.result("agents.register", Some(register_params(SESSION, 2143)));

    kill_process(&daemon.proc_root, 2143);
    let list = daemon.result("agents.scan", None);
    assert_eq!(list["sessions"][0]["status"], "ended");

    let lines = daemon.registry_lines();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1]["status"], "ended");
    let reap = daemon
        .audit_lines()
        .into_iter()
        .find(|e| e["action"] == "agents.reap")
        .expect("the reap is audited");
    assert_eq!(reap["agent_session_id"], SESSION);
    assert_eq!(reap["result"], "reaped");
    assert_eq!(reap["source"], "service");
    assert_eq!(reap["decision"], "allow");
}

/// `agents.list` refreshes a stale view by itself — the whole reason M7
/// needs no timer (spec section 6.3).
#[test]
fn list_refreshes_a_stale_view_without_any_timer() {
    let daemon = TestDaemon::start(
        "stale",
        Peer::user(PUNAR_UID),
        Duration::from_millis(0),
        |_proc| {},
    );
    assert!(
        daemon.result("agents.list", None)["detections"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // Something suspicious appears *after* the daemon started; nobody
    // tells the daemon.
    fake_process(
        &daemon.proc_root,
        2410,
        "foo-agent",
        "/usr/bin/dash",
        &["/bin/sh", "/home/punar/Downloads/foo-agent"],
        PUNAR_UID,
        "/user.slice/session-3.scope",
    );
    let list = daemon.result("agents.list", None);
    assert_eq!(list["detections"].as_array().unwrap().len(), 1);
    assert_eq!(list["detections"][0]["classification"], "unknown");
}

/// Only the session's owner — or root — may end it (spec section 22: the
/// registry knows *whose* agent this is).
#[test]
fn ending_someone_elses_session_is_denied() {
    let mut daemon = TestDaemon::start("owner", Peer::root(), Duration::from_secs(30), |proc| {
        fake_process(
            proc,
            2143,
            "punar-mock-agen",
            "/usr/lib/punar/punar-mock-agent",
            &["/usr/lib/punar/punar-mock-agent"],
            PUNAR_UID,
            &managed_cgroup(SESSION),
        );
    });
    // Root registers a session running as `punar`: the session belongs to
    // the process owner, not to whoever called.
    daemon.result("agents.register", Some(register_params(SESSION, 2143)));

    // A different, unprivileged user connects (after a restart, so the
    // owner is re-derived from the persisted record's user name).
    daemon.restart_as(Peer::user(PUNAR_UID + 7));
    assert_eq!(
        daemon.error_code("agents.end", Some(json!({"session_id": SESSION}))),
        "denied"
    );
    let denial = daemon
        .audit_lines()
        .into_iter()
        .find(|e| e["action"] == "agents.end" && e["decision"] == "deny")
        .expect("the refusal is on the record");
    assert_eq!(denial["result"], "denied");
    assert_eq!(denial["agent_session_id"], SESSION);
    // Still active: a denied end changes nothing.
    assert_eq!(
        daemon.result("agents.list", None)["sessions"][0]["status"],
        "active"
    );

    // The owner may end it.
    daemon.restart_as(Peer::user(PUNAR_UID));
    daemon.result("agents.end", Some(json!({"session_id": SESSION})));
    assert_eq!(
        daemon.result("agents.list", None)["sessions"][0]["status"],
        "ended"
    );
}

/// The method table is closed, and the reserved names say so honestly
/// (docs/api/ipc.md section 10.2).
#[test]
fn the_method_table_is_closed_and_the_reserved_names_are_honest() {
    let daemon = TestDaemon::start("closed", Peer::root(), Duration::from_secs(30), |_proc| {});

    for probe in ["system.exec", "shell.run", "agents.run", "status"] {
        assert_eq!(daemon.error_code(probe, None), "unknown_method", "{probe}");
    }
    // There is no export or remote-query path at all, and the refusal
    // says so rather than promising one (spec sections 1.22, 24).
    for probe in ["ledger.export", "ledger.query", "ledger.upload"] {
        let refusal = daemon.call(probe, Some(json!({"session_id": SESSION})));
        assert_eq!(refusal["error"]["code"], "unknown_method", "{probe}");
        assert!(
            refusal["error"]["message"]
                .as_str()
                .unwrap()
                .contains("stays on this device"),
            "{probe}: {refusal}"
        );
    }
    // M7 reserved `admin.*` "for Milestone 10" and this test asserted that
    // wording. M10 has now shipped, and the answer is no longer a promise
    // about a milestone — it is the INVARIANT the milestone established:
    // admin.* names belong to the control plane, nothing on this device
    // listens for an administrator, and the device's own record of what
    // was asked is one command away (milestone-10.md laws 1 and 3).
    let admin = daemon.call("admin.query", None);
    assert_eq!(admin["error"]["code"], "unknown_method");
    let message = admin["error"]["message"].as_str().unwrap();
    assert!(message.contains("CONTROL PLANE"), "{admin}");
    assert!(message.contains("Nothing listens here"), "{admin}");
    assert!(message.contains("punarctl privacy queries"), "{admin}");
    assert!(
        !message.contains("reserved"),
        "the reservation was fulfilled; the refusal must not still promise it: {admin}"
    );

    // Unknown ids are not found; a bad envelope is malformed; a wrong
    // version is unsupported — the shared pipeline, unchanged.
    assert_eq!(
        daemon.error_code("agents.get", Some(json!({"session_id": "agt_absent00001"}))),
        "not_found"
    );
    assert_eq!(
        daemon.raw("not json\n")["error"]["code"],
        "malformed_request"
    );
    assert_eq!(
        daemon.raw("{\"v\":2,\"id\":\"1\",\"method\":\"agents.list\"}\n")["error"]["code"],
        "unsupported_version"
    );
    // No agents.* method accepts anything executable: params are typed and
    // strict.
    assert_eq!(
        daemon.error_code("agents.list", Some(json!({"command": "/bin/sh"}))),
        "invalid_params"
    );
}

/// A restarted daemon rebuilds the registry from disk — and never claims a
/// session is running because a file says so.
#[test]
fn a_restart_replays_the_registry_and_closes_dead_sessions() {
    let mut daemon = TestDaemon::start(
        "replay",
        Peer::user(PUNAR_UID),
        Duration::from_secs(30),
        |proc| {
            fake_process(
                proc,
                2143,
                "punar-mock-agen",
                "/usr/lib/punar/punar-mock-agent",
                &["/usr/lib/punar/punar-mock-agent"],
                PUNAR_UID,
                &managed_cgroup(SESSION),
            );
        },
    );
    daemon.result("agents.register", Some(register_params(SESSION, 2143)));

    // Process still alive across the restart: carried, still active.
    daemon.restart_as(Peer::user(PUNAR_UID));
    let list = daemon.result("agents.list", None);
    assert_eq!(list["sessions"][0]["status"], "active");
    assert_eq!(list["sessions"][0]["session_id"], SESSION);
    assert_eq!(daemon.registry_lines().len(), 1, "no phantom transitions");

    // Process gone while the daemon was down: the replay closes it with a
    // real `ended` record rather than reporting a running agent.
    kill_process(&daemon.proc_root, 2143);
    daemon.restart_as(Peer::user(PUNAR_UID));
    let list = daemon.result("agents.list", None);
    assert_eq!(list["sessions"][0]["status"], "ended");
    let lines = daemon.registry_lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[1]["status"], "ended");
    assert_eq!(lines[1]["session_id"], SESSION);
}

/// **Attack: choose what your organization believes.**
///
/// The `authority` block is supplied by whoever calls `agents.register`.
/// Through M7-M9 that was display data, rendered to the person whose
/// machine it described. Milestone 10's `authority` query scope exports it
/// **off the device**, to an administrator told they are reading "the
/// org's own policy, read back" (milestone-10.md section 8.1). An
/// unprivileged local process therefore had a channel through which it
/// chose its organization's view of its own machine: a forged
/// `enforcement` reading `enforced` over something merely declared, a file
/// path or a prompt smuggled out through a field documented as carrying
/// zone classes, and a terminal escape delivered to whatever renders the
/// answer.
///
/// The block is now bounded, single-line and printable before it is
/// stored, and the export labels the rows as asserted rather than
/// measured — because nothing on this device measures them, and spec 1.22
/// forbids letting an administrator believe otherwise.
#[test]
fn the_launcher_authority_block_is_bounded_printable_and_labelled_asserted() {
    let daemon = TestDaemon::start(
        "authority-forgery",
        Peer::user(PUNAR_UID),
        Duration::from_secs(30),
        |proc| {
            fake_process(
                proc,
                2143,
                "punar-mock-agen",
                "/usr/lib/punar/punar-mock-agent",
                &["/usr/lib/punar/punar-mock-agent"],
                PUNAR_UID,
                &managed_cgroup(SESSION),
            );
        },
    );

    let probes: Vec<(&str, Value)> = vec![
        (
            "a terminal escape in a decision word",
            json!({"zone": "network.internet",
                   "decision": "\u{1b}[32mallow\u{1b}[0m",
                   "enforcement": "declared · M12"}),
        ),
        (
            "a newline that forges a second row",
            json!({"zone": "network.internet\nfilesystem.home",
                   "decision": "allow",
                   "enforcement": "declared · M12"}),
        ),
        (
            "a file path where a zone class belongs",
            json!({"zone": "x".repeat(400),
                   "decision": "allow",
                   "enforcement": "declared · M12"}),
        ),
        (
            "a blank field",
            json!({"zone": "", "decision": "allow", "enforcement": "declared · M12"}),
        ),
    ];
    for (label, row) in probes {
        let mut params = register_params(SESSION, 2143);
        params["authority"]["rows"] = json!([row]);
        let response = daemon.call("agents.register", Some(params));
        assert_eq!(
            response["error"]["code"], "invalid_params",
            "{label} must not be stored: {response}"
        );
    }

    // A well-formed block still registers, and `agents.get` still renders
    // it — the guard refuses garbage, not authority blocks.
    let registered = daemon.result("agents.register", Some(register_params(SESSION, 2143)));
    assert_eq!(registered["classification"], "managed", "{registered}");
    let got = daemon.result("agents.get", Some(json!({"session_id": SESSION})));
    assert_eq!(
        got["session"]["authority"]["rows"][0]["enforcement"],
        "declared · M9"
    );
}
