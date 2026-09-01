//! Milestone 10 integration tests: periodic detection and the alert
//! engine, driven over the wire exactly as the scan timer, `punarctl` and
//! the shell will drive them (`docs/development/milestone-10.md`).
//!
//! Everything the daemon touches is injected — the socket, the state
//! directory, the audit trail, the signature data and, crucially,
//! `/proc`, including the two system-wide files M10 reads: the boot id
//! and `btime`. That is what makes detection **identity** testable at
//! all: a fixture process has a real `starttime` tick stamp, so pid reuse
//! can be staged rather than argued about.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use punar_agentd::authz::{Peer, PeerSource};
use punar_agentd::server::{AgentdConfig, Daemon, DaemonHandle};
use punar_agentd::testsupport::{
    FIXTURE_BOOT_ID, FIXTURE_BTIME, fake_process, fixture_adapters, fixture_nss,
    fixture_proc_system, fixture_suspected, kill_process,
};
use serde_json::{Value, json};

const PUNAR_UID: u32 = 1000;
const FOO_PATH: &str = "/home/punar/Downloads/foo-agent";

struct TestDaemon {
    dir: PathBuf,
    proc_root: PathBuf,
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
        "punar-agentd-m10-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

impl TestDaemon {
    fn start(tag: &str, peer: Peer, prepare: impl FnOnce(&Path)) -> Self {
        let dir = test_dir(tag);
        let proc_root = dir.join("proc");
        fs::create_dir_all(&proc_root).unwrap();
        fixture_proc_system(&proc_root, FIXTURE_BOOT_ID, FIXTURE_BTIME);
        prepare(&proc_root);
        fixture_nss(&dir);
        fixture_adapters(&dir);
        fixture_suspected(&dir);
        fs::create_dir_all(dir.join("state")).unwrap();

        let mut daemon = TestDaemon {
            dir,
            proc_root,
            socket_seq: 0,
            handle: None,
        };
        daemon.launch(peer);
        daemon
    }

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
            // Long, so nothing in these tests runs a pass the test did
            // not ask for: every pass here is deliberate.
            scan_stale_after: Duration::from_secs(3_600),
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

    fn call(&self, method: &str, params: Option<Value>) -> Value {
        let mut request = json!({"v": 1, "id": "t1", "method": method});
        if let Some(params) = params {
            request["params"] = params;
        }
        let mut stream = UnixStream::connect(self.socket()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(format!("{request}\n").as_bytes()).unwrap();
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

    fn scan(&self, trigger: &str) -> Value {
        self.result("agents.scan", Some(json!({"trigger": trigger})))
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

    fn alerts_file(&self) -> Value {
        let text = fs::read_to_string(self.dir.join("state/alerts.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn detection_lines(&self) -> Vec<Value> {
        match fs::read_to_string(self.dir.join("state/agents/detections.jsonl")) {
            Ok(text) => text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Every regular file the daemon owns, path → contents. Sockets are
    /// skipped (they have no contents), and so is the fixture `/proc`,
    /// which the *test* writes.
    fn state_snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        let mut snapshot = BTreeMap::new();
        collect(&self.dir.join("state"), &self.dir, &mut snapshot);
        if let Ok(bytes) = fs::read(self.dir.join("audit.jsonl")) {
            snapshot.insert("audit.jsonl".to_string(), bytes);
        }
        snapshot
    }
}

fn collect(dir: &Path, base: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            collect(&path, base, out);
        } else if meta.is_file() {
            let key = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            out.insert(key, fs::read(&path).unwrap_or_default());
        }
    }
}

fn with_foo_agent(proc: &Path) {
    fake_process(
        proc,
        2410,
        "foo-agent",
        "/usr/bin/dash",
        &["/bin/sh", FOO_PATH],
        PUNAR_UID,
        "/user.slice/user-1000.slice/session-3.scope",
    );
}

fn scan_events(daemon: &TestDaemon) -> Vec<(String, String)> {
    daemon
        .audit_lines()
        .into_iter()
        .filter(|event| event["action"] == "agents.scan")
        .map(|event| {
            (
                event["resource"].as_str().unwrap_or_default().to_string(),
                event["result"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Decision 4: the diff is the event
// ---------------------------------------------------------------------------

/// **The headline invariant of Milestone 10** (decision 4, section 3.4):
/// a pass whose detection set is unchanged writes *nothing at all* — no
/// `agents.json` rewrite, no audit line, no ledger write, no
/// `alerts.json`, no byte anywhere.
///
/// This is what makes a 240 s timer compatible with spec 6.4: the steady
/// state of periodic detection is zero bytes written. The test asserts it
/// the only way worth asserting it — by comparing every file the daemon
/// owns, byte for byte, across three passes.
#[test]
fn an_unchanged_pass_writes_absolutely_nothing() {
    let daemon = TestDaemon::start("zero-write", Peer::user(PUNAR_UID), with_foo_agent);

    // Pass 1 finds the fixture and therefore *does* write: a transition
    // is news. (Startup already ran one, so this may be a no-op too —
    // either way the state is settled after it.)
    daemon.scan("timer");
    let settled = daemon.state_snapshot();
    assert!(
        settled.contains_key("state/alerts.json"),
        "the detection raised a card: {:?}",
        settled.keys().collect::<Vec<_>>()
    );
    let audit_before = daemon.audit_lines().len();

    // Passes 2 and 3 change nothing.
    for trigger in ["timer", "manual"] {
        let result = daemon.scan(trigger);
        assert_eq!(
            result["changed"], false,
            "an unchanged pass must report itself as unchanged"
        );
    }

    let after = daemon.state_snapshot();
    assert_eq!(
        after.keys().collect::<Vec<_>>(),
        settled.keys().collect::<Vec<_>>(),
        "an unchanged pass created no file"
    );
    for (path, bytes) in &settled {
        assert_eq!(
            after.get(path),
            Some(bytes),
            "{path} was rewritten by a pass that changed nothing"
        );
    }
    assert_eq!(
        daemon.audit_lines().len(),
        audit_before,
        "an unchanged pass appended no audit line — the trail logs events, not scans"
    );

    // And the socket still tells the truth about liveness, because that
    // is in memory rather than in a file (section 3.4).
    let list = daemon.result("agents.list", None);
    assert_eq!(list["last_scan_trigger"], "manual");
    assert!(list["last_scan_at"].as_str().unwrap() >= list["scanned_at"].as_str().unwrap());
    assert_eq!(
        daemon.agents_scanned_at(),
        list["scanned_at"],
        "agents.json carries the last CHANGE, and the socket carries the last PASS"
    );
}

impl TestDaemon {
    fn agents_scanned_at(&self) -> Value {
        let text = fs::read_to_string(self.dir.join("state/agents.json")).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        value["scanned_at"].clone()
    }
}

/// The trigger travels into the audit trail, so a check can prove a
/// detection came from the timer and not from a command it typed
/// (section 3.4, `m10-check` group 3).
///
/// The daemon is driven as **root** here because that is what actually
/// runs the non-manual triggers — the timer unit has no `User=`, punard is
/// root, and the register/reap trigger is the daemon's own. A non-root
/// peer's claim is a different test, immediately below.
#[test]
fn the_scan_trigger_is_recorded_in_the_audit_trail() {
    let daemon = TestDaemon::start("trigger", Peer::root(), |_| {});

    // Nothing running yet: a pass with no diff writes no event at all.
    daemon.scan("timer");
    assert!(scan_events(&daemon).is_empty());

    // Now the fixture appears, and the *timer* is what noticed.
    with_foo_agent(&daemon.proc_root);
    let result = daemon.scan("timer");
    assert_eq!(result["changed"], true);
    assert_eq!(result["last_scan_trigger"], "timer");

    let events = scan_events(&daemon);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].1, "detected");
    assert_eq!(
        events[0].0, "foo-agent:timer",
        "the trigger rides in `resource`; audit-event.json has no field for one"
    );
    assert!(
        !events
            .iter()
            .any(|(resource, _)| resource.ends_with(":manual")),
        "no manual scan produced a detection in this window: {events:?}"
    );

    // An unlabelled request is `manual`, never an assumed timer.
    kill_process(&daemon.proc_root, 2410);
    daemon.result("agents.scan", None);
    let events = scan_events(&daemon);
    assert_eq!(events.last().unwrap().0, "foo-agent:manual");
    assert_eq!(events.last().unwrap().1, "cleared");
}

/// **Attack: forge the provenance of a detection.**
///
/// `agents.scan` is open to every peer the socket admits — the desktop
/// user, and any AI agent running as them. The whole value of the trigger
/// is that it separates "the timer noticed this" from "somebody typed a
/// command", and `m10-check` group 3 asserts exactly that separation to
/// prove periodic detection works at all. A trigger taken from the caller
/// would let any local process write `foo-agent:timer` into the audit
/// trail — an assertion satisfiable by a typed command, and, worse than a
/// broken check, a permanent lie in the section 53 record about what this
/// device did on its own.
///
/// So a non-root peer's claim is recorded as `manual`, which is what
/// happened. It is not refused: `manual` is the truth, and turning a
/// provenance question into an availability question would break a user
/// who passed the wrong flag while costing an attacker nothing.
#[test]
fn a_local_peer_cannot_claim_a_scan_came_from_the_timer() {
    let daemon = TestDaemon::start("trigger-forgery", Peer::user(PUNAR_UID), with_foo_agent);

    for claimed in ["timer", "enroll", "register"] {
        let result = daemon.scan(claimed);
        assert_eq!(
            result["last_scan_trigger"], "manual",
            "an unprivileged peer claiming {claimed:?} is recorded as manual: {result}"
        );
    }
    let events = scan_events(&daemon);
    assert!(!events.is_empty(), "the fixture was detected");
    for (resource, _) in &events {
        assert!(
            resource.ends_with(":manual"),
            "no unprivileged peer put a machine trigger in the audit trail: {resource}"
        );
    }
    for forged in [":timer", ":enroll", ":register"] {
        assert!(
            !events
                .iter()
                .any(|(resource, _)| resource.ends_with(forged)),
            "{forged} was forged by uid {PUNAR_UID}: {events:?}"
        );
    }
}

/// Identity, over the wire: a detection keeps its id while it lives, and
/// a recycled pid is a different detection rather than a resurrected one.
#[test]
fn detection_identity_is_stable_and_survives_pid_reuse() {
    let daemon = TestDaemon::start("identity", Peer::user(PUNAR_UID), with_foo_agent);
    let first = daemon.scan("timer");
    let detections = first["detections"].as_array().unwrap();
    assert_eq!(detections.len(), 1);
    let id = detections[0]["session_id"].as_str().unwrap().to_string();
    assert!(id.starts_with("agt_"), "{id}");

    // Same process, later pass: same id, so the diff sees no transition.
    let again = daemon.scan("timer");
    assert_eq!(again["detections"][0]["session_id"], id.as_str());
    assert_eq!(again["changed"], false);

    // The process exits and the kernel recycles 2410 to a new run.
    kill_process(&daemon.proc_root, 2410);
    with_foo_agent(&daemon.proc_root);
    let stat = daemon.proc_root.join("2410/stat");
    let text = fs::read_to_string(&stat).unwrap();
    fs::write(&stat, text.replace(" 902410\n", " 1204915\n")).unwrap();

    let recycled = daemon.scan("timer");
    let new_id = recycled["detections"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        new_id, id,
        "pid reuse must not let a new process inherit a dead detection's record"
    );
    // Which reads, correctly, as one clearing and another appearing.
    let events = scan_events(&daemon);
    assert!(
        events.iter().any(|(_, result)| result == "cleared"),
        "{events:?}"
    );
    assert_eq!(
        events.iter().filter(|(_, r)| r == "detected").count(),
        2,
        "{events:?}"
    );
}

// ---------------------------------------------------------------------------
// Section 5: the alert engine
// ---------------------------------------------------------------------------

/// The anti-nag rule end to end over the wire: raise once, stay quiet
/// while it lives, clear, stay quiet inside the 24 h window on restart —
/// and exactly **one** `agents.alert_raise` audit event throughout.
#[test]
fn one_alert_per_signature_across_restarts_of_the_same_binary() {
    let daemon = TestDaemon::start("antinag", Peer::user(PUNAR_UID), with_foo_agent);
    daemon.scan("timer");

    let alerts = daemon.result("alerts.list", None);
    assert_eq!(alerts["alerts"].as_array().unwrap().len(), 1);
    assert_eq!(alerts["quiet_window_secs"], 86_400);
    let alert = &alerts["alerts"][0];
    let alert_id = alert["alert_id"].as_str().unwrap().to_string();
    let first_seen = alert["first_seen"].as_str().unwrap().to_string();
    assert_eq!(alert["state"], "live");
    assert_eq!(alert["live"], 1);
    assert_eq!(alert["agent"], "foo-agent");
    assert_eq!(alert["executable"], FOO_PATH);
    assert_eq!(alert["owner"], "punar");
    assert_eq!(alert["policy_citation"], "personal-defaults");
    let signature_id = alert["signature_id"].as_str().unwrap().to_string();
    assert!(signature_id.starts_with("sig_"), "{signature_id}");

    // Two more passes with the same process: still one card, no re-raise.
    daemon.scan("timer");
    daemon.scan("timer");
    assert_eq!(
        daemon.result("alerts.list", None)["alerts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // It dies, and comes back a moment later — the crash-loop shape.
    kill_process(&daemon.proc_root, 2410);
    daemon.scan("timer");
    assert_eq!(
        daemon.result("alerts.list", None)["alerts"][0]["state"],
        "cleared"
    );
    with_foo_agent(&daemon.proc_root);
    // A different pid this time, which is a different *detection* but the
    // same *thing seen*.
    kill_process(&daemon.proc_root, 2410);
    fake_process(
        &daemon.proc_root,
        2999,
        "foo-agent",
        "/usr/bin/dash",
        &["/bin/sh", FOO_PATH],
        PUNAR_UID,
        "/user.slice",
    );
    daemon.scan("timer");

    let alerts = daemon.result("alerts.list", None);
    assert_eq!(
        alerts["alerts"].as_array().unwrap().len(),
        1,
        "the 24 h quiet window suppresses the second card: {alerts}"
    );
    assert_eq!(alerts["alerts"][0]["signature_id"], signature_id.as_str());
    // The card is the SAME card — the id and the first sighting are the
    // user-visible promise — and it reads `live`, because the process is
    // live. A row saying `cleared` beside `live: 1` was the CI-32933114578
    // regression: the register kept the id but never came back, so
    // alerts.json froze at the clear and the shell showed a stale card.
    let back = &alerts["alerts"][0];
    assert_eq!(back["alert_id"], alert_id.as_str(), "{alerts}");
    assert_eq!(back["first_seen"], first_seen.as_str(), "{alerts}");
    assert_eq!(back["state"], "live", "{alerts}");
    assert_eq!(back["live"], 1, "{alerts}");
    assert!(
        back.get("cleared_at").is_none_or(Value::is_null),
        "{alerts}"
    );
    assert!(
        back.get("quiet_until").is_none_or(Value::is_null),
        "{alerts}"
    );
    // The file the shell actually reads must agree with the socket.
    let file = daemon.alerts_file();
    assert_eq!(file["alerts"][0]["alert_id"], alert_id.as_str(), "{file}");
    assert_eq!(file["alerts"][0]["state"], "live", "{file}");
    assert_eq!(file["alerts"][0]["live"], 1, "{file}");

    // Exactly one raise, ever — the audit half of the anti-nag rule.
    let raises: Vec<Value> = daemon
        .audit_lines()
        .into_iter()
        .filter(|event| event["action"] == "agents.alert_raise")
        .collect();
    assert_eq!(raises.len(), 1, "{raises:?}");
    assert_eq!(raises[0]["result"], "raised");
    assert_eq!(raises[0]["source"], "service");

    // …while the detection transitions were all recorded.
    let events = scan_events(&daemon);
    assert!(
        events.iter().filter(|(_, r)| r == "detected").count() >= 2,
        "{events:?}"
    );
    assert!(events.iter().any(|(_, r)| r == "cleared"), "{events:?}");
}

/// Dismissal files the card. It never deletes it, and it never moves
/// suppression (section 5.4).
#[test]
fn dismissal_files_the_card_and_is_authorized_by_the_owner() {
    let mut daemon = TestDaemon::start("dismiss", Peer::user(PUNAR_UID), with_foo_agent);
    daemon.scan("timer");
    let alert_id = daemon.result("alerts.list", None)["alerts"][0]["alert_id"]
        .as_str()
        .unwrap()
        .to_string();

    // A different unprivileged user may not file someone else's card.
    daemon.restart_as(Peer::user(1234));
    daemon.scan("timer");
    assert_eq!(
        daemon.error_code("alerts.dismiss", Some(json!({"alert_id": alert_id}))),
        "denied"
    );

    daemon.restart_as(Peer::user(PUNAR_UID));
    daemon.scan("timer");
    let filed = daemon.result("alerts.dismiss", Some(json!({"alert_id": alert_id})));
    assert_eq!(filed["dismissed"], true);
    assert_eq!(
        filed["suppression_changed"], false,
        "filing a card moves no suppression state — there is none to move"
    );

    // Filed, not destroyed.
    assert!(
        daemon.result("alerts.list", None)["alerts"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let all = daemon.result("alerts.list", Some(json!({"include_dismissed": true})));
    assert_eq!(all["alerts"].as_array().unwrap().len(), 1);
    assert_eq!(all["alerts"][0]["state"], "dismissed");
    assert!(all["alerts"][0]["dismissed_at"].is_string());

    // The file agrees, and the audit trail has exactly one dismissal.
    let file = daemon.alerts_file();
    assert_eq!(file["alerts"][0]["state"], "dismissed");
    let dismissals: Vec<Value> = daemon
        .audit_lines()
        .into_iter()
        .filter(|e| e["action"] == "agents.alert_dismiss" && e["decision"] == "allow")
        .collect();
    assert_eq!(dismissals.len(), 1, "{dismissals:?}");

    // Idempotent, and unknown ids are `not_found` rather than a silent ok.
    daemon.result("alerts.dismiss", Some(json!({"alert_id": alert_id})));
    assert_eq!(
        daemon
            .audit_lines()
            .into_iter()
            .filter(|e| e["action"] == "agents.alert_dismiss" && e["decision"] == "allow")
            .count(),
        1,
        "a second dismissal is not a second event"
    );
    assert_eq!(
        daemon.error_code(
            "alerts.dismiss",
            Some(json!({"alert_id": "alr_000000000000"}))
        ),
        "not_found"
    );
    assert_eq!(daemon.error_code("alerts.bogus", None), "unknown_method");
}

/// The `alerts.json` side contract (section 5.3): `0640`, exactly the
/// twelve documented fields, and no pid, cmdline, argv, `comm` or cgroup
/// anywhere in it.
///
/// The one path it does carry is the matched executable — the datum the
/// D-009 card is built around, and one the same user can already print
/// with `punarctl agents list`. Spec 24.2 is the rule: the card may not
/// tell the user less than they can already read, and it carries nothing
/// more than the surface it mirrors.
#[test]
fn the_alert_file_is_root_owned_and_carries_no_process_internals() {
    let daemon = TestDaemon::start("alert-privacy", Peer::user(PUNAR_UID), with_foo_agent);
    daemon.scan("timer");

    let path = daemon.dir.join("state/alerts.json");
    let mode = std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o640, "alerts.json is 0640 root:punar");

    let text = fs::read_to_string(&path).unwrap();
    let file: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(file["v"], 1);
    let alert = &file["alerts"][0];
    let mut keys: Vec<&str> = alert
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
            "alert_id",
            "detection_id",
            "executable",
            "first_seen",
            "last_seen",
            "live",
            "owner",
            "policy_citation",
            "signature",
            "signature_id",
            "state",
        ]
    );

    // The regression, stated as strings rather than field names, so a
    // future field that smuggles one in also fails.
    assert!(!text.contains("2410"), "no pid reaches the card: {text}");
    assert!(
        !text.contains("/bin/sh"),
        "no argv reaches the card: {text}"
    );
    assert!(
        !text.contains("dash"),
        "no interpreter/comm reaches the card: {text}"
    );
    assert!(!text.contains("cgroup"), "{text}");
    assert!(!text.contains("user.slice"), "{text}");
    // Exactly one path, and it is the executable the card is about.
    assert_eq!(text.matches("/home/").count(), 1, "{text}");
    assert!(text.contains(FOO_PATH));
}

/// **A read must not be able to manufacture a detection.**
///
/// `alerts.list` runs no staleness-gated pass, unlike `agents.list`. If
/// it did, the first person to *look* could be the one who produced the
/// `agents.scan` / `detected` event — labelled `manual`, and therefore
/// indistinguishable from a typed command. That would destroy the one
/// property that lets a check prove periodic detection actually fired.
#[test]
fn reading_the_alert_register_never_runs_a_detection_pass() {
    // Root, because the pass here is labelled `timer`: a non-root peer's
    // claim is recorded as `manual` (see the trigger-forgery test).
    let daemon = TestDaemon::start("read-only", Peer::root(), |_| {});
    daemon.scan("timer");
    // The fixture appears *after* the last pass. Nobody has scanned it.
    with_foo_agent(&daemon.proc_root);

    let alerts = daemon.result("alerts.list", None);
    assert!(
        alerts["alerts"].as_array().unwrap().is_empty(),
        "a read reports what the last pass knew, and no more"
    );
    assert!(
        scan_events(&daemon).is_empty(),
        "reading the register produced no detection event"
    );
    assert!(!daemon.dir.join("state/alerts.json").exists());

    // Only a pass finds it, and the pass is labelled by whatever asked —
    // when whatever asked is allowed to say (root).
    daemon.scan("timer");
    assert_eq!(
        daemon.result("alerts.list", None)["alerts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        scan_events(&daemon),
        vec![("foo-agent:timer".to_string(), "detected".to_string())]
    );
}

/// Restarting the daemon is not a new sighting (section 5.2): the
/// register resumes from the file this daemon last wrote, so a package
/// update does not re-raise every standing card.
#[test]
fn a_daemon_restart_does_not_re_raise_a_standing_card() {
    let mut daemon = TestDaemon::start("restart", Peer::user(PUNAR_UID), with_foo_agent);
    daemon.scan("timer");
    let alert_id = daemon.result("alerts.list", None)["alerts"][0]["alert_id"]
        .as_str()
        .unwrap()
        .to_string();

    daemon.restart_as(Peer::user(PUNAR_UID));
    daemon.scan("timer");

    let alerts = daemon.result("alerts.list", None);
    assert_eq!(alerts["alerts"].as_array().unwrap().len(), 1);
    assert_eq!(alerts["alerts"][0]["alert_id"], alert_id.as_str());
    assert_eq!(
        daemon
            .audit_lines()
            .into_iter()
            .filter(|e| e["action"] == "agents.alert_raise")
            .count(),
        1,
        "a restart is bookkeeping, not news"
    );

    // Nor does it re-record the detection: the identity is derived from
    // the kernel's facts, so the same process keeps the same id across
    // daemon lifetimes, and the ledger it already had is resumed rather
    // than started over.
    let lines = daemon.detection_lines();
    assert_eq!(lines.len(), 1, "no second `active` record: {lines:?}");
    assert_eq!(
        scan_events(&daemon)
            .into_iter()
            .filter(|(_, result)| result == "detected")
            .count(),
        1,
        "no second `detected` transition"
    );
    let detection_id = lines[0]["session_id"].as_str().unwrap();
    let access = daemon.result("agents.access", Some(json!({"session_id": detection_id})));
    assert_eq!(
        access["summary"]["security_events"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "the resumed ledger kept the reference it already held"
    );
}

// ---------------------------------------------------------------------------
// Section 6: the unknown-agent ledger
// ---------------------------------------------------------------------------

/// M8's open question, closed: a detection gets a schema-exact persisted
/// record and a bounded ledger — and the ledger is strictly *smaller*
/// than a managed one, by construction rather than by policy.
#[test]
fn a_detection_gets_a_persisted_record_and_a_bounded_ledger() {
    let daemon = TestDaemon::start("unknown-ledger", Peer::user(PUNAR_UID), with_foo_agent);
    let scan = daemon.scan("timer");
    let detection_id = scan["detections"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 1. The persisted record: schema-exact, ten fields, `unknown`.
    let lines = daemon.detection_lines();
    assert_eq!(lines.len(), 1, "one line per state change: {lines:?}");
    let record = &lines[0];
    let mut keys: Vec<&str> = record
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
            "process_id",
            "project",
            "session_id",
            "started_at",
            "status",
            "user",
            "version",
        ]
    );
    assert_eq!(record["classification"], "unknown");
    assert_eq!(record["status"], "active");
    assert_eq!(record["agent"], "foo-agent");
    assert_eq!(record["version"], "unknown");
    assert_eq!(record["environment"], "host");
    assert_eq!(
        record["project"], "unknown",
        "`project` is never inferred from cwd — the fixture's hero value is not \
         something real detection can honestly produce"
    );

    // 2. The ledger, read by its owner.
    let access = daemon.result("agents.access", Some(json!({"session_id": detection_id})));
    let summary = &access["summary"];
    assert_eq!(summary["session_id"], detection_id.as_str());
    assert_eq!(summary["agent"], "foo-agent");

    let resources = &summary["resources"];
    // What it *does* carry: the executable's own process class and the
    // zone class of where it lives.
    assert!(
        !resources["process_classes"].as_array().unwrap().is_empty(),
        "{resources}"
    );
    assert_eq!(resources["directory_zones"], json!(["downloads"]));
    // What it cannot carry, and why each is empty.
    for empty in [
        "repositories",
        "network_destinations",
        "credential_classes",
        "mcp_servers",
    ] {
        assert_eq!(
            resources[empty],
            json!([]),
            "{empty} has no producer for an unmanaged agent"
        );
    }
    let honest: Vec<&str> = access["not_yet_observed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["category"].as_str().unwrap())
        .collect();
    for named in [
        "repositories",
        "credential_classes",
        "network_destinations",
        "mcp_servers",
    ] {
        assert!(honest.contains(&named), "{named} must be named: {honest:?}");
    }
    assert!(
        !honest.contains(&"unknown_ai_execution"),
        "M10 shipped the producer, so the row left the list: {honest:?}"
    );

    // 3. The Level-4 reference: the transition that produced it.
    let events = summary["security_events"].as_array().unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["event_type"], "unknown_ai_execution");
    assert!(
        events[0]["event_id"].as_str().unwrap().starts_with("evt_"),
        "{events:?}"
    );
    // A reference, not a copy: the payload stayed in the audit trail.
    assert!(events[0].get("resource").is_none());

    // 4. Retention is the shorter, detection-specific window.
    assert_eq!(access["retention"]["days"], 7);

    // 5. The privacy regression, on the whole document: no path, no
    //    argv, no cmdline, no comm, no cwd, no pid.
    let ledger_text = fs::read_to_string(
        daemon
            .dir
            .join(format!("state/agents/ledger/{detection_id}.json")),
    )
    .unwrap();
    for forbidden in [
        "/home/",
        "Downloads",
        "/bin/sh",
        "dash",
        "cwd",
        "cmdline",
        "argv",
    ] {
        assert!(
            !ledger_text.contains(forbidden),
            "{forbidden:?} must be unrepresentable in a ledger record: {ledger_text}"
        );
    }
    fn contains_exact(value: &Value, needle: &str) -> bool {
        match value {
            Value::String(value) => value == needle,
            Value::Number(value) => value.to_string() == needle,
            Value::Array(values) => values.iter().any(|value| contains_exact(value, needle)),
            Value::Object(values) => values
                .iter()
                .any(|(key, value)| key == needle || contains_exact(value, needle)),
            Value::Null | Value::Bool(_) => false,
        }
    }
    let ledger_json: Value = serde_json::from_str(&ledger_text).unwrap();
    assert!(
        !contains_exact(&ledger_json, "pid") && !contains_exact(&ledger_json, "2410"),
        "the process id must be absent as a field or exact value: {ledger_text}"
    );
    // The zone survived as a *class*; the path it came from did not.
    assert!(ledger_text.contains("downloads"));
    let served = serde_json::to_string(&access).unwrap();
    for forbidden in ["/home/", "/bin/sh", "cmdline", "argv"] {
        assert!(!served.contains(forbidden), "{forbidden:?} in {served}");
    }
}

/// The detection's ledger closes when the process goes, with the ended
/// record beside it — and the transition log holds two lines, not two
/// per pass.
#[test]
fn a_cleared_detection_closes_its_ledger_and_appends_one_ended_record() {
    let daemon = TestDaemon::start("clear-ledger", Peer::user(PUNAR_UID), with_foo_agent);
    let detection_id = daemon.scan("timer")["detections"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    daemon.scan("timer");
    daemon.scan("timer");
    assert_eq!(
        daemon.detection_lines().len(),
        1,
        "passes that change nothing append nothing"
    );

    kill_process(&daemon.proc_root, 2410);
    daemon.scan("timer");

    let lines = daemon.detection_lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[1]["status"], "ended");
    assert_eq!(lines[1]["session_id"], detection_id.as_str());

    let access = daemon.result("agents.access", Some(json!({"session_id": detection_id})));
    assert_eq!(access["detail"]["status"], "ended");
    assert_eq!(access["retention"]["days"], 7);
    assert!(
        access["retention"]["active"].is_null(),
        "an ended ledger states an expiry rather than an `active` clock"
    );
    assert!(access["retention"]["expires_at"].is_string());
    // Still exactly one Level-4 reference: the `cleared` transition is
    // the same execution ending, not a second execution.
    assert_eq!(
        access["summary"]["security_events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

/// A detection's ledger is personal data about one user's machine, so it
/// is read by that user or by root — the M8 rule, applied unchanged.
#[test]
fn another_user_cannot_read_a_detections_ledger() {
    let mut daemon = TestDaemon::start("ledger-authz", Peer::user(PUNAR_UID), with_foo_agent);
    let detection_id = daemon.scan("timer")["detections"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    daemon.restart_as(Peer::user(1234));
    daemon.scan("timer");
    assert_eq!(
        daemon.error_code("agents.access", Some(json!({"session_id": detection_id}))),
        "denied"
    );

    daemon.restart_as(Peer::root());
    daemon.scan("timer");
    let access = daemon.result("agents.access", Some(json!({"session_id": detection_id})));
    assert_eq!(access["summary"]["session_id"], detection_id.as_str());
    // Root reading somebody else's ledger is itself an event.
    assert!(
        daemon
            .audit_lines()
            .iter()
            .any(|e| e["action"] == "agents.access" && e["decision"] == "allow"),
        "root reading another user's ledger is audited"
    );
}

/// A *known* agent running outside the managed runtime is `observed`, not
/// `unknown`: it gets a record and a ledger, but no card. Calling a named
/// product "unknown AI" would be false (spec 1.22).
#[test]
fn an_observed_detection_is_recorded_but_never_alerted() {
    let daemon = TestDaemon::start("observed", Peer::user(PUNAR_UID), |proc| {
        fake_process(
            proc,
            3001,
            "claude",
            "/usr/bin/claude",
            &["/usr/bin/claude"],
            PUNAR_UID,
            "/user.slice/user-1000.slice/session-3.scope",
        );
    });
    let scan = daemon.scan("timer");
    assert_eq!(scan["detections"][0]["classification"], "observed");
    let detection_id = scan["detections"][0]["session_id"].as_str().unwrap();

    assert!(
        daemon.result("alerts.list", None)["alerts"]
            .as_array()
            .unwrap()
            .is_empty(),
        "an `observed` detection raises no UNKNOWN AI card"
    );
    assert!(
        !daemon.dir.join("state/alerts.json").exists(),
        "and writes no alert file"
    );
    // It is still recorded and still answerable.
    assert_eq!(daemon.detection_lines().len(), 1);
    let access = daemon.result("agents.access", Some(json!({"session_id": detection_id})));
    assert_eq!(access["summary"]["agent"], "claude-code");
    assert_eq!(
        access["summary"]["resources"]["directory_zones"],
        json!(["system"])
    );
}
