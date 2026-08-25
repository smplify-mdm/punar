//! Integration tests for the AI Access Ledger (spec sections 21, 24;
//! Milestone 8), driven over the real socket exactly as `punarctl` and the
//! panel will drive it (docs/api/ipc.md sections 12–13).
//!
//! Everything is injected — the socket, the state directory, the audit
//! trail, `/etc/passwd`, `/proc`, and (new in M8) the cgroup tree the
//! ledger samples. A fixture scope is a directory holding `cgroup.procs`
//! and `pids.peak`, which is exactly what the kernel shows for a
//! `systemd-run --scope` launch; a fixture process is the same five
//! `/proc` files the daemon reads on a real kernel. Nothing here mocks the
//! code under test — only the kernel surfaces it reads.
//!
//! The load-bearing test is
//! [`the_ledger_files_contain_no_paths_no_argv_and_no_prompts`]: the
//! privacy rules of spec 21.2 are asserted against the **bytes actually
//! written to disk**, not against the types that wrote them.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use punar_agentd::authz::{Peer, PeerSource};
use punar_agentd::server::{AgentdConfig, Daemon, DaemonHandle};
use punar_agentd::testsupport::{
    fake_process, fixture_adapters, fixture_cgroup_scope, fixture_nss, fixture_suspected,
    managed_cgroup,
};
use serde_json::{Value, json};

const PUNAR_UID: u32 = 1000;
const OTHER_UID: u32 = 1001;
const SESSION: &str = "agt_4f21c09ab3e1";
/// The workspace path a real session would have run in. It must appear
/// **zero** times in everything the ledger writes.
const WORKSPACE_PATH: &str = "/home/punar/atlas";

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
        "punar-agentd-ledger-{tag}-{}-{nanos}",
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

    /// Stop and restart on the **same state** — used here to change the
    /// connecting peer, which is how "another user connects" is tested
    /// without needing a second real uid.
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
            cgroup_root: self.dir.join("cgroup"),
            // Absent on purpose: the built-in class table is the shipped
            // fallback, and this proves it is the one that ships.
            process_classes_path: self.dir.join("absent-process-classes.json"),
            ledger_runtime_file: self.dir.join("run/ledger.json"),
            group_file: self.dir.join("group"),
            passwd_file: self.dir.join("passwd"),
            peer_source: PeerSource::Fixed(peer),
            io_timeout: Duration::from_secs(5),
            scan_stale_after: Duration::from_secs(0),
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

    fn ledger_dir(&self) -> PathBuf {
        self.dir.join("state/agents/ledger")
    }

    fn ledger_file(&self, session_id: &str) -> PathBuf {
        self.ledger_dir().join(format!("{session_id}.json"))
    }

    fn index(&self) -> Value {
        let text = fs::read_to_string(self.ledger_dir().join("index.json")).unwrap();
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

    /// Append one audit event as punard would, once the M8 attribution
    /// rule tags it with the agent session that made the call.
    fn append_audit(&self, event_id: &str, session_id: &str, action: &str, decision: &str) {
        self.append_audit_on(event_id, session_id, action, decision, "security.firewall");
    }

    /// The same, with the `resource` spelled out — the M9 credential
    /// drain reads it (milestone-9.md section 9.2).
    fn append_audit_on(
        &self,
        event_id: &str,
        session_id: &str,
        action: &str,
        decision: &str,
        resource: &str,
    ) {
        let event = json!({
            "event_id": event_id,
            "timestamp": "2026-08-27T09:59:12Z",
            "device_id": "dev_test",
            "user_id": "punar",
            "agent_session_id": session_id,
            "project_id": "atlas",
            "source": "ai_agent",
            "action": action,
            "resource": resource,
            "decision": decision,
            "policy_ids": ["personal-defaults"],
            "result": if decision == "deny" { "denied" } else { "success" }
        });
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("audit.jsonl"))
            .unwrap();
        writeln!(file, "{event}").unwrap();
    }

    /// Every file the ledger owns, as raw text — what a privacy
    /// regression is asserted against.
    /// Everything the **ledger** wrote: its records, its index and the
    /// panel's side file. Deliberately excludes `agents.json`, which is
    /// the M7 registry summary and carries the registry's own fields.
    fn ledger_written_bytes(&self) -> String {
        let mut text = String::new();
        if let Ok(content) = fs::read_to_string(self.dir.join("run/ledger.json")) {
            text.push_str(&content);
        }
        if let Ok(entries) = fs::read_dir(self.ledger_dir()) {
            for entry in entries.flatten() {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    text.push_str(&content);
                }
            }
        }
        text
    }

    fn all_written_bytes(&self) -> String {
        let mut text = String::new();
        for path in [
            self.dir.join("run/ledger.json"),
            self.dir.join("state/agents.json"),
            self.ledger_dir().join("index.json"),
        ] {
            if let Ok(content) = fs::read_to_string(&path) {
                text.push_str(&content);
            }
        }
        if let Ok(entries) = fs::read_dir(self.ledger_dir()) {
            for entry in entries.flatten() {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    text.push_str(&content);
                }
            }
        }
        text
    }
}

/// A managed session with three processes in its scope: the agent itself,
/// a `git`, and a shell — the D-005 shape.
fn managed_session(daemon: &TestDaemon) -> Value {
    fixture_cgroup_scope(
        &daemon.dir.join("cgroup"),
        SESSION,
        &[2143, 2200, 2201],
        Some(6),
    );
    daemon.result(
        "agents.register",
        Some(json!({
            "session_id": SESSION,
            "agent": "claude-code",
            "version": "mock",
            "process_id": 2143,
            "project": "atlas",
            "environment": "punar-env-atlas",
            "authority": {
                "policy_citation": "personal-defaults",
                "rows": [
                    {"zone": "filesystem.project", "decision": "read_write",
                     "enforcement": "declared · M9"}
                ]
            }
        })),
    )
}

fn scope_processes(proc: &Path) {
    // The agent's own root process. `comm` is the kernel's 15-character
    // name, so a 16-character binary arrives one character short — the
    // class table carries both spellings.
    fake_process(
        proc,
        2143,
        "punar-mock-agen",
        "/usr/lib/punar/punar-mock-agent",
        &["/usr/lib/punar/punar-mock-agent"],
        PUNAR_UID,
        &managed_cgroup(SESSION),
    );
    // A child whose *argument vector* names the workspace and looks like
    // a command line — none of which may reach the ledger.
    fake_process(
        proc,
        2200,
        "git",
        "/usr/bin/git",
        &[
            "/usr/bin/git",
            "hash-object",
            "--stdin-paths",
            WORKSPACE_PATH,
        ],
        PUNAR_UID,
        &managed_cgroup(SESSION),
    );
    fake_process(
        proc,
        2201,
        "bash",
        "/usr/bin/bash",
        &["/bin/sh", WORKSPACE_PATH],
        PUNAR_UID,
        &managed_cgroup(SESSION),
    );
}

/// `agents.access` returns a schema-exact summary plus the sibling
/// detail, honesty rows, retention and privacy notice (ipc.md 12.2).
#[test]
fn access_returns_the_schema_exact_summary_and_its_siblings() {
    let daemon = TestDaemon::start("access", Peer::user(PUNAR_UID), scope_processes);
    managed_session(&daemon);
    daemon.append_audit("evt_502", SESSION, "capabilities.set", "deny");

    let result = daemon.result("agents.access", Some(json!({"session_id": SESSION})));

    // -- the schema-exact half ---------------------------------------
    let summary = &result["summary"];
    let mut keys: Vec<&str> = summary
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
            "generated_at",
            "resources",
            "security_events",
            "session_id"
        ],
        "the summary is the shipped document and nothing else"
    );
    let resources = summary["resources"].as_object().unwrap();
    let mut categories: Vec<&str> = resources.keys().map(String::as_str).collect();
    categories.sort_unstable();
    assert_eq!(
        categories,
        vec![
            "credential_classes",
            "directory_zones",
            "mcp_servers",
            "network_destinations",
            "process_classes",
            "repositories"
        ],
        "all six required arrays are present, empty or not"
    );

    // Level 3 — what M8 can honestly claim.
    assert_eq!(resources["repositories"], json!(["atlas"]));
    assert_eq!(resources["directory_zones"], json!(["workspace"]));
    let classes: Vec<&str> = resources["process_classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(classes.contains(&"git"), "{classes:?}");
    assert!(classes.contains(&"shell"), "{classes:?}");
    assert!(classes.contains(&"agent"), "{classes:?}");

    // Level 3 — what it cannot, said out loud rather than left blank.
    // `credential_classes` is empty here too, but it is NOT in the honesty
    // rows any more: M9 shipped punar-secrets, so an empty array now means
    // "this session asked for no credential", which is a fact, not a gap.
    for empty in ["network_destinations", "mcp_servers", "credential_classes"] {
        assert_eq!(resources[empty], json!([]), "{empty}");
    }
    let honest: Vec<(&str, &str)> = result["not_yet_observed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["category"].as_str().unwrap(),
                row["milestone"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(honest.len(), 5);
    assert!(honest.contains(&("network_destinations", "M12")));
    // M9 re-milestoned this rather than leaving it promising M9+: the
    // milestone shipped a credential broker, not a tool gateway.
    assert!(honest.contains(&("mcp_servers", "M11+")));
    // Left the list in M9 — punar-secrets is the producer, and a category
    // with a producer is not "not yet observed".
    assert!(!honest.iter().any(|(cat, _)| *cat == "credential_classes"));
    assert!(!honest.iter().any(|(cat, _)| *cat == "credential_request"));
    assert!(
        !honest
            .iter()
            .any(|(cat, _)| *cat == "policy_bypass_attempt")
    );
    // All seven Level-4 categories are accounted for: four have producers
    // as of M9, the other three are named here.
    assert!(honest.contains(&("unknown_ai_execution", "M10")));

    // Level 4 — a reference, joined to the audit trail by event id.
    let events = summary["security_events"].as_array().unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["event_id"], "evt_502");
    assert_eq!(events[0]["event_type"], "denied_access");
    // The payload stayed in the audit log where it belongs (spec 53).
    assert!(events[0].get("resource").is_none());
    assert!(
        daemon
            .audit_lines()
            .iter()
            .any(|line| line["event_id"] == "evt_502" && line["resource"] == "security.firewall")
    );

    // -- the sibling half --------------------------------------------
    let detail = &result["detail"];
    assert_eq!(detail["status"], "active");
    assert_eq!(detail["process_peak"], 6);
    assert_eq!(detail["truncated"], false);
    for entry in detail["entries"].as_array().unwrap() {
        assert!(entry["count"].as_u64().unwrap() >= 1);
        assert!(entry["first_seen"].as_str().unwrap() <= entry["last_seen"].as_str().unwrap());
        assert!(
            [
                "cgroup_scope",
                "audit_event",
                "workspace_bind",
                "adapter_metadata"
            ]
            .contains(&entry["evidence"].as_str().unwrap()),
            "{entry}"
        );
    }

    assert_eq!(result["retention"]["days"], 14);
    assert_eq!(result["retention"]["active"], true);
    assert_eq!(result["privacy"]["local_only"], true);
    assert_eq!(result["privacy"]["audit_trail_separate"], true);
    assert_eq!(
        result["privacy"]["purge_command"],
        format!("punarctl privacy purge --session {SESSION}")
    );
    let never: Vec<&str> = result["privacy"]["never_recorded"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(never.contains(&"prompts"));
    assert!(never.contains(&"file paths inside the workspace"));
}

/// The load-bearing privacy test: spec 21.2 asserted against the bytes on
/// disk, not against the types that wrote them.
#[test]
fn the_ledger_files_contain_no_paths_no_argv_and_no_prompts() {
    let daemon = TestDaemon::start("privacy", Peer::user(PUNAR_UID), scope_processes);
    managed_session(&daemon);
    daemon.append_audit("evt_502", SESSION, "capabilities.set", "deny");
    daemon.result("agents.access", Some(json!({"session_id": SESSION})));
    daemon.result("agents.scan", None);

    let written = daemon.all_written_bytes();
    assert!(!written.is_empty(), "nothing was written to check");

    // Paths — the workspace path, any path at all, and the executables.
    for path_ish in [
        WORKSPACE_PATH,
        "/home/",
        "/usr/bin/git",
        "/usr/lib/punar",
        "/bin/sh",
    ] {
        assert!(
            !written.contains(path_ish),
            "{path_ish} leaked into the ledger: {written}"
        );
    }
    // Argument vectors, and the tokens a command line would carry.
    for argv_ish in ["hash-object", "--stdin-paths", "cmdline", "argv"] {
        assert!(
            !written.contains(argv_ish),
            "{argv_ish} leaked into the ledger: {written}"
        );
    }
    // "prompt" appears exactly once across everything written, and only
    // as the *promise* that prompts are never recorded — the privacy
    // notice's own `never_recorded` list.
    let stored = fs::read_to_string(daemon.ledger_file(SESSION)).unwrap()
        + &fs::read_to_string(daemon.ledger_dir().join("index.json")).unwrap();
    for never in ["prompt", "source code", "secret"] {
        assert!(
            !stored.contains(never),
            "{never} appears in a stored ledger record: {stored}"
        );
    }
    // The raw `comm` is mapped and dropped; the class name is what is
    // kept.
    assert!(
        !written.contains("punar-mock-agen"),
        "a raw comm leaked: {written}"
    );

    // Structural check: no resource class anywhere holds a separator or
    // whitespace, whatever the category (including the one the schema
    // leaves unpatterned).
    let ledger: Value =
        serde_json::from_str(&fs::read_to_string(daemon.ledger_file(SESSION)).unwrap()).unwrap();
    for entry in ledger["entries"].as_array().unwrap() {
        let class = entry["resource_class"].as_str().unwrap();
        assert!(
            !class.contains('/') && !class.contains(':') && !class.contains(char::is_whitespace),
            "{class:?} is not a class"
        );
    }
    // And no field exists for the things that must never be recorded.
    let record = ledger.as_object().unwrap();
    for forbidden in [
        "cmdline",
        "argv",
        "prompt",
        "comm",
        "cwd",
        "path",
        "executable",
        "process_id",
        "pid",
    ] {
        assert!(
            !record.contains_key(forbidden),
            "the record has a {forbidden} field"
        );
    }

    // The world-readable summary file carries no ledger identifiers at
    // all — it is not even permitted the fingerprint's class names.
    let agents_json = fs::read_to_string(daemon.dir.join("state/agents.json")).unwrap();
    for leak in ["evt_", "process_classes", "security_events"] {
        assert!(
            !agents_json.contains(leak),
            "{leak} leaked into the world-readable agents.json: {agents_json}"
        );
    }
}

/// A ledger is personal data: owner or root, and nobody else
/// (ipc.md 12.2, spec 24.1).
/// Adversarial: `agents.register` pattern-checks `session_id` and
/// `agent`, but the registry-record schema leaves `project` unpatterned,
/// so a caller may register a **path** as its project. That path is the
/// one piece of free text a client controls end to end, and spec 21.2
/// forbids a workspace path in the ledger — so it must reach no ledger
/// byte, not even as the record's own `project` field.
///
/// The type is what enforces it (`LedgerRecord::project` is an
/// `Option<ResourceClass>`); this test asserts the consequence on disk.
#[test]
fn a_path_shaped_project_reaches_no_ledger_byte() {
    const HOSTILE_PROJECT: &str = "/home/punar/clients/acme-merger";

    let daemon = TestDaemon::start("hostile-project", Peer::user(PUNAR_UID), scope_processes);
    fixture_cgroup_scope(
        &daemon.dir.join("cgroup"),
        SESSION,
        &[2143, 2200, 2201],
        Some(6),
    );
    daemon.result(
        "agents.register",
        Some(json!({
            "session_id": SESSION,
            "agent": "claude-code",
            "version": "mock",
            "process_id": 2143,
            "project": HOSTILE_PROJECT,
            "environment": "punar-env-atlas",
            "authority": {
                "policy_citation": "personal-defaults",
                "rows": [
                    {"zone": "filesystem.project", "decision": "read_write",
                     "enforcement": "declared · M9"}
                ]
            }
        })),
    );
    let access = daemon.result("agents.access", Some(json!({"session_id": SESSION})));
    daemon.result("agents.scan", None);

    // Nothing derived from it is claimed: an unresolvable project is not
    // a repository the session reached, and no zone is inferred from one.
    let resources = &access["summary"]["resources"];
    assert_eq!(
        resources["repositories"].as_array().unwrap().len(),
        0,
        "a path must not become a repository: {access}"
    );
    assert_eq!(
        resources["directory_zones"].as_array().unwrap().len(),
        0,
        "no zone may be inferred from an unresolvable project: {access}"
    );

    // And no fragment of it is in any ledger byte: the per-session
    // record, `index.json`, or the panel's side file.
    //
    // The corpus is the ledger's own artifacts. `/run/punar/agents.json`
    // is the M7 registry summary and still echoes the launcher's raw
    // `project` string verbatim — a separate, pre-existing surface with
    // its own contract, not something this ledger produces.
    let written = daemon.ledger_written_bytes();
    assert!(!written.is_empty(), "nothing was written to check");
    for fragment in [HOSTILE_PROJECT, "/home/", "clients", "acme-merger", "acme"] {
        assert!(
            !written.contains(fragment),
            "{fragment} leaked from the project field into the ledger: {written}"
        );
    }
    assert!(
        written.contains(SESSION),
        "the corpus must actually hold this session, or the assertions above are vacuous"
    );
}

#[test]
fn another_user_may_neither_read_nor_delete_a_ledger() {
    let mut daemon = TestDaemon::start("authz", Peer::user(PUNAR_UID), scope_processes);
    managed_session(&daemon);

    // The same daemon, now answering a different user's connection.
    daemon.restart_as(Peer::user(OTHER_UID));
    assert_eq!(
        daemon.error_code("agents.access", Some(json!({"session_id": SESSION}))),
        "denied"
    );
    assert_eq!(
        daemon.error_code("ledger.purge", Some(json!({"session_id": SESSION}))),
        "denied"
    );
    // The denial voice names the reason and a next step (spec 73).
    let refusal = daemon.call("agents.access", Some(json!({"session_id": SESSION})));
    let message = refusal["error"]["message"].as_str().unwrap();
    assert!(message.contains("another user"), "{message}");
    assert!(message.contains("Next step"), "{message}");
    // Nothing was deleted.
    assert!(daemon.ledger_file(SESSION).exists());

    // `--all` from that user purges only *their* sessions — which is
    // none, so the owner's ledger survives.
    let purged = daemon.result("ledger.purge", Some(json!({"all": true})));
    assert_eq!(purged["purged"], 0);
    assert!(daemon.ledger_file(SESSION).exists());

    // Root may read it, and that read is itself audited — the seed of
    // Milestone 10's authorized administrator query.
    daemon.restart_as(Peer::root());
    daemon.result("agents.access", Some(json!({"session_id": SESSION})));
    assert!(
        daemon
            .audit_lines()
            .iter()
            .any(|line| line["action"] == "agents.access"
                && line["decision"] == "allow"
                && line["agent_session_id"] == SESSION),
        "root reading another user's ledger is audited"
    );
}

/// Deleting your own ledger works unconditionally, is durable, is
/// audited, and does **not** touch the audit trail (spec 24.2, 53).
#[test]
fn purge_deletes_the_ledger_and_leaves_the_audit_trail_alone() {
    let daemon = TestDaemon::start("purge", Peer::user(PUNAR_UID), scope_processes);
    managed_session(&daemon);
    daemon.append_audit("evt_502", SESSION, "capabilities.set", "deny");
    daemon.result("agents.access", Some(json!({"session_id": SESSION})));
    let audit_before = fs::read_to_string(daemon.dir.join("audit.jsonl")).unwrap();

    let result = daemon.result("ledger.purge", Some(json!({"session_id": SESSION})));
    assert_eq!(result["purged"], 1);
    assert!(result["resource_classes"].as_u64().unwrap() >= 3);
    assert_eq!(result["security_events"], 1);

    assert!(!daemon.ledger_file(SESSION).exists(), "the file is gone");

    // The index row is a tombstone carrying no resource data.
    let index = daemon.index();
    let row = index["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["session_id"] == SESSION)
        .unwrap();
    assert!(row["purged_at"].is_string());
    assert!(row.get("project").is_none(), "{row}");
    assert!(row.get("agent").is_none(), "{row}");
    assert_eq!(row["counts"]["resources"], 0);

    // The answer says *purged*, never "nothing recorded".
    let access = daemon.result("agents.access", Some(json!({"session_id": SESSION})));
    assert!(access["purged_at"].is_string(), "{access}");
    assert_eq!(access["summary"]["resources"]["repositories"], json!([]));

    // The audit trail is untouched — it is not the user's to delete —
    // and the purge itself is audited.
    assert_eq!(
        fs::read_to_string(daemon.dir.join("audit.jsonl")).unwrap()[..audit_before.len()],
        audit_before
    );
    assert!(audit_before.contains("evt_502"));
    assert!(
        daemon.audit_lines().iter().any(|line| {
            line["action"] == "ledger.purge"
                && line["decision"] == "allow"
                && line["result"] == "purged"
                && line["agent_session_id"] == SESSION
        }),
        "the purge is always audited"
    );

    // A scan drains the audit tail again; it must not resurrect what the
    // user deleted.
    daemon.result("agents.scan", None);
    assert!(!daemon.ledger_file(SESSION).exists());
    let access = daemon.result("agents.access", Some(json!({"session_id": SESSION})));
    assert!(access["purged_at"].is_string(), "{access}");
}

/// Ending a session compacts its ledger and starts the retention clock;
/// a backdated ledger is pruned on the next event-driven pass, and one
/// audit event is emitted per batch (spec 6.4).
#[test]
fn retention_starts_at_end_and_prunes_in_batches() {
    let daemon = TestDaemon::start("retention", Peer::user(PUNAR_UID), scope_processes);
    managed_session(&daemon);
    daemon.result("agents.end", Some(json!({"session_id": SESSION})));

    let record: Value =
        serde_json::from_str(&fs::read_to_string(daemon.ledger_file(SESSION)).unwrap()).unwrap();
    assert_eq!(record["status"], "ended");
    let ended_at = record["ended_at"].as_str().unwrap();
    let expires = record["retention_expires_at"].as_str().unwrap();
    assert!(expires > ended_at);
    // Fourteen days, asserted to the day, against arithmetic the daemon
    // did not do.
    let expected_day = {
        let d = &ended_at[..10];
        let (y, m, day): (i64, u32, u32) = (
            d[0..4].parse().unwrap(),
            d[5..7].parse().unwrap(),
            d[8..10].parse().unwrap(),
        );
        let seconds = (days_from_civil(y, m, day) as u64 + 14) * 86_400;
        punar_common::time::rfc3339_utc_from_unix_seconds(seconds)[..10].to_string()
    };
    assert_eq!(&expires[..10], expected_day.as_str());

    // Backdate the record past its deadline, exactly as a fortnight would.
    let mut record = record;
    record["retention_expires_at"] = json!("2026-07-01T00:00:00Z");
    fs::write(
        daemon.ledger_file(SESSION),
        serde_json::to_string(&record).unwrap(),
    )
    .unwrap();
    let mut index = daemon.index();
    for row in index["sessions"].as_array_mut().unwrap() {
        if row["session_id"] == SESSION {
            row["retention_expires_at"] = json!("2026-07-01T00:00:00Z");
        }
    }
    fs::write(
        daemon.ledger_dir().join("index.json"),
        serde_json::to_string(&index).unwrap(),
    )
    .unwrap();

    // A fresh daemon over the same state prunes at startup — no timer
    // anywhere, just the event of coming up.
    let mut daemon = daemon;
    daemon.restart_as(Peer::user(PUNAR_UID));
    assert!(
        !daemon.ledger_file(SESSION).exists(),
        "an expired ledger is deleted"
    );
    assert!(
        daemon.index()["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["session_id"] != SESSION)
    );
    assert!(
        daemon
            .audit_lines()
            .iter()
            .any(|line| line["action"] == "ledger.prune" && line["result"] == "expired"),
        "one ledger.prune event per batch"
    );
    assert_eq!(
        daemon
            .audit_lines()
            .iter()
            .filter(|line| line["action"] == "ledger.prune")
            .count(),
        1,
        "one event for the batch, not one per file"
    );
}

/// Unknown ids, detections, and an ambiguous purge are all refused
/// honestly (ipc.md 12.2, 12.3).
#[test]
fn the_negative_paths_are_honest() {
    let daemon = TestDaemon::start("negative", Peer::user(PUNAR_UID), scope_processes);
    managed_session(&daemon);

    assert_eq!(
        daemon.error_code(
            "agents.access",
            Some(json!({"session_id": "agt_absent00001"}))
        ),
        "not_found"
    );
    assert_eq!(
        daemon.error_code(
            "ledger.purge",
            Some(json!({"session_id": "agt_absent00001"}))
        ),
        "not_found"
    );
    // Neither scope, or both — never inferred.
    for ambiguous in [json!({}), json!({"session_id": SESSION, "all": true})] {
        assert_eq!(
            daemon.error_code("ledger.purge", Some(ambiguous.clone())),
            "invalid_params",
            "{ambiguous}"
        );
    }
    // There is no export path at all, and the refusal says why.
    for probe in ["ledger.export", "ledger.query"] {
        let refusal = daemon.call(probe, Some(json!({"session_id": SESSION})));
        assert_eq!(refusal["error"]["code"], "unknown_method", "{probe}");
        assert!(
            refusal["error"]["message"]
                .as_str()
                .unwrap()
                .contains("stays on this device"),
            "{refusal}"
        );
    }
}

/// M9's Level-3 door (milestone-9.md section 9.2). M8 wired `drain_audit`
/// for Level-4 references only; this asserts the missing half end to end,
/// through the socket, without any of the four M8 evidence sources being
/// involved: an issued credential fills `credential_classes` **and** its
/// Level-4 reference, a refused one fills only the denial, and an agent
/// refused at the approval gate lands as `policy_bypass_attempt` rather
/// than as a generic `denied_access`.
#[test]
fn an_issued_credential_fills_the_level_3_row_and_a_refused_gate_is_a_bypass_attempt() {
    let daemon = TestDaemon::start("credentials", Peer::user(PUNAR_UID), scope_processes);
    managed_session(&daemon);
    daemon.append_audit_on("evt_610", SESSION, "credential.request", "allow", "github");
    daemon.append_audit_on("evt_611", SESSION, "credential.request", "allow", "aws-dev");
    // Same class twice: a count, never a second row.
    daemon.append_audit_on("evt_612", SESSION, "credential.request", "allow", "github");
    // Refused: a denial, not a class the agent used.
    daemon.append_audit_on("evt_613", SESSION, "credential.request", "deny", "aws-prod");
    // The self-approval refusal — the one action whose denial is a bypass.
    daemon.append_audit_on(
        "evt_614",
        SESSION,
        "approval.resolve",
        "deny",
        "apr_1a2b3c4d",
    );
    daemon.result("agents.scan", None);

    let result = daemon.result("agents.access", Some(json!({"session_id": SESSION})));
    let classes = result["summary"]["resources"]["credential_classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        classes,
        vec!["aws-dev", "github"],
        "kebab-case, deduplicated"
    );
    // aws-prod was refused, so it is NOT a class this session used.
    assert!(!classes.contains(&"aws-prod"));

    let entry = result["detail"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["category"] == "credential_classes" && e["resource_class"] == "github")
        .cloned()
        .expect("a credential_classes entry for github");
    assert_eq!(entry["count"], 2, "the same class twice is a count");
    assert_eq!(
        entry["evidence"], "audit_event",
        "the evidence variant M8 declared and never produced"
    );

    let events: Vec<(&str, &str)> = result["summary"]["security_events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["event_id"].as_str().unwrap(),
                e["event_type"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(events.contains(&("evt_610", "credential_request")));
    assert!(events.contains(&("evt_613", "denied_access")));
    assert!(events.contains(&("evt_614", "policy_bypass_attempt")));

    // Still no token, no hash, no approval payload anywhere on disk: the
    // broker's events carry the class name and nothing else, which is the
    // property that makes this door safe (spec 53).
    let written = daemon.ledger_written_bytes();
    assert!(written.contains("github"), "the class name IS recorded");
    assert!(!written.contains("punar-mock-"), "no token prefix");
    assert!(!written.contains("apr_1a2b3c4d"), "no approval payload");
}

/// The panel's side file is root-owned, `0640`, and carries the same rows
/// the socket returns (ipc.md 13.2).
#[test]
fn the_runtime_view_matches_the_socket_and_is_not_world_readable() {
    let daemon = TestDaemon::start("runtime", Peer::user(PUNAR_UID), scope_processes);
    managed_session(&daemon);
    daemon.result("agents.scan", None);

    let path = daemon.dir.join("run/ledger.json");
    let mode = std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o640, "a ledger is not world-readable");

    let file: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(file["v"], 1);
    let view = &file["sessions"][0];
    assert_eq!(view["summary"]["session_id"], SESSION);
    assert_eq!(view["not_yet_observed"].as_array().unwrap().len(), 5);
    assert_eq!(view["retention"]["days"], 14);

    // Same rows as the socket, so the pane and the CLI cannot disagree.
    let socket = daemon.result("agents.access", Some(json!({"session_id": SESSION})));
    assert_eq!(view["summary"]["resources"], socket["summary"]["resources"]);
}

/// Howard Hinnant's `days_from_civil`, restated here so the retention
/// deadline is checked against arithmetic the daemon did not do.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = u64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + u64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}
