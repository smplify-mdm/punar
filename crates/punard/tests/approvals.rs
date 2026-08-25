//! Milestone 9 integration tests: the approval gate, AI authority, and
//! just-in-time privilege, driven over the wire exactly as `punarctl` and
//! `punar-secrets` will drive them (docs/api/ipc.md sections 14–15).
//!
//! Agent attribution is real here, not mocked away: the daemon reads
//! `/proc/<pid>/cgroup` for the peer's pid, so these tests point
//! `DaemonConfig::proc_root` at a tempdir and write the same
//! `punar-agent-<id>.scope` line the kernel writes. That means the tests
//! exercise the **actual** section 12.5 rule, including the case that
//! matters most: an AI agent trying to answer its own approval.
//!
//! What these tests are about, in one line each:
//!
//! - a human's call is not gated, an agent's identical call is;
//! - `pending → approved` executes exactly once, and the trail names both
//!   the agent that asked and the human that allowed;
//! - `pending → denied` and `pending → expired` never execute anything;
//! - an AI agent cannot resolve an approval — not its own, not a human's;
//! - a grant is time-boxed for real, and an agent never gets one.

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

/// The capability the shipped personal defaults gate behind a human
/// (`host.firewall: approval_required`) — deliberately the highest-risk one
/// in the M9 registry, because a gate that only guards something trivial has
/// not been tested.
const GATED: &str = "security.firewall";
/// A session id shaped exactly like `punar-env`'s.
const AGENT: &str = "agt_4f21c09ab3e1";
/// The pid the tests hand the daemon as the peer's; the cgroup fixture below
/// is written at `<proc_root>/<pid>/cgroup`.
const AGENT_PID: i32 = 4242;
const HUMAN_PID: i32 = 4243;
/// A peer sitting in a scope that *names* a managed agent session but spells
/// no valid id (`punar-agent-notasession.scope`). Attribution refuses to name
/// it — `agent_session_in_cgroup` returns `None` — while the wide M9 rule
/// (contract section 14.5) still sees an agent. The gap between those two
/// rules is where a method that used the narrow test would let an
/// agent-shaped peer through, so the tests keep a peer that lives in it.
const SMELLY_PID: i32 = 4244;
/// The uid the shipped image gives the session user, and the uid an
/// agent-raised approval is routed to.
const CONSOLE_UID: u32 = 1000;

struct TestDaemon {
    dir: PathBuf,
    handle: Option<DaemonHandle>,
    mock: MockCapability,
    sockets: u32,
}

impl TestDaemon {
    /// A daemon whose registry is `security.firewall` (so the shipped AI
    /// authority map applies), with a `/proc` fixture describing both a
    /// managed-agent peer and an ordinary one.
    fn start(peer: PeerSource) -> Self {
        let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("punard-m9-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let group_file = dir.join("group");
        fs::write(&group_file, "root:x:0:\npunar:x:970:\n").unwrap();
        let passwd_file = dir.join("passwd");
        fs::write(
            &passwd_file,
            "root:x:0:0::/root:/bin/bash\npunar:x:1000:1000::/home/punar:/bin/nologin\n\
             other:x:1001:1001::/home/other:/bin/nologin\n",
        )
        .unwrap();

        // The kernel's own shape, for both peers.
        let proc_root = dir.join("proc");
        fs::create_dir_all(proc_root.join(AGENT_PID.to_string())).unwrap();
        fs::write(
            proc_root.join(AGENT_PID.to_string()).join("cgroup"),
            format!(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/\
punar-agent-{AGENT}.scope\n"
            ),
        )
        .unwrap();
        fs::create_dir_all(proc_root.join(HUMAN_PID.to_string())).unwrap();
        fs::write(
            proc_root.join(HUMAN_PID.to_string()).join("cgroup"),
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/session-1.scope\n",
        )
        .unwrap();
        fs::create_dir_all(proc_root.join(SMELLY_PID.to_string())).unwrap();
        fs::write(
            proc_root.join(SMELLY_PID.to_string()).join("cgroup"),
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/\
punar-agent-notasession.scope\n",
        )
        .unwrap();

        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let mock = MockCapability::with_default(GATED, json!("enabled"), json!("enabled"));
        let registry = Registry::new(vec![Box::new(mock.clone())]);
        let cfg = DaemonConfig {
            group_file,
            passwd_file,
            proc_root,
            peer_source: peer,
            io_timeout: Duration::from_secs(5),
            console_uid: CONSOLE_UID,
            // Not present in a tempdir: the loader falls back to the
            // compiled-in shipped document, which is the same bytes the
            // image installs.
            ai_defaults_file: dir.join("absent-ai-defaults.yaml"),
            ..DaemonConfig::new(dir.join("punard.sock"), state_dir, dir.join("audit.jsonl"))
        };
        let daemon = Daemon::new(cfg, registry).unwrap();
        daemon.boot_reconcile();
        let handle = daemon.spawn().unwrap();
        TestDaemon {
            dir,
            handle: Some(handle),
            mock,
            sockets: 0,
        }
    }

    /// Stop this daemon and start a fresh one over the **same state
    /// directory** as a different peer.
    ///
    /// This is how a test changes who is calling — and it is also the only
    /// honest way to do it: punard keeps its approval store in memory while
    /// it runs, so two live daemons over one directory would each hold half
    /// the truth. Restarting is what actually happens on the device (one
    /// daemon, many clients), and it exercises the store's reload path on
    /// every switch.
    fn restart_as(&mut self, peer: PeerSource) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
        self.sockets += 1;
        let registry = Registry::new(vec![Box::new(self.mock.clone())]);
        let cfg = DaemonConfig {
            group_file: self.dir.join("group"),
            passwd_file: self.dir.join("passwd"),
            proc_root: self.dir.join("proc"),
            peer_source: peer,
            io_timeout: Duration::from_secs(5),
            console_uid: CONSOLE_UID,
            ai_defaults_file: self.dir.join("absent-ai-defaults.yaml"),
            ..DaemonConfig::new(
                self.dir.join(format!("punard-{}.sock", self.sockets)),
                self.dir.join("state"),
                self.dir.join("audit.jsonl"),
            )
        };
        // Deliberately no `boot_reconcile()`: a restart in the middle of a
        // test must not quietly re-apply desired state and mask what the
        // test is watching.
        let daemon = Daemon::new(cfg, registry).unwrap();
        self.handle = Some(daemon.spawn().unwrap());
    }

    fn become_root(&mut self) {
        self.restart_as(PeerSource::Fixed(Peer {
            uid: 0,
            gid: 0,
            pid: Some(HUMAN_PID),
        }));
    }

    fn become_agent(&mut self) {
        self.restart_as(PeerSource::Fixed(Peer {
            uid: CONSOLE_UID,
            gid: CONSOLE_UID,
            pid: Some(AGENT_PID),
        }));
    }

    fn become_user(&mut self, uid: u32) {
        self.restart_as(PeerSource::Fixed(Peer {
            uid,
            gid: uid,
            pid: Some(HUMAN_PID),
        }));
    }

    /// Rewrite a record's `expires_at` into the past and reload, so a lapse
    /// can be tested without sleeping out a five-minute TTL. The daemon
    /// still has to *notice*, which is what is under test.
    fn expire_record_now(&mut self, approval_id: &str) {
        let path = self.record_path(approval_id);
        let mut record: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        record["approval"]["expires_at"] = json!("2020-01-01T00:00:00Z");
        fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    }

    /// The same trick for a grant.
    fn expire_grant_now(&mut self, grant_id: &str) {
        let path = self
            .dir
            .join("state/grants")
            .join(format!("{grant_id}.json"));
        let mut grant: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        grant["expires_at"] = json!("2020-01-01T00:00:00Z");
        fs::write(&path, serde_json::to_vec_pretty(&grant).unwrap()).unwrap();
    }

    /// Drop an organization AI authority document into `policy.d`, with the
    /// provenance envelope that gives it its rank. Both halves are
    /// required: a document that cannot say who wrote it and at what rank
    /// may not outrank the OS default.
    fn drop_org_ai_policy(&self, firewall: &str) {
        let policy_d = self.dir.join("state/policy.d");
        fs::create_dir_all(&policy_d).unwrap();
        fs::write(
            policy_d.join("eng-ai-v3.yaml"),
            format!("ai:\n  agents:\n    default:\n      host:\n        firewall: {firewall}\n"),
        )
        .unwrap();
        fs::write(
            policy_d.join("eng-ai-v3.json"),
            r#"{"policy_id":"eng-ai-v3","source_kind":"organization_baseline",
                "precedence_rank":2,"source_name":"Acme Engineering AI Policy"}"#,
        )
        .unwrap();
    }

    fn resolve(&self, approval_id: &str, decision: &str) -> Value {
        self.call(
            "approvals.resolve",
            Some(json!({ "approval_id": approval_id, "decision": decision })),
        )
    }

    /// A peer inside a managed agent scope. `uid` is deliberately a
    /// parameter: one test runs an agent as **root** to prove that
    /// root-ness inside an agent scope buys no bypass (SPEC section 60).
    fn as_agent(uid: u32) -> Self {
        Self::start(PeerSource::Fixed(Peer {
            uid,
            gid: uid,
            pid: Some(AGENT_PID),
        }))
    }

    fn as_root() -> Self {
        Self::start(PeerSource::Fixed(Peer {
            uid: 0,
            gid: 0,
            pid: Some(HUMAN_PID),
        }))
    }

    fn as_user(uid: u32) -> Self {
        Self::start(PeerSource::Fixed(Peer {
            uid,
            gid: uid,
            pid: Some(HUMAN_PID),
        }))
    }

    /// A peer in an agent-*shaped* scope that names no valid session id (see
    /// [`SMELLY_PID`]). `uid` is a parameter for the same reason `as_agent`
    /// takes one: the rule must not depend on it.
    fn as_agent_shaped(uid: u32) -> Self {
        Self::start(PeerSource::Fixed(Peer {
            uid,
            gid: uid,
            pid: Some(SMELLY_PID),
        }))
    }

    /// The recorded rank-5 user preference for `capability`, if punard wrote
    /// one. The gate's strongest claim lives in this file rather than in the
    /// backend: a preference recorded for a *pending* mutation would become
    /// effective at the next reconcile pass, long after the human said
    /// nothing.
    fn preference(&self, capability: &str) -> Option<Value> {
        let text = fs::read_to_string(self.dir.join("state/preferences.json")).ok()?;
        let doc: Value = serde_json::from_str(&text).ok()?;
        doc.get("preferences")?.get(capability).cloned()
    }

    fn call(&self, method: &str, params: Option<Value>) -> Value {
        let mut req = json!({ "v": 1, "id": "t-1", "method": method });
        if let Some(p) = params {
            req["params"] = p;
        }
        let mut stream = UnixStream::connect(self.handle.as_ref().unwrap().socket_path()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .write_all(format!("{req}\n").as_bytes())
            .expect("request written");
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn set(&self, state: &str) -> Value {
        self.call(
            "capabilities.set",
            Some(json!({ "capability": GATED, "desired_state": state })),
        )
    }

    /// Every audit event, oldest first.
    fn audit(&self) -> Vec<Value> {
        let text = fs::read_to_string(self.dir.join("audit.jsonl")).unwrap_or_default();
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn events(&self, action: &str) -> Vec<Value> {
        self.audit()
            .into_iter()
            .filter(|e| e["action"] == action)
            .collect()
    }

    fn summary(&self) -> Value {
        let text = fs::read_to_string(self.dir.join("state/approvals.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn record_path(&self, approval_id: &str) -> PathBuf {
        self.dir
            .join("state/approvals")
            .join(format!("{approval_id}.json"))
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

/// Every audit event must be schema-shaped; M9 adds actions, not fields.
fn assert_schema_shaped(event: &Value) {
    for field in [
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
    ] {
        assert!(
            event.get(field).is_some(),
            "audit event is missing {field}: {event}"
        );
    }
    assert_eq!(
        event.as_object().unwrap().len(),
        12,
        "audit-event.json is closed at 12 fields and M9 does not extend it: {event}"
    );
    assert!(event["event_id"].as_str().unwrap().starts_with("evt_"));
    assert!(
        ["allow", "deny", "approval_required"].contains(&event["decision"].as_str().unwrap()),
        "decision must be a section 20 value: {event}"
    );
}

/// The `.approval` member must validate against `schemas/audit/approval.json`
/// as-is: nine properties, no tenth, and the shipped enums.
fn assert_is_the_schema_document(document: &Value) {
    let object = document.as_object().expect("approval is an object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "approval_id",
            "capability",
            "expires_at",
            "reason",
            "requester",
            "resource",
            "risk",
            "status",
            "user"
        ],
        "the approval document grew a field: {document}"
    );
    assert!(
        document["approval_id"]
            .as_str()
            .unwrap()
            .starts_with("apr_")
    );
    assert!(
        ["pending", "approved", "denied", "expired"]
            .contains(&document["status"].as_str().unwrap()),
        "status left the shipped enum: {document}"
    );
    assert!(["low", "medium", "high"].contains(&document["risk"].as_str().unwrap()));
    let requester = document["requester"].as_object().unwrap();
    assert_eq!(requester.len(), 2);
    assert!(requester.contains_key("type") && requester.contains_key("id"));
    // Consumption and execution are siblings of the envelope, never a fifth
    // status value and never inside the document.
    assert!(!object.contains_key("consumed_at"));
    assert!(!object.contains_key("execution"));
}

// ---------------------------------------------------------------------------
// Attribution-driven gating
// ---------------------------------------------------------------------------

/// The same call, from two peers, gets two different answers — which is the
/// whole of SPEC sections 20 and 28. Root's call is not gated.
#[test]
fn a_human_root_call_is_not_gated() {
    let daemon = TestDaemon::as_root();
    let response = daemon.set("disabled");
    assert!(
        response.get("result").is_some(),
        "root's own call must not be gated: {response}"
    );
    assert_eq!(daemon.mock.state(), json!("disabled"));
    assert!(
        daemon.events("approval.create").is_empty(),
        "no approval should exist for a human's root call"
    );
}

/// The identical call from inside a managed agent scope is gated: an
/// approval is raised, `approval_required` comes back, and **nothing is
/// applied**. This is Law 1 — a gate, not a notification.
#[test]
fn an_agent_call_is_gated_and_nothing_executes() {
    let daemon = TestDaemon::as_agent(CONSOLE_UID);
    let response = daemon.set("disabled");
    let error = &response["error"];
    assert_eq!(error["code"], "approval_required");
    let details = &error["details"];
    let approval_id = details["approval_id"].as_str().unwrap();
    assert!(approval_id.starts_with("apr_"));
    assert_eq!(details["capability"], GATED);
    assert_eq!(details["resource"], "disabled");
    assert_eq!(details["decision"], "approval_required");
    assert_eq!(details["policy_ids"], json!(["personal-defaults"]));
    assert!(details["expires_at"].as_str().unwrap().ends_with('Z'));

    // The capability did not move, and the preference was not recorded
    // either: a gated call is refused before the pipeline, not rolled back
    // after it.
    assert_eq!(daemon.mock.state(), json!("enabled"));
    assert_eq!(daemon.mock.apply_calls(), 0);
    // The load-bearing half of that sentence, asserted rather than assumed.
    // `apply_calls == 0` only says nothing ran *now*; a rank-5 preference
    // written for a pending mutation would be picked up by the next
    // reconcile pass and applied later, with no human in the loop at all —
    // a gate that leaks through the clock. There must be no entry.
    assert_eq!(
        daemon.preference(GATED),
        None,
        "a pending mutation must not leave a user preference behind"
    );

    // The trail names the request twice, under two indexes: by capability
    // (what an incident review greps for) and by approval id (the
    // lifecycle). Both carry the agent's kernel-attested identity.
    let gated = daemon.events("capabilities.set");
    let gated = gated.last().unwrap();
    assert_eq!(gated["decision"], "approval_required");
    assert_eq!(gated["resource"], GATED);
    assert_eq!(gated["source"], "ai_agent");
    assert_eq!(gated["agent_session_id"], AGENT);
    let created = daemon.events("approval.create");
    assert_eq!(created.len(), 1);
    assert_eq!(created[0]["resource"], approval_id);
    assert_eq!(created[0]["decision"], "approval_required");
    assert_eq!(created[0]["agent_session_id"], AGENT);
    for event in daemon.audit() {
        assert_schema_shaped(&event);
    }
}

/// **Root-ness inside an agent scope buys no bypass** (SPEC section 60: no
/// bypassing AI policy enforcement). The AI path is evaluated before the uid
/// test, on purpose, and this is the test that pins the order.
#[test]
fn an_agent_running_as_root_is_still_gated() {
    let daemon = TestDaemon::as_agent(0);
    let response = daemon.set("disabled");
    assert_eq!(
        response["error"]["code"], "approval_required",
        "an agent scope is evaluated as an agent whatever its uid: {response}"
    );
    assert_eq!(daemon.mock.state(), json!("enabled"));
}

/// A capability AI policy does not name is denied, not allowed. "Punar does
/// not guess."
#[test]
fn an_unmapped_capability_fails_closed_for_an_agent() {
    let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("punard-m9-unmapped-{}-{seq}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("group"), "root:x:0:\npunar:x:970:\n").unwrap();
    fs::write(
        dir.join("passwd"),
        "root:x:0:0::/root:/bin/bash\npunar:x:1000:1000::/home/punar:/bin/nologin\n",
    )
    .unwrap();
    let proc_root = dir.join("proc");
    fs::create_dir_all(proc_root.join(AGENT_PID.to_string())).unwrap();
    fs::write(
        proc_root.join(AGENT_PID.to_string()).join("cgroup"),
        format!("0::/user.slice/punar-agent-{AGENT}.scope\n"),
    )
    .unwrap();
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir).unwrap();
    // `mock.widget` is in no AI authority document and maps to no section 20
    // token — exactly the "policy is silent" case.
    let mock = MockCapability::new("mock.widget", json!("off"));
    let cfg = DaemonConfig {
        group_file: dir.join("group"),
        passwd_file: dir.join("passwd"),
        proc_root,
        peer_source: PeerSource::Fixed(Peer {
            uid: CONSOLE_UID,
            gid: CONSOLE_UID,
            pid: Some(AGENT_PID),
        }),
        io_timeout: Duration::from_secs(5),
        ai_defaults_file: dir.join("absent.yaml"),
        ..DaemonConfig::new(dir.join("punard.sock"), state_dir, dir.join("audit.jsonl"))
    };
    let daemon = Daemon::new(cfg, Registry::new(vec![Box::new(mock.clone())])).unwrap();
    daemon.boot_reconcile();
    let handle = daemon.spawn().unwrap();

    let mut stream = UnixStream::connect(handle.socket_path()).unwrap();
    stream
        .write_all(
            b"{\"v\":1,\"id\":\"t\",\"method\":\"capabilities.set\",\
              \"params\":{\"capability\":\"mock.widget\",\"desired_state\":\"on\"}}\n",
        )
        .unwrap();
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["error"]["code"], "denied");
    let message = response["error"]["message"].as_str().unwrap();
    assert!(message.contains("No AI authority rule"), "{message}");
    assert!(message.contains("does not guess"), "{message}");
    assert_eq!(mock.state(), json!("off"));

    handle.stop();
    let _ = fs::remove_dir_all(&dir);
}

/// The section 39 ladder, live in the daemon: an organization AI authority
/// document dropped into `policy.d` outranks the shipped personal defaults,
/// and the citation names the organization.
///
/// Two verdicts, one mechanism. `deny` refuses the agent outright and cites
/// the org; `allow` executes the mutation on the agent's behalf — the
/// section 20 value **no shipped M9 policy uses**, implemented rather than
/// left as a hole that would surprise the first organization to write it.
#[test]
fn an_org_ai_layer_outranks_the_personal_default_in_both_directions() {
    let mut daemon = TestDaemon::as_agent(CONSOLE_UID);
    // Personal defaults: gated.
    assert_eq!(daemon.set("disabled")["error"]["code"], "approval_required");

    // The org says deny. An AI agent is refused outright, and the message
    // cites the organization, not "personal defaults" (DESIGN_LANGUAGE
    // section 8: org citations only when an org rule actually won).
    daemon.drop_org_ai_policy("deny");
    daemon.become_agent();
    let denied = daemon.set("disabled");
    assert_eq!(denied["error"]["code"], "denied");
    let message = denied["error"]["message"].as_str().unwrap();
    assert!(message.contains("Acme Engineering AI Policy"), "{message}");
    assert!(message.contains("eng-ai-v3"), "{message}");
    assert!(message.contains("approval is not available"), "{message}");
    assert_eq!(daemon.mock.state(), json!("enabled"));
    let denial = daemon
        .events("capabilities.set")
        .into_iter()
        .find(|e| e["decision"] == "deny")
        .expect("the refusal is audited");
    assert_eq!(denial["policy_ids"], json!(["eng-ai-v3"]));
    assert_eq!(denial["source"], "ai_agent");
    assert_eq!(denial["agent_session_id"], AGENT);

    // The org says allow. The mutation runs on the agent's behalf, with no
    // approval and no human — which is exactly what `allow` means, and
    // exactly why no shipped M9 policy uses it.
    daemon.drop_org_ai_policy("allow");
    daemon.become_agent();
    let allowed = daemon.set("disabled");
    assert!(allowed.get("result").is_some(), "{allowed}");
    assert_eq!(daemon.mock.state(), json!("disabled"));
    let execution = daemon
        .events("capabilities.set")
        .into_iter()
        .find(|e| e["decision"] == "allow" && e["result"] == "success")
        .expect("the allowed mutation is audited");
    assert_eq!(execution["source"], "ai_agent");
    assert_eq!(execution["agent_session_id"], AGENT);
    // Still no approval was raised: `allow` is not a quiet approval.
    assert_eq!(daemon.events("approval.create").len(), 1);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// `pending → approved → executed`, with both halves of the pointer between
/// the approval and the audit trail asserted, and the two identities kept
/// straight: the agent did it, the human allowed it.
#[test]
fn approving_executes_the_recorded_call_exactly_once() {
    let mut daemon = TestDaemon::as_agent(CONSOLE_UID);
    let approval_id = gated_approval_id(&daemon);

    // The pending record, as the shell and the CLI see it.
    let listed = daemon.call("approvals.list", None);
    let pending = &listed["result"]["approvals"][0];
    assert_eq!(pending["approval"]["status"], "pending");
    assert_eq!(pending["kind"], "capability_set");
    assert_eq!(pending["contract"], "SetFirewall(disabled)");
    assert_eq!(pending["policy"]["policy_id"], "personal-defaults");
    assert!(pending["execution"].is_null());
    assert_is_the_schema_document(&pending["approval"]);

    // A human answers it. The daemon decides who that is from the peer's
    // cgroup, not from a flag.
    daemon.become_root();
    let resolved = daemon.resolve(&approval_id, "approved");
    let envelope = &resolved["result"];
    assert_eq!(envelope["approval"]["status"], "approved");
    assert_eq!(envelope["execution"]["result"], "success");
    assert_eq!(envelope["execution"]["changed"], true);
    assert_eq!(envelope["resolved_by"]["uid"], 0);
    assert_eq!(envelope["resolved_by"]["user"], "root");
    assert!(envelope["resolved_at"].as_str().unwrap().ends_with('Z'));
    assert_is_the_schema_document(&envelope["approval"]);

    // The capability actually moved — this is what makes it a gate and not
    // a notification. The preference appears at the same moment and not
    // before: the state that survives a reboot is written by the *approval*,
    // which is the other half of the pending-state assertion in
    // `an_agent_call_is_gated_and_nothing_executes`.
    assert_eq!(daemon.mock.state(), json!("disabled"));
    assert_eq!(daemon.mock.apply_calls(), 1);
    assert_eq!(
        daemon.preference(GATED).map(|p| p["value"].clone()),
        Some(json!("disabled")),
        "an answered approval records the preference the human authorized"
    );

    // Pointer direction 1: the approval names the audit event.
    let audit_event_id = envelope["execution"]["audit_event_id"].as_str().unwrap();
    let execution_event = daemon
        .events("capabilities.set")
        .into_iter()
        .find(|e| e["event_id"] == audit_event_id)
        .expect("the approval's audit_event_id names a real event");
    // SPEC section 22: the execution is attributed to the AGENT.
    assert_eq!(execution_event["source"], "ai_agent");
    assert_eq!(execution_event["agent_session_id"], AGENT);
    assert_eq!(execution_event["decision"], "allow");
    assert_eq!(execution_event["result"], "success");
    assert!(
        execution_event["policy_ids"]
            .as_array()
            .unwrap()
            .contains(&json!(approval_id)),
        "the execution event cites the approval that authorized it"
    );

    // Pointer direction 2: the trail names the approval, attributed to the
    // HUMAN who allowed it.
    let resolve_events = daemon.events("approval.resolve");
    assert_eq!(resolve_events.len(), 1);
    assert_eq!(resolve_events[0]["resource"], approval_id);
    assert_eq!(resolve_events[0]["decision"], "allow");
    assert_eq!(resolve_events[0]["result"], "approved");
    assert_eq!(resolve_events[0]["source"], "human");
    assert_eq!(resolve_events[0]["agent_session_id"], "agt_none");
    for event in daemon.audit() {
        assert_schema_shaped(&event);
    }

    // Terminal means terminal: a second resolve conflicts and nothing runs
    // a second time.
    let again = daemon.resolve(&approval_id, "approved");
    assert_eq!(again["error"]["code"], "conflict");
    assert_eq!(again["error"]["details"]["state"], "approved");
    assert_eq!(daemon.mock.apply_calls(), 1, "exactly once");
}

/// `pending → denied`: the capability never moves, and the record says who
/// said no.
#[test]
fn denying_records_the_verdict_and_executes_nothing() {
    let mut daemon = TestDaemon::as_agent(CONSOLE_UID);
    let approval_id = gated_approval_id(&daemon);

    daemon.become_root();
    let resolved = daemon.resolve(&approval_id, "denied");
    assert_eq!(resolved["result"]["approval"]["status"], "denied");
    assert!(resolved["result"]["execution"].is_null());
    assert_eq!(daemon.mock.state(), json!("enabled"));
    assert_eq!(daemon.mock.apply_calls(), 0);

    let events = daemon.events("approval.resolve");
    assert_eq!(events[0]["decision"], "deny");
    assert_eq!(events[0]["result"], "denied");
    assert_eq!(events[0]["resource"], approval_id);

    // A denied approval is terminal too: it cannot be talked into a yes.
    let flipped = daemon.resolve(&approval_id, "approved");
    assert_eq!(flipped["error"]["code"], "conflict");
    assert_eq!(daemon.mock.apply_calls(), 0);
    assert_eq!(
        daemon.preference(GATED),
        None,
        "a no leaves no preference for a later reconcile to find"
    );
}

/// `pending → expired`, never executed. The lapse is audited once, the
/// error is `expired` (not `conflict` — "you were too late" and "someone
/// already answered" are different facts), and pressing Approve afterwards
/// does nothing.
#[test]
fn an_expired_approval_can_never_be_executed() {
    let mut daemon = TestDaemon::as_agent(CONSOLE_UID);
    let approval_id = gated_approval_id(&daemon);

    daemon.expire_record_now(&approval_id);
    daemon.become_root();

    // A read sweeps it. There is no timer anywhere (SPEC section 6.3).
    let listed = daemon.call("approvals.list", None);
    let swept = &listed["result"]["approvals"][0];
    assert_eq!(swept["approval"]["status"], "expired");
    assert!(swept["execution"].is_null());

    let expiries = daemon.events("approval.expire");
    assert_eq!(expiries.len(), 1, "one event per lapse, not one per read");
    assert_eq!(expiries[0]["resource"], approval_id);
    assert_eq!(expiries[0]["decision"], "deny");
    assert_eq!(expiries[0]["result"], "expired");
    assert_eq!(
        expiries[0]["source"], "service",
        "nobody did this; time passed"
    );

    // Pressing Approve on a lapsed card gets `expired`, and nothing runs.
    let late = daemon.resolve(&approval_id, "approved");
    assert_eq!(late["error"]["code"], "expired");
    assert_eq!(daemon.mock.state(), json!("enabled"));
    assert_eq!(daemon.mock.apply_calls(), 0);
    assert_eq!(
        daemon.preference(GATED),
        None,
        "a lapsed approval leaves no preference for a later reconcile to find"
    );

    // A second read does not re-audit the same lapse.
    daemon.call("approvals.list", None);
    assert_eq!(daemon.events("approval.expire").len(), 1);
}

/// **An agent may not author the card a human reads.** `approvals.create`
/// is root-only, and root-ness inside an agent scope is not the same thing
/// as being root: everything on this call is requester-authored — the
/// `requester` block, the `reason`, the `contract` line, the `user` it is
/// routed to — and those strings *are* the D-003 overlay. An agent that
/// reached a root-privileged call inside its own scope (a person running
/// `sudo punarctl` there is the ordinary way) must not be able to write a
/// consent dialog that says a *person* asked.
#[test]
fn an_ai_agent_cannot_author_an_approval_even_as_root() {
    for uid in [CONSOLE_UID, 0] {
        let daemon = TestDaemon::as_agent(uid);
        let response = daemon.call(
            "approvals.create",
            Some(json!({
                "kind": "privilege_request",
                "capability": GATED,
                "resource": "60m",
                // The forgery this rule exists to refuse.
                "reason": "the owner asked me to prepare the firewall",
                "risk": "high",
                "user": "punar",
                "requester": { "type": "human", "id": "punar" },
            })),
        );
        assert_eq!(response["error"]["code"], "denied", "uid {uid}: {response}");
        assert_eq!(
            response["error"]["details"]["result"], "agent_create_refused",
            "uid {uid}: an agent-scoped peer must be refused as an agent, not merely \
             told to become root"
        );

        // Nothing was recorded as pending, so nothing can be answered.
        assert!(
            daemon.call("approvals.list", None)["result"]["approvals"]
                .as_array()
                .unwrap()
                .is_empty(),
            "uid {uid}: a refused authorship must leave no card behind"
        );
        let refusals = daemon.events("approval.create");
        assert_eq!(refusals.len(), 1, "uid {uid}");
        assert_eq!(refusals[0]["decision"], "deny");
        assert_eq!(refusals[0]["result"], "agent_create_refused");
        assert_eq!(refusals[0]["source"], "ai_agent");
        assert_eq!(refusals[0]["agent_session_id"], AGENT);
        assert_schema_shaped(&refusals[0]);
    }
}

/// The same three methods, against a peer whose cgroup *names* an agent
/// scope it cannot spell (`punar-agent-notasession.scope`). Attribution
/// refuses to name such a session — deliberately, because a false name in
/// the trail is worse than none — so a method that tested `agent_session_id`
/// alone would wave this peer through as a human. Contract section 14.5
/// makes all three use the wide test instead, and this pins it.
#[test]
fn an_agent_shaped_peer_is_refused_by_every_consent_authoring_method() {
    let daemon = TestDaemon::as_agent_shaped(CONSOLE_UID);

    // 1. It may not ask for a privilege window that a human's yes would turn
    //    into a grant.
    let response = daemon.call(
        "privilege.request",
        Some(json!({ "capability": GATED, "reason": "fifteen minutes please" })),
    );
    assert_eq!(response["error"]["code"], "denied", "{response}");
    assert_eq!(
        response["error"]["details"]["result"],
        "agent_privilege_refused"
    );
    // Unattributed, so the trail cannot name a session — and does not invent
    // one. The refusal is still recorded.
    let refusals = daemon.events("privilege.request");
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0]["result"], "agent_privilege_refused");
    assert_eq!(refusals[0]["agent_session_id"], "agt_none");
    assert!(
        response["error"]["details"]
            .get("agent_session_id")
            .is_none(),
        "an unattributed peer must not be given a session id it does not have"
    );

    // 2. It may not author an approval.
    let response = daemon.call(
        "approvals.create",
        Some(json!({
            "kind": "capability_set",
            "capability": GATED,
            "resource": "disabled",
            "reason": "routine maintenance",
            "risk": "high",
            "user": "punar",
            "requester": { "type": "human", "id": "punar" },
        })),
    );
    assert_eq!(response["error"]["code"], "denied", "{response}");
    assert_eq!(
        response["error"]["details"]["result"],
        "agent_create_refused"
    );

    // 3. And it may not answer one. (Nothing is pending; the point is that
    //    the refusal is the agent refusal, not `not_found` — rule 1 is
    //    checked before the store is even consulted.)
    let response = daemon.resolve("apr_00000001", "approved");
    assert_eq!(response["error"]["code"], "denied", "{response}");
    assert_eq!(
        response["error"]["details"]["result"],
        "self_approval_refused"
    );

    // Nothing pending, no grant, nothing applied.
    assert!(
        daemon.call("approvals.list", None)["result"]["approvals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        daemon.call("privilege.status", None)["result"]["grants"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(daemon.mock.apply_calls(), 0);
}

/// `approvals.create` is root-only: a process that could mint approvals
/// could flood the human until they stop reading them.
#[test]
fn an_unprivileged_peer_cannot_mint_approvals() {
    let daemon = TestDaemon::as_user(CONSOLE_UID);
    let response = daemon.call(
        "approvals.create",
        Some(json!({
            "kind": "credential_request",
            "capability": "credential.request",
            "resource": "aws-dev",
            "reason": "please",
            "risk": "low",
            "user": "punar",
            "requester": { "type": "human", "id": "punar" },
        })),
    );
    assert_eq!(response["error"]["code"], "denied");
    assert!(
        daemon.call("approvals.list", None)["result"]["approvals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Law 2: an AI agent may approve nothing, ever
// ---------------------------------------------------------------------------

/// **The headline safety test.** An agent raises an approval and then tries
/// to answer it. The refusal is by architecture, it is audited with the
/// agent's own identity, the approval stays pending, and the capability
/// never moves.
#[test]
fn an_ai_agent_cannot_approve_its_own_request() {
    let agent = TestDaemon::as_agent(CONSOLE_UID);
    let approval_id = gated_approval_id(&agent);

    let response = agent.call(
        "approvals.resolve",
        Some(json!({ "approval_id": approval_id, "decision": "approved" })),
    );
    assert_eq!(response["error"]["code"], "denied");
    let message = response["error"]["message"].as_str().unwrap();
    assert!(message.contains("AI agent"), "{message}");
    assert!(message.contains("cannot approve"), "{message}");

    // Still pending. Still enabled. Nothing ran.
    let got = agent.call("approvals.get", Some(json!({ "approval_id": approval_id })));
    assert_eq!(got["result"]["approval"]["status"], "pending");
    assert!(got["result"]["execution"].is_null());
    assert_eq!(agent.mock.state(), json!("enabled"));
    assert_eq!(agent.mock.apply_calls(), 0);

    // The refusal is in the trail, with the agent's kernel-attested id —
    // which is what makes it a Level-4 `policy_bypass_attempt` for the M8
    // ledger.
    let refusals = agent.events("approval.resolve");
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0]["decision"], "deny");
    assert_eq!(refusals[0]["result"], "self_approval_refused");
    assert_eq!(refusals[0]["source"], "ai_agent");
    assert_eq!(refusals[0]["agent_session_id"], AGENT);
    assert_eq!(refusals[0]["resource"], approval_id);
    assert_schema_shaped(&refusals[0]);
}

/// An agent may not resolve a **human's** request either. Law 2 is about
/// the resolver, not about the requester: an agent that could answer a
/// person's approval could suppress it, or grant it.
#[test]
fn an_ai_agent_cannot_approve_a_humans_request() {
    let mut daemon = TestDaemon::as_root();
    let created = daemon.call(
        "approvals.create",
        Some(json!({
            "kind": "credential_request",
            "capability": "credential.request",
            "resource": "aws-dev",
            "reason": "a person asked for this",
            "risk": "medium",
            "user": "punar",
            "requester": { "type": "human", "id": "punar" },
        })),
    );
    let approval_id = created["result"]["approval"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    daemon.become_agent();
    for decision in ["approved", "denied"] {
        let response = daemon.resolve(&approval_id, decision);
        assert_eq!(response["error"]["code"], "denied", "{decision}");
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("AI agent")
        );
    }
    let got = daemon.call("approvals.get", Some(json!({ "approval_id": approval_id })));
    assert_eq!(got["result"]["approval"]["status"], "pending");
    let refusals = daemon.events("approval.resolve");
    assert_eq!(refusals.len(), 2);
    for refusal in refusals {
        assert_eq!(refusal["result"], "self_approval_refused");
        assert_eq!(refusal["source"], "ai_agent");
    }
}

/// Approvals are routed to a person. A different unprivileged user may read
/// one and may not decide it — socket access is not consent.
#[test]
fn an_approval_is_answered_only_by_the_user_it_is_routed_to() {
    let mut daemon = TestDaemon::as_root();
    let created = daemon.call(
        "approvals.create",
        Some(json!({
            "kind": "credential_request",
            "capability": "credential.request",
            "resource": "aws-dev",
            "reason": "routed to punar",
            "risk": "medium",
            "user": "punar",
            "requester": { "type": "ai_agent", "id": AGENT },
        })),
    );
    let approval_id = created["result"]["approval"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // uid 1001 is "other" in the passwd fixture: an ordinary user who is
    // not the routed one.
    daemon.become_user(1001);
    let refused = daemon.resolve(&approval_id, "approved");
    assert_eq!(refused["error"]["code"], "denied");
    let message = refused["error"]["message"].as_str().unwrap();
    assert!(message.contains("punar"), "{message}");
    assert!(message.contains("not other"), "{message}");
    // Reading it is still fine — a gate is not a secret.
    let got = daemon.call("approvals.get", Some(json!({ "approval_id": approval_id })));
    assert_eq!(got["result"]["approval"]["status"], "pending");

    // The routed user may answer it.
    daemon.become_user(CONSOLE_UID);
    let resolved = daemon.resolve(&approval_id, "approved");
    assert_eq!(resolved["result"]["approval"]["status"], "approved");
    assert_eq!(resolved["result"]["resolved_by"]["user"], "punar");
}

/// The M3 denial has promised just-in-time elevation "in Milestone 9" since
/// M3. It now names a command that exists.
#[test]
fn the_root_only_denial_points_at_a_command_that_exists() {
    let daemon = TestDaemon::as_user(CONSOLE_UID);
    let denied = daemon.set("disabled");
    assert_eq!(denied["error"]["code"], "denied");
    let message = denied["error"]["message"].as_str().unwrap();
    assert!(message.contains("administrator"), "{message}");
    assert!(message.contains("personal defaults"), "{message}");
    assert!(
        message.contains("punarctl privilege request --capability security.firewall"),
        "{message}"
    );
    assert!(!message.contains("Milestone 9"), "{message}");
}

// ---------------------------------------------------------------------------
// approvals.create / consume
// ---------------------------------------------------------------------------

/// `approvals.create` is root-only and `approvals.consume` spends a
/// credential approval exactly once — the two methods `punar-secrets` uses.
#[test]
fn a_credential_approval_is_created_by_root_and_spent_once() {
    let root = TestDaemon::as_root();
    let created = root.call(
        "approvals.create",
        Some(json!({
            "kind": "credential_request",
            "capability": "credential.request",
            "resource": "aws-dev",
            "reason": "Atlas deploy needs the dev account",
            "risk": "medium",
            "user": "punar",
            "requester": { "type": "ai_agent", "id": AGENT },
        })),
    );
    let envelope = &created["result"];
    let approval_id = envelope["approval"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(envelope["kind"], "credential_request");
    assert_eq!(envelope["contract"], "RequestCredential(aws-dev)");
    // The class name and nothing else: no token, no id, no hash (SPEC 53).
    assert_eq!(envelope["approval"]["resource"], "aws-dev");
    assert_is_the_schema_document(&envelope["approval"]);

    // Consuming before approval is a conflict, not a silent success.
    let early = root.call(
        "approvals.consume",
        Some(json!({ "approval_id": approval_id })),
    );
    assert_eq!(early["error"]["code"], "conflict");
    assert_eq!(early["error"]["details"]["state"], "pending");

    // Approving a credential approval executes NOTHING in punard: the
    // broker spends it later. A plaintext token must never enter the daemon
    // that writes /etc.
    let resolved = root.resolve(&approval_id, "approved");
    assert_eq!(resolved["result"]["approval"]["status"], "approved");
    assert!(resolved["result"]["execution"].is_null());

    let consumed = root.call(
        "approvals.consume",
        Some(json!({ "approval_id": approval_id })),
    );
    let consumed_at = consumed["result"]["consumed_at"].as_str().unwrap();
    assert!(consumed_at.ends_with('Z'));
    // Consumption is a sibling field, not a fifth status value.
    assert_eq!(
        consumed["result"]["approval"]["approval"]["status"],
        "approved"
    );
    assert_eq!(consumed["result"]["approval"]["consumed_at"], consumed_at);
    assert_is_the_schema_document(&consumed["result"]["approval"]["approval"]);

    // Single use. A second credential needs a second decision.
    let twice = root.call(
        "approvals.consume",
        Some(json!({ "approval_id": approval_id })),
    );
    assert_eq!(twice["error"]["code"], "conflict");
    assert_eq!(twice["error"]["details"]["state"], "consumed");

    let events = root.events("approval.consume");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["resource"], approval_id);
    assert_eq!(events[0]["result"], "consumed");
}

/// An approved credential approval **still expires**: a human's yes is not a
/// standing grant.
#[test]
fn an_approved_credential_approval_still_expires() {
    let mut root = TestDaemon::as_root();
    let created = root.call(
        "approvals.create",
        Some(json!({
            "kind": "credential_request",
            "capability": "credential.request",
            "resource": "aws-dev",
            "reason": "Atlas deploy needs the dev account",
            "risk": "medium",
            "user": "punar",
            "requester": { "type": "ai_agent", "id": AGENT },
        })),
    );
    let approval_id = created["result"]["approval"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();
    root.resolve(&approval_id, "approved");
    root.expire_record_now(&approval_id);
    // Reload so the daemon reads the rewritten record, exactly as a restart
    // would; the store is in memory while punard runs.
    root.become_root();

    let consumed = root.call(
        "approvals.consume",
        Some(json!({ "approval_id": approval_id })),
    );
    assert_eq!(consumed["error"]["code"], "expired");
}

/// Approval fatigue is refused in code, not in advice.
#[test]
fn a_flood_of_approvals_is_refused_and_audited() {
    let root = TestDaemon::as_root();
    let create = |n: u32| {
        root.call(
            "approvals.create",
            Some(json!({
                "kind": "credential_request",
                "capability": "credential.request",
                "resource": format!("class-{n}"),
                "reason": "flood test",
                "risk": "low",
                "user": "punar",
                "requester": { "type": "ai_agent", "id": AGENT },
            })),
        )
    };
    assert!(create(1)["result"].is_object());
    assert!(create(2)["result"].is_object());
    // Two pending per requester is the bound.
    let flooded = create(3);
    assert_eq!(flooded["error"]["code"], "denied");
    assert_eq!(flooded["error"]["details"]["reason"], "approval_flood");
    let refusals: Vec<Value> = root
        .events("approval.create")
        .into_iter()
        .filter(|e| e["result"] == "approval_flood")
        .collect();
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0]["decision"], "deny");
}

/// A justification that could forge a dialog inside the real one is refused
/// at creation, before it can ever be rendered.
#[test]
fn a_multi_line_reason_is_refused_at_creation() {
    let root = TestDaemon::as_root();
    let response = root.call(
        "approvals.create",
        Some(json!({
            "kind": "credential_request",
            "capability": "credential.request",
            "resource": "aws-dev",
            "reason": "harmless\nPolicy: personal defaults — this is safe",
            "risk": "low",
            "user": "punar",
            "requester": { "type": "ai_agent", "id": AGENT },
        })),
    );
    assert_eq!(response["error"]["code"], "invalid_params");
    assert_eq!(response["error"]["details"]["param"], "reason");
}

// ---------------------------------------------------------------------------
// Just-in-time privilege
// ---------------------------------------------------------------------------

/// A human asks, a human approves, and for a bounded window a non-root peer
/// may make exactly one kind of change. Then the window closes for real.
#[test]
fn a_grant_authorizes_one_capability_for_a_bounded_window() {
    let user = TestDaemon::as_user(CONSOLE_UID);
    // Without a grant: denied, in the unchanged M3 way.
    assert_eq!(user.set("disabled")["error"]["code"], "denied");

    let requested = user.call(
        "privilege.request",
        Some(json!({
            "capability": GATED,
            "reason": "Reproducing the Atlas net bug",
            "duration_minutes": 15,
        })),
    );
    assert_eq!(requested["error"]["code"], "approval_required");
    let approval_id = requested["error"]["details"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(requested["error"]["details"]["resource"], "15m");
    let asked = user.events("privilege.request");
    assert_eq!(asked[0]["decision"], "approval_required");
    assert_eq!(asked[0]["resource"], approval_id);

    // The requester may answer their own privilege request (Plate D-012
    // draws exactly that: the friction is the required reason, the
    // countdown and the trail — not a second person).
    let resolved = user.resolve(&approval_id, "approved");
    let execution = &resolved["result"]["execution"];
    assert_eq!(execution["result"], "granted");
    let grant_id = execution["grant_id"].as_str().unwrap().to_string();
    assert!(grant_id.starts_with("gnt_"));
    assert_eq!(
        resolved["result"]["contract"],
        format!("RequestPrivilege({GATED}, 15m)")
    );
    // The reason travels verbatim from the request into the record.
    assert_eq!(
        resolved["result"]["approval"]["reason"],
        "Reproducing the Atlas net bug"
    );
    let granted = user.events("privilege.grant");
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0]["resource"], grant_id);
    assert_eq!(granted[0]["decision"], "allow");

    // The same non-root call now succeeds, and the trail cites the grant as
    // the authority that permitted it (a section 39 Temporary Approved
    // Exception — no `details` field was added to the audit schema).
    let allowed = user.set("disabled");
    assert!(allowed.get("result").is_some(), "{allowed}");
    assert_eq!(user.mock.state(), json!("disabled"));
    let execution_event = user
        .events("capabilities.set")
        .into_iter()
        .find(|e| e["decision"] == "allow" && e["result"] == "success")
        .expect("the grant-authorized mutation is audited");
    assert!(
        execution_event["policy_ids"]
            .as_array()
            .unwrap()
            .contains(&json!(grant_id))
    );
    // ...and it is attributed to the human, not to any agent.
    assert_eq!(execution_event["source"], "human");
    assert_eq!(execution_event["agent_session_id"], "agt_none");

    // Privilege is visible for exactly as long as it exists.
    let status = user.call("privilege.status", None);
    assert_eq!(status["result"]["grants"][0]["grant_id"], grant_id);
    assert_eq!(status["result"]["grants"][0]["capability"], GATED);
    assert_eq!(
        user.summary()["grants"][0]["grant_id"],
        json!(grant_id),
        "the bar chip reads the same file the overlay does"
    );

    // Handing it back early works, is audited, and ends the privilege.
    let revoked = user.call("privilege.revoke", Some(json!({ "grant_id": grant_id })));
    assert_eq!(revoked["result"]["revoked"], json!([grant_id]));
    assert_eq!(user.events("privilege.revoke").len(), 1);
    assert!(
        user.summary()["grants"].as_array().unwrap().is_empty(),
        "a revoked grant leaves the bar chip immediately"
    );
    let after = user.set("enabled");
    assert_eq!(
        after["error"]["code"], "denied",
        "privilege ends when it is handed back"
    );
}

/// A grant names one capability. There is no wildcard, and no "close
/// enough".
#[test]
fn a_grant_does_not_leak_to_another_capability() {
    let user = TestDaemon::as_user(CONSOLE_UID);
    let requested = user.call(
        "privilege.request",
        Some(json!({ "capability": GATED, "reason": "narrow grant test" })),
    );
    let approval_id = requested["error"]["details"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();
    user.resolve(&approval_id, "approved");
    // Another capability is not in the registry of this test daemon, so the
    // strongest available assertion is that the grant is recorded against
    // exactly one id and the store matches on it exactly.
    let status = user.call("privilege.status", None);
    assert_eq!(status["result"]["grants"].as_array().unwrap().len(), 1);
    assert_eq!(status["result"]["grants"][0]["capability"], GATED);
}

/// A lapsed grant authorizes nothing, is unlinked, and is audited once.
/// "Fifteen minutes" is a promise the daemon keeps, not a label.
#[test]
fn a_grant_expires_for_real() {
    let mut user = TestDaemon::as_user(CONSOLE_UID);
    let requested = user.call(
        "privilege.request",
        Some(json!({
            "capability": GATED,
            "reason": "expiry test",
            "duration_minutes": 1,
        })),
    );
    let approval_id = requested["error"]["details"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();
    let resolved = user.resolve(&approval_id, "approved");
    let grant_id = resolved["result"]["execution"]["grant_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(user.set("disabled").get("result").is_some());

    // Push the window into the past, the way a minute of wall clock would.
    user.expire_grant_now(&grant_id);
    user.become_user(CONSOLE_UID);

    let status = user.call("privilege.status", None);
    assert!(
        status["result"]["grants"].as_array().unwrap().is_empty(),
        "a lapsed grant is not live: {status}"
    );
    let expiries = user.events("privilege.expire");
    assert_eq!(expiries.len(), 1);
    assert_eq!(expiries[0]["resource"], grant_id);
    assert_eq!(expiries[0]["result"], "expired");
    assert!(
        !user
            .dir
            .join("state/grants")
            .join(format!("{grant_id}.json"))
            .exists(),
        "a lapsed grant is unlinked, not tombstoned"
    );

    // And the privilege it carried is gone.
    assert_eq!(user.set("enabled")["error"]["code"], "denied");
    // The lapse is audited once, however many times anyone looks.
    user.call("privilege.status", None);
    assert_eq!(user.events("privilege.expire").len(), 1);
}

/// **A grant is never issued to an AI agent** (SPEC sections 48, 60). Agents
/// get per-request approvals; they never get a time window.
#[test]
fn an_ai_agent_is_refused_a_privilege_grant() {
    let agent = TestDaemon::as_agent(CONSOLE_UID);
    let response = agent.call(
        "privilege.request",
        Some(json!({ "capability": GATED, "reason": "let me have fifteen minutes" })),
    );
    assert_eq!(response["error"]["code"], "denied");
    assert_eq!(
        response["error"]["details"]["result"],
        "agent_privilege_refused"
    );
    let message = response["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("cannot hold elevated privilege"),
        "{message}"
    );

    let events = agent.events("privilege.request");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["decision"], "deny");
    assert_eq!(events[0]["result"], "agent_privilege_refused");
    assert_eq!(events[0]["source"], "ai_agent");
    assert_eq!(events[0]["agent_session_id"], AGENT);

    // No grant, and no approval to answer either.
    let status = agent.call("privilege.status", None);
    assert!(status["result"]["grants"].as_array().unwrap().is_empty());
}

/// A privilege request with no justification is a params error, not a
/// default (Plate D-012: the reason travels verbatim into the audit event).
#[test]
fn a_privilege_request_without_a_reason_is_refused() {
    let user = TestDaemon::as_user(CONSOLE_UID);
    let response = user.call(
        "privilege.request",
        Some(json!({ "capability": GATED, "reason": "   " })),
    );
    assert_eq!(response["error"]["code"], "invalid_params");
    assert_eq!(response["error"]["details"]["param"], "reason");
}

/// `privilege.revoke` must be told what to revoke.
#[test]
fn revoking_nothing_in_particular_is_a_params_error() {
    let user = TestDaemon::as_user(CONSOLE_UID);
    assert_eq!(
        user.call("privilege.revoke", Some(json!({})))["error"]["code"],
        "invalid_params"
    );
    assert_eq!(
        user.call(
            "privilege.revoke",
            Some(json!({ "grant_id": "gnt_1", "all": true })),
        )["error"]["code"],
        "invalid_params"
    );
}

// ---------------------------------------------------------------------------
// The methods that do not exist
// ---------------------------------------------------------------------------

/// A grant is only ever produced by resolving an approval. There is no path
/// that mints privilege without a recorded human decision, and no shortcut
/// verb that answers an approval on someone's behalf.
#[test]
fn there_is_no_shortcut_to_privilege_or_to_a_verdict() {
    let root = TestDaemon::as_root();
    for method in [
        "approvals.approve",
        "approvals.deny",
        "approvals.delete",
        "privilege.grant",
        "privilege.extend",
        "credential.show",
        "secrets.dump",
        "system.exec",
        "shell.run",
    ] {
        let response = root.call(method, Some(json!({})));
        assert_eq!(
            response["error"]["code"], "unknown_method",
            "{method} must not exist"
        );
    }
}

/// The summary file the shell watches is written before the socket opens and
/// carries the overlay's fields — including the reason, which Plate D-003
/// renders and SPEC section 73 requires.
#[test]
fn the_summary_file_feeds_the_overlay() {
    let agent = TestDaemon::as_agent(CONSOLE_UID);
    // Present and empty before anything happens: the overlay never has to
    // tell "no approvals" apart from "punard has not started".
    let approval_id = gated_approval_id(&agent);
    let summary = agent.summary();
    assert_eq!(summary["v"], 1);
    let row = &summary["approvals"][0];
    assert_eq!(row["approval_id"], approval_id);
    assert_eq!(row["status"], "pending");
    // The risk on the card is the capability's own declared risk, read from
    // the registry descriptor — `MockCapability` declares `low`, the shipped
    // `security.firewall` backend declares `high`. The overlay never invents
    // one, and a test that hard-coded "high" here would be asserting the
    // fixture, not the wiring.
    assert_eq!(row["risk"], "low");
    assert_eq!(row["contract"], "SetFirewall(disabled)");
    assert_eq!(row["policy"]["policy_id"], "personal-defaults");
    assert_eq!(row["requester"]["type"], "ai_agent");
    assert_eq!(row["requester"]["id"], AGENT);
    // No spoofable display name is copied into the unspoofable file.
    assert!(row["requester"].get("agent_name").is_none());
    assert!(row["reason"].as_str().unwrap().contains(AGENT));
    assert!(row["expires_at"].as_str().unwrap().ends_with('Z'));
}

/// The exact `approvals.create` frame `punar-secrets` sends (its
/// `ApprovalClient::create`), asserted here so a divergence between the two
/// services fails on the host instead of in the VM.
///
/// The broker supplies three things punard cannot re-derive: the peer
/// credentials it read at **its own** socket, the policy citation it
/// evaluated (which may name an org layer), and the originating typed call.
/// All three are accepted because `approvals.create` is root-only.
#[test]
fn the_brokers_create_frame_is_accepted_verbatim() {
    let root = TestDaemon::as_root();
    let created = root.call(
        "approvals.create",
        Some(json!({
            "kind": "credential_request",
            "capability": "credential.request",
            "resource": "aws-dev",
            "user": "punar",
            "requester": { "type": "ai_agent", "id": AGENT },
            "requester_peer": { "uid": 1000, "agent_session_id": AGENT },
            "reason": "AWS development (mock) requested by agt_4f21c09ab3e1",
            "risk": "medium",
            "contract": "RequestCredential(aws-dev)",
            "policy": { "name": "Acme Engineering AI Policy", "policy_id": "eng-ai-v3" },
            "request": {
                "method": "credential.request",
                "params": { "credential": "aws-dev", "ttl": 60 }
            },
            "ttl": 300,
        })),
    );
    let envelope = &created["result"];
    assert!(
        envelope.get("approval").is_some(),
        "create must answer with the envelope: {created}"
    );
    assert_eq!(envelope["kind"], "credential_request");
    assert_eq!(envelope["contract"], "RequestCredential(aws-dev)");
    assert_eq!(envelope["requester_peer"]["agent_session_id"], AGENT);
    assert_eq!(envelope["request"]["params"]["credential"], "aws-dev");
    // The citation is the caller's, because the caller is the one that
    // evaluated the policy. punard would otherwise have to guess, and a
    // wrong citation on an approval card is worse than none.
    assert_eq!(envelope["policy"]["policy_id"], "eng-ai-v3");
    assert_is_the_schema_document(&envelope["approval"]);
    // The audit event cites what the card cites.
    let created_events = root.events("approval.create");
    assert_eq!(created_events[0]["policy_ids"], json!(["eng-ai-v3"]));
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Raise the standard gated approval and return its id.
fn gated_approval_id(daemon: &TestDaemon) -> String {
    let response = daemon.set("disabled");
    response["error"]["details"]["approval_id"]
        .as_str()
        .expect("the agent's call was gated")
        .to_string()
}
