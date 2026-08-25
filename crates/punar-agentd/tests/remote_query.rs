//! Milestone 10 integration tests for the **data owner's** half of the
//! remote query: `query.answer` and `queries.list`
//! (`docs/development/milestone-10.md` §7–§10; SPEC 24.1, 24.2, 51, 51.1,
//! 59.4).
//!
//! The courier half (`punard` fetching and posting back) has its own suite
//! next door. What is proved **here** is the half that decides:
//!
//! 1. **Law 2 — the transport is not the authority.** The grant is read
//!    from this device's own `enrollment.json`; nothing in the request can
//!    widen it, because there is no parameter through which a grant could
//!    arrive.
//! 2. **Gate B — fail closed.** No enrollment file ⇒ empty grant ⇒ every
//!    scope refused, on a device that is otherwise fully functional.
//! 3. **The refusal list is structural.** An answered `inventory` payload
//!    carries no executable path, no pid, no username, no project and no
//!    command line — not because a filter removed them, but because the
//!    projection has no field for them.
//! 4. **Spec 24.2.** The record of who asked is readable by an
//!    unprivileged peer, and it is written whether the answer was given or
//!    refused.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use punar_agentd::authz::{Peer, PeerSource};
use punar_agentd::server::{AgentdConfig, Daemon, DaemonHandle};
use punar_agentd::testsupport::{
    FIXTURE_BOOT_ID, FIXTURE_BTIME, fake_process, fixture_adapters, fixture_nss,
    fixture_proc_system, fixture_suspected,
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
        "punar-agentd-m10q-{tag}-{}-{nanos}",
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

    /// Write the enrollment document this device would have written at
    /// `enroll.start`. The **only** way a grant can reach the data owner.
    fn enroll(&self, scopes: &[&str]) {
        fs::write(
            self.dir.join("state/enrollment.json"),
            serde_json::to_vec_pretty(&json!({
                "org": {"name": "acme.com", "display_name": "Acme Engineering"},
                "device_token": "tok_fixture",
                "policy_files": ["eng-ai-v3.json"],
                "remote_query_scopes": scopes,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn queries_jsonl(&self) -> Vec<Value> {
        match fs::read_to_string(self.dir.join("state/agents/queries.jsonl")) {
            Ok(text) => text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
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

fn query(id: &str, admin: &str, scope: &str) -> Value {
    json!({
        "query_id": id,
        "requesting_admin": admin,
        "organization": "acme.com",
        "requested_scope": scope,
        "received_at": "2026-08-25T14:02:09Z",
    })
}

fn with_foo_agent(proc_root: &Path) {
    fake_process(
        proc_root,
        4242,
        "foo-agent",
        FOO_PATH,
        &[FOO_PATH],
        PUNAR_UID,
        "0::/user.slice/user-1000.slice/session-1.scope",
    );
}

/// Root only, and the refusal is an **error frame**, not a decision: a
/// local user asking this device to answer a question nobody asked is not
/// an authorization outcome to relay, it is a caller who is not admitted.
#[test]
fn only_root_may_hand_this_daemon_a_question() {
    let daemon = TestDaemon::start("nonroot", Peer::user(PUNAR_UID), with_foo_agent);
    daemon.enroll(&["inventory"]);

    let response = daemon.call(
        "query.answer",
        Some(query("qry_1", "cio@acme.com", "inventory")),
    );
    assert_eq!(response["error"]["code"], "denied", "{response}");
    // Nothing was decided, so nothing is recorded: the query log is a log
    // of questions this device answered or refused, not of local probes.
    assert!(daemon.queries_jsonl().is_empty());
}

/// Gate B, independent of gate A: even handed a perfectly well-formed
/// question by a root caller, a device with no enrollment file answers
/// nothing. Absent grant ⇒ empty set ⇒ refusal (milestone-10.md §9.2).
#[test]
fn an_unenrolled_device_refuses_every_scope_and_still_records_the_attempt() {
    let daemon = TestDaemon::start("gateb", Peer::root(), with_foo_agent);
    daemon.scan_now();

    for scope in [
        "inventory",
        "authority",
        "resource_summary",
        "security_events",
    ] {
        let result = daemon.result(
            "query.answer",
            Some(query(&format!("qry_{scope}"), "secops@acme.com", scope)),
        );
        assert_eq!(
            result["authorization_decision"], "deny",
            "{scope}: {result}"
        );
        assert_eq!(result["refusal_reason"], "out_of_scope", "{scope}");
        assert_eq!(result["result_category"], "refused", "{scope}");
        assert!(result.get("payload").is_none(), "{scope}: {result}");
        // Section 73: what was asked, what is permitted, and who can
        // change it — never a bare "denied".
        let message = result["refusal_message"].as_str().unwrap();
        assert!(message.contains(scope), "{message}");
        assert!(message.contains("Next step"), "{message}");
    }

    // The attempt is recorded either way — that is the point of the log.
    let recorded = daemon.queries_jsonl();
    assert_eq!(recorded.len(), 4);
    assert!(
        recorded
            .iter()
            .all(|r| r["authorization_decision"] == "deny")
    );
    assert!(
        recorded
            .iter()
            .all(|r| r["admin_identity_verified"] == false)
    );
    assert!(recorded.iter().all(|r| r["granted_scope"].is_null()));

    let lines = daemon.audit_lines();
    let audited: Vec<&Value> = lines
        .iter()
        .filter(|e| e["action"] == "admin.ai_query")
        .collect();
    assert_eq!(audited.len(), 4);
    for event in audited {
        assert_eq!(event["decision"], "deny");
        assert_eq!(event["result"], "refused");
        assert_eq!(event["source"], "organization");
        // The administrator is named: an audit line about an
        // administrative query that does not name the administrator is a
        // line nobody can act on (milestone-10.md §10.2).
        assert_eq!(event["user_id"], "secops@acme.com");
    }
}

/// The answered case, and the whole refusal list asserted against the
/// bytes that would leave the device.
#[test]
fn an_authorized_inventory_answer_carries_no_path_pid_user_or_project() {
    let daemon = TestDaemon::start("inventory", Peer::root(), with_foo_agent);
    daemon.enroll(&["inventory", "authority"]);
    daemon.scan_now();

    let result = daemon.result(
        "query.answer",
        Some(query("qry_ok", "cio@acme.com", "inventory")),
    );
    assert_eq!(result["authorization_decision"], "allow", "{result}");
    assert_eq!(result["granted_scope"], "inventory");
    assert_eq!(result["result_category"], "answered");

    let payload = &result["payload"];
    let detections = payload["detections"].as_array().unwrap();
    assert_eq!(detections.len(), 1, "{payload}");
    let detection = &detections[0];
    assert_eq!(detection["agent"], "foo-agent");
    assert_eq!(detection["classification"], "unknown");
    // The honesty label travels in the data (spec 23).
    assert_eq!(detection["suspected"], true);
    // A zone CLASS, never the location.
    assert_eq!(detection["zone"], "downloads");
    assert!(
        detection["signature_id"]
            .as_str()
            .unwrap()
            .starts_with("sig_"),
        "{detection}"
    );

    // What is absent is the contract. Asserted against the serialized
    // bytes, because a field added by a later milestone must fail here
    // rather than quietly ride along.
    let bytes = serde_json::to_string(payload).unwrap();
    for forbidden in [
        FOO_PATH,
        "Downloads",
        "process_id",
        "cmdline",
        "cwd",
        "cgroup",
        "punar-agent-",
        "\"user\"",
        "\"pid\"",
    ] {
        assert!(
            !bytes.contains(forbidden),
            "an inventory answer must not carry {forbidden}: {bytes}"
        );
    }

    let recorded = daemon.queries_jsonl();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0]["granted_scope"], "inventory");
    assert_eq!(recorded[0]["record_counts"]["detections"], 1);
    // The payload itself is deliberately NOT stored: one exported copy of
    // a user's data is enough to protect (milestone-10.md §10.1).
    let log_bytes = serde_json::to_string(&recorded[0]).unwrap();
    assert!(!log_bytes.contains("foo-agent"), "{log_bytes}");
    assert!(!log_bytes.contains("payload"), "{log_bytes}");
}

/// A scope the organization never asked for at enrollment is refused even
/// though the device can produce it and the administrator's role permits
/// it. This is the half of spec 24.1 the *device* owns.
#[test]
fn a_scope_the_organization_never_asked_for_is_refused_by_the_device() {
    let daemon = TestDaemon::start("outofscope", Peer::root(), with_foo_agent);
    daemon.enroll(&["inventory", "authority"]);
    daemon.scan_now();

    let result = daemon.result(
        "query.answer",
        Some(query("qry_rs", "secops@acme.com", "resource_summary")),
    );
    assert_eq!(result["authorization_decision"], "deny", "{result}");
    assert_eq!(result["refusal_reason"], "out_of_scope");
    let message = result["refusal_message"].as_str().unwrap();
    assert!(message.contains("inventory"), "{message}");
    assert!(message.contains("authority"), "{message}");

    // And an invented scope cannot be answered best-effort: the closed
    // enum refuses it before anything is projected.
    let junk = daemon.result(
        "query.answer",
        Some(query("qry_junk", "secops@acme.com", "everything")),
    );
    assert_eq!(junk["authorization_decision"], "deny", "{junk}");
    assert!(junk.get("payload").is_none(), "{junk}");
}

/// Spec 24.2: the user reads the record of who asked about them, without
/// being root, and the surface's vocabulary comes from the daemon that
/// enforces it rather than from a CLI-side constant.
#[test]
fn the_query_log_is_readable_by_an_unprivileged_peer() {
    let mut daemon = TestDaemon::start("visible", Peer::root(), with_foo_agent);
    daemon.enroll(&["inventory"]);
    daemon.scan_now();
    daemon.result(
        "query.answer",
        Some(query("qry_a", "cio@acme.com", "inventory")),
    );
    daemon.result(
        "query.answer",
        Some(query("qry_b", "secops@acme.com", "security_events")),
    );

    daemon.restart_as(Peer::user(PUNAR_UID));
    let listed = daemon.result("queries.list", None);
    let queries = listed["queries"].as_array().unwrap();
    assert_eq!(queries.len(), 2, "{listed}");
    assert_eq!(queries[0]["query_id"], "qry_a");
    assert_eq!(queries[1]["result_category"], "refused");

    assert_eq!(listed["enrolled"], true);
    assert_eq!(listed["granted_scopes"], json!(["inventory"]));
    // There is no IdP, and every surface says so.
    assert_eq!(listed["admin_identity_verified"], false);
    let never = serde_json::to_string(&listed["never_answered"]).unwrap();
    for expected in ["prompts", "file paths", "command lines", "secret values"] {
        assert!(never.contains(expected), "{never}");
    }
    assert_eq!(listed["storage"]["purged_by_privacy_purge"], false);

    // `--since` filters daemon-side, so a script and the human renderer
    // cannot disagree about what it means.
    let since = daemon.result(
        "queries.list",
        Some(json!({"since": "2900-01-01T00:00:00Z"})),
    );
    assert!(since["queries"].as_array().unwrap().is_empty(), "{since}");
}

impl TestDaemon {
    /// One deliberate detection pass. Every pass in this suite is asked
    /// for; nothing here runs on a staleness timer.
    fn scan_now(&self) {
        self.result("agents.scan", Some(json!({"trigger": "manual"})));
    }
}

// ---------------------------------------------------------------------------
// Adversarial: a COMPROMISED control plane (SPEC 59.4)
//
// The suite above proves law 2 for the one field the plan names — the
// *scope*. These prove it for the rest of the question. A control plane
// that has been taken over chooses every byte of a `PendingQuery`, and the
// data owner uses several of those bytes as keys rather than as prose: a
// ledger lookup key, three pattern-checked audit fields, and four strings
// that land on the SPEC 24.2 surface and in a 365-day log. Each test below
// is one way to reach past the scope check without ever widening a scope.
// ---------------------------------------------------------------------------

/// **Attack: use the narrowing key as a path.**
///
/// milestone-10.md section 8.1 allows a query to name one `session_id` to
/// *narrow* an answer. A ledger record is a file named after its session,
/// so a narrowing key that is not an `agt_` id is a path — and the
/// unnarrowed answer's session set is exactly the set the narrowed one must
/// be a subset of. Both gates are asserted: the malformed key is refused at
/// the boundary, and a well-formed key that names something outside the
/// index still yields nothing.
#[test]
fn a_narrowing_key_can_never_be_a_path_and_can_never_widen() {
    let daemon = TestDaemon::start("traversal", Peer::root(), with_foo_agent);
    daemon.enroll(&["resource_summary"]);
    daemon.scan_now();

    // A real ledger record, planted three directories above the ledger
    // store — the shape of any record that lives outside the index: a
    // backup, a copy, another store.
    let ledger_dir = daemon.dir.join("state/agents/ledger");
    let planted = fs::read_dir(&ledger_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("agt_"))
        })
        .expect("the detection pass opened a ledger");
    fs::copy(&planted, daemon.dir.join("planted.json")).unwrap();

    let mut attack = query("qry_traverse", "secops@acme.com", "resource_summary");
    attack["session_id"] = json!("../../../planted");
    let response = daemon.call("query.answer", Some(attack));
    assert_eq!(
        response["error"]["code"], "invalid_params",
        "a narrowing key that is not an agent session id must be refused \
         before anything is read: {response}"
    );
    // Nothing was decided, so nothing was recorded and nothing left.
    assert!(
        daemon.queries_jsonl().is_empty(),
        "a malformed question is not a question"
    );

    // Second gate, independent of the first: a *well-formed* id that the
    // index does not hold narrows to nothing rather than to a lookup.
    let mut ghost = query("qry_ghost", "secops@acme.com", "resource_summary");
    ghost["session_id"] = json!("agt_notinthisindex");
    let result = daemon.result("query.answer", Some(ghost));
    assert_eq!(result["result_category"], "answered", "{result}");
    assert!(
        result["payload"]["summaries"]
            .as_array()
            .unwrap()
            .is_empty(),
        "narrowing filters the answered set; it never performs a lookup: {result}"
    );
}

/// **Attack: suppress the audit record of your own query.**
///
/// SPEC 51.1 requires every query to be audited, and
/// `audit::validate_event_schema` refuses to write an event whose
/// `user_id` is empty, whose `resource` is empty, or whose
/// `agent_session_id` is not `^agt_[A-Za-z0-9]+$`. All three of those
/// fields are filled from the request. A control plane that chooses them
/// badly used to get its answer **and** no audit line — the query log then
/// naming an `audit_event_id` for an event that was never written.
#[test]
fn a_control_plane_cannot_choose_fields_that_suppress_its_own_audit_event() {
    let daemon = TestDaemon::start("auditsuppress", Peer::root(), with_foo_agent);
    daemon.enroll(&["inventory"]);

    let probes: Vec<(&str, Value)> = vec![
        // user_id empty -> the event fails validation and is dropped.
        ("blank admin", query("qry_1", "", "inventory")),
        // resource empty -> same.
        ("blank scope", query("qry_2", "cio@acme.com", "")),
        // agent_session_id off-pattern -> same.
        ("off-pattern session", {
            let mut q = query("qry_3", "cio@acme.com", "inventory");
            q["session_id"] = json!("not-an-agt-id");
            q
        }),
    ];
    for (label, probe) in probes {
        let response = daemon.call("query.answer", Some(probe));
        assert_eq!(
            response["error"]["code"], "invalid_params",
            "{label} must be refused before the answer is projected: {response}"
        );
    }
    assert!(
        daemon
            .audit_lines()
            .iter()
            .all(|e| e["action"] != "admin.ai_query"),
        "nothing was decided, so nothing is audited"
    );
    assert!(daemon.queries_jsonl().is_empty());

    // And the control: a well-formed question is still answered and still
    // audited, so the fix refuses garbage rather than refusing questions.
    let result = daemon.result(
        "query.answer",
        Some(query("qry_ok", "cio@acme.com", "inventory")),
    );
    assert_eq!(result["result_category"], "answered", "{result}");
    let lines = daemon.audit_lines();
    let audited: Vec<&Value> = lines
        .iter()
        .filter(|e| e["action"] == "admin.ai_query")
        .collect();
    assert_eq!(audited.len(), 1, "exactly one audit event for one query");
    assert_eq!(audited[0]["event_id"], result["audit_event_id"]);
}

/// **Attack: forge the SPEC 24.2 surface.**
///
/// `punarctl privacy queries` is the one screen that tells a user who asked
/// about them. Every string it renders comes from the control plane. A
/// terminal escape there is the same class of harm that put `alerts.json`
/// in a root-owned directory (milestone-10.md section 5.3) — a forged card,
/// arriving through a different door. Unbounded strings on a hook that runs
/// every reconcile period are the other half: a disk-fill primitive handed
/// to the control plane, on a log kept 365 days.
#[test]
fn control_plane_strings_cannot_forge_a_terminal_or_fill_a_disk() {
    let daemon = TestDaemon::start("forge", Peer::root(), with_foo_agent);
    daemon.enroll(&["inventory"]);

    let escape = "\u{1b}[2J\u{1b}[HPunar · no queries were made";
    let probes: Vec<(&str, Value)> = vec![
        ("ansi in admin", query("qry_1", escape, "inventory")),
        (
            "newline in admin",
            query("qry_2", "cio@acme.com\nfake row", "inventory"),
        ),
        ("ansi in scope", query("qry_3", "cio@acme.com", escape)),
        // The ipc.md section 2 line bound already caps a single field at
        // 4 KiB; these sit under it, which is the point — a field that fits
        // the transport can still be far too long for a printed surface and
        // for a log kept 365 days.
        (
            "oversize admin",
            query("qry_4", &"a".repeat(1024), "inventory"),
        ),
        (
            "oversize scope",
            query("qry_5", "cio@acme.com", &"a".repeat(1024)),
        ),
        ("ansi in organization", {
            let mut q = query("qry_6", "cio@acme.com", "inventory");
            q["organization"] = json!(escape);
            q
        }),
        ("ansi in query_id", {
            let mut q = query("qry_7", "cio@acme.com", "inventory");
            q["query_id"] = json!(escape);
            q
        }),
        ("received_at is not a timestamp", {
            let mut q = query("qry_8", "cio@acme.com", "inventory");
            q["received_at"] = json!("whenever\u{1b}[31m");
            q
        }),
    ];
    for (label, probe) in probes {
        let response = daemon.call("query.answer", Some(probe));
        assert_eq!(
            response["error"]["code"], "invalid_params",
            "{label} must not reach the query log: {response}"
        );
    }
    assert!(
        daemon.queries_jsonl().is_empty(),
        "not one attacker-chosen byte reached the 365-day log"
    );
    for line in daemon.audit_lines() {
        let text = serde_json::to_string(&line).unwrap();
        assert!(
            !text.contains("\\u001b"),
            "an escape reached the audit log: {text}"
        );
    }
}

/// The `authority` answer says where its rows came from.
///
/// milestone-10.md section 8.1 describes this scope as "the org's own
/// policy, read back". What is actually read back is the block the local
/// launcher handed to `agents.register` — asserted by a local process, not
/// measured by this device. Section 9.1 already established the discipline
/// for the other asserted identity in the same answer (the requesting
/// admin is labelled `not verified by this device`); spec 1.22 requires the
/// same label here, or `enforcement: "enforced"` becomes a claim the device
/// never made.
#[test]
fn an_authority_answer_labels_its_rows_asserted_not_measured() {
    let daemon = TestDaemon::start("authority-label", Peer::root(), with_foo_agent);
    daemon.enroll(&["authority"]);

    let result = daemon.result(
        "query.answer",
        Some(query("qry_auth", "cio@acme.com", "authority")),
    );
    assert_eq!(result["result_category"], "answered", "{result}");
    let label = result["payload"]["authority_source"]
        .as_str()
        .unwrap_or_default();
    assert!(
        label.contains("not verified by this device"),
        "the administrator must be told these rows are asserted: {result}"
    );
}

/// **Attack: smuggle a path out through the one location field.**
///
/// milestone-10.md section 8.3 rests on a distinction: what an export may
/// not contain is absent because no field exists to carry it, not because
/// a filter drops it. `zone` is where that claim is thinnest — the export
/// reads it back from `detections-index.json` as a plain `String`, and the
/// field one line above it in the same record holds the full executable
/// path. A wrong index, a corrupt file, or a future writer that swaps two
/// fields would put a path into a datum documented as a class, on the one
/// surface that leaves the device.
///
/// The export narrows the stored value back to the closed class set. An
/// honest `unknown` is always a safe answer here; a path never is.
#[test]
fn only_a_zone_class_can_leave_even_if_the_index_says_otherwise() {
    let mut daemon = TestDaemon::start("zone-narrow", Peer::root(), with_foo_agent);
    daemon.enroll(&["inventory"]);
    daemon.scan_now();

    // Rewrite the stored zone as the executable path it sits beside.
    let index_path = daemon.dir.join("state/agents/detections-index.json");
    let mut index: Value = serde_json::from_str(&fs::read_to_string(&index_path).unwrap()).unwrap();
    for row in index["rows"].as_object_mut().unwrap().values_mut() {
        row["zone"] = json!(FOO_PATH);
    }
    fs::write(&index_path, serde_json::to_vec_pretty(&index).unwrap()).unwrap();
    daemon.restart_as(Peer::root());

    let result = daemon.result(
        "query.answer",
        Some(query("qry_zone", "cio@acme.com", "inventory")),
    );
    let payload = serde_json::to_string(&result["payload"]).unwrap();
    assert!(
        !payload.contains(FOO_PATH) && !payload.contains("/home/"),
        "no path may leave through the zone field: {payload}"
    );
    let zone = result["payload"]["detections"][0]["zone"].as_str().unwrap();
    assert_eq!(
        zone, "unknown",
        "an unrecognised class answers honestly: {result}"
    );
}
