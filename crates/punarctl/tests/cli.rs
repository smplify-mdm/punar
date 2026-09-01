//! Integration tests: the real `punarctl` binary against a mock `punard`
//! on a tempdir Unix socket.
//!
//! The mock speaks the docs/api/ipc.md envelope verbatim (NDJSON, v: 1,
//! id echo, result XOR error) with fixture data mirroring the wire-contract
//! examples, and asserts the client's request shape while doing so. Human
//! output is snapshot-tested in plain mode (stdout is a pipe, so ANSI is
//! stripped by design); `--json` must round-trip the fixture result
//! verbatim.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Fixtures (docs/api/ipc.md section 5 examples)
// ---------------------------------------------------------------------------

fn fixture_status() -> Value {
    json!({
        "protocol_version": 1,
        "daemon_version": "0.1.0",
        "started_at": "2026-08-25T07:00:12Z",
        "device_id": "dev_9f3k2v8q1x",
        "mode": "personal",
        "enrolled": false,
        "hostname": "punar-m3",
        "capabilities_total": 3,
        "last_reconcile": "2026-08-25T07:00:13Z",
        "audit": {"path": "/var/log/punar/audit.jsonl", "events": 42},
        // M4 (contract section 5.1): SPEC section 52 states in personal
        // scope, always present since M4.
        "compliance": {
            "overall": "compliant",
            "capabilities": [
                {"capability": "security.firewall", "state": "compliant"},
                {"capability": "system.hostname", "state": "compliant"},
                {"capability": "time.timezone", "state": "compliant"}
            ],
            "drift_remediated_total": 2,
            "last_remediation_at": "2026-08-25T09:14:02Z"
        }
    })
}

fn fixture_update_status() -> Value {
    json!({
        "v": 1,
        "image_id": "punar-desktop",
        "current": {"version": "2026.08.30.1", "slot": "a", "blessed": true,
                    "snapshot_pin": "20260820T000000Z"},
        "desired": {"version": "2026.09.01.1", "slot": "b", "state": "staged"},
        "channel": {"name": "stable", "source": "personal-preference",
                    "policy_ids": ["personal-defaults"], "metadata_age_seconds": 7200,
                    "rollout_bps": 10000, "in_cohort": true, "halted": false,
                    "reachable": true},
        "health": {"state": "pass", "signals": {"boot": "pass", "services": "pass",
                    "session": "pass", "capabilities": "pass"}},
        "rollback": {"state": "available", "target_version": "2026.08.29.1",
                     "target_slot": "a"},
        "browser": {"engine": "chromium", "version": "151.0.7922.169-1",
                    "channel": "snapshot", "snapshot_pin": "20260820T000000Z",
                    "pin_source": "running image"}
    })
}

fn firewall_descriptor() -> Value {
    json!({
        "capability": "security.firewall",
        "supported": true,
        "current_state": "enabled",
        "desired_state": "enabled",
        "mutable": true,
        "requires_reboot": false,
        "risk": "high",
        "managed_by": "local",
        "verification": "nftables",
        "allowed_desired_states": ["enabled", "disabled"],
        "privilege_required": "root",
        "approval_requirement": "allow",
        "audit_category": "security"
    })
}

fn hostname_descriptor(state: &str) -> Value {
    json!({
        "capability": "system.hostname",
        "supported": true,
        "current_state": state,
        "desired_state": state,
        "mutable": true,
        "requires_reboot": false,
        "risk": "low",
        "managed_by": "local",
        "verification": "kernel+file",
        "privilege_required": "root",
        "approval_requirement": "allow",
        "audit_category": "system"
    })
}

fn timezone_descriptor() -> Value {
    json!({
        "capability": "time.timezone",
        "supported": true,
        "current_state": "UTC",
        "desired_state": "UTC",
        "mutable": true,
        "requires_reboot": false,
        "risk": "low",
        "managed_by": "local",
        "verification": "symlink",
        "privilege_required": "root",
        "approval_requirement": "allow",
        "audit_category": "system"
    })
}

fn fixture_capabilities() -> Value {
    json!({
        "capabilities": [
            firewall_descriptor(),
            hostname_descriptor("punar-m3"),
            timezone_descriptor(),
        ]
    })
}

fn fixture_audit_events() -> Vec<Value> {
    vec![
        json!({
            "event_id": "evt_000001", "timestamp": "2026-08-25T07:00:13Z",
            "device_id": "dev_9f3k2v8q1x", "user_id": "punard",
            "agent_session_id": "agt_none", "project_id": "system",
            "source": "service", "action": "reconcile",
            "resource": "capability_registry", "decision": "allow",
            "policy_ids": ["personal-defaults"], "result": "clean"
        }),
        json!({
            "event_id": "evt_000002", "timestamp": "2026-08-25T07:31:02Z",
            "device_id": "dev_9f3k2v8q1x", "user_id": "root",
            "agent_session_id": "agt_none", "project_id": "system",
            "source": "human", "action": "capabilities.set",
            "resource": "system.hostname", "decision": "allow",
            "policy_ids": ["personal-defaults"], "result": "success"
        }),
        json!({
            "event_id": "evt_000003", "timestamp": "2026-08-25T07:32:40Z",
            "device_id": "dev_9f3k2v8q1x", "user_id": "punar",
            "agent_session_id": "agt_none", "project_id": "system",
            "source": "human", "action": "capabilities.set",
            "resource": "system.hostname", "decision": "deny",
            "policy_ids": ["personal-defaults"], "result": "denied"
        }),
    ]
}

fn fixture_reconcile() -> Value {
    // M4 shape (contract section 5.6): the M3 fields keep their meaning
    // (`drift` is the pre-remediation observation) plus the additive
    // classification/remediation fields and the compliance block.
    json!({
        "reconciled_at": "2026-08-25T07:41:03Z",
        "drift_count": 1,
        "remediated_count": 1,
        "capabilities": [
            {"capability": "security.firewall", "desired_state": "enabled",
             "current_state": "disabled", "drift": true, "verified": true,
             "classification": "auto_remediate", "remediation": "applied"},
            {"capability": "system.hostname", "desired_state": "punar-m3",
             "current_state": "punar-m3", "drift": false, "verified": true,
             "classification": "auto_remediate", "remediation": "none"},
            {"capability": "time.timezone", "desired_state": "UTC",
             "current_state": "UTC", "drift": false, "verified": true,
             "classification": "auto_remediate", "remediation": "none"}
        ],
        "compliance": {
            "overall": "compliant",
            "capabilities": [
                {"capability": "security.firewall", "state": "compliant"},
                {"capability": "system.hostname", "state": "compliant"},
                {"capability": "time.timezone", "state": "compliant"}
            ],
            "drift_remediated_total": 1,
            "last_remediation_at": "2026-08-25T07:41:03Z"
        }
    })
}

/// One `policy.effective` entry (contract section 5.7). Personal mode:
/// only `local_user_preference` (rank 5) and `os_secure_default` (rank 6)
/// sources exist, the policy id is always `personal-defaults`, and a user
/// override is always permitted (winning rank >= 5).
fn policy_entry(path: &str, value: &str, kind: &str, rank: u64, name: &str) -> Value {
    json!({
        "path": path,
        "effective_value": value,
        "source": {"kind": kind, "rank": rank,
                   "policy_id": "personal-defaults", "name": name},
        "user_override_permitted": true,
        "compliance_state": "compliant"
    })
}

fn fixture_policy_effective() -> Value {
    json!({
        "computed_at": "2026-08-25T09:14:02Z",
        "entries": [
            policy_entry(
                "security.firewall",
                "enabled",
                "local_user_preference",
                5,
                "Personal preference",
            ),
            policy_entry(
                "system.hostname",
                "punar-m3",
                "local_user_preference",
                5,
                "Personal preference",
            ),
            policy_entry("time.timezone", "UTC", "os_secure_default", 6, "OS default"),
        ]
    })
}

/// The `policy.explain` result for `path`: the matching effective entry
/// without its `path` field (contract section 5.8), or `None` when the
/// path is not in the effective document.
fn fixture_policy_explain(path: &str) -> Option<Value> {
    let effective = fixture_policy_effective();
    let entry = effective["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["path"] == path)?;
    let mut entry = entry.clone();
    entry.as_object_mut().unwrap().remove("path");
    Some(entry)
}

// ---------------------------------------------------------------------------
// M5 enrollment fixtures (contract sections 5.1, 5.4, 5.9–5.11)
// ---------------------------------------------------------------------------

fn fixture_org() -> Value {
    json!({"id": "acme", "name": "Acme",
           "display_name": "Acme Engineering", "domain": "acme.com"})
}

fn fixture_enroll_start() -> Value {
    json!({
        "enrolled": true,
        "org": fixture_org(),
        "policy_ids": ["eng-baseline-v12"],
        "attestation": "simulated",
        "enrolled_at": "2026-08-26T09:00:00Z",
        "first_sync": {"compliance": "success", "inventory": "success"}
    })
}

fn fixture_enroll_status() -> Value {
    json!({
        "enrolled": true,
        "org": fixture_org(),
        "policy_ids": ["eng-baseline-v12"],
        "enrolled_at": "2026-08-26T09:00:00Z",
        "attestation": "simulated",
        "last_sync": {"at": "2026-08-26T09:02:00Z", "result": "success",
                       "pending": false}
    })
}

fn fixture_enroll_stop() -> Value {
    json!({"enrolled": false, "removed_policy_ids": ["eng-baseline-v12"]})
}

/// A managed device's responder: `status` carries the M5 org fields; a
/// root set on the org-pinned firewall path is recorded-but-overridden;
/// `policy.explain` cites the pinning source (contract section 5.4).
fn managed_respond(request: &Value) -> Result<Value, Value> {
    let method = request["method"].as_str().expect("method must be a string");
    match method {
        "status" => {
            let mut status = fixture_status();
            let map = status.as_object_mut().unwrap();
            map.insert("mode".to_string(), json!("managed"));
            map.insert("enrolled".to_string(), json!(true));
            map.insert("org".to_string(), fixture_org());
            Ok(status)
        }
        "capabilities.set" => {
            let params = request.get("params").expect("set takes params");
            assert_eq!(params["capability"], "security.firewall");
            Ok(json!({
                "descriptor": firewall_descriptor(),
                "changed": false,
                "overridden": true,
                "effective_state": "enabled"
            }))
        }
        "policy.explain" => Ok(json!({
            "effective_value": "enabled",
            "source": {"kind": "organization_baseline", "rank": 2,
                       "policy_id": "eng-baseline-v12",
                       "name": "Acme Engineering Baseline"},
            "user_override_permitted": false,
            "compliance_state": "compliant"
        })),
        _ => respond(request),
    }
}

/// The ipc.md section 3.2 denial example — the section 73 voice the real
/// daemon sends a non-root `capabilities.set`.
const DENIED_MESSAGE: &str = "Changing system.hostname needs administrator privileges.\nPolicy: personal defaults — just-in-time elevation arrives in Milestone 9.\nNext step: re-run as root: sudo punarctl capabilities set system.hostname <name>";

// ---------------------------------------------------------------------------
// Mock daemon
// ---------------------------------------------------------------------------

/// Answer one request. The mock enforces the client-side envelope contract:
/// v must be 1, id must be a 1–64-char string, and no-param methods must
/// omit `params` entirely (the server is strict about unknown params, so a
/// client that sends spurious ones is broken).
fn respond(request: &Value) -> Result<Value, Value> {
    assert_eq!(request["v"], json!(1), "client must send v: 1");
    let id = request["id"].as_str().expect("id must be a string");
    assert!((1..=64).contains(&id.len()), "id must be 1-64 chars");
    let method = request["method"].as_str().expect("method must be a string");
    let params = request.get("params");

    match method {
        "status" | "capabilities.list" | "reconcile" | "policy.effective" | "update.status" => {
            assert!(params.is_none(), "{method} takes no params");
        }
        _ => {}
    }

    match method {
        "status" => Ok(fixture_status()),
        "update.status" => Ok(fixture_update_status()),
        "capabilities.list" => Ok(fixture_capabilities()),
        "capabilities.get" => {
            let capability = params.unwrap()["capability"].as_str().unwrap();
            match capability {
                "security.firewall" => Ok(firewall_descriptor()),
                "system.hostname" => Ok(hostname_descriptor("punar-m3")),
                "time.timezone" => Ok(timezone_descriptor()),
                other => Err(json!({
                    "code": "not_found",
                    "message": format!(
                        "No capability named {other} exists in the registry.\nNext step: punarctl capabilities"
                    ),
                    "details": {"capability": other}
                })),
            }
            .map(|descriptor| json!({"descriptor": descriptor}))
        }
        "capabilities.set" => {
            let params = params.unwrap();
            let desired = params["desired_state"].as_str().unwrap();
            if desired == "mallory" {
                // The mock plays the daemon refusing a non-root peer.
                Err(json!({
                    "code": "denied",
                    "message": DENIED_MESSAGE,
                    "details": {
                        "capability": "system.hostname",
                        "decision": "deny",
                        "policy_ids": ["personal-defaults"]
                    }
                }))
            } else {
                Ok(json!({
                    "descriptor": hostname_descriptor(desired),
                    "changed": true
                }))
            }
        }
        "audit.tail" => {
            let n = params.and_then(|p| p["n"].as_u64()).unwrap_or(20).min(1000) as usize;
            let events = fixture_audit_events();
            let skip = events.len().saturating_sub(n);
            Ok(json!({"events": events[skip..].to_vec()}))
        }
        "reconcile" => Ok(fixture_reconcile()),
        "enroll.start" => {
            let params = params.expect("enroll.start takes params");
            let object = params.as_object().unwrap();
            assert_eq!(object.len(), 1, "enroll.start takes only `org_domain`");
            assert_eq!(object["org_domain"], "acme.com");
            Ok(fixture_enroll_start())
        }
        "enroll.status" => {
            assert!(params.is_none(), "enroll.status takes no params");
            Ok(fixture_enroll_status())
        }
        "enroll.stop" => {
            assert!(params.is_none(), "enroll.stop takes no params");
            Ok(fixture_enroll_stop())
        }
        "policy.effective" => Ok(fixture_policy_effective()),
        "policy.explain" => {
            let params = params.expect("policy.explain takes params");
            let object = params.as_object().unwrap();
            assert_eq!(object.len(), 1, "policy.explain takes only `path`");
            let path = object["path"].as_str().expect("path must be a string");
            fixture_policy_explain(path).ok_or_else(|| {
                json!({
                    "code": "not_found",
                    "message": format!(
                        "No capability path named {path} exists in the effective policy.\n\
                         Next step: punarctl policy effective"
                    ),
                    "details": {"param": "path", "path": path}
                })
            })
        }
        other => Err(json!({
            "code": "unknown_method",
            "message": format!(
                "The method \"{other}\" does not exist. Punar exposes typed capabilities only — \
                 there is no generic execution RPC, by architecture (SPEC sections 10, 60).\n\
                 Next step: punarctl capabilities"
            ),
            "details": {"method": other}
        })),
    }
}

fn handle_connection(stream: UnixStream, responder: fn(&Value) -> Result<Value, Value>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut writer = stream;
    let mut line = String::new();
    while let Ok(read) = reader.read_line(&mut line) {
        if read == 0 {
            break;
        }
        let request: Value = serde_json::from_str(line.trim_end()).expect("request must be JSON");
        let id = request["id"].clone();
        let envelope = match responder(&request) {
            Ok(result) => json!({"v": 1, "id": id, "result": result}),
            Err(error) => json!({"v": 1, "id": id, "error": error}),
        };
        writeln!(writer, "{envelope}").expect("write response");
        line.clear();
    }
}

/// Start a mock daemon with a custom responder on a fresh tempdir socket;
/// returns the socket path.
fn start_mock_with(responder: fn(&Value) -> Result<Value, Value>) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "punarctl-mock-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create mock dir");
    let path = dir.join("punard.sock");
    let listener = UnixListener::bind(&path).expect("bind mock socket");
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    thread::spawn(move || handle_connection(stream, responder));
                }
                Err(_) => break,
            }
        }
    });
    path
}

/// Start the default mock daemon (the section 5 fixtures).
fn start_mock() -> PathBuf {
    start_mock_with(respond)
}

fn run(socket: &PathBuf, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_punarctl"))
        .args(args)
        .env("PUNARD_SOCKET", socket)
        .env("NO_COLOR", "1")
        .output()
        .expect("run punarctl")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

/// The client's own masthead-context hostname (mirrors `local_hostname` in
/// the binary) for views whose result carries no hostname.
fn local_hostname() -> String {
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(contents) = fs::read_to_string(path) {
            let name = contents.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    std::env::var("HOSTNAME")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

/// Compose the deterministic masthead line: tracked left + right-aligned
/// uppercased context in 72 columns (min two-space gap).
fn masthead_line(tracked_left: &str, context: &str) -> String {
    let right = context.to_uppercase();
    let used = tracked_left.chars().count() + right.chars().count();
    let gap = if used + 2 > 72 { 2 } else { 72 - used };
    format!("{tracked_left}{}{right}", " ".repeat(gap))
}

const RULE: &str = "────────────────────────────────────────────────────────────────────────";

// ---------------------------------------------------------------------------
// Snapshots (plain mode — stdout is a pipe, NO_COLOR set)
// ---------------------------------------------------------------------------

#[test]
fn status_human_output_matches_the_d014_snapshot() {
    let socket = start_mock();
    let output = run(&socket, &["status"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let expected = format!(
        "{}\n{RULE}\n{}",
        masthead_line("P U N A R   ·   S T A T U S", "punar-m3 · Personal"),
        "DEVICE        PERSONAL    punar-m3 · dev_9f3k2v8q1x · not enrolled · nothing leaves this machine\n\
         DAEMON        READY       punard 0.1.0 · protocol v1 · started 2026-08-25 07:00:12\n\
         CAPABILITIES  3 TRACKED   registry local · last reconcile 2026-08-25 07:00:13\n\
         AUDIT         42 EVENTS   /var/log/punar/audit.jsonl · local only\n\
         \n\
         OVERALL       MATCHES    drift put back 2 · last 2026-08-25 09:14:02\n\
         FIREWALL      MATCHES\n\
         HOSTNAME      MATCHES\n\
         TIMEZONE      MATCHES\n\
         PERSONAL DEVICE · ENROLLMENT LATER NEVER APPLIES RETROACTIVELY\n"
    );
    assert_eq!(stdout(&output), expected);
    assert!(
        !stdout(&output).contains('\x1b'),
        "plain mode must carry no ANSI"
    );
}

#[test]
fn capabilities_human_output_matches_the_d014_snapshot() {
    let socket = start_mock();
    let output = run(&socket, &["capabilities"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let context = format!("{} · Personal", local_hostname());
    let expected = format!(
        "{}\n{RULE}\n{}",
        masthead_line("P U N A R   ·   C A P A B I L I T I E S", &context),
        "SECURITY.FIREWALL  ENABLED    desired enabled · risk high · verify nftables · local\n\
         SYSTEM.HOSTNAME    PUNAR-M3   desired punar-m3 · risk low · verify kernel+file · local\n\
         TIME.TIMEZONE      UTC        desired UTC · risk low · verify symlink · local\n\
         OBSERVED LIVE AT REQUEST TIME\n"
    );
    assert_eq!(stdout(&output), expected);
}

// ---------------------------------------------------------------------------
// --json round-trips (the raw result, verbatim)
// ---------------------------------------------------------------------------

#[test]
fn json_status_round_trips_the_result_verbatim() {
    let socket = start_mock();
    let output = run(&socket, &["--json", "status"]);
    assert!(output.status.success());
    let parsed: Value = serde_json::from_str(&stdout(&output)).expect("stdout is JSON");
    assert_eq!(parsed, fixture_status());
}

#[test]
fn json_capabilities_round_trips_and_keeps_registry_field_names() {
    let socket = start_mock();
    let output = run(&socket, &["capabilities", "--json"]);
    assert!(output.status.success());
    let parsed: Value = serde_json::from_str(&stdout(&output)).expect("stdout is JSON");
    assert_eq!(parsed, fixture_capabilities());
    // Registry field names verbatim (Plate D-014 Sect III).
    let text = stdout(&output);
    for field in ["current_state", "managed_by", "verification"] {
        assert!(text.contains(field), "missing registry field {field}");
    }
}

#[test]
fn json_capabilities_get_and_audit_tail_and_reconcile() {
    let socket = start_mock();

    let get = run(
        &socket,
        &["--json", "capabilities", "get", "security.firewall"],
    );
    assert!(get.status.success());
    let parsed: Value = serde_json::from_str(&stdout(&get)).unwrap();
    assert_eq!(parsed, json!({"descriptor": firewall_descriptor()}));

    let tail = run(&socket, &["--json", "audit", "tail", "-n", "2"]);
    assert!(tail.status.success());
    let parsed: Value = serde_json::from_str(&stdout(&tail)).unwrap();
    let events = parsed["events"].as_array().unwrap();
    assert_eq!(events.len(), 2, "-n 2 must reach the daemon");
    assert_eq!(events[1]["event_id"], "evt_000003");

    let reconcile = run(&socket, &["--json", "reconcile"]);
    assert!(reconcile.status.success());
    let parsed: Value = serde_json::from_str(&stdout(&reconcile)).unwrap();
    assert_eq!(parsed, fixture_reconcile());
}

// ---------------------------------------------------------------------------
// Denial, probes, reachability (SPEC sections 60, 73, 74.4)
// ---------------------------------------------------------------------------

#[test]
fn denied_set_exits_3_with_the_section_73_voice() {
    let socket = start_mock();
    let output = run(
        &socket,
        &["capabilities", "set", "system.hostname", "mallory"],
    );
    assert_eq!(output.status.code(), Some(3), "denied must exit 3");
    assert!(stdout(&output).is_empty());
    let err = stderr(&output);
    assert!(err.contains("administrator"), "stderr: {err}");
    assert!(err.contains("personal defaults"), "stderr: {err}");
    assert!(err.contains("Next step"), "stderr: {err}");
    assert!(!err.contains("EPERM"), "stderr must never be an errno");
}

#[test]
fn successful_set_renders_a_verdict_and_json_reports_changed() {
    let socket = start_mock();
    let human = run(
        &socket,
        &["capabilities", "set", "system.hostname", "punar-m3"],
    );
    assert!(human.status.success(), "stderr: {}", stderr(&human));
    let text = stdout(&human);
    assert!(
        text.contains("✓ APPLIED · SYSTEM.HOSTNAME → PUNAR-M3 · VERIFIED"),
        "{text}"
    );

    let json_out = run(
        &socket,
        &[
            "--json",
            "capabilities",
            "set",
            "system.hostname",
            "punar-m3",
        ],
    );
    assert!(json_out.status.success());
    let parsed: Value = serde_json::from_str(&stdout(&json_out)).unwrap();
    assert_eq!(parsed["changed"], json!(true));
    assert_eq!(parsed["descriptor"]["current_state"], json!("punar-m3"));
}

#[test]
fn debug_rpc_probe_gets_unknown_method_and_exit_1() {
    let socket = start_mock();
    for probe in ["system.exec", "shell.run"] {
        let output = run(&socket, &["debug", "rpc", probe]);
        assert_eq!(output.status.code(), Some(1), "{probe} must exit 1");
        let err = stderr(&output);
        assert!(err.contains(probe), "stderr must name the method: {err}");
        assert!(err.contains("does not exist"), "stderr: {err}");
    }
}

#[test]
fn unreachable_daemon_exits_5_with_a_voiced_message() {
    let missing = std::env::temp_dir().join("punarctl-no-daemon-here.sock");
    let output = run(&missing, &["status"]);
    assert_eq!(output.status.code(), Some(5));
    let err = stderr(&output);
    assert!(err.contains("not reachable"), "stderr: {err}");
    assert!(err.contains("systemctl status punard"), "stderr: {err}");
}

#[test]
fn socket_flag_overrides_the_environment() {
    let socket = start_mock();
    let output = Command::new(env!("CARGO_BIN_EXE_punarctl"))
        .args(["--socket", socket.to_str().unwrap(), "--json", "status"])
        .env("PUNARD_SOCKET", "/definitely/not/here.sock")
        .env("NO_COLOR", "1")
        .output()
        .expect("run punarctl");
    assert!(output.status.success());
}

// ---------------------------------------------------------------------------
// Human audit + reconcile views (shape checks, not full snapshots)
// ---------------------------------------------------------------------------

#[test]
fn audit_tail_human_view_holds_decisions_and_columns() {
    let socket = start_mock();
    let output = run(&socket, &["audit", "tail"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("P U N A R   ·   A U D I T"));
    assert!(text.contains("2026-08-25 07:31:02"));
    assert!(text.contains("capabilities.set"));
    assert!(text.contains("ALLOW · SUCCESS"));
    assert!(text.contains("DENY · DENIED"));
    assert!(text.contains("evt_000003"));
    assert!(text.contains("LOCAL ONLY · NOTHING LEAVES THIS MACHINE"));
}

#[test]
fn reconcile_human_view_shows_the_m4_remediation() {
    let socket = start_mock();
    let output = run(&socket, &["reconcile"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("SECURITY.FIREWALL"), "{text}");
    assert!(text.contains("remediation applied"), "{text}");
    assert!(
        text.contains("✓ DRIFT REMEDIATED · 1 OF 3 CAPABILITIES · VERIFIED"),
        "{text}"
    );
    assert!(
        text.contains("EVERY ATTEMPT LANDS IN THE LOCAL AUDIT LOG"),
        "{text}"
    );
    // The M3 "reported only" wording must be gone against an M4 daemon.
    assert!(!text.contains("REPORTED ONLY"), "{text}");
}

// ---------------------------------------------------------------------------
// Policy verbs (M4 — contract sections 5.7/5.8, SPEC section 40)
// ---------------------------------------------------------------------------

#[test]
fn policy_effective_human_output_matches_the_d014_snapshot() {
    let socket = start_mock();
    let output = run(&socket, &["policy", "effective"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let context = format!("{} · Personal", local_hostname());
    let expected = format!(
        "{}\n{RULE}\n{}",
        masthead_line("P U N A R   ·   P O L I C Y", &context),
        "SECURITY.FIREWALL  ENABLED    Personal preference · personal-defaults\n\
         SYSTEM.HOSTNAME    PUNAR-M3   Personal preference · personal-defaults\n\
         TIME.TIMEZONE      UTC        OS default · personal-defaults\n\
         COMPUTED 2026-08-25 09:14:02 · MERGED FROM OS DEFAULTS + YOUR PREFERENCES\n"
    );
    assert_eq!(stdout(&output), expected);
}

#[test]
fn policy_explain_human_output_matches_the_spec_40_snapshot() {
    let socket = start_mock();
    let output = run(&socket, &["policy", "explain", "security.firewall"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    // The SPEC section 40 information set in the D-014 field-note grammar
    // (milestone-4.md section 7): EFFECTIVE VALUE / SOURCE / POLICY /
    // USER OVERRIDE / COMPLIANCE rows; source and policy names verbatim
    // in the mixed-case description column.
    let expected = format!(
        "{}\n{RULE}\n{}",
        masthead_line(
            "P U N A R   ·   P O L I C Y   E X P L A I N",
            "security.firewall"
        ),
        "EFFECTIVE VALUE  ENABLED\n\
         SOURCE                       Personal preference\n\
         POLICY                       personal-defaults\n\
         USER OVERRIDE                Permitted · it is your device\n\
         COMPLIANCE       COMPLIANT\n\
         MERGED FROM OS DEFAULTS + YOUR PREFERENCES\n"
    );
    assert_eq!(stdout(&output), expected);
}

#[test]
fn policy_explain_renders_the_os_default_source() {
    // Both source kinds must render (m4-check exercises both live):
    // time.timezone is untouched by any preference, so the OS default
    // (rank 6) wins.
    let socket = start_mock();
    let output = run(&socket, &["policy", "explain", "time.timezone"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("EFFECTIVE VALUE  UTC"), "{text}");
    assert!(text.contains("OS default"), "{text}");
    assert!(text.contains("personal-defaults"), "{text}");
    assert!(text.contains("Permitted"), "{text}");
}

#[test]
fn json_policy_effective_and_explain_round_trip_verbatim() {
    let socket = start_mock();

    let effective = run(&socket, &["--json", "policy", "effective"]);
    assert!(effective.status.success());
    let parsed: Value = serde_json::from_str(&stdout(&effective)).unwrap();
    assert_eq!(parsed, fixture_policy_effective());

    let explain = run(&socket, &["--json", "policy", "explain", "time.timezone"]);
    assert!(explain.status.success());
    let parsed: Value = serde_json::from_str(&stdout(&explain)).unwrap();
    assert_eq!(parsed, fixture_policy_explain("time.timezone").unwrap());
    // The winning-source fields keep their contract names verbatim.
    assert_eq!(parsed["source"]["kind"], json!("os_secure_default"));
    assert_eq!(parsed["source"]["rank"], json!(6));
    assert_eq!(parsed["user_override_permitted"], json!(true));
}

#[test]
fn policy_explain_unknown_path_exits_1_with_the_section_73_voice() {
    let socket = start_mock();
    let output = run(&socket, &["policy", "explain", "security.doesnotexist"]);
    assert_eq!(output.status.code(), Some(1), "not_found must exit 1");
    assert!(stdout(&output).is_empty());
    let err = stderr(&output);
    assert!(err.contains("security.doesnotexist"), "stderr: {err}");
    assert!(err.contains("punarctl policy effective"), "stderr: {err}");
    assert!(err.contains("Next step"), "stderr: {err}");
    assert!(!err.contains("ENOENT"), "stderr must never be an errno");
}

#[test]
fn policy_verbs_need_the_daemon_and_exit_5_without_it() {
    // M4 retired the local M3 "no policy engine yet" answer: the effective
    // document lives in punard, so an unreachable daemon is exit 5.
    let missing = std::env::temp_dir().join("punarctl-no-daemon-here.sock");
    for args in [
        ["policy", "effective"].as_slice(),
        ["policy", "explain", "security.firewall"].as_slice(),
    ] {
        let output = run(&missing, args);
        assert_eq!(output.status.code(), Some(5), "{args:?}");
        assert!(stderr(&output).contains("not reachable"), "{args:?}");
    }
}

// ---------------------------------------------------------------------------
// Governed update status
// ---------------------------------------------------------------------------

#[test]
fn update_status_is_typed_and_names_system_and_browser_evidence() {
    let socket = start_mock();
    let output = run(&socket, &["update", "status"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("P U N A R   ·   U P D A T E"), "{text}");
    assert!(text.contains("2026.08.30.1"), "{text}");
    assert!(text.contains("2026.09.01.1"), "{text}");
    assert!(text.contains("SYSTEM"), "{text}");
    assert!(text.contains("BROWSER"), "{text}");
    assert!(text.contains("151.0.7922.169-1"), "{text}");

    let json_output = run(&socket, &["--json", "update", "status"]);
    assert_eq!(json_output.status.code(), Some(0));
    assert_eq!(
        serde_json::from_str::<Value>(&stdout(&json_output)).unwrap(),
        fixture_update_status()
    );
}

// ---------------------------------------------------------------------------
// M5 enrollment verbs (contract sections 5.9–5.11, 7)
// ---------------------------------------------------------------------------

#[test]
fn enroll_start_renders_the_loud_simulated_label_and_json_round_trips() {
    let socket = start_mock();

    let output = run(&socket, &["enroll", "start", "acme.com"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("P U N A R   ·   E N R O L L"), "{text}");
    assert!(text.contains("ATTESTATION"), "{text}");
    // The honesty label, loud by design (milestone-5.md section 5.2).
    assert!(text.contains("SIMULATED"), "{text}");
    assert!(text.contains("Acme Engineering · acme.com"), "{text}");
    assert!(text.contains("eng-baseline-v12"), "{text}");
    assert!(text.contains("✓ ENROLLED · ACME ENGINEERING"), "{text}");

    let output = run(&socket, &["--json", "enroll", "start", "acme.com"]);
    assert_eq!(output.status.code(), Some(0));
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(value, fixture_enroll_start());
    // No device token anywhere in any enrollment output, ever.
    assert!(!stdout(&output).contains("tok_"));
}

#[test]
fn enroll_status_and_stop_render_and_round_trip() {
    let socket = start_mock();

    let output = run(&socket, &["enroll", "status"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("SIMULATED"), "{text}");
    assert!(text.contains("LAST SYNC"), "{text}");
    assert!(text.contains("SUCCESS"), "{text}");

    let output = run(&socket, &["--json", "enroll", "status"]);
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(value, fixture_enroll_status());

    // `enroll stop` without --yes: stdin is not a TTY under run(), so the
    // interactive confirmation is skipped by design (scripts and the
    // m5-check call it plainly).
    let output = run(&socket, &["enroll", "stop"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains("PERSONAL STATE RESTORED · ORG LAYERS REMOVED"),
        "{text}"
    );

    let output = run(&socket, &["--json", "enroll", "stop", "--yes"]);
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(value, fixture_enroll_stop());
}

#[test]
fn managed_status_renders_the_org_row_from_the_enroll_status_follow_up() {
    let socket = start_mock_with(managed_respond);
    let output = run(&socket, &["status"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("ORGANIZATION"), "{text}");
    // Display name + policy id (fetched via enroll.status; ipc.md § 7).
    assert!(
        text.contains("Acme Engineering · eng-baseline-v12"),
        "{text}"
    );
    assert!(text.contains("MANAGED"), "{text}");
    assert!(!text.contains("NO ORGANIZATION IS ENROLLED"), "{text}");

    // --json stays the status result verbatim — no follow-up merge.
    let output = run(&socket, &["--json", "status"]);
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(value["mode"], "managed");
    assert_eq!(value["org"]["id"], "acme");
    assert!(value.get("policy_ids").is_none());
}

#[test]
fn overridden_set_exits_0_with_the_recorded_not_applied_verdict() {
    let socket = start_mock_with(managed_respond);
    let output = run(
        &socket,
        &["capabilities", "set", "security.firewall", "disabled"],
    );
    // Recorded-but-overridden, not forbidden (SPEC section 39): exit 0.
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains(
            "RECORDED, NOT APPLIED · SECURITY.FIREWALL IS MANAGED BY \
             ACME ENGINEERING BASELINE (ENG-BASELINE-V12) · EFFECTIVE: ENABLED"
        ),
        "{text}"
    );

    // --json was already complete in M4: the raw result, no extra fields.
    let output = run(
        &socket,
        &[
            "--json",
            "capabilities",
            "set",
            "security.firewall",
            "disabled",
        ],
    );
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(value["changed"], false);
    assert_eq!(value["overridden"], true);
    assert_eq!(value["effective_state"], "enabled");
}

// ---------------------------------------------------------------------------
// M7 agent registry verbs (contract section 10 — the punar-agentd socket)
// ---------------------------------------------------------------------------

/// The `agents.list` example from docs/api/ipc.md section 10.2, verbatim.
fn fixture_agents_list() -> Value {
    json!({
        "scanned_at": "2026-08-27T10:00:02Z",
        "sessions": [
            {"session_id": "agt_4f21c09ab3e1", "agent": "claude-code",
             "version": "mock", "process_id": 2143, "user": "punar",
             "project": "atlas", "environment": "punar-env-atlas",
             "status": "active", "classification": "managed",
             "started_at": "2026-08-27T09:58:40Z",
             // M8 (contract section 12.4): counts only — no class names,
             // no evt_ ids, no zones.
             "ledger": {"resources": 5, "process_classes": 3,
                        "security_events": 1,
                        "updated_at": "2026-08-27T10:00:02Z"}}
        ],
        "detections": [
            {"session_id": "agt_d11e0aa7c402", "agent": "foo-agent",
             "version": "unknown", "process_id": 2410, "user": "punar",
             "project": "unknown", "environment": "host",
             "status": "active", "classification": "unknown",
             "started_at": "2026-08-27T09:59:55Z",
             "suspected": true, "executable": "/home/punar/Downloads/foo-agent",
             "signature_id": "downloads-foo-agent"}
        ]
    })
}

/// The `alerts.list` example (contract section 17.1): one card per
/// signature, in the milestone-10.md section 5.3 field list. Two rows so
/// `--all` has something to include and something to leave out.
fn fixture_alerts_list(include_dismissed: bool) -> Value {
    let live = json!({
        "alert_id": "alr_9f3c2a10bb41",
        "signature_id": "sig_7a18557a94d2",
        "agent": "foo-agent",
        "executable": "/home/punar/Downloads/foo-agent",
        "owner": "punar",
        "first_seen": "2026-08-27T09:59:55Z",
        "last_seen": "2026-08-27T10:00:02Z",
        "live": 1,
        "detection_id": "agt_d11e0aa7c402",
        "signature": "downloads-foo-agent",
        "policy_citation": "personal-defaults",
        "state": "live",
        "raised_at": "2026-08-27T09:59:55Z"
    });
    let filed = json!({
        "alert_id": "alr_2b7710dd0c93",
        "signature_id": "sig_3c99ab120fe4",
        "agent": "bar-agent",
        "executable": "/home/punar/Downloads/bar-agent",
        "owner": "punar",
        "first_seen": "2026-08-26T21:10:00Z",
        "last_seen": "2026-08-26T22:40:00Z",
        "live": 0,
        "detection_id": "agt_aa02bb44cc66",
        "signature": "downloads-agent-like",
        "policy_citation": "personal-defaults",
        "state": "dismissed",
        "raised_at": "2026-08-26T21:10:00Z",
        "cleared_at": "2026-08-26T22:40:00Z",
        "dismissed_at": "2026-08-26T22:41:00Z"
    });
    let alerts = if include_dismissed {
        json!([live, filed])
    } else {
        json!([live])
    };
    json!({"alerts": alerts, "quiet_window_secs": 86400})
}

/// The `agents.get` example (section 10.2): the row plus `scope_unit` and
/// the display-level authority summary captured at launch (section 10.3).
fn fixture_agent_get(session_id: &str) -> Option<Value> {
    let list = fixture_agents_list();
    let mut row = list["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .chain(list["detections"].as_array().unwrap())
        .find(|row| row["session_id"] == session_id)?
        .clone();
    if row["classification"] == "managed" {
        row["scope_unit"] = json!(format!("punar-agent-{session_id}.scope"));
        row["authority"] = json!({
            "policy_citation": "personal-defaults",
            "rows": [
                {"zone": "filesystem.project", "decision": "read_write",
                 "enforcement": "declared · M9"},
                {"zone": "network.internet", "decision": "allow",
                 "enforcement": "enforced (agent scope)"},
                {"zone": "network.corp_prod", "decision": "deny",
                 "enforcement": "enforced (agent scope)"},
                {"zone": "credentials.aws_dev", "decision": "request",
                 "enforcement": "declared · M9"}
            ]
        });
    }
    Some(json!({ "session": row }))
}

/// The `agents.access` example from docs/api/ipc.md section 12.2, verbatim:
/// the schema-exact `summary` document plus the sibling fields the schema
/// deliberately cannot hold.
fn fixture_agents_access() -> Value {
    json!({
        "summary": {
            "session_id": "agt_4f21c09ab3e1",
            "agent": "claude-code",
            "generated_at": "2026-08-27T10:00:02Z",
            "resources": {
                "repositories": ["atlas"],
                "directory_zones": ["workspace"],
                "network_destinations": ["127.0.0.9"],
                "mcp_servers": [],
                "credential_classes": [],
                "process_classes": ["agent", "git", "shell"]
            },
            "security_events": [
                {"event_id": "evt_502", "event_type": "denied_access",
                 "timestamp": "2026-08-27T09:59:12Z"}
            ]
        },
        "detail": {
            "status": "active",
            "process_peak": 6,
            "truncated": false,
            "entries": [
                {"category": "repositories", "resource_class": "atlas", "count": 1,
                 "first_seen": "2026-08-27T09:58:40Z", "last_seen": "2026-08-27T09:58:40Z",
                 "evidence": "workspace_bind"},
                {"category": "directory_zones", "resource_class": "workspace", "count": 1,
                 "first_seen": "2026-08-27T09:58:40Z", "last_seen": "2026-08-27T09:58:40Z",
                 "evidence": "workspace_bind"},
                {"category": "process_classes", "resource_class": "git", "count": 2,
                 "first_seen": "2026-08-27T09:58:44Z", "last_seen": "2026-08-27T10:00:02Z",
                 "evidence": "cgroup_scope"},
                {"category": "process_classes", "resource_class": "shell", "count": 3,
                 "first_seen": "2026-08-27T09:58:44Z", "last_seen": "2026-08-27T10:00:02Z",
                 "evidence": "cgroup_scope"},
                {"category": "process_classes", "resource_class": "agent", "count": 1,
                 "first_seen": "2026-08-27T09:58:40Z", "last_seen": "2026-08-27T10:00:02Z",
                 "evidence": "cgroup_scope"},
                {"category": "network_destinations", "resource_class": "127.0.0.9", "count": 1,
                 "first_seen": "2026-08-27T09:59:00Z", "last_seen": "2026-08-27T10:00:02Z",
                 "evidence": "netd_aggregate"}
            ]
        },
        "not_yet_observed": [
            {"level": 3, "category": "mcp_servers", "milestone": "M11+",
             "reason": "no tool/MCP gateway mediates MCP traffic yet"}
        ],
        "retention": {"days": 14, "active": true},
        "privacy": {
            "local_only": true,
            "purge_command": "punarctl privacy purge --session agt_4f21c09ab3e1",
            "never_recorded": ["file paths inside the workspace", "prompts",
                               "source code", "secret values", "individual file reads"],
            "audit_trail_separate": true
        }
    })
}

/// `ledger.purge` result (contract section 12.3).
fn fixture_ledger_purge() -> Value {
    json!({"purged": 1, "resource_classes": 5, "security_events": 1,
           "purged_at": "2026-08-27T10:05:00Z"})
}

/// The mock `punar-agentd`: the same envelope, the closed M7 method table,
/// and the reserved-name answers the contract prescribes (section 10.2).
/// The M10 `queries.list` result: two answered, one refused — the shape
/// milestone-10.md section 10.3 draws. Note what it does **not** carry:
/// no payloads, no paths, no pids. The record says who asked what and what
/// was decided, and that is all it is able to say.
fn fixture_queries_list() -> Value {
    json!({
        "enrolled": true,
        "organization": "acme.com",
        "policy_citation": "Acme Engineering · eng-ai-v3",
        "granted_scopes": ["inventory", "authority"],
        "admin_identity_verified": false,
        "never_answered": [
            "prompts and conversation content",
            "source code, file contents, diffs",
            "file paths (zone classes only)",
            "command lines, argv, environment variables",
            "secret values and credential material",
            "audit event payloads",
            "anything outside the granted scope"
        ],
        "storage": {
            "path": "/var/lib/punar/agents/queries.jsonl",
            "retention_days": 365,
            "max_records": 10000,
            "purged_by_privacy_purge": false
        },
        "queries": [
            {"query_id": "qry_7c1a00000001", "received_at": "2026-08-25T13:40:00Z",
             "answered_at": "2026-08-25T13:40:02Z", "requesting_admin": "cio@acme.com",
             "admin_identity_verified": false, "organization": "acme.com",
             "device_id": "dev_1", "requested_scope": "authority",
             "granted_scope": "authority", "authorization_decision": "allow",
             "result_category": "answered",
             "record_counts": {"sessions": 1, "detections": 0, "security_events": 0},
             "audit_event_id": "evt_609"},
            {"query_id": "qry_7c1a00000002", "received_at": "2026-08-25T13:58:00Z",
             "answered_at": "2026-08-25T13:58:03Z", "requesting_admin": "cio@acme.com",
             "admin_identity_verified": false, "organization": "acme.com",
             "device_id": "dev_1", "requested_scope": "inventory",
             "granted_scope": "inventory", "authorization_decision": "allow",
             "result_category": "answered",
             "record_counts": {"sessions": 1, "detections": 1, "security_events": 0},
             "audit_event_id": "evt_610"},
            {"query_id": "qry_7c1a00000003", "received_at": "2026-08-25T14:02:09Z",
             "answered_at": "2026-08-25T14:02:11Z", "requesting_admin": "secops@acme.com",
             "admin_identity_verified": false, "organization": "acme.com",
             "device_id": "dev_1", "requested_scope": "resource_summary",
             "granted_scope": null, "authorization_decision": "deny",
             "refusal_reason": "out_of_scope", "result_category": "refused",
             "record_counts": {"sessions": 0, "detections": 0, "security_events": 0},
             "audit_event_id": "evt_611"}
        ]
    })
}

fn agents_respond(request: &Value) -> Result<Value, Value> {
    assert_eq!(request["v"], json!(1), "client must send v: 1");
    let method = request["method"].as_str().expect("method must be a string");
    match method {
        "agents.list" => {
            assert!(
                request.get("params").is_none(),
                "no-param methods omit params entirely"
            );
            Ok(fixture_agents_list())
        }
        // M10: `agents.scan` may carry a trigger, and an absent one means
        // `manual` — decided by the daemon, never filled in by the CLI
        // (milestone-10.md section 3.4).
        "agents.scan" => {
            if let Some(params) = request.get("params") {
                let trigger = params["trigger"].as_str().expect("trigger is a string");
                assert!(
                    ["manual", "timer", "register", "enroll"].contains(&trigger),
                    "the trigger vocabulary is closed: {trigger}"
                );
            }
            Ok(fixture_agents_list())
        }
        "alerts.list" => {
            let include = request
                .get("params")
                .and_then(|p| p.get("include_dismissed"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Ok(fixture_alerts_list(include))
        }
        "alerts.dismiss" => {
            let id = request["params"]["alert_id"]
                .as_str()
                .expect("alert_id param")
                .to_string();
            if id == "alr_9f3c2a10bb41" {
                Ok(json!({
                    "dismissed": true,
                    "alert_id": id,
                    "dismissed_at": "2026-08-27T10:05:00Z",
                    "suppression_changed": false
                }))
            } else {
                Err(json!({
                    "code": "not_found",
                    "message": format!("No alert with id {id:?} is in the register."),
                    "details": {"alert_id": id}
                }))
            }
        }
        "agents.get" => {
            let id = request["params"]["session_id"]
                .as_str()
                .expect("session_id param")
                .to_string();
            fixture_agent_get(&id).ok_or_else(|| {
                json!({
                    "code": "not_found",
                    "message": format!(
                        "No AI agent session {id} is known to the registry.\n\
                         Next step: punarctl agents list"
                    ),
                    "details": {"param": "session_id", "session_id": id}
                })
            })
        }
        // M8 (contract section 12.2). Ownership is the daemon's call: the
        // mock refuses one id outright so the CLI's exit-3 path is real.
        "agents.access" => {
            let Some(id) = request
                .get("params")
                .and_then(|p| p.get("session_id"))
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                return Err(json!({
                    "code": "invalid_params",
                    "message": "agents.access needs a session_id.\n\
                                Next step: punarctl agents list",
                    "details": {"param": "session_id"}
                }));
            };
            match id.as_str() {
                "agt_4f21c09ab3e1" => Ok(fixture_agents_access()),
                "agt_someoneelse" => Err(json!({
                    "code": "denied",
                    "message": "The access ledger for agt_someoneelse belongs to another \
                                user.\nWhy: a ledger is personal data — only the session's \
                                owner or root may read it.\nNext step: ask that user, or \
                                re-run as root: sudo punarctl agents access agt_someoneelse",
                    "details": {"session_id": id}
                })),
                _ => Err(json!({
                    "code": "not_found",
                    "message": format!(
                        "No AI agent session {id} has an access ledger on this device.\n\
                         Next step: punarctl agents list"
                    ),
                    "details": {"param": "session_id", "session_id": id}
                })),
            }
        }
        // M10 (contract section 13.1): the user's own query log. Readable
        // by any admitted peer — SPEC section 24.2.
        "queries.list" => Ok(fixture_queries_list()),
        // M8 (contract section 12.3): exactly one of session_id / all.
        "ledger.purge" => {
            let params = request.get("params");
            let one = params.and_then(|p| p.get("session_id")).is_some();
            let all = params
                .and_then(|p| p.get("all"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if one == all {
                return Err(json!({
                    "code": "invalid_params",
                    "message": "ledger.purge needs exactly one of session_id or all.",
                    "details": {"param": "session_id|all"}
                }));
            }
            Ok(fixture_ledger_purge())
        }
        other => Err(json!({
            "code": "unknown_method",
            "message": format!(
                "The method \"{other}\" does not exist. The punar-agentd IPC method table \
                 is closed and typed; there is no generic execution method, by design \
                 (spec sections 10 and 60).\n\
                 Next step: run `punarctl --help` for the supported commands."
            ),
            "details": {"method": other}
        })),
    }
}

/// Start the mock agent registry; the returned path goes in
/// `PUNAR_AGENTD_SOCKET`.
fn start_agentd_mock() -> PathBuf {
    start_mock_with(agents_respond)
}

/// Run punarctl with **both** sockets pointed at mocks, so a mis-routed
/// call fails loudly instead of silently hitting the other daemon.
fn run_agents(agentd: &PathBuf, args: &[&str]) -> Output {
    let punard = start_mock();
    Command::new(env!("CARGO_BIN_EXE_punarctl"))
        .args(args)
        .env("PUNARD_SOCKET", punard)
        .env("PUNAR_AGENTD_SOCKET", agentd)
        .env("NO_COLOR", "1")
        .output()
        .expect("run punarctl")
}

#[test]
fn agents_list_renders_the_registry_and_says_suspected() {
    let agentd = start_agentd_mock();
    let output = run_agents(&agentd, &["agents", "list"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);

    assert!(text.contains("P U N A R   ·   A I   A G E N T S"), "{text}");
    assert!(text.contains(RULE), "{text}");
    // The managed session and the detection share one row model.
    let managed = text
        .lines()
        .find(|l| l.starts_with("AGT_4F21C09AB3E1"))
        .unwrap_or_default();
    assert!(managed.contains("claude-code"), "{text}");
    assert!(managed.contains("atlas"), "{text}");
    assert!(managed.contains("MANAGED"), "{text}");
    assert!(managed.contains("ACTIVE"), "{text}");
    assert!(managed.contains("2026-08-27 09:58:40"), "{text}");

    // SPEC section 23: the unknown row never claims certainty.
    let unknown = text
        .lines()
        .find(|l| l.starts_with("AGT_D11E0AA7C402"))
        .unwrap_or_default();
    assert!(unknown.contains("foo-agent"), "{text}");
    assert!(unknown.contains("UNKNOWN · SUSPECTED"), "{text}");
    assert!(
        text.contains("DETECTION IS HEURISTIC — SUSPECTED, NOT CERTAIN"),
        "{text}"
    );
    // M7 promised "continuous detection arrives in Milestone 10" here and
    // this test asserted that string. M10 shipped the timer, so the
    // footer now states the INVARIANT the promise was standing in for:
    // the cadence is real, and sampling detection has a hole that no
    // cadence closes (milestone-10.md section 3.2).
    assert!(text.contains("CONTINUOUS · EVERY 4 MIN"), "{text}");
    assert!(
        text.contains("STARTS AND EXITS INSIDE ONE INTERVAL IS NOT SEEN"),
        "{text}"
    );
    assert!(
        !text.contains("ARRIVES IN MILESTONE 10"),
        "the deferral was fulfilled; the footer must not still defer: {text}"
    );
    assert!(text.contains("1 SESSION · 1 SUSPECTED"), "{text}");
    // Unmanaged-first: no org chrome on a personal device.
    assert!(!text.to_lowercase().contains("organization"), "{text}");
}

/// `agents scan` forces a pass now and renders the same view as `list`
/// (hidden verb — the advertised surface stays list/inspect).
#[test]
fn agents_scan_forces_a_pass_and_renders_the_list_view() {
    let agentd = start_agentd_mock();
    let output = run_agents(&agentd, &["agents", "scan"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("P U N A R   ·   A I   A G E N T S"), "{text}");
    assert!(text.contains("UNKNOWN · SUSPECTED"), "{text}");

    let output = run_agents(&agentd, &["--json", "agents", "scan"]);
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(value, fixture_agents_list());
}

/// M10: the alert register, in the same voice as the D-009 card. The
/// words are the assertion — a surface that renders a red row and implies
/// something was blocked is worse than no surface (law 4, spec 1.22).
#[test]
fn agents_alerts_renders_the_register_and_never_claims_an_action() {
    let agentd = start_agentd_mock();
    let output = run_agents(&agentd, &["agents", "alerts"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);

    assert!(text.contains("P U N A R   ·   A I   A L E R T S"), "{text}");
    // Suspected, never certain (spec 23) — in the header and in the row.
    assert!(text.to_uppercase().contains("SUSPECTED"), "{text}");
    assert!(text.contains("ALR_9F3C2A10BB41"), "{text}");
    // The executable path is Level-1 LOCAL data: the user sees it here,
    // and the export carries a zone class instead (section 8.3).
    assert!(text.contains("/home/punar/Downloads/foo-agent"), "{text}");
    assert!(text.contains("downloads-foo-agent"), "{text}");
    assert!(text.contains("sig_7a18557a94d2"), "{text}");
    assert!(text.to_uppercase().contains("POLICY"), "{text}");
    // `fmt::rows` uppercases label and value — the standing lesson that
    // every rendered-word assertion is case-insensitive.
    assert!(text.to_uppercase().contains("PERSONAL DEFAULTS"), "{text}");
    // The anti-nag rule is stated from the daemon's own value.
    assert!(text.to_uppercase().contains("24 H"), "{text}");
    // Law 4, in words, because a user who believes they are protected
    // when they are not is worse off than one who knows.
    assert!(
        text.to_uppercase().contains("NOTHING WAS BLOCKED"),
        "{text}"
    );
    // The plate's `→ api.foo.ai` is a datum no code produces before M12.
    assert!(!text.contains("api.foo.ai"), "{text}");
    // And no dead buttons anywhere: M10 renders no action it cannot take.
    assert!(!text.to_uppercase().contains("BLOCK NETWORK"), "{text}");
    // Live cards only, unless asked.
    assert!(!text.contains("bar-agent"), "{text}");

    let output = run_agents(&agentd, &["agents", "alerts", "--all"]);
    let text = stdout(&output);
    assert!(text.contains("bar-agent"), "{text}");
    assert!(text.to_uppercase().contains("NOT DELETED"), "{text}");
}

/// Dismissal files a card. It never destroys one, and it never moves
/// suppression — because there is none to move (section 5.2).
#[test]
fn agents_alerts_dismiss_files_the_card_and_says_that_plainly() {
    let agentd = start_agentd_mock();
    let output = run_agents(
        &agentd,
        &["agents", "alerts", "dismiss", "alr_9f3c2a10bb41"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output).to_uppercase();
    assert!(text.contains("DISMISSED"), "{text}");
    assert!(text.contains("FILED TO THE RECORD"), "{text}");
    assert!(text.contains("NOT DELETED"), "{text}");
    assert!(text.contains("UNCHANGED"), "{text}");

    let output = run_agents(&agentd, &["agents", "alerts", "dismiss", "alr_nosuchcard"]);
    assert_eq!(output.status.code(), Some(1), "not_found must exit 1");
    assert!(
        stderr(&output).contains("No alert with id"),
        "{}",
        stderr(&output)
    );
}

/// The trigger travels to the daemon or is absent; the CLI never fills in
/// a default, because a CLI that labelled a typed command as a timer would
/// destroy the one property `m10-check` group 3 exists to prove.
#[test]
fn agents_scan_carries_the_trigger_and_invents_none() {
    let agentd = start_agentd_mock();
    for trigger in ["manual", "timer", "register", "enroll"] {
        let output = run_agents(&agentd, &["agents", "scan", "--trigger", trigger]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{trigger}: {}",
            stderr(&output)
        );
    }
    // The vocabulary is closed at the CLI too: an invented trigger never
    // reaches the socket.
    let output = run_agents(&agentd, &["agents", "scan", "--trigger", "cron"]);
    assert_ne!(output.status.code(), Some(0));
}

#[test]
fn agents_inspect_renders_authority_then_the_real_ledger_register() {
    let agentd = start_agentd_mock();
    let output = run_agents(&agentd, &["agents", "inspect", "agt_4f21c09ab3e1"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);

    // Attribution masthead (SPEC section 22) — the D-005 identity line.
    assert!(text.contains("P U N A R   ·   A G E N T"), "{text}");
    assert!(
        text.contains("AGT_4F21C09AB3E1 · MANAGED · ACTIVE"),
        "{text}"
    );
    assert!(
        text.contains("AGT_4F21C09AB3E1 · PUNAR · PUNAR-ENV-ATLAS · STARTED 2026-08-27 09:58:40"),
        "{text}"
    );
    assert!(
        text.contains("PUNAR-AGENT-AGT_4F21C09AB3E1.SCOPE") || text.contains("SCOPE"),
        "{text}"
    );

    // Authority · what it may access, citing its named source.
    assert!(text.contains("AUTHORITY · WHAT IT MAY ACCESS"), "{text}");
    assert!(text.contains("POLICY · PERSONAL DEFAULTS"), "{text}");
    assert!(text.contains("FILESYSTEM.PROJECT"), "{text}");
    assert!(text.contains("READ_WRITE"), "{text}");
    // Every authority row wears its current enforcement state (SPEC 1.22).
    for line in text.lines().filter(|l| l.starts_with("NETWORK.")) {
        assert!(line.contains("enforced (agent scope)"), "{line}");
    }
    for line in text.lines().filter(|l| l.starts_with("CREDENTIALS.")) {
        assert!(line.contains("declared · M"), "{line}");
    }
    assert!(
        text.contains("NETWORK AUTHORITY IS ENFORCED FOR MANAGED AGENT SCOPES"),
        "{text}"
    );

    // Ledger · what it accessed — real since M8, fetched by the
    // best-effort `agents.access` follow-up and rendered under authority.
    assert!(text.contains("LEDGER · WHAT IT ACCESSED"), "{text}");
    assert!(text.contains("REPOSITORIES"), "{text}");
    assert!(text.contains("ATLAS"), "{text}");
    assert!(text.contains("GIT × 2 · SHELL × 3"), "{text}");
    // The May/Did split stays structural: two registers, two questions.
    let authority_at = text.find("AUTHORITY · WHAT IT MAY ACCESS").unwrap();
    let ledger_at = text.find("LEDGER · WHAT IT ACCESSED").unwrap();
    assert!(authority_at < ledger_at, "{text}");
}

#[test]
fn agents_inspect_renders_a_detection_as_suspected_with_no_authority() {
    let agentd = start_agentd_mock();
    let output = run_agents(&agentd, &["agents", "inspect", "agt_d11e0aa7c402"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains("AGT_D11E0AA7C402 · UNKNOWN · SUSPECTED"),
        "{text}"
    );
    assert!(text.contains("/home/punar/Downloads/foo-agent"), "{text}");
    assert!(
        text.contains("downloads-foo-agent · heuristic match"),
        "{text}"
    );
    assert!(text.contains("IDENTITY · OBSERVED"), "{text}");
    assert!(
        text.contains("DETECTION IS HEURISTIC — SUSPECTED, NOT CERTAIN"),
        "{text}"
    );
    // A detection was never launched through the runtime: it has no
    // authority to show, and none is invented.
    assert!(!text.contains("AUTHORITY · WHAT IT MAY ACCESS"), "{text}");
    // No dead buttons in a terminal either: the D-005 unknown-view actions
    // are M9/M10 capabilities and are not offered.
    assert!(!text.to_uppercase().contains("BLOCK NETWORK"), "{text}");
}

#[test]
fn agents_json_round_trips_the_result_verbatim() {
    let agentd = start_agentd_mock();

    let output = run_agents(&agentd, &["--json", "agents", "list"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(value, fixture_agents_list());
    // Registry field names are the schema's, unchanged by the CLI.
    assert_eq!(value["sessions"][0]["classification"], "managed");
    assert_eq!(value["detections"][0]["suspected"], true);

    let output = run_agents(
        &agentd,
        &["--json", "agents", "inspect", "agt_4f21c09ab3e1"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(value, fixture_agent_get("agt_4f21c09ab3e1").unwrap());
}

#[test]
fn agents_inspect_of_an_unknown_id_exits_1_with_the_section_73_voice() {
    let agentd = start_agentd_mock();
    let output = run_agents(&agentd, &["agents", "inspect", "agt_nosuchsession"]);
    assert_eq!(output.status.code(), Some(1));
    let text = stderr(&output);
    assert!(text.contains("No AI agent session"), "{text}");
    assert!(text.contains("Next step"), "{text}");
}

/// Routing (contract section 10.5): `agents.*` goes to the sibling socket,
/// and an unreachable registry names *its* unit in the next step — never
/// punard's.
#[test]
fn agents_verbs_reach_the_agentd_socket_and_name_it_when_it_is_missing() {
    let punard = start_mock();
    let missing = std::env::temp_dir().join("punarctl-no-agentd-here.sock");
    let output = Command::new(env!("CARGO_BIN_EXE_punarctl"))
        .args(["agents", "list"])
        .env("PUNARD_SOCKET", &punard)
        .env("PUNAR_AGENTD_SOCKET", &missing)
        .env("NO_COLOR", "1")
        .output()
        .expect("run punarctl");
    assert_eq!(output.status.code(), Some(5), "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("not reachable"), "{text}");
    assert!(text.contains("systemctl status punar-agentd"), "{text}");
}

/// The SPEC section 74.4 negative probes on the new socket: an unknown
/// `agents.*` name auto-routes there, and `--socket agentd` forces any
/// other name to it. Both must answer `unknown_method`, never anything
/// executable (SPEC sections 10, 60).
#[test]
fn debug_probes_on_the_agentd_socket_get_unknown_method() {
    let agentd = start_agentd_mock();

    let output = run_agents(&agentd, &["debug", "rpc", "agents.bogus"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("does not exist"),
        "{}",
        stderr(&output)
    );

    let output = run_agents(
        &agentd,
        &["debug", "rpc", "admin.query", "--socket", "agentd"],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("does not exist"),
        "{}",
        stderr(&output)
    );

    // agents.access exists since M8, so the bare probe (no params) is a
    // typed parameter error — not a reserved-name answer, and never
    // anything executable.
    let output = run_agents(&agentd, &["debug", "rpc", "agents.access"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("needs a session_id"),
        "{}",
        stderr(&output)
    );

    // `ledger.export`, `ledger.query` and `admin.*` do not exist: there is
    // no upload path in M8 (contract section 12.1).
    for method in ["ledger.export", "ledger.query", "admin.query"] {
        let output = run_agents(&agentd, &["debug", "rpc", method, "--socket", "agentd"]);
        assert_eq!(output.status.code(), Some(1), "{method}");
        assert!(stderr(&output).contains("does not exist"), "{method}");
    }

    // M10 routing (contract section 10.5): the alert register and the two
    // remote-query methods belong to the daemon that owns the data, and a
    // bare probe must reach it WITHOUT `--socket`. If it reached punard
    // instead, the answer would still be `unknown_method` — from the wrong
    // daemon — and a probe that hides which thing said no is worse than no
    // probe. The mock agentd here answers these names, so a mis-route
    // fails loudly rather than looking like a refusal.
    let output = run_agents(&agentd, &["debug", "rpc", "alerts.list"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let listed: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(listed["quiet_window_secs"], json!(86400), "{listed}");

    // `--params` makes a negative probe SPECIFIC: this is a well-formed
    // question refused, not a request with no params rejected.
    let output = run_agents(
        &agentd,
        &[
            "debug",
            "rpc",
            "alerts.dismiss",
            "--params",
            r#"{"alert_id":"alr_nosuchcard"}"#,
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("No alert with id"),
        "{}",
        stderr(&output)
    );

    // A typo in the probe is refused by the CLI, before any socket is
    // dialled: a daemon answering `invalid_params` to a broken --params
    // would look like a daemon refusing the method.
    let output = run_agents(
        &agentd,
        &["debug", "rpc", "alerts.list", "--params", "{oops"],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("not valid JSON"),
        "{}",
        stderr(&output)
    );
}

// ---------------------------------------------------------------------------
// M8 AI Access Ledger (contract sections 12–13)
// ---------------------------------------------------------------------------

#[test]
fn agents_access_renders_the_ledger_register_with_counts_and_honest_gaps() {
    let agentd = start_agentd_mock();
    let output = run_agents(&agentd, &["agents", "access", "agt_4f21c09ab3e1"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);

    assert!(
        text.contains("P U N A R   ·   A I   A C C E S S   L E D G E R"),
        "{text}"
    );
    assert!(text.contains(RULE), "{text}");
    assert!(text.contains("LEDGER · WHAT IT ACCESSED"), "{text}");

    // Level 3: the observed categories, with counts and the mediation
    // point that proved them.
    assert!(text.contains("REPOSITORIES"), "{text}");
    assert!(text.contains("ATLAS"), "{text}");
    assert!(text.contains("workspace bind"), "{text}");
    assert!(text.contains("DIRECTORY ZONES"), "{text}");
    assert!(text.contains("WORKSPACE"), "{text}");
    assert!(text.contains("AGENT × 1 · GIT × 2 · SHELL × 3"), "{text}");
    assert!(text.contains("cgroup scope"), "{text}");
    assert!(text.contains("peak 6 concurrent"), "{text}");
    // The count qualifier travels with the count, always.
    assert!(
        text.contains("SHORT-LIVED CHILDREN MAY BE MISSED"),
        "{text}"
    );

    // M12's bounded network aggregate renders as observed, with no port.
    assert!(text.contains("NETWORK DESTINATIONS"), "{text}");
    assert!(text.contains("127.0.0.9"), "{text}");
    assert!(text.contains("netd aggregate"), "{text}");
    assert!(text.contains("MCP SERVERS"), "{text}");
    assert!(text.contains("NOT YET OBSERVED · M11+"), "{text}");
    assert!(text.contains("CREDENTIAL CLASSES"), "{text}");

    // Level 4: the event reference, and where the payload actually lives.
    assert!(text.contains("SECURITY EVENTS · LEVEL 4"), "{text}");
    assert!(text.contains("DENIED ACCESS"), "{text}");
    assert!(text.contains("evt_502"), "{text}");
    assert!(text.contains("PUNARCTL AUDIT TAIL"), "{text}");
    // Produced Level-4 categories with no event are facts, not pending
    // promises; only the event that occurred is rendered.
    assert!(!text.contains("CREDENTIAL REQUEST (M9)"), "{text}");
    assert!(!text.contains("PRODUCTION ACCESS (M12)"), "{text}");

    // Retention + the section 24.2 guarantee.
    assert!(text.contains("14 days after the session ends"), "{text}");
    assert!(text.contains("/var/lib/punar/agents/ledger"), "{text}");
    assert!(text.contains("NEVER RECORDED"), "{text}");
    assert!(text.contains("prompts"), "{text}");
    assert!(
        text.contains("punarctl privacy purge --session agt_4f21c09ab3e1"),
        "{text}"
    );
    // M8 wrote the `REMOTE QUERY` row as a placeholder naming Milestone 10.
    // M10 fulfils it, so the assertion is restated as the invariant the
    // placeholder was protecting: nothing is uploaded continuously, and the
    // user has a command that shows every question that was asked.
    assert!(text.contains("REMOTE QUERY"), "{text}");
    assert!(text.contains("never continuous"), "{text}");
    assert!(text.contains("punarctl privacy queries"), "{text}");

    // Nothing section 21.2 forbids can appear, because nothing carries it.
    assert!(!text.contains("/home/"), "{text}");
    assert!(!text.to_lowercase().contains("cmdline"), "{text}");
}

#[test]
fn agents_access_json_round_trips_the_result_verbatim() {
    let agentd = start_agentd_mock();
    let output = run_agents(&agentd, &["--json", "agents", "access", "agt_4f21c09ab3e1"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(value, fixture_agents_access());
    // `result.summary` alone is the schema-exact ledger-summary.json
    // document — the artifact a future authorized query would return.
    let summary = &value["summary"];
    for key in ["session_id", "agent", "generated_at", "resources"] {
        assert!(summary.get(key).is_some(), "{key}");
    }
    for key in [
        "repositories",
        "directory_zones",
        "network_destinations",
        "mcp_servers",
        "credential_classes",
        "process_classes",
    ] {
        assert!(summary["resources"][key].is_array(), "{key}");
    }
}

#[test]
fn agents_access_of_another_users_session_exits_3_with_the_section_73_voice() {
    let agentd = start_agentd_mock();
    let output = run_agents(&agentd, &["agents", "access", "agt_someoneelse"]);
    assert_eq!(output.status.code(), Some(3), "denied must exit 3");
    let text = stderr(&output);
    assert!(text.contains("personal data"), "{text}");
    assert!(text.contains("Next step"), "{text}");

    let output = run_agents(&agentd, &["agents", "access", "agt_nosuchthing"]);
    assert_eq!(output.status.code(), Some(1), "not_found must exit 1");
    assert!(stderr(&output).contains("punarctl agents list"));
}

#[test]
fn privacy_ledger_states_what_is_recorded_and_what_never_is() {
    let agentd = start_agentd_mock();
    let output = run_agents(&agentd, &["privacy", "ledger"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);

    assert!(text.contains("P U N A R   ·   P R I V A C Y"), "{text}");
    assert!(
        text.contains("LOCAL AI LEDGER · WHAT THIS DEVICE RECORDED"),
        "{text}"
    );
    assert!(text.contains("WHAT IS RECORDED"), "{text}");
    assert!(text.contains("1 SESSION"), "{text}");
    assert!(text.contains("claude-code · atlas"), "{text}");
    // The never-record list is as prominent as the record itself (24.2).
    assert!(text.contains("NEVER RECORDED"), "{text}");
    assert!(text.contains("source code"), "{text}");
    assert!(text.contains("secret values"), "{text}");
    assert!(text.contains("RETENTION"), "{text}");
    assert!(text.contains("14 days after a session ends"), "{text}");
    assert!(
        text.contains("punarctl privacy purge --session <id>"),
        "{text}"
    );
    // M10: the device-wide row is live — three queries, one refused, read
    // from the daemon's own log rather than from a CLI-side constant.
    assert!(text.contains("REMOTE QUERY"), "{text}");
    assert!(text.contains("3 queries · 1 refused"), "{text}");
    assert!(text.contains("punarctl privacy queries"), "{text}");
    assert!(
        !text.contains("no upload path exists"),
        "the M8 placeholder is gone, not merely hidden: {text}"
    );
    // M8 rendered "a detection has no ledger · Milestone 10" here and this
    // test asserted the milestone tag. M10 landed the unknown-agent
    // ledger, so the invariant to assert is the one that outlives both
    // milestones: a suspected process is NAMED on this surface, its
    // ledger's shape is stated, and its shorter retention window is
    // stated with it (milestone-10.md sections 6.3, 6.5).
    assert!(text.contains("SUSPECTED AI PROCESS"), "{text}");
    assert!(text.contains("BOUNDED DETECTION LEDGER"), "{text}");
    assert!(text.contains("7 DAYS AFTER IT CLEARS"), "{text}");
    assert!(
        !text.contains("NO ACCESS LEDGER IN MILESTONE 8"),
        "the open question was closed; the surface must not still pose it: {text}"
    );

    // One session: the same register, opened from the privacy side.
    let output = run_agents(&agentd, &["privacy", "ledger", "agt_4f21c09ab3e1"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains("LEDGER · WHAT IT ACCESSED"));

    // `--session` is the same argument, spelled for symmetry with purge.
    let flagged = run_agents(
        &agentd,
        &["privacy", "ledger", "--session", "agt_4f21c09ab3e1"],
    );
    assert_eq!(stdout(&flagged), stdout(&output));
}

/// M10 (milestone-10.md section 10.3): the SPEC section 24.2 command.
/// Every question, who asked it, what scope, and what this device decided —
/// with the honesty label on the identity and the never-answered list as
/// prominent as the record itself.
#[test]
fn privacy_queries_shows_who_asked_and_what_was_refused() {
    let agentd = start_agentd_mock();
    let output = run_agents(&agentd, &["privacy", "queries"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);

    assert!(text.contains("P U N A R   ·   P R I V A C Y"), "{text}");
    assert!(text.contains(RULE), "{text}");
    assert!(text.contains("WHO ASKED ABOUT THIS DEVICE"), "{text}");
    assert!(
        text.contains("3 QUERIES · 2 ANSWERED · 1 REFUSED"),
        "{text}"
    );

    // Each row: when, who, at what scope, and the verdict.
    let refused = text
        .lines()
        .find(|l| l.contains("SECOPS@ACME.COM"))
        .unwrap_or_default();
    assert!(refused.contains("RESOURCE_SUMMARY"), "{text}");
    assert!(refused.contains("refused · out of scope"), "{text}");
    assert!(refused.contains("evt_611"), "{text}");

    let answered = text
        .lines()
        .find(|l| l.contains("13:58") && l.contains("CIO@ACME.COM"))
        .unwrap_or_default();
    assert!(answered.contains("INVENTORY"), "{text}");
    // The *shape* of what left, never a second copy of the contents.
    assert!(answered.contains("1 session"), "{text}");
    assert!(answered.contains("1 detection"), "{text}");

    // SPEC section 9.1's honesty label, on every rendering of an admin.
    assert!(
        text.contains("asserted by acme.com · not verified by this device"),
        "{text}"
    );
    // The refusal list, and the grant the user can check answers against.
    assert!(text.contains("NEVER ANSWERED"), "{text}");
    assert!(text.contains("prompts"), "{text}");
    assert!(text.contains("secret values"), "{text}");
    assert!(text.contains("outside the granted scope"), "{text}");
    assert!(text.contains("GRANTED SCOPES"), "{text}");
    assert!(text.contains("inventory · authority"), "{text}");
    assert!(text.contains("Acme Engineering · eng-ai-v3"), "{text}");
    // Where it lives, and the boundary that keeps purge from deleting it.
    assert!(
        text.contains("/var/lib/punar/agents/queries.jsonl"),
        "{text}"
    );
    assert!(text.contains("kept 365 days"), "{text}");
    assert!(
        text.contains("NOT deleted by punarctl privacy purge"),
        "{text}"
    );

    // Nothing SPEC 21.2 forbids can appear, because nothing carries it.
    // ("audit event payloads" is in the *never answered* list, which is the
    //  opposite of a leak, so the probe is for structure, not the word.)
    assert!(!text.contains("/home/"), "{text}");
    assert!(!text.to_lowercase().contains("cmdline"), "{text}");
    assert!(
        !text.contains('{') && !text.contains('}'),
        "the log surface renders records, never an answered payload: {text}"
    );
}

/// `--json` is the `queries.list` result verbatim — one call, one document.
#[test]
fn privacy_queries_json_is_the_result_verbatim() {
    let agentd = start_agentd_mock();
    let output = run_agents(&agentd, &["--json", "privacy", "queries"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(value, fixture_queries_list());
}

/// `--since` travels as a param; the daemon does the filtering, because the
/// daemon owns the log. Omitted, no `params` object is sent at all
/// (contract section 3.1).
fn queries_since_responder(request: &Value) -> Result<Value, Value> {
    if request["method"] == json!("queries.list") {
        let since = request
            .get("params")
            .and_then(|p| p.get("since"))
            .and_then(Value::as_str);
        return match since {
            Some("2026-08-25T14:00:00Z") => Ok(fixture_queries_list()),
            other => Err(json!({
                "code": "invalid_params",
                "message": format!("since travelled as {other:?}, not the value typed"),
                "details": {"param": "since"}
            })),
        };
    }
    agents_respond(request)
}

#[test]
fn privacy_queries_since_is_a_daemon_side_filter() {
    let agentd = start_mock_with(queries_since_responder);
    let output = run_agents(
        &agentd,
        &["privacy", "queries", "--since", "2026-08-25T14:00:00Z"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "the daemon saw the timestamp it was given: {}",
        stderr(&output)
    );

    // And without the flag, the responder above sees no `since` at all and
    // refuses — proving the CLI omits the param rather than inventing one.
    let bare = run_agents(&agentd, &["privacy", "queries"]);
    assert_eq!(bare.status.code(), Some(1), "{}", stdout(&bare));
    assert!(
        stderr(&bare).contains("since travelled as None"),
        "{}",
        stderr(&bare)
    );
}

/// The personal-device sentence: calm, exit 0, no error and no upsell.
/// Not an empty table that could read as "nobody has asked *yet*" — a
/// statement that the path does not exist here (milestone-10.md section 11).
fn personal_queries_responder(request: &Value) -> Result<Value, Value> {
    if request["method"] == json!("queries.list") {
        return Ok(json!({
            "queries": [],
            "enrolled": false,
            "granted_scopes": [],
            "admin_identity_verified": false,
            "never_answered": [],
            "storage": {
                "path": "/var/lib/punar/agents/queries.jsonl",
                "retention_days": 365,
                "max_records": 10000,
                "purged_by_privacy_purge": false
            }
        }));
    }
    agents_respond(request)
}

/// The M10 shape: a device that WAS enrolled, answered questions, and has
/// since been unenrolled. The history is real and must stay; the relationship
/// is over and must be said.
fn unenrolled_with_history_responder(request: &Value) -> Result<Value, Value> {
    if request["method"] == json!("queries.list") {
        let mut list = fixture_queries_list();
        list["enrolled"] = json!(false);
        return Ok(list);
    }
    agents_respond(request)
}

#[test]
fn privacy_queries_names_the_personal_scope_when_history_outlives_enrollment() {
    let agentd = start_mock_with(unenrolled_with_history_responder);
    let output = run_agents(&agentd, &["privacy", "queries"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);

    // The current state is named in the section context, beside the counts.
    assert!(
        text.contains("PERSONAL DEVICE · 3 QUERIES · 2 ANSWERED · 1 REFUSED"),
        "{text}"
    );
    // And explained once, after the rows. fmt::note uppercases per the
    // Plate D-014 grammar, so this reads case-insensitively like its
    // neighbour above.
    assert!(
        text.to_lowercase().contains("personal device now"),
        "{text}"
    );
    assert!(
        text.to_lowercase()
            .contains("record of what was asked while this device was enrolled"),
        "{text}"
    );

    // The record itself is UNCHANGED — unenrolling does not edit history.
    // Same three rows the enrolled fixture renders.
    assert!(text.contains("SECOPS@ACME.COM"), "{text}");
    assert!(text.contains("CIO@ACME.COM"), "{text}");
    assert!(text.contains("refused · out of scope"), "{text}");

    // Still no error voice and no upsell on a personal device.
    assert!(stderr(&output).is_empty(), "{}", stderr(&output));
    assert!(!text.to_lowercase().contains("enroll to"), "{text}");
}

#[test]
fn privacy_queries_on_a_personal_device_is_one_calm_line_and_exit_0() {
    let agentd = start_mock_with(personal_queries_responder);
    let output = run_agents(&agentd, &["privacy", "queries"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Personal mode"), "{text}");
    assert!(text.contains("no remote-query path exists"), "{text}");
    assert!(text.contains("nothing has ever been asked"), "{text}");
    // fmt::note uppercases, per the Plate D-014 grammar.
    assert!(
        text.to_lowercase()
            .contains("nothing listens on this device"),
        "{text}"
    );
    // No error voice, no upsell, no "enroll to enable".
    assert!(stderr(&output).is_empty(), "{}", stderr(&output));
    assert!(!text.to_lowercase().contains("enroll to"), "{text}");
}

#[test]
fn privacy_ledger_json_is_a_labelled_composed_document() {
    let agentd = start_agentd_mock();

    // Device-wide: composed from two methods, and it says so rather than
    // pretending to be one verbatim IPC result.
    let output = run_agents(&agentd, &["--json", "privacy", "ledger"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert!(
        value["source"]
            .as_str()
            .unwrap()
            .contains("composed locally"),
        "{value}"
    );
    assert_eq!(value["registry"], fixture_agents_list());
    assert_eq!(value["ledgers"][0]["access"], fixture_agents_access());
    // M8 shipped `{"available": false, "milestone": "M10"}` here, by design
    // and with the milestone named. M10 makes it live: the block carries
    // the log itself, and a consumer can tell "none" from "not read".
    assert_eq!(value["remote_query"]["available"], json!(true));
    assert_eq!(value["remote_query"]["log"], fixture_queries_list());
    assert_eq!(
        value["remote_query"]["command"],
        json!("punarctl privacy queries")
    );
    assert_eq!(value["local_only"], json!(true));

    // One session: a single call, so the result is verbatim.
    let output = run_agents(
        &agentd,
        &["--json", "privacy", "ledger", "agt_4f21c09ab3e1"],
    );
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(value, fixture_agents_access());
}

#[test]
fn privacy_purge_prints_what_it_deleted_and_the_audit_boundary() {
    let agentd = start_agentd_mock();

    let output = run_agents(
        &agentd,
        &["privacy", "purge", "--session", "agt_4f21c09ab3e1", "--yes"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains("✓ PURGED · 1 SESSION · 5 RESOURCE CLASSES · 1 EVENT REFERENCE"),
        "{text}"
    );
    // The one sentence that keeps the two records from being confused.
    assert!(
        text.contains(
            "THE AUDIT TRAIL IS A SEPARATE RECORD AND WAS NOT DELETED · PUNARCTL AUDIT TAIL"
        ),
        "{text}"
    );

    // `--all` scopes to the caller's own sessions; the daemon enforces it.
    let output = run_agents(&agentd, &["--json", "privacy", "purge", "--all", "--yes"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(value, fixture_ledger_purge());
}

fn fixture_network_status() -> Value {
    json!({
        "enforcement": {"state": "available", "installed_sessions": 1},
        "relay": {"mode": "direct", "simulated": false, "hops": []},
        "dns_protection": {"state": "not_configured", "milestone": "phase_2"},
        "observation": {
            "transport": "tcp", "udp_quic": "not_observed",
            "content_inspection": false, "dns_logging": false
        }
    })
}

fn fixture_connections() -> Value {
    json!({
        "scanned_at": "2026-08-28T23:45:00Z",
        "enforcement": "available",
        "relay": {"mode": "direct", "simulated": false, "hops": []},
        "dns_protection": {"state": "not_configured", "milestone": "phase_2"},
        "transport": "tcp",
        "limitations": ["UDP and QUIC are not observed"],
        "processes": [{
            "name": "claude", "pid_class": "agent", "governed": true,
            "session": {"id": "agt_4f21c09ab3e1", "project": "atlas"},
            "connections": [{
                "destination": "198.51.100.10", "name": "Acme Dev API",
                "zone": "corp_dev", "category": "corporate", "route": "direct",
                "state": "established"
            }]
        }]
    })
}

fn fixture_zones() -> Value {
    json!([
        {"name": "corp_dev", "display_name": "Corporate development",
         "description": "Reviewed development services", "kind": "corporate",
         "relay_mode": "enterprise_route"},
        {"name": "internet", "display_name": "Internet", "kind": "internet",
         "relay_mode": "direct"}
    ])
}

fn fixture_network_policy() -> Value {
    json!({
        "project_id": "atlas",
        "rules": [
            {"zone": "corp_dev", "decision": "allow", "bound_by": "both",
             "manifest_decision": "allow", "policy_decision": "allow"},
            {"zone": "internet", "decision": "deny", "bound_by": "manifest",
             "manifest_decision": "deny", "policy_decision": null}
        ],
        "container_network": {"mode": "none", "reason": "project residual denies internet"}
    })
}

fn fixture_network_explain() -> Value {
    json!({
        "what": "Network access to zone corp_dev is allow.",
        "why": "The effective decision is the strictest project value.",
        "who": "Managed AI sessions in project atlas.",
        "which_policy": ["/home/punar/atlas/.punar/network-policy.json",
                         "/home/punar/atlas/.punar/manifest.yaml"],
        "can_you_change_it": "Edit the project documents; organization policy may only restrict.",
        "next_step": "punarctl network policy atlas",
        "decision": "allow", "zone": "corp_dev", "project": "atlas",
        "enforcement": {"state": "available", "installed_sessions": 1}
    })
}

fn fixture_network_apply() -> Value {
    json!({"installed_sessions": 1, "skipped_sessions": [], "warnings": []})
}

fn fixture_private_relay() -> Value {
    json!({
        "mode": "private_relay", "simulated": true,
        "hops": [
            {"role": "ingress", "knows": ["client_identity", "connect_time"]},
            {"role": "egress", "knows": ["destination", "connect_time"]}
        ],
        "property_claimed": "no single hop holds both client identity and destination",
        "property_not_held": "both hops are the same process on the same device",
        "real_relay_milestone": "phase_2"
    })
}

fn netd_respond(request: &Value) -> Result<Value, Value> {
    assert_eq!(request["v"], json!(1));
    match request["method"].as_str().unwrap() {
        "network.status" => Ok(fixture_network_status()),
        "network.connections" => Ok(fixture_connections()),
        "network.zones" => Ok(fixture_zones()),
        "network.policy" => {
            assert_eq!(request["params"], json!({"project": "atlas"}));
            Ok(fixture_network_policy())
        }
        "network.explain" => {
            assert_eq!(
                request["params"],
                json!({"project": "atlas", "zone": "corp_dev"})
            );
            Ok(fixture_network_explain())
        }
        "network.apply" => {
            assert_eq!(request["params"], json!({"project": "atlas"}));
            Ok(fixture_network_apply())
        }
        "relay.status" => Ok(fixture_private_relay()),
        "relay.set" => {
            assert_eq!(request["params"], json!({"mode": "private_relay"}));
            Ok(fixture_private_relay())
        }
        other => Err(json!({
            "code": "unknown_method", "message": format!("unknown {other}")
        })),
    }
}

fn run_netd(args: &[&str]) -> Output {
    let netd = start_mock_with(netd_respond);
    let punard = start_mock();
    Command::new(env!("CARGO_BIN_EXE_punarctl"))
        .args(args)
        .env("PUNARD_SOCKET", punard)
        .env("PUNAR_NETD_SOCKET", netd)
        .env("NO_COLOR", "1")
        .output()
        .expect("run punarctl")
}

#[test]
fn network_privacy_and_relay_are_real_netd_surfaces() {
    for (args, expected) in [
        (vec!["network", "status"], "no packet or payload inspection"),
        (vec!["network", "zones"], "MEMBERSHIP IS CIDR-ONLY"),
        (vec!["network", "policy", "atlas"], "STRICTEST SOURCE WINS"),
        (
            vec!["network", "explain", "atlas", "corp_dev"],
            "Managed AI sessions in project atlas",
        ),
        (
            vec!["network", "apply", "atlas"],
            "KERNEL NETWORK POLICY RECONCILED",
        ),
        (
            vec!["privacy", "connections"],
            "NO PORTS · NO LOCAL ADDRESSES",
        ),
        (vec!["relay", "status"], "SIMULATED"),
        (
            vec!["relay", "set", "private_relay"],
            "packet path remains direct",
        ),
    ] {
        let output = run_netd(&args);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stdout(&output).contains(expected),
            "{args:?}: {}",
            stdout(&output)
        );
    }

    let output = run_netd(&["--json", "privacy", "connections"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        serde_json::from_str::<Value>(stdout(&output).trim()).unwrap(),
        fixture_connections()
    );
}

#[test]
fn privacy_connections_names_netd_when_the_owner_is_missing() {
    let missing = std::env::temp_dir().join("punarctl-no-netd-here.sock");
    let output = Command::new(env!("CARGO_BIN_EXE_punarctl"))
        .args(["privacy", "connections"])
        .env("PUNAR_NETD_SOCKET", missing)
        .env("NO_COLOR", "1")
        .output()
        .expect("run punarctl");
    assert_eq!(output.status.code(), Some(5));
    let text = stderr(&output);
    assert!(text.contains("systemctl status punar-netd"), "{text}");
    assert!(!text.contains("systemctl status punar-agentd"), "{text}");
}

/// Routing (contract section 12): `ledger.purge` lives on the agentd
/// socket, so an absent registry names *its* unit — never punard's.
#[test]
fn privacy_verbs_reach_the_agentd_socket() {
    let punard = start_mock();
    let missing = std::env::temp_dir().join("punarctl-no-agentd-here.sock");
    for args in [
        ["privacy", "ledger"].as_slice(),
        ["privacy", "purge", "--all", "--yes"].as_slice(),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_punarctl"))
            .args(args)
            .env("PUNARD_SOCKET", &punard)
            .env("PUNAR_AGENTD_SOCKET", &missing)
            .env("NO_COLOR", "1")
            .output()
            .expect("run punarctl");
        assert_eq!(output.status.code(), Some(5), "{args:?}");
        assert!(
            stderr(&output).contains("systemctl status punar-agentd"),
            "{args:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Milestone 9 — the approval gate, JIT privilege, the secret broker
// (docs/api/ipc.md sections 14 and 16)
// ---------------------------------------------------------------------------

/// The mock broker's issued value. Deliberately carries the class-marked
/// mock prefix of contract section 16.4, so a leak is identifiable as a
/// mock in any grep — including the greps in these tests.
const MOCK_TOKEN: &str = "punar-mock-aws-dev-9Qw3ZzmXk1TnP0aB";

fn pending_approval() -> Value {
    json!({
        "v": 1,
        "approval": {
            "approval_id": "apr_7c1d9a4e",
            "requester": {"type": "ai_agent", "id": "agt_4f21c09ab3e1",
                          "agent_name": "claude-code"},
            "user": "punar",
            "capability": "security.firewall",
            "resource": "disabled",
            "reason": "Atlas integration test needs the host firewall down",
            "risk": "high",
            "status": "pending",
            "expires_at": "2126-08-25T10:05:00Z"
        },
        "kind": "capability_set",
        "created_at": "2126-08-25T10:00:00Z",
        "contract": "SetFirewall(disabled)",
        "policy": {"name": "Personal preference", "policy_id": "personal-defaults"},
        "resolved_at": null, "resolved_by": null,
        "consumed_at": null, "execution": null
    })
}

/// The contract section 14.1 gate error, with the machine data the
/// section 73 surface renders beneath the daemon's prose.
fn approval_required_error() -> Value {
    json!({
        "code": "approval_required",
        "message": "Claude Code may not disable the host firewall on this device \
                    without your approval.\n\
                    Why: personal defaults gate host firewall changes made by an AI \
                    agent.\n\
                    Next step: punarctl approvals wait apr_7c1d9a4e",
        "details": {
            "approval_id": "apr_7c1d9a4e",
            "expires_at": "2126-08-25T10:05:00Z",
            "capability": "security.firewall",
            "resource": "disabled",
            "decision": "approval_required",
            "policy_ids": ["personal-defaults"]
        }
    })
}

/// punard's M9 half: approvals + privilege. Every other method still
/// answers from the section 5 fixtures.
fn m9_punard_respond(request: &Value) -> Result<Value, Value> {
    match request["method"].as_str().unwrap_or_default() {
        // The gate: a set an AI policy gates executes NOTHING.
        "capabilities.set" => Err(approval_required_error()),
        "approvals.list" => Ok(json!({
            "approvals": [pending_approval()],
            "checked_at": "2126-08-25T10:00:30Z"
        })),
        "approvals.get" => {
            assert_eq!(request["params"]["approval_id"], json!("apr_7c1d9a4e"));
            Ok(pending_approval())
        }
        "approvals.resolve" => {
            assert_eq!(request["params"]["approval_id"], json!("apr_7c1d9a4e"));
            assert_eq!(request["params"]["decision"], json!("approved"));
            let mut approval = pending_approval();
            approval["approval"]["status"] = json!("approved");
            approval["resolved_at"] = json!("2126-08-25T10:01:00Z");
            approval["resolved_by"] = json!({"uid": 1000, "user": "punar", "pid": 812});
            approval["execution"] = json!({
                "result": "success", "changed": true, "audit_event_id": "evt_501"
            });
            Ok(approval)
        }
        "privilege.request" => {
            // The reason travels verbatim — Plate D-012.
            assert_eq!(
                request["params"]["reason"],
                json!("Reproducing the Atlas net bug")
            );
            assert_eq!(request["params"]["duration_minutes"], json!(15));
            Err(json!({
                "code": "approval_required",
                "message": "Elevation for time.timezone is waiting on your approval.",
                "details": {
                    "approval_id": "apr_11ba32cd",
                    "expires_at": "2126-08-25T10:05:00Z",
                    "capability": "time.timezone",
                    "resource": "15m",
                    "decision": "approval_required",
                    "policy_ids": ["personal-defaults"]
                }
            }))
        }
        "privilege.status" => Ok(json!({
            "grants": [{"grant_id": "gnt_2b8e11c4", "capability": "time.timezone",
                        "reason": "Reproducing the Atlas net bug",
                        "granted_at": "2126-08-25T10:00:00Z",
                        "expires_at": "2126-08-25T10:15:00Z"}],
            "checked_at": "2126-08-25T10:00:30Z"
        })),
        "privilege.revoke" => {
            assert_eq!(request["params"]["grant_id"], json!("gnt_2b8e11c4"));
            Ok(json!({"revoked": ["gnt_2b8e11c4"], "revoked_at": "2126-08-25T10:03:00Z"}))
        }
        _ => respond(request),
    }
}

/// The `punar-secrets` mock (contract section 16.2, closed method set).
fn secrets_respond(request: &Value) -> Result<Value, Value> {
    match request["method"].as_str().unwrap_or_default() {
        "credential.classes" => Ok(json!({
            "classes": [
                {"credential": "github", "decision": "allow", "policy_key": "github",
                 "default_ttl": 3600, "max_ttl": 3600, "provider": "mock"},
                {"credential": "aws-dev", "decision": "request", "policy_key": "aws_dev",
                 "default_ttl": 3600, "max_ttl": 3600, "provider": "mock"},
                {"credential": "aws-prod", "decision": "deny", "policy_key": "aws_prod",
                 "default_ttl": 0, "max_ttl": 0, "provider": "mock"}
            ],
            "provider": "mock",
            "checked_at": "2126-08-25T10:00:00Z"
        })),
        "credential.request" => match request["params"]["credential"].as_str() {
            Some("github") => Ok(json!({
                "credential": "github",
                "value": MOCK_TOKEN,
                "expires_at": "2126-08-25T11:00:00Z",
                "provider": "mock",
                "agent_session_id": "agt_4f21c09ab3e1"
            })),
            Some("aws-dev") => Err(json!({
                "code": "approval_required",
                "message": "A dev AWS credential for Claude Code is waiting on your approval.",
                "details": {"approval_id": "apr_11ba32cd",
                            "expires_at": "2126-08-25T10:05:00Z",
                            "capability": "credential.request",
                            "resource": "aws-dev",
                            "decision": "approval_required",
                            "policy_ids": ["personal-defaults"]}
            })),
            _ => Err(json!({
                "code": "denied",
                "message": "Production AWS credentials are not issued on this device.\n\
                            Why: personal defaults deny the aws-prod credential class.\n\
                            Next step: change it in punarctl policy, or use aws-dev.",
                "details": {"decision": "deny"}
            })),
        },
        "credential.validate" => {
            // The value reaches the broker in `params`, having arrived at
            // punarctl on stdin — never on argv.
            assert_eq!(request["params"]["value"], json!(MOCK_TOKEN));
            Ok(json!({"valid": true, "credential": "github",
                      "expires_at": "2126-08-25T11:00:00Z"}))
        }
        "credential.revoke" => {
            assert_eq!(request["params"]["value"], json!(MOCK_TOKEN));
            Ok(json!({"credential": "github", "revoked": true,
                      "revoked_at": "2126-08-25T10:04:00Z"}))
        }
        other => Err(json!({
            "code": "unknown_method",
            "message": format!(
                "punar-secrets does not implement {other}.\n\
                 Why: the broker's method table is closed — after issuance it holds \
                 only a hash, so no method can return a value twice.\n\
                 Next step: punarctl secrets list"
            ),
            "details": {"method": other}
        })),
    }
}

fn start_secrets_mock() -> PathBuf {
    start_mock_with(secrets_respond)
}

fn start_m9_punard_mock() -> PathBuf {
    start_mock_with(m9_punard_respond)
}

/// Run punarctl with **all three** sockets pointed at mocks, so a
/// mis-routed call fails loudly instead of silently reaching the wrong
/// daemon. `stdin_text` is piped in for the verbs that read a value from
/// standard input.
fn run_m9(punard: &PathBuf, secrets: &PathBuf, args: &[&str], stdin_text: Option<&str>) -> Output {
    let agentd = start_agentd_mock();
    let mut child = Command::new(env!("CARGO_BIN_EXE_punarctl"))
        .args(args)
        .env("PUNARD_SOCKET", punard)
        .env("PUNAR_AGENTD_SOCKET", agentd)
        .env("PUNAR_SECRETS_SOCKET", secrets)
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn punarctl");
    {
        let mut sink = child.stdin.take().expect("stdin");
        if let Some(text) = stdin_text {
            sink.write_all(text.as_bytes()).expect("write stdin");
        }
    }
    child.wait_with_output().expect("run punarctl")
}

/// **Exit 4 is real.** An agent-originated mutation the AI policy gates
/// returns `approval_required`, executes nothing, and says so in the
/// section 73 voice — and stdout stays empty, because there is no result
/// to pipe.
#[test]
fn a_gated_capability_set_exits_four_and_executes_nothing() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(
        &punard,
        &secrets,
        &["capabilities", "set", "security.firewall", "disabled"],
        None,
    );
    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert_eq!(stdout(&output), "", "nothing ran, so nothing is piped");

    let text = stderr(&output);
    // The daemon's own prose, verbatim.
    assert!(text.contains("without your approval"), "{text}");
    // The approval id the m9-check greps for.
    assert!(
        text.contains("apr_7c1d9a4e") || text.contains("APR_7C1D9A4E"),
        "{text}"
    );
    assert!(
        text.contains("PENDING · NOTHING HAS BEEN EXECUTED"),
        "{text}"
    );
    assert!(text.contains("AN AI AGENT MAY RESOLVE NOTHING"), "{text}");
    assert!(
        text.contains("PUNARCTL APPROVALS WAIT APR_7C1D9A4E"),
        "{text}"
    );
}

/// `--json` puts the gate error on stderr as one machine-readable line,
/// so a script lifts the `approval_id` without parsing prose — and stdout
/// still stays empty.
#[test]
fn a_gated_call_reports_json_on_stderr_and_nothing_on_stdout() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(
        &punard,
        &secrets,
        &[
            "--json",
            "capabilities",
            "set",
            "security.firewall",
            "disabled",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(stdout(&output), "");
    let line: Value = serde_json::from_str(stderr(&output).trim()).expect("one JSON line");
    assert_eq!(line["error"]["code"], json!("approval_required"));
    assert_eq!(
        line["error"]["details"]["approval_id"],
        json!("apr_7c1d9a4e")
    );
}

/// The card, and Plate D-014 register 05's affordance rule. This process
/// is not in an agent scope, so eligibility depends on the routed user;
/// either way the card itself renders in full.
#[test]
fn approvals_get_renders_the_contract_card() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(
        &punard,
        &secrets,
        &["approvals", "get", "apr_7c1d9a4e"],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("APR_7C1D9A4E"), "{text}");
    assert!(text.contains("SetFirewall(disabled)"), "{text}");
    assert!(
        text.contains("RECORDED TO LOCAL AUDIT EITHER WAY"),
        "{text}"
    );
    assert!(
        text.contains("claude-code says: \"Atlas integration test needs the host firewall down\""),
        "{text}"
    );
}

/// Resolving prints Plate D-003's verdict, including the audit pointer
/// that ties the approval to the trail.
#[test]
fn resolving_an_approval_prints_the_d003_verdict() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(
        &punard,
        &secrets,
        &[
            "approvals",
            "resolve",
            "apr_7c1d9a4e",
            "--decision",
            "approved",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains("✓ APPROVED · SETFIREWALL(DISABLED) EXECUTED · AUDIT EVT_501"),
        "{text}"
    );
    assert!(text.contains("punar · uid 1000 · pid 812"), "{text}");
}

/// A wait that outlives its patience is still `approval_required`: exit
/// 4, and an explicit statement that nothing ran. Bounded by the flag, so
/// this test costs one second and can never hang.
#[test]
fn waiting_past_the_timeout_is_still_approval_required() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(
        &punard,
        &secrets,
        &["approvals", "wait", "apr_7c1d9a4e", "--timeout", "1"],
        None,
    );
    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("Still pending"),
        "{}",
        stderr(&output)
    );
}

/// **The headline of this milestone at the CLI boundary.** The value goes
/// to stdout, bare, and the card goes to stderr — so
/// `TOKEN=$(punarctl secrets get github)` captures the value and only the
/// value, and no prose can contaminate it. The token appears **nowhere**
/// in the human card.
#[test]
fn an_issued_credential_is_on_stdout_alone_and_never_in_the_card() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(&punard, &secrets, &["secrets", "get", "github"], None);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    // stdout is the value and nothing else — no masthead, no newlineful
    // prose, nothing a shell would have to strip.
    assert_eq!(stdout(&output).trim_end_matches('\n'), MOCK_TOKEN);

    let card = stderr(&output);
    assert!(
        !card.contains(MOCK_TOKEN),
        "the card must never carry the value: {card}"
    );
    assert!(!card.contains("punar-mock"), "{card}");
    assert!(card.contains("GITHUB"), "{card}");
    assert!(
        card.contains("NEVER WRITTEN TO DISK · NEVER LOGGED"),
        "{card}"
    );
    assert!(card.contains("SIMULATED · MOCK PROVIDER"), "{card}");
}

/// `--json` serializes the value on stdout. That is the **one** place
/// Punar ever serializes a secret (contract section 16.4) — and the card
/// on stderr still does not carry it.
#[test]
fn json_issuance_is_the_one_documented_serialization() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(
        &punard,
        &secrets,
        &["--json", "secrets", "get", "github"],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: Value = serde_json::from_str(stdout(&output).trim()).expect("one JSON line");
    assert_eq!(value["value"], json!(MOCK_TOKEN));
    assert!(!stderr(&output).contains(MOCK_TOKEN));
}

/// A `request`-policy class raises an approval and issues nothing: exit
/// 4, no value anywhere.
#[test]
fn a_request_policy_credential_exits_four_with_no_value() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(&punard, &secrets, &["secrets", "get", "aws-dev"], None);
    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "",
        "nothing was issued, so stdout is empty"
    );
    assert!(
        stderr(&output).contains("APR_11BA32CD"),
        "{}",
        stderr(&output)
    );
}

/// A denied class exits 3 with the daemon's section 73 sentence verbatim
/// — what, why, which policy, what to do next.
#[test]
fn a_denied_credential_exits_three_with_the_section_73_sentence() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(&punard, &secrets, &["secrets", "get", "aws-prod"], None);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert_eq!(stdout(&output), "");
    let text = stderr(&output);
    assert!(
        text.contains("Production AWS credentials are not issued"),
        "{text}"
    );
    assert!(text.contains("Why:"), "{text}");
    assert!(text.contains("Next step:"), "{text}");
}

/// The value arrives on **stdin**, never on argv — `/proc/<pid>/cmdline`
/// is world-readable. The mock asserts the value reached the broker; this
/// asserts it never came back out.
#[test]
fn validate_and_revoke_read_the_value_from_stdin_and_never_echo_it() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();

    let output = run_m9(
        &punard,
        &secrets,
        &["secrets", "validate", "--class", "github"],
        Some(MOCK_TOKEN),
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!stdout(&output).contains(MOCK_TOKEN), "{}", stdout(&output));
    assert!(!stderr(&output).contains(MOCK_TOKEN));
    assert!(stdout(&output).contains("GITHUB"), "{}", stdout(&output));

    let output = run_m9(&punard, &secrets, &["secrets", "revoke"], Some(MOCK_TOKEN));
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!stdout(&output).contains(MOCK_TOKEN));
    assert!(!stderr(&output).contains(MOCK_TOKEN));
    assert!(
        stdout(&output).contains("THE CLASS ONLY, NEVER THE VALUE"),
        "{}",
        stdout(&output)
    );
}

/// Empty stdin is a usage error with a sentence, not a round trip — and
/// the sentence names why there is no `--token` flag.
#[test]
fn a_missing_stdin_value_is_a_usage_error_that_explains_itself() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(
        &punard,
        &secrets,
        &["secrets", "validate", "--class", "github"],
        Some(""),
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("standard input"), "{text}");
    assert!(text.contains("world-readable"), "{text}");
    assert!(text.contains("there is no --token flag"), "{text}");
}

/// Routing (contract section 16.2): `credential.*` reaches the broker,
/// and the closed method table answers `unknown_method` for everything
/// the milestone refuses to build. Both sibling sockets are live mocks,
/// so a mis-route would answer differently rather than silently.
#[test]
fn credential_probes_reach_the_broker_and_its_closed_table() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    for method in ["credential.show", "credential.export", "credential.list"] {
        let output = run_m9(&punard, &secrets, &["debug", "rpc", method], None);
        assert_eq!(output.status.code(), Some(1), "{method}");
        let text = stderr(&output);
        assert!(text.contains("punar-secrets does not implement"), "{text}");
        assert!(text.contains("only a hash"), "{text}");
    }
    // `--socket secrets` forces the broker for a name it does not own,
    // which is how the section 74.4 negative probes work.
    let output = run_m9(
        &punard,
        &secrets,
        &["--socket", "secrets", "debug", "rpc", "secrets.dump"],
        None,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("punar-secrets does not implement"));
}

/// `secrets list` names classes, decisions and the mock provider — and
/// never a value, because the broker could not produce one.
#[test]
fn secrets_list_renders_classes_and_no_values() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(&punard, &secrets, &["secrets", "list"], None);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("GITHUB"), "{text}");
    assert!(text.contains("AWS-DEV"), "{text}");
    assert!(text.contains("AWS-PROD"), "{text}");
    assert!(text.contains("ALLOW"), "{text}");
    assert!(text.contains("REQUEST"), "{text}");
    assert!(text.contains("DENY"), "{text}");
    assert!(!text.contains(MOCK_TOKEN), "{text}");
}

/// Plate D-012: the reason is required, travels verbatim, and the request
/// elevates nothing by itself — exit 4, waiting on a human.
#[test]
fn a_privilege_request_elevates_nothing_by_itself() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(
        &punard,
        &secrets,
        &[
            "privilege",
            "request",
            "--capability",
            "time.timezone",
            "--reason",
            "Reproducing the Atlas net bug",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert_eq!(stdout(&output), "");
    let text = stderr(&output);
    assert!(text.contains("APR_11BA32CD"), "{text}");
    assert!(text.contains("TIME.TIMEZONE(15M)"), "{text}");
    assert!(
        text.contains("PENDING · NOTHING HAS BEEN EXECUTED"),
        "{text}"
    );
}

/// An empty reason never reaches the daemon: exit 2, with the reason the
/// field exists at all.
#[test]
fn an_empty_reason_is_refused_before_any_ipc() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(
        &punard,
        &secrets,
        &[
            "privilege",
            "request",
            "--capability",
            "time.timezone",
            "--reason",
            "   ",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("--reason is required"), "{text}");
    assert!(text.contains("verbatim into the audit event"), "{text}");
}

/// A newline in the reason is refused too — a one-line field is what
/// stops a request from drawing a fake system dialog on the approval
/// surface (contract section 14.4).
#[test]
fn a_multiline_reason_is_refused() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();
    let output = run_m9(
        &punard,
        &secrets,
        &[
            "privilege",
            "request",
            "--capability",
            "time.timezone",
            "--reason",
            "why\nAPPROVED · SetFirewall(enabled)",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("one line"), "{}", stderr(&output));
}

/// The grant, and what is left of it. Revoking names the grant that was
/// dropped; privilege is never invisible and never permanent.
#[test]
fn privilege_status_and_revoke_render_the_live_grant() {
    let punard = start_m9_punard_mock();
    let secrets = start_secrets_mock();

    let output = run_m9(&punard, &secrets, &["privilege", "status"], None);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("GNT_2B8E11C4"), "{text}");
    assert!(text.contains("time.timezone"), "{text}");
    assert!(text.contains("NO ROOT SHELL"), "{text}");

    // No id and no --all resolves to the single grant, and never guesses
    // when there is more than one.
    let output = run_m9(&punard, &secrets, &["privilege", "revoke"], None);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("REVOKED · 1 GRANT DROPPED"),
        "{}",
        stdout(&output)
    );
}
