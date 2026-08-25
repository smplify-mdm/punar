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
        "status" | "capabilities.list" | "reconcile" | "policy.effective" => {
            assert!(params.is_none(), "{method} takes no params");
        }
        _ => {}
    }

    match method {
        "status" => Ok(fixture_status()),
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
         OVERALL       COMPLIANT   personal scope · drift remediated 2 · last 2026-08-25 09:14:02\n\
         FIREWALL      COMPLIANT\n\
         HOSTNAME      COMPLIANT\n\
         TIMEZONE      COMPLIANT\n\
         NO ORGANIZATION IS ENROLLED · ENROLLING LATER NEVER APPLIES RETROACTIVELY\n"
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
         OBSERVED LIVE AT REQUEST TIME · NO ORGANIZATION IS ENROLLED\n"
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
         COMPUTED 2026-08-25 09:14:02 · MERGED FROM OS DEFAULTS + YOUR PREFERENCES · NO ORGANIZATION IS ENROLLED\n"
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
         MERGED FROM OS DEFAULTS + YOUR PREFERENCES · NO ORGANIZATION IS ENROLLED\n"
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
// Remaining stubs
// ---------------------------------------------------------------------------

#[test]
fn unimplemented_verbs_keep_their_milestone_stubs() {
    let missing = std::env::temp_dir().join("punarctl-no-daemon-here.sock");
    for (args, expected) in [
        (vec!["compliance"], "Milestone 5"),
        (vec!["agents", "list"], "Milestone 7"),
        (vec!["agents", "access", "agt_1"], "Milestone 8"),
        (vec!["privacy", "connections"], "Milestone 12"),
        (vec!["relay", "status"], "Milestone 12"),
        (vec!["update", "status"], "not scheduled"),
    ] {
        let output = run(&missing, &args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(
            stderr(&output).contains(expected),
            "{args:?} stderr: {}",
            stderr(&output)
        );
    }
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
