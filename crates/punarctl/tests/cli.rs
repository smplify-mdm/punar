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
        "audit": {"path": "/var/log/punar/audit.jsonl", "events": 42}
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
    json!({
        "reconciled_at": "2026-08-25T07:41:03Z",
        "drift_count": 1,
        "capabilities": [
            {"capability": "security.firewall", "desired_state": "enabled",
             "current_state": "disabled", "drift": true, "verified": true},
            {"capability": "system.hostname", "desired_state": "punar-m3",
             "current_state": "punar-m3", "drift": false, "verified": true},
            {"capability": "time.timezone", "desired_state": "UTC",
             "current_state": "UTC", "drift": false, "verified": true}
        ]
    })
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
        "status" | "capabilities.list" | "reconcile" => {
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

fn handle_connection(stream: UnixStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut writer = stream;
    let mut line = String::new();
    while let Ok(read) = reader.read_line(&mut line) {
        if read == 0 {
            break;
        }
        let request: Value = serde_json::from_str(line.trim_end()).expect("request must be JSON");
        let id = request["id"].clone();
        let envelope = match respond(&request) {
            Ok(result) => json!({"v": 1, "id": id, "result": result}),
            Err(error) => json!({"v": 1, "id": id, "error": error}),
        };
        writeln!(writer, "{envelope}").expect("write response");
        line.clear();
    }
}

/// Start a mock daemon on a fresh tempdir socket; returns the socket path.
fn start_mock() -> PathBuf {
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
                    thread::spawn(move || handle_connection(stream));
                }
                Err(_) => break,
            }
        }
    });
    path
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
fn reconcile_human_view_reports_drift_only() {
    let socket = start_mock();
    let output = run(&socket, &["reconcile"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("SECURITY.FIREWALL"));
    assert!(text.contains("DRIFT DETECTED · 1 OF 3 CAPABILITIES · REPORTED ONLY"));
    assert!(text.contains("MILESTONE 4"));
}

// ---------------------------------------------------------------------------
// Policy honesty and remaining stubs
// ---------------------------------------------------------------------------

#[test]
fn policy_verbs_answer_honestly_without_a_daemon() {
    // Deliberately no mock: the honest Milestone 4 answer needs no IPC.
    let missing = std::env::temp_dir().join("punarctl-no-daemon-here.sock");

    let effective = run(&missing, &["policy", "effective"]);
    assert!(effective.status.success());
    let text = stdout(&effective);
    assert!(text.contains("MILESTONE 4"), "{text}");
    assert!(text.contains("PERSONAL DEFAULTS"), "{text}");

    let explain = run(&missing, &["policy", "explain", "security.firewall"]);
    assert!(explain.status.success());
    let text = stdout(&explain);
    assert!(text.contains("SECURITY.FIREWALL"));
    assert!(text.contains("MILESTONE 4"));

    let json_out = run(
        &missing,
        &["--json", "policy", "explain", "security.firewall"],
    );
    assert!(json_out.status.success());
    let parsed: Value = serde_json::from_str(&stdout(&json_out)).unwrap();
    assert_eq!(parsed["policy_loaded"], json!(false));
    assert_eq!(parsed["available_in_milestone"], json!(4));
    assert_eq!(parsed["capability"], json!("security.firewall"));
}

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
