//! Device → Smplify recovery custody proof against the real dev/CI mock.
//! The literal recovery key is known to this test so the negative assertion
//! can grep every server-side byte for it.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use punar_common::Redacted;
use punar_mock_smplify::config::MockConfig;
use punar_mock_smplify::server::MockServer;
use punar_recovery::{RecoveryBinding, SecretRecoveryKey};
use punard::enroll::ControlPlaneClient;
use serde_json::{Value, json};

const RECOVERY_KEY: &str =
    "lhkbicdj-trbuftjv-tviijfck-dfvbknrh-uiulbhui-higltier-kecfhkbk-egrirkui";

fn temp_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "punard-recovery-escrow-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/organizations/acme")
}

fn rpc(socket: &Path, method: &str, params: Value) -> Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    let mut request = json!({
        "v": 1,
        "id": "recovery-test",
        "method": method,
        "params": params,
    })
    .to_string();
    request.push('\n');
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    serde_json::from_str(response.trim_end()).unwrap()
}

#[test]
fn enrolled_device_wraps_uploads_and_verifies_without_server_plaintext() {
    let root = temp_dir();
    let socket = root.join("api.sock");
    let state = root.join("state");
    let handle = MockServer::new(MockConfig {
        socket: socket.clone(),
        fixtures_dir: fixtures_dir(),
        state_dir: state.clone(),
    })
    .unwrap()
    .spawn()
    .unwrap();
    let client = ControlPlaneClient::new(&socket);
    let bootstrap = Redacted::new("a".repeat(64));
    let (token, _) = client.register("dev_456", &bootstrap).unwrap();
    let secret = SecretRecoveryKey::parse(RECOVERY_KEY).unwrap();
    let binding = RecoveryBinding {
        organization_id: "acme".into(),
        tenant_key_id: "trk_mock_2026_08".into(),
        device_id: "dev_456".into(),
        luks_uuid: "21d4af4f-a19c-4c6a-b4e8-dd50e9f7ecb9".into(),
        recovery_keyslot: 1,
    };

    let outcome = client
        .escrow_recovery_key(&token, &binding, &secret)
        .unwrap();
    assert_eq!(outcome.envelope.device_id, "dev_456");
    assert_eq!(
        outcome.receipt.envelope_sha256(),
        outcome.envelope.digest_hex().unwrap()
    );

    let custody = std::fs::read_to_string(state.join("received-recovery-envelopes.jsonl")).unwrap();
    assert!(custody.contains("encapsulated_key"), "{custody}");
    assert!(!custody.contains(RECOVERY_KEY), "{custody}");
    assert!(
        !custody.contains(&RECOVERY_KEY.replace('-', "")),
        "{custody}"
    );

    let denied = rpc(
        &socket,
        "admin.recovery_release",
        json!({
            "admin": "helpdesk@acme.com",
            "device_id": "dev_456",
            "reason": "INC-2048-lost-passphrase",
        }),
    );
    assert_eq!(denied["error"]["code"], "denied", "{denied}");

    let released = rpc(
        &socket,
        "admin.recovery_release",
        json!({
            "admin": "secops@acme.com",
            "device_id": "dev_456",
            "reason": "INC-2048-lost-passphrase",
        }),
    );
    assert_eq!(
        released["result"]["recovery_key"], RECOVERY_KEY,
        "{released}"
    );
    assert_eq!(released["result"]["recovery_keyslot"], 1);
    assert_eq!(released["result"]["release_once"], true);
    assert_eq!(released["result"]["identity_verified"], false);

    let audit = std::fs::read_to_string(state.join("recovery-releases.jsonl")).unwrap();
    assert_eq!(audit.lines().count(), 2, "{audit}");
    assert!(audit.contains(r#""outcome":"denied""#), "{audit}");
    assert!(audit.contains(r#""outcome":"released""#), "{audit}");
    assert!(!audit.contains(RECOVERY_KEY), "{audit}");
    assert!(!audit.contains(&RECOVERY_KEY.replace('-', "")), "{audit}");

    handle.stop();
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn token_cannot_escrow_an_envelope_for_another_device() {
    let root = temp_dir();
    let socket = root.join("api.sock");
    let state = root.join("state");
    let handle = MockServer::new(MockConfig {
        socket: socket.clone(),
        fixtures_dir: fixtures_dir(),
        state_dir: state.clone(),
    })
    .unwrap()
    .spawn()
    .unwrap();
    let client = ControlPlaneClient::new(&socket);
    let (token, _) = client
        .register("dev_456", &Redacted::new("b".repeat(64)))
        .unwrap();
    let tenant = client.recovery_key(&token).unwrap();
    let secret = SecretRecoveryKey::parse(RECOVERY_KEY).unwrap();
    let envelope = tenant
        .seal(
            &RecoveryBinding {
                organization_id: "acme".into(),
                tenant_key_id: tenant.key_id.clone(),
                device_id: "dev_999".into(),
                luks_uuid: "21d4af4f-a19c-4c6a-b4e8-dd50e9f7ecb9".into(),
                recovery_keyslot: 1,
            },
            &secret,
        )
        .unwrap();
    assert!(client.recovery_escrow(&token, &envelope).is_err());
    assert!(!state.join("received-recovery-envelopes.jsonl").exists());

    handle.stop();
    let _ = std::fs::remove_dir_all(root);
}
