//! F0-S3 (F-AUD): `audit.tail` answers each person with their own events and
//! the device's, and counts — never shows — everyone else's
//! (docs/api/ipc.md §5.5). Root sees the whole trail.
//!
//! The trail is written by the daemon under test, exactly as on a device: a
//! boot reconcile (the device's), alice's device-policy change, and bob's
//! refused one.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use punar_common::reauth_ticket::{Spender, TicketBody};
use punar_common::trusted_time::{SystemClock, TrustedClock};
use punard::authz::{Peer, PeerSource};
use punard::capability::Registry;
use punard::capability::mock::MockCapability;
use punard::server::{Daemon, DaemonConfig, DaemonHandle};
use serde_json::{Value, json};

static SEQ: AtomicU32 = AtomicU32::new(0);

/// The one process every peer in this file calls from, and when it started.
const PEER_PID: i32 = 5200;
const PEER_START: u64 = 520_000;

struct Device {
    dir: PathBuf,
    handle: Option<DaemonHandle>,
    mock: MockCapability,
    sockets: u32,
}

impl Device {
    fn new() -> Device {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("punard-audit-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("state")).unwrap();
        fs::write(
            dir.join("group"),
            "root:x:0:\npunar:x:970:\npunar-admin:x:971:\npunar-audit:x:972:\n",
        )
        .unwrap();
        fs::write(dir.join("passwd"), "root:x:0:0::/root:/bin/bash\n").unwrap();
        for (id, user, uid, admin) in [
            ("acct_00000000000000a1", "alice", 1000, true),
            ("acct_00000000000000b0", "bob", 1001, false),
        ] {
            let mut groups = vec!["punar"];
            if admin {
                groups.push("punar-admin");
            }
            let account = dir.join("identity/accounts").join(id);
            fs::create_dir_all(&account).unwrap();
            fs::write(
                account.join("account.json"),
                json!({"v": 1, "accountId": id, "username": user, "uid": uid, "gid": uid,
                       "groups": groups})
                .to_string(),
            )
            .unwrap();
            fs::create_dir_all(dir.join("userdb")).unwrap();
            for group in groups {
                fs::write(dir.join(format!("userdb/{user}:{group}.membership")), "{}").unwrap();
            }
        }
        let proc = dir.join("proc").join(PEER_PID.to_string());
        fs::create_dir_all(&proc).unwrap();
        fs::write(
            proc.join("stat"),
            format!(
                "{PEER_PID} (punarctl) S 1 {PEER_PID} {PEER_PID} 0 -1 4194560 0 0 0 0 0 0 0 0 \
                 20 0 1 0 {PEER_START} 0 0\n"
            ),
        )
        .unwrap();
        fs::write(
            proc.join("cgroup"),
            "0::/user.slice/user-1000.slice/session-2.scope\n",
        )
        .unwrap();
        Device {
            dir,
            handle: None,
            mock: MockCapability::new("security.firewall", json!("enabled")),
            sockets: 0,
        }
    }

    fn as_peer(&mut self, uid: u32, boot: bool) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
        self.sockets += 1;
        let cfg = DaemonConfig {
            group_file: self.dir.join("group"),
            passwd_file: self.dir.join("passwd"),
            proc_root: self.dir.join("proc"),
            peer_source: PeerSource::Fixed(Peer {
                uid,
                gid: uid,
                pid: Some(PEER_PID),
            }),
            io_timeout: Duration::from_secs(5),
            reauth_ticket_dir: self.dir.join("tickets"),
            identity_accounts_dir: self.dir.join("identity/accounts"),
            userdb_dir: self.dir.join("userdb"),
            ..DaemonConfig::new(
                self.dir.join(format!("punard-{}.sock", self.sockets)),
                self.dir.join("state"),
                self.dir.join("audit.jsonl"),
            )
        };
        let daemon = Daemon::new(cfg, Registry::new(vec![Box::new(self.mock.clone())])).unwrap();
        if boot {
            daemon.boot_reconcile();
        }
        self.handle = Some(daemon.spawn().unwrap());
    }

    fn call(&self, method: &str, params: Option<Value>) -> Value {
        let mut request = json!({ "v": 1, "id": "aud", "method": method });
        if let Some(params) = params {
            request["params"] = params;
        }
        let mut stream = UnixStream::connect(self.handle.as_ref().unwrap().socket_path()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(format!("{request}\n").as_bytes()).unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn mint(&self, uid: u32, token: &str) {
        let per_uid = self.dir.join("tickets").join(uid.to_string());
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&per_uid)
            .unwrap();
        let body = TicketBody {
            minted: SystemClock::new().now().expect("the boot clock"),
            action: "policy.set".to_string(),
            spender: Spender {
                pid: PEER_PID as u32,
                start: PEER_START,
            },
        };
        fs::write(per_uid.join(token), serde_json::to_vec(&body).unwrap()).unwrap();
    }

    fn pin(&self, ticket: &str) -> Value {
        self.call(
            "policy.set",
            Some(
                json!({"capability": "security.firewall", "value": "enabled",
                        "reason": "kept on", "ticket": ticket}),
            ),
        )
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn users(events: &Value) -> Vec<String> {
    events
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["user_id"].as_str().unwrap().to_string())
        .collect()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_person_reads_their_own_events_and_the_devices_and_is_told_what_was_withheld() {
    let mut device = Device::new();
    // The device's own event: the boot reconcile, attributed to punard.
    device.as_peer(1000, true);
    let alice_ticket = "a".repeat(64);
    device.mint(1000, &alice_ticket);
    assert!(device.pin(&alice_ticket).get("result").is_some());
    device.as_peer(1001, false);
    let bob_ticket = "b".repeat(64);
    device.mint(1001, &bob_ticket);
    assert_eq!(
        device.pin(&bob_ticket)["error"]["details"]["reason"],
        "device_admin_required"
    );

    // Bob: his refusal and the device's reconcile; alice's change withheld.
    let bob = device.call("audit.tail", Some(json!({"n": 1000})));
    let seen = users(&bob["result"]["events"]);
    assert!(seen.iter().any(|u| u == "uid:1001"), "{bob}");
    assert!(seen.iter().any(|u| u == "punard"), "{bob}");
    assert!(
        !seen.iter().any(|u| u == "uid:1000"),
        "alice's events leak: {bob}"
    );
    let withheld = bob["result"]["withheld"].as_u64().unwrap();
    assert!(withheld >= 1, "{bob}");

    // Alice sees hers, not bob's.
    device.as_peer(1000, false);
    let alice = device.call("audit.tail", Some(json!({"n": 1000})));
    let seen = users(&alice["result"]["events"]);
    assert!(seen.iter().any(|u| u == "uid:1000"), "{alice}");
    assert!(
        !seen.iter().any(|u| u == "uid:1001"),
        "bob's events leak: {alice}"
    );
    assert!(alice["result"]["withheld"].as_u64().unwrap() >= 1);

    // Root sees everything and withholds nothing.
    device.as_peer(0, false);
    let root = device.call("audit.tail", Some(json!({"n": 1000})));
    let seen = users(&root["result"]["events"]);
    for user in ["uid:1000", "uid:1001", "punard"] {
        assert!(
            seen.iter().any(|u| u == user),
            "{user} missing for root: {root}"
        );
    }
    assert_eq!(root["result"]["withheld"], 0);

    // The file itself is 0640: only its owner and group read it — and the
    // group, in the image, is punar-audit, which no person is in (gate A23).
    assert_eq!(mode(&device.dir.join("audit.jsonl")), 0o640);
}

/// F0 review, finding R4: a daemon's event about a person's agent session —
/// punar-netd refusing alice's agent a production zone — names her session
/// and her project. It is not the device's event: bob neither sees it nor
/// sees it counted as the device's, and root still reads it.
#[test]
fn a_daemons_event_about_a_persons_agent_is_not_the_devices() {
    let mut device = Device::new();
    device.as_peer(1000, true);
    let netd = json!({
        "event_id": "evt_netd_0001",
        "timestamp": "2026-09-25T10:00:00Z",
        "device_id": "dev_test",
        "user_id": "daemon",
        "agent_session_id": "agt_0a1b2c3d4e5f",
        "project_id": "atlas",
        "source": "service",
        "action": "network.deny",
        "resource": "prod-db",
        "decision": "deny",
        "policy_ids": ["personal-defaults"],
        "result": "denied_production"
    });
    let sweep = json!({
        "event_id": "evt_netd_0002",
        "timestamp": "2026-09-25T10:00:01Z",
        "device_id": "dev_test",
        "user_id": "punar-agentd",
        "agent_session_id": "agt_none",
        "project_id": "system",
        "source": "service",
        "action": "agents.scan",
        "resource": "agent",
        "decision": "allow",
        "policy_ids": ["personal-defaults"],
        "result": "success"
    });
    let mut trail = fs::read_to_string(device.dir.join("audit.jsonl")).unwrap_or_default();
    trail.push_str(&format!("{netd}\n{sweep}\n"));
    fs::write(device.dir.join("audit.jsonl"), trail).unwrap();

    device.as_peer(1001, false);
    let bob = device.call("audit.tail", Some(json!({"n": 1000})));
    let text = bob["result"]["events"].to_string();
    assert!(
        !text.contains("agt_0a1b2c3d4e5f"),
        "alice's session leaks: {bob}"
    );
    assert!(!text.contains("atlas"), "alice's project leaks: {bob}");
    assert!(
        text.contains("evt_netd_0002"),
        "a device event that names no one is still shown: {bob}"
    );
    assert!(bob["result"]["withheld"].as_u64().unwrap() >= 1, "{bob}");

    device.as_peer(0, false);
    let root = device.call("audit.tail", Some(json!({"n": 1000})));
    assert!(
        root["result"]["events"]
            .to_string()
            .contains("evt_netd_0001")
    );
}
