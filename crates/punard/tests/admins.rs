//! F0-S1: device administrators and the rule for acting on other people
//! (docs/api/ipc.md section 23), driven over the wire as punarctl drives it.
//!
//! The device has two onboarded product accounts, exactly as onboarding and
//! the materializer leave them: alice (uid 1000) in `punar-admin`, bob (uid
//! 1001) not. Neither is in `/etc/passwd` — a Punar account is a userdb
//! record — so every name here is resolved the way the daemon resolves it on
//! a device.
//!
//! F-ADM-1: B's fresh ticket on an action that reaches A is refused with
//! `device_admin_required`, audited, and left unspent; A's succeeds; an agent
//! is refused before either question is asked.
//! F-ADM-2: `admins.set` never removes the last administrator, and every
//! change and refusal is audited.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use punar_common::trusted_time::{SystemClock, TrustedClock};
use punard::authz::{Peer, PeerSource};
use punard::capability::Registry;
use punard::capability::mock::MockCapability;
use punard::server::{Daemon, DaemonConfig, DaemonHandle};
use serde_json::{Value, json};

static SEQ: AtomicU32 = AtomicU32::new(0);

const ALICE: u32 = 1000;
const BOB: u32 = 1001;
const HUMAN_PID: i32 = 5100;
const AGENT_PID: i32 = 5101;

struct Device {
    dir: PathBuf,
    handle: Option<DaemonHandle>,
    mock: MockCapability,
    sockets: u32,
}

impl Device {
    /// A device with alice (administrator) and bob, and no organization.
    fn new() -> Device {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("punard-admins-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("state")).unwrap();
        fs::write(
            dir.join("group"),
            "root:x:0:\npunar:x:970:\npunar-admin:x:971:\n",
        )
        .unwrap();
        fs::write(dir.join("passwd"), "root:x:0:0::/root:/bin/bash\n").unwrap();
        onboard(&dir, "acct_00000000000000a1", "alice", ALICE, true);
        onboard(&dir, "acct_00000000000000b0", "bob", BOB, false);
        let proc_root = dir.join("proc");
        for (pid, cgroup) in [
            (
                HUMAN_PID,
                "0::/user.slice/user-1000.slice/session-2.scope\n",
            ),
            (
                AGENT_PID,
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/\
punar-agent-agt_0a1b2c3d4e5f.scope\n",
            ),
        ] {
            fs::create_dir_all(proc_root.join(pid.to_string())).unwrap();
            fs::write(proc_root.join(pid.to_string()).join("cgroup"), cgroup).unwrap();
        }
        Device {
            dir,
            handle: None,
            mock: MockCapability::new("security.firewall", json!("enabled")),
            sockets: 0,
        }
    }

    /// (Re)start the daemon as `uid` calling from `pid`. One daemon at a
    /// time over one state directory, as on a device.
    fn as_peer(&mut self, uid: u32, pid: i32) -> &mut Device {
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
                pid: Some(pid),
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
        let registry = Registry::new(vec![Box::new(self.mock.clone())]);
        let daemon = Daemon::new(cfg, registry).unwrap();
        self.handle = Some(daemon.spawn().unwrap());
        self
    }

    fn as_person(&mut self, uid: u32) -> &mut Device {
        self.as_peer(uid, HUMAN_PID)
    }

    fn call(&self, method: &str, params: Option<Value>) -> Value {
        let mut request = json!({ "v": 1, "id": "adm", "method": method });
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

    /// A ticket exactly as punar-authd mints one for `uid`.
    fn mint(&self, uid: u32) -> (String, PathBuf) {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let token = format!("{:064x}", 0xadd0_0000_u128 + u128::from(seq));
        let per_uid = self.dir.join("tickets").join(uid.to_string());
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&per_uid)
            .unwrap();
        let stamp = SystemClock::new().now().expect("the boot clock");
        let path = per_uid.join(&token);
        fs::write(&path, serde_json::to_vec(&stamp).unwrap()).unwrap();
        (token, path)
    }

    fn audit(&self) -> Vec<Value> {
        fs::read_to_string(self.dir.join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn member(&self, user: &str) -> bool {
        self.dir
            .join(format!("userdb/{user}:punar-admin.membership"))
            .is_file()
    }

    fn policy_set(&self, ticket: Option<&str>) -> Value {
        let mut params = json!({
            "capability": "security.firewall",
            "value": "enabled",
            "reason": "the lab machines keep it on",
        });
        if let Some(ticket) = ticket {
            params["ticket"] = json!(ticket);
        }
        self.call("policy.set", Some(params))
    }

    fn admins_set(&self, user: &str, administrator: bool, ticket: Option<&str>) -> Value {
        let mut params = json!({ "user": user, "administrator": administrator });
        if let Some(ticket) = ticket {
            params["ticket"] = json!(ticket);
        }
        self.call("admins.set", Some(params))
    }

    /// Put an organization's roster on the device, as an enrollment would.
    fn organization_roster(&self, administrators: Value) {
        let policy_d = self.dir.join("state/policy.d");
        fs::create_dir_all(&policy_d).unwrap();
        fs::write(
            policy_d.join("acme.json"),
            serde_json::to_vec(&json!({
                "policy_id": "acme-baseline-v4",
                "source_kind": "organization_baseline",
                "precedence_rank": 2,
                "source_name": "Acme IT",
                "policy": {
                    "apiVersion": "smplify.io/v1alpha1",
                    "kind": "DeviceDesiredState",
                    "metadata": {"organization": "acme", "device": "dev_test"},
                    // No capability opinion at all: what is under test is
                    // who may act, not what an organization pins.
                    "spec": {"security": {
                        "localAdmin": {"policyEditing": "allowed", "administrators": administrators}
                    }}
                }
            }))
            .unwrap(),
        )
        .unwrap();
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

/// An onboarded account exactly as onboarding writes it, and the drop-ins
/// the materializer publishes for it.
fn onboard(dir: &Path, id: &str, user: &str, uid: u32, administrator: bool) {
    let mut groups = vec!["punar"];
    if administrator {
        groups.push("punar-admin");
    }
    let account = dir.join("identity/accounts").join(id);
    fs::create_dir_all(&account).unwrap();
    fs::write(
        account.join("account.json"),
        serde_json::to_vec_pretty(&json!({
            "v": 1, "accountId": id, "username": user, "uid": uid, "gid": uid,
            "uidSource": "local", "realName": null, "realNameSource": "local",
            "groups": groups, "home": format!("/home/{user}"), "shell": "/bin/bash",
            "identity": null, "auth": {"kinds": ["password"]}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::create_dir_all(dir.join("userdb")).unwrap();
    for group in groups {
        fs::write(dir.join(format!("userdb/{user}:{group}.membership")), "{}").unwrap();
    }
}

fn reason(response: &Value) -> &str {
    response["error"]["details"]["reason"]
        .as_str()
        .unwrap_or_default()
}

/// F-ADM-1, on the existing device-wide method the owner named first.
#[test]
fn a_person_without_the_role_cannot_set_device_policy_and_keeps_their_password() {
    let mut device = Device::new();

    // Bob, with a perfectly good confirmation, is refused by role.
    device.as_person(BOB);
    let (ticket, file) = device.mint(BOB);
    let refused = device.policy_set(Some(&ticket));
    assert_eq!(refused["error"]["code"], "denied", "{refused}");
    assert_eq!(reason(&refused), "device_admin_required");
    assert_eq!(
        refused["error"]["details"]["administrators"],
        json!(["alice"])
    );
    assert_eq!(refused["error"]["details"]["user"], "bob");
    let message = refused["error"]["message"].as_str().unwrap();
    assert!(message.contains("alice"), "names who can act: {message}");
    assert!(
        message.contains("punarctl admins add bob"),
        "names the way to the role: {message}"
    );
    assert!(!message.contains("sudo"), "{message}");
    assert!(
        file.exists(),
        "the role is checked before the ticket is spent"
    );
    let events = device.audit();
    let denial = events
        .iter()
        .rev()
        .find(|e| e["action"] == "policy.set")
        .expect("the refusal is audited");
    assert_eq!(denial["decision"], "deny");
    assert_eq!(denial["result"], "device_admin_required");
    assert_eq!(denial["user_id"], "uid:1001");

    // Alice's confirmation does it.
    device.as_person(ALICE);
    let (ticket, file) = device.mint(ALICE);
    let pinned = device.policy_set(Some(&ticket));
    assert_eq!(
        pinned["result"]["source"]["kind"], "device_specific_override",
        "{pinned}"
    );
    assert!(!file.exists(), "and her ticket is spent by the change");

    // An agent running as alice, carrying alice's live ticket, is refused
    // before the role or the ticket is looked at.
    device.as_peer(ALICE, AGENT_PID);
    let (ticket, file) = device.mint(ALICE);
    let agent = device.policy_set(Some(&ticket));
    assert_eq!(reason(&agent), "agent_scope", "{agent}");
    assert!(file.exists());
}

/// F-ADM-1 across every other existing device-wide method: each refuses a
/// person without the role before spending anything, in the same words.
#[test]
fn every_device_wide_method_asks_for_the_role_before_the_password() {
    let mut device = Device::new();
    device.as_person(BOB);
    for (method, params) in [
        ("enroll.start", json!({ "org_domain": "acme.test" })),
        ("enroll.stop", json!({})),
        (
            "update.apply",
            json!({ "version": "2026.08.27.1", "allow_downgrade": false }),
        ),
        ("update.rollback", json!({ "to_version": null })),
        (
            "privilege.request",
            json!({ "capability": "security.firewall", "reason": "lab", "duration_minutes": 15 }),
        ),
    ] {
        let (ticket, file) = device.mint(BOB);
        let mut params = params;
        if method != "privilege.request" {
            params["ticket"] = json!(ticket);
        }
        let response = device.call(method, Some(params));
        assert_eq!(
            reason(&response),
            "device_admin_required",
            "{method}: {response}"
        );
        assert!(file.exists(), "{method} left bob's ticket unspent");
        assert!(
            device
                .audit()
                .iter()
                .any(|e| e["action"] == method && e["result"] == "device_admin_required"),
            "{method}'s refusal is audited"
        );
    }

    // Checking for updates reaches nobody, so it stays open to any person
    // who confirms their password: it is refused for another reason here
    // (this fixture has no update source), never for the role.
    let (ticket, _) = device.mint(BOB);
    let checked = device.call(
        "update.check",
        Some(json!({ "force": true, "ticket": ticket })),
    );
    assert_ne!(reason(&checked), "device_admin_required", "{checked}");
}

/// A grant bob somehow still holds buys nothing once he is not an
/// administrator: the role is checked each time the grant is used.
#[test]
fn a_person_who_loses_the_role_cannot_spend_a_grant() {
    let mut device = Device::new();
    device.as_person(ALICE);
    let requested = device.call(
        "privilege.request",
        Some(json!({ "capability": "security.firewall", "reason": "lab", "duration_minutes": 15 })),
    );
    assert_eq!(
        requested["error"]["code"], "approval_required",
        "{requested}"
    );
    let approval = requested["error"]["details"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Approving needs her password now (contract section 23.2)...
    let missing = device.call(
        "approvals.resolve",
        Some(json!({ "approval_id": approval, "decision": "approved" })),
    );
    assert_eq!(reason(&missing), "reauthentication_required", "{missing}");
    let (ticket, file) = device.mint(ALICE);
    let resolved = device.call(
        "approvals.resolve",
        Some(json!({ "approval_id": approval, "decision": "approved", "ticket": ticket })),
    );
    assert_eq!(
        resolved["result"]["approval"]["status"], "approved",
        "{resolved}"
    );
    assert!(!file.exists());
    let set = device.call(
        "capabilities.set",
        Some(json!({ "capability": "security.firewall", "desired_state": "disabled" })),
    );
    assert!(
        set.get("result").is_some(),
        "the grant works while she holds the role: {set}"
    );

    // Take the role away (bob first, so she is not the last one).
    let (ticket, _) = device.mint(ALICE);
    assert_eq!(
        device.admins_set("bob", true, Some(&ticket))["result"]["changed"],
        true
    );
    let (ticket, _) = device.mint(ALICE);
    assert_eq!(
        device.admins_set("alice", false, Some(&ticket))["result"]["changed"],
        true
    );
    assert!(!device.member("alice"));

    let set = device.call(
        "capabilities.set",
        Some(json!({ "capability": "security.firewall", "desired_state": "enabled" })),
    );
    assert_eq!(reason(&set), "device_admin_required", "{set}");
}

/// F-ADM-2.
#[test]
fn the_last_administrator_is_never_removed_and_every_change_is_audited() {
    let mut device = Device::new();
    device.as_person(BOB);
    let listed = device.call("admins.list", None);
    assert_eq!(listed["result"]["mode"], "local", "{listed}");
    assert_eq!(listed["result"]["administrators"], json!(["alice"]));
    assert_eq!(listed["result"]["caller"]["user"], "bob");
    assert_eq!(listed["result"]["caller"]["administrator"], false);
    assert_eq!(listed["result"]["accounts"][1]["user"], "bob");
    assert_eq!(listed["result"]["accounts"][1]["administrator"], false);

    // Bob cannot give himself the role.
    let (ticket, file) = device.mint(BOB);
    let refused = device.admins_set("bob", true, Some(&ticket));
    assert_eq!(reason(&refused), "device_admin_required", "{refused}");
    assert!(file.exists());
    assert!(!device.member("bob"));

    // Alice cannot remove herself while she is the only one — refused
    // before her password is spent.
    device.as_person(ALICE);
    let (ticket, file) = device.mint(ALICE);
    let last = device.admins_set("alice", false, Some(&ticket));
    assert_eq!(reason(&last), "last_administrator", "{last}");
    assert!(file.exists());
    assert!(device.member("alice"));

    // She makes bob one, then may step down; bob is then the last one.
    let (ticket, _) = device.mint(ALICE);
    let granted = device.admins_set("bob", true, Some(&ticket));
    assert_eq!(granted["result"]["changed"], true, "{granted}");
    assert_eq!(granted["result"]["administrators"], json!(["alice", "bob"]));
    assert!(device.member("bob"));
    let recorded: Value = serde_json::from_slice(
        &fs::read(
            device
                .dir
                .join("identity/accounts/acct_00000000000000b0/account.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(recorded["groups"], json!(["punar", "punar-admin"]));
    assert_eq!(recorded["home"], "/home/bob", "no other field was touched");

    let (ticket, _) = device.mint(ALICE);
    assert_eq!(
        device.admins_set("alice", false, Some(&ticket))["result"]["changed"],
        true
    );
    device.as_person(BOB);
    let (ticket, file) = device.mint(BOB);
    let last = device.admins_set("bob", false, Some(&ticket));
    assert_eq!(reason(&last), "last_administrator", "{last}");
    assert!(file.exists());

    // No ticket, an unknown account, an agent.
    let missing = device.admins_set("alice", true, None);
    assert_eq!(reason(&missing), "reauthentication_required", "{missing}");
    let (ticket, _) = device.mint(BOB);
    let nobody = device.admins_set("mallory", true, Some(&ticket));
    assert_eq!(nobody["error"]["code"], "not_found", "{nobody}");
    device.as_peer(BOB, AGENT_PID);
    let (ticket, file) = device.mint(BOB);
    let agent = device.admins_set("alice", true, Some(&ticket));
    assert_eq!(reason(&agent), "agent_scope", "{agent}");
    assert!(file.exists());

    // Every change and every refusal is in the trail, attributed.
    let events: Vec<(String, String, String)> = device
        .audit()
        .into_iter()
        .filter(|e| e["action"] == "admins.set")
        .map(|e| {
            (
                e["user_id"].as_str().unwrap().to_string(),
                e["resource"].as_str().unwrap().to_string(),
                e["result"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    for expected in [
        ("uid:1001", "account/bob", "device_admin_required"),
        ("uid:1000", "account/alice", "last_administrator"),
        ("uid:1000", "account/bob", "success"),
        ("uid:1000", "account/alice", "success"),
        ("uid:1001", "account/bob", "last_administrator"),
        ("uid:1001", "account/alice", "denied"),
    ] {
        assert!(
            events
                .iter()
                .any(|(u, r, res)| (u.as_str(), r.as_str(), res.as_str()) == expected),
            "{expected:?} in {events:?}"
        );
    }
    let trail = fs::read_to_string(device.dir.join("audit.jsonl")).unwrap();
    assert!(
        !trail.contains(&format!("{:064x}", 0xadd0_0000_u128)),
        "no ticket is audited"
    );
}

/// On an enrolled device the organization can pin the list, or deny local
/// administrators, and the local list is inert while it does.
#[test]
fn an_organization_can_pin_the_list_or_turn_local_administration_off() {
    let mut device = Device::new();
    device.organization_roster(json!({ "mode": "pinned", "accounts": ["bob"] }));

    device.as_person(ALICE);
    let listed = device.call("admins.list", None);
    assert_eq!(listed["result"]["mode"], "pinned", "{listed}");
    assert_eq!(listed["result"]["administrators"], json!(["bob"]));
    assert_eq!(listed["result"]["source"]["policy_id"], "acme-baseline-v4");
    // Alice is a local member and is not an administrator while pinned.
    let (ticket, file) = device.mint(ALICE);
    let refused = device.policy_set(Some(&ticket));
    assert_eq!(reason(&refused), "device_admin_required", "{refused}");
    assert_eq!(
        refused["error"]["details"]["administrators_policy"],
        "pinned"
    );
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Acme IT")
    );
    assert!(file.exists());
    // And the list itself is the organization's to change.
    let (ticket, _) = device.mint(ALICE);
    let set = device.admins_set("bob", true, Some(&ticket));
    assert_eq!(reason(&set), "administrators_set_by_organization", "{set}");

    // Bob, whom the organization lists, may act.
    device.as_person(BOB);
    let (ticket, _) = device.mint(BOB);
    let pinned = device.policy_set(Some(&ticket));
    assert!(pinned.get("result").is_some(), "{pinned}");

    // `none`: nobody at the device; root still may.
    device.organization_roster(json!({ "mode": "none" }));
    device.as_person(BOB);
    let (ticket, _) = device.mint(BOB);
    let refused = device.policy_set(Some(&ticket));
    assert_eq!(reason(&refused), "device_admin_required", "{refused}");
    assert_eq!(refused["error"]["details"]["administrators_policy"], "none");
    device.as_person(0);
    let root = device.policy_set(None);
    assert!(root.get("result").is_some(), "{root}");
}
