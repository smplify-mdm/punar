//! Integration tests: a real daemon on a tempdir socket, driven over the
//! wire exactly as punarctl will drive it (docs/api/ipc.md).
//!
//! The registry is the scriptable `MockCapability`; peer identity uses the
//! test-only `PeerSource::Fixed` hook (root vs non-root), plus one
//! Linux-only test of the real `SO_PEERCRED` path.
//!
//! M4 note: `TestDaemon::start` runs the boot reconcile before the socket
//! opens, mirroring `punard run` — SPEC section 52 states are guaranteed
//! before any request is served, and the boot reconcile's audit summary
//! event exists in every test's trail (tests count deltas, not absolutes,
//! where that matters).

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use punar_common::update::{Architecture, BootPlatform};
use punard::authz::{Peer, PeerSource};
use punard::capability::Registry;
use punard::capability::mock::MockCapability;
use punard::server::{Daemon, DaemonConfig, DaemonHandle};
use punard::update_check::UpdateCheckSources;
use punard::update_transaction::UpdateTransactionSources;
use serde_json::{Value, json};

static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

struct TestDaemon {
    dir: PathBuf,
    handle: Option<DaemonHandle>,
    mock: MockCapability,
}

fn test_dir(tag: &str) -> PathBuf {
    let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("punard-it-{tag}-{}-{seq}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_nss_files(dir: &Path) -> (PathBuf, PathBuf) {
    // /etc/{group,passwd} substitutes so username resolution is
    // deterministic regardless of the host.
    let group_file = dir.join("group");
    fs::write(&group_file, "root:x:0:\npunar:x:970:\n").unwrap();
    let passwd_file = dir.join("passwd");
    fs::write(
        &passwd_file,
        "root:x:0:0::/root:/bin/bash\npunar:x:1000:1000::/home/punar:/bin/nologin\n",
    )
    .unwrap();
    (group_file, passwd_file)
}

impl TestDaemon {
    fn start(peer: PeerSource) -> Self {
        let mock = MockCapability::new("mock.widget", json!("off"));
        Self::start_with(peer, mock, |_| {})
    }

    /// Start a daemon around `mock`, after `prepare` has had a chance to
    /// pre-populate the state directory (policy.d drops, an M3
    /// desired.json, …). Runs the boot reconcile before the socket opens,
    /// like `punard run`.
    fn start_with(peer: PeerSource, mock: MockCapability, prepare: impl FnOnce(&Path)) -> Self {
        Self::start_configured(peer, mock, prepare, |_, _| {})
    }

    fn start_configured(
        peer: PeerSource,
        mock: MockCapability,
        prepare: impl FnOnce(&Path),
        configure: impl FnOnce(&mut DaemonConfig, &Path),
    ) -> Self {
        let dir = test_dir("d");
        let (group_file, passwd_file) = write_nss_files(&dir);
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        prepare(&state_dir);

        let registry = Registry::new(vec![Box::new(mock.clone())]);
        let mut cfg = DaemonConfig {
            group_file,
            passwd_file,
            peer_source: peer,
            io_timeout: Duration::from_secs(5),
            ..DaemonConfig::new(dir.join("punard.sock"), state_dir, dir.join("audit.jsonl"))
        };
        configure(&mut cfg, &dir);
        let daemon = Daemon::new(cfg, registry).unwrap();
        daemon.boot_reconcile();
        let handle = daemon.spawn().unwrap();
        TestDaemon {
            dir,
            handle: Some(handle),
            mock,
        }
    }

    fn start_as_root() -> Self {
        Self::start(PeerSource::Fixed(Peer::root()))
    }

    fn start_as_uid(uid: u32) -> Self {
        Self::start(PeerSource::Fixed(Peer {
            uid,
            gid: uid,
            pid: None,
        }))
    }

    fn start_update(peer: PeerSource, configure: impl FnOnce(&mut DaemonConfig, &Path)) -> Self {
        let dir = test_dir("update");
        let (group_file, passwd_file) = write_nss_files(&dir);
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let mock = MockCapability::new("mock.widget", json!("off"));
        let channel =
            MockCapability::with_default("system.update_channel", json!("stable"), json!("stable"));
        let registry = Registry::new(vec![Box::new(mock.clone()), Box::new(channel)]);
        let mut cfg = DaemonConfig {
            group_file,
            passwd_file,
            peer_source: peer,
            io_timeout: Duration::from_secs(5),
            ..DaemonConfig::new(dir.join("punard.sock"), state_dir, dir.join("audit.jsonl"))
        };
        configure(&mut cfg, &dir);
        let daemon = Daemon::new(cfg, registry).unwrap();
        daemon.boot_reconcile();
        let handle = daemon.spawn().unwrap();
        TestDaemon {
            dir,
            handle: Some(handle),
            mock,
        }
    }

    fn connect(&self) -> UnixStream {
        let stream = UnixStream::connect(self.handle.as_ref().unwrap().socket_path()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
    }

    /// One request per connection, like punarctl.
    fn call(&self, method: &str, params: Option<Value>) -> Value {
        let mut req = json!({ "v": 1, "id": "t-1", "method": method });
        if let Some(p) = params {
            req["params"] = p;
        }
        self.raw(&format!("{req}"))
    }

    /// Send a raw line, read one response line.
    fn raw(&self, line: &str) -> Value {
        let mut stream = self.connect();
        stream.write_all(line.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        serde_json::from_str(&response).unwrap()
    }

    fn audit_lines(&self) -> Vec<Value> {
        match fs::read_to_string(self.dir.join("audit.jsonl")) {
            Ok(content) => content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str(l).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn state_path(&self, name: &str) -> PathBuf {
        self.dir.join("state").join(name)
    }
}

fn app_catalog_fixture(dir: &Path) -> (PathBuf, PathBuf, String) {
    let metadata = "[Application]\nruntime=org.freedesktop.Platform/x86_64/25.08\n[Context]\nshared=network;\nsockets=wayland;pulseaudio;\ndevices=dri;\n";
    let digest = punard::util::sha256_hex(metadata.as_bytes());
    let metadata_path = dir.join("app-metadata");
    let state_path = dir.join("app-state");
    let argv_path = dir.join("app-argv");
    fs::write(&metadata_path, metadata).unwrap();
    let flatpak = dir.join("flatpak");
    let commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fs::write(
        &flatpak,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$1\" in\nremote-info) cat '{}' ;;\nlist) if [ -f '{}' ]; then printf 'com.spotify.Client\\t%s\\n' \"$(cat '{}')\"; fi ;;\ninfo) [ -f '{}' ] && cat '{}' || exit 1 ;;\ninstall) printf '%s\\n' '{}' > '{}' ;;\nuninstall) rm -f '{}' ;;\n*) exit 1 ;;\nesac\n",
            argv_path.display(), metadata_path.display(), state_path.display(),
            state_path.display(), state_path.display(), state_path.display(), commit,
            state_path.display(), state_path.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&flatpak, fs::Permissions::from_mode(0o755)).unwrap();
    let catalog = dir.join("catalog.json");
    fs::write(
        &catalog,
        serde_json::to_vec_pretty(&json!({
            "v": 1, "catalogVersion": "test", "generatedAt": "2026-08-27T00:00:00Z",
            "remotes": [{"id":"flathub", "repoFile":"/usr/share/punar/catalog/remotes/flathub.flatpakrepo", "url":"https://dl.flathub.org/repo/"}],
            "apps": [{
                "id":"spotify", "name":"Spotify", "category":"media", "summary":"Music",
                "trustTier":"community", "license":"proprietary", "publisher":"flathub",
                "bundledUpdater":"disabled-by-packaging", "disclosures":[],
                "sources":[{"kind":"flatpak", "architectures":["x86_64"], "remote":"flathub",
                    "appId":"com.spotify.Client", "ref":"app/com.spotify.Client/x86_64/stable",
                    "commit":commit, "runtime":"org.freedesktop.Platform/x86_64/25.08",
                    "metadataSha256":digest}]
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    (catalog, flatpak, digest)
}

fn test_uki(root_partuuid: &str) -> Vec<u8> {
    let cmdline = format!("root=PARTUUID={root_partuuid} ro quiet\0").into_bytes();
    let data_offset = 128_u32;
    let mut image = vec![0_u8; data_offset as usize + cmdline.len()];
    image[..2].copy_from_slice(b"MZ");
    image[60..64].copy_from_slice(&64_u32.to_le_bytes());
    image[64..68].copy_from_slice(b"PE\0\0");
    image[70..72].copy_from_slice(&1_u16.to_le_bytes());
    image[88..96].copy_from_slice(b".cmdline");
    image[104..108].copy_from_slice(&(cmdline.len() as u32).to_le_bytes());
    image[108..112].copy_from_slice(&data_offset.to_le_bytes());
    image[data_offset as usize..].copy_from_slice(&cmdline);
    image
}

fn configure_update_fixture(
    cfg: &mut DaemonConfig,
    dir: &Path,
    source_present: bool,
    tampered: bool,
) {
    let repository = dir.join("update-source");
    let keys = dir.join("release-keys");
    let os_release = dir.join("os-release");
    fs::create_dir_all(&repository).unwrap();
    fs::create_dir_all(&keys).unwrap();
    fs::write(
        &os_release,
        "IMAGE_ID=punar-desktop\nIMAGE_VERSION=2026.08.20.1\n",
    )
    .unwrap();
    let signing = SigningKey::from_bytes(&[17; 32]);
    fs::write(keys.join("fixture.pub"), signing.verifying_key().to_bytes()).unwrap();
    if source_present {
        let mut document = serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "image_id": "punar-desktop",
            "architecture": "aarch64",
            "boot_platform": "uefi",
            "channel": "stable",
            "current": "2026.08.27.1",
            "release_manifest": "releases/2026.08.27.1/release.json",
            "rollout_bps": 10000,
            "halted": false,
            "published_at": "2026-08-27T22:00:00Z",
            "min_supported_version": "2026.08.01.1"
        }))
        .unwrap();
        let signature = signing.sign(&document).to_bytes();
        if tampered {
            document[20] ^= 1;
        }
        fs::write(repository.join("channel.json"), document).unwrap();
        fs::write(repository.join("channel.json.sig"), signature).unwrap();

        let release = repository.join("releases/2026.08.27.1");
        fs::create_dir_all(&release).unwrap();
        let root_a = vec![0xa1_u8; 4096];
        let root_b = vec![0xb2_u8; 4096];
        let uki_a = test_uki(punard::install::ROOT_A_PARTUUID);
        let uki_b = test_uki(punard::install::ROOT_B_PARTUUID);
        let payload = |filename: &str, bytes: &[u8]| {
            json!({
                "filename": filename,
                "digest_sha256": punard::util::sha256_hex(bytes),
                "size_bytes": bytes.len(),
                "uncompressed_digest_sha256": punard::util::sha256_hex(bytes),
                "uncompressed_size_bytes": bytes.len(),
                "compression": "zstd"
            })
        };
        let boot = |filename: &str, bytes: &[u8]| {
            json!({
                "kind": "uki",
                "filename": filename,
                "digest_sha256": punard::util::sha256_hex(bytes),
                "size_bytes": bytes.len()
            })
        };
        for (name, bytes) in [
            ("slot-a.raw.zst", root_a.as_slice()),
            ("slot-b.raw.zst", root_b.as_slice()),
            ("slot-a.efi", uki_a.as_slice()),
            ("slot-b.efi", uki_b.as_slice()),
        ] {
            fs::write(release.join(name), bytes).unwrap();
        }
        let slot_a_payload = payload("slot-a.raw.zst", &root_a);
        let slot_a_boot = boot("slot-a.efi", &uki_a);
        let manifest = serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "release_id": "punar-desktop-stable-aarch64-uefi-2026.08.27.1",
            "image_id": "punar-desktop",
            "architecture": "aarch64",
            "boot_platform": "uefi",
            "version": "2026.08.27.1",
            "channel": "stable",
            "snapshot_pin": "20260820T000000Z",
            "overlay_pin": null,
            "payload": slot_a_payload,
            "boot_artifact": slot_a_boot,
            "uefi_slots": {
                "a": {
                    "payload": payload("slot-a.raw.zst", &root_a),
                    "boot_artifact": boot("slot-a.efi", &uki_a)
                },
                "b": {
                    "payload": payload("slot-b.raw.zst", &root_b),
                    "boot_artifact": boot("slot-b.efi", &uki_b)
                }
            },
            "min_from": null,
            "security": {"severity": "none", "advisory_ids": []},
            "provenance": {
                "git_commit": "0123456789abcdef0123456789abcdef01234567",
                "ci_run_id": "daemon-integration",
                "builder_base_digest": format!("sha256:{}", "3".repeat(64)),
                "source_date_epoch": 1787184000,
                "built_at": "2026-08-27T22:00:00Z"
            },
            "sbom": null
        }))
        .unwrap();
        fs::write(release.join("release.json"), &manifest).unwrap();
        fs::write(
            release.join("release.json.sig"),
            signing.sign(&manifest).to_bytes(),
        )
        .unwrap();
    }
    cfg.update_check_sources = UpdateCheckSources {
        repository_url_file: dir.join("update-repository.url"),
        repository_url_owner_uid: rustix::process::geteuid().as_raw(),
        repository_dir: repository,
        curl_bin: dir.join("curl"),
        trusted_keys_dir: keys,
        cached_channel: cfg.state_dir.join("update/verified-channel.json"),
        cached_signature: cfg.state_dir.join("update/verified-channel.json.sig"),
        os_release,
        pi_boot_partition: dir.join("pi-partition"),
        cache_max_age_seconds: 900,
        architecture_override: Some(Architecture::Aarch64),
        boot_platform_override: Some(BootPlatform::Uefi),
    };
}

fn configure_update_apply_fixture(cfg: &mut DaemonConfig, dir: &Path) {
    configure_update_fixture(cfg, dir, true, false);
    let cmdline = dir.join("update-cmdline");
    fs::write(
        &cmdline,
        format!("root=PARTUUID={} ro\n", punard::install::ROOT_A_PARTUUID),
    )
    .unwrap();
    let root_a = dir.join("root-a");
    let root_b = dir.join("root-b");
    for path in [&root_a, &root_b] {
        let file = fs::File::create(path).unwrap();
        file.set_len(8192).unwrap();
    }
    fs::write(&root_a, vec![0x11_u8; 8192]).unwrap();
    let esp = dir.join("esp");
    fs::create_dir_all(esp.join("EFI/Linux")).unwrap();
    fs::create_dir_all(esp.join("loader")).unwrap();
    fs::write(
        esp.join("EFI/Linux/punar_2026.08.20.1.efi"),
        test_uki(punard::install::ROOT_A_PARTUUID),
    )
    .unwrap();
    fs::write(
        esp.join("loader/loader.conf"),
        "preferred punar_2026.08.20.1*.efi\ntimeout 0\neditor no\n",
    )
    .unwrap();
    let zstd = dir.join("zstd");
    fs::write(&zstd, "#!/bin/sh\nexec /bin/cat\n").unwrap();
    fs::set_permissions(&zstd, fs::Permissions::from_mode(0o755)).unwrap();
    cfg.update_transaction_sources = UpdateTransactionSources {
        cmdline,
        root_a_partition: root_a,
        root_b_partition: root_b,
        esp_partition: dir.join("unused-esp-device"),
        mount_root: dir.join("update-mounts"),
        pending_uefi: cfg.state_dir.join("update/pending-uefi.json"),
        zstd_path: zstd,
        allow_regular_targets: true,
        esp_mount_override: Some(esp),
    };
}

fn prepare_enrolled_application_policy(state_dir: &Path, applications: Value) {
    let policy_dir = state_dir.join("policy.d");
    fs::create_dir_all(&policy_dir).unwrap();
    fs::write(
        policy_dir.join("application-baseline.json"),
        serde_json::to_vec_pretty(&json!({
            "policy_id": "application-baseline",
            "source_kind": "organization_baseline",
            "precedence_rank": 2,
            "source_name": "Acme Application Baseline",
            "policy": {
                "apiVersion": "smplify.io/v1alpha1",
                "kind": "DeviceDesiredState",
                "metadata": {"organization": "acme", "device": "dev_test"},
                "spec": {"applications": applications}
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        state_dir.join("enrollment.json"),
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "org": {
                "id": "acme",
                "name": "Acme",
                "display_name": "Acme Engineering",
                "domain": "acme.test"
            },
            "enrolled_at": "2026-08-30T00:00:00Z",
            "attestation": "test",
            "policy_files": ["application-baseline.json"],
            "last_sync": {"at": null, "result": null},
            "last_inventory_hash": null
        }))
        .unwrap(),
    )
    .unwrap();
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

const AUDIT_REQUIRED_KEYS: [&str; 12] = [
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
];

fn configure_empty_live_installer(cfg: &mut DaemonConfig, dir: &Path) {
    let block = dir.join("sys-block");
    let devices = dir.join("dev-block");
    let udev = dir.join("udev-data");
    fs::create_dir_all(&block).unwrap();
    fs::create_dir_all(&devices).unwrap();
    fs::create_dir_all(&udev).unwrap();
    let mountinfo = dir.join("mountinfo");
    fs::write(&mountinfo, "").unwrap();
    cfg.live_mode = true;
    cfg.installer_sources.sys_class_block = block;
    cfg.installer_sources.dev_root = devices;
    cfg.installer_sources.udev_data_root = udev;
    cfg.installer_sources.mountinfo_path = mountinfo;
    cfg.installer_sources.status_path = dir.join("install.json");
}

fn assert_schema_shaped(event: &Value) {
    let obj = event.as_object().unwrap();
    for key in AUDIT_REQUIRED_KEYS {
        assert!(obj.contains_key(key), "audit event missing {key}: {event}");
    }
    assert_eq!(obj.len(), 12, "additionalProperties: false — {event}");
    assert!(obj["event_id"].as_str().unwrap().starts_with("evt_"));
    assert!(obj["device_id"].as_str().unwrap().starts_with("dev_"));
    assert!(
        obj["agent_session_id"]
            .as_str()
            .unwrap()
            .starts_with("agt_")
    );
    let decision = obj["decision"].as_str().unwrap();
    assert!(matches!(decision, "allow" | "deny" | "approval_required"));
    let ts = obj["timestamp"].as_str().unwrap();
    assert_eq!(ts.len(), 20, "RFC3339 Z-form: {ts}");
    assert!(ts.ends_with('Z'));
}

#[test]
fn status_reports_personal_mode_with_compliance() {
    let td = TestDaemon::start_as_root();
    let resp = td.call("status", None);
    assert_eq!(resp["v"], 1);
    assert_eq!(resp["id"], "t-1");
    let result = &resp["result"];
    assert_eq!(result["protocol_version"], 1);
    assert_eq!(result["mode"], "personal");
    assert_eq!(result["enrolled"], false);
    assert!(result["device_id"].as_str().unwrap().starts_with("dev_"));
    assert_eq!(result["capabilities_total"], 1);
    assert!(result.get("audit").is_some());
    // Design section 8: no org fields exist in personal mode.
    assert!(result.get("org").is_none());
    assert!(result.get("organization").is_none());

    // M4: the SPEC section 52 personal-scope compliance block — the boot
    // reconcile ran before the socket opened, so states exist.
    let compliance = &result["compliance"];
    assert_eq!(compliance["overall"], "compliant");
    let caps = compliance["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0]["capability"], "mock.widget");
    assert_eq!(caps[0]["state"], "compliant");
    assert_eq!(compliance["drift_remediated_total"], 0);
    assert_eq!(compliance["last_remediation_at"], Value::Null);
}

#[test]
fn capabilities_list_returns_schema_shaped_descriptors() {
    let td = TestDaemon::start_as_root();
    let resp = td.call("capabilities.list", None);
    let caps = resp["result"]["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 1);
    let d = &caps[0];
    assert_eq!(d["capability"], "mock.widget");
    assert_eq!(d["supported"], true);
    assert_eq!(d["mutable"], true);
    assert_eq!(d["requires_reboot"], false);
    assert_eq!(d["managed_by"], "local");
    assert_eq!(d["privilege_required"], "root");
    assert_eq!(d["approval_requirement"], "allow");
    assert_eq!(d["current_state"], "off");
    // M4: desired_state renders the effective value (the OS-default seed).
    assert_eq!(d["desired_state"], "off");
}

#[test]
fn catalog_install_is_digest_bound_human_available_and_audited() {
    let mock = MockCapability::new("mock.widget", json!("off"));
    let td = TestDaemon::start_configured(
        PeerSource::Fixed(Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        }),
        mock,
        |_| {},
        |cfg, dir| {
            let (catalog, flatpak, _digest) = app_catalog_fixture(dir);
            cfg.app_catalog_path = Some(catalog);
            cfg.flatpak_bin = flatpak;
            cfg.app_arch_override = Some("x86_64".to_string());
        },
    );
    let detail = td.call("apps.catalog", Some(json!({ "id": "spotify" })));
    assert_eq!(
        detail["result"]["app"]["inspection"]["verified"], true,
        "{detail}"
    );
    assert_eq!(
        detail["result"]["app"]["inspection"]["containment"],
        "sandboxed"
    );
    let digest = detail["result"]["app"]["inspection"]["metadata_sha256"]
        .as_str()
        .unwrap();

    let stale = td.call(
        "apps.install",
        Some(json!({
            "id": "spotify",
            "confirm_metadata_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        })),
    );
    assert_eq!(stale["error"]["code"], "verify_failed");
    assert!(!td.dir.join("app-state").exists());

    let installed = td.call(
        "apps.install",
        Some(json!({
            "id": "spotify",
            "confirm_metadata_sha256": digest,
        })),
    );
    assert_eq!(installed["result"]["installed"], true);
    assert_eq!(installed["result"]["changed"], true);
    let events = td.audit_lines();
    let event = events.last().unwrap();
    assert_schema_shaped(event);
    assert_eq!(event["action"], "system.install_package");
    assert_eq!(event["resource"], "spotify");
    assert_eq!(event["source"], "human");
    assert_eq!(event["result"], "success");
}

#[test]
fn catalog_update_all_updates_only_installed_apps_to_signed_targets_and_audits() {
    let mock = MockCapability::new("mock.widget", json!("off"));
    let td = TestDaemon::start_configured(
        PeerSource::Fixed(Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        }),
        mock,
        |_| {},
        |cfg, dir| {
            let (catalog, flatpak, _digest) = app_catalog_fixture(dir);
            cfg.app_catalog_path = Some(catalog);
            cfg.flatpak_bin = flatpak;
            cfg.app_arch_override = Some("x86_64".to_string());
        },
    );
    let absent = td.call("apps.update", Some(json!({ "id": "spotify" })));
    assert_eq!(absent["error"]["code"], "conflict", "{absent}");
    assert_eq!(absent["error"]["details"]["installed"], false);

    fs::write(
        td.dir.join("app-state"),
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n",
    )
    .unwrap();

    let listed = td.call("apps.list", None);
    assert_eq!(listed["result"]["updates_available"], 1, "{listed}");
    assert_eq!(listed["result"]["apps"][0]["update_available"], true);

    let invalid = td.call("apps.update", Some(json!({ "all": true, "id": "spotify" })));
    assert_eq!(invalid["error"]["code"], "invalid_params", "{invalid}");
    assert_eq!(
        fs::read_to_string(td.dir.join("app-state")).unwrap().trim(),
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    );

    let updated = td.call("apps.update", Some(json!({ "all": true })));
    assert_eq!(updated["result"]["eligible"], 1, "{updated}");
    assert_eq!(updated["result"]["updated"], 1);
    assert_eq!(updated["result"]["current"], 0);
    assert_eq!(updated["result"]["failed"], 0);
    assert_eq!(updated["result"]["apps"][0]["status"], "updated");
    assert_eq!(
        fs::read_to_string(td.dir.join("app-state")).unwrap().trim(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let event = td.audit_lines().last().unwrap().clone();
    assert_eq!(event["action"], "system.update_package");
    assert_eq!(event["resource"], "spotify");
    assert_eq!(event["result"], "success");

    let current = td.call("apps.update", Some(json!({ "id": "spotify" })));
    assert_eq!(current["result"]["updated"], 0, "{current}");
    assert_eq!(current["result"]["current"], 1);
    assert_eq!(current["result"]["apps"][0]["status"], "current");
    assert_eq!(td.audit_lines().last().unwrap()["result"], "noop");
}

#[test]
fn managed_required_app_installs_but_cannot_be_removed() {
    let mock = MockCapability::new("mock.widget", json!("off"));
    let td = TestDaemon::start_configured(
        PeerSource::Fixed(Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        }),
        mock,
        |state_dir| {
            prepare_enrolled_application_policy(
                state_dir,
                json!({
                    "required": ["spotify"],
                    "denied": [],
                    "allowUserInstall": false
                }),
            );
        },
        |cfg, dir| {
            let (catalog, flatpak, _digest) = app_catalog_fixture(dir);
            cfg.app_catalog_path = Some(catalog);
            cfg.flatpak_bin = flatpak;
            cfg.app_arch_override = Some("x86_64".to_string());
        },
    );
    let detail = td.call("apps.catalog", Some(json!({"id": "spotify"})));
    let digest = detail["result"]["app"]["inspection"]["metadata_sha256"]
        .as_str()
        .unwrap();
    let installed = td.call(
        "apps.install",
        Some(json!({
            "id": "spotify",
            "confirm_metadata_sha256": digest
        })),
    );
    assert_eq!(installed["result"]["installed"], true, "{installed}");

    let removed = td.call("apps.remove", Some(json!({"id": "spotify"})));
    assert_eq!(removed["error"]["code"], "denied", "{removed}");
    assert_eq!(removed["error"]["details"]["reason"], "required");
    assert_eq!(
        removed["error"]["details"]["policy_ids"],
        json!(["application-baseline"])
    );
    assert!(td.dir.join("app-state").exists(), "denial changed nothing");
}

#[test]
fn managed_denied_app_is_not_installed_and_optional_remove_is_allowed() {
    let mock = MockCapability::new("mock.widget", json!("off"));
    let denied = TestDaemon::start_configured(
        PeerSource::Fixed(Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        }),
        mock,
        |state_dir| {
            prepare_enrolled_application_policy(
                state_dir,
                json!({
                    "required": [],
                    "denied": [{"package": "spotify"}],
                    "allowUserInstall": true
                }),
            );
        },
        |cfg, dir| {
            let (catalog, flatpak, _digest) = app_catalog_fixture(dir);
            cfg.app_catalog_path = Some(catalog);
            cfg.flatpak_bin = flatpak;
            cfg.app_arch_override = Some("x86_64".to_string());
        },
    );
    let detail = denied.call("apps.catalog", Some(json!({"id": "spotify"})));
    let digest = detail["result"]["app"]["inspection"]["metadata_sha256"]
        .as_str()
        .unwrap();
    let response = denied.call(
        "apps.install",
        Some(json!({
            "id": "spotify",
            "confirm_metadata_sha256": digest
        })),
    );
    assert_eq!(response["error"]["code"], "denied", "{response}");
    assert_eq!(response["error"]["details"]["reason"], "denied");
    assert!(!denied.dir.join("app-state").exists());

    let optional = TestDaemon::start_configured(
        PeerSource::Fixed(Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        }),
        MockCapability::new("mock.widget", json!("off")),
        |state_dir| {
            prepare_enrolled_application_policy(
                state_dir,
                json!({
                    "required": [],
                    "denied": [],
                    "allowUserInstall": true
                }),
            );
        },
        |cfg, dir| {
            let (catalog, flatpak, _digest) = app_catalog_fixture(dir);
            cfg.app_catalog_path = Some(catalog);
            cfg.flatpak_bin = flatpak;
            cfg.app_arch_override = Some("x86_64".to_string());
        },
    );
    let detail = optional.call("apps.catalog", Some(json!({"id": "spotify"})));
    let digest = detail["result"]["app"]["inspection"]["metadata_sha256"]
        .as_str()
        .unwrap();
    assert_eq!(
        optional.call(
            "apps.install",
            Some(json!({
                "id": "spotify",
                "confirm_metadata_sha256": digest
            }))
        )["result"]["installed"],
        true
    );
    let removed = optional.call("apps.remove", Some(json!({"id": "spotify"})));
    assert_eq!(removed["result"]["installed"], false, "{removed}");
    assert_eq!(removed["result"]["changed"], true);
}

#[test]
fn set_as_root_applies_verifies_audits_and_records_the_preference() {
    let td = TestDaemon::start_as_root();
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    assert!(resp.get("error").is_none(), "{resp}");
    assert_eq!(resp["result"]["changed"], true);
    assert_eq!(resp["result"]["descriptor"]["current_state"], "on");
    // Personal mode: nothing outranks the preference — the result carries
    // no override fields (byte-identical to M3, contract section 5.4).
    assert!(resp["result"].get("overridden").is_none());
    assert!(resp["result"].get("effective_state").is_none());
    assert_eq!(td.mock.state(), json!("on"));
    assert_eq!(td.mock.apply_calls(), 1);

    let audit = td.audit_lines();
    let ev = audit.last().unwrap();
    assert_schema_shaped(ev);
    assert_eq!(ev["action"], "capabilities.set");
    assert_eq!(ev["resource"], "mock.widget");
    assert_eq!(ev["decision"], "allow");
    assert_eq!(ev["result"], "success");
    assert_eq!(ev["user_id"], "root");
    assert_eq!(ev["source"], "human");
    assert_eq!(ev["policy_ids"], json!(["personal-defaults"]));

    // M4: the request was recorded as a User Preference layer entry; the
    // M3 desired.json store no longer exists.
    let preferences: Value =
        serde_json::from_str(&fs::read_to_string(td.state_path("preferences.json")).unwrap())
            .unwrap();
    assert_eq!(preferences["version"], 1);
    assert_eq!(preferences["preferences"]["mock.widget"]["value"], "on");
    assert_eq!(preferences["preferences"]["mock.widget"]["set_by"], "root");
    assert!(!td.state_path("desired.json").exists());
    // The OS-default seed store exists alongside.
    assert!(td.state_path("os-defaults.json").exists());
}

#[test]
fn set_as_non_root_is_denied_audited_and_does_not_mutate() {
    let td = TestDaemon::start_as_uid(1000);
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    let error = &resp["error"];
    assert_eq!(error["code"], "denied");
    // SPEC section 73 voice — the m3-check greps for these two markers.
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("administrator"), "{message}");
    assert!(message.contains("personal defaults"), "{message}");
    assert_eq!(error["details"]["capability"], "mock.widget");
    assert_eq!(error["details"]["policy_ids"], json!(["personal-defaults"]));

    // No mutation happened — and no preference was recorded.
    assert_eq!(td.mock.state(), json!("off"));
    assert_eq!(td.mock.apply_calls(), 0);
    assert!(!td.state_path("preferences.json").exists());

    // The denial is audited.
    let audit = td.audit_lines();
    let ev = audit.last().unwrap();
    assert_schema_shaped(ev);
    assert_eq!(ev["decision"], "deny");
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["user_id"], "punar");
    assert_eq!(ev["policy_ids"], json!(["personal-defaults"]));
}

#[test]
fn reads_are_open_to_non_root_peers_and_are_not_audited() {
    let td = TestDaemon::start_as_uid(1000);
    let baseline = td.audit_lines().len(); // boot reconcile summary
    assert!(td.call("status", None).get("error").is_none());
    let update = td.call("update.status", None);
    assert!(update.get("error").is_none());
    assert_eq!(update["result"]["v"], 1);
    assert_eq!(update["result"]["desired"]["state"], "unknown");
    assert!(td.call("capabilities.list", None).get("error").is_none());
    assert!(
        td.call("audit.tail", Some(json!({ "n": 5 })))
            .get("error")
            .is_none()
    );
    // M4: the policy read methods are open to any connected peer too.
    assert!(td.call("policy.effective", None).get("error").is_none());
    assert!(
        td.call("policy.explain", Some(json!({ "path": "mock.widget" })))
            .get("error")
            .is_none()
    );
    // Reads are not audited.
    assert_eq!(td.audit_lines().len(), baseline);
}

#[test]
fn update_check_is_root_only_authenticated_cached_and_audited() {
    let td = TestDaemon::start_update(PeerSource::Fixed(Peer::root()), |cfg, dir| {
        configure_update_fixture(cfg, dir, true, false)
    });
    let before = td.audit_lines().len();
    let response = td.call("update.check", Some(json!({ "force": false })));
    let result = &response["result"];
    assert_eq!(result["current"], "2026.08.20.1");
    assert_eq!(result["available"], "2026.08.27.1");
    assert_eq!(result["admissible"], true);
    assert_eq!(result["cached"], false);

    let cache = td.state_path("update/verified-channel.json");
    let signature = td.state_path("update/verified-channel.json.sig");
    assert!(cache.is_file());
    assert!(signature.is_file());
    assert_eq!(
        fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(cache.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let event = td.audit_lines().pop().unwrap();
    assert_eq!(td.audit_lines().len(), before + 1);
    assert_eq!(event["action"], "update.check");
    assert_eq!(event["resource"], "update_channel");
    assert_eq!(event["result"], "success");

    let cached = td.call("update.check", Some(json!({ "force": false })));
    assert_eq!(cached["result"]["cached"], true);
}

#[test]
fn update_check_non_root_denial_writes_no_cache_and_is_audited() {
    let td = TestDaemon::start_update(
        PeerSource::Fixed(Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        }),
        |cfg, dir| configure_update_fixture(cfg, dir, true, false),
    );
    let response = td.call("update.check", Some(json!({ "force": true })));
    assert_eq!(response["error"]["code"], "denied");
    assert!(!td.state_path("update/verified-channel.json").exists());
    let event = td.audit_lines().pop().unwrap();
    assert_eq!(event["action"], "update.check");
    assert_eq!(event["decision"], "deny");
    assert_eq!(event["result"], "denied");
}

#[test]
fn update_check_tampering_fails_as_untrusted_and_never_caches() {
    let td = TestDaemon::start_update(PeerSource::Fixed(Peer::root()), |cfg, dir| {
        configure_update_fixture(cfg, dir, true, true)
    });
    let response = td.call("update.check", Some(json!({ "force": true })));
    assert_eq!(response["error"]["code"], "untrusted_artifact");
    assert_eq!(response["error"]["details"]["stage"], "channel_signature");
    assert!(!td.state_path("update/verified-channel.json").exists());
    let event = td.audit_lines().pop().unwrap();
    assert_eq!(event["action"], "update.check");
    assert_eq!(event["result"], "failure");
}

#[test]
fn update_check_missing_source_is_visible_and_audited_as_unreachable() {
    let td = TestDaemon::start_update(PeerSource::Fixed(Peer::root()), |cfg, dir| {
        configure_update_fixture(cfg, dir, false, false)
    });
    let response = td.call("update.check", Some(json!({ "force": true })));
    assert_eq!(response["error"]["code"], "upstream_unreachable");
    assert!(!td.state_path("update/verified-channel.json").exists());
    let event = td.audit_lines().pop().unwrap();
    assert_eq!(event["action"], "update.check");
    assert_eq!(event["result"], "unreachable");
}

#[test]
fn update_apply_and_rollback_are_verified_inactive_slot_transactions() {
    let td = TestDaemon::start_update(PeerSource::Fixed(Peer::root()), |cfg, dir| {
        configure_update_apply_fixture(cfg, dir)
    });
    let root_a_before = fs::read(td.dir.join("root-a")).unwrap();
    let check = td.call("update.check", Some(json!({"force": true})));
    assert_eq!(check["result"]["admissible"], true, "{check}");

    let applied = td.call(
        "update.apply",
        Some(json!({
            "version": "2026.08.27.1",
            "allow_downgrade": false
        })),
    );
    assert_eq!(
        applied["result"]["staged_version"], "2026.08.27.1",
        "{applied}"
    );
    assert_eq!(applied["result"]["staged_slot"], "b");
    assert_eq!(applied["result"]["verified"], true);
    assert_eq!(applied["result"]["requires_reboot"], true);
    assert_eq!(fs::read(td.dir.join("root-a")).unwrap(), root_a_before);
    assert_eq!(
        &fs::read(td.dir.join("root-b")).unwrap()[..4096],
        &vec![0xb2_u8; 4096],
    );
    let esp = td.dir.join("esp");
    assert!(
        esp.join("EFI/Linux/punar_2026.08.20.1.efi").is_file(),
        "last-known-good UKI must be retained"
    );
    assert!(esp.join("EFI/Linux/punar_2026.08.27.1+3-0.efi").is_file());
    assert!(
        fs::read_to_string(esp.join("loader/loader.conf"))
            .unwrap()
            .contains("preferred punar_2026.08.27.1*.efi")
    );
    assert!(td.state_path("update/pending-uefi.json").is_file());

    let rolled_back = td.call("update.rollback", Some(json!({"to_version": null})));
    assert_eq!(
        rolled_back["result"]["previous_default"],
        "punar_2026.08.27.1*.efi"
    );
    assert_eq!(
        rolled_back["result"]["new_default"],
        "punar_2026.08.20.1*.efi"
    );
    assert_eq!(rolled_back["result"]["requires_reboot"], true);
    assert!(!td.state_path("update/pending-uefi.json").exists());
    assert!(
        fs::read_to_string(esp.join("loader/loader.conf"))
            .unwrap()
            .contains("preferred punar_2026.08.20.1*.efi")
    );
    let events = td.audit_lines();
    for action in ["update.apply", "update.rollback"] {
        let event = events
            .iter()
            .find(|event| event["action"] == action)
            .unwrap();
        assert_eq!(event["resource"], "system_image");
        assert_eq!(event["decision"], "allow");
        assert_eq!(event["result"], "success");
    }
}

#[test]
fn update_apply_from_slot_b_uses_the_independently_bound_slot_a_pair() {
    let td = TestDaemon::start_update(PeerSource::Fixed(Peer::root()), |cfg, dir| {
        configure_update_apply_fixture(cfg, dir);
        fs::write(
            &cfg.update_transaction_sources.cmdline,
            format!("root=PARTUUID={} ro\n", punard::install::ROOT_B_PARTUUID),
        )
        .unwrap();
        fs::write(
            dir.join("esp/EFI/Linux/punar_2026.08.20.1.efi"),
            test_uki(punard::install::ROOT_B_PARTUUID),
        )
        .unwrap();
    });
    let root_b_before = fs::read(td.dir.join("root-b")).unwrap();
    let applied = td.call(
        "update.apply",
        Some(json!({
            "version": "2026.08.27.1",
            "allow_downgrade": false
        })),
    );
    assert_eq!(applied["result"]["staged_slot"], "a", "{applied}");
    assert_eq!(applied["result"]["verified"], true);
    assert_eq!(fs::read(td.dir.join("root-b")).unwrap(), root_b_before);
    assert_eq!(
        &fs::read(td.dir.join("root-a")).unwrap()[..4096],
        &vec![0xa1_u8; 4096],
    );
    assert!(
        td.dir
            .join("esp/EFI/Linux/punar_2026.08.27.1+3-0.efi")
            .is_file()
    );
}

#[test]
fn update_apply_refreshes_the_signed_head_and_honors_a_new_halt() {
    let td = TestDaemon::start_update(PeerSource::Fixed(Peer::root()), |cfg, dir| {
        configure_update_apply_fixture(cfg, dir)
    });
    let check = td.call("update.check", Some(json!({"force": true})));
    assert_eq!(check["result"]["admissible"], true, "{check}");

    let repository = td.dir.join("update-source");
    let channel_path = repository.join("channel.json");
    let mut channel: Value = serde_json::from_slice(&fs::read(&channel_path).unwrap()).unwrap();
    channel["halted"] = json!(true);
    let document = serde_json::to_vec_pretty(&channel).unwrap();
    let signing = SigningKey::from_bytes(&[17; 32]);
    fs::write(&channel_path, &document).unwrap();
    fs::write(
        repository.join("channel.json.sig"),
        signing.sign(&document).to_bytes(),
    )
    .unwrap();

    let root_b_before = fs::read(td.dir.join("root-b")).unwrap();
    let response = td.call(
        "update.apply",
        Some(json!({
            "version": "2026.08.27.1",
            "allow_downgrade": false
        })),
    );
    assert_eq!(
        response["error"]["code"], "untrusted_artifact",
        "{response}"
    );
    assert_eq!(response["error"]["details"]["stage"], "channel_admission");
    assert_eq!(fs::read(td.dir.join("root-b")).unwrap(), root_b_before);
    assert!(!td.state_path("update/pending-uefi.json").exists());
}

#[test]
fn update_apply_denies_non_root_before_release_or_slot_access() {
    let td = TestDaemon::start_update(
        PeerSource::Fixed(Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        }),
        configure_update_apply_fixture,
    );
    let root_b_before = fs::read(td.dir.join("root-b")).unwrap();
    let response = td.call(
        "update.apply",
        Some(json!({
            "version": "2026.08.27.1",
            "allow_downgrade": false
        })),
    );
    assert_eq!(response["error"]["code"], "denied");
    assert_eq!(fs::read(td.dir.join("root-b")).unwrap(), root_b_before);
    assert!(!td.state_path("update/pending-uefi.json").exists());
}

#[test]
fn update_apply_denies_root_inside_an_agent_scope_by_named_rule() {
    let td = TestDaemon::start_update(
        PeerSource::Fixed(Peer {
            uid: 0,
            gid: 0,
            pid: Some(4242),
        }),
        |cfg, dir| {
            configure_update_apply_fixture(cfg, dir);
            let proc_root = dir.join("proc");
            fs::create_dir_all(proc_root.join("4242")).unwrap();
            fs::write(
                proc_root.join("4242/cgroup"),
                "0::/user.slice/punar-agent-agt_updatetest.scope\n",
            )
            .unwrap();
            cfg.proc_root = proc_root;
        },
    );
    let response = td.call(
        "update.apply",
        Some(json!({
            "version": "2026.08.27.1",
            "allow_downgrade": false
        })),
    );
    assert_eq!(response["error"]["code"], "denied");
    assert_eq!(response["error"]["details"]["rule"], "host.system_update");
    assert_eq!(
        response["error"]["details"]["policy_ids"],
        json!(["personal-defaults"])
    );
    let event = td
        .audit_lines()
        .into_iter()
        .find(|event| event["action"] == "update.apply")
        .unwrap();
    assert_eq!(event["source"], "ai_agent");
    assert_eq!(event["agent_session_id"], "agt_updatetest");
    assert_eq!(event["decision"], "deny");
    assert_eq!(event["result"], "denied");
}

#[test]
fn update_apply_agent_denial_cannot_be_overridden_by_an_allow_policy() {
    let td = TestDaemon::start_update(
        PeerSource::Fixed(Peer {
            uid: 0,
            gid: 0,
            pid: Some(4243),
        }),
        |cfg, dir| {
            configure_update_apply_fixture(cfg, dir);
            let proc_root = dir.join("proc");
            fs::create_dir_all(proc_root.join("4243")).unwrap();
            fs::write(
                proc_root.join("4243/cgroup"),
                "0::/user.slice/punar-agent-agt_updateallow.scope\n",
            )
            .unwrap();
            cfg.proc_root = proc_root;
            cfg.ai_defaults_file = dir.join("ai-allow.yaml");
            fs::write(
                &cfg.ai_defaults_file,
                "ai:\n  agents:\n    default:\n      filesystem: {}\n      host:\n        system_update: allow\n      network: {}\n      credentials: {}\n",
            )
            .unwrap();
        },
    );
    let response = td.call(
        "update.apply",
        Some(json!({
            "version": "2026.08.27.1",
            "allow_downgrade": false
        })),
    );
    assert_eq!(response["error"]["code"], "denied");
    assert_eq!(response["error"]["details"]["rule"], "host.system_update");
    assert_eq!(
        response["error"]["details"]["policy_ids"],
        json!(["os-hard-safety"])
    );
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Punar OS hard safety constraint")
    );
    assert!(!td.state_path("update/pending-uefi.json").exists());
}

/// M4 semantics (contract section 5.6): reconcile now REMEDIATES drift —
/// the deliberate behavior change M3 pre-announced by making the method
/// root-only. This replaces the M3 test of report-only reconcile.
#[test]
fn reconcile_remediates_drift_and_audits_every_attempt() {
    let td = TestDaemon::start_as_root();
    // Set desired = "on" (audited apply), then simulate external drift.
    td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    let applies_before = td.mock.apply_calls();
    td.mock.set_state(json!("tampered"));

    let resp = td.call("reconcile", None);
    let result = &resp["result"];
    // M3 fields keep their M3 meaning: pre-remediation observation.
    assert_eq!(result["drift_count"], 1);
    let entry = &result["capabilities"][0];
    assert_eq!(entry["capability"], "mock.widget");
    assert_eq!(entry["desired_state"], "on");
    assert_eq!(entry["current_state"], "tampered");
    assert_eq!(entry["drift"], true);
    // M4 additive fields: classification + what this pass did.
    assert_eq!(entry["classification"], "auto_remediate");
    assert_eq!(entry["remediation"], "applied");
    assert_eq!(result["remediated_count"], 1);
    assert_eq!(result["compliance"]["overall"], "compliant");
    assert_eq!(result["compliance"]["drift_remediated_total"], 1);
    assert!(result["compliance"]["last_remediation_at"].is_string());

    // The drift was actually fixed.
    assert_eq!(td.mock.apply_calls(), applies_before + 1);
    assert_eq!(td.mock.state(), json!("on"));

    // Audit: one event per remediation attempt + the unchanged M3 summary.
    let audit = td.audit_lines();
    let summary = audit.last().unwrap();
    assert_schema_shaped(summary);
    assert_eq!(summary["action"], "reconcile");
    assert_eq!(summary["resource"], "capability_registry");
    assert_eq!(summary["result"], "drift_detected");
    let remediate = &audit[audit.len() - 2];
    assert_schema_shaped(remediate);
    assert_eq!(remediate["action"], "reconcile.remediate");
    assert_eq!(remediate["resource"], "mock.widget");
    assert_eq!(remediate["decision"], "allow");
    assert_eq!(remediate["result"], "success");
    assert_eq!(remediate["policy_ids"], json!(["personal-defaults"]));

    // A second reconcile is clean and remediates nothing.
    let resp = td.call("reconcile", None);
    assert_eq!(resp["result"]["drift_count"], 0);
    assert_eq!(resp["result"]["remediated_count"], 0);
    assert_eq!(resp["result"]["capabilities"][0]["remediation"], "none");
    assert_eq!(td.audit_lines().pop().unwrap()["result"], "clean");

    // status reflects the remediation counter (the drift-demo observable).
    let status = td.call("status", None);
    assert_eq!(status["result"]["compliance"]["drift_remediated_total"], 1);
}

/// Loop protection (contract section 5.6): 3 consecutive failed attempts →
/// non_compliant + one attempts_exhausted audit event on the transition,
/// then suppression until a manual set succeeds.
#[test]
fn remediation_loop_protection_engages_and_resets() {
    let td = TestDaemon::start_as_root();
    td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    td.mock.set_state(json!("tampered"));
    td.mock.fail_next_applies(true);

    // Attempts 1 and 2: apply fails, capability is remediating.
    for attempt in 1..=2 {
        let resp = td.call("reconcile", None);
        let entry = &resp["result"]["capabilities"][0];
        assert_eq!(entry["remediation"], "apply_failed", "attempt {attempt}");
        assert_eq!(resp["result"]["remediated_count"], 0);
        assert_eq!(resp["result"]["compliance"]["overall"], "remediating");
        let audit = td.audit_lines();
        let ev = &audit[audit.len() - 2];
        assert_eq!(ev["action"], "reconcile.remediate");
        assert_eq!(ev["result"], "apply_failed", "attempt {attempt}");
    }

    // Attempt 3: the transition — attempts_exhausted, non_compliant.
    let resp = td.call("reconcile", None);
    let entry = &resp["result"]["capabilities"][0];
    assert_eq!(entry["remediation"], "apply_failed");
    assert_eq!(resp["result"]["compliance"]["overall"], "non_compliant");
    let audit = td.audit_lines();
    let ev = &audit[audit.len() - 2];
    assert_schema_shaped(ev);
    assert_eq!(ev["action"], "reconcile.remediate");
    assert_eq!(ev["result"], "attempts_exhausted");
    let exhausted_events = audit
        .iter()
        .filter(|e| e["result"] == "attempts_exhausted")
        .count();
    assert_eq!(exhausted_events, 1, "one event, on the transition");

    // Attempt 4: suppressed — no further apply, no new remediate event.
    let applies = td.mock.apply_calls();
    let events = td.audit_lines().len();
    let resp = td.call("reconcile", None);
    let entry = &resp["result"]["capabilities"][0];
    assert_eq!(entry["remediation"], "suppressed");
    assert_eq!(resp["result"]["compliance"]["overall"], "non_compliant");
    assert_eq!(td.mock.apply_calls(), applies, "no apply while suppressed");
    // Only the summary event was appended.
    assert_eq!(td.audit_lines().len(), events + 1);
    assert_eq!(
        td.audit_lines().pop().unwrap()["action"],
        "reconcile",
        "suppressed pass audits only the summary"
    );

    // status shows the section 52 state.
    let status = td.call("status", None);
    assert_eq!(
        status["result"]["compliance"]["capabilities"][0]["state"],
        "non_compliant"
    );

    // A successful manual set clears the suppression…
    td.mock.fail_next_applies(false);
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    assert!(resp.get("error").is_none(), "{resp}");
    assert_eq!(td.mock.state(), json!("on"));
    // …and the next drift is remediated again.
    td.mock.set_state(json!("tampered"));
    let resp = td.call("reconcile", None);
    assert_eq!(resp["result"]["capabilities"][0]["remediation"], "applied");
    assert_eq!(resp["result"]["compliance"]["overall"], "compliant");
    assert_eq!(td.mock.state(), json!("on"));
}

#[test]
fn reconcile_is_root_only_and_denials_are_audited() {
    let td = TestDaemon::start_as_uid(1000);
    let resp = td.call("reconcile", None);
    assert_eq!(resp["error"]["code"], "denied");
    let ev = td.audit_lines().pop().unwrap();
    assert_schema_shaped(&ev);
    assert_eq!(ev["action"], "reconcile");
    assert_eq!(ev["decision"], "deny");
}

// ---------------------------------------------------------------------------
// M4: policy.effective / policy.explain (contract sections 5.7, 5.8)
// ---------------------------------------------------------------------------

#[test]
fn policy_effective_and_explain_cover_both_personal_source_kinds() {
    let td = TestDaemon::start_as_root();

    // Before any set: the OS-default (observation-seeded) layer wins.
    let resp = td.call("policy.effective", None);
    let result = &resp["result"];
    assert!(result["computed_at"].is_string());
    let entries = result["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["path"], "mock.widget");
    assert_eq!(entry["effective_value"], "off");
    assert_eq!(entry["source"]["kind"], "os_secure_default");
    assert_eq!(entry["source"]["rank"], 6);
    assert_eq!(entry["source"]["policy_id"], "personal-defaults");
    assert_eq!(entry["source"]["name"], "OS default");
    assert_eq!(entry["user_override_permitted"], true);
    assert_eq!(entry["compliance_state"], "compliant");

    // After a set: the User Preference layer wins.
    td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    let resp = td.call("policy.explain", Some(json!({ "path": "mock.widget" })));
    let result = &resp["result"];
    assert_eq!(result["effective_value"], "on");
    assert_eq!(result["source"]["kind"], "local_user_preference");
    assert_eq!(result["source"]["rank"], 5);
    assert_eq!(result["source"]["policy_id"], "personal-defaults");
    assert_eq!(result["source"]["name"], "Personal preference");
    assert_eq!(result["user_override_permitted"], true);
    assert_eq!(result["compliance_state"], "compliant");
    assert!(result.get("path").is_none(), "explain omits the path field");
}

#[test]
fn policy_explain_unknown_path_is_not_found_in_section_73_voice() {
    let td = TestDaemon::start_as_root();
    let resp = td.call(
        "policy.explain",
        Some(json!({ "path": "not.a_capability" })),
    );
    let error = &resp["error"];
    assert_eq!(error["code"], "not_found");
    assert_eq!(error["details"]["param"], "path");
    assert_eq!(error["details"]["path"], "not.a_capability");
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("not.a_capability"), "{message}");
    assert!(message.contains("Next step"), "{message}");
    assert!(message.contains("punarctl policy effective"), "{message}");
}

#[test]
fn no_write_side_policy_method_exists() {
    // Contract section 8: the only policy mutations are capabilities.set
    // and (M5) the enrollment-managed policy.d drop.
    let td = TestDaemon::start_as_root();
    for probe in ["policy.set", "policy.write", "policy.apply"] {
        let resp = td.call(probe, Some(json!({ "path": "mock.widget" })));
        assert_eq!(resp["error"]["code"], "unknown_method", "probe {probe}");
    }
}

/// The Acme org fixtures through the whole daemon: an organization_baseline
/// drop in policy.d outranks the user preference (SPEC sections 39, 40).
/// Engine/tests only until M5 — the shipped image's policy.d is empty and
/// nothing org renders in the VM (design language section 8).
#[test]
fn org_policy_drop_overrides_the_user_preference() {
    let mut envelope: Value = serde_json::from_str(include_str!(
        "../../../fixtures/organizations/acme/policy-source-eng-baseline-v12.json"
    ))
    .unwrap();
    let desired: Value = serde_json::from_str(include_str!(
        "../../../fixtures/organizations/acme/desired-state-eng-baseline-v12.json"
    ))
    .unwrap();
    envelope
        .as_object_mut()
        .unwrap()
        .insert("policy".to_string(), desired);

    let mock = MockCapability::new("security.firewall", json!("disabled"));
    let td = TestDaemon::start_with(PeerSource::Fixed(Peer::root()), mock, move |state_dir| {
        let policy_dir = state_dir.join("policy.d");
        fs::create_dir_all(&policy_dir).unwrap();
        fs::write(
            policy_dir.join("eng-baseline-v12.json"),
            serde_json::to_string(&envelope).unwrap(),
        )
        .unwrap();
    });

    // Boot reconcile already remediated toward the org value.
    assert_eq!(td.mock.state(), json!("enabled"));
    let boot_remediate = td
        .audit_lines()
        .into_iter()
        .find(|e| e["action"] == "reconcile.remediate")
        .expect("boot remediation audited");
    assert_eq!(boot_remediate["policy_ids"], json!(["eng-baseline-v12"]));
    assert_eq!(boot_remediate["user_id"], "punard");
    assert_eq!(boot_remediate["source"], "service");

    // Explain cites the org source and pins the value.
    let resp = td.call(
        "policy.explain",
        Some(json!({ "path": "security.firewall" })),
    );
    let result = &resp["result"];
    assert_eq!(result["effective_value"], "enabled");
    assert_eq!(result["source"]["kind"], "organization_baseline");
    assert_eq!(result["source"]["rank"], 2);
    assert_eq!(result["source"]["policy_id"], "eng-baseline-v12");
    assert_eq!(result["source"]["name"], "Acme Engineering Baseline");
    assert_eq!(result["user_override_permitted"], false);

    // A root set records the preference but the EFFECTIVE value stays the
    // org's: the result says so via the optional override fields.
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "security.firewall", "desired_state": "disabled" })),
    );
    let result = &resp["result"];
    assert_eq!(result["changed"], false, "already in the effective state");
    assert_eq!(result["overridden"], true);
    assert_eq!(result["effective_state"], "enabled");
    assert_eq!(td.mock.state(), json!("enabled"), "org value stands");
    let preferences: Value =
        serde_json::from_str(&fs::read_to_string(td.state_path("preferences.json")).unwrap())
            .unwrap();
    assert_eq!(
        preferences["preferences"]["security.firewall"]["value"], "disabled",
        "the preference is still recorded (it wins the day the org rung lifts)"
    );
    // The set audit cites the winning policy.
    let ev = td.audit_lines().pop().unwrap();
    assert_eq!(ev["action"], "capabilities.set");
    assert_eq!(ev["result"], "noop");
    assert_eq!(ev["policy_ids"], json!(["eng-baseline-v12"]));
}

/// The one-shot M3 → M4 store migration through a real daemon start
/// (docs/development/milestone-4.md section 3.3). Fresh installs — every
/// CI image boot — skip this path entirely; it is host-test-only coverage.
#[test]
fn m3_desired_store_is_migrated_once_at_startup() {
    let mock = MockCapability::with_default("mock.widget", json!("off"), json!("on"));
    let td = TestDaemon::start_with(PeerSource::Fixed(Peer::root()), mock, |state_dir| {
        // An M3 store whose recorded value differs from the compiled
        // default: it can only have come from a root set → preference.
        fs::write(state_dir.join("desired.json"), r#"{"mock.widget": "off"}"#).unwrap();
    });

    // The store was split and retired.
    let preferences: Value =
        serde_json::from_str(&fs::read_to_string(td.state_path("preferences.json")).unwrap())
            .unwrap();
    assert_eq!(preferences["preferences"]["mock.widget"]["value"], "off");
    assert_eq!(
        preferences["preferences"]["mock.widget"]["set_by"],
        "migrated"
    );
    assert!(!td.state_path("desired.json").exists());
    assert!(td.state_path("desired.json.pre-m4").exists());

    // The migration is audited.
    let migrate = td
        .audit_lines()
        .into_iter()
        .find(|e| e["action"] == "state.migrate")
        .expect("state.migrate audited");
    assert_schema_shaped(&migrate);
    assert_eq!(migrate["resource"], "state_store");
    assert_eq!(migrate["user_id"], "punard");
    assert_eq!(migrate["source"], "service");
    assert_eq!(migrate["result"], "success");

    // The migrated preference governs: explain cites rank 5, and the boot
    // reconcile already applied it (initial state "off" == preference).
    let resp = td.call("policy.explain", Some(json!({ "path": "mock.widget" })));
    assert_eq!(resp["result"]["effective_value"], "off");
    assert_eq!(resp["result"]["source"]["kind"], "local_user_preference");
    assert_eq!(td.mock.state(), json!("off"));
}

#[test]
fn audit_tail_returns_newest_last_and_clamps() {
    let td = TestDaemon::start_as_root();
    let baseline = td.audit_lines().len() as u64; // boot reconcile summary
    for state in ["a1", "a2", "a3"] {
        td.call(
            "capabilities.set",
            Some(json!({ "capability": "mock.widget", "desired_state": state })),
        );
    }
    let resp = td.call("audit.tail", Some(json!({ "n": 2 })));
    let events = resp["result"]["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    for event in events {
        assert_schema_shaped(event);
    }
    // n over the cap is clamped, not an error.
    let resp = td.call("audit.tail", Some(json!({ "n": 100000 })));
    assert!(resp.get("error").is_none());
    // Default n covers the whole (small) trail.
    let resp = td.call("audit.tail", None);
    assert_eq!(
        resp["result"]["events"].as_array().unwrap().len() as u64,
        baseline + 3
    );
}

#[test]
fn set_is_idempotent_with_noop_audit() {
    let td = TestDaemon::start_as_root();
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "off" })),
    );
    assert_eq!(resp["result"]["changed"], false);
    assert_eq!(td.mock.apply_calls(), 0);
    let ev = td.audit_lines().pop().unwrap();
    assert_schema_shaped(&ev);
    assert_eq!(ev["result"], "noop");
    // Even a noop set records the preference (rank 5 provenance from here
    // on — the m4-check relies on this after m3-check's set).
    let resp = td.call("policy.explain", Some(json!({ "path": "mock.widget" })));
    assert_eq!(resp["result"]["source"]["kind"], "local_user_preference");
}

#[test]
fn apply_failures_are_typed_and_audited() {
    let td = TestDaemon::start_as_root();
    td.mock.fail_next_applies(true);
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    assert_eq!(resp["error"]["code"], "apply_failed");
    assert_eq!(resp["error"]["details"]["stage"], "apply");
    assert_eq!(td.audit_lines().pop().unwrap()["result"], "failure");
}

#[test]
fn verify_failures_are_typed_and_audited() {
    let td = TestDaemon::start_as_root();
    td.mock.force_verify_false(true);
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    assert_eq!(resp["error"]["code"], "verify_failed");
    assert_eq!(resp["error"]["details"]["expected"], "on");
    assert_eq!(td.audit_lines().pop().unwrap()["result"], "verify_failed");
}

#[test]
fn unknown_capability_is_not_found() {
    let td = TestDaemon::start_as_root();
    let resp = td.call(
        "capabilities.get",
        Some(json!({ "capability": "no.such_thing" })),
    );
    assert_eq!(resp["error"]["code"], "not_found");
    assert_eq!(resp["error"]["details"]["capability"], "no.such_thing");
}

#[test]
fn malformed_json_gets_typed_error_with_null_id_and_closes() {
    let td = TestDaemon::start_as_root();
    let mut stream = td.connect();
    stream.write_all(b"this is not json\n").unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["error"]["code"], "malformed_request");
    assert_eq!(resp["id"], Value::Null);
    // The connection is closed after a malformed request.
    line.clear();
    assert_eq!(reader.read_line(&mut line).unwrap(), 0);
}

#[test]
fn oversized_line_is_malformed_request() {
    let td = TestDaemon::start_as_root();
    let big = format!(
        r#"{{"v":1,"id":"big","method":"status","params":{{"x":"{}"}}}}"#,
        "y".repeat(8192)
    );
    let resp = td.raw(&big);
    assert_eq!(resp["error"]["code"], "malformed_request");
    assert!(
        resp["error"]["message"].as_str().unwrap().contains("4096"),
        "{resp}"
    );
}

#[test]
fn unsupported_version_is_rejected_with_supported_list() {
    let td = TestDaemon::start_as_root();
    let resp = td.raw(r#"{"v":2,"id":"vv","method":"status"}"#);
    assert_eq!(resp["error"]["code"], "unsupported_version");
    assert_eq!(resp["error"]["details"]["supported"], json!([1]));
    assert_eq!(resp["id"], "vv");
}

#[test]
fn no_exec_like_method_exists() {
    // SPEC sections 10, 60: the method table is closed; every generic
    // execution probe gets unknown_method — root included.
    let td = TestDaemon::start_as_root();
    for probe in [
        "system.exec",
        "shell.run",
        "exec",
        "run",
        "system.run_as_root",
        "debug.exec",
        "capabilities.exec",
    ] {
        let resp = td.call(probe, Some(json!({ "command": "id" })));
        assert_eq!(resp["error"]["code"], "unknown_method", "probe {probe}");
        assert_eq!(resp["error"]["details"]["method"], probe);
        assert!(
            resp["error"]["message"]
                .as_str()
                .unwrap()
                .contains("does not exist"),
            "{resp}"
        );
    }
}

#[test]
fn unknown_params_are_rejected_strictly() {
    let td = TestDaemon::start_as_root();
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on", "force": true })),
    );
    assert_eq!(resp["error"]["code"], "invalid_params");

    let resp = td.call("status", Some(json!({ "verbose": true })));
    assert_eq!(resp["error"]["code"], "invalid_params");

    let resp = td.call("policy.effective", Some(json!({ "path": "mock.widget" })));
    assert_eq!(resp["error"]["code"], "invalid_params");
}

#[test]
fn invalid_desired_state_is_invalid_params() {
    let td = TestDaemon::start_as_root();
    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": 42 })),
    );
    assert_eq!(resp["error"]["code"], "invalid_params");
    assert_eq!(resp["error"]["details"]["param"], "desired_state");
}

#[test]
fn multiple_requests_on_one_connection_are_sequential() {
    let td = TestDaemon::start_as_root();
    let mut stream = td.connect();
    stream
        .write_all(
            b"{\"v\":1,\"id\":\"a\",\"method\":\"status\"}\n{\"v\":1,\"id\":\"b\",\"method\":\"capabilities.list\"}\n",
        )
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let first: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(first["id"], "a");
    line.clear();
    reader.read_line(&mut line).unwrap();
    let second: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(second["id"], "b");
}

#[test]
fn device_id_is_stable_across_restarts() {
    let dir = test_dir("devid");
    let make = || {
        let mock = MockCapability::new("mock.widget", json!("off"));
        let cfg = DaemonConfig {
            peer_source: PeerSource::Fixed(Peer::root()),
            ..DaemonConfig::new(
                dir.join("punard.sock"),
                dir.join("state"),
                dir.join("audit.jsonl"),
            )
        };
        Daemon::new(cfg, Registry::new(vec![Box::new(mock)]))
            .unwrap()
            .spawn()
            .unwrap()
    };

    let handle = make();
    let stream = UnixStream::connect(handle.socket_path()).unwrap();
    let first_id = status_device_id(stream);
    handle.stop();

    let handle = make();
    let stream = UnixStream::connect(handle.socket_path()).unwrap();
    let second_id = status_device_id(stream);
    handle.stop();

    assert_eq!(first_id, second_id);
    let _ = fs::remove_dir_all(&dir);
}

fn status_device_id(mut stream: UnixStream) -> String {
    stream
        .write_all(b"{\"v\":1,\"id\":\"s\",\"method\":\"status\"}\n")
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let resp: Value = serde_json::from_str(&line).unwrap();
    resp["result"]["device_id"].as_str().unwrap().to_string()
}

/// The real SO_PEERCRED path (Linux only, which is where `cargo test` runs
/// in CI — docker rust:1). Whether we are root decides which side of the
/// authz matrix we exercise; both sides assert *consistency* between the
/// peercred-derived decision and our actual uid.
#[cfg(target_os = "linux")]
#[test]
fn peercred_path_matches_actual_uid() {
    use std::os::unix::fs::MetadataExt;

    let td = TestDaemon::start(PeerSource::SoPeercred);
    // Our effective uid, read from a file we own.
    let probe = td.dir.join("uid-probe");
    fs::write(&probe, b"x").unwrap();
    let my_uid = fs::metadata(&probe).unwrap().uid();

    let resp = td.call(
        "capabilities.set",
        Some(json!({ "capability": "mock.widget", "desired_state": "on" })),
    );
    if my_uid == 0 {
        assert!(resp.get("error").is_none(), "{resp}");
        assert_eq!(td.mock.state(), json!("on"));
    } else {
        assert_eq!(resp["error"]["code"], "denied");
        assert_eq!(td.mock.state(), json!("off"));
    }
    // Reads work either way.
    assert!(td.call("status", None).get("error").is_none());
}

/// M8 / docs/api/ipc.md section 12.5 — the one attribution rule `punard`
/// gained for the AI Access Ledger.
///
/// A capability call made from inside a managed agent session must land in
/// the audit trail carrying that session's id and `source: "ai_agent"`,
/// **including when it is denied**. That denial is the Level-4
/// `denied_access` event the ledger derives; without this rule the ledger's
/// security-event half would be permanently empty and would have to say so.
///
/// The evidence is the kernel's: a `/proc/<pid>/cgroup` fixture standing in
/// for the real scope, read through the injectable `proc_root`. Nothing
/// here traces the call, and the agent is never asked to identify itself.
#[test]
fn a_denied_call_from_inside_an_agent_scope_is_attributed_to_that_session() {
    const SESSION: &str = "agt_4f21c09ab3e1";
    let dir = test_dir("attrib");
    let (group_file, passwd_file) = write_nss_files(&dir);
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir).unwrap();

    // A /proc fixture: pid 4242 lives in the session's transient scope.
    let proc_root = dir.join("proc");
    fs::create_dir_all(proc_root.join("4242")).unwrap();
    fs::write(
        proc_root.join("4242").join("cgroup"),
        format!(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/\
             punar-agent-{SESSION}.scope\n"
        ),
    )
    .unwrap();
    // And pid 4243, an ordinary login shell, is not in any scope.
    fs::create_dir_all(proc_root.join("4243")).unwrap();
    fs::write(
        proc_root.join("4243").join("cgroup"),
        "0::/user.slice/user-1000.slice/session-3.scope\n",
    )
    .unwrap();

    let start = |pid: i32| {
        let mock = MockCapability::new("mock.widget", json!("off"));
        let cfg = DaemonConfig {
            group_file: group_file.clone(),
            passwd_file: passwd_file.clone(),
            proc_root: proc_root.clone(),
            peer_source: PeerSource::Fixed(Peer {
                uid: 1000,
                gid: 1000,
                pid: Some(pid),
            }),
            io_timeout: Duration::from_secs(5),
            ..DaemonConfig::new(
                dir.join(format!("punard-{pid}.sock")),
                state_dir.clone(),
                dir.join("audit.jsonl"),
            )
        };
        Daemon::new(cfg, Registry::new(vec![Box::new(mock)]))
            .unwrap()
            .spawn()
            .unwrap()
    };

    // A mutation from uid 1000 is denied by the M3 rule either way; what
    // changes is who the trail says asked.
    for pid in [4242, 4243] {
        let handle = start(pid);
        let mut stream = UnixStream::connect(handle.socket_path()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .write_all(
                b"{\"v\":1,\"id\":\"x\",\"method\":\"capabilities.set\",\
                  \"params\":{\"capability\":\"mock.widget\",\"desired_state\":\"on\"}}\n",
            )
            .unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["error"]["code"], "denied", "pid {pid}: {response}");
        handle.stop();
    }

    let events: Vec<Value> = fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|e: &Value| e["action"] == "capabilities.set")
        .collect();
    assert_eq!(events.len(), 2, "{events:#?}");

    // From inside the scope: attributed, and still a denial.
    assert_eq!(events[0]["agent_session_id"], SESSION);
    assert_eq!(events[0]["source"], "ai_agent");
    assert_eq!(events[0]["decision"], "deny");
    assert_eq!(events[0]["result"], "denied");
    // The human who owns the session keeps their name on the record.
    assert_eq!(events[0]["user_id"], "punar");

    // From outside: unchanged pre-M8 behaviour, no invented attribution.
    assert_eq!(events[1]["agent_session_id"], "agt_none");
    assert_eq!(events[1]["source"], "human");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn installer_methods_are_unknown_on_an_installed_system() {
    let daemon = TestDaemon::start_as_root();
    for (method, params) in [
        ("install.targets", None),
        (
            "install.plan",
            Some(json!({
                "disk": "/dev/vda",
                "keymap": "us",
                "encryption": "luks2",
                "recovery_mode": "personal_copy"
            })),
        ),
        (
            "install.apply",
            Some(json!({
                "plan_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "disk": "/dev/vda",
                "passphrase_fd": 3,
                "recovery_output_fd": 4,
                "keymap": "us",
                "seed": {"locale": "C.UTF-8"},
                "unattended": false
            })),
        ),
        (
            "install.recovery_ack",
            Some(json!({
                "plan_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "groups_fd": 5
            })),
        ),
        ("install.status", None),
    ] {
        let response = daemon.call(method, params);
        assert_eq!(response["error"]["code"], "unknown_method", "{method}");
        assert_eq!(response["error"]["details"]["mode"], "installed");
    }
}

#[test]
fn live_installer_targets_are_read_only_and_plan_refusals_are_audited() {
    let daemon = TestDaemon::start_configured(
        PeerSource::Fixed(Peer::root()),
        MockCapability::new("mock.widget", json!("off")),
        |_| {},
        configure_empty_live_installer,
    );
    let targets = daemon.call("install.targets", None);
    assert_eq!(targets["result"]["v"], 1);
    assert_eq!(targets["result"]["targets"], json!([]));
    let status = daemon.call("install.status", None);
    assert_eq!(status["result"]["state"], "idle");
    assert_eq!(status["result"]["phases"].as_array().unwrap().len(), 9);
    assert!(daemon.dir.join("install.json").exists());

    let apply = daemon.call(
        "install.apply",
        Some(json!({
            "plan_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "disk": "/dev/vda",
            "passphrase_fd": 3,
            "recovery_output_fd": 4,
            "keymap": "us",
            "seed": {"locale": "C.UTF-8"},
            "unattended": false
        })),
    );
    assert_ne!(apply["error"]["code"], "unknown_method");
    assert_eq!(apply["error"]["code"], "invalid_params");
    assert_eq!(apply["error"]["details"]["disk_changed"], false);

    let plan = daemon.call(
        "install.plan",
        Some(json!({
            "disk": "/dev/vda",
            "keymap": "us",
            "encryption": "luks2",
            "recovery_mode": "personal_copy"
        })),
    );
    assert_eq!(plan["error"]["code"], "invalid_params");
    assert_eq!(plan["error"]["details"]["disk_changed"], false);
    let event = daemon
        .audit_lines()
        .into_iter()
        .find(|event| event["action"] == "install.plan")
        .unwrap();
    assert_eq!(event["resource"], "system_disk");
    assert_eq!(event["result"], "refused");
}

#[test]
fn live_install_apply_denies_agent_attribution_before_descriptor_or_disk_access() {
    let peer = Peer {
        uid: 0,
        gid: 0,
        pid: Some(4242),
    };
    let daemon = TestDaemon::start_configured(
        PeerSource::Fixed(peer),
        MockCapability::new("mock.widget", json!("off")),
        |_| {},
        |cfg, dir| {
            configure_empty_live_installer(cfg, dir);
            let proc_root = dir.join("proc");
            let process = proc_root.join("4242");
            fs::create_dir_all(&process).unwrap();
            fs::write(
                process.join("cgroup"),
                "0::/user.slice/punar-agent-agt_installtest.scope\n",
            )
            .unwrap();
            cfg.proc_root = proc_root;
        },
    );
    let response = daemon.call(
        "install.apply",
        Some(json!({
            "plan_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "disk": "/dev/vda",
            "passphrase_fd": 999999,
            "recovery_output_fd": 999998,
            "keymap": "us",
            "seed": {"locale": "C.UTF-8"},
            "unattended": false
        })),
    );
    assert_eq!(response["error"]["code"], "denied");
    assert_eq!(response["error"]["details"]["disk_changed"], false);
    assert_eq!(
        daemon.call("install.status", None)["result"]["state"],
        "idle"
    );
    assert!(
        fs::read_dir(daemon.dir.join("dev-block"))
            .unwrap()
            .next()
            .is_none()
    );
    let event = daemon
        .audit_lines()
        .into_iter()
        .find(|event| event["action"] == "install.apply")
        .unwrap();
    assert_eq!(event["source"], "ai_agent");
    assert_eq!(event["agent_session_id"], "agt_installtest");
    assert_eq!(event["decision"], "deny");
}

#[test]
fn live_install_plan_is_root_only_before_disk_discovery() {
    let daemon = TestDaemon::start_configured(
        PeerSource::Fixed(Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        }),
        MockCapability::new("mock.widget", json!("off")),
        |_| {},
        configure_empty_live_installer,
    );
    let response = daemon.call(
        "install.plan",
        Some(json!({
            "disk": "/dev/vda",
            "keymap": "us",
            "encryption": "luks2",
            "recovery_mode": "personal_copy"
        })),
    );
    assert_eq!(response["error"]["code"], "denied");
    let event = daemon
        .audit_lines()
        .into_iter()
        .find(|event| event["action"] == "install.plan")
        .unwrap();
    assert_eq!(event["decision"], "deny");
    assert_eq!(event["result"], "denied");
}
