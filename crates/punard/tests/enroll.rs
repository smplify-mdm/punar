//! M5 enrollment integration tests: a real `punard` daemon on a tempdir
//! socket, enrolled against a live control-plane counterparty speaking the
//! `punar-mock-smplify` wire protocol (milestone-5.md section 4.3 —
//! NDJSON `{v,id,method,params}` over a UDS; `org.discover`,
//! `enroll.register`, `policy.fetch`, `compliance.report`,
//! `inventory.report`) and serving the Acme fixtures verbatim, with the
//! one documented composition (envelope + embedded desired-state as
//! `policy`).
//!
//! The counterparty here is an in-test server implementing that documented
//! protocol so the suite can stop, restart, and corrupt it deterministically
//! (offline phases, all-or-nothing aborts); the in-VM `m5-check` exercises
//! the real `punar-mock-smplify` binary end-to-end against the same
//! contract.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use punar_common::storage::StorageSources;
use punar_common::update::{Architecture, BootPlatform};
use punard::authz::{Peer, PeerSource};
use punard::capability::Registry;
use punard::capability::mock::MockCapability;
use punard::device::DeviceSources;
use punard::inventory::CollectorSources;
use punard::server::{Daemon, DaemonConfig, DaemonHandle};
use punard::update_check::UpdateCheckSources;
use punard::update_status::UpdateStatusSources;
use serde_json::{Value, json};

const ACME_ORG: &str = include_str!("../../../fixtures/organizations/acme/org.json");
const ACME_ENVELOPE: &str =
    include_str!("../../../fixtures/organizations/acme/policy-source-eng-baseline-v12.json");
const ACME_DESIRED: &str =
    include_str!("../../../fixtures/organizations/acme/desired-state-eng-baseline-v12.json");

static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

fn test_dir(tag: &str) -> PathBuf {
    let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("punard-m5-{tag}-{}-{seq}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// In-test control plane (the milestone-5.md section 4.3 protocol)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ControlPlaneState {
    /// token → device_id (the mock's `devices.json` in miniature).
    devices: Mutex<HashMap<String, String>>,
    /// Received compliance lines (`received-compliance.jsonl`).
    compliance: Mutex<Vec<Value>>,
    /// Received inventory lines (`received-inventory.jsonl`).
    inventory: Mutex<Vec<Value>>,
    /// The `code` each `enroll.register` carried (`None` when absent): the
    /// enrollment code must reach the control plane and nothing else.
    codes: Mutex<Vec<Option<String>>>,
    /// Fault injection: serve a corrupt policy envelope (contradicted
    /// fixed rank) so the all-or-nothing abort path can be exercised.
    serve_bad_policy: AtomicBool,
    /// Serve no policy at all — a fresh Smplify tenant that has not assigned
    /// anything to this device yet (`policy.fetch` answers `{policies: []}`).
    serve_no_policy: AtomicBool,
    /// Serve a desired state that turns local policy editing off
    /// (spec section 44.5; docs/api/ipc.md section 5.7 `local_admin`).
    deny_local_admin: AtomicBool,
    token_seq: AtomicUsize,
    /// Every method punard called, in order: proves whether anything left
    /// the device on behalf of a caller.
    methods: Mutex<Vec<String>>,
    /// Every request line exactly as it arrived, to prove what never did.
    lines: Mutex<Vec<String>>,
    /// Serve this as the organization document's `enrollment.removable`
    /// (docs/development/smplify-enrollment.md section 3.1); absent when
    /// `None`, as in the Acme fixture.
    org_removable: Mutex<Option<Value>>,
    /// Serve this as the organization document's `enrollment.ownership`
    /// (docs/development/smplify-enrollment.md section 3.2); absent when
    /// `None`, as in the Acme fixture.
    org_ownership: Mutex<Option<Value>>,
    /// Serve these as the organization document's `enrollment.display_name`,
    /// `name` and `discovery.domain`: strings the organization chooses.
    org_display_name: Mutex<Option<Value>>,
    org_name: Mutex<Option<Value>>,
    org_shown_domain: Mutex<Option<Value>>,
    /// Answer `inventory.report` as `punar-smplifyd` does: put the inventory
    /// through the agent's own translation and answer `{sent}` with the
    /// result. Off, it answers as the development mock does.
    translate_like_smplifyd: AtomicBool,
    /// Every body that translation produced: what Smplify itself received.
    status_bodies: Mutex<Vec<Value>>,
    /// Answer these methods only after the given delay: a control plane
    /// that is slow to reach the organization's server.
    answer_late: Mutex<HashMap<&'static str, Duration>>,
    /// Refuse every `inventory.report`: an inventory that cannot get
    /// through.
    refuse_inventory: AtomicBool,
    /// Hold the next report of this method, once its token is resolved,
    /// until `release_held`: a sync pass caught with its report in flight.
    hold_next: Mutex<Option<&'static str>>,
    held: AtomicBool,
    release_held: AtomicBool,
}

impl ControlPlaneState {
    fn handle(&self, method: &str, params: &Value) -> Result<Value, (&'static str, String)> {
        let late = self.answer_late.lock().unwrap().get(method).copied();
        if let Some(delay) = late {
            std::thread::sleep(delay);
        }
        match method {
            "org.discover" => {
                let domain = params["domain"].as_str().unwrap_or_default();
                let mut org: Value = serde_json::from_str(ACME_ORG).unwrap();
                if let Some(removable) = self.org_removable.lock().unwrap().clone() {
                    org["enrollment"]["removable"] = removable;
                }
                if let Some(ownership) = self.org_ownership.lock().unwrap().clone() {
                    org["enrollment"]["ownership"] = ownership;
                }
                if domain != org["discovery"]["domain"].as_str().unwrap() {
                    return Err(("not_found", format!("no organization at {domain:?}")));
                }
                if let Some(name) = self.org_display_name.lock().unwrap().clone() {
                    org["enrollment"]["display_name"] = name;
                }
                if let Some(name) = self.org_name.lock().unwrap().clone() {
                    org["name"] = name;
                }
                if let Some(shown) = self.org_shown_domain.lock().unwrap().clone() {
                    org["discovery"]["domain"] = shown;
                }
                Ok(json!({ "organization": org }))
            }
            "enroll.register" => {
                let device_id = params["device_id"].as_str().unwrap_or_default();
                let bootstrap = params["bootstrap"].as_str().unwrap_or_default();
                // The mock's admission rule: ≥ 32 hex chars.
                if bootstrap.len() < 32 || !bootstrap.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(("invalid_params", "bootstrap must be ≥32 hex chars".into()));
                }
                self.codes
                    .lock()
                    .unwrap()
                    .push(params["code"].as_str().map(str::to_string));
                let seq = self.token_seq.fetch_add(1, Ordering::SeqCst);
                let token = format!("tok_{seq:08x}{}", "e5d1c0de".repeat(6));
                self.devices
                    .lock()
                    .unwrap()
                    .insert(token.clone(), device_id.to_string());
                Ok(json!({
                    "device_token": token,
                    "attestation": "simulated",
                    "organization": serde_json::from_str::<Value>(ACME_ORG).unwrap(),
                }))
            }
            "policy.fetch" => {
                self.device_for(params)?;
                if self.serve_no_policy.load(Ordering::SeqCst) {
                    return Ok(json!({ "policies": [] }));
                }
                let mut envelope: Value = serde_json::from_str(ACME_ENVELOPE).unwrap();
                if self.serve_bad_policy.load(Ordering::SeqCst) {
                    envelope["precedence_rank"] = json!(5); // fixed rank is 2
                }
                let mut desired = serde_json::from_str::<Value>(ACME_DESIRED).unwrap();
                if self.deny_local_admin.load(Ordering::SeqCst) {
                    desired["spec"]["security"]["localAdmin"] =
                        json!({ "policyEditing": "denied" });
                }
                envelope
                    .as_object_mut()
                    .unwrap()
                    .insert("policy".to_string(), desired);
                Ok(json!({ "policies": [envelope] }))
            }
            "compliance.report" => {
                let device_id = self.device_for(params)?;
                self.hold_if_next(method);
                self.compliance.lock().unwrap().push(json!({
                    "device_id": device_id,
                    "received_at": "now",
                    "report": params["report"],
                }));
                Ok(json!({ "accepted": true }))
            }
            "inventory.report" => {
                let device_id = self.device_for(params)?;
                self.hold_if_next(method);
                if self.refuse_inventory.load(Ordering::SeqCst) {
                    return Err(("internal", "the upload did not finish in time".into()));
                }
                self.inventory.lock().unwrap().push(json!({
                    "device_id": device_id,
                    "received_at": "now",
                    "inventory": params["inventory"],
                }));
                if self.translate_like_smplifyd.load(Ordering::SeqCst) {
                    let body = punar_smplifyd::status::inventory_status_body(
                        &device_id,
                        &params["inventory"],
                    );
                    self.status_bodies.lock().unwrap().push(body.clone());
                    return Ok(json!({ "sent": body }));
                }
                Ok(json!({ "accepted": true }))
            }
            // admin.* stays reserved for M10 — like every unknown name.
            "enroll.unregister" => {
                let token = params["device_token"].as_str().unwrap_or_default();
                self.devices.lock().unwrap().remove(token);
                Ok(json!({}))
            }
            other => Err(("unknown_method", format!("no method {other:?}"))),
        }
    }

    /// Hold this report until `release_held` if it is the one `hold_next`
    /// names.
    fn hold_if_next(&self, method: &str) {
        {
            let mut next = self.hold_next.lock().unwrap();
            if *next != Some(method) {
                return;
            }
            *next = None;
        }
        self.held.store(true, Ordering::SeqCst);
        while !self.release_held.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn device_for(&self, params: &Value) -> Result<String, (&'static str, String)> {
        let token = params["device_token"].as_str().unwrap_or_default();
        self.devices
            .lock()
            .unwrap()
            .get(token)
            .cloned()
            .ok_or(("unauthorized", "unknown device token".into()))
    }
}

struct ControlPlane {
    socket: PathBuf,
    state: Arc<ControlPlaneState>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlPlane {
    fn start(dir: &Path) -> ControlPlane {
        Self::start_with(dir, Arc::new(ControlPlaneState::default()))
    }

    /// (Re)start on the same socket path with existing state — the mock's
    /// state deliberately persists across restarts (milestone-5.md § 4.5).
    fn start_with(dir: &Path, state: Arc<ControlPlaneState>) -> ControlPlane {
        let socket = dir.join("control-plane.sock");
        let _ = fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let accept_state = Arc::clone(&state);
        let accept_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if accept_stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { break };
                let state = Arc::clone(&accept_state);
                std::thread::spawn(move || serve_connection(stream, &state));
            }
        });
        ControlPlane {
            socket,
            state,
            stop,
            thread: Some(thread),
        }
    }

    /// Stop the server and remove the socket — the "control plane died"
    /// phase. State survives for a later [`ControlPlane::start_with`].
    fn stop(mut self) -> Arc<ControlPlaneState> {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.socket);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.socket);
        Arc::clone(&self.state)
    }
}

impl Drop for ControlPlane {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.socket);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_connection(stream: UnixStream, state: &ControlPlaneState) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;
    let mut line = String::new();
    while let Ok(read) = reader.read_line(&mut line) {
        if read == 0 {
            break;
        }
        let request: Value = match serde_json::from_str(line.trim_end()) {
            Ok(value) => value,
            Err(_) => break,
        };
        assert_eq!(request["v"], json!(1), "punard must send v:1");
        let id = request["id"].clone();
        let method = request["method"].as_str().unwrap_or_default();
        let params = request.get("params").cloned().unwrap_or(json!({}));
        state.methods.lock().unwrap().push(method.to_string());
        state.lines.lock().unwrap().push(line.clone());
        let response = match state.handle(method, &params) {
            Ok(result) => json!({"v": 1, "id": id, "result": result}),
            Err((code, message)) => {
                json!({"v": 1, "id": id, "error": {"code": code, "message": message}})
            }
        };
        if writeln!(writer, "{response}").is_err() {
            break;
        }
        line.clear();
    }
}

// ---------------------------------------------------------------------------
// Daemon harness (mirrors tests/daemon.rs, plus the M5 config seams)
// ---------------------------------------------------------------------------

struct TestDaemon {
    dir: PathBuf,
    handle: Option<DaemonHandle>,
    #[allow(dead_code)]
    mock: MockCapability,
}

fn write_nss_files(dir: &Path) -> (PathBuf, PathBuf) {
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

fn write_inventory_sources(dir: &Path) -> (PathBuf, PathBuf) {
    let os_release = dir.join("os-release");
    fs::write(
        &os_release,
        "ID=punar\nVERSION_ID=\"0.5\"\nPRETTY_NAME=\"Punar OS 0.5 (M5)\"\n",
    )
    .unwrap();
    let kernel = dir.join("osrelease");
    fs::write(&kernel, "6.12.0-punar\n").unwrap();
    (os_release, kernel)
}

/// The serial number the fixture firmware reports. It must never reach a
/// personal enrollment's inventory.
const FIXTURE_SERIAL: &str = "PNR-FIXTURE-SERIAL-0042";

fn write_file(path: &Path, contents: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

/// A fixture machine for the managed inventory's collectors — a QEMU x86_64
/// guest with SMBIOS, UEFI (Secure Boot off), a TPM 2.0, LUKS2 under /var and
/// /home (hidden from punard's own namespace, as ProtectHome=yes hides it),
/// a system Flatpak installation and Punar's desktop entries — so nothing the
/// daemon reports depends on the host running the test.
fn write_collector_sources(dir: &Path) -> (CollectorSources, UpdateStatusSources, PathBuf) {
    let root = dir.join("machine");
    let at = |relative: &str| root.join(relative);
    write_file(&at("proc/meminfo"), "MemTotal:        8192000 kB\n");
    write_file(&at("sys/devices/system/cpu/online"), "0-3\n");
    for cpu in 0..4 {
        write_file(
            &at(&format!(
                "sys/devices/system/cpu/cpu{cpu}/topology/core_cpus_list"
            )),
            format!("{cpu}\n"),
        );
    }
    write_file(
        &at("proc/cpuinfo"),
        "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: QEMU Virtual CPU\n\
         flags\t\t: fpu hypervisor\n",
    );
    write_file(&at("sys/class/dmi/id/sys_vendor"), "QEMU\n");
    write_file(
        &at("sys/class/dmi/id/product_name"),
        "Standard PC (Q35 + ICH9, 2009)\n",
    );
    write_file(&at("sys/class/dmi/id/bios_version"), "1.16.3\n");
    write_file(
        &at("sys/class/dmi/id/product_serial"),
        format!("{FIXTURE_SERIAL}\n"),
    );
    write_file(
        &at("sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
        [6u8, 0, 0, 0, 0],
    );
    write_file(&at("sys/class/tpm/tpm0/tpm_version_major"), "2\n");
    write_file(&at("sys/class/power_supply/AC/type"), "Mains\n");
    // /var and /home are subvolumes of one btrfs on the LUKS2 mapping
    // punar-data. The system's mount table says so; punard's own ends with
    // the empty tmpfs ProtectHome=yes stacks on /home, as in production.
    fs::create_dir_all(at("var")).unwrap();
    fs::create_dir_all(at("home")).unwrap();
    let system_mounts = format!(
        "22 1 253:1 / / ro,relatime - erofs /dev/mapper/usr ro\n\
         40 22 0:44 /@var {} rw - btrfs /dev/mapper/punar-data rw,subvol=/@var\n\
         41 22 0:44 /@home {} rw - btrfs /dev/mapper/punar-data rw,subvol=/@home\n",
        at("var").display(),
        at("home").display()
    );
    write_file(&at("proc/1/mountinfo"), &system_mounts);
    write_file(
        &at("proc/self/mountinfo"),
        format!(
            "{system_mounts}90 41 0:25 /systemd/inaccessible/dir {} ro - tmpfs tmpfs rw\n",
            at("home").display()
        ),
    );
    write_file(&at("sys/class/block/dm-0/dm/name"), "punar-data\n");
    write_file(&at("sys/class/block/dm-0/dev"), "253:0\n");
    write_file(
        &at("sys/class/block/dm-0/dm/uuid"),
        "CRYPT-LUKS2-0123456789abcdef-punar-data\n",
    );
    fs::create_dir_all(at("sys/fs/btrfs/9f1c/devices/dm-0")).unwrap();
    write_file(
        &at("usr/local/share/applications/org.punar.Mail.desktop"),
        "[Desktop Entry]\nType=Application\nName=Mail\nX-Punar-FirstParty=true\n",
    );
    write_file(
        &at("usr/share/applications/thunar.desktop"),
        "[Desktop Entry]\nType=Application\nName=Thunar File Manager\n",
    );
    // A system installation exists, so only the tier stops it being listed.
    write_file(&at("var/lib/flatpak/.changed"), "");
    let flatpak = at("bin/flatpak");
    write_file(
        &flatpak,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n\
             printf 'org.mozilla.firefox\\tFirefox\\t131.0\\t0123456789ab\\n'\n",
            at("flatpak-argv").display()
        ),
    );
    fs::set_permissions(&flatpak, fs::Permissions::from_mode(0o755)).unwrap();
    write_file(
        &at("var/lib/dpkg/status"),
        "Package: chromium\nStatus: install ok installed\nVersion: 151.0.7922.173-1\n\n",
    );
    write_file(&at("proc/cmdline"), "quiet rw\n");

    let collector = CollectorSources {
        device: DeviceSources {
            meminfo: at("proc/meminfo"),
            cpu_online: at("sys/devices/system/cpu/online"),
            power_supply_dir: at("sys/class/power_supply"),
            drm_dir: at("sys/class/drm"),
        },
        cpuinfo: at("proc/cpuinfo"),
        cpu_dir: at("sys/devices/system/cpu"),
        dmi_dir: at("sys/class/dmi/id"),
        device_tree_dir: at("proc/device-tree"),
        efi_dir: at("sys/firmware/efi"),
        tpm_dir: at("sys/class/tpm"),
        storage: StorageSources {
            sys_dev_block: at("sys/dev/block"),
            sys_class_block: at("sys/class/block"),
            sys_fs_btrfs: at("sys/fs/btrfs"),
            mountinfo: at("proc/self/mountinfo"),
        },
        system_mountinfo: at("proc/1/mountinfo"),
        encrypted_paths: vec![at("var"), at("home")],
        capacity_path: root.clone(),
        desktop_entry_dirs: vec![
            at("usr/local/share/applications"),
            at("usr/share/applications"),
        ],
        flatpak_installation: at("var/lib/flatpak"),
        detect_virt_bin: at("bin/systemd-detect-virt"),
    };
    let update_status = UpdateStatusSources {
        os_release: dir.join("os-release"),
        cmdline: at("proc/cmdline"),
        pi_boot_partition: at("proc/device-tree/chosen/bootloader/partition"),
        pi_tryboot: at("proc/device-tree/chosen/bootloader/tryboot"),
        health_report: at("run/punar/update-health.json"),
        pending_pi: at("var/lib/punar/update/pending-pi.json"),
        pending_uefi: at("var/lib/punar/update/pending-uefi.json"),
        channel_preference: at("var/lib/punar/update/channel"),
        dpkg_status: at("var/lib/dpkg/status"),
        pacman_local: at("var/lib/pacman/local"),
    };
    (collector, update_status, flatpak)
}

impl TestDaemon {
    /// Start a daemon whose control-plane endpoint is `control_plane` and
    /// whose registry holds one `security.firewall` mock (the capability
    /// the Acme baseline pins).
    fn start(dir: &Path, peer: Peer, control_plane: &Path, firewall_state: &str) -> TestDaemon {
        Self::start_with(dir, peer, control_plane, firewall_state, Vec::new(), |_| {})
    }

    /// [`TestDaemon::start`], with more mock capabilities registered after
    /// the firewall and a last word on the configuration.
    fn start_with(
        dir: &Path,
        peer: Peer,
        control_plane: &Path,
        firewall_state: &str,
        more: Vec<MockCapability>,
        configure: impl FnOnce(&mut DaemonConfig),
    ) -> TestDaemon {
        let (group_file, passwd_file) = write_nss_files(dir);
        let (os_release_path, kernel_release_path) = write_inventory_sources(dir);
        let (inventory_sources, update_status_sources, flatpak_bin) = write_collector_sources(dir);
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let mock = MockCapability::new("security.firewall", json!(firewall_state));
        let mut capabilities: Vec<Box<dyn punard::capability::Capability>> =
            vec![Box::new(mock.clone())];
        capabilities.extend(
            more.into_iter()
                .map(|cap| Box::new(cap) as Box<dyn punard::capability::Capability>),
        );
        let registry = Registry::new(capabilities);
        let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let mut cfg = DaemonConfig {
            group_file,
            passwd_file,
            peer_source: PeerSource::Fixed(peer),
            io_timeout: Duration::from_secs(10),
            control_plane_socket: control_plane.to_path_buf(),
            os_release_path,
            kernel_release_path,
            inventory_sources,
            update_status_sources,
            flatpak_bin,
            reauth_ticket_dir: dir.join("tickets"),
            proc_root: dir.join("proc"),
            ..DaemonConfig::new(
                dir.join(format!("punard-{seq}.sock")),
                state_dir,
                dir.join("audit.jsonl"),
            )
        };
        configure(&mut cfg);
        let daemon = Daemon::new(cfg, registry).unwrap();
        daemon.boot_reconcile();
        let handle = daemon.spawn().unwrap();
        TestDaemon {
            dir: dir.to_path_buf(),
            handle: Some(handle),
            mock,
        }
    }

    fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
    }

    fn call(&self, method: &str, params: Option<Value>) -> Value {
        let mut request = json!({ "v": 1, "id": "m5-t", "method": method });
        if let Some(params) = params {
            request["params"] = params;
        }
        let mut stream = UnixStream::connect(self.handle.as_ref().unwrap().socket_path()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream.write_all(request.to_string().as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
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

    fn error(&self, method: &str, params: Option<Value>) -> Value {
        let response = self.call(method, params);
        assert!(
            response.get("result").is_none(),
            "{method} unexpectedly succeeded: {response}"
        );
        response["error"].clone()
    }

    fn state_path(&self, name: &str) -> PathBuf {
        self.dir.join("state").join(name)
    }

    fn audit_text(&self) -> String {
        fs::read_to_string(self.dir.join("audit.jsonl")).unwrap_or_default()
    }

    fn audit_events(&self) -> Vec<Value> {
        self.audit_text()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn status_summary(&self) -> Value {
        serde_json::from_str(&fs::read_to_string(self.state_path("status.json")).unwrap()).unwrap()
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
    }
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn policy_d_files(daemon: &TestDaemon) -> Vec<String> {
    match fs::read_dir(daemon.state_path("policy.d")) {
        Ok(entries) => entries
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Assert the SPEC 24/54 privacy shape of one received compliance line:
/// exact key sets, category states only — never values or activity.
fn assert_compliance_shape(line: &Value, device_id: &str) {
    assert_eq!(line["device_id"], device_id);
    let report = line["report"].as_object().unwrap();
    let mut keys: Vec<&str> = report.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["categories", "overall"], "category states ONLY");
    for entry in report["categories"].as_array().unwrap() {
        let mut keys: Vec<&str> = entry
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["category", "state"]);
    }
}

fn sorted_keys(value: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

/// The received inventory of a personal (not organization-owned) enrollment,
/// as exact key sets: device facts and posture states, the image's own
/// applications, no identifiers — checked where it arrives, not where it was
/// built.
fn assert_personal_inventory(body: &Value) {
    assert_eq!(
        sorted_keys(body),
        [
            "applications",
            "capabilities",
            "hardware",
            "kernel",
            "os",
            "posture"
        ],
        "no identifiers on a personal enrollment, and never the hostname"
    );
    assert_eq!(
        sorted_keys(&body["os"]),
        [
            "architecture",
            "id",
            "image_id",
            "image_version",
            "pretty_name",
            "version_id"
        ]
    );
    assert_eq!(body["os"]["id"], "punar");
    assert!(matches!(
        body["os"]["architecture"].as_str(),
        Some("x86_64" | "aarch64")
    ));
    assert_eq!(body["kernel"], "6.12.0-punar");
    // Which capabilities exist, never what they observe: a value is not a
    // state, and it never leaves the device.
    assert_eq!(
        body["capabilities"],
        json!([{"capability": "security.firewall", "supported": true}])
    );

    assert_eq!(
        body["posture"],
        json!({
            "secure_boot": false,
            "uefi": true,
            "tpm_present": true,
            "tpm_version": "2.0",
            "is_virtual": true,
            "virtualization": null,
            "disk_encryption_enabled": true,
            "firewall_enabled": true,
            "firewall": "nftables",
            // No verified channel check has run on this device.
            "os_patch_status": "unknown",
            "reboot_required": false,
        })
    );
    let hardware = &body["hardware"];
    assert_eq!(
        sorted_keys(hardware),
        [
            "battery_present",
            "bios_version",
            "cpu_cores",
            "cpu_model",
            "cpu_threads",
            "cpu_vendor",
            "device_capacity_bytes",
            "manufacturer",
            "memory_total_bytes",
            "model_name",
            "root_filesystem_type"
        ]
    );
    assert_eq!(hardware["manufacturer"], "QEMU");
    assert_eq!(hardware["model_name"], "Standard PC (Q35 + ICH9, 2009)");
    assert_eq!(hardware["cpu_vendor"], "AuthenticAMD");
    assert_eq!(hardware["cpu_cores"], 4);
    assert_eq!(hardware["cpu_threads"], 4);
    assert_eq!(hardware["memory_total_bytes"], 8_192_000u64 * 1024);
    assert_eq!(hardware["root_filesystem_type"], "erofs");
    assert_eq!(hardware["battery_present"], false);
    assert_eq!(
        hardware["device_capacity_bytes"].as_u64().unwrap() % 1_000_000_000,
        0
    );

    // The image's first-party entry and its browser — never Debian's own
    // entries, never a Flatpak the person installed.
    assert_eq!(
        body["applications"],
        json!([
            {"name": "chromium", "display_name": "Chromium", "version": "151.0.7922.173-1",
             "source": "punar-image", "managed": false},
            {"name": "org.punar.Mail", "display_name": "Mail", "version": null,
             "source": "punar-image", "managed": false},
        ])
    );
    let text = body.to_string();
    for forbidden in [FIXTURE_SERIAL, "firefox", "Thunar", "/home"] {
        assert!(
            !text.contains(forbidden),
            "the inventory carries {forbidden}"
        );
    }
}

// ---------------------------------------------------------------------------
// The lifecycle
// ---------------------------------------------------------------------------

#[test]
fn enroll_lifecycle_org_wins_sync_flows_offline_survives_unenroll_restores() {
    let dir = test_dir("lifecycle");
    let control_plane = ControlPlane::start(&dir);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "disabled");
    let device_id = fs::read_to_string(daemon.state_path("device-id"))
        .unwrap()
        .trim()
        .to_string();

    // Pre-state: personal, no org anywhere, summary file says so.
    assert_eq!(
        daemon.result("enroll.status", None),
        json!({"enrolled": false})
    );
    let status = daemon.result("status", None);
    assert_eq!(status["mode"], "personal");
    assert_eq!(status["enrolled"], false);
    assert!(status.get("org").is_none(), "org absent, never null");
    assert!(policy_d_files(&daemon).is_empty());
    let summary = daemon.status_summary();
    assert_eq!(summary["enrolled"], false);
    assert_eq!(summary["org_name"], Value::Null);

    // Record a personal preference (rank 5): firewall disabled. The mock
    // capability observes "disabled", so this is an idempotent no-op.
    let set = daemon.result(
        "capabilities.set",
        Some(json!({"capability": "security.firewall", "desired_state": "disabled"})),
    );
    assert_eq!(set["changed"], false);
    assert!(
        set.get("overridden").is_none(),
        "personal mode: no override"
    );

    // Enroll.
    let enrolled = daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(enrolled["enrolled"], true);
    assert_eq!(enrolled["org"]["id"], "acme");
    assert_eq!(enrolled["org"]["name"], "Acme");
    assert_eq!(enrolled["org"]["display_name"], "Acme Engineering");
    assert_eq!(enrolled["org"]["domain"], "acme.com");
    assert_eq!(enrolled["policy_ids"], json!(["eng-baseline-v12"]));
    // The honesty label travels with the data.
    assert_eq!(enrolled["attestation"], "simulated");
    assert_eq!(enrolled["first_sync"]["compliance"], "success");
    assert_eq!(enrolled["first_sync"]["inventory"], "success");

    // Files and modes: 0600 stores, the envelope carries its embedded
    // payload, and the token is not inside enrollment.json.
    assert_eq!(mode_of(&daemon.state_path("enrollment.json")), 0o600);
    assert_eq!(mode_of(&daemon.state_path("device-token")), 0o600);
    let token = fs::read_to_string(daemon.state_path("device-token"))
        .unwrap()
        .trim()
        .to_string();
    assert!(token.starts_with("tok_"));
    assert!(
        !fs::read_to_string(daemon.state_path("enrollment.json"))
            .unwrap()
            .contains(&token)
    );
    assert_eq!(policy_d_files(&daemon), ["eng-baseline-v12.json"]);
    let drop_path = daemon.state_path("policy.d").join("eng-baseline-v12.json");
    assert_eq!(mode_of(&drop_path), 0o600);
    let envelope: Value = serde_json::from_str(&fs::read_to_string(&drop_path).unwrap()).unwrap();
    assert_eq!(envelope["policy"]["kind"], "DeviceDesiredState");
    assert_eq!(envelope["source_name"], "Acme Engineering Baseline");

    // SPEC section 40 managed explain, now real: org rank 2 beats the
    // recorded personal preference; override not permitted.
    let explain = daemon.result("policy.explain", Some(json!({"path": "security.firewall"})));
    assert_eq!(explain["effective_value"], "enabled");
    assert_eq!(explain["source"]["kind"], "organization_baseline");
    assert_eq!(explain["source"]["rank"], 2);
    assert_eq!(explain["source"]["policy_id"], "eng-baseline-v12");
    assert_eq!(explain["source"]["name"], "Acme Engineering Baseline");
    assert_eq!(explain["user_override_permitted"], false);

    // status flips additively to managed.
    let status = daemon.result("status", None);
    assert_eq!(status["mode"], "managed");
    assert_eq!(status["enrolled"], true);
    assert_eq!(status["org"]["id"], "acme");
    let summary = daemon.status_summary();
    assert_eq!(summary["enrolled"], true);
    assert_eq!(summary["org_name"], "Acme Engineering");
    assert_eq!(summary["compliance_overall"], "compliant");

    // Received side (the check-the-receiver principle): one compliance
    // report and one inventory from the enrollment pass, both in the
    // privacy shape.
    {
        let compliance = control_plane.state.compliance.lock().unwrap();
        assert_eq!(compliance.len(), 1);
        assert_compliance_shape(&compliance[0], &device_id);
        assert_eq!(compliance[0]["report"]["overall"], "compliant");
    }
    {
        let inventory = control_plane.state.inventory.lock().unwrap();
        assert_eq!(inventory.len(), 1);
        assert_personal_inventory(&inventory[0]["inventory"]);
    }
    // A personal enrollment never lists the system installation.
    assert!(
        !dir.join("machine/flatpak-argv").exists(),
        "flatpak never ran"
    );
    // The person's record of what left: exactly what the control plane
    // received (this one keeps the inventory itself), and no secret.
    let view_path = daemon.state_path("organization-view.json");
    assert_eq!(mode_of(&view_path), 0o640);
    let view = read_json(&view_path);
    assert_eq!(
        view["sent"],
        control_plane.state.inventory.lock().unwrap()[0]["inventory"]
    );
    assert!(
        !view.to_string().contains(&token),
        "the view leaked the token"
    );

    // Recorded-but-overridden (the verified M4 semantics, now reachable):
    // a root set of `disabled` on the pinned path records the preference,
    // keeps the org value, exits successfully.
    let set = daemon.result(
        "capabilities.set",
        Some(json!({"capability": "security.firewall", "desired_state": "disabled"})),
    );
    assert_eq!(set["changed"], false);
    assert_eq!(set["overridden"], true);
    assert_eq!(set["effective_state"], "enabled");
    let noop_event = daemon
        .audit_events()
        .into_iter()
        .rev()
        .find(|e| e["action"] == "capabilities.set" && e["result"] == "noop")
        .expect("the overridden set audits as noop");
    assert_eq!(noop_event["policy_ids"], json!(["eng-baseline-v12"]));

    // Deliberately re-record `enabled` so the post-unenroll personal state
    // is firewall-enabled (the resurfacing witness, milestone-5.md § 5.4).
    daemon.result(
        "capabilities.set",
        Some(json!({"capability": "security.firewall", "desired_state": "enabled"})),
    );

    // A reconcile pass syncs compliance again; the inventory is hash-gated
    // and must NOT be resent.
    daemon.result("reconcile", None);
    assert_eq!(control_plane.state.compliance.lock().unwrap().len(), 2);
    assert_eq!(control_plane.state.inventory.lock().unwrap().len(), 1);

    // Offline (SPEC section 55): the control plane dies; local policy
    // stays enforceable from the cached org layer; sync queues.
    let state = control_plane.stop();
    let report = daemon.result("reconcile", None);
    assert_eq!(report["compliance"]["overall"], "compliant");
    let enroll_status = daemon.result("enroll.status", None);
    assert_eq!(enroll_status["last_sync"]["result"], "unreachable");
    assert_eq!(enroll_status["last_sync"]["pending"], true);
    assert_eq!(enroll_status["attestation"], "simulated");
    let unreachable_events = |daemon: &TestDaemon| {
        daemon
            .audit_events()
            .iter()
            .filter(|e| e["action"] == "enroll.sync" && e["result"] == "unreachable")
            .count()
    };
    assert_eq!(unreachable_events(&daemon), 1);
    // A second failing pass adds no second transition event (transitions
    // only, never per-retry spam).
    daemon.result("reconcile", None);
    assert_eq!(unreachable_events(&daemon), 1);
    assert_eq!(
        state.compliance.lock().unwrap().len(),
        2,
        "nothing received while down"
    );

    // Recovery: restart on the same socket with the same state; exactly
    // one new compliance line (latest-wins queue — a flag, not a spool).
    let control_plane = ControlPlane::start_with(&dir, state);
    daemon.result("reconcile", None);
    let enroll_status = daemon.result("enroll.status", None);
    assert_eq!(enroll_status["last_sync"]["result"], "success");
    assert_eq!(enroll_status["last_sync"]["pending"], false);
    assert_eq!(control_plane.state.compliance.lock().unwrap().len(), 3);
    assert_eq!(control_plane.state.inventory.lock().unwrap().len(), 1);
    let success_transitions = daemon
        .audit_events()
        .iter()
        .filter(|e| e["action"] == "enroll.sync" && e["result"] == "success")
        .count();
    assert_eq!(success_transitions, 1);

    // Unenroll — deliberately with the control plane DOWN: local restore
    // needs no counterparty.
    let state = control_plane.stop();
    let stopped = daemon.result("enroll.stop", None);
    assert_eq!(stopped["enrolled"], false);
    assert_eq!(stopped["removed_policy_ids"], json!(["eng-baseline-v12"]));
    assert!(policy_d_files(&daemon).is_empty());
    assert!(!daemon.state_path("enrollment.json").exists());
    assert!(!daemon.state_path("device-token").exists());
    assert!(
        !view_path.exists(),
        "the view describes an enrollment that has ended"
    );

    // Personal state restored — and the preference recorded while
    // overridden is the winner again (SPEC section 39).
    let explain = daemon.result("policy.explain", Some(json!({"path": "security.firewall"})));
    assert_eq!(explain["source"]["kind"], "local_user_preference");
    assert_eq!(explain["source"]["rank"], 5);
    assert_eq!(explain["source"]["name"], "Personal preference");
    assert_eq!(explain["user_override_permitted"], true);
    assert_eq!(explain["effective_value"], "enabled");
    let status = daemon.result("status", None);
    assert_eq!(status["mode"], "personal");
    assert_eq!(status["enrolled"], false);
    assert!(status.get("org").is_none());
    let summary = daemon.status_summary();
    assert_eq!(summary["enrolled"], false);
    assert_eq!(summary["org_name"], Value::Null);

    // The mock keeps its history (unenrollment is local; the past is not
    // retracted) — and no further reports arrive.
    assert_eq!(state.compliance.lock().unwrap().len(), 3);
    daemon.result("reconcile", None);
    assert_eq!(state.compliance.lock().unwrap().len(), 3);

    // Audit lifecycle: enroll.start success citing the org policy,
    // enroll.stop success, both sync transitions.
    let events = daemon.audit_events();
    let start_event = events
        .iter()
        .find(|e| e["action"] == "enroll.start" && e["result"] == "success")
        .expect("enroll.start audited");
    assert_eq!(start_event["resource"], "enrollment");
    assert_eq!(start_event["policy_ids"], json!(["eng-baseline-v12"]));
    let stop_event = events
        .iter()
        .find(|e| e["action"] == "enroll.stop" && e["result"] == "success")
        .expect("enroll.stop audited");
    assert_eq!(stop_event["policy_ids"], json!(["eng-baseline-v12"]));

    // SPEC sections 1.19/53: the device token appears in NOTHING — not the
    // audit trail, not the summary file, not the effective-document debug
    // copy, not any result surfaced above.
    assert!(!token.is_empty());
    assert!(!daemon.audit_text().contains(&token));
    for artifact in ["status.json", "effective.json", "preferences.json"] {
        let content = fs::read_to_string(daemon.state_path(artifact)).unwrap_or_default();
        assert!(!content.contains(&token), "{artifact} leaked the token");
    }
    for surfaced in [&enrolled, &status, &enroll_status, &stopped] {
        assert!(!surfaced.to_string().contains(&token));
    }
}

/// A ticket exactly as punar-authd mints one: an empty 0600 file named by the
/// token, in a 0700 directory named by the uid that proved its password.
fn mint_ticket(dir: &Path, uid: u32, token: &str) -> PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let per_uid = dir.join("tickets").join(uid.to_string());
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&per_uid)
        .unwrap();
    let path = per_uid.join(token);
    fs::File::create(&path).unwrap();
    path
}

const TICKET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn person() -> Peer {
    Peer {
        uid: 1000,
        gid: 1000,
        pid: None,
    }
}

/// No account on a Punar device holds sudo and root is locked, so a person
/// enrolls by confirming their password. A request without that confirmation
/// is refused before anything leaves the device, and unenrolling stays
/// root-only.
#[test]
fn a_person_without_a_password_confirmation_cannot_enroll() {
    let dir = test_dir("authz");
    let state = Arc::new(ControlPlaneState::default());
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, person(), &control_plane.socket, "enabled");

    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(error["code"], "denied");
    assert_eq!(error["details"]["reason"], "reauthentication_required");
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("needs your password"), "{message}");
    assert!(
        !message.contains("sudo"),
        "no account on a Punar device can use sudo, so the refusal must not suggest it"
    );
    assert!(
        state.methods.lock().unwrap().is_empty(),
        "nothing may leave the device for an unconfirmed caller"
    );
    let error = daemon.error("enroll.stop", None);
    assert_eq!(error["code"], "denied");
    // Both denials audited; the read stays open.
    let events = daemon.audit_events();
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "enroll.start" && e["decision"] == "deny")
    );
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "enroll.stop" && e["decision"] == "deny")
    );
    assert_eq!(
        daemon.result("enroll.status", None),
        json!({"enrolled": false})
    );
    // Nothing was written.
    assert!(!daemon.state_path("enrollment.json").exists());
    assert!(!daemon.state_path("device-token").exists());
}

#[test]
fn unreachable_control_plane_fails_enrollment_with_no_trace() {
    let dir = test_dir("unreachable");
    let daemon = TestDaemon::start(
        &dir,
        Peer::root(),
        &dir.join("no-such-control-plane.sock"),
        "enabled",
    );

    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(error["code"], "upstream_unreachable");
    assert_eq!(error["details"]["stage"], "discover");
    assert!(error["message"].as_str().unwrap().contains("Next step"));

    assert!(!daemon.state_path("enrollment.json").exists());
    assert!(!daemon.state_path("device-token").exists());
    assert!(policy_d_files(&daemon).is_empty());
    assert_eq!(
        daemon.result("enroll.status", None),
        json!({"enrolled": false})
    );
}

#[test]
fn conflicts_unknown_domains_and_bad_domains_are_typed_errors() {
    let dir = test_dir("conflict");
    let control_plane = ControlPlane::start(&dir);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");

    // Not enrolled yet: stop is a conflict.
    let error = daemon.error("enroll.stop", None);
    assert_eq!(error["code"], "conflict");
    assert_eq!(error["details"]["state"], "personal");

    // Malformed domain: rejected before any network hop.
    let error = daemon.error("enroll.start", Some(json!({"org_domain": "not a domain"})));
    assert_eq!(error["code"], "invalid_params");

    // Unknown (but well-formed) domain: the control plane's not_found.
    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "unknown.example"})),
    );
    assert_eq!(error["code"], "invalid_params");
    assert_eq!(error["details"]["param"], "org_domain");

    // Enroll, then a second enroll is a conflict.
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(error["code"], "conflict");
    assert_eq!(error["details"]["state"], "enrolled");
}

/// An organization can turn local policy editing off — and unenrolling must
/// give it back.
///
/// THE BUG THIS CLOSES was an outlived opinion. `enroll.stop` cleared the org
/// layers and the application policy but not the local-admin veto, so the
/// device's owner stayed locked out of their own machine by a policy whose
/// files had just been deleted, citing an organization it was no longer
/// enrolled with, until punard happened to restart.
#[test]
fn an_organization_can_deny_local_policy_editing_and_unenrolling_gives_it_back() {
    let dir = test_dir("localadmin");
    let control_plane = ControlPlane::start(&dir);
    control_plane
        .state
        .deny_local_admin
        .store(true, Ordering::SeqCst);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");

    // Before enrollment the owner administers the device.
    let effective = daemon.result("policy.effective", None);
    assert_eq!(effective["local_admin"]["allowed"], true);

    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));

    let effective = daemon.result("policy.effective", None);
    assert_eq!(effective["local_admin"]["allowed"], false);
    assert_eq!(
        effective["local_admin"]["source"]["policy_id"],
        "eng-baseline-v12"
    );
    // Even root is refused, and the refusal names who decided.
    let error = daemon.error(
        "policy.set",
        Some(json!({
            "capability": "security.firewall",
            "value": "disabled",
            "reason": "the lab bench machines run without it"
        })),
    );
    assert_eq!(error["code"], "denied");
    assert_eq!(error["details"]["reason"], "local_admin_disabled");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("eng-baseline-v12"),
        "{error}"
    );

    // Unenroll — and the veto goes with the layers it arrived with, in this
    // running daemon, without waiting for a restart.
    daemon.result("enroll.stop", None);
    let effective = daemon.result("policy.effective", None);
    assert_eq!(effective["local_admin"]["allowed"], true);
    assert!(effective["local_admin"].get("source").is_none());

    let set = daemon.result(
        "policy.set",
        Some(json!({
            "capability": "security.firewall",
            "value": "disabled",
            "reason": "the lab bench machines run without it"
        })),
    );
    assert_eq!(set["capability"], "security.firewall");
    assert_eq!(set["pinned_value"], "disabled");
    assert_eq!(set["effective_value"], "disabled");
    assert_eq!(set["source"]["kind"], "device_specific_override");
}

#[test]
fn invalid_policy_envelope_aborts_enrollment_atomically() {
    let dir = test_dir("badpolicy");
    let control_plane = ControlPlane::start(&dir);
    control_plane
        .state
        .serve_bad_policy
        .store(true, Ordering::SeqCst);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");

    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(error["code"], "invalid_params");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("failed validation")
    );
    // All-or-nothing: the rejected enrollment left nothing behind.
    assert!(policy_d_files(&daemon).is_empty());
    assert!(!daemon.state_path("enrollment.json").exists());
    assert!(!daemon.state_path("device-token").exists());
    assert_eq!(
        daemon.result("enroll.status", None),
        json!({"enrolled": false})
    );
    // The rejection is audited as a failed enroll.start.
    assert!(
        daemon
            .audit_events()
            .iter()
            .any(|e| e["action"] == "enroll.start" && e["result"] == "failure")
    );
    // And the identity the control plane issued at register was released,
    // so neither side is left holding a device the other has forgotten.
    let methods = control_plane.state.methods.lock().unwrap().clone();
    assert_eq!(
        methods,
        vec![
            "org.discover",
            "enroll.register",
            "policy.fetch",
            "enroll.unregister"
        ]
    );
    assert!(control_plane.state.devices.lock().unwrap().is_empty());

    // The same daemon can enroll once the control plane behaves.
    control_plane
        .state
        .serve_bad_policy
        .store(false, Ordering::SeqCst);
    let enrolled = daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(enrolled["enrolled"], true);
}

#[test]
fn enrollment_persists_across_restart_and_non_root_set_cites_the_org_policy() {
    let dir = test_dir("restart");
    let control_plane = ControlPlane::start(&dir);
    {
        let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "disabled");
        daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
        daemon.stop();
    }

    // A fresh daemon on the same state dir — the SPEC section 55 shape:
    // enrollment, policy.d, and the token are plain files; nothing about
    // them depends on the control plane being alive. This daemon sees
    // non-root peers.
    let daemon = TestDaemon::start(
        &dir,
        Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        },
        &control_plane.socket,
        "enabled",
    );
    let status = daemon.result("status", None);
    assert_eq!(status["mode"], "managed");
    assert_eq!(status["org"]["display_name"], "Acme Engineering");

    // Non-root set on the org-pinned path: denied (exit 3 client-side),
    // and the M5 amendment cites the pinning org policy — not the false
    // "personal defaults" citation.
    let error = daemon.error(
        "capabilities.set",
        Some(json!({"capability": "security.firewall", "desired_state": "disabled"})),
    );
    assert_eq!(error["code"], "denied");
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("Acme Engineering Baseline"), "{message}");
    assert!(message.contains("eng-baseline-v12"), "{message}");
    assert!(message.contains("not permitted"), "{message}");
    assert!(!message.contains("personal defaults"), "{message}");
    assert_eq!(error["details"]["policy_ids"], json!(["eng-baseline-v12"]));
    // The denial's audit event cites the pinning policy too.
    let denial = daemon
        .audit_events()
        .into_iter()
        .rev()
        .find(|e| e["action"] == "capabilities.set" && e["decision"] == "deny")
        .expect("denial audited");
    assert_eq!(denial["policy_ids"], json!(["eng-baseline-v12"]));

    // An unpinned capability id keeps the M3/M4 denial byte-identical in
    // spirit: "personal defaults" citation (no org policy governs it).
    let error = daemon.error(
        "capabilities.set",
        Some(json!({"capability": "mock.unpinned", "desired_state": "x"})),
    );
    // Unknown capability → not_found before authz? The registry lookup
    // runs first; assert only that no org policy is cited.
    assert!(
        !error["message"]
            .as_str()
            .unwrap()
            .contains("Acme Engineering"),
        "{error}"
    );
}

/// The enrollment code (a Smplify enrollment token) travels from the
/// `enroll.start` params to exactly one place — the control plane's
/// `enroll.register` — and is never written to the state directory, the
/// audit trail, or the result (SPEC section 49; ipc.md section 5.9).
#[test]
fn the_enrollment_code_reaches_the_control_plane_and_nowhere_else() {
    let dir = test_dir("code");
    let state = Arc::new(ControlPlaneState::default());
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "disabled");
    let code = "lex_test-code-never-on-disk-7f3a";
    let result = daemon.result(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "code": code})),
    );
    assert_eq!(result["org"]["display_name"], "Acme Engineering");
    assert_eq!(
        *state.codes.lock().unwrap(),
        vec![Some(code.to_string())],
        "the register call carries the code verbatim"
    );
    assert!(
        !result.to_string().contains(code),
        "enroll.start must never echo the code"
    );
    assert!(
        !daemon
            .result("enroll.status", None)
            .to_string()
            .contains(code),
        "enroll.status must never expose the code"
    );
    daemon.stop();
    // Nothing on disk — state, policy.d, audit — may contain the code.
    fn walk(dir: &Path, needle: &str, hits: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, needle, hits);
            } else if let Ok(bytes) = std::fs::read(&path) {
                if bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                    hits.push(path);
                }
            }
        }
    }
    let mut hits = Vec::new();
    walk(&dir, code, &mut hits);
    assert!(hits.is_empty(), "the code leaked to disk: {hits:?}");
}

/// The first account on a Punar device enrolls it the way a Mac administrator
/// does: the code, then their own password. The ticket punar-authd minted for
/// that password is spent by the call, and stored or forwarded nowhere. A
/// spent ticket on an enrolled device is refused as a spent ticket, never
/// recorded as an allowed attempt. The same person unenrolls with a fresh
/// confirmation.
#[test]
fn a_person_enrolls_and_unenrolls_by_confirming_their_password() {
    let dir = test_dir("person");
    let state = Arc::new(ControlPlaneState::default());
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, person(), &control_plane.socket, "disabled");
    let ticket = mint_ticket(&dir, 1000, TICKET);

    let result = daemon.result(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "code": "lex_person", "ticket": TICKET})),
    );
    assert_eq!(result["org"]["display_name"], "Acme Engineering");
    assert!(!ticket.exists(), "the ticket was spent, not merely checked");
    assert_eq!(daemon.result("enroll.status", None)["enrolled"], true);
    // An organization document that states no removal term leaves the
    // device removable, and says so; one that states no ownership leaves it
    // personal.
    assert_eq!(result["removable"], true);
    assert_eq!(daemon.result("enroll.status", None)["removable"], true);
    assert_eq!(result["organization_owned"], false);
    assert_eq!(
        daemon.result("enroll.status", None)["organization_owned"],
        false
    );
    let allowed = |daemon: &TestDaemon| {
        daemon
            .audit_events()
            .iter()
            .filter(|e| {
                e["action"] == "enroll.start" && e["user_id"] == "punar" && e["decision"] != "deny"
            })
            .count()
    };
    assert!(
        allowed(&daemon) >= 1,
        "the enrollment is attributed to the person who confirmed it"
    );

    // Replaying the spent ticket on the enrolled device: refused for the
    // ticket, before the conflict, and never audited as allowed.
    let before = allowed(&daemon);
    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "ticket": TICKET})),
    );
    assert_eq!(error["details"]["reason"], "reauthentication_missing");
    assert_eq!(allowed(&daemon), before);

    // Unenrolling takes a fresh confirmation, and spends it.
    let error = daemon.error("enroll.stop", None);
    assert_eq!(error["details"]["reason"], "reauthentication_required");
    const SECOND: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let second = mint_ticket(&dir, 1000, SECOND);
    let stopped = daemon.result("enroll.stop", Some(json!({"ticket": SECOND})));
    assert_eq!(stopped["enrolled"], false);
    assert!(!second.exists());
    assert!(
        !daemon.state_path("enrollment-terms.json").exists(),
        "unenrolling removes the removal term with the enrollment"
    );
    assert_eq!(daemon.result("enroll.status", None)["enrolled"], false);
    daemon.stop();

    // Neither ticket reached anything but punard: not the control plane,
    // not the audit trail, not the state directory.
    for token in [TICKET, SECOND] {
        assert!(
            state
                .lines
                .lock()
                .unwrap()
                .iter()
                .all(|l| !l.contains(token)),
            "a ticket reached the control plane"
        );
        let mut hits = Vec::new();
        for place in [dir.clone(), dir.join("state")] {
            for entry in fs::read_dir(&place).unwrap().flatten() {
                let path = entry.path();
                if path.is_file()
                    && fs::read(&path)
                        .map(|b| b.windows(token.len()).any(|w| w == token.as_bytes()))
                        .unwrap_or(false)
                {
                    hits.push(path);
                }
            }
        }
        assert!(hits.is_empty(), "a ticket leaked to disk: {hits:?}");
    }
}

/// Every refusal a person meets on the way through enrollment must point
/// somewhere they can go: no account on a Punar device is root.
fn assert_no_root_advice(message: &str) {
    assert!(!message.contains("sudo"), "{message}");
    assert!(!message.contains("as root"), "{message}");
}

/// An organization can keep its device — but only by saying so in its
/// organization document, and only with the enrolling person's explicit yes,
/// asked for before the organization ever hears of the device. Once given,
/// the term binds every local caller, root included, survives a restart, and
/// never costs a password to be told.
#[test]
fn a_non_removable_enrollment_needs_the_persons_yes_and_then_binds_everyone() {
    let dir = test_dir("nonremovable");
    let state = Arc::new(ControlPlaneState::default());
    *state.org_removable.lock().unwrap() = Some(json!(false));
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, person(), &control_plane.socket, "disabled");

    // Not accepted: refused after discovery and before register, so the
    // organization never learns of a device that did not enroll.
    let ticket = mint_ticket(&dir, 1000, TICKET);
    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "code": "lex_terms", "ticket": TICKET})),
    );
    assert_eq!(error["code"], "denied", "{error}");
    assert_eq!(error["details"]["reason"], "non_removable_not_accepted");
    assert_eq!(error["details"]["organization_name"], "Acme Engineering");
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("--accept-non-removable"), "{message}");
    assert_no_root_advice(message);
    assert!(!ticket.exists(), "the confirmation paid for discovery");
    assert_eq!(*state.methods.lock().unwrap(), vec!["org.discover"]);
    assert!(
        state
            .lines
            .lock()
            .unwrap()
            .iter()
            .all(|l| !l.contains("lex_terms")),
        "the code never left the device"
    );
    assert_eq!(daemon.result("enroll.status", None)["enrolled"], false);
    assert!(!daemon.state_path("enrollment.json").exists());

    // Accepted.
    mint_ticket(&dir, 1000, TICKET);
    let enrolled = daemon.result(
        "enroll.start",
        Some(json!({
            "org_domain": "acme.com",
            "ticket": TICKET,
            "accept_non_removable": true
        })),
    );
    assert_eq!(enrolled["removable"], false);
    assert_eq!(daemon.result("enroll.status", None)["removable"], false);

    // Now nobody on the device can unenroll it, and a person is told so
    // before a password could matter: with or without one, their ticket
    // stays unspent.
    const SECOND: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let second = mint_ticket(&dir, 1000, SECOND);
    for params in [None, Some(json!({"ticket": SECOND}))] {
        let error = daemon.error("enroll.stop", params);
        assert_eq!(error["code"], "denied");
        assert_eq!(error["details"]["reason"], "enrollment_not_removable");
        assert_eq!(error["details"]["organization"], "acme");
        let message = error["message"].as_str().unwrap();
        assert!(message.contains("erasing and reinstalling"), "{message}");
        assert_no_root_advice(message);
    }
    assert!(
        second.exists(),
        "a refused unenroll must not cost the password"
    );
    // Asking to enroll again says who can end this one.
    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "ticket": SECOND})),
    );
    assert_eq!(error["code"], "conflict");
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("not removable"), "{message}");
    assert_no_root_advice(message);
    assert_eq!(daemon.result("enroll.status", None)["enrolled"], true);
    daemon.stop();

    // An older punard, booted from a retained UKI, writes enrollment.json back
    // without the field it does not know. The term is kept apart from it too.
    let enrollment_path = dir.join("state/enrollment.json");
    let mut raw: Value = serde_json::from_slice(&fs::read(&enrollment_path).unwrap()).unwrap();
    raw.as_object_mut().unwrap().remove("removable");
    fs::write(&enrollment_path, raw.to_string()).unwrap();
    assert!(dir.join("state/enrollment-terms.json").is_file());

    // Root is refused too, and the term survived both the restart and the
    // rewrite.
    let root = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "disabled");
    assert_eq!(root.result("enroll.status", None)["removable"], false);
    let error = root.error("enroll.stop", None);
    assert_eq!(error["details"]["reason"], "enrollment_not_removable");
    assert_eq!(root.result("enroll.status", None)["enrolled"], true);
    assert!(root.state_path("enrollment.json").exists());
    assert!(root.state_path("device-token").exists());
    let denials = root
        .audit_events()
        .into_iter()
        .filter(|e| e["action"] == "enroll.stop" && e["decision"] == "deny")
        .count();
    assert_eq!(denials, 3, "every refused unenroll is audited");
    root.stop();
}

/// The calls the built-in agent may spend longest on are waited for past
/// the generic per-call timeout. A registration: the agent may spend its
/// whole register budget reaching Smplify, and once Smplify has recorded the
/// device it refuses a second active record for the same machine, so an
/// answer punard gave up on would leave the person unable to enroll until an
/// administrator removed the stale record. And a compliance report, which
/// carries the check-in that pins the organization's key until it is pinned.
#[test]
fn a_registration_and_a_report_slower_than_one_call_still_succeed() {
    let dir = test_dir("slow-calls");
    let control_plane = ControlPlane::start(&dir);
    let late = punard::enroll::CONTROL_PLANE_CALL_TIMEOUT + Duration::from_millis(500);
    control_plane
        .state
        .answer_late
        .lock()
        .unwrap()
        .extend([("enroll.register", late), ("compliance.report", late)]);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    let result = daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(result["enrolled"], true, "{result}");
    assert_eq!(result["first_sync"]["compliance"], "success", "{result}");
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["last_sync"]["pending"], false, "{status}");
}

/// An organization that tried to state a removal term this device cannot
/// read gets a refusal, never the permissive reading of its document.
#[test]
fn an_unreadable_removal_term_refuses_enrollment_before_register() {
    let dir = test_dir("removable-bad");
    let state = Arc::new(ControlPlaneState::default());
    *state.org_removable.lock().unwrap() = Some(json!("no"));
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "disabled");
    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(error["code"], "invalid_params", "{error}");
    assert_eq!(error["details"]["reason"], "enrollment.removable");
    assert_eq!(*state.methods.lock().unwrap(), vec!["org.discover"]);
    assert_eq!(daemon.result("enroll.status", None)["enrolled"], false);
    assert!(!daemon.state_path("enrollment.json").exists());
    daemon.stop();
}

/// A confirmation is good once, for the account that made it. A cheap
/// refusal (a malformed domain) does not cost the person their password; a
/// ticket another account minted, or one already spent, enrolls nothing and
/// sends nothing.
#[test]
fn a_confirmation_is_good_once_and_only_for_the_account_that_made_it() {
    let dir = test_dir("ticket");
    let state = Arc::new(ControlPlaneState::default());
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, person(), &control_plane.socket, "disabled");

    // Someone else's confirmation is not yours.
    let foreign = mint_ticket(&dir, 1001, TICKET);
    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "ticket": TICKET})),
    );
    assert_eq!(error["code"], "denied");
    assert_eq!(error["details"]["reason"], "reauthentication_missing");
    assert!(foreign.exists(), "another account's ticket is left alone");

    // A malformed token never reaches the filesystem.
    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "ticket": "../1001/whatever"})),
    );
    assert_eq!(error["details"]["reason"], "reauthentication_malformed");
    assert!(
        state.methods.lock().unwrap().is_empty(),
        "nothing may leave the device for an unconfirmed caller"
    );

    // A typo in the domain is refused before the ticket is spent.
    let mine = mint_ticket(&dir, 1000, TICKET);
    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "not a domain", "ticket": TICKET})),
    );
    assert_eq!(error["code"], "invalid_params");
    assert!(mine.exists(), "a cheap refusal must not cost the password");

    // An organization that is not there spends it: the network was used.
    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "nobody.example", "ticket": TICKET})),
    );
    assert_ne!(error["code"], "denied", "{error}");
    assert!(!mine.exists());
    assert_eq!(*state.methods.lock().unwrap(), vec!["org.discover"]);

    // And a spent ticket authorizes nothing.
    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "ticket": TICKET})),
    );
    assert_eq!(error["details"]["reason"], "reauthentication_missing");
    assert_eq!(*state.methods.lock().unwrap(), vec!["org.discover"]);
    assert_eq!(daemon.result("enroll.status", None)["enrolled"], false);
    daemon.stop();
}

/// An AI agent may never choose an organization for the device: not with a
/// valid confirmation, and not as root (SPEC section 60 — root-ness inside an
/// agent scope buys no bypass). The person's ticket is left unspent, and each
/// pass runs in its own directory so its evidence is its own.
#[test]
fn an_agent_cannot_enroll_even_with_a_valid_confirmation() {
    const AGENT_PID: i32 = 4242;
    for uid in [1000, 0] {
        let dir = test_dir(&format!("agent-{uid}"));
        let cgroup = dir.join("proc").join(AGENT_PID.to_string());
        fs::create_dir_all(&cgroup).unwrap();
        fs::write(
            cgroup.join("cgroup"),
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/\
punar-agent-agt_4f21c09ab3e1.scope\n",
        )
        .unwrap();
        let state = Arc::new(ControlPlaneState::default());
        let control_plane = ControlPlane::start_with(&dir, state.clone());
        let daemon = TestDaemon::start(
            &dir,
            Peer {
                uid,
                gid: uid,
                pid: Some(AGENT_PID),
            },
            &control_plane.socket,
            "disabled",
        );
        let ticket = mint_ticket(&dir, uid, TICKET);
        for (method, params) in [
            (
                "enroll.start",
                json!({"org_domain": "acme.com", "code": "lex_agent", "ticket": TICKET}),
            ),
            ("enroll.stop", json!({"ticket": TICKET})),
        ] {
            let error = daemon.error(method, Some(params));
            assert_eq!(error["code"], "denied", "uid {uid} {method}: {error}");
            assert_eq!(error["details"]["reason"], "agent_scope");
            assert!(
                daemon
                    .audit_events()
                    .iter()
                    .any(|e| e["action"] == method && e["decision"] == "deny"),
                "uid {uid} {method}: the refusal is audited"
            );
        }
        assert!(
            ticket.exists(),
            "an agent's attempt must not burn the ticket"
        );
        assert!(state.methods.lock().unwrap().is_empty());
        assert_eq!(daemon.result("enroll.status", None)["enrolled"], false);
        daemon.stop();
    }
}

/// A real Smplify tenant can enroll a device before assigning it any policy:
/// the built-in agent answers `policy.fetch` with an empty list. Enrollment
/// must still complete — managed, no organization layers, compliance and
/// inventory reported — and unenroll cleanly.
#[test]
fn enrolling_before_the_organization_assigns_any_policy_succeeds() {
    let dir = test_dir("no-policy");
    let state = Arc::new(ControlPlaneState::default());
    state.serve_no_policy.store(true, Ordering::SeqCst);
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "disabled");
    let result = daemon.result(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "code": "lex_empty-tenant"})),
    );
    assert_eq!(result["org"]["display_name"], "Acme Engineering");
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["enrolled"], true);
    assert_eq!(daemon.result("status", None)["mode"], "managed");
    assert!(
        !state.compliance.lock().unwrap().is_empty(),
        "the first compliance report is sent even with no organization policy"
    );
    daemon.result("enroll.stop", None);
    assert_eq!(daemon.result("enroll.status", None)["enrolled"], false);
    daemon.stop();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// The hash gate skips an unchanged inventory, but a 2xx proves only that the
/// request arrived: once a day an unchanged inventory is sent again. The
/// recorded send time moves only when a send succeeds.
#[test]
fn an_unchanged_inventory_is_resent_after_a_day_and_only_a_success_moves_the_clock() {
    const LONG_AGO: &str = "2026-01-01T00:00:00Z";
    let dir = test_dir("resend-floor");
    let state_file = dir.join("state/enrollment.json");
    let control_plane = ControlPlane::start(&dir);
    {
        let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
        daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
        daemon.result("reconcile", None);
        daemon.stop();
    }
    assert_eq!(
        control_plane.state.inventory.lock().unwrap().len(),
        1,
        "hash-gated within the day"
    );
    let record = read_json(&state_file);
    let hash = record["last_inventory_hash"].clone();
    assert!(
        record["last_inventory_sent_at"]
            .as_str()
            .is_some_and(|at| at.ends_with('Z')),
        "{record}"
    );

    // A day and more has passed, as far as the record says, and the control
    // plane is down: the due send fails and the record keeps the old time.
    let mut record = read_json(&state_file);
    record["last_inventory_sent_at"] = json!(LONG_AGO);
    fs::write(&state_file, record.to_string()).unwrap();
    let state = control_plane.stop();
    {
        let daemon = TestDaemon::start(
            &dir,
            Peer::root(),
            &dir.join("control-plane.sock"),
            "enabled",
        );
        daemon.stop();
    }
    assert_eq!(read_json(&state_file)["last_inventory_sent_at"], LONG_AGO);
    assert_eq!(state.inventory.lock().unwrap().len(), 1);

    // Back online: the unchanged inventory goes out again and the time moves.
    let control_plane = ControlPlane::start_with(&dir, state);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    {
        let inventory = control_plane.state.inventory.lock().unwrap();
        assert_eq!(inventory.len(), 2);
        assert_eq!(
            inventory[0]["inventory"], inventory[1]["inventory"],
            "the floor resent it, not a change"
        );
    }
    let record = read_json(&state_file);
    assert_eq!(record["last_inventory_hash"], hash);
    assert_ne!(record["last_inventory_sent_at"], LONG_AGO);
    // Within the day the gate holds again.
    daemon.result("reconcile", None);
    assert_eq!(control_plane.state.inventory.lock().unwrap().len(), 2);
}

/// The organization chooses its display name, and punard shows it beside the
/// terms a person accepts, in every view of the enrollment, in the shell's
/// bar. It is cleaned once, where punard reads the document, so the refusal,
/// the enrollment record, `enroll.status` and the status file all carry the
/// same safe, bounded text: no control or invisible character, no line
/// separator, one space for any run of whitespace, at most 64 characters.
#[test]
fn the_organizations_name_is_cleaned_once_where_punard_reads_it() {
    let dir = test_dir("org-name");
    let state = Arc::new(ControlPlaneState::default());
    let control_plane = ControlPlane::start_with(&dir, Arc::clone(&state));
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    *state.org_display_name.lock().unwrap() = Some(json!(format!(
        "Acme\u{1b}[8m\u{202e} (personal\u{2028}enrollment:\u{200b} nothing{}is sent) {}",
        " ".repeat(5000),
        "x".repeat(300)
    )));
    *state.org_name.lock().unwrap() = Some(json!("\u{1b}]0;Acme\u{7}\u{2066}"));
    *state.org_shown_domain.lock().unwrap() = Some(json!("acme.com\u{1b}[2K"));
    *state.org_ownership.lock().unwrap() = Some(json!("organization"));
    let expected = format!(
        "Acme[8m (personal enrollment: nothing is sent) {}\u{2026}",
        "x".repeat(16)
    );
    assert_eq!(expected.chars().count(), 64);

    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(error["details"]["organization_name"], expected.as_str());
    let message = error["message"].as_str().unwrap();
    for steer in ['\u{1b}', '\u{202e}', '\u{2028}', '\u{200b}', '\u{7}'] {
        assert!(!message.contains(steer), "{steer:?} in {message:?}");
    }
    assert!(message.contains(&format!("\"{expected}\"")), "{message}");
    assert!(message.len() < 1024, "{message}");

    daemon.result(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "accept_organization_owned": true})),
    );
    let org = daemon.result("enroll.status", None)["org"].clone();
    assert_eq!(org["display_name"], expected.as_str());
    assert_eq!(org["name"], "]0;Acme");
    assert_eq!(org["domain"], "acme.com", "the domain the person typed");
    assert_eq!(read_json(&daemon.state_path("enrollment.json"))["org"], org);
    assert_eq!(daemon.status_summary()["org_name"], expected.as_str());
}

fn wait_until(what: &str, done: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Run a sync pass whose `method` report is held in flight while `during`
/// runs, then let it finish.
fn pass_held_at(
    daemon: &TestDaemon,
    state: &ControlPlaneState,
    method: &'static str,
    during: &dyn Fn(),
) {
    state.release_held.store(false, Ordering::SeqCst);
    state.held.store(false, Ordering::SeqCst);
    *state.hold_next.lock().unwrap() = Some(method);
    std::thread::scope(|scope| {
        let pass = scope.spawn(|| daemon.result("reconcile", None));
        wait_until("the held report", || state.held.load(Ordering::SeqCst));
        during();
        state.release_held.store(true, Ordering::SeqCst);
        pass.join().unwrap();
    });
}

/// A sync pass works from the enrollment it began with, and can outlive it:
/// its inventory report may still be in flight while `enroll.stop` runs, and
/// `enroll.start` after that. The reply must write nothing back — not the
/// ended enrollment's view, which unenroll removed and promised stays
/// removed, and not into the enrollment that replaced it, whose view and
/// inventory hash are its own.
#[test]
fn a_pass_that_outlives_its_enrollment_writes_nothing_back() {
    const SECURE_BOOT: &str =
        "machine/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
    let dir = test_dir("stale-pass");
    let view_path = dir.join("state/organization-view.json");
    let enrollment_path = dir.join("state/enrollment.json");
    let control_plane = ControlPlane::start(&dir);
    let state = Arc::clone(&control_plane.state);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    // Something the inventory carries changes, so the next pass sends one,
    // and that report is held in flight while `during` runs.
    let pass_in_flight = |secure_boot: u8, during: &dyn Fn()| {
        write_file(&dir.join(SECURE_BOOT), [6u8, 0, 0, 0, secure_boot]);
        pass_held_at(&daemon, &state, "inventory.report", during);
    };

    // Unenrolled while the report is in flight: nothing is recreated.
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert!(view_path.exists());
    pass_in_flight(1, &|| {
        daemon.result("enroll.stop", None);
        assert!(!view_path.exists(), "unenroll removed the view");
    });
    assert_eq!(
        state.inventory.lock().unwrap().len(),
        2,
        "the reply arrived"
    );
    assert!(!view_path.exists(), "a late reply recreated the view");
    assert!(!enrollment_path.exists());

    // Unenrolled and enrolled again, now as organization-owned, possibly
    // within the same second: the late reply belongs to neither.
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    pass_in_flight(0, &|| {
        daemon.result("enroll.stop", None);
        *state.org_ownership.lock().unwrap() = Some(json!("organization"));
        daemon.result(
            "enroll.start",
            Some(json!({"org_domain": "acme.com", "accept_organization_owned": true})),
        );
    });
    let inventory = state.inventory.lock().unwrap().clone();
    assert_eq!(inventory.len(), 5);
    let (owned, late) = (&inventory[3]["inventory"], &inventory[4]["inventory"]);
    assert!(owned.get("identifiers").is_some(), "{owned}");
    assert!(late.get("identifiers").is_none(), "the ended enrollment's");
    let record = read_json(&view_path);
    assert_eq!(
        record["sent"], *owned,
        "the view is the new enrollment's own"
    );
    assert_eq!(
        record["enrolled_at"],
        read_json(&enrollment_path)["enrolled_at"]
    );
    // Nor did the late reply move the new enrollment's hash: an unchanged
    // device sends nothing on the next pass.
    daemon.result("reconcile", None);
    assert_eq!(state.inventory.lock().unwrap().len(), 5);
}

/// A pass that outlives its enrollment leaves the device's sync state alone
/// too: whether a report is pending, and the sync and withheld-list
/// transitions it audits. Its reports fail against a token that no longer
/// exists, and otherwise the enrollment that replaced it would read as
/// pending, the audit would record a failure and a withheld list that were
/// not its own, and its unchanged inventory would be sent again.
#[test]
fn a_pass_that_outlives_its_enrollment_leaves_the_sync_state_alone() {
    let dir = test_dir("stale-state");
    let control_plane = ControlPlane::start(&dir);
    let state = Arc::clone(&control_plane.state);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    // The first enrollment is organization-owned, and its application list
    // is withheld: the installation lists a row with no columns.
    fs::write(
        dir.join("machine/bin/flatpak"),
        "#!/bin/sh\nprintf 'not-a-flatpak-row\\n'\n",
    )
    .unwrap();
    *state.org_ownership.lock().unwrap() = Some(json!("organization"));
    daemon.result(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "accept_organization_owned": true})),
    );
    let events = |action: &str, result: &str| {
        daemon
            .audit_events()
            .iter()
            .filter(|e| e["action"] == action && e["result"] == result)
            .count()
    };
    assert_eq!(events("enroll.inventory", "applications_withheld"), 1);
    let first_token = state
        .devices
        .lock()
        .unwrap()
        .keys()
        .next()
        .cloned()
        .unwrap();

    // Something the inventory carries changes, so the next pass sends one.
    // That pass is caught with its compliance report in flight while the
    // device is unenrolled and enrolled again, personally.
    write_file(
        &dir.join(
            "machine/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
        ),
        [6u8, 0, 0, 0, 1],
    );
    pass_held_at(&daemon, &state, "compliance.report", &|| {
        daemon.result("enroll.stop", None);
        *state.org_ownership.lock().unwrap() = None;
        daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    });
    let last_inventory = state
        .lines
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|line| line.contains(r#""inventory.report""#))
        .cloned()
        .unwrap();
    assert!(
        last_inventory.contains(&first_token),
        "the stale pass went on to report its inventory, and was refused"
    );
    assert_eq!(events("enroll.inventory", "applications_withheld"), 1);
    assert_eq!(events("enroll.sync", "unreachable"), 0);
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["last_sync"]["result"], "success", "{status}");
    assert_eq!(status["last_sync"]["pending"], false, "{status}");

    // The new enrollment's own next pass finds nothing to resend.
    let sent = state.inventory.lock().unwrap().len();
    daemon.result("reconcile", None);
    assert_eq!(state.inventory.lock().unwrap().len(), sent);
    assert_eq!(events("enroll.inventory", "success"), 0);
}

/// An inventory that cannot get through — too large to upload within the
/// agent's budget on a slow link, say — is not sent again on every pass. It
/// stays pending and waits, twice as long after each failure; it goes at
/// once when it changes, and a send that gets through starts the waits
/// afresh.
#[test]
fn a_failing_inventory_waits_longer_each_time_unless_it_changes() {
    const SECURE_BOOT: &str =
        "machine/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
    const RETRY: Duration = Duration::from_millis(1000);
    let dir = test_dir("inventory-retry");
    let control_plane = ControlPlane::start(&dir);
    let state = Arc::clone(&control_plane.state);
    let daemon = TestDaemon::start_with(
        &dir,
        Peer::root(),
        &control_plane.socket,
        "enabled",
        Vec::new(),
        |cfg| cfg.inventory_retry_base = RETRY,
    );
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    let attempts = || {
        state
            .methods
            .lock()
            .unwrap()
            .iter()
            .filter(|method| *method == "inventory.report")
            .count()
    };
    let secure_boot = |on: u8| write_file(&dir.join(SECURE_BOOT), [6u8, 0, 0, 0, on]);
    let pass_at = |at: std::time::Instant| {
        std::thread::sleep(at.saturating_duration_since(std::time::Instant::now()));
        daemon.result("reconcile", None);
    };
    assert_eq!(attempts(), 1);

    // It changes and cannot get through; the next pass does not send it
    // again, and the device reads as pending.
    state.refuse_inventory.store(true, Ordering::SeqCst);
    secure_boot(1);
    let failed = std::time::Instant::now();
    daemon.result("reconcile", None);
    assert_eq!(attempts(), 2);
    daemon.result("reconcile", None);
    assert_eq!(attempts(), 2, "sent again at once");
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["last_sync"]["pending"], true, "{status}");
    assert_eq!(status["last_sync"]["result"], "unreachable", "{status}");
    assert_eq!(
        state.compliance.lock().unwrap().len(),
        3,
        "compliance still goes every pass"
    );

    // After its wait it goes once more, and fails; the next wait is longer.
    let failed_again = std::time::Instant::now().max(failed + RETRY);
    pass_at(failed_again + Duration::from_millis(50));
    assert_eq!(attempts(), 3);
    pass_at(failed_again + RETRY + Duration::from_millis(300));
    assert_eq!(attempts(), 3, "the second wait is no longer than the first");

    // A changed inventory goes at once.
    secure_boot(0);
    daemon.result("reconcile", None);
    assert_eq!(attempts(), 4);

    // One that gets through starts the waits afresh: the same failed body
    // fails again, and waits only the first wait.
    state.refuse_inventory.store(false, Ordering::SeqCst);
    secure_boot(1);
    daemon.result("reconcile", None);
    assert_eq!(attempts(), 5);
    assert_eq!(state.inventory.lock().unwrap().len(), 2);
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["last_sync"]["pending"], false, "{status}");
    state.refuse_inventory.store(true, Ordering::SeqCst);
    secure_boot(0);
    let failed = std::time::Instant::now();
    daemon.result("reconcile", None);
    assert_eq!(attempts(), 6);
    pass_at(failed + RETRY + Duration::from_millis(50));
    assert_eq!(
        attempts(),
        7,
        "a send that got through did not reset the wait"
    );
}

/// The resend gate hashes what can leave the device and nothing else. The
/// hostname and a capability's value — the timezone a network hands out when
/// its owner travels — are never sent, so changing them sends no inventory:
/// one sent off its daily schedule would tell the organization when they
/// changed. The compliance report of the same pass still goes out.
#[test]
fn a_changed_hostname_or_timezone_sends_no_inventory() {
    let dir = test_dir("never-sent-values");
    let control_plane = ControlPlane::start(&dir);
    let daemon = TestDaemon::start_with(
        &dir,
        Peer::root(),
        &control_plane.socket,
        "enabled",
        vec![
            MockCapability::new("system.hostname", json!("atlas")),
            MockCapability::new("time.timezone", json!("America/New_York")),
        ],
        |_| {},
    );
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    let first = control_plane.state.inventory.lock().unwrap()[0]["inventory"].clone();
    assert_eq!(first.get("hostname"), None);
    assert_eq!(
        first["capabilities"],
        json!([
            {"capability": "security.firewall", "supported": true},
            {"capability": "system.hostname", "supported": true},
            {"capability": "time.timezone", "supported": true},
        ])
    );
    let text = first.to_string();
    for value in ["atlas", "America/New_York"] {
        assert!(!text.contains(value), "the inventory carries {value}");
    }

    // The person travels and renames the laptop.
    let compliance = control_plane.state.compliance.lock().unwrap().len();
    for (capability, value) in [
        ("time.timezone", "Europe/Berlin"),
        ("system.hostname", "atlas-berlin"),
    ] {
        daemon.result(
            "capabilities.set",
            Some(json!({"capability": capability, "desired_state": value})),
        );
    }
    daemon.result("reconcile", None);
    assert!(
        control_plane.state.compliance.lock().unwrap().len() > compliance,
        "the pass ran and reported compliance"
    );
    assert_eq!(
        control_plane.state.inventory.lock().unwrap().len(),
        1,
        "nothing that can leave the device changed"
    );
    let lines = control_plane.state.lines.lock().unwrap().join("");
    for value in ["atlas", "Berlin", "America/New_York"] {
        assert!(!lines.contains(value), "{value} reached the control plane");
    }
}

/// A local, signed stable channel whose head (2026.08.27.1) is newer than
/// the running release (2026.08.20.1), so a person's `update check` finds an
/// update and caches the verified document.
fn configure_update_channel(cfg: &mut DaemonConfig, dir: &Path) {
    let repository = dir.join("update-source");
    let keys = dir.join("release-keys");
    let os_release = dir.join("update-os-release");
    fs::create_dir_all(&repository).unwrap();
    fs::create_dir_all(&keys).unwrap();
    fs::write(
        &os_release,
        "IMAGE_ID=punar-desktop\nIMAGE_VERSION=2026.08.20.1\n",
    )
    .unwrap();
    let signing = SigningKey::from_bytes(&[17; 32]);
    fs::write(keys.join("fixture.pub"), signing.verifying_key().to_bytes()).unwrap();
    let document = serde_json::to_vec_pretty(&json!({
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
    fs::write(
        repository.join("channel.json.sig"),
        signing.sign(&document).to_bytes(),
    )
    .unwrap();
    fs::write(repository.join("channel.json"), document).unwrap();
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

/// Looking for updates is something a person does, not something the device
/// is. A verified check that finds a newer release changes what they know
/// and leaves the device's patch state as it was, so it changes nothing the
/// organization receives: no verdict appears, and no inventory is sent off
/// its schedule to announce one. Otherwise the organization would learn the
/// moment the person looked.
#[test]
fn a_persons_update_check_tells_the_organization_nothing() {
    let dir = test_dir("update-check-quiet");
    let control_plane = ControlPlane::start(&dir);
    let daemon = TestDaemon::start_with(
        &dir,
        Peer::root(),
        &control_plane.socket,
        "enabled",
        Vec::new(),
        |cfg| configure_update_channel(cfg, &dir),
    );
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(control_plane.state.inventory.lock().unwrap().len(), 1);

    let check = daemon.result("update.check", Some(json!({"force": true})));
    assert_eq!(check["available"], "2026.08.27.1", "{check}");
    assert!(daemon.state_path("update/verified-channel.json").is_file());
    daemon.result("reconcile", None);
    daemon.result("reconcile", None);

    let inventory = control_plane.state.inventory.lock().unwrap();
    assert_eq!(inventory.len(), 1, "the check sent nothing: {inventory:?}");
    assert_eq!(
        inventory[0]["inventory"]["posture"]["os_patch_status"],
        "unknown"
    );
}

/// The organization-owned tier through the whole daemon: the same device
/// enrolled personally, then by an organization that claims it and a person
/// who accepted that. Ownership adds the serial number and the system-wide
/// applications, and nothing else.
#[test]
fn an_organization_owned_enrollment_adds_the_serial_and_system_apps() {
    let dir = test_dir("org-owned");
    let control_plane = ControlPlane::start(&dir);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(
        read_json(&daemon.state_path("enrollment.json"))["organization_owned"],
        false
    );
    assert!(
        !dir.join("machine/flatpak-argv").exists(),
        "a personal enrollment never lists the installation"
    );
    daemon.result("enroll.stop", None);

    *control_plane.state.org_ownership.lock().unwrap() = Some(json!("organization"));
    let enrolled = daemon.result(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "accept_organization_owned": true})),
    );
    assert_eq!(enrolled["organization_owned"], true);
    assert_eq!(enrolled["removable"], true, "the terms are independent");
    assert_eq!(
        daemon.result("enroll.status", None)["organization_owned"],
        true
    );
    assert_eq!(
        read_json(&daemon.state_path("enrollment.json"))["organization_owned"],
        true
    );
    let inventory = control_plane.state.inventory.lock().unwrap();
    assert_eq!(inventory.len(), 2);
    let personal = &inventory[0]["inventory"];
    let owned = &inventory[1]["inventory"];
    assert_personal_inventory(personal);
    assert_eq!(
        sorted_keys(owned),
        [
            "applications",
            "capabilities",
            "hardware",
            "identifiers",
            "kernel",
            "os",
            "posture"
        ]
    );
    assert_eq!(
        owned["identifiers"],
        json!({ "serial_number": FIXTURE_SERIAL })
    );
    for section in ["os", "posture", "hardware", "capabilities"] {
        assert_eq!(owned[section], personal[section], "{section}");
    }
    let rows: Vec<(&str, &str)> = owned["applications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|app| {
            (
                app["name"].as_str().unwrap(),
                app["source"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("chromium", "punar-image"),
            ("org.mozilla.firefox", "flatpak"),
            ("org.punar.Mail", "punar-image"),
        ]
    );
    assert_eq!(
        fs::read_to_string(dir.join("machine/flatpak-argv")).unwrap(),
        "list --system --app --columns=application,name,version,active\n",
        "the system installation only, fixed argv"
    );
}

/// An organization can claim the device as its own, but only its user can
/// make that claim count: without the person's yes the enrollment is refused
/// after discovery and before register, so the organization never hears of
/// the device and nothing about it is sent. The refusal says what the
/// organization would receive, and which flag accepts it.
#[test]
fn an_organization_owned_enrollment_needs_the_persons_yes_before_register() {
    let dir = test_dir("owned-consent");
    let state = Arc::new(ControlPlaneState::default());
    *state.org_ownership.lock().unwrap() = Some(json!("organization"));
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, person(), &control_plane.socket, "disabled");

    let ticket = mint_ticket(&dir, 1000, TICKET);
    let error = daemon.error(
        "enroll.start",
        Some(json!({
            "org_domain": "acme.com",
            "code": "lex_owned",
            "ticket": TICKET,
            // Accepting a term the organization did not set accepts nothing.
            "accept_non_removable": true
        })),
    );
    assert_eq!(error["code"], "denied", "{error}");
    assert_eq!(
        error["details"]["reason"],
        "organization_owned_not_accepted"
    );
    assert_eq!(error["details"]["terms"], json!(["organization_owned"]));
    assert_eq!(error["details"]["organization_name"], "Acme Engineering");
    let message = error["message"].as_str().unwrap();
    assert!(
        message.contains("--accept-organization-owned`"),
        "{message}"
    );
    assert!(!message.contains("--accept-non-removable"), "{message}");
    assert!(message.contains("serial number"), "{message}");
    assert!(
        message.contains("every app installed for all users"),
        "{message}"
    );
    assert_no_root_advice(message);
    assert!(!ticket.exists(), "the confirmation paid for discovery");
    assert_eq!(*state.methods.lock().unwrap(), vec!["org.discover"]);
    assert!(
        state
            .lines
            .lock()
            .unwrap()
            .iter()
            .all(|l| !l.contains("lex_owned")),
        "the code never left the device"
    );
    assert!(state.inventory.lock().unwrap().is_empty());
    assert_eq!(daemon.result("enroll.status", None)["enrolled"], false);
    assert!(!daemon.state_path("enrollment.json").exists());
    assert!(!dir.join("machine/flatpak-argv").exists());
    assert_eq!(
        daemon
            .audit_events()
            .iter()
            .filter(|e| e["action"] == "enroll.start" && e["decision"] == "deny")
            .count(),
        1,
        "the refusal is audited"
    );

    mint_ticket(&dir, 1000, TICKET);
    let enrolled = daemon.result(
        "enroll.start",
        Some(json!({
            "org_domain": "acme.com",
            "ticket": TICKET,
            "accept_organization_owned": true
        })),
    );
    assert_eq!(enrolled["organization_owned"], true);
    assert_eq!(enrolled["removable"], true);
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["organization_owned"], true);
    // Owned, but still the person's to unenroll: the terms are separate.
    assert_eq!(status["removable"], true);
    let inventory = state.inventory.lock().unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(
        inventory[0]["inventory"]["identifiers"]["serial_number"],
        FIXTURE_SERIAL
    );
}

/// `personal`, or no ownership at all, asks nothing more and sends the
/// personal tier: no identifiers, only the image's own applications.
#[test]
fn a_personal_ownership_term_asks_nothing_and_sends_no_identifiers() {
    let dir = test_dir("owned-personal");
    let state = Arc::new(ControlPlaneState::default());
    *state.org_ownership.lock().unwrap() = Some(json!("personal"));
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    let enrolled = daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(enrolled["organization_owned"], false);
    assert_eq!(
        daemon.result("enroll.status", None)["organization_owned"],
        false
    );
    let inventory = state.inventory.lock().unwrap();
    assert_eq!(inventory.len(), 1);
    assert_personal_inventory(&inventory[0]["inventory"]);
    assert!(!dir.join("machine/flatpak-argv").exists());
}

/// An organization that tried to state an ownership this device cannot read
/// gets a refusal before register, never either reading of its document.
#[test]
fn an_unreadable_ownership_term_refuses_enrollment_before_register() {
    let dir = test_dir("owned-bad");
    let state = Arc::new(ControlPlaneState::default());
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "disabled");
    for ownership in [
        json!("Organization"),
        json!("corporate"),
        json!(""),
        json!(true),
        json!(null),
        json!({"type": "organization"}),
    ] {
        state.methods.lock().unwrap().clear();
        *state.org_ownership.lock().unwrap() = Some(ownership.clone());
        let error = daemon.error(
            "enroll.start",
            Some(json!({"org_domain": "acme.com", "accept_organization_owned": true})),
        );
        assert_eq!(error["code"], "invalid_params", "{ownership}: {error}");
        assert_eq!(error["details"]["reason"], "enrollment.ownership");
        assert_no_root_advice(error["message"].as_str().unwrap());
        assert_eq!(*state.methods.lock().unwrap(), vec!["org.discover"]);
    }
    assert_eq!(daemon.result("enroll.status", None)["enrolled"], false);
    assert!(!daemon.state_path("enrollment.json").exists());
    assert!(state.inventory.lock().unwrap().is_empty());
}

/// An organization that sets both terms is refused once, naming both, with
/// both meanings and both flags, so a person is asked once rather than once
/// per term. Each flag accepts only its own term: a request that accepts one
/// is refused for the other, the non-removable refusal exactly as it reads
/// when it is the only term. Nothing reaches the control plane until both
/// are accepted.
#[test]
fn both_enrollment_terms_are_named_in_one_refusal_and_accepted_together() {
    let dir = test_dir("two-terms");
    let state = Arc::new(ControlPlaneState::default());
    *state.org_removable.lock().unwrap() = Some(json!(false));
    *state.org_ownership.lock().unwrap() = Some(json!("organization"));
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");

    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(error["code"], "denied", "{error}");
    assert_eq!(error["details"]["reason"], "enrollment_terms_not_accepted");
    assert_eq!(
        error["details"]["terms"],
        json!(["non_removable", "organization_owned"])
    );
    assert_eq!(error["details"]["organization"], "acme");
    let message = error["message"].as_str().unwrap();
    assert!(
        message.contains(
            "`punarctl enroll start acme.com --accept-non-removable --accept-organization-owned`"
        ),
        "{message}"
    );
    assert!(
        message.contains("nobody on it, you included, can unenroll it"),
        "{message}"
    );
    assert!(message.contains("serial number"), "{message}");
    assert!(
        message.contains("every app installed for all users"),
        "{message}"
    );
    assert_no_root_advice(message);

    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "accept_non_removable": true})),
    );
    assert_eq!(
        error["details"]["reason"],
        "organization_owned_not_accepted"
    );
    assert_eq!(error["details"]["terms"], json!(["organization_owned"]));

    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "accept_organization_owned": true})),
    );
    assert_eq!(error["details"]["reason"], "non_removable_not_accepted");
    assert_eq!(error["details"]["terms"], json!(["non_removable"]));
    assert!(
        error["message"].as_str().unwrap().starts_with(
            "\"Acme Engineering\" enrolls devices so that nobody on them can unenroll them"
        ),
        "{error}"
    );
    assert_eq!(
        *state.methods.lock().unwrap(),
        vec!["org.discover", "org.discover", "org.discover"],
        "nothing but discovery until every term is accepted"
    );
    assert!(!daemon.state_path("enrollment.json").exists());

    let enrolled = daemon.result(
        "enroll.start",
        Some(json!({
            "org_domain": "acme.com",
            "accept_non_removable": true,
            "accept_organization_owned": true
        })),
    );
    assert_eq!(enrolled["removable"], false);
    assert_eq!(enrolled["organization_owned"], true);
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["removable"], false);
    assert_eq!(status["organization_owned"], true);
    let inventory = state.inventory.lock().unwrap();
    assert_eq!(
        inventory[0]["inventory"]["identifiers"]["serial_number"],
        FIXTURE_SERIAL
    );
}

/// A row the receiver could not store would discard its whole snapshot, so
/// the list goes out as `null` instead of without the row — and the audit
/// says so once when that starts and once when a full list is back, never
/// once per pass.
#[test]
fn a_withheld_application_list_is_null_and_audited_on_transitions_only() {
    let dir = test_dir("withheld");
    let control_plane = ControlPlane::start(&dir);
    *control_plane.state.org_ownership.lock().unwrap() = Some(json!("organization"));
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    daemon.result(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "accept_organization_owned": true})),
    );
    let events = |daemon: &TestDaemon, result: &str| {
        daemon
            .audit_events()
            .iter()
            .filter(|e| e["action"] == "enroll.inventory" && e["result"] == result)
            .count()
    };
    assert_eq!(events(&daemon, "applications_withheld"), 0);

    // The installation changes and now lists a row with no columns.
    let flatpak = dir.join("machine/bin/flatpak");
    let changed = dir.join("machine/var/lib/flatpak/.changed");
    let good_script = fs::read_to_string(&flatpak).unwrap();
    fs::write(&flatpak, "#!/bin/sh\nprintf 'not-a-flatpak-row\\n'\n").unwrap();
    fs::write(&changed, "1").unwrap();
    daemon.result("reconcile", None);
    daemon.result("reconcile", None);
    {
        let inventory = control_plane.state.inventory.lock().unwrap();
        let last = &inventory.last().unwrap()["inventory"];
        assert_eq!(last["applications"], Value::Null, "never a truncated list");
        assert_eq!(last["identifiers"]["serial_number"], FIXTURE_SERIAL);
    }
    assert_eq!(
        events(&daemon, "applications_withheld"),
        1,
        "once, not per pass"
    );
    assert_eq!(events(&daemon, "success"), 0);

    // Repaired: the full list goes out again, and that is audited once.
    fs::write(&flatpak, good_script).unwrap();
    fs::write(&changed, "22").unwrap();
    daemon.result("reconcile", None);
    daemon.result("reconcile", None);
    {
        let inventory = control_plane.state.inventory.lock().unwrap();
        let last = &inventory.last().unwrap()["inventory"];
        assert_eq!(last["applications"].as_array().unwrap().len(), 3);
    }
    assert_eq!(events(&daemon, "applications_withheld"), 1);
    assert_eq!(events(&daemon, "success"), 1);
}

// ---------------------------------------------------------------------------
// What Smplify receives, and what the person is shown of it
// ---------------------------------------------------------------------------

/// The non-null keys of one section: what a field-name summary must list.
fn carried_keys(section: &Value) -> Vec<String> {
    let mut keys: Vec<String> = section
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, value)| match value {
            Value::Null => false,
            Value::Array(rows) => !rows.is_empty(),
            Value::String(text) => !text.is_empty(),
            _ => true,
        })
        .map(|(key, _)| key.clone())
        .collect();
    keys.sort();
    keys
}

/// `aa:bb:cc:dd:ee:ff`, or four dot-separated numbers of at most three
/// digits: the shape an address would have if one leaked.
fn carries_an_address(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.'))
        .any(|token| {
            let mac: Vec<&str> = token.split(':').collect();
            let ip: Vec<&str> = token.split('.').collect();
            (mac.len() == 6 && mac.iter().all(|part| part.len() == 2))
                || (ip.len() == 4
                    && ip.iter().all(|part| {
                        (1..=3).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit())
                    }))
        })
}

const SMPLIFY_HARDWARE_KEYS: [&str; 17] = [
    "batteryPresent",
    "biosVersion",
    "cpuCores",
    "cpuModel",
    "cpuThreads",
    "cpuVendor",
    "deviceCapacityBytes",
    "isVirtual",
    "manufacturer",
    "memoryTotalBytes",
    "modelName",
    "rootFilesystemType",
    "secureBoot",
    "tpmPresent",
    "tpmVersion",
    "uefi",
    "virtualization",
];

/// The whole path, punard to Smplify: punard's real inventory through the
/// agent's real translation (`punar_smplifyd::status`), checked as exact
/// key sets per tier where Smplify would receive it. Then the person's side
/// of the same send: `organization-view.json` holds exactly the body that
/// left, and `enroll.status` names exactly its non-null fields.
#[test]
fn smplify_receives_exactly_the_allowlist_per_tier_and_the_person_is_shown_it() {
    let dir = test_dir("smplify-path");
    let state = Arc::new(ControlPlaneState::default());
    state.translate_like_smplifyd.store(true, Ordering::SeqCst);
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));

    let personal = state.status_bodies.lock().unwrap()[0].clone();
    assert_eq!(
        sorted_keys(&personal),
        [
            "deviceId",
            "facts",
            "heartbeat",
            "supportedActions",
            "systemInfo"
        ]
    );
    let info = &personal["systemInfo"];
    assert_eq!(
        sorted_keys(info),
        ["hardware", "os", "security", "software"],
        "never network, never identity"
    );
    assert_eq!(
        sorted_keys(&info["os"]),
        ["arch", "kernelRelease", "name", "version"]
    );
    assert_eq!(
        sorted_keys(&info["hardware"]),
        SMPLIFY_HARDWARE_KEYS,
        "no serial number on a personal enrollment"
    );
    assert_eq!(
        sorted_keys(&info["security"]),
        [
            "diskEncryptionEnabled",
            "firewall",
            "firewallEnabled",
            "osPatchStatus",
            "rebootRequired"
        ]
    );
    assert_eq!(
        sorted_keys(&info["software"]),
        [
            "installedPackages",
            "installedPackagesCount",
            "installedPackagesHash",
            "smplifydBuildDate",
            "smplifydRevision",
            "smplifydVersion"
        ]
    );
    assert_eq!(personal["supportedActions"], json!([]));
    assert_eq!(personal["facts"], json!({}));

    // The fixture machine, typed as Smplify reads it.
    assert_eq!(info["os"]["name"], "Punar OS 0.5 (M5)");
    assert_eq!(info["os"]["version"], "0.5");
    assert_eq!(info["os"]["kernelRelease"], "6.12.0-punar");
    assert!(matches!(
        info["os"]["arch"].as_str(),
        Some("x86_64" | "aarch64")
    ));
    let hardware = &info["hardware"];
    assert_eq!(hardware["manufacturer"], "QEMU");
    assert_eq!(hardware["modelName"], "Standard PC (Q35 + ICH9, 2009)");
    assert_eq!(hardware["cpuCores"], json!(4));
    assert_eq!(hardware["memoryTotalBytes"], json!(8_192_000u64 * 1024));
    assert_eq!(hardware["secureBoot"], json!(false));
    assert_eq!(hardware["uefi"], json!(true));
    assert_eq!(hardware["tpmPresent"], json!(true));
    assert_eq!(hardware["tpmVersion"], "2.0");
    assert_eq!(hardware["isVirtual"], json!(true));
    assert_eq!(hardware["batteryPresent"], json!(false));
    let security = &info["security"];
    assert_eq!(security["diskEncryptionEnabled"], json!(true));
    assert_eq!(security["firewallEnabled"], json!(true));
    assert_eq!(security["firewall"], "nftables");
    assert_eq!(security["osPatchStatus"], "unknown");
    assert_eq!(security["rebootRequired"], json!(false));
    assert_eq!(
        info["software"]["installedPackages"],
        json!([
            {"name": "chromium", "displayName": "Chromium",
             "version": "151.0.7922.173-1", "source": "punar-image", "managed": false},
            {"name": "org.punar.Mail", "displayName": "Mail", "version": null,
             "source": "punar-image", "managed": false},
        ])
    );
    assert_eq!(info["software"]["installedPackagesCount"], 2);
    let text = personal.to_string();
    for forbidden in [
        FIXTURE_SERIAL,
        "firefox",
        "Thunar",
        "/home",
        "hostname",
        "current_state",
        "capabilities",
        "timezone",
        "machineId",
    ] {
        assert!(!text.contains(forbidden), "Smplify received {forbidden}");
    }
    assert!(!carries_an_address(&text), "{text}");

    // The person's record is the body that left, byte for byte, and the
    // summary names exactly its non-null fields — never a field that did not
    // travel.
    let view_path = daemon.state_path("organization-view.json");
    assert_eq!(mode_of(&view_path), 0o640);
    let record = read_json(&view_path);
    assert_eq!(
        sorted_keys(&record),
        ["enrolled_at", "org_id", "sent", "sent_at", "version"],
        "bookkeeping around the body, nothing else"
    );
    assert_eq!(record["sent"], personal);
    let status = daemon.result("enroll.status", None);
    let view = &status["organization_view"];
    assert_eq!(view["sent_at"], record["sent_at"]);
    let categories: Vec<&str> = view["categories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|category| category["category"].as_str().unwrap())
        .collect();
    assert_eq!(
        categories,
        ["hardware", "os", "security", "software"],
        "the empty supportedActions and facts told the organization nothing"
    );
    for category in view["categories"].as_array().unwrap() {
        let name = category["category"].as_str().unwrap();
        let fields: Vec<String> = serde_json::from_value(category["fields"].clone()).unwrap();
        assert_eq!(fields, carried_keys(&info[name]), "{name}");
    }
    assert_eq!(
        view["categories"][3]["counts"],
        json!({"installedPackages": 2})
    );
    assert!(!view.to_string().contains("serialNumber"));

    // The same device, enrolled again by an organization that owns it: the
    // serial number and the system-wide applications, and nothing else.
    daemon.result("enroll.stop", None);
    assert!(!view_path.exists());
    *state.org_ownership.lock().unwrap() = Some(json!("organization"));
    daemon.result(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "accept_organization_owned": true})),
    );
    let owned = state.status_bodies.lock().unwrap()[1].clone();
    assert_eq!(sorted_keys(&owned), sorted_keys(&personal));
    assert_eq!(sorted_keys(&owned["systemInfo"]), sorted_keys(info));
    let mut owned_hardware = SMPLIFY_HARDWARE_KEYS.to_vec();
    owned_hardware.push("serialNumber");
    owned_hardware.sort_unstable();
    assert_eq!(
        sorted_keys(&owned["systemInfo"]["hardware"]),
        owned_hardware
    );
    assert_eq!(
        owned["systemInfo"]["hardware"]["serialNumber"],
        FIXTURE_SERIAL
    );
    for section in ["os", "security"] {
        assert_eq!(owned["systemInfo"][section], info[section], "{section}");
    }
    let rows: Vec<(&str, &str)> = owned["systemInfo"]["software"]["installedPackages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["name"].as_str().unwrap(),
                row["source"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("chromium", "punar-image"),
            ("org.mozilla.firefox", "flatpak"),
            ("org.punar.Mail", "punar-image"),
        ]
    );
    let record = read_json(&view_path);
    assert_eq!(record["sent"], owned);
    let status = daemon.result("enroll.status", None);
    let hardware_fields = status["organization_view"]["categories"][0].clone();
    assert_eq!(hardware_fields["category"], "hardware");
    assert!(
        hardware_fields["fields"]
            .as_array()
            .unwrap()
            .contains(&json!("serialNumber")),
        "{hardware_fields}"
    );
    let text = owned.to_string();
    for forbidden in ["hostname", "current_state", "/home", "Thunar"] {
        assert!(!text.contains(forbidden), "Smplify received {forbidden}");
    }
    assert!(!carries_an_address(&text), "{text}");
}

/// From a control plane that does not say what it sent on (the development
/// mock), the record is the inventory it received. It moves only when a send
/// succeeds, and a record that is missing or belongs to another enrollment
/// is reported as nothing sent rather than shown.
#[test]
fn the_organization_view_changes_only_when_a_send_succeeds() {
    const LONG_AGO: &str = "2026-01-01T00:00:00Z";
    let dir = test_dir("org-view");
    let enrollment_file = dir.join("state/enrollment.json");
    let view_path = dir.join("state/organization-view.json");
    let control_plane = ControlPlane::start(&dir);
    {
        let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
        daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
        let received = control_plane.state.inventory.lock().unwrap()[0]["inventory"].clone();
        assert_eq!(read_json(&view_path)["sent"], received);
        let view = daemon.result("enroll.status", None)["organization_view"].clone();
        let categories: Vec<(String, Vec<String>)> = view["categories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|category| {
                (
                    category["category"].as_str().unwrap().to_string(),
                    serde_json::from_value(category["fields"].clone()).unwrap(),
                )
            })
            .collect();
        // The mock keeps punard's own inventory, and the person is told
        // what is in it: which capabilities exist, never a hostname or a
        // capability's value, because the body carries none.
        assert_eq!(categories[0].0, "device");
        assert_eq!(categories[0].1, ["applications", "capabilities", "kernel"]);
        assert_eq!(
            view["categories"][0]["counts"],
            json!({"applications": 2, "capabilities": 1})
        );
        let names: Vec<&str> = categories.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["device", "hardware", "os", "posture"]);
        daemon.stop();
    }
    let recorded = fs::read(&view_path).unwrap();

    // Due again, with the control plane down: the send fails, and the record
    // of what the organization has is untouched.
    let mut enrollment = read_json(&enrollment_file);
    enrollment["last_inventory_sent_at"] = json!(LONG_AGO);
    fs::write(&enrollment_file, enrollment.to_string()).unwrap();
    let state = control_plane.stop();
    {
        let daemon = TestDaemon::start(
            &dir,
            Peer::root(),
            &dir.join("control-plane.sock"),
            "enabled",
        );
        daemon.stop();
    }
    assert_eq!(fs::read(&view_path).unwrap(), recorded);

    // Back online, the resend succeeds and the record moves with it. (Dated
    // back first, so the move shows even within the same second.)
    let mut dated = read_json(&view_path);
    dated["sent_at"] = json!(LONG_AGO);
    fs::write(&view_path, dated.to_string()).unwrap();
    let control_plane = ControlPlane::start_with(&dir, state);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    assert_eq!(control_plane.state.inventory.lock().unwrap().len(), 2);
    let record = read_json(&view_path);
    assert_ne!(record["sent_at"], LONG_AGO);
    assert_eq!(
        record["sent_at"],
        read_json(&enrollment_file)["last_inventory_sent_at"]
    );
    assert_eq!(
        record["sent"],
        control_plane.state.inventory.lock().unwrap()[1]["inventory"]
    );

    // A record of another enrollment is not this one's.
    let mut stale = record.clone();
    stale["enrolled_at"] = json!("2020-01-01T00:00:00Z");
    fs::write(&view_path, stale.to_string()).unwrap();
    assert_eq!(
        daemon.result("enroll.status", None)["organization_view"],
        json!({"sent_at": null, "categories": []})
    );
    fs::remove_file(&view_path).unwrap();
    assert_eq!(
        daemon.result("enroll.status", None)["organization_view"],
        json!({"sent_at": null, "categories": []})
    );
}
