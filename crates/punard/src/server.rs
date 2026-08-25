//! The punard daemon: UDS NDJSON server, method dispatch, capability
//! pipeline, reconcile, and boot behavior (docs/api/ipc.md is the binding
//! wire contract; docs/development/milestone-3.md section 3 the
//! architecture).
//!
//! Threading model (budget, PERFORMANCE_BUDGETS.md 1.2/6.2): no async
//! runtime; std accept loop, one thread per connection, hard cap
//! [`DaemonConfig::max_connections`] — when full, the listener simply does
//! not accept. Per-connection memory is bounded by the 4096-byte line limit.

use std::io::{self, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use punar_common::{CapabilityId, Decision, PrincipalKind};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::audit::{AuditLog, RESOURCE_REGISTRY, USER_DAEMON, build_event};
use crate::authz::{self, Peer, PeerSource, authorize_mutation, denial_message};
use crate::capability::{Capability, Descriptor, Registry};
use crate::state::{DesiredStore, load_or_create_device_id};
use crate::timeutil::utc_now_rfc3339;
use crate::util::{lookup_gid, lookup_username};
use crate::wire::{
    ErrorCode, MAX_LINE_BYTES, PROTOCOL_VERSION, Request, Response, WireError, parse_request_line,
};

/// Daemon configuration. All paths are injectable so tests run against a
/// tempdir; production values are the documented contract paths.
pub struct DaemonConfig {
    /// `/run/punard/punard.sock`.
    pub socket_path: PathBuf,
    /// `/var/lib/punar` — holds `desired.json` and `device-id`.
    pub state_dir: PathBuf,
    /// `/var/log/punar/audit.jsonl`.
    pub audit_path: PathBuf,
    /// Group granted socket access (`punar`).
    pub group: String,
    /// `/etc/group` (injectable for tests).
    pub group_file: PathBuf,
    /// `/etc/passwd` (injectable for tests).
    pub passwd_file: PathBuf,
    /// Peer identity source; `PeerSource::Fixed` is the test hook.
    pub peer_source: PeerSource,
    /// Hard cap on concurrent connections.
    pub max_connections: usize,
    /// Socket read/write timeout per operation.
    pub io_timeout: Duration,
}

impl DaemonConfig {
    pub fn new(socket_path: PathBuf, state_dir: PathBuf, audit_path: PathBuf) -> Self {
        DaemonConfig {
            socket_path,
            state_dir,
            audit_path,
            group: "punar".to_string(),
            group_file: PathBuf::from("/etc/group"),
            passwd_file: PathBuf::from("/etc/passwd"),
            peer_source: PeerSource::SoPeercred,
            max_connections: 16,
            io_timeout: Duration::from_secs(10),
        }
    }
}

struct Inner {
    cfg: DaemonConfig,
    registry: Registry,
    audit: AuditLog,
    desired: DesiredStore,
    device_id: String,
    started_at: String,
    last_reconcile: Mutex<Option<String>>,
    shutdown: AtomicBool,
    active: Mutex<usize>,
    slot_freed: Condvar,
}

/// A constructed (not yet listening) daemon.
pub struct Daemon {
    inner: Arc<Inner>,
}

/// A listening daemon; `stop()` shuts it down gracefully.
pub struct DaemonHandle {
    inner: Arc<Inner>,
    accept_thread: JoinHandle<()>,
}

impl Daemon {
    /// Build the daemon: device id, audit log, desired-state store with
    /// first-boot seeding (firewall default `enabled` [os default];
    /// everything else seeded from first observation).
    pub fn new(cfg: DaemonConfig, registry: Registry) -> io::Result<Self> {
        std::fs::create_dir_all(&cfg.state_dir)?;
        if let Some(parent) = cfg.audit_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let device_id = load_or_create_device_id(&cfg.state_dir.join("device-id"))?;
        let audit = AuditLog::open(&cfg.audit_path, lookup_gid(&cfg.group_file, &cfg.group))?;
        let desired = DesiredStore::load(&cfg.state_dir.join("desired.json"))?;

        for cap in registry.iter() {
            let id = cap.descriptor().capability.to_string();
            if desired.get(&id).is_some() {
                continue;
            }
            let seed = cap
                .default_desired()
                .or_else(|| cap.observe().ok())
                .unwrap_or(Value::String("unknown".to_string()));
            desired.seed(&id, seed)?;
        }

        Ok(Daemon {
            inner: Arc::new(Inner {
                cfg,
                registry,
                audit,
                desired,
                device_id,
                started_at: utc_now_rfc3339(),
                last_reconcile: Mutex::new(None),
                shutdown: AtomicBool::new(false),
                active: Mutex::new(0),
                slot_freed: Condvar::new(),
            }),
        })
    }

    /// Boot-time reconcile (daemon-initiated: `user_id: "punard"`). Observes
    /// and verifies everything; the **one** boot-time apply is
    /// `security.firewall` when its desired state is `enabled` and the table
    /// is absent/deviant — the firewall default is a fixed os default.
    /// Runtime `reconcile` requests never remediate in M3.
    pub fn boot_reconcile(&self) {
        let inner = &self.inner;
        for cap in inner.registry.iter() {
            let id = cap.descriptor().capability.to_string();
            if id != crate::backends::firewall::CAPABILITY_ID {
                continue;
            }
            let desired = inner
                .desired
                .get(&id)
                .unwrap_or(Value::String("enabled".to_string()));
            if desired != json!("enabled") {
                continue;
            }
            let current = cap.observe().ok();
            if current.as_ref() == Some(&desired) {
                continue;
            }
            let result = match cap.apply(&desired).and_then(|()| cap.verify(&desired)) {
                Ok(true) => "success",
                Ok(false) => "verify_failed",
                Err(e) => {
                    eprintln!("punard: boot firewall apply failed: {e}");
                    "failure"
                }
            };
            inner.log_audit(build_event(
                &inner.device_id,
                USER_DAEMON,
                PrincipalKind::Service,
                "capabilities.set",
                &id,
                Decision::Allow,
                result,
            ));
        }

        // Record the boot reconcile itself (observe + verify + drift report).
        let (result_value, drift_count) = inner.reconcile_report();
        *inner.last_reconcile.lock().unwrap() = Some(
            result_value["reconciled_at"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        );
        inner.log_audit(build_event(
            &inner.device_id,
            USER_DAEMON,
            PrincipalKind::Service,
            "reconcile",
            RESOURCE_REGISTRY,
            Decision::Allow,
            if drift_count > 0 {
                "drift_detected"
            } else {
                "clean"
            },
        ));
    }

    /// Bind the socket (fresh: stale files are unlinked), set permissions
    /// **before** `listen()` (0660 root:`punar`; chown best-effort when
    /// unprivileged), then start the accept loop on a background thread.
    pub fn spawn(self) -> io::Result<DaemonHandle> {
        let inner = self.inner;
        let listener = bind_with_perms(
            &inner.cfg.socket_path,
            lookup_gid(&inner.cfg.group_file, &inner.cfg.group),
        )?;
        let accept_inner = Arc::clone(&inner);
        let accept_thread = std::thread::Builder::new()
            .name("punard-accept".to_string())
            .spawn(move || accept_loop(accept_inner, listener))?;
        Ok(DaemonHandle {
            inner,
            accept_thread,
        })
    }
}

impl DaemonHandle {
    pub fn socket_path(&self) -> &Path {
        &self.inner.cfg.socket_path
    }

    /// Request shutdown, wake the accept loop, and join it.
    pub fn stop(self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner.slot_freed.notify_all();
        // Nudge a blocked accept(2) with a throwaway connection.
        let _ = UnixStream::connect(&self.inner.cfg.socket_path);
        let _ = self.accept_thread.join();
        let _ = std::fs::remove_file(&self.inner.cfg.socket_path);
    }
}

/// socket + bind + perms + listen, in that order (docs/api/ipc.md
/// section 1.2). rustix keeps this free of `unsafe`; std's
/// `UnixListener::bind` would listen before we could set permissions.
fn bind_with_perms(path: &Path, gid: Option<u32>) -> io::Result<UnixListener> {
    use rustix::net::{AddressFamily, SocketType, bind, listen, socket};

    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let fd = socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    let addr = rustix::net::SocketAddrUnix::new(path)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    bind(&fd, &addr)?;
    // Not yet listening: connects fail ECONNREFUSED while we fix perms.
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o660))?;
    if let Some(gid) = gid {
        // Meaningful only as root; harmless EPERM otherwise (tests).
        let _ = std::os::unix::fs::chown(path, Some(0), Some(gid));
    }
    listen(&fd, 16)?;
    Ok(UnixListener::from(fd))
}

fn accept_loop(inner: Arc<Inner>, listener: UnixListener) {
    loop {
        // Connection cap: hold accepts until a slot frees (ipc.md: "the
        // listener simply doesn't accept").
        {
            let mut active = inner.active.lock().unwrap();
            while *active >= inner.cfg.max_connections && !inner.shutdown.load(Ordering::SeqCst) {
                active = inner.slot_freed.wait(active).unwrap();
            }
        }
        if inner.shutdown.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                if inner.shutdown.load(Ordering::SeqCst) {
                    break;
                }
                *inner.active.lock().unwrap() += 1;
                let conn_inner = Arc::clone(&inner);
                let spawned = std::thread::Builder::new()
                    .name("punard-conn".to_string())
                    .spawn(move || {
                        handle_connection(&conn_inner, stream);
                        *conn_inner.active.lock().unwrap() -= 1;
                        conn_inner.slot_freed.notify_all();
                    });
                if spawned.is_err() {
                    *inner.active.lock().unwrap() -= 1;
                }
            }
            Err(e) => {
                if inner.shutdown.load(Ordering::SeqCst) {
                    break;
                }
                eprintln!("punard: accept failed: {e}");
            }
        }
    }
}

/// Outcome of one bounded line read.
enum LineRead {
    Line(String),
    TooLong,
    Eof,
}

/// Read one `\n`-terminated line of at most `max` bytes (terminator
/// included). Never buffers more than `max` bytes of an oversized line.
fn read_line_bounded<R: Read>(reader: &mut BufReader<R>, max: usize) -> io::Result<LineRead> {
    use std::io::BufRead;
    let mut line: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(LineRead::Eof)
            } else {
                // Trailing data without newline: treat as a (final) line.
                Ok(LineRead::Line(String::from_utf8_lossy(&line).into_owned()))
            };
        }
        if let Some(pos) = available.iter().position(|b| *b == b'\n') {
            if line.len() + pos + 1 > max {
                reader.consume(pos + 1);
                return Ok(LineRead::TooLong);
            }
            line.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            return Ok(LineRead::Line(String::from_utf8_lossy(&line).into_owned()));
        }
        let chunk = available.len();
        if line.len() + chunk > max {
            reader.consume(chunk);
            return Ok(LineRead::TooLong);
        }
        line.extend_from_slice(available);
        reader.consume(chunk);
    }
}

fn write_response(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    let mut line = serde_json::to_string(response).map_err(io::Error::other)?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    stream.flush()
}

fn handle_connection(inner: &Inner, mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(inner.cfg.io_timeout));
    let _ = stream.set_write_timeout(Some(inner.cfg.io_timeout));

    let peer = match inner.cfg.peer_source.peer_of(&stream) {
        Ok(peer) => peer,
        Err(e) => {
            eprintln!("punard: could not read peer credentials: {e}");
            return;
        }
    };

    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("punard: could not clone connection stream: {e}");
            return;
        }
    };
    let mut reader = BufReader::with_capacity(MAX_LINE_BYTES, reader_stream);

    // Requests are processed sequentially, in order (ipc.md section 2).
    loop {
        match read_line_bounded(&mut reader, MAX_LINE_BYTES) {
            Ok(LineRead::Eof) => break,
            Ok(LineRead::TooLong) => {
                let err = WireError::new(
                    ErrorCode::MalformedRequest,
                    format!(
                        "The request line exceeded the {MAX_LINE_BYTES}-byte limit.\n\
                         Policy: os default — punard bounds request size (docs/api/ipc.md section 2).\n\
                         Next step: no M3 request needs more; use punarctl."
                    ),
                );
                let _ = write_response(&mut stream, &Response::err(None, err));
                break; // malformed closes the connection
            }
            Ok(LineRead::Line(line)) => match parse_request_line(&line) {
                Ok(request) => {
                    let id = request.id.clone();
                    let response = match inner.dispatch(&peer, &request) {
                        Ok(result) => Response::ok(id, result),
                        Err(err) => Response::err(Some(id), err),
                    };
                    if write_response(&mut stream, &response).is_err() {
                        break;
                    }
                }
                Err((id, err)) => {
                    let close = err.code == ErrorCode::MalformedRequest;
                    let _ = write_response(&mut stream, &Response::err(id, err));
                    if close {
                        break;
                    }
                }
            },
            Err(_) => break, // read timeout or I/O error: close (ipc.md section 2)
        }
    }
}

// ---------------------------------------------------------------------------
// Method dispatch and handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetParams {
    capability: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetParams {
    capability: String,
    desired_state: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TailParams {
    #[serde(default)]
    n: Option<u64>,
}

fn invalid_params(reason: &str, param: &str) -> WireError {
    WireError::new(
        ErrorCode::InvalidParams,
        format!(
            "The request parameters were not accepted: {reason}.\n\
             Policy: os default — punard validates every parameter strictly (docs/api/ipc.md section 3.1).\n\
             Next step: check `punarctl --help` for the expected arguments."
        ),
    )
    .with_details(json!({ "param": param, "reason": reason }))
}

/// Strictly deserialize params; absent params become `{}`.
fn parse_params<T: serde::de::DeserializeOwned>(
    params: Option<Map<String, Value>>,
) -> Result<T, WireError> {
    serde_json::from_value(Value::Object(params.unwrap_or_default()))
        .map_err(|e| invalid_params(&e.to_string(), "params"))
}

/// Methods that take no params reject any non-empty params object.
fn expect_no_params(params: Option<Map<String, Value>>) -> Result<(), WireError> {
    match params {
        None => Ok(()),
        Some(map) if map.is_empty() => Ok(()),
        Some(map) => {
            let keys: Vec<&str> = map.keys().map(String::as_str).collect();
            Err(invalid_params(
                &format!("this method takes no parameters, got {keys:?}"),
                "params",
            ))
        }
    }
}

impl Inner {
    fn log_audit(&self, event: punar_common::AuditEvent) {
        if let Err(e) = self.audit.append(&event) {
            // Never lose a response over an audit I/O error, but say so
            // loudly — the audit trail is a contract.
            eprintln!("punard: FAILED to append audit event: {e}");
        }
    }

    fn username_of(&self, peer: &Peer) -> String {
        lookup_username(&self.cfg.passwd_file, peer.uid)
            .unwrap_or_else(|| format!("uid:{}", peer.uid))
    }

    /// Full descriptor for a capability: static meta + live observation +
    /// recorded desired state.
    fn describe(&self, cap: &dyn Capability) -> Descriptor {
        let meta = cap.descriptor();
        let id = meta.capability.to_string();
        let current = cap
            .observe()
            .unwrap_or_else(|_| Value::String("unknown".to_string()));
        let desired = self.desired.get(&id).unwrap_or_else(|| current.clone());
        Descriptor::from_meta(&meta, current, desired)
    }

    /// The closed method table (docs/api/ipc.md section 5). There is no
    /// exec, shell, script, or run-as-root method, by architecture (SPEC
    /// sections 10, 60) — unknown names get `unknown_method`, and that is
    /// the permanent answer.
    fn dispatch(&self, peer: &Peer, request: &Request) -> Result<Value, WireError> {
        let params = request.params.clone();
        match request.method.as_str() {
            "status" => {
                expect_no_params(params)?;
                Ok(self.handle_status())
            }
            "capabilities.list" => {
                expect_no_params(params)?;
                Ok(self.handle_capabilities_list())
            }
            "capabilities.get" => {
                let p: GetParams = parse_params(params)?;
                self.handle_capabilities_get(&p)
            }
            "capabilities.set" => {
                let p: SetParams = parse_params(params)?;
                self.handle_capabilities_set(peer, &p)
            }
            "audit.tail" => {
                let p: TailParams = parse_params(params)?;
                self.handle_audit_tail(&p)
            }
            "reconcile" => {
                expect_no_params(params)?;
                self.handle_reconcile(peer)
            }
            other => Err(WireError::new(
                ErrorCode::UnknownMethod,
                format!(
                    "Method {other:?} does not exist.\n\
                     Policy: os default — punard exposes only typed capability methods; \
                     there is no generic execution method and never will be (SPEC sections 10, 60).\n\
                     Next step: `punarctl --help` lists the supported commands."
                ),
            )
            .with_details(json!({ "method": other }))),
        }
    }

    fn handle_status(&self) -> Value {
        let hostname = self
            .registry
            .get(crate::backends::hostname::CAPABILITY_ID)
            .and_then(|cap| cap.observe().ok())
            .unwrap_or(Value::String("unknown".to_string()));
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "daemon_version": env!("CARGO_PKG_VERSION"),
            "started_at": self.started_at,
            "device_id": self.device_id,
            "mode": "personal",
            "enrolled": false,
            "hostname": hostname,
            "capabilities_total": self.registry.len(),
            "last_reconcile": *self.last_reconcile.lock().unwrap(),
            "audit": {
                "path": self.cfg.audit_path.display().to_string(),
                "events": self.audit.count(),
            },
        })
    }

    fn handle_capabilities_list(&self) -> Value {
        let descriptors: Vec<Value> = self
            .registry
            .iter()
            .map(|cap| serde_json::to_value(self.describe(cap)).expect("descriptor serializes"))
            .collect();
        json!({ "capabilities": descriptors })
    }

    fn handle_capabilities_get(&self, p: &GetParams) -> Result<Value, WireError> {
        let cap = self.lookup(&p.capability)?;
        Ok(json!({
            "descriptor": serde_json::to_value(self.describe(cap)).expect("descriptor serializes")
        }))
    }

    fn lookup(&self, capability: &str) -> Result<&dyn Capability, WireError> {
        CapabilityId::new(capability).map_err(|e| invalid_params(&e.to_string(), "capability"))?;
        self.registry.get(capability).ok_or_else(|| {
            WireError::new(
                ErrorCode::NotFound,
                format!(
                    "No capability named {capability:?} is registered on this device.\n\
                     Policy: os default — the M3 registry holds security.firewall, \
                     system.hostname, and time.timezone.\n\
                     Next step: `punarctl capabilities` lists what exists."
                ),
            )
            .with_details(json!({ "capability": capability }))
        })
    }

    /// The mutation pipeline (SPEC section 42, M3 subset): validate →
    /// authorize → record desired → apply → verify → audit → respond.
    /// Allow and deny, success and failure are all audited.
    fn handle_capabilities_set(&self, peer: &Peer, p: &SetParams) -> Result<Value, WireError> {
        let cap = self.lookup(&p.capability)?;
        let id = p.capability.as_str();
        cap.validate(&p.desired_state)
            .map_err(|reason| invalid_params(&reason, "desired_state"))?;

        let user = self.username_of(peer);
        if authorize_mutation(peer) != Decision::Allow {
            self.log_audit(build_event(
                &self.device_id,
                &user,
                PrincipalKind::Human,
                "capabilities.set",
                id,
                Decision::Deny,
                "denied",
            ));
            let state_hint = match &p.desired_state {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            return Err(WireError::new(
                ErrorCode::Denied,
                denial_message(
                    &format!("Changing {id}"),
                    &format!("punarctl capabilities set {id} {state_hint}"),
                ),
            )
            .with_details(json!({
                "capability": id,
                "decision": "deny",
                "policy_ids": [authz::POLICY_PERSONAL_DEFAULTS],
            })));
        }

        // Idempotence: already in the desired state → record + audit noop.
        let already = cap.observe().ok().is_some_and(|cur| cur == p.desired_state);
        self.desired
            .set(id, p.desired_state.clone())
            .map_err(|e| self.internal(&format!("persisting desired state failed: {e}")))?;
        if already {
            self.log_audit(build_event(
                &self.device_id,
                &user,
                PrincipalKind::Human,
                "capabilities.set",
                id,
                Decision::Allow,
                "noop",
            ));
            return Ok(json!({
                "descriptor": serde_json::to_value(self.describe(cap)).expect("descriptor serializes"),
                "changed": false,
            }));
        }

        if let Err(apply_err) = cap.apply(&p.desired_state) {
            self.log_audit(build_event(
                &self.device_id,
                &user,
                PrincipalKind::Human,
                "capabilities.set",
                id,
                Decision::Allow,
                "failure",
            ));
            return Err(WireError::new(
                ErrorCode::ApplyFailed,
                format!(
                    "Applying the new state for {id} failed: {apply_err}.\n\
                     Policy: personal defaults — the change was authorized but the backend could not complete it.\n\
                     Next step: check `journalctl -u punard` and retry."
                ),
            )
            .with_details(json!({ "capability": id, "stage": "apply" })));
        }

        match cap.verify(&p.desired_state) {
            Ok(true) => {
                self.log_audit(build_event(
                    &self.device_id,
                    &user,
                    PrincipalKind::Human,
                    "capabilities.set",
                    id,
                    Decision::Allow,
                    "success",
                ));
                Ok(json!({
                    "descriptor": serde_json::to_value(self.describe(cap)).expect("descriptor serializes"),
                    "changed": true,
                }))
            }
            verify_outcome => {
                let observed = cap
                    .observe()
                    .unwrap_or(Value::String("unknown".to_string()));
                self.log_audit(build_event(
                    &self.device_id,
                    &user,
                    PrincipalKind::Human,
                    "capabilities.set",
                    id,
                    Decision::Allow,
                    "verify_failed",
                ));
                let why = match verify_outcome {
                    Err(e) => format!("verification errored: {e}"),
                    _ => "the system did not reach the requested state".to_string(),
                };
                Err(WireError::new(
                    ErrorCode::VerifyFailed,
                    format!(
                        "The change to {id} was applied but could not be verified: {why}.\n\
                         Policy: personal defaults — punard re-observes after every change (SPEC section 42).\n\
                         Next step: `punarctl capabilities get {id}` to inspect the live state."
                    ),
                )
                .with_details(json!({
                    "capability": id,
                    "expected": p.desired_state,
                    "observed": observed,
                })))
            }
        }
    }

    fn handle_audit_tail(&self, p: &TailParams) -> Result<Value, WireError> {
        // Default 20, values above 1000 clamped, not errors (ipc.md 5.5).
        let n = p.n.unwrap_or(20).min(1000) as usize;
        let events = self
            .audit
            .tail(n)
            .map_err(|e| self.internal(&format!("reading the audit log failed: {e}")))?;
        Ok(json!({ "events": events }))
    }

    /// M3 reconcile: re-observe + re-verify, **report drift only** — no
    /// remediation (that, plus the policy merge, is Milestone 4). Root-only
    /// because M4 makes it applying and the authz surface must not loosen.
    fn handle_reconcile(&self, peer: &Peer) -> Result<Value, WireError> {
        let user = self.username_of(peer);
        if authorize_mutation(peer) != Decision::Allow {
            self.log_audit(build_event(
                &self.device_id,
                &user,
                PrincipalKind::Human,
                "reconcile",
                RESOURCE_REGISTRY,
                Decision::Deny,
                "denied",
            ));
            return Err(WireError::new(
                ErrorCode::Denied,
                denial_message("Running a reconcile", "punarctl reconcile"),
            )
            .with_details(json!({
                "capability": RESOURCE_REGISTRY,
                "decision": "deny",
                "policy_ids": [authz::POLICY_PERSONAL_DEFAULTS],
            })));
        }

        let (result, drift_count) = self.reconcile_report();
        *self.last_reconcile.lock().unwrap() = Some(
            result["reconciled_at"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        );
        self.log_audit(build_event(
            &self.device_id,
            &user,
            PrincipalKind::Human,
            "reconcile",
            RESOURCE_REGISTRY,
            Decision::Allow,
            if drift_count > 0 {
                "drift_detected"
            } else {
                "clean"
            },
        ));
        Ok(result)
    }

    /// Observe + verify every capability against the recorded desired
    /// state; report drift. Shared by boot reconcile and the RPC.
    fn reconcile_report(&self) -> (Value, u64) {
        let mut entries: Vec<Value> = Vec::new();
        let mut drift_count: u64 = 0;
        for cap in self.registry.iter() {
            let id = cap.descriptor().capability.to_string();
            let current = cap
                .observe()
                .unwrap_or_else(|_| Value::String("unknown".to_string()));
            let desired = self.desired.get(&id).unwrap_or_else(|| current.clone());
            // `verified` = the verification mechanism itself ran; a drifted
            // state still verifies as Ok(false).
            let verified = cap.verify(&desired).is_ok();
            let drift = current != desired;
            if drift {
                drift_count += 1;
            }
            entries.push(json!({
                "capability": id,
                "desired_state": desired,
                "current_state": current,
                "drift": drift,
                "verified": verified,
            }));
        }
        (
            json!({
                "reconciled_at": utc_now_rfc3339(),
                "drift_count": drift_count,
                "capabilities": entries,
            }),
            drift_count,
        )
    }

    fn internal(&self, detail: &str) -> WireError {
        // Operator detail goes to the journal; the wire gets a generic
        // message (no internals, never secrets — Redacted by construction).
        eprintln!("punard: internal error: {detail}");
        WireError::new(
            ErrorCode::Internal,
            "punard hit an internal error while handling the request.\n\
             Policy: os default — details are in the system journal, not on the wire.\n\
             Next step: `journalctl -u punard` and retry."
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_line_bounded_handles_lines_and_limits() {
        let data = b"short\n".to_vec();
        let mut reader = BufReader::new(io::Cursor::new(data));
        match read_line_bounded(&mut reader, 16).unwrap() {
            LineRead::Line(l) => assert_eq!(l, "short"),
            _ => panic!("expected a line"),
        }
        match read_line_bounded(&mut reader, 16).unwrap() {
            LineRead::Eof => {}
            _ => panic!("expected EOF"),
        }

        let long = vec![b'x'; 64];
        let mut data = long.clone();
        data.push(b'\n');
        data.extend_from_slice(b"after\n");
        let mut reader = BufReader::new(io::Cursor::new(data));
        match read_line_bounded(&mut reader, 16).unwrap() {
            LineRead::TooLong => {}
            _ => panic!("expected TooLong"),
        }
        // The oversized line was consumed; the next one still parses.
        match read_line_bounded(&mut reader, 16).unwrap() {
            LineRead::Line(l) => assert_eq!(l, "after"),
            _ => panic!("expected the next line"),
        }
    }
}
