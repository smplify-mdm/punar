//! The punard daemon: UDS NDJSON server, method dispatch, capability
//! pipeline, reconcile, and boot behavior. The wire contract is
//! `docs/api/ipc.md`, implemented by the shared types in
//! [`punar_common::ipc`]; audit plumbing is [`punar_common::audit`].
//!
//! Threading model (budget, PERFORMANCE_BUDGETS.md 1.2/6.2): no async
//! runtime; std accept loop, one thread per connection, hard cap
//! [`DaemonConfig::max_connections`] — when full, the listener simply does
//! not accept. Per-connection memory is bounded by the 4096-byte line limit.

use std::io::{self, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use punar_common::audit::{
    AuditActor, AuditOutcome, AuditWriter, RESOURCE_CAPABILITY_REGISTRY, count_events, tail,
};
use punar_common::ipc::{
    AuditStatus, AuditTailParams, CapabilitiesGetParams, CapabilitiesSetParams, ErrorCode,
    IpcError, MAX_REQUEST_LINE_BYTES, Method, Mode, PROTOCOL_VERSION, ReconcileEntry,
    ReconcileResult, Request, Response, SERVER_READ_TIMEOUT, StatusResult,
};
use punar_common::time::utc_now_rfc3339;
use punar_common::{AuditEvent, Decision};
use serde_json::{Value, json};

use crate::authz::{Peer, PeerSource, authorize_mutation};
use crate::capability::{Capability, Registry};
use crate::state::{DesiredStore, load_or_create_device_id};
use crate::util::{lookup_gid, lookup_username};

/// Daemon configuration. All paths are injectable so tests run against a
/// tempdir; production values are the documented contract paths.
pub struct DaemonConfig {
    /// [`punar_common::ipc::SOCKET_PATH`] in production.
    pub socket_path: PathBuf,
    /// `/var/lib/punar` — holds `desired.json` and `device-id`.
    pub state_dir: PathBuf,
    /// [`punar_common::audit::AUDIT_LOG_PATH`] in production.
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
            io_timeout: SERVER_READ_TIMEOUT,
        }
    }
}

struct Inner {
    cfg: DaemonConfig,
    registry: Registry,
    audit: Mutex<AuditWriter>,
    audit_events: AtomicU64,
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
        let audit = AuditWriter::open(&cfg.audit_path)?;
        // Group ownership (root:punar) is the daemon's job, not the
        // writer's; meaningful only when running as root (tests are not).
        if let Some(gid) = lookup_gid(&cfg.group_file, &cfg.group) {
            let _ = std::os::unix::fs::chown(&cfg.audit_path, Some(0), Some(gid));
        }
        let audit_events = count_events(&cfg.audit_path)?;
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
                audit: Mutex::new(audit),
                audit_events: AtomicU64::new(audit_events),
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

    /// Boot-time reconcile (daemon-initiated: [`AuditActor::daemon`]).
    /// Observes and verifies everything; the **one** boot-time apply is
    /// `security.firewall` when its desired state is `enabled` and the table
    /// is absent/deviant — the firewall default is a fixed os default.
    /// Runtime `reconcile` requests never remediate in M3.
    pub fn boot_reconcile(&self) {
        let inner = &self.inner;
        let actor = AuditActor::daemon();
        for cap in inner.registry.iter() {
            let meta = cap.descriptor();
            if meta.capability.as_str() != crate::backends::firewall::CAPABILITY_ID {
                continue;
            }
            let desired = inner
                .desired
                .get(meta.capability.as_str())
                .unwrap_or(Value::String("enabled".to_string()));
            if desired != json!("enabled") {
                continue;
            }
            let current = cap.observe().ok();
            if current.as_ref() == Some(&desired) {
                continue;
            }
            let outcome = match cap.apply(&desired).and_then(|()| cap.verify(&desired)) {
                Ok(true) => AuditOutcome::Success,
                Ok(false) => AuditOutcome::VerifyFailed,
                Err(e) => {
                    eprintln!("punard: boot firewall apply failed: {e}");
                    AuditOutcome::Failure
                }
            };
            inner.log_audit(AuditEvent::capabilities_set(
                &inner.device_id,
                &actor,
                &meta.capability,
                Decision::Allow,
                outcome,
            ));
        }

        // Record the boot reconcile itself (observe + verify + drift report).
        let report = inner.reconcile_report();
        *inner.last_reconcile.lock().unwrap() = Some(report.reconciled_at.clone());
        let outcome = if report.drift_count > 0 {
            AuditOutcome::DriftDetected
        } else {
            AuditOutcome::Clean
        };
        inner.log_audit(AuditEvent::reconcile(&inner.device_id, &actor, outcome));
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
    stream.write_all(response.to_json_line().as_bytes())?;
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
    let mut reader = BufReader::with_capacity(MAX_REQUEST_LINE_BYTES, reader_stream);

    // Requests are processed sequentially, in order (ipc.md section 2).
    loop {
        match read_line_bounded(&mut reader, MAX_REQUEST_LINE_BYTES) {
            Ok(LineRead::Eof) => break,
            Ok(LineRead::TooLong) => {
                let err = IpcError::new(
                    ErrorCode::MalformedRequest,
                    format!(
                        "The request line exceeded the {MAX_REQUEST_LINE_BYTES}-byte limit.\n\
                         Policy: os default — punard bounds request size (docs/api/ipc.md section 2).\n\
                         Next step: no M3 request needs more; use punarctl."
                    ),
                );
                let _ = write_response(&mut stream, &Response::error(None, err));
                break; // framing violation closes the connection
            }
            Ok(LineRead::Line(line)) => match Request::parse_json_line(&line) {
                Ok(request) => {
                    let id = request.id.clone();
                    let response = match inner.dispatch(&peer, &request) {
                        Ok(result) => Response::result(id, result),
                        Err(err) => Response::error(Some(id), err),
                    };
                    if write_response(&mut stream, &response).is_err() {
                        break;
                    }
                }
                Err(reject) => {
                    let close = reject.error.code.closes_connection();
                    let _ = write_response(&mut stream, &Response::from_reject(reject));
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
// Method handlers
// ---------------------------------------------------------------------------

fn invalid_state(reason: &str) -> IpcError {
    IpcError::with_details(
        ErrorCode::InvalidParams,
        format!(
            "The requested state was not accepted: {reason}.\n\
             Policy: os default — punard validates every state value against the \
             capability's declared state space (docs/api/ipc.md section 5.4).\n\
             Next step: `punarctl capabilities get <id>` shows the allowed states."
        ),
        json!({ "param": "desired_state", "reason": reason }),
    )
}

impl Inner {
    fn log_audit(&self, event: AuditEvent) {
        match self.audit.lock().unwrap().append(&event) {
            Ok(()) => {
                self.audit_events.fetch_add(1, Ordering::SeqCst);
            }
            Err(e) => {
                // Never lose a response over an audit I/O error, but say so
                // loudly — the audit trail is a contract.
                eprintln!("punard: FAILED to append audit event: {e}");
            }
        }
    }

    fn actor_of(&self, peer: &Peer) -> AuditActor {
        match lookup_username(&self.cfg.passwd_file, peer.uid) {
            Some(name) => AuditActor::cli_peer(name),
            None => AuditActor::cli_peer_uid(peer.uid),
        }
    }

    /// Full descriptor for a capability: static meta + live observation +
    /// recorded desired state.
    fn describe(&self, cap: &dyn Capability) -> punar_common::CapabilityDescriptor {
        let meta = cap.descriptor();
        let current = cap
            .observe()
            .unwrap_or_else(|_| Value::String("unknown".to_string()));
        let desired = self
            .desired
            .get(meta.capability.as_str())
            .unwrap_or_else(|| current.clone());
        meta.describe(current, desired)
    }

    /// Dispatch a typed request. The method table is closed at the type
    /// level ([`Method`]): unknown names never reach this point — they were
    /// already answered with `unknown_method` by the parse pipeline (SPEC
    /// sections 10, 60: no generic execution method exists, ever).
    fn dispatch(&self, peer: &Peer, request: &Request) -> Result<Value, IpcError> {
        match &request.method {
            Method::Status => Ok(to_value(self.handle_status())),
            Method::CapabilitiesList => {
                let capabilities: Vec<punar_common::CapabilityDescriptor> =
                    self.registry.iter().map(|cap| self.describe(cap)).collect();
                Ok(json!({ "capabilities": capabilities }))
            }
            Method::CapabilitiesGet(params) => self.handle_capabilities_get(params),
            Method::CapabilitiesSet(params) => self.handle_capabilities_set(peer, params),
            Method::AuditTail(params) => self.handle_audit_tail(params),
            Method::Reconcile => self.handle_reconcile(peer),
        }
    }

    fn handle_status(&self) -> StatusResult {
        let hostname = self
            .registry
            .get(crate::backends::hostname::CAPABILITY_ID)
            .and_then(|cap| cap.observe().ok())
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string());
        // In production the boot reconcile runs before the socket opens, so
        // a recorded time always exists; the started_at fallback only
        // matters for embedded/test daemons that skip boot_reconcile.
        let last_reconcile = self
            .last_reconcile
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| self.started_at.clone());
        StatusResult {
            protocol_version: PROTOCOL_VERSION,
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            started_at: self.started_at.clone(),
            device_id: self.device_id.clone(),
            mode: Mode::Personal,
            enrolled: false,
            hostname,
            capabilities_total: self.registry.len() as u64,
            last_reconcile,
            audit: AuditStatus {
                path: self.cfg.audit_path.display().to_string(),
                events: self.audit_events.load(Ordering::SeqCst),
            },
        }
    }

    fn lookup(&self, capability: &punar_common::CapabilityId) -> Result<&dyn Capability, IpcError> {
        self.registry.get(capability.as_str()).ok_or_else(|| {
            IpcError::with_details(
                ErrorCode::NotFound,
                format!(
                    "No capability named {capability:?} is registered on this device.\n\
                     Policy: os default — the M3 registry holds security.firewall, \
                     system.hostname, and time.timezone.\n\
                     Next step: `punarctl capabilities` lists what exists."
                ),
                json!({ "capability": capability.as_str() }),
            )
        })
    }

    fn handle_capabilities_get(&self, params: &CapabilitiesGetParams) -> Result<Value, IpcError> {
        let cap = self.lookup(&params.capability)?;
        Ok(json!({ "descriptor": self.describe(cap) }))
    }

    /// The mutation pipeline (SPEC section 42, M3 subset): validate →
    /// authorize → record desired → apply → verify → audit → respond.
    /// Allow and deny, success and failure are all audited.
    fn handle_capabilities_set(
        &self,
        peer: &Peer,
        params: &CapabilitiesSetParams,
    ) -> Result<Value, IpcError> {
        let cap = self.lookup(&params.capability)?;
        let id = params.capability.as_str();
        cap.validate(&params.desired_state)
            .map_err(|reason| invalid_state(&reason))?;

        let actor = self.actor_of(peer);
        if authorize_mutation(peer) != Decision::Allow {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                "capabilities.set",
                id,
            ));
            let state_hint = match &params.desired_state {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            return Err(IpcError::denied_needs_root(
                id,
                Some(id),
                &format!("sudo punarctl capabilities set {id} {state_hint}"),
            ));
        }

        // Idempotence: already in the desired state → record + audit noop.
        let already = cap
            .observe()
            .ok()
            .is_some_and(|cur| cur == params.desired_state);
        self.desired
            .set(id, params.desired_state.clone())
            .map_err(|e| self.internal(&format!("persisting desired state failed: {e}")))?;
        if already {
            self.log_audit(AuditEvent::capabilities_set(
                &self.device_id,
                &actor,
                &params.capability,
                Decision::Allow,
                AuditOutcome::Noop,
            ));
            return Ok(json!({ "descriptor": self.describe(cap), "changed": false }));
        }

        if let Err(apply_err) = cap.apply(&params.desired_state) {
            self.log_audit(AuditEvent::capabilities_set(
                &self.device_id,
                &actor,
                &params.capability,
                Decision::Allow,
                AuditOutcome::Failure,
            ));
            return Err(IpcError::with_details(
                ErrorCode::ApplyFailed,
                format!(
                    "Applying the new state for {id} failed: {apply_err}.\n\
                     Policy: personal defaults — the change was authorized but the backend could not complete it.\n\
                     Next step: check `journalctl -u punard` and retry."
                ),
                json!({ "capability": id, "stage": "apply" }),
            ));
        }

        match cap.verify(&params.desired_state) {
            Ok(true) => {
                self.log_audit(AuditEvent::capabilities_set(
                    &self.device_id,
                    &actor,
                    &params.capability,
                    Decision::Allow,
                    AuditOutcome::Success,
                ));
                Ok(json!({ "descriptor": self.describe(cap), "changed": true }))
            }
            verify_outcome => {
                let observed = cap
                    .observe()
                    .unwrap_or(Value::String("unknown".to_string()));
                self.log_audit(AuditEvent::capabilities_set(
                    &self.device_id,
                    &actor,
                    &params.capability,
                    Decision::Allow,
                    AuditOutcome::VerifyFailed,
                ));
                let why = match verify_outcome {
                    Err(e) => format!("verification errored: {e}"),
                    _ => "the system did not reach the requested state".to_string(),
                };
                Err(IpcError::with_details(
                    ErrorCode::VerifyFailed,
                    format!(
                        "The change to {id} was applied but could not be verified: {why}.\n\
                         Policy: personal defaults — punard re-observes after every change (SPEC section 42).\n\
                         Next step: `punarctl capabilities get {id}` to inspect the live state."
                    ),
                    json!({
                        "capability": id,
                        "expected": params.desired_state,
                        "observed": observed,
                    }),
                ))
            }
        }
    }

    fn handle_audit_tail(&self, params: &AuditTailParams) -> Result<Value, IpcError> {
        let n = params.effective_n() as usize;
        let tail = tail(&self.cfg.audit_path, n)
            .map_err(|e| self.internal(&format!("reading the audit log failed: {e}")))?;
        if tail.malformed_lines > 0 {
            eprintln!(
                "punard: audit log {} has {} malformed line(s) in the tail window",
                self.cfg.audit_path.display(),
                tail.malformed_lines
            );
        }
        Ok(json!({ "events": tail.events }))
    }

    /// M3 reconcile: re-observe + re-verify, **report drift only** — no
    /// remediation (that, plus the policy merge, is Milestone 4). Root-only
    /// because M4 makes it applying and the authz surface must not loosen.
    fn handle_reconcile(&self, peer: &Peer) -> Result<Value, IpcError> {
        let actor = self.actor_of(peer);
        if authorize_mutation(peer) != Decision::Allow {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                "reconcile",
                RESOURCE_CAPABILITY_REGISTRY,
            ));
            return Err(IpcError::denied_needs_root(
                "the capability registry (reconcile)",
                Some(RESOURCE_CAPABILITY_REGISTRY),
                "sudo punarctl reconcile",
            ));
        }

        let report = self.reconcile_report();
        *self.last_reconcile.lock().unwrap() = Some(report.reconciled_at.clone());
        let outcome = if report.drift_count > 0 {
            AuditOutcome::DriftDetected
        } else {
            AuditOutcome::Clean
        };
        self.log_audit(AuditEvent::reconcile(&self.device_id, &actor, outcome));
        Ok(to_value(report))
    }

    /// Observe + verify every capability against the recorded desired
    /// state; report drift. Shared by boot reconcile and the RPC.
    fn reconcile_report(&self) -> ReconcileResult {
        let mut entries: Vec<ReconcileEntry> = Vec::new();
        let mut drift_count: u64 = 0;
        for cap in self.registry.iter() {
            let meta = cap.descriptor();
            let current = cap
                .observe()
                .unwrap_or_else(|_| Value::String("unknown".to_string()));
            let desired = self
                .desired
                .get(meta.capability.as_str())
                .unwrap_or_else(|| current.clone());
            // `verified` = the verification mechanism itself ran; a drifted
            // state still verifies as Ok(false).
            let verified = cap.verify(&desired).is_ok();
            let drift = current != desired;
            if drift {
                drift_count += 1;
            }
            entries.push(ReconcileEntry {
                capability: meta.capability,
                desired_state: desired,
                current_state: current,
                drift,
                verified,
            });
        }
        ReconcileResult {
            reconciled_at: utc_now_rfc3339(),
            drift_count,
            capabilities: entries,
        }
    }

    fn internal(&self, detail: &str) -> IpcError {
        // Operator detail goes to the journal; the wire gets a generic
        // message (no internals, never secrets — Redacted by construction).
        eprintln!("punard: internal error: {detail}");
        IpcError::new(
            ErrorCode::Internal,
            "punard hit an internal error while handling the request.\n\
             Policy: os default — details are in the system journal, not on the wire.\n\
             Next step: `journalctl -u punard` and retry.",
        )
    }
}

fn to_value<T: serde::Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("result structs serialize infallibly")
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
