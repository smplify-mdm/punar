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

use std::collections::BTreeMap;

use punar_common::audit::{
    AGENT_SESSION_NONE, AuditActor, AuditOutcome, AuditWriter, PROJECT_ID_SYSTEM,
    RESOURCE_CAPABILITY_REGISTRY, count_events, next_event_id, tail,
};
use punar_common::ipc::{
    AuditStatus, AuditTailParams, CapabilitiesGetParams, CapabilitiesSetParams,
    CapabilityCompliance, Classification as WireClassification, ComplianceBlock, ComplianceState,
    EnrollStartParams, EnrollStartResult, EnrollStatusResult, EnrollStopResult, ErrorCode,
    FirstSync, IpcError, LastSync, MAX_REQUEST_LINE_BYTES, Method, Mode, OrgInfo,
    PROTOCOL_VERSION, PolicyEffectiveEntry, PolicyEffectiveResult, PolicyExplainParams,
    PolicyExplainResult, PolicySourceRef, ReconcileEntry, ReconcileResult, RemediationOutcome,
    Request, Response, SERVER_READ_TIMEOUT, StatusResult,
};
use punar_common::time::utc_now_rfc3339;
use punar_common::{AuditEvent, Decision, Redacted};
use punar_policy::{Classification, EffectiveEntry, Provenance};
use serde_json::{Value, json};

use crate::authz::{Peer, PeerSource, authorize_mutation};
use crate::capability::{Capability, Registry};
use crate::enroll::{
    ControlPlaneClient, DEFAULT_CONTROL_PLANE_SOCKET, Enrollment, InventorySources,
    LastSyncRecord, OrgRecord, StatusSummary, UpstreamError, compliance_report_body,
    inventory_body, load_device_token, load_enrollment, save_device_token, save_enrollment,
    write_status_summary,
};
use crate::policy::{
    EffectiveDocument, Layer, compute_effective, load_policy_dir, write_effective_debug_copy,
};
use crate::state::{
    MigrationOutcome, OsDefaultsStore, PreferenceEntry, PreferencesStore, load_or_create_device_id,
    migrate_m3_store,
};
use crate::util::{lookup_gid, lookup_username, random_hex, sha256_hex};

/// Loop protection (SPEC section 42 "avoid remediation loops";
/// docs/development/milestone-4.md section 5): at most this many
/// consecutive failed remediation attempts per capability, then the
/// capability goes `non_compliant` and further attempts are suppressed
/// until the effective value changes, a manual set succeeds, or the daemon
/// restarts.
pub const MAX_REMEDIATION_ATTEMPTS: u32 = 3;

/// Daemon configuration. All paths are injectable so tests run against a
/// tempdir; production values are the documented contract paths.
pub struct DaemonConfig {
    /// [`punar_common::ipc::SOCKET_PATH`] in production.
    pub socket_path: PathBuf,
    /// `/var/lib/punar` — holds `device-id`, the layer stores
    /// (`preferences.json`, `os-defaults.json`), the `policy.d/` drop
    /// directory, and the `effective.json` debug copy.
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
    /// M5: control-plane endpoint (the dev/CI mock's root-only UDS in the
    /// image; a temp socket in host tests). Compiled default
    /// [`DEFAULT_CONTROL_PLANE_SOCKET`], overridable via
    /// `PUNAR_CONTROL_PLANE_SOCKET` / `--control-plane-socket` (resolved
    /// in `main.rs`).
    pub control_plane_socket: PathBuf,
    /// M5: the shell summary file (ipc.md section 9);
    /// `/run/punar/status.json` in production, a state-dir file by
    /// default so embedded/test daemons never write outside their
    /// tempdir.
    pub status_file: PathBuf,
    /// M5 inventory source (injectable for tests).
    pub os_release_path: PathBuf,
    /// M5 inventory source (injectable for tests).
    pub kernel_release_path: PathBuf,
}

impl DaemonConfig {
    pub fn new(socket_path: PathBuf, state_dir: PathBuf, audit_path: PathBuf) -> Self {
        let status_file = state_dir.join("status.json");
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
            control_plane_socket: PathBuf::from(DEFAULT_CONTROL_PLANE_SOCKET),
            status_file,
            os_release_path: PathBuf::from("/etc/os-release"),
            kernel_release_path: PathBuf::from("/proc/sys/kernel/osrelease"),
        }
    }
}

/// Per-capability compliance bookkeeping (SPEC section 52, personal scope)
/// plus the remediation loop-protection counters. In-memory only —
/// recomputed from observation at every reconcile; counters reset on
/// restart by design (docs/development/milestone-4.md section 5).
#[derive(Default)]
struct ComplianceTracker {
    /// Capability id → last computed section 52 state. Populated by the
    /// boot reconcile (which in production runs before the socket opens);
    /// a capability never yet reconciled reads as `unknown`.
    states: BTreeMap<String, ComplianceState>,
    /// Capability id → consecutive failed remediation attempts.
    fail_counts: BTreeMap<String, u32>,
    /// Monotonic count of successful remediations since daemon start.
    drift_remediated_total: u64,
    /// RFC 3339 of the most recent successful remediation.
    last_remediation_at: Option<String>,
}

impl ComplianceTracker {
    fn state_of(&self, capability: &str) -> ComplianceState {
        self.states
            .get(capability)
            .copied()
            .unwrap_or(ComplianceState::Unknown)
    }

    fn block(&self, registry: &Registry) -> ComplianceBlock {
        let capabilities: Vec<CapabilityCompliance> = registry
            .iter()
            .map(|cap| {
                let meta = cap.descriptor();
                let state = self.state_of(meta.capability.as_str());
                CapabilityCompliance {
                    capability: meta.capability,
                    state,
                }
            })
            .collect();
        ComplianceBlock {
            overall: ComplianceState::overall(capabilities.iter().map(|c| c.state)),
            capabilities,
            drift_remediated_total: self.drift_remediated_total,
            last_remediation_at: self.last_remediation_at.clone(),
        }
    }
}

struct Inner {
    cfg: DaemonConfig,
    registry: Registry,
    audit: Mutex<AuditWriter>,
    audit_events: AtomicU64,
    /// Rank-6 layer: persisted first-observation seeds (compiled defaults
    /// stay in the backends).
    os_defaults: OsDefaultsStore,
    /// Rank-5 layer: recorded user preferences.
    preferences: PreferencesStore,
    /// Ranks 1–4 (and stored-rank overrides): policy.d drops. Loaded at
    /// startup; since M5 the **enrollment chain** reloads them live
    /// (`enroll.start` writes + reloads, `enroll.stop` empties). A manual
    /// root file-drop into policy.d still requires a daemon restart —
    /// documented limit (milestone-5.md section 5.1): the authoritative
    /// policy.d writer is the enrollment chain.
    org_layers: Mutex<Vec<Layer>>,
    /// The merged effective document — in-memory truth, recomputed at
    /// startup and on every `capabilities.set`.
    effective: Mutex<EffectiveDocument>,
    tracker: Mutex<ComplianceTracker>,
    device_id: String,
    started_at: String,
    last_reconcile: Mutex<Option<String>>,
    /// M5 enrollment state (mirrors `enrollment.json`); `None` = personal.
    enrollment: Mutex<Option<Enrollment>>,
    /// M5: the device token, [`Redacted`] the moment it exists in memory —
    /// no formatter or serializer can print it (SPEC section 53).
    device_token: Mutex<Option<Redacted<String>>>,
    /// M5 offline queue (SPEC section 55): bounded latest-wins — two
    /// booleans, not a spool. Compliance/inventory are state snapshots; a
    /// missed intermediate report carries nothing the next snapshot does
    /// not supersede.
    pending_compliance: AtomicBool,
    pending_inventory: AtomicBool,
    /// Outcome of the most recent sync attempt, for `enroll.start`'s
    /// `first_sync` result field.
    last_sync_outcome: Mutex<Option<FirstSync>>,
    /// The last tuple written to the ipc.md section 9 status file, so the
    /// file is rewritten only when the summary actually changes.
    status_written: Mutex<Option<StatusSummary>>,
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
    /// Build the daemon: device id, audit log, one-shot M3-store migration
    /// (docs/development/milestone-4.md section 3.3), layer stores with
    /// first-boot OS-default seeding, policy.d load, and the initial
    /// effective-document computation.
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
        let mut audit = audit;
        let mut audit_events = count_events(&cfg.audit_path)?;

        // Layer stores. Migration must run before regular seeding so the
        // M3 values become the seeds (not a fresh observation).
        let os_defaults = OsDefaultsStore::load(&cfg.state_dir.join("os-defaults.json"))?;
        let preferences = PreferencesStore::load(&cfg.state_dir.join("preferences.json"))?;
        if let Some(outcome) = migrate_m3_store(
            &cfg.state_dir,
            &registry,
            &preferences,
            &os_defaults,
            &utc_now_rfc3339(),
        )? {
            log_migration(&outcome);
            let event = migration_event(&device_id, &outcome);
            match audit.append(&event) {
                Ok(()) => audit_events += 1,
                Err(e) => eprintln!("punard: FAILED to append state.migrate audit event: {e}"),
            }
        }

        // First-boot OS-default seeding: capabilities without a compiled
        // default get their first observation persisted so the default is
        // stable across boots (milestone-4.md section 3.1).
        for cap in registry.iter() {
            let id = cap.descriptor().capability.to_string();
            if cap.default_desired().is_some() || os_defaults.get(&id).is_some() {
                continue;
            }
            let seed = cap
                .observe()
                .unwrap_or_else(|_| Value::String("unknown".to_string()));
            os_defaults.seed(&id, seed)?;
        }

        // Org layers (empty directory in the shipped image; loader + tests
        // run against fixtures). Load errors refuse start.
        let loaded = load_policy_dir(&cfg.state_dir.join("policy.d"))?;
        for unmapped in &loaded.unmapped {
            eprintln!(
                "punard: policy.d: no registered capability for {unmapped}; ignored \
                 (its capability lands in a later milestone)"
            );
        }

        let effective = compute_effective(
            &registry,
            &os_defaults,
            &preferences,
            &loaded.layers,
            utc_now_rfc3339(),
        );
        let _ = write_effective_debug_copy(&cfg.state_dir.join("effective.json"), &effective);

        // M5: enrollment persists as plain files (SPEC section 55 — no
        // control-plane liveness involved). A corrupt store refuses start,
        // same posture as the layer stores; a missing token on an enrolled
        // device degrades to unreachable syncs, never to a silent
        // unenroll.
        let enrollment = load_enrollment(&cfg.state_dir.join("enrollment.json"))?;
        let device_token = load_device_token(&cfg.state_dir.join("device-token"))?;
        if enrollment.is_some() && device_token.is_none() {
            eprintln!(
                "punard: enrolled but the device token file is missing; \
                 compliance/inventory sync will fail until re-enrollment"
            );
        }

        let daemon = Daemon {
            inner: Arc::new(Inner {
                cfg,
                registry,
                audit: Mutex::new(audit),
                audit_events: AtomicU64::new(audit_events),
                os_defaults,
                preferences,
                org_layers: Mutex::new(loaded.layers),
                effective: Mutex::new(effective),
                tracker: Mutex::new(ComplianceTracker::default()),
                device_id,
                started_at: utc_now_rfc3339(),
                last_reconcile: Mutex::new(None),
                enrollment: Mutex::new(enrollment),
                device_token: Mutex::new(device_token),
                pending_compliance: AtomicBool::new(false),
                pending_inventory: AtomicBool::new(false),
                last_sync_outcome: Mutex::new(None),
                status_written: Mutex::new(None),
                shutdown: AtomicBool::new(false),
                active: Mutex::new(0),
                slot_freed: Condvar::new(),
            }),
        };
        // First write of the ipc.md section 9 summary file (rewritten by
        // the boot reconcile moments later with computed compliance).
        daemon.inner.publish_status_summary();
        Ok(daemon)
    }

    /// Boot-time reconcile (daemon-initiated: [`AuditActor::daemon`]) —
    /// since M4 the same full section 42 chain as the `reconcile` method:
    /// drift against the effective document is remediated per
    /// classification (in practice the one boot-time apply is
    /// `security.firewall`, whose compiled default is `enabled` while
    /// hostname/timezone seeds equal their first observation). Guarantees
    /// every capability has a section 52 state before the socket opens.
    pub fn boot_reconcile(&self) {
        let inner = &self.inner;
        let report = inner.reconcile_and_remediate(&AuditActor::daemon());
        *inner.last_reconcile.lock().unwrap() = Some(report.reconciled_at.clone());
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
// Migration audit plumbing (docs/development/milestone-4.md section 3.3)
// ---------------------------------------------------------------------------

fn log_migration(outcome: &MigrationOutcome) {
    eprintln!(
        "punard: migrated the M3 desired-state store: {} preference(s) carried, \
         {} OS-default seed(s) recorded, {} value(s) equal to compiled defaults dropped, \
         {} unknown id(s) left in desired.json.pre-m4",
        outcome.migrated_preferences.len(),
        outcome.seeded_defaults.len(),
        outcome.dropped.len(),
        outcome.ignored_unknown.len(),
    );
}

/// The one-shot `state.migrate` audit event (docs/api/ipc.md section 6):
/// daemon-initiated, `resource: "state_store"`, schema-conformant.
fn migration_event(device_id: &str, _outcome: &MigrationOutcome) -> AuditEvent {
    let actor = AuditActor::daemon();
    AuditEvent {
        event_id: next_event_id(),
        timestamp: utc_now_rfc3339(),
        device_id: device_id.to_string(),
        user_id: Some(actor.user_id.clone()),
        agent_session_id: Some(AGENT_SESSION_NONE.to_string()),
        project_id: Some(PROJECT_ID_SYSTEM.to_string()),
        source: actor.source,
        action: "state.migrate".to_string(),
        resource: Some("state_store".to_string()),
        decision: Decision::Allow,
        policy_ids: vec![punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string()],
        result: AuditOutcome::Success.as_str().to_string(),
    }
}

fn wire_classification(classification: Classification) -> WireClassification {
    match classification {
        Classification::AutoRemediate => WireClassification::AutoRemediate,
        Classification::AlertOnly => WireClassification::AlertOnly,
        Classification::ApprovalRequired => WireClassification::ApprovalRequired,
    }
}

fn source_ref(provenance: &Provenance) -> PolicySourceRef {
    PolicySourceRef {
        kind: provenance.kind.as_str().to_string(),
        rank: provenance.rank,
        policy_id: provenance.policy_id.clone(),
        name: provenance.source_name.clone(),
    }
}

/// The wire `org` object for a persisted [`OrgRecord`].
fn org_info(org: &OrgRecord) -> OrgInfo {
    OrgInfo {
        id: org.id.clone(),
        name: org.name.clone(),
        display_name: org.display_name.clone(),
        domain: org.domain.clone(),
    }
}

/// M5 domain-syntax gate for `enroll.start` (contract section 5.9): the
/// value is data handed to `org.discover`, never anything executable, but
/// an obviously-not-a-domain string earns `invalid_params` before any
/// network hop.
fn domain_syntax_ok(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
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
    /// the **effective** desired state from the layered merge (M4 —
    /// registry `desired_state` fields render the effective value).
    fn describe(&self, cap: &dyn Capability) -> punar_common::CapabilityDescriptor {
        let meta = cap.descriptor();
        let current = cap
            .observe()
            .unwrap_or_else(|_| Value::String("unknown".to_string()));
        let desired = self
            .effective_value_of(meta.capability.as_str())
            .unwrap_or_else(|| current.clone());
        meta.describe(current, desired)
    }

    /// The effective value for one capability path, if the document has an
    /// opinion (it always does for registered capabilities — the OS-default
    /// layer covers every one).
    fn effective_value_of(&self, path: &str) -> Option<Value> {
        self.effective
            .lock()
            .unwrap()
            .get(path)
            .map(|entry| entry.value.clone())
    }

    /// Recompute the effective document from the layers (startup, every
    /// `capabilities.set`, and the M5 enrollment transitions) and refresh
    /// the debug copy.
    fn recompute_effective(&self) {
        let doc = {
            let org_layers = self.org_layers.lock().unwrap();
            compute_effective(
                &self.registry,
                &self.os_defaults,
                &self.preferences,
                &org_layers,
                utc_now_rfc3339(),
            )
        };
        let _ = write_effective_debug_copy(&self.cfg.state_dir.join("effective.json"), &doc);
        *self.effective.lock().unwrap() = doc;
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
            Method::PolicyEffective => Ok(to_value(self.handle_policy_effective())),
            Method::PolicyExplain(params) => self.handle_policy_explain(params),
            Method::EnrollStart(params) => self.handle_enroll_start(peer, params),
            Method::EnrollStatus => Ok(to_value(self.handle_enroll_status())),
            Method::EnrollStop => self.handle_enroll_stop(peer),
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
        // M5 (contract section 5.1): enrollment surfaces additively —
        // `mode: managed`, `enrolled: true`, and the optional `org` object
        // while enrolled; the personal shape stays byte-identical to M3.
        let org: Option<OrgInfo> = self
            .enrollment
            .lock()
            .unwrap()
            .as_ref()
            .map(|e| org_info(&e.org));
        let enrolled = org.is_some();
        StatusResult {
            protocol_version: PROTOCOL_VERSION,
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            started_at: self.started_at.clone(),
            device_id: self.device_id.clone(),
            mode: if enrolled {
                Mode::Managed
            } else {
                Mode::Personal
            },
            enrolled,
            hostname,
            capabilities_total: self.registry.len() as u64,
            last_reconcile,
            audit: AuditStatus {
                path: self.cfg.audit_path.display().to_string(),
                events: self.audit_events.load(Ordering::SeqCst),
            },
            // M4: personal-scope section 52 compliance — always present
            // since M4 (contract section 5.1). States are computed at
            // reconcile time; the boot reconcile runs before the socket
            // opens in production.
            compliance: Some(self.tracker.lock().unwrap().block(&self.registry)),
            org,
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

    /// The mutation pipeline (SPEC section 42; contract section 5.4 M4
    /// semantics): validate → authorize → **record UserPreference entry** →
    /// recompute the effective document → apply the **effective** value →
    /// verify → audit → respond. In personal mode nothing outranks a user
    /// preference, so effective == requested and the result is
    /// byte-identical to M3. Allow and deny, success and failure are all
    /// audited; `policy_ids` cites the winning source.
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

        // Record the request as a User Preference layer entry (rank 5) and
        // recompute the merge. The preference is recorded even when a
        // higher layer overrides it — it becomes effective the moment the
        // override goes away (SPEC section 39).
        self.preferences
            .set(
                id,
                PreferenceEntry {
                    value: params.desired_state.clone(),
                    set_at: utc_now_rfc3339(),
                    set_by: actor.user_id.clone(),
                },
            )
            .map_err(|e| self.internal(&format!("persisting the preference failed: {e}")))?;
        self.recompute_effective();

        let (effective_value, winning_policy_id) = {
            let doc = self.effective.lock().unwrap();
            let entry = doc
                .get(id)
                .expect("registered capability has an effective entry");
            (entry.value.clone(), entry.provenance.policy_id.clone())
        };
        let overridden = effective_value != params.desired_state;
        let audited = |outcome: AuditOutcome| {
            let mut event = AuditEvent::capabilities_set(
                &self.device_id,
                &actor,
                &params.capability,
                Decision::Allow,
                outcome,
            );
            event.policy_ids = vec![winning_policy_id.clone()];
            event
        };
        // Optional M4 result fields — emitted only when a higher layer
        // wins; personal-mode results stay byte-identical to M3.
        let extend = |mut result: Value| {
            if !overridden {
                return result;
            }
            if let Some(map) = result.as_object_mut() {
                map.insert("overridden".to_string(), json!(true));
                map.insert("effective_state".to_string(), effective_value.clone());
            }
            result
        };

        // Idempotence: already in the effective state → audit noop.
        let already = cap.observe().ok().is_some_and(|cur| cur == effective_value);
        if already {
            self.log_audit(audited(AuditOutcome::Noop));
            self.mark_settled(id);
            return Ok(extend(
                json!({ "descriptor": self.describe(cap), "changed": false }),
            ));
        }

        if let Err(apply_err) = cap.apply(&effective_value) {
            self.log_audit(audited(AuditOutcome::Failure));
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

        match cap.verify(&effective_value) {
            Ok(true) => {
                self.log_audit(audited(AuditOutcome::Success));
                self.mark_settled(id);
                Ok(extend(
                    json!({ "descriptor": self.describe(cap), "changed": true }),
                ))
            }
            verify_outcome => {
                let observed = cap
                    .observe()
                    .unwrap_or(Value::String("unknown".to_string()));
                self.log_audit(audited(AuditOutcome::VerifyFailed));
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
                        "expected": effective_value,
                        "observed": observed,
                    }),
                ))
            }
        }
    }

    /// A manual set reached (or confirmed) the effective state: the
    /// capability is compliant, and the loop-protection counter resets —
    /// one of the documented suppression exits (contract section 5.6).
    fn mark_settled(&self, capability: &str) {
        let mut tracker = self.tracker.lock().unwrap();
        tracker
            .states
            .insert(capability.to_string(), ComplianceState::Compliant);
        tracker.fail_counts.remove(capability);
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

    /// M4 reconcile (contract section 5.6): one synchronous pass of the
    /// full SPEC section 42 chain — the semantic change M3 pre-announced by
    /// making the method root-only ("M4 will make it applying, and the
    /// authz surface must not loosen later").
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

        let report = self.reconcile_and_remediate(&actor);
        *self.last_reconcile.lock().unwrap() = Some(report.reconciled_at.clone());
        Ok(to_value(report))
    }

    /// The SPEC section 42 chain, one synchronous pass (shared by boot
    /// reconcile, the timer-driven `punarctl reconcile`, and manual calls):
    /// observe → normalize (the backends' observers return canonical
    /// values) → load (the layered merge, already computed) → diff →
    /// policy (SPEC section 43 classify, data in the effective document) →
    /// plan (skip loop-protected capabilities) → apply → verify → audit
    /// (one event per remediation attempt + the M3 summary event) →
    /// compliance (SPEC section 52, personal scope).
    ///
    /// M3 result fields keep their M3 meaning: `drift` / `drift_count`
    /// describe the **pre-remediation** observation.
    fn reconcile_and_remediate(&self, actor: &AuditActor) -> ReconcileResult {
        let effective: BTreeMap<String, EffectiveEntry<Value>> =
            self.effective.lock().unwrap().entries.clone();
        let mut entries: Vec<ReconcileEntry> = Vec::new();
        let mut drift_count: u64 = 0;
        let mut remediated_count: u64 = 0;

        for cap in self.registry.iter() {
            let meta = cap.descriptor();
            let id = meta.capability.to_string();
            let observation = cap.observe();
            let current = observation
                .as_ref()
                .cloned()
                .unwrap_or_else(|_| Value::String("unknown".to_string()));
            let entry = effective.get(&id);
            let desired = entry
                .map(|e| e.value.clone())
                .unwrap_or_else(|| current.clone());
            let classification = entry
                .map(|e| e.classification)
                .unwrap_or(Classification::AutoRemediate);
            let policy_id = entry
                .map(|e| e.provenance.policy_id.clone())
                .unwrap_or_else(|| punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string());
            let exception_source = entry.is_some_and(|e| {
                e.provenance.kind == punar_policy::SourceKind::TemporaryApprovedException
            });
            // `verified` = the verification mechanism itself ran; a drifted
            // state still verifies as Ok(false).
            let verified = cap.verify(&desired).is_ok();
            let drift = current != desired;
            if drift {
                drift_count += 1;
            }

            let (remediation, state) = self.plan_and_remediate(
                cap,
                &id,
                &desired,
                drift,
                observation.is_ok(),
                classification,
                exception_source,
                &policy_id,
                actor,
                &mut remediated_count,
            );
            self.tracker.lock().unwrap().states.insert(id, state);

            entries.push(ReconcileEntry {
                capability: meta.capability,
                desired_state: desired,
                current_state: current,
                drift,
                verified,
                classification: Some(wire_classification(classification)),
                remediation: Some(remediation),
            });
        }

        // The unchanged M3 summary event (pre-remediation drift).
        let outcome = if drift_count > 0 {
            AuditOutcome::DriftDetected
        } else {
            AuditOutcome::Clean
        };
        self.log_audit(AuditEvent::reconcile(&self.device_id, actor, outcome));

        let compliance = self.tracker.lock().unwrap().block(&self.registry);
        ReconcileResult {
            reconciled_at: utc_now_rfc3339(),
            drift_count,
            capabilities: entries,
            remediated_count: Some(remediated_count),
            compliance: Some(compliance),
        }
    }

    /// Steps 6–10 of the chain for one capability: plan (loop protection),
    /// apply, verify, audit the attempt, and compute the SPEC section 52
    /// state. Returns `(remediation, compliance state)`.
    #[allow(clippy::too_many_arguments)]
    fn plan_and_remediate(
        &self,
        cap: &dyn Capability,
        id: &str,
        desired: &Value,
        drift: bool,
        observed_ok: bool,
        classification: Classification,
        exception_source: bool,
        policy_id: &str,
        actor: &AuditActor,
        remediated_count: &mut u64,
    ) -> (RemediationOutcome, ComplianceState) {
        if !observed_ok {
            // Observe failed: nothing trustworthy to diff against.
            return (RemediationOutcome::None, ComplianceState::Unknown);
        }
        if !drift {
            // Observed == effective is a successful verification of the
            // effective state: the loop-protection counter resets (even a
            // path won by an exception source is compliant while the
            // observed state matches the effective value).
            self.tracker.lock().unwrap().fail_counts.remove(id);
            return (RemediationOutcome::None, ComplianceState::Compliant);
        }
        match classification {
            // approval_required classifies as such but behaves as
            // alert_only until M9 delivers approvals (contract section 5.6).
            Classification::AlertOnly | Classification::ApprovalRequired => {
                let state = if exception_source {
                    ComplianceState::Exception
                } else {
                    ComplianceState::NonCompliant
                };
                (RemediationOutcome::AlertOnly, state)
            }
            Classification::AutoRemediate => {
                let fail_count = self
                    .tracker
                    .lock()
                    .unwrap()
                    .fail_counts
                    .get(id)
                    .copied()
                    .unwrap_or(0);
                if fail_count >= MAX_REMEDIATION_ATTEMPTS {
                    // Suppressed until the effective value changes, a
                    // manual set succeeds, or the daemon restarts. Note:
                    // flapping never trips this — every successful cycle
                    // resets the counter; the audit trail's repeated
                    // success events are the record of contested ownership.
                    return (
                        RemediationOutcome::Suppressed,
                        ComplianceState::NonCompliant,
                    );
                }
                let attempt = match cap.apply(desired) {
                    Err(e) => {
                        eprintln!("punard: remediation apply for {id} failed: {e}");
                        Err(RemediationOutcome::ApplyFailed)
                    }
                    Ok(()) => match cap.verify(desired) {
                        Ok(true) => Ok(()),
                        Ok(false) => Err(RemediationOutcome::VerifyFailed),
                        Err(e) => {
                            eprintln!("punard: remediation verify for {id} errored: {e}");
                            Err(RemediationOutcome::VerifyFailed)
                        }
                    },
                };
                match attempt {
                    Ok(()) => {
                        let now = utc_now_rfc3339();
                        {
                            let mut tracker = self.tracker.lock().unwrap();
                            tracker.fail_counts.remove(id);
                            tracker.drift_remediated_total += 1;
                            tracker.last_remediation_at = Some(now);
                        }
                        *remediated_count += 1;
                        self.log_audit(self.remediation_event(actor, id, policy_id, "success"));
                        (RemediationOutcome::Applied, ComplianceState::Compliant)
                    }
                    Err(failure) => {
                        let attempts = fail_count + 1;
                        self.tracker
                            .lock()
                            .unwrap()
                            .fail_counts
                            .insert(id.to_string(), attempts);
                        if attempts >= MAX_REMEDIATION_ATTEMPTS {
                            // The exhausting attempt's audit event carries
                            // the transition result (contract section 5.6:
                            // one attempts_exhausted event, emitted on the
                            // transition; the attempt kind is preserved in
                            // the reconcile result's `remediation` field).
                            self.log_audit(self.remediation_event(
                                actor,
                                id,
                                policy_id,
                                "attempts_exhausted",
                            ));
                            (failure, ComplianceState::NonCompliant)
                        } else {
                            let result = match failure {
                                RemediationOutcome::ApplyFailed => "apply_failed",
                                _ => "verify_failed",
                            };
                            self.log_audit(self.remediation_event(actor, id, policy_id, result));
                            (failure, ComplianceState::Remediating)
                        }
                    }
                }
            }
        }
    }

    /// One schema-conformant audit event per remediation attempt
    /// (docs/api/ipc.md sections 5.6, 6).
    fn remediation_event(
        &self,
        actor: &AuditActor,
        capability: &str,
        policy_id: &str,
        result: &str,
    ) -> AuditEvent {
        AuditEvent {
            event_id: next_event_id(),
            timestamp: utc_now_rfc3339(),
            device_id: self.device_id.clone(),
            user_id: Some(actor.user_id.clone()),
            agent_session_id: Some(AGENT_SESSION_NONE.to_string()),
            project_id: Some(PROJECT_ID_SYSTEM.to_string()),
            source: actor.source,
            action: "reconcile.remediate".to_string(),
            resource: Some(capability.to_string()),
            decision: Decision::Allow,
            policy_ids: vec![policy_id.to_string()],
            result: result.to_string(),
        }
    }

    /// `policy.effective` (contract section 5.7): the merged document with
    /// per-path provenance and compliance. Read, not audited.
    fn handle_policy_effective(&self) -> PolicyEffectiveResult {
        let doc = self.effective.lock().unwrap().clone();
        let tracker = self.tracker.lock().unwrap();
        let entries = doc
            .entries
            .iter()
            .map(|(path, entry)| PolicyEffectiveEntry {
                path: path.clone(),
                effective_value: entry.value.clone(),
                source: source_ref(&entry.provenance),
                user_override_permitted: entry.user_override_permitted,
                compliance_state: tracker.state_of(path),
            })
            .collect();
        PolicyEffectiveResult {
            computed_at: doc.computed_at,
            entries,
        }
    }

    /// `policy.explain` (contract section 5.8): one effective entry —
    /// exactly the SPEC section 40 information set. Unknown path →
    /// `not_found`.
    fn handle_policy_explain(&self, params: &PolicyExplainParams) -> Result<Value, IpcError> {
        let path = params.path.as_str();
        let entry = self.effective.lock().unwrap().get(path).cloned();
        let Some(entry) = entry else {
            return Err(IpcError::with_details(
                ErrorCode::NotFound,
                format!(
                    "No effective policy entry exists for {path:?} on this device.\n\
                     Policy: personal defaults — the effective document covers the \
                     registered capabilities.\n\
                     Next step: `punarctl policy effective` lists every governed path."
                ),
                json!({ "param": "path", "path": path }),
            ));
        };
        let result = PolicyExplainResult {
            effective_value: entry.value.clone(),
            source: source_ref(&entry.provenance),
            user_override_permitted: entry.user_override_permitted,
            compliance_state: self.tracker.lock().unwrap().state_of(path),
        };
        Ok(to_value(result))
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
