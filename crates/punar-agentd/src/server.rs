//! The `punar-agentd` daemon: UDS NDJSON server for the closed `agents.*`
//! method table (docs/api/ipc.md section 10), the registry it serves, the
//! detection pass behind it, and the `/run/punar/agents.json` summary it
//! publishes (section 11).
//!
//! # Same mechanics as punard, different table
//!
//! Framing, envelope, versioning, timeouts, error codes and the
//! bind-before-listen permission dance are `punar_common::ipc` and the M3
//! `punard` pattern verbatim — a second socket, not a second protocol.
//! Threading is the same frugal shape: no async runtime, a std accept loop,
//! one thread per connection, a hard connection cap, and per-connection
//! memory bounded by the 4096-byte line limit (PERFORMANCE_BUDGETS.md
//! section 1.2; the services RSS gate now sums both daemons' cgroups).
//!
//! # What this daemon will not do
//!
//! There is no exec, shell, or script method here either (spec sections 10,
//! 60 — permanent). Nothing on this socket takes a command line, and
//! nothing in the registry stores one.
//!
//! # No background work
//!
//! Between requests the daemon does nothing at all: no timer, no reconcile
//! nudge, no `/proc` polling (spec section 6.3). A detection pass runs when
//! `agents.scan` asks for one, or when `agents.list` finds the previous
//! pass older than [`punar_common::agent::SCAN_STALE_AFTER_SECS`].
//! Continuous detection is Milestone 10's deliverable and is not quietly
//! shipped here.

use std::collections::HashSet;
use std::io::{self, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use punar_common::agent::{
    ADAPTERS_DIR, AGENTS_SUMMARY_PATH, AgentClassification, AgentMethod, AgentRequest, AgentStatus,
    AgentsEndParams, AgentsEndResult, AgentsGetParams, AgentsGetResult, AgentsListResult,
    AgentsRegisterParams, AgentsRegisterResult, REGISTRY_JSONL_PATH, RegistryRecord,
    SCAN_STALE_AFTER_SECS, SUSPECTED_SIGNATURES_PATH, SessionRow, agent_name_ok, session_id_ok,
    validate_registry_record,
};
use punar_common::audit::{AGENT_SESSION_NONE, AuditWriter, PROJECT_ID_SYSTEM};
use punar_common::ipc::{
    ErrorCode, IpcError, LineRead, MAX_REQUEST_LINE_BYTES, Response, SERVER_READ_TIMEOUT,
    read_line_bounded,
};
use punar_common::time::utc_now_rfc3339;
use punar_common::{AuditEvent, Decision, PrincipalKind};
use serde_json::{Value, json};

use crate::adapters::SignatureSet;
use crate::authz::{Peer, PeerSource, may_act_on_session};
use crate::detect::Detector;
use crate::proc::{ProcRoot, scope_unit_name};
use crate::registry::{Detection, Registry, RegistryStore, Session, replay_into};
use crate::summary::CitationSources;
use crate::util::{lookup_gid, username_or_uid};

/// `user_id` on daemon-initiated audit events (the punard `USER_ID_DAEMON`
/// convention, for the second daemon).
pub const USER_ID_AGENTD: &str = "punar-agentd";

/// Audit actions this daemon emits (docs/api/ipc.md section 10.4).
pub const ACTION_REGISTER: &str = "agents.register";
pub const ACTION_END: &str = "agents.end";
pub const ACTION_REAP: &str = "agents.reap";
pub const ACTION_SCAN: &str = "agents.scan";

/// Audit `result` words added to the open set by M7: a detection appeared,
/// a detection disappeared, a crashed session was closed.
pub const RESULT_DETECTED: &str = "detected";
pub const RESULT_CLEARED: &str = "cleared";
pub const RESULT_REAPED: &str = "reaped";

/// The facts behind one audit event. A struct rather than eight
/// positional arguments so a call site cannot silently swap `agent` and
/// `project` — the audit trail is a contract, and this is the shape
/// docs/api/ipc.md section 6 pins.
struct EventFacts<'a> {
    /// Dotted action name, e.g. `agents.register`.
    action: &'a str,
    /// Audit `resource`: the agent product name.
    agent: &'a str,
    /// The real `agt_` id — the sentinel's purpose, fulfilled.
    session_id: &'a str,
    project: &'a str,
    decision: Decision,
    result: &'a str,
}

/// Daemon configuration. Every path is injectable so tests run entirely
/// inside a tempdir — including `/proc`, which is why classification and
/// detection are testable at all.
#[derive(Debug, Clone)]
pub struct AgentdConfig {
    /// [`punar_common::agent::AGENTD_SOCKET_PATH`] in production.
    pub socket_path: PathBuf,
    /// `/var/lib/punar` — shared with punard (this daemon only *reads*
    /// punard's `device-id` and `enrollment.json`) and the parent of the
    /// registry's own `agents/` directory.
    pub state_dir: PathBuf,
    /// Append-only registry transition log.
    pub registry_path: PathBuf,
    /// The **shared** audit trail (docs/api/ipc.md section 10.4).
    pub audit_path: PathBuf,
    /// Staged `agent-definition.json` documents.
    pub adapters_dir: PathBuf,
    /// Suspected-signature heuristic input.
    pub suspected_path: PathBuf,
    /// The panel's summary file (section 11).
    pub agents_file: PathBuf,
    /// punard's section 9 status file — read for the enrolled flag.
    pub status_file: PathBuf,
    /// `/proc` in production, a fixture tree in tests.
    pub proc_root: PathBuf,
    /// Group granted socket access (`punar`).
    pub group: String,
    /// `/etc/group` (injectable).
    pub group_file: PathBuf,
    /// `/etc/passwd` (injectable).
    pub passwd_file: PathBuf,
    pub peer_source: PeerSource,
    pub max_connections: usize,
    pub io_timeout: Duration,
    /// How stale the last detection pass may be before `agents.list`
    /// runs one first.
    pub scan_stale_after: Duration,
}

impl AgentdConfig {
    /// Production defaults for everything except the three paths a test (or
    /// a flag) overrides. Test-safe by construction: derived paths live
    /// under `state_dir`, so an embedded daemon never writes to `/run`.
    pub fn new(socket_path: PathBuf, state_dir: PathBuf, audit_path: PathBuf) -> AgentdConfig {
        AgentdConfig {
            socket_path,
            registry_path: state_dir.join("agents/registry.jsonl"),
            agents_file: state_dir.join("agents.json"),
            status_file: state_dir.join("status.json"),
            state_dir,
            audit_path,
            adapters_dir: PathBuf::from(ADAPTERS_DIR),
            suspected_path: PathBuf::from(SUSPECTED_SIGNATURES_PATH),
            proc_root: PathBuf::from("/proc"),
            group: "punar".to_string(),
            group_file: PathBuf::from("/etc/group"),
            passwd_file: PathBuf::from("/etc/passwd"),
            peer_source: PeerSource::SoPeercred,
            max_connections: 16,
            io_timeout: SERVER_READ_TIMEOUT,
            scan_stale_after: Duration::from_secs(SCAN_STALE_AFTER_SECS),
        }
    }

    /// The production contract paths (docs/api/ipc.md sections 10.1, 11).
    pub fn production() -> AgentdConfig {
        let mut cfg = AgentdConfig::new(
            PathBuf::from(punar_common::agent::AGENTD_SOCKET_PATH),
            PathBuf::from("/var/lib/punar"),
            PathBuf::from(punar_common::audit::AUDIT_LOG_PATH),
        );
        cfg.registry_path = PathBuf::from(REGISTRY_JSONL_PATH);
        cfg.agents_file = PathBuf::from(AGENTS_SUMMARY_PATH);
        cfg.status_file = PathBuf::from("/run/punar/status.json");
        cfg
    }
}

struct Inner {
    cfg: AgentdConfig,
    registry: Mutex<Registry>,
    store: RegistryStore,
    detector: Detector,
    citation: CitationSources,
    audit: Mutex<AuditWriter>,
    /// punard's device id, read lazily: agentd never creates it (punard
    /// owns that file), and a daemon started before punard's first boot
    /// picks it up on the next audit rather than caching a sentinel
    /// forever.
    device_id: Mutex<Option<String>>,
    /// Monotonic time of the last detection pass (staleness gate) and the
    /// wall-clock stamp reported with it.
    last_scan: Mutex<(Option<Instant>, String)>,
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
    /// Build the daemon: load signature data, replay `registry.jsonl`
    /// (closing sessions whose processes are gone), run the first detection
    /// pass, and publish the first `agents.json` — all before the socket
    /// opens, so the very first `agents.list` answers a true view.
    pub fn new(cfg: AgentdConfig) -> io::Result<Daemon> {
        std::fs::create_dir_all(&cfg.state_dir)?;
        if let Some(parent) = cfg.registry_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if let Some(parent) = cfg.audit_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let audit = AuditWriter::open(&cfg.audit_path)?;
        if let Some(gid) = lookup_gid(&cfg.group_file, &cfg.group) {
            // Group ownership of the shared trail (root:punar) is the
            // daemons' job; meaningful only as root, harmless otherwise.
            let _ = std::os::unix::fs::chown(&cfg.audit_path, Some(0), Some(gid));
        }

        let signatures = SignatureSet::load(&cfg.adapters_dir, &cfg.suspected_path);
        for warning in &signatures.warnings {
            eprintln!("punar-agentd: {warning}");
        }
        let proc = ProcRoot::new(&cfg.proc_root);
        let store = RegistryStore::new(&cfg.registry_path);
        let (registry, replay) = replay_into(&store, &proc, &cfg.passwd_file)?;
        if !replay.carried.is_empty() || !replay.reaped.is_empty() || replay.skipped_lines > 0 {
            eprintln!(
                "punar-agentd: registry replay carried {} live session(s), closed {} whose \
                 process is gone, skipped {} unreadable line(s)",
                replay.carried.len(),
                replay.reaped.len(),
                replay.skipped_lines
            );
        }
        let detector = Detector::new(proc, signatures, &cfg.passwd_file);
        let citation = CitationSources {
            status_file: cfg.status_file.clone(),
            enrollment_file: cfg.state_dir.join("enrollment.json"),
        };

        let inner = Arc::new(Inner {
            registry: Mutex::new(registry),
            store,
            detector,
            citation,
            audit: Mutex::new(audit),
            device_id: Mutex::new(None),
            last_scan: Mutex::new((None, utc_now_rfc3339())),
            shutdown: AtomicBool::new(false),
            active: Mutex::new(0),
            slot_freed: Condvar::new(),
            cfg,
        });
        // First pass + first publish: the panel has a truthful file to read
        // before anything connects.
        inner.scan_now();
        Ok(Daemon { inner })
    }

    /// Bind the socket (stale files are unlinked), set permissions
    /// **before** `listen()` (`0660 root:punar`; chown best-effort when
    /// unprivileged), then start the accept loop.
    pub fn spawn(self) -> io::Result<DaemonHandle> {
        let inner = self.inner;
        let listener = bind_with_perms(
            &inner.cfg.socket_path,
            lookup_gid(&inner.cfg.group_file, &inner.cfg.group),
        )?;
        let accept_inner = Arc::clone(&inner);
        let accept_thread = std::thread::Builder::new()
            .name("punar-agentd-accept".to_string())
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

    /// Request shutdown, wake the accept loop, join it, remove the socket.
    pub fn stop(self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner.slot_freed.notify_all();
        let _ = UnixStream::connect(&self.inner.cfg.socket_path);
        let _ = self.accept_thread.join();
        let _ = std::fs::remove_file(&self.inner.cfg.socket_path);
    }
}

/// socket + bind + perms + listen, in that order (docs/api/ipc.md section
/// 1.2, applied to the sibling socket by section 10.1). rustix keeps this
/// free of `unsafe`; `UnixListener::bind` would listen before permissions
/// could be fixed.
fn bind_with_perms(path: &Path, gid: Option<u32>) -> io::Result<UnixListener> {
    use rustix::net::{AddressFamily, SocketType, bind, listen, socket};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
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
        let _ = std::os::unix::fs::chown(path, Some(0), Some(gid));
    }
    listen(&fd, 16)?;
    Ok(UnixListener::from(fd))
}

fn accept_loop(inner: Arc<Inner>, listener: UnixListener) {
    loop {
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
                    .name("punar-agentd-conn".to_string())
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
                eprintln!("punar-agentd: accept failed: {e}");
            }
        }
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
            eprintln!("punar-agentd: could not read peer credentials: {e}");
            return;
        }
    };
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("punar-agentd: could not clone connection stream: {e}");
            return;
        }
    };
    let mut reader = BufReader::with_capacity(MAX_REQUEST_LINE_BYTES, reader_stream);

    loop {
        match read_line_bounded(&mut reader, MAX_REQUEST_LINE_BYTES) {
            Ok(LineRead::Eof) => break,
            Ok(LineRead::TooLong) => {
                let err = IpcError::new(
                    ErrorCode::MalformedRequest,
                    format!(
                        "The request line exceeded the {MAX_REQUEST_LINE_BYTES}-byte limit.\n\
                         Policy: os default — punar-agentd bounds request size \
                         (docs/api/ipc.md sections 2, 10.1).\n\
                         Next step: no agents.* request needs more; use punarctl."
                    ),
                );
                let _ = write_response(&mut stream, &Response::error(None, err));
                break;
            }
            Ok(LineRead::Line(line)) => match AgentRequest::parse_json_line(&line) {
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
            Err(_) => break, // timeout or I/O error: close (ipc.md section 2)
        }
    }
}

impl Inner {
    fn dispatch(&self, peer: &Peer, request: &AgentRequest) -> Result<Value, IpcError> {
        match &request.method {
            AgentMethod::List => Ok(self.handle_list()),
            AgentMethod::Get(params) => self.handle_get(params),
            AgentMethod::Register(params) => self.handle_register(peer, params),
            AgentMethod::End(params) => self.handle_end(peer, params),
            AgentMethod::Scan => Ok(self.handle_scan()),
        }
    }

    // -- reads ---------------------------------------------------------

    fn handle_list(&self) -> Value {
        self.scan_if_stale();
        to_value(self.list_result())
    }

    fn handle_scan(&self) -> Value {
        self.scan_now();
        to_value(self.list_result())
    }

    fn list_result(&self) -> AgentsListResult {
        // Read the scan stamp first and let its guard go: no code path
        // ever holds `last_scan` while taking `registry`, so taking them
        // in this order can never deadlock against a concurrent request.
        let scanned_at = self.last_scan.lock().unwrap().1.clone();
        let registry = self.registry.lock().unwrap();
        AgentsListResult {
            scanned_at,
            sessions: registry
                .sessions()
                .map(|session| session.record.clone())
                .collect(),
            detections: registry.detections().map(Detection::row).collect(),
        }
    }

    fn handle_get(&self, params: &AgentsGetParams) -> Result<Value, IpcError> {
        let registry = self.registry.lock().unwrap();
        let row: Option<SessionRow> = registry
            .session(&params.session_id)
            .map(Session::row)
            .or_else(|| registry.detection(&params.session_id).map(Detection::row));
        match row {
            Some(session) => Ok(to_value(AgentsGetResult { session })),
            None => Err(IpcError::with_details(
                ErrorCode::NotFound,
                format!(
                    "No agent session or detection with id {:?} is known to this registry.\n\
                     Next step: run `punarctl agents list` to see the current sessions.",
                    params.session_id
                ),
                json!({ "session_id": params.session_id }),
            )),
        }
    }

    // -- mutations -----------------------------------------------------

    /// `agents.register` — the managed-launch registration. Everything the
    /// launcher *claims* about attribution is verified here (spec section
    /// 22); `user`, `started_at`, and `classification` are the daemon's to
    /// decide and are never read from params.
    fn handle_register(
        &self,
        peer: &Peer,
        params: &AgentsRegisterParams,
    ) -> Result<Value, IpcError> {
        if !session_id_ok(&params.session_id) {
            return Err(invalid_params(format!(
                "session_id {:?} must match ^agt_[A-Za-z0-9]+$ (the launcher mints it).",
                params.session_id
            )));
        }
        if !agent_name_ok(&params.agent) {
            return Err(invalid_params(format!(
                "agent {:?} must match ^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$.",
                params.agent
            )));
        }
        if self.registry.lock().unwrap().contains(&params.session_id) {
            return Err(invalid_params(format!(
                "session_id {:?} is already in use; every managed session gets a fresh id.",
                params.session_id
            )));
        }

        let proc = self.detector.proc();
        let Some(entry) = proc.entry(params.process_id) else {
            return Err(invalid_params(format!(
                "process {} does not exist; register after the agent process is running.",
                params.process_id
            )));
        };

        // 1. Peer credentials: the caller must own the process it claims
        //    (root exempt). This is the check that stops one user
        //    registering another user's — or root's — process as their
        //    agent session.
        let process_uid = entry.uid;
        if !peer.is_root() && process_uid != Some(peer.uid) {
            self.audit_denial(peer, params);
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "Registering process {} was denied: it is not owned by the calling user.\n\
                     Policy: os default — agent attribution is verified against the process \
                     owner, never taken from the request (spec section 22).\n\
                     Next step: launch the agent with `punar-env agent <name>`, which \
                     registers the session it started.",
                    params.process_id
                ),
                json!({ "process_id": params.process_id }),
            ));
        }

        // 2. Attribution: the cgroup proves managed launch. A known-agent
        //    signature outside a managed scope is an honest downgrade to
        //    `observed`, reported back so the launcher can say so. Anything
        //    else means the launch path is broken — nothing to pretend
        //    about.
        let (classification, scope_unit) = if entry.in_scope_of(&params.session_id) {
            (
                AgentClassification::Managed,
                Some(scope_unit_name(&params.session_id)),
            )
        } else if self.detector.matches_known_agent(&entry) {
            (AgentClassification::Observed, None)
        } else {
            return Err(invalid_params(format!(
                "process {} is neither inside its session scope ({}) nor recognizable as a \
                 known agent, so it cannot be registered. The managed launch path creates \
                 the scope before registering.",
                params.process_id,
                scope_unit_name(&params.session_id)
            )));
        };

        let user = process_uid
            .or(Some(peer.uid))
            .map(|uid| username_or_uid(&self.cfg.passwd_file, uid))
            .unwrap_or_else(|| format!("uid:{}", peer.uid));
        let record = RegistryRecord {
            session_id: params.session_id.clone(),
            agent: params.agent.clone(),
            version: params.version.clone(),
            process_id: params.process_id,
            user,
            project: params.project.clone(),
            environment: params.environment.clone(),
            status: AgentStatus::Active,
            classification,
            started_at: utc_now_rfc3339(),
        };
        if let Err(violations) = validate_registry_record(&record) {
            return Err(invalid_params(format!(
                "the resulting registry record would violate \
                 schemas/ai-agent/registry-record.json: {violations:?}"
            )));
        }
        // Persist before answering: a session the caller believes is
        // registered must survive a daemon restart.
        if let Err(e) = self.store.append(&record) {
            return Err(IpcError::new(
                ErrorCode::Internal,
                format!(
                    "The session could not be recorded in the registry log: {e}\n\
                     Next step: check /var/lib/punar/agents and the daemon journal."
                ),
            ));
        }

        let session = Session {
            record,
            scope_unit,
            executable: entry.exe.clone(),
            authority: Some(params.authority.clone()),
            owner_uid: process_uid.or(Some(peer.uid)),
        };
        let row = session.row();
        self.registry.lock().unwrap().insert_session(session);
        self.audit(self.human_event(
            peer,
            EventFacts {
                action: ACTION_REGISTER,
                agent: &params.agent,
                session_id: &params.session_id,
                project: &params.project,
                decision: Decision::Allow,
                result: "success",
            },
        ));
        self.publish_summary();
        Ok(to_value(AgentsRegisterResult {
            session: row,
            classification,
        }))
    }

    /// `agents.end` — the owner (or root) marks a session ended.
    fn handle_end(&self, peer: &Peer, params: &AgentsEndParams) -> Result<Value, IpcError> {
        let (owner_uid, agent, project, status) = {
            let registry = self.registry.lock().unwrap();
            match registry.session(&params.session_id) {
                Some(session) => (
                    session.owner_uid,
                    session.record.agent.clone(),
                    session.record.project.clone(),
                    session.record.status,
                ),
                None => {
                    return Err(IpcError::with_details(
                        ErrorCode::NotFound,
                        format!(
                            "No agent session with id {:?} is registered.\n\
                             Next step: run `punarctl agents list` to see current sessions.",
                            params.session_id
                        ),
                        json!({ "session_id": params.session_id }),
                    ));
                }
            }
        };
        if !may_act_on_session(peer, owner_uid) {
            self.audit(self.human_event(
                peer,
                EventFacts {
                    action: ACTION_END,
                    agent: &agent,
                    session_id: &params.session_id,
                    project: &project,
                    decision: Decision::Deny,
                    result: "denied",
                },
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "Ending session {:?} was denied: it belongs to another user.\n\
                     Policy: os default — a session is ended by the user who started it, \
                     or by root.\n\
                     Next step: ask that user, or run the command as root.",
                    params.session_id
                ),
                json!({ "session_id": params.session_id }),
            ));
        }
        if status == AgentStatus::Ended {
            return Err(IpcError::with_details(
                ErrorCode::Conflict,
                format!(
                    "Session {:?} has already ended; there is nothing to end.\n\
                     Next step: `punarctl agents inspect {}` shows when it ended.",
                    params.session_id, params.session_id
                ),
                json!({ "session_id": params.session_id, "state": "ended" }),
            ));
        }

        let (record, row) = {
            let mut registry = self.registry.lock().unwrap();
            let record = registry
                .mark_ended(&params.session_id)
                .expect("the session existed and was active a moment ago");
            let row = registry
                .session(&params.session_id)
                .map(Session::row)
                .expect("just marked ended");
            (record, row)
        };
        self.persist_transition(&record, "ended");
        self.audit(self.human_event(
            peer,
            EventFacts {
                action: ACTION_END,
                agent: &agent,
                session_id: &params.session_id,
                project: &project,
                decision: Decision::Allow,
                result: "success",
            },
        ));
        self.publish_summary();
        Ok(to_value(AgentsEndResult { session: row }))
    }

    // -- detection -----------------------------------------------------

    /// Run a pass only if the last one is older than the staleness bound.
    fn scan_if_stale(&self) {
        let stale = {
            let last = self.last_scan.lock().unwrap();
            match last.0 {
                Some(instant) => instant.elapsed() >= self.cfg.scan_stale_after,
                None => true,
            }
        };
        if stale {
            self.scan_now();
        }
    }

    /// One detection pass: reap managed sessions whose process is gone,
    /// re-derive the detection set, audit only the transitions, and
    /// republish `agents.json` if anything changed.
    fn scan_now(&self) {
        let now = utc_now_rfc3339();
        let reaped = self.reap_dead_sessions();

        let accounted: HashSet<u32> = self.registry.lock().unwrap().active_pids();
        let found = self.detector.scan(&accounted, &now);
        let (appeared, disappeared) = self.registry.lock().unwrap().replace_detections(found);

        *self.last_scan.lock().unwrap() = (Some(Instant::now()), now);

        for detection in &appeared {
            self.audit(self.service_event(EventFacts {
                action: ACTION_SCAN,
                agent: &detection.record.agent,
                session_id: &detection.record.session_id,
                project: &detection.record.project,
                decision: Decision::Allow,
                result: RESULT_DETECTED,
            }));
        }
        for detection in &disappeared {
            self.audit(self.service_event(EventFacts {
                action: ACTION_SCAN,
                agent: &detection.record.agent,
                session_id: &detection.record.session_id,
                project: &detection.record.project,
                decision: Decision::Allow,
                result: RESULT_CLEARED,
            }));
        }
        if !reaped.is_empty() || !appeared.is_empty() || !disappeared.is_empty() {
            self.publish_summary();
        } else if !self.cfg.agents_file.exists() {
            // First pass of this boot: publish even with nothing to say,
            // so the panel reads a fresh empty view rather than a stale one.
            self.publish_summary();
        }
    }

    /// Close sessions whose process is gone without an `agents.end` (the
    /// launcher died, or the machine did). No exit status is invented — the
    /// record simply becomes `ended`, audited as a reap.
    fn reap_dead_sessions(&self) -> Vec<String> {
        let candidates = self.registry.lock().unwrap().active_sessions();
        let proc = self.detector.proc();
        let mut reaped = Vec::new();
        for (session_id, pid) in candidates {
            if proc.is_alive(pid) {
                continue;
            }
            let (record, agent, project) = {
                let mut registry = self.registry.lock().unwrap();
                let Some(record) = registry.mark_ended(&session_id) else {
                    continue;
                };
                let agent = record.agent.clone();
                let project = record.project.clone();
                (record, agent, project)
            };
            self.persist_transition(&record, "reaped");
            self.audit(self.service_event(EventFacts {
                action: ACTION_REAP,
                agent: &agent,
                session_id: &session_id,
                project: &project,
                decision: Decision::Allow,
                result: RESULT_REAPED,
            }));
            reaped.push(session_id);
        }
        reaped
    }

    // -- plumbing ------------------------------------------------------

    fn persist_transition(&self, record: &RegistryRecord, what: &str) {
        if let Err(e) = self.store.append(record) {
            eprintln!(
                "punar-agentd: FAILED to append the {what} record for {}: {e}",
                record.session_id
            );
        }
    }

    /// Rewrite `/run/punar/agents.json`. Best effort by contract: the file
    /// is display data, so a failure is reported and the request continues.
    fn publish_summary(&self) {
        let scanned_at = self.last_scan.lock().unwrap().1.clone();
        let citation = self.citation.citation();
        let summary = {
            let registry = self.registry.lock().unwrap();
            crate::summary::build(&registry, &citation, &scanned_at, &utc_now_rfc3339())
        };
        if let Err(e) = crate::summary::write(&self.cfg.agents_file, &summary) {
            eprintln!(
                "punar-agentd: could not write {}: {e} (the AI panel will render its \
                 last known state, or an empty one)",
                self.cfg.agents_file.display()
            );
        }
    }

    /// punard's device id, or the documented `dev_unknown` sentinel when
    /// punard has not created one yet. Re-read until it is found: agentd
    /// must not permanently attribute events to a sentinel because it
    /// happened to start first.
    fn device_id(&self) -> String {
        let mut cached = self.device_id.lock().unwrap();
        if let Some(id) = cached.as_ref() {
            return id.clone();
        }
        let read = std::fs::read_to_string(self.cfg.state_dir.join("device-id"))
            .ok()
            .map(|text| text.trim().to_string())
            .filter(|id| id.starts_with("dev_") && id.len() > 4);
        match read {
            Some(id) => {
                *cached = Some(id.clone());
                id
            }
            None => "dev_unknown".to_string(),
        }
    }

    /// An event attributed to the human whose CLI action caused it. The
    /// *subject* agent is named by `agent_session_id` — which, at last,
    /// carries a real `agt_` id rather than the `agt_none` sentinel
    /// (docs/api/ipc.md section 10.4).
    fn human_event(&self, peer: &Peer, facts: EventFacts<'_>) -> AuditEvent {
        self.event(
            username_or_uid(&self.cfg.passwd_file, peer.uid),
            PrincipalKind::Human,
            facts,
        )
    }

    /// A daemon-initiated event (reaps and detection transitions):
    /// `user_id: "punar-agentd"`, `source: service`.
    fn service_event(&self, facts: EventFacts<'_>) -> AuditEvent {
        self.event(USER_ID_AGENTD.to_string(), PrincipalKind::Service, facts)
    }

    fn event(&self, user_id: String, source: PrincipalKind, facts: EventFacts<'_>) -> AuditEvent {
        let agent_session_id = if session_id_ok(facts.session_id) {
            facts.session_id.to_string()
        } else {
            // A malformed id can still be denied — the event stays
            // schema-valid by falling back to the sentinel.
            AGENT_SESSION_NONE.to_string()
        };
        let project_id = if facts.project.is_empty() {
            PROJECT_ID_SYSTEM.to_string()
        } else {
            facts.project.to_string()
        };
        let resource = if facts.agent.is_empty() {
            "agent".to_string()
        } else {
            facts.agent.to_string()
        };
        AuditEvent {
            event_id: punar_common::audit::next_event_id(),
            timestamp: utc_now_rfc3339(),
            device_id: self.device_id(),
            user_id: Some(user_id),
            agent_session_id: Some(agent_session_id),
            project_id: Some(project_id),
            source,
            action: facts.action.to_string(),
            resource: Some(resource),
            decision: facts.decision,
            policy_ids: vec![self.citation.citation()],
            result: facts.result.to_string(),
        }
    }

    fn audit_denial(&self, peer: &Peer, params: &AgentsRegisterParams) {
        self.audit(self.human_event(
            peer,
            EventFacts {
                action: ACTION_REGISTER,
                agent: &params.agent,
                session_id: &params.session_id,
                project: &params.project,
                decision: Decision::Deny,
                result: "denied",
            },
        ));
    }

    fn audit(&self, event: AuditEvent) {
        let mut writer = self.audit.lock().unwrap();
        if let Err(e) = writer.append(&event) {
            eprintln!(
                "punar-agentd: FAILED to append the {} audit event: {e}",
                event.action
            );
        }
    }
}

fn invalid_params(reason: String) -> IpcError {
    IpcError::with_details(
        ErrorCode::InvalidParams,
        format!(
            "Invalid parameters for agents.register: {reason}\n\
             Next step: managed sessions are started by `punar-env agent <name>`, which \
             sends the verified facts."
        ),
        json!({ "reason": reason }),
    )
}

fn to_value<T: serde::Serialize>(value: T) -> Value {
    serde_json::to_value(value).unwrap_or_else(|e| json!({ "serialization_error": e.to_string() }))
}
