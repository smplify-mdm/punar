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
//!
//! **Milestone 10 kept it that way.** Periodic detection is a systemd
//! timer (`punar-agentd-scan.timer`, 240 s) that runs
//! `punarctl agents scan --trigger timer` through this same socket, authz
//! and audit path — so there is exactly one code path to verify and the
//! daemon gains no internal clock. The three immediate triggers
//! (`agents.register`, a session ending, an enrollment transition) are
//! events, not intervals.
//!
//! # And a pass that changes nothing writes nothing
//!
//! [`Inner::scan_now`] compares the detection **set** against the previous
//! one and acts only on the difference. In the steady state — the same
//! processes still running — it emits no audit line, rewrites no
//! `agents.json`, touches no ledger and does not write `alerts.json`: the
//! idle write rate of periodic detection is exactly zero bytes (spec 6.4).
//! The consequence, stated because it looks like a bug otherwise:
//! `agents.json`'s `scanned_at` means *the view as of the last change*.
//! When a pass last actually ran is in-memory state the socket serves as
//! `last_scan_at` / `last_scan_trigger`, because the socket is the
//! authority and the file is a change log.

use std::collections::HashSet;
use std::io::{self, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use punar_common::agent::{
    ADAPTERS_DIR, AGENTS_SUMMARY_PATH, ALERT_QUIET_WINDOW_SECS, ALERTS_RUNTIME_PATH,
    AUTHORITY_SOURCE_LABEL, AgentClassification, AgentMethod, AgentRequest, AgentStatus,
    AgentsAccessParams, AgentsEndParams, AgentsEndResult, AgentsGetParams, AgentsGetResult,
    AgentsListResult, AgentsRegisterParams, AgentsRegisterResult, AgentsScanParams,
    AlertsDismissParams, AlertsDismissResult, AlertsListParams, AlertsListResult,
    DETECTIONS_INDEX_PATH, DETECTIONS_JSONL_PATH, LedgerNetworkParams, LedgerPurgeParams,
    ListedSession, PurgeScope, REGISTRY_JSONL_PATH, RegistryRecord, SCAN_STALE_AFTER_SECS,
    SUSPECTED_SIGNATURES_PATH, ScanTrigger, SessionRow, agent_name_ok, session_id_ok,
    validate_authority_summary, validate_registry_record,
};
use punar_common::audit::{AGENT_SESSION_NONE, AuditWriter, PROJECT_ID_SYSTEM};
use punar_common::ipc::{
    ErrorCode, IpcError, LineRead, MAX_REQUEST_LINE_BYTES, Response, SERVER_READ_TIMEOUT,
    read_line_bounded,
};
use punar_common::ledger::{
    AgentsAccessResult, LEDGER_RUNTIME_PATH, PROCESS_CLASSES_PATH, RetentionInfo,
};
use punar_common::query::{
    AuthorizationDecision, NEVER_ANSWERED, PendingQuery, QUERIES_LOG_PATH, QueriesListParams,
    QueriesListResult, QueryAnswerResult, QueryLogStorage, QueryRecord, QueryScope, RecordCounts,
    authorize, read_org_granted_scopes,
};
use punar_common::time::utc_now_rfc3339;
use punar_common::{AuditEvent, Decision, PrincipalKind};
use serde_json::{Value, json};

use crate::adapters::SignatureSet;
use crate::alerts::{AlertConfig, AlertEngine, DismissError, Observation};
use crate::authz::{Peer, PeerSource, may_act_on_session};
use crate::detect::Detector;
use crate::detections::{DetectionIndex, DetectionIndexRow, DetectionStore};
use crate::ledger::{DetectionFacts, LedgerConfig, LedgerEngine, SessionFacts};
use crate::proc::{ProcRoot, scope_unit_name};
use crate::queries::QueryLog;
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
/// M8 (docs/api/ipc.md section 12.6): the user deleted a ledger.
pub const ACTION_LEDGER_PURGE: &str = "ledger.purge";
/// M12: root-only destination-aggregate bridge from `punar-netd`.
pub const ACTION_LEDGER_NETWORK: &str = "ledger.network";
/// M8: one event per retention **batch**, never one per file (spec 6.4).
pub const ACTION_LEDGER_PRUNE: &str = "ledger.prune";
/// M8: root read a ledger it does not own — the seed of Milestone 10's
/// audited administrator query. An owner reading their own ledger is not
/// audited: reading your own data is not an event about you.
pub const ACTION_LEDGER_READ: &str = "agents.access";
/// M10 (milestone-10.md section 5): an alert was raised. **Once per
/// `signature_id`** — this is the audit half of the anti-nag rule, and a
/// check counts these events to prove it.
pub const ACTION_ALERT_RAISE: &str = "agents.alert_raise";
/// M10: the user filed a card. Never a deletion.
pub const ACTION_ALERT_DISMISS: &str = "agents.alert_dismiss";
/// M10 (milestone-10.md section 10.2): one administrator query, answered
/// or refused. `source: organization`, `user_id`: the requesting admin —
/// an audit line about an administrative query that does not name the
/// administrator is a line nobody can act on.
pub const ACTION_ADMIN_QUERY: &str = "admin.ai_query";

/// Audit `result` words added to the open set by M7: a detection appeared,
/// a detection disappeared, a crashed session was closed.
pub const RESULT_DETECTED: &str = "detected";
pub const RESULT_CLEARED: &str = "cleared";
pub const RESULT_REAPED: &str = "reaped";
/// M8 result words: a ledger was deleted by its owner (or root), and a
/// retention batch removed records.
pub const RESULT_PURGED: &str = "purged";
/// `resource` on a device-wide (`--all`) purge — the caller's own
/// sessions, named without listing them.
pub const RESOURCE_OWN_LEDGERS: &str = "own";
/// `resource` on a prune batch; the count travels with it, because the
/// audit schema has no numeric field and the batch size is the fact
/// worth keeping.
pub const RESOURCE_LEDGER: &str = "ledger";
/// M10 result words: a card was raised, and a card was filed.
pub const RESULT_RAISED: &str = "raised";
pub const RESULT_DISMISSED: &str = "dismissed";

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
    /// M10 (milestone-10.md sections 5.3, 6.4): the root-owned alert
    /// state file and the detection persistence pair. Injectable for the
    /// same reason everything else here is — a test runs the whole
    /// engine inside a tempdir.
    pub alerts_file: PathBuf,
    pub detections_path: PathBuf,
    pub detections_index_path: PathBuf,
    /// M10 (milestone-10.md section 10.1): the local record of every
    /// question an administrator asked about this device.
    pub queries_path: PathBuf,
    /// punard's section 9 status file — read for the enrolled flag.
    pub status_file: PathBuf,
    /// `/proc` in production, a fixture tree in tests.
    pub proc_root: PathBuf,
    /// M8 ledger paths (docs/api/ipc.md sections 12-13), all injectable
    /// for the same reason the rest are: a test runs the whole engine
    /// inside a tempdir.
    pub ledger_dir: PathBuf,
    pub ledger_runtime_file: PathBuf,
    pub process_classes_path: PathBuf,
    /// `/sys/fs/cgroup` in production — the ledger samples the agent
    /// scope's `cgroup.procs` and `pids.peak` from here.
    pub cgroup_root: PathBuf,
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
        let state_dir_for_ledger = state_dir.clone();
        AgentdConfig {
            socket_path,
            registry_path: state_dir.join("agents/registry.jsonl"),
            agents_file: state_dir.join("agents.json"),
            alerts_file: state_dir.join("alerts.json"),
            detections_path: state_dir.join("agents/detections.jsonl"),
            detections_index_path: state_dir.join("agents/detections-index.json"),
            queries_path: state_dir.join("agents/queries.jsonl"),
            status_file: state_dir.join("status.json"),
            state_dir,
            audit_path,
            adapters_dir: PathBuf::from(ADAPTERS_DIR),
            suspected_path: PathBuf::from(SUSPECTED_SIGNATURES_PATH),
            proc_root: PathBuf::from("/proc"),
            ledger_dir: state_dir_for_ledger.join("agents/ledger"),
            ledger_runtime_file: state_dir_for_ledger.join("ledger.json"),
            process_classes_path: PathBuf::from(PROCESS_CLASSES_PATH),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
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
        cfg.alerts_file = PathBuf::from(ALERTS_RUNTIME_PATH);
        cfg.detections_path = PathBuf::from(DETECTIONS_JSONL_PATH);
        cfg.detections_index_path = PathBuf::from(DETECTIONS_INDEX_PATH);
        cfg.queries_path = PathBuf::from(QUERIES_LOG_PATH);
        cfg.status_file = PathBuf::from("/run/punar/status.json");
        cfg.ledger_dir = PathBuf::from(punar_common::ledger::LEDGER_DIR);
        cfg.ledger_runtime_file = PathBuf::from(LEDGER_RUNTIME_PATH);
        cfg
    }
}

struct Inner {
    cfg: AgentdConfig,
    registry: Mutex<Registry>,
    store: RegistryStore,
    detector: Detector,
    /// The M8 AI Access Ledger (spec sections 21, 24). Its own lock; the
    /// daemon never holds the registry lock across a ledger call, so the
    /// two cannot deadlock.
    ledger: LedgerEngine,
    citation: CitationSources,
    audit: Mutex<AuditWriter>,
    /// punard's device id, read lazily: agentd never creates it (punard
    /// owns that file), and a daemon started before punard's first boot
    /// picks it up on the next audit rather than caching a sentinel
    /// forever.
    device_id: Mutex<Option<String>>,
    /// M10: the alert engine (milestone-10.md section 5) and the
    /// detection persistence pair (section 6). Each has its own lock, and
    /// neither is ever held across a call into the other or into the
    /// registry, so none of the four can deadlock against another.
    alerts: AlertEngine,
    detections: DetectionStore,
    detection_index: Mutex<DetectionIndex>,
    /// M10: the append-only query log. Its own file, its own lock-free
    /// discipline (one `write_all` to an `O_APPEND` fd), and no shared
    /// state with the registry or the ledger.
    queries: QueryLog,
    /// When the last pass ran, when the detection set last **changed**,
    /// and what asked for the pass.
    last_scan: Mutex<ScanState>,
    shutdown: AtomicBool,
    active: Mutex<usize>,
    slot_freed: Condvar,
}

/// Liveness of the detection pass, in memory only.
///
/// Two clocks, because M10 separates two facts that M7 conflated
/// (milestone-10.md section 3.4). `changed_at` is what `agents.json`
/// carries and means *the view as of the last change* — a pass that
/// changes nothing does not advance it, because a pass that changes
/// nothing writes nothing. `last_at` is *when a pass actually ran*, which
/// only the socket can answer, because no file records it.
#[derive(Debug)]
struct ScanState {
    /// Monotonic instant of the last pass — the staleness gate.
    at: Option<Instant>,
    /// Wall clock of the last change to the detection set.
    changed_at: String,
    /// Wall clock of the last pass, changed or not.
    last_at: String,
    /// What asked for that pass.
    trigger: ScanTrigger,
}

/// A constructed (not yet listening) daemon.
pub struct Daemon {
    inner: Arc<Inner>,
}

/// A listening daemon; `stop()` shuts it down gracefully.
pub struct DaemonHandle {
    inner: Arc<Inner>,
    accept_thread: JoinHandle<()>,
    /// The ledger's `inotify` reader (Milestone 8): one thread parked in
    /// a blocking `read(2)`. `None` when no watch could be established —
    /// the lazy catch-up drain on every ledger read is the correctness
    /// mechanism, and the watch is only freshness.
    ledger_watch: Option<JoinHandle<()>>,
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
        let ledger_cfg = LedgerConfig {
            dir: cfg.ledger_dir.clone(),
            runtime_file: cfg.ledger_runtime_file.clone(),
            audit_path: cfg.audit_path.clone(),
            process_classes_path: cfg.process_classes_path.clone(),
            cgroup_root: cfg.cgroup_root.clone(),
            retention_days: punar_common::ledger::LEDGER_RETENTION_DAYS,
            detection_retention_days: punar_common::ledger::DETECTION_RETENTION_DAYS,
        };
        let ledger = LedgerEngine::open(
            ledger_cfg,
            ProcRoot::new(&cfg.proc_root),
            lookup_gid(&cfg.group_file, &cfg.group),
        );
        for warning in &ledger.warnings {
            eprintln!("punar-agentd: ledger: {warning}");
        }
        let detector = Detector::new(proc, signatures, &cfg.passwd_file);
        let citation = CitationSources {
            status_file: cfg.status_file.clone(),
            enrollment_file: cfg.state_dir.join("enrollment.json"),
        };

        let detections = DetectionStore::new(&cfg.detections_path, &cfg.detections_index_path);
        let detection_index = detections.load_index();
        let alerts = AlertEngine::new(AlertConfig::new(
            &cfg.alerts_file,
            lookup_gid(&cfg.group_file, &cfg.group),
        ));
        // A restart is not a new sighting: rebuild the alert register
        // from the file this daemon last wrote, so a package update does
        // not re-raise every standing card (milestone-10.md section 5.2).
        alerts.resume();

        let now = utc_now_rfc3339();
        let inner = Arc::new(Inner {
            registry: Mutex::new(registry),
            store,
            detector,
            ledger,
            alerts,
            detections,
            detection_index: Mutex::new(detection_index),
            queries: QueryLog::new(&cfg.queries_path),
            citation,
            audit: Mutex::new(audit),
            device_id: Mutex::new(None),
            last_scan: Mutex::new(ScanState {
                at: None,
                changed_at: now.clone(),
                last_at: now,
                trigger: ScanTrigger::Manual,
            }),
            shutdown: AtomicBool::new(false),
            active: Mutex::new(0),
            slot_freed: Condvar::new(),
            cfg,
        });
        // Resume the ledgers of sessions the replay carried, so a
        // restarted daemon keeps aggregating into the same records rather
        // than starting a second one.
        inner.ledger.resume(&inner.active_facts());
        // First pass + first publish: the panel has a truthful file to read
        // before anything connects. The pass also drains the audit tail
        // and runs the first retention prune (crash honesty).
        //
        // The trigger is `manual`: this is a human (or systemd) starting
        // the daemon, and calling it `timer` would let a check "prove"
        // a periodic detection that never fired.
        inner.scan_now(ScanTrigger::Manual);
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

        // The one piece of "background" work in this daemon, and it is
        // not background at all: a thread blocked in `read(2)` on an
        // inotify descriptor, woken only when the audit trail changes
        // (spec 6.3 — event-driven, no timer, zero idle CPU).
        let stop_inner = Arc::clone(&inner);
        let drain_inner = Arc::clone(&inner);
        let ledger_watch = crate::ledger::tail::spawn_watch(
            &inner.cfg.audit_path,
            &inner.cfg.ledger_dir,
            move || stop_inner.shutdown.load(Ordering::SeqCst),
            move || {
                // The audit trail moved: ingest the Level-4 references it
                // named, and republish the panel's view only if anything
                // was actually ingested.
                if drain_inner.ledger.drain_audit(&utc_now_rfc3339()) {
                    drain_inner.publish_ledger_view();
                }
            },
        );
        if ledger_watch.is_none() {
            eprintln!(
                "punar-agentd: no inotify watch on the audit trail; the AI Access Ledger \
                 will catch up on every read instead (still correct, just less fresh \
                 between reads)"
            );
        }
        Ok(DaemonHandle {
            inner,
            accept_thread,
            ledger_watch,
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
        // Wake the ledger's blocking reader the same way the accept loop
        // is woken — by touching something it is already watching.
        if let Some(watch) = self.ledger_watch {
            crate::ledger::tail::wake(&self.inner.cfg.ledger_dir);
            let _ = watch.join();
        }
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
            AgentMethod::Scan(params) => Ok(self.handle_scan(peer, params)),
            AgentMethod::Access(params) => self.handle_access(peer, params),
            AgentMethod::Purge(params) => self.handle_purge(peer, params),
            AgentMethod::LedgerNetwork(params) => self.handle_ledger_network(peer, params),
            AgentMethod::AlertsList(params) => Ok(self.handle_alerts_list(params)),
            AgentMethod::AlertsDismiss(params) => self.handle_alerts_dismiss(peer, params),
            AgentMethod::QueryAnswer(params) => self.handle_query_answer(peer, params),
            AgentMethod::QueriesList(params) => Ok(self.handle_queries_list(params)),
        }
    }

    // -- the ledger's view of the registry ------------------------------

    /// The facts the ledger needs about every **active** session. Taken
    /// under the registry lock and released immediately — no ledger call
    /// ever runs while the registry lock is held.
    fn active_facts(&self) -> Vec<SessionFacts> {
        let registry = self.registry.lock().unwrap();
        registry
            .sessions()
            .filter(|session| session.record.status == AgentStatus::Active)
            .map(session_facts)
            .collect()
    }

    /// The facts for one session, active or ended.
    fn facts_of(&self, session_id: &str) -> Option<SessionFacts> {
        let registry = self.registry.lock().unwrap();
        registry.session(session_id).map(session_facts)
    }

    /// The uid that owns a session's ledger. The registry answers for
    /// this boot; the ledger index answers for a session from a previous
    /// one, via the username it recorded. Unknown ⇒ `None`, which
    /// [`may_act_on_session`] treats as root-only — fail closed.
    fn ledger_owner_uid(&self, session_id: &str) -> Option<u32> {
        {
            let registry = self.registry.lock().unwrap();
            if let Some(uid) = registry
                .session(session_id)
                .and_then(|session| session.owner_uid)
            {
                return Some(uid);
            }
            // A live detection answers for its own ledger: the process
            // runs as somebody, and that somebody owns the record about
            // it (milestone-10.md section 6).
            if let Some(uid) = registry
                .detection(session_id)
                .and_then(|detection| detection.owner_uid)
            {
                return Some(uid);
            }
        }
        let user = self.ledger.owner_of(session_id)?;
        crate::util::lookup_uid(&self.cfg.passwd_file, &user)
    }

    // -- reads ---------------------------------------------------------

    fn handle_list(&self) -> Value {
        self.scan_if_stale();
        to_value(self.list_result())
    }

    /// `agents.scan` — one detection pass, on request.
    ///
    /// # The trigger is provenance, so it is not taken from the caller
    ///
    /// milestone-10.md section 3.4 puts `--trigger` into the audit event
    /// specifically so a detection produced by `punar-agentd-scan.timer`
    /// is distinguishable from one produced by a command a human — or a
    /// check script — typed. That distinction is worth nothing if the
    /// claim comes from whoever is calling: `agents.scan` is open to every
    /// peer the socket admits, which includes the desktop user and any AI
    /// agent running as them, and all three non-manual triggers name a
    /// **root** caller (the timer unit, punard on an enrollment
    /// transition, the daemon on its own register/reap path).
    ///
    /// So a non-root peer's claimed trigger is **downgraded to
    /// [`ScanTrigger::Manual`]**, never honoured and never refused.
    /// Downgrading rather than refusing is the honest option and the safe
    /// one: `manual` is *what actually happened* — somebody typed a
    /// command — and turning a provenance question into an availability
    /// question would break nothing an attacker cares about while
    /// breaking a user who passed the wrong flag.
    fn handle_scan(&self, peer: &Peer, params: &AgentsScanParams) -> Value {
        let trigger = if peer.is_root() {
            params.trigger
        } else {
            if params.trigger != ScanTrigger::Manual {
                eprintln!(
                    "punar-agentd: uid {} claimed scan trigger {:?}; recording it as \
                     {:?} — the timer, enrollment and register triggers are root's, and \
                     the audit trail records what happened",
                    peer.uid,
                    params.trigger.as_str(),
                    ScanTrigger::Manual.as_str()
                );
            }
            ScanTrigger::Manual
        };
        let changed = self.scan_now(trigger);
        let mut result = self.list_result();
        result.changed = Some(changed);
        to_value(result)
    }

    fn list_result(&self) -> AgentsListResult {
        // Read the scan stamps first and let the guard go: no code path
        // ever holds `last_scan` while taking `registry`, so taking them
        // in this order can never deadlock against a concurrent request.
        let (scanned_at, last_scan_at, last_scan_trigger) = {
            let last = self.last_scan.lock().unwrap();
            (last.changed_at.clone(), last.last_at.clone(), last.trigger)
        };
        // Same rule for the ledger: its fingerprints are gathered before
        // the registry lock is taken.
        let mut fingerprints = self.ledger.fingerprints();
        let registry = self.registry.lock().unwrap();
        AgentsListResult {
            scanned_at,
            last_scan_at,
            last_scan_trigger,
            // `agents.list` did not necessarily run a pass, so it makes
            // no claim about whether one changed anything.
            changed: None,
            sessions: registry
                .sessions()
                .map(|session| ListedSession {
                    // Counts only (docs/api/ipc.md section 12.4): no class
                    // names, no `evt_` ids, no zones. Identifiers require
                    // `agents.access` and its ownership check.
                    ledger: fingerprints.remove(&session.record.session_id),
                    record: session.record.clone(),
                })
                .collect(),
            // Detection rows still carry no ledger **fingerprint**: the
            // list is a now-view of processes, and a detection's ledger
            // is read with `agents.access <detection_id>` under the same
            // owner-or-root check as a session's (M10).
            detections: registry.detections().map(Detection::row).collect(),
        }
    }

    // -- the AI Access Ledger (docs/api/ipc.md section 12) --------------

    /// `agents.access` — one session's ledger, for its **owner or root**.
    ///
    /// A ledger is personal data about one user's session, which is
    /// stricter than `agents.list` and is the local half of spec section
    /// 24.1's "RBAC applies". The read drains the audit tail and samples
    /// the scope first, so it can never show a staler answer than the
    /// panel.
    fn handle_access(&self, peer: &Peer, params: &AgentsAccessParams) -> Result<Value, IpcError> {
        let now = utc_now_rfc3339();
        if self.ledger.refresh(&self.active_facts(), &now) {
            self.publish_ledger_view();
        }

        if !self.ledger.knows(&params.session_id) {
            // M10 amendment: a detection **does** have a ledger now
            // (milestone-10.md section 6), so reaching here for a
            // detection id means the pass that would have opened it has
            // not run yet — a live id the daemon has not scanned into
            // existence. Say that, rather than M8's "detections have no
            // ledger", which is no longer true.
            let is_detection = self
                .registry
                .lock()
                .unwrap()
                .detection(&params.session_id)
                .is_some();
            let message = if is_detection {
                format!(
                    "{:?} is a detection whose ledger has not been opened yet.\n\
                     Next step: run `punarctl agents scan`, then ask again.",
                    params.session_id
                )
            } else {
                format!(
                    "No AI Access Ledger exists for {:?}.\n\
                     Next step: run `punarctl agents list` to see the sessions and \
                     detections this device has recorded.",
                    params.session_id
                )
            };
            return Err(IpcError::with_details(
                ErrorCode::NotFound,
                message,
                json!({ "session_id": params.session_id }),
            ));
        }

        let owner_uid = self.ledger_owner_uid(&params.session_id);
        if !may_act_on_session(peer, owner_uid) {
            self.audit_ledger(
                peer,
                ACTION_LEDGER_READ,
                &params.session_id,
                &params.session_id,
                Decision::Deny,
                "denied",
            );
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "Reading the AI Access Ledger for {:?} was denied: it belongs to \
                     another user.\n\
                     Policy: os default — a ledger records what an agent did on one \
                     person's behalf, so it is read by that person, or by root (spec \
                     sections 21, 24.1).\n\
                     Next step: ask that user, or run the command as root.",
                    params.session_id
                ),
                json!({ "session_id": params.session_id }),
            ));
        }

        let Some(record) = self.ledger.record_of(&params.session_id) else {
            return Err(IpcError::with_details(
                ErrorCode::NotFound,
                format!(
                    "The AI Access Ledger for {:?} could not be read.\n\
                     Next step: check /var/lib/punar/agents/ledger and the daemon journal.",
                    params.session_id
                ),
                json!({ "session_id": params.session_id }),
            ));
        };

        // Root reading someone else's ledger is itself an event — the
        // seed of Milestone 10's audited administrator query. An owner
        // reading their own ledger is not audited: reading your own data
        // is not an event about you.
        let reading_anothers = peer.is_root() && owner_uid.is_some_and(|uid| uid != peer.uid);
        if reading_anothers {
            self.audit_ledger(
                peer,
                ACTION_LEDGER_READ,
                &record.agent,
                &params.session_id,
                Decision::Allow,
                "success",
            );
        }

        let mut result = AgentsAccessResult::from_record(&record, &now);
        if record.is_purged() {
            // A purged ledger has no retention story left to tell; the
            // renderer must say *purged*, never "nothing recorded".
            result.retention =
                RetentionInfo::expiring(record.retention_expires_at.as_deref().unwrap_or_default());
        }
        Ok(to_value(result))
    }

    /// `ledger.purge` — the user deletes their own ledger (spec 24.2).
    ///
    /// Authorization, verbatim: `peer.uid == session.owner_uid ||
    /// peer.uid == 0`. `--all` from a non-root peer scopes to that uid's
    /// own sessions. The right is unconditional for one's own sessions in
    /// M8: no policy can withhold it, because no organization can read
    /// the data either.
    ///
    /// It does **not** touch `/var/log/punar/audit.jsonl`.
    fn handle_purge(&self, peer: &Peer, params: &LedgerPurgeParams) -> Result<Value, IpcError> {
        let now = utc_now_rfc3339();
        let scope = params
            .scope()
            .expect("the method table refuses an ambiguous purge before dispatch");

        let (targets, resource, audited_session) = match scope {
            PurgeScope::Session(session_id) => {
                if !self.ledger.knows(&session_id) {
                    return Err(IpcError::with_details(
                        ErrorCode::NotFound,
                        format!(
                            "No AI Access Ledger exists for {session_id:?}, so there is \
                             nothing to delete.\n\
                             Next step: `punarctl privacy ledger` lists what this device \
                             has recorded."
                        ),
                        json!({ "session_id": session_id }),
                    ));
                }
                let owner_uid = self.ledger_owner_uid(&session_id);
                if !may_act_on_session(peer, owner_uid) {
                    self.audit_ledger(
                        peer,
                        ACTION_LEDGER_PURGE,
                        &session_id,
                        &session_id,
                        Decision::Deny,
                        "denied",
                    );
                    return Err(IpcError::with_details(
                        ErrorCode::Denied,
                        format!(
                            "Deleting the AI Access Ledger for {session_id:?} was denied: \
                             it belongs to another user.\n\
                             Policy: os default — you may always delete your own ledger, \
                             and only your own (spec section 24.2).\n\
                             Next step: ask that user, or run the command as root."
                        ),
                        json!({ "session_id": session_id }),
                    ));
                }
                let audited = session_id.clone();
                (vec![session_id.clone()], session_id, audited)
            }
            PurgeScope::CallersOwn => {
                let targets = if peer.is_root() {
                    self.ledger.all_sessions()
                } else {
                    self.ledger
                        .sessions_of(&username_or_uid(&self.cfg.passwd_file, peer.uid))
                };
                (
                    targets,
                    RESOURCE_OWN_LEDGERS.to_string(),
                    AGENT_SESSION_NONE.to_string(),
                )
            }
        };

        let result = self.ledger.purge(&targets, &now);
        // M10 decision 11: the user's delete authority reaches the
        // DETECTION records too, not only their ledgers. A record about a
        // process the user never asked for is data derived about their
        // machine, and M8's privacy guarantee 2 is not narrowed for it —
        // no policy, org or otherwise, may withhold that authority.
        // The audit event survives, exactly as M8 guarantee 4 says: purge
        // removes the derived summary, never the decision record.
        self.purge_detection_records(&targets, &now);
        self.audit_ledger(
            peer,
            ACTION_LEDGER_PURGE,
            &resource,
            &audited_session,
            Decision::Allow,
            RESULT_PURGED,
        );
        self.publish_summary();
        Ok(to_value(result))
    }

    /// `ledger.network` — accept a privacy-bounded absolute aggregate from
    /// the root-owned network mediation service, and nobody else.
    fn handle_ledger_network(
        &self,
        peer: &Peer,
        params: &LedgerNetworkParams,
    ) -> Result<Value, IpcError> {
        if !peer.is_root() {
            self.audit_ledger(
                peer,
                ACTION_LEDGER_NETWORK,
                &params.session_id,
                &params.session_id,
                Decision::Deny,
                "denied",
            );
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                "Writing network evidence was denied: only the root-owned punar-netd mediation service may contribute this aggregate. Policy: local OS default — a user process or AI agent cannot forge another principal's history. Next step: use `punarctl privacy connections` to read the local view; there is no user-facing ledger write command.",
                json!({"session_id": params.session_id}),
            ));
        }
        if !self.ledger.knows(&params.session_id) {
            return Err(IpcError::with_details(
                ErrorCode::NotFound,
                format!(
                    "No AI Access Ledger exists for {:?}; network evidence was not held for an unregistered principal. Next step: let the managed launch register before retrying.",
                    params.session_id
                ),
                json!({"session_id": params.session_id}),
            ));
        }
        let now = utc_now_rfc3339();
        let result = self.ledger.ingest_network(params, &now);
        if result.accepted > 0 {
            self.publish_ledger_view();
        }
        if result.rejected > 0 {
            // The destination itself is intentionally absent: a rejection
            // may have been a URL or path, and the audit trail is not
            // purgeable. Record the producer failure, never its payload.
            self.audit_ledger(
                peer,
                ACTION_LEDGER_NETWORK,
                &params.session_id,
                &params.session_id,
                Decision::Deny,
                "privacy_type_rejected",
            );
        }
        Ok(to_value(result))
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
        // The launcher's display block becomes export data at the M10
        // `authority` scope, so it is bounded and printable before it is
        // stored — never after (punar_common::agent::validate_authority_summary).
        if let Err(violations) = validate_authority_summary(&params.authority) {
            return Err(invalid_params(format!(
                "the authority block is not renderable display data: {violations:?}"
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
            scope_path: entry.scope_path_of(&params.session_id),
            executable: entry.exe.clone(),
            authority: Some(params.authority.clone()),
            owner_uid: process_uid.or(Some(peer.uid)),
        };
        let row = session.row();
        let facts = session_facts(&session);
        self.registry.lock().unwrap().insert_session(session);
        // Open this session's ledger now: the workspace grant and the
        // agent's own process class are known at registration, so the
        // very first `agents.access` answers something true.
        self.ledger.begin_session(&facts, &utc_now_rfc3339());
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
        // Immediate trigger 1 (milestone-10.md section 3.3): a managed
        // launch is the moment the process landscape changes, and the
        // moment a sibling unmanaged agent is most likely to be running.
        // Event-driven, which is spec 6.3's stated preference over any
        // interval.
        self.scan_now(ScanTrigger::Register);
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
        self.close_ledger(&params.session_id);
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
        // Immediate trigger 2: a session ending is the same moment, seen
        // from the other side.
        self.scan_now(ScanTrigger::Register);
        Ok(to_value(AgentsEndResult { session: row }))
    }

    // -- alerts (milestone-10.md section 5) ----------------------------

    /// `alerts.list` — the shadow-AI alert register.
    ///
    /// Readable by **any peer the socket admitted**, deliberately.
    /// Withholding it from the user would violate spec 24.2: from M10
    /// onward an authorized administrator can query the existence of
    /// unmanaged agents on this device, so a surface the user cannot read
    /// would create a state in which the administrator knows about a
    /// process on the user's machine and the user does not.
    fn handle_alerts_list(&self, params: &AlertsListParams) -> Value {
        // Deliberately **no** staleness-gated pass here, unlike
        // `agents.list`.
        //
        // A read must not be able to manufacture a detection. If
        // `alerts.list` ran a pass, the first person to *look* could be
        // the one who produces the `agents.scan` / `detected` event —
        // and that event would be labelled `manual`, making it
        // indistinguishable from a typed command and destroying the one
        // property that lets a check prove periodic detection actually
        // fired (milestone-10.md section 3.4, `m10-check` group 3).
        //
        // The register is derived state whose freshness is the scan's
        // job; the cadence is stated on the surface instead. Nothing is
        // lost: a read still gets everything the last pass knew.
        to_value(AlertsListResult {
            alerts: self.alerts.list(params.include_dismissed),
            quiet_window_secs: ALERT_QUIET_WINDOW_SECS,
        })
    }

    /// `alerts.dismiss` — file one card.
    ///
    /// Owner of the detection that raised it, or root: an alert names a
    /// process running as one user, so it is put away by that user. An
    /// alert whose owner is unknown (resumed from the file after a daemon
    /// restart, before the next sighting re-attaches the owner) is
    /// root-only — fail closed, the [`may_act_on_session`] rule verbatim.
    ///
    /// **It files; it never destroys, and it never changes suppression.**
    /// The card stays in the register and in the detection record, and
    /// the signature was already never going to be raised twice.
    fn handle_alerts_dismiss(
        &self,
        peer: &Peer,
        params: &AlertsDismissParams,
    ) -> Result<Value, IpcError> {
        if !self.alerts.knows(&params.alert_id) {
            return Err(IpcError::with_details(
                ErrorCode::NotFound,
                format!(
                    "No alert with id {:?} is in the register.\n\
                     Next step: `punarctl agents alerts --all` lists every card, including \
                     the ones already filed.",
                    params.alert_id
                ),
                json!({ "alert_id": params.alert_id }),
            ));
        }
        let owner_uid = self.alerts.owner_uid_of(&params.alert_id);
        if !may_act_on_session(peer, owner_uid) {
            self.audit(self.human_event(
                peer,
                EventFacts {
                    action: ACTION_ALERT_DISMISS,
                    agent: &params.alert_id,
                    session_id: AGENT_SESSION_NONE,
                    project: PROJECT_ID_SYSTEM,
                    decision: Decision::Deny,
                    result: "denied",
                },
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "Filing alert {:?} was denied: it is about a process running as \
                     another user.\n\
                     Policy: os default — an alert is put away by the person it is about, \
                     or by root (spec section 24.2).\n\
                     Next step: ask that user, or run the command as root.",
                    params.alert_id
                ),
                json!({ "alert_id": params.alert_id }),
            ));
        }

        let now = utc_now_rfc3339();
        let filed = match self.alerts.dismiss(&params.alert_id, &now) {
            Ok(filed) => filed,
            Err(DismissError::NotFound) => {
                return Err(IpcError::with_details(
                    ErrorCode::NotFound,
                    format!("No alert with id {:?} is in the register.", params.alert_id),
                    json!({ "alert_id": params.alert_id }),
                ));
            }
        };
        if filed.newly_dismissed {
            // The alert set changed, so the file is rewritten — and the
            // shell's FileView, not this call's result, is what the card
            // disappears on.
            self.alerts.write(&now);
            self.audit(self.human_event(
                peer,
                EventFacts {
                    action: ACTION_ALERT_DISMISS,
                    agent: &format!("{}:{}", filed.row.agent, filed.row.signature),
                    session_id: &filed.row.detection_id,
                    project: PROJECT_ID_SYSTEM,
                    decision: Decision::Allow,
                    result: RESULT_DISMISSED,
                },
            ));
        }
        Ok(to_value(AlertsDismissResult {
            dismissed: true,
            alert_id: params.alert_id.clone(),
            dismissed_at: filed.dismissed_at,
            // Stated on the wire, not only in the CLI's prose: filing a
            // card moves no suppression state, because there is none to
            // move (milestone-10.md section 5.2).
            suppression_changed: false,
        }))
    }

    // -- the remote query (milestone-10.md sections 7-10) ---------------

    /// `query.answer` — one administrator question the device **fetched**,
    /// decided here.
    ///
    /// # Law 2, made structural
    ///
    /// The transport is not the authority. `punard` is a courier: it hands
    /// over the question exactly as it pulled it and posts back whatever
    /// this method returns, byte-identical. **Nothing in `params` can
    /// widen what may be answered.** The grant is read from
    /// `/var/lib/punar/enrollment.json` by this daemon, through a function
    /// whose only input is a path (`read_org_granted_scopes`), so there is
    /// no parameter through which a compromised control plane could pass
    /// one (spec 59.4).
    ///
    /// # A refusal is a result, not an error
    ///
    /// An out-of-scope query returns `Ok` carrying
    /// `authorization_decision: "deny"` and the section-73 message. An
    /// error frame would mean *the call did not happen*, and the courier
    /// would then have no decision to relay and would leave the query
    /// pending forever. The one thing that *is* an error frame here is a
    /// non-root peer: that is not a refusal to answer a question, it is a
    /// refusal to accept the caller.
    fn handle_query_answer(&self, peer: &Peer, params: &PendingQuery) -> Result<Value, IpcError> {
        if !peer.is_root() {
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                "Answering an administrator query was denied: query.answer is called by \
                 punard, the only control-plane client, and by nothing else.\n\
                 Policy: os default — the courier runs as root and the data owner checks \
                 the peer, so a local user cannot make this device answer a question \
                 nobody asked (ipc.md section 17.8, spec section 61).\n\
                 Next step: `punarctl privacy queries` shows every question that did \
                 reach this device."
                    .to_string(),
                json!({ "method": "query.answer", "required": "root peer" }),
            ));
        }

        // Law 2, the half that is not about scope. `authorize` below makes
        // the *scope* untrusted-safe; every other field of the question is
        // also chosen by whatever answered `queries.pending`, and those
        // fields are used as keys — a ledger lookup key, a pattern-checked
        // audit field, a line on the spec 24.2 surface, a line in a
        // 365-day log. A control plane that can choose them can reach past
        // the scope check without ever widening a scope (spec 59.4), so
        // they are checked here, before anything is projected, audited or
        // written. See `PendingQuery::validate` for each vector by name.
        if let Err(why) = params.validate() {
            eprintln!(
                "punar-agentd: refusing a malformed pending query: {why} — nothing was \
                 projected, audited or recorded; it stays pending on the control plane"
            );
            return Err(IpcError::with_details(
                ErrorCode::InvalidParams,
                format!(
                    "This device will not answer that question: {why}\n\
                     Policy: os default — a question whose fields this device cannot read \
                     is not a question it can decide, and a decision it cannot record is \
                     one it does not make (spec sections 51.1, 59.4).\n\
                     Next step: `punarctl privacy queries` shows every question that did \
                     reach this device."
                ),
                json!({ "method": "query.answer", "reason": "malformed_query" }),
            ));
        }

        let now = utc_now_rfc3339();
        // The middle term of the intersection, read from local state by
        // the daemon that holds the data. Never from the request.
        let grant = read_org_granted_scopes(&self.citation.enrollment_file);
        let authorization = authorize(&params.requested_scope, &grant);

        let (payload, counts) = match authorization.granted_scope {
            Some(scope) => {
                let (payload, counts) = self.project_answer(scope, params, &now);
                (Some(payload), counts)
            }
            None => (None, RecordCounts::default()),
        };

        // The audit event is written BEFORE the answer leaves, so a
        // device that dies mid-answer has still recorded the question.
        let decision = match authorization.decision {
            AuthorizationDecision::Allow => Decision::Allow,
            AuthorizationDecision::Deny => Decision::Deny,
        };
        let result_word = authorization.result_category().as_str();
        let policy_ids = match &grant.policy_citation {
            Some(citation) => vec![citation.clone()],
            None => vec![self.citation.citation()],
        };
        let event = {
            let mut event = self.event(
                params.requesting_admin.clone(),
                // Already in the shipped `principal_kind` enum: the
                // organization asked, not a human on this device.
                PrincipalKind::Organization,
                EventFacts {
                    action: ACTION_ADMIN_QUERY,
                    agent: &params.requested_scope,
                    session_id: params.session_id.as_deref().unwrap_or(AGENT_SESSION_NONE),
                    project: PROJECT_ID_SYSTEM,
                    decision,
                    result: result_word,
                },
            );
            event.policy_ids = policy_ids;
            event
        };
        let audit_event_id = event.event_id.clone();
        self.audit(event);

        let record = QueryRecord {
            query_id: params.query_id.clone(),
            received_at: params.received_at.clone(),
            answered_at: now.clone(),
            requesting_admin: params.requesting_admin.clone(),
            // There is no IdP in M10, and every surface says so.
            admin_identity_verified: false,
            organization: params.organization.clone(),
            device_id: self.device_id(),
            requested_scope: params.requested_scope.clone(),
            granted_scope: authorization.granted_scope,
            authorization_decision: authorization.decision,
            refusal_reason: authorization.refusal_reason.map(str::to_string),
            result_category: authorization.result_category(),
            record_counts: counts,
            audit_event_id: Some(audit_event_id.clone()),
        };
        if let Err(e) = self.queries.append(&record, &now) {
            // The answer still goes back — the audit event is already
            // written and the organization's question was decided — but
            // the failure is loud, because the user's own copy of the
            // record is the section 24.2 guarantee.
            eprintln!(
                "punar-agentd: FAILED to record query {} in {}: {e}",
                params.query_id,
                self.queries.path().display()
            );
        }

        Ok(to_value(QueryAnswerResult {
            query_id: params.query_id.clone(),
            authorization_decision: authorization.decision,
            granted_scope: authorization.granted_scope,
            result_category: authorization.result_category(),
            payload,
            refusal_reason: authorization.refusal_reason.map(str::to_string),
            refusal_message: (!authorization.message.is_empty())
                .then(|| authorization.message.clone()),
            audit_event_id: Some(audit_event_id),
        }))
    }

    /// `queries.list` — the section 24.2 command's data.
    ///
    /// Readable by **any peer the socket admitted**, deliberately:
    /// withholding the record of who asked about the user from the user
    /// would be the exact inversion spec 24.2 forbids, and root-only would
    /// be absurd on a single-user personal device.
    ///
    /// Everything the surface prints comes from here — the granted scopes
    /// the daemon actually enforces, the never-answered list, and the
    /// storage facts — so the CLI invents nothing and the two cannot
    /// drift.
    fn handle_queries_list(&self, params: &QueriesListParams) -> Value {
        let grant = read_org_granted_scopes(&self.citation.enrollment_file);
        to_value(QueriesListResult {
            queries: self.queries.list(params.since.as_deref(), params.limit),
            enrolled: grant.enrolled,
            organization: grant.organization.clone(),
            policy_citation: grant.policy_citation.clone(),
            granted_scopes: grant.scopes.clone(),
            admin_identity_verified: false,
            never_answered: NEVER_ANSWERED.iter().map(|s| s.to_string()).collect(),
            storage: QueryLogStorage {
                path: self.queries.path().display().to_string(),
                ..QueryLogStorage::default()
            },
        })
    }

    /// Project the answer for one **granted** scope.
    ///
    /// Every branch is a projection of data the owning user can already
    /// print about themselves (spec 24.2 guarantee 9). What is absent is
    /// absent because **no field exists to carry it**, not because a
    /// filter drops it: there is no executable path, no pid, no cmdline,
    /// no username, no `cwd` and no project anywhere below.
    fn project_answer(
        &self,
        scope: QueryScope,
        params: &PendingQuery,
        now: &str,
    ) -> (Value, RecordCounts) {
        let narrow = params.session_id.as_deref();
        match scope {
            QueryScope::Inventory => self.project_inventory(narrow, now),
            QueryScope::Authority => self.project_authority(narrow, now),
            QueryScope::ResourceSummary => self.project_resource_summary(narrow, now),
            QueryScope::SecurityEvents => self.project_security_events(narrow, now),
        }
    }

    /// Level 1 — counts, sessions, detections. Note what is **not** here
    /// even at the coarsest scope: no executable path (only `zone`), no
    /// pid, no user, no project, no cwd, no cmdline
    /// (milestone-10.md section 8.2).
    fn project_inventory(&self, narrow: Option<&str>, now: &str) -> (Value, RecordCounts) {
        let zones = {
            let index = self.detection_index.lock().unwrap();
            index
                .rows
                .iter()
                // Narrowed back to the closed class set on the way out:
                // the stored value is a `String` in a struct whose
                // neighbouring field is a full executable path, and
                // section 8.3's guarantee is that only classes leave.
                .map(|(id, row)| {
                    (
                        id.clone(),
                        crate::identity::zone_class_or_unknown(&row.zone),
                    )
                })
                .collect::<std::collections::BTreeMap<String, &'static str>>()
        };
        let registry = self.registry.lock().unwrap();
        let mut managed = 0u32;
        let mut observed = 0u32;
        let mut unknown = 0u32;
        let mut sessions = Vec::new();
        for session in registry.sessions() {
            let record = &session.record;
            if narrow.is_some_and(|id| id != record.session_id) {
                continue;
            }
            match record.classification {
                AgentClassification::Managed => managed += 1,
                AgentClassification::Observed => observed += 1,
                AgentClassification::Unknown => unknown += 1,
            }
            sessions.push(json!({
                "session_id": record.session_id,
                "agent": record.agent,
                "classification": record.classification,
                "status": record.status,
                "started_at": record.started_at,
            }));
        }
        let mut detections = Vec::new();
        for detection in registry.detections() {
            let record = &detection.record;
            if narrow.is_some_and(|id| id != record.session_id) {
                continue;
            }
            match record.classification {
                AgentClassification::Managed => managed += 1,
                AgentClassification::Observed => observed += 1,
                AgentClassification::Unknown => unknown += 1,
            }
            detections.push(json!({
                // The coarse identity: an administrator needs "how many
                // distinct unmanaged things", not process churn.
                "signature_id": detection.signature_id,
                "agent": record.agent,
                "classification": record.classification,
                // The honesty label travels in the data (spec 23).
                "suspected": true,
                "zone": zones
                    .get(&record.session_id)
                    .copied()
                    .unwrap_or_else(|| {
                        crate::identity::zone_class_or_unknown(detection.zone)
                    }),
                "first_seen": detection.observed_at,
                "live": record.status == AgentStatus::Active,
            }));
        }
        let counts = RecordCounts {
            sessions: sessions.len() as u32,
            detections: detections.len() as u32,
            security_events: 0,
        };
        let payload = json!({
            "query_id": Value::Null,
            "scope": QueryScope::Inventory,
            "answered_at": now,
            "counts": {"managed": managed, "observed": observed, "unknown": unknown},
            "sessions": sessions,
            "detections": detections,
            "not_yet_observed": punar_common::ledger::not_yet_observed(),
        });
        (payload, counts)
    }

    /// Level 2 — the organization's own policy, read back. Display-level
    /// authority rows carry their current enforcement labels unchanged:
    /// an administrator must not be told that something is enforced when
    /// it is only declared, or vice versa (spec 1.22).
    fn project_authority(&self, narrow: Option<&str>, now: &str) -> (Value, RecordCounts) {
        let registry = self.registry.lock().unwrap();
        let mut sessions = Vec::new();
        for session in registry.sessions() {
            let record = &session.record;
            if narrow.is_some_and(|id| id != record.session_id) {
                continue;
            }
            let Some(authority) = session.authority.as_ref() else {
                continue;
            };
            sessions.push(json!({
                "session_id": record.session_id,
                "agent": record.agent,
                "classification": record.classification,
                "policy_citation": authority.policy_citation,
                "rows": authority.rows,
            }));
        }
        let counts = RecordCounts {
            sessions: sessions.len() as u32,
            ..RecordCounts::default()
        };
        let payload = json!({
            "query_id": Value::Null,
            "scope": QueryScope::Authority,
            "answered_at": now,
            "sessions": sessions,
            // Spec 1.22, and the same discipline section 9.1 applies to
            // the requesting admin's identity: these rows are asserted by
            // the process that registered the session, not measured by
            // this device. An administrator reading them must be told
            // that, or `enforcement: "enforced"` becomes a claim the
            // device never made.
            "authority_source": AUTHORITY_SOURCE_LABEL,
            // A detection has no authority block at all: nothing granted
            // an unmanaged process anything, so there is nothing to read
            // back. Said, rather than rendered as an empty allowance.
            "detections": Value::Array(Vec::new()),
            "not_yet_observed": punar_common::ledger::not_yet_observed(),
        });
        (payload, counts)
    }

    /// The session ids one ledger-backed projection may read.
    ///
    /// milestone-10.md section 8.1: *"A query may optionally name one
    /// `session_id` to narrow the answer; it may never widen it."* This
    /// function is that sentence, made structural: narrowing **filters**
    /// the set the unnarrowed answer would have carried, it does not
    /// replace it. Substituting the requested id for the set — the obvious
    /// reading — would have turned the narrowing key into a direct lookup
    /// against `LedgerEngine::record_of`, which resolves an unknown id by
    /// reading `<ledger dir>/<id>.json`; a control plane choosing that
    /// string chooses a **path**, and reaches records the unnarrowed answer
    /// deliberately excludes (a tombstoned one, or a file outside the
    /// directory entirely). `PendingQuery::validate` already refuses a
    /// non-`agt_` key; this is the second, independent gate, and it is the
    /// one that holds even if a caller other than the courier ever arrives.
    fn narrowed_sessions(&self, narrow: Option<&str>) -> Vec<String> {
        let all = self.ledger.all_sessions();
        match narrow {
            Some(id) => all.into_iter().filter(|known| known == id).collect(),
            None => all,
        }
    }

    /// Level 3 — M8's `result.summary` **verbatim**, the same
    /// `ledger-summary.json` document `punarctl agents access --json`
    /// hands the user. The administrator's view is a subset of the
    /// user's by construction rather than by promise.
    fn project_resource_summary(&self, narrow: Option<&str>, now: &str) -> (Value, RecordCounts) {
        let ids = self.narrowed_sessions(narrow);
        let mut summaries = Vec::new();
        let mut events = 0u32;
        for id in ids {
            let Some(record) = self.ledger.record_of(&id) else {
                continue;
            };
            let summary = record.summary(now);
            events += summary.security_events.len() as u32;
            summaries.push(to_value(summary));
        }
        let counts = RecordCounts {
            sessions: summaries.len() as u32,
            detections: 0,
            security_events: events,
        };
        let payload = json!({
            "query_id": Value::Null,
            "scope": QueryScope::ResourceSummary,
            "answered_at": now,
            "summaries": summaries,
            "not_yet_observed": punar_common::ledger::not_yet_observed(),
        });
        (payload, counts)
    }

    /// Level 4 — event **references** only: `{event_id, event_type,
    /// timestamp}`. The action, resource, decision and policy ids stay on
    /// the device. An administrator who needs the payload asks the human,
    /// which is the correct social protocol and is printed in the answer.
    fn project_security_events(&self, narrow: Option<&str>, now: &str) -> (Value, RecordCounts) {
        let ids = self.narrowed_sessions(narrow);
        let mut events = Vec::new();
        for id in ids {
            let Some(record) = self.ledger.record_of(&id) else {
                continue;
            };
            for reference in &record.security_events {
                events.push(json!({
                    "event_id": reference.event_id,
                    "event_type": reference.event_type,
                    "timestamp": reference.timestamp,
                }));
            }
        }
        let counts = RecordCounts {
            security_events: events.len() as u32,
            ..RecordCounts::default()
        };
        let payload = json!({
            "query_id": Value::Null,
            "scope": QueryScope::SecurityEvents,
            "answered_at": now,
            "security_events": events,
            "payloads_withheld": "event payloads stay on this device (spec 53); \
                                  ask the person who uses it",
            "not_yet_observed": punar_common::ledger::not_yet_observed(),
        });
        (payload, counts)
    }

    // -- detection -----------------------------------------------------

    /// Run a pass only if the last one is older than the staleness bound.
    fn scan_if_stale(&self) {
        let stale = {
            let last = self.last_scan.lock().unwrap();
            match last.at {
                Some(instant) => instant.elapsed() >= self.cfg.scan_stale_after,
                None => true,
            }
        };
        if stale {
            // A staleness-triggered pass is still a `manual` one: a human
            // asked for the list. Nothing here may claim the timer fired.
            self.scan_now(ScanTrigger::Manual);
        }
    }

    /// One detection pass.
    ///
    /// # The diff is the event (milestone-10.md section 3.4)
    ///
    /// The pass compares the detection **set** against the previous one
    /// and emits `detected` / `cleared` **once per detection identity**.
    ///
    /// | Transition | Emitted, once | Written |
    /// |---|---|---|
    /// | absent → present | audit `agents.scan` / `detected` | `detections.jsonl` (`active`), a ledger, `agents.json`, and `alerts.json` iff the signature is new |
    /// | present → absent | audit `agents.scan` / `cleared` | `detections.jsonl` (`ended`), the ledger closes, `agents.json` |
    /// | present → present | **nothing** | **nothing** |
    /// | empty diff | **nothing** | **nothing** |
    ///
    /// That last row is what makes a 240 s timer compatible with spec
    /// 6.4: **the steady state of periodic detection is zero bytes
    /// written.** It also makes the audit log a log of *events* rather
    /// than a log of *scans*, which is what keeps `punarctl audit tail`
    /// readable after a week of uptime.
    ///
    /// # Ordering, and why it is this order
    ///
    /// The transition events are audited **before** the detection
    /// ledgers are opened. That is deliberate: the drain then holds the
    /// `unknown_ai_execution` reference as a pending attribution, and
    /// [`crate::ledger::LedgerEngine::begin_detection`] applies it as
    /// part of the record's first write — one write per new detection
    /// instead of two, reusing the machinery M8 built for exactly this
    /// race.
    ///
    /// Returns whether the pass changed anything, which is what
    /// `agents.scan` reports back as `changed`.
    fn scan_now(&self, trigger: ScanTrigger) -> bool {
        let now = utc_now_rfc3339();
        let reaped = self.reap_dead_sessions();

        let accounted: HashSet<u32> = self.registry.lock().unwrap().active_pids();
        let found = self.detector.scan(&accounted, &now);
        let (appeared, disappeared) = self.registry.lock().unwrap().replace_detections(found);
        let registry_changed =
            !reaped.is_empty() || !appeared.is_empty() || !disappeared.is_empty();

        // A detection this device already recorded, whose ledger can be
        // resumed, is the **same execution seen again** after an agentd
        // restart — not a new sighting. Splitting it out here is what
        // stops a restart producing a second `detected` event, a second
        // `active` record and a ledger that forgets what it held. The
        // identity is what makes the split possible at all: the same
        // process keeps the same id across daemon lifetimes, because the
        // id is derived from the kernel's facts and not from ours.
        let (resumed, appeared): (Vec<Detection>, Vec<Detection>) = appeared
            .into_iter()
            .partition(|detection| self.ledger.resume_detection(&detection.record.session_id));
        if !resumed.is_empty() {
            eprintln!(
                "punar-agentd: resumed {} detection(s) still running from before this \
                 daemon started; a restart is bookkeeping, not a new sighting",
                resumed.len()
            );
        }

        {
            let mut last = self.last_scan.lock().unwrap();
            last.at = Some(Instant::now());
            last.last_at = now.clone();
            last.trigger = trigger;
            // `scanned_at` in `agents.json` means "as of the last
            // change", so it only moves when something changed.
            if registry_changed {
                last.changed_at = now.clone();
            }
        }

        // 1. The transitions, audited once each. The trigger travels in
        //    `resource` so a check can prove a detection came from the
        //    timer and not from a command a check script typed.
        for detection in &appeared {
            self.audit_scan_transition(detection, RESULT_DETECTED, trigger);
        }
        for detection in &disappeared {
            self.audit_scan_transition(detection, RESULT_CLEARED, trigger);
        }

        // 2. Let the drain see those events before any detection ledger
        //    exists, so the references are held rather than dropped.
        if !appeared.is_empty() || !disappeared.is_empty() {
            self.ledger.drain_audit(&now);
        }

        // 3. Persist the transitions and open/close their ledgers.
        self.persist_detection_transitions(&appeared, &disappeared, &now);

        // 4. The alert engine sees the whole live set, because the
        //    anti-nag rule is a statement about the set.
        self.reconcile_alerts(&now);

        // 5. The M8 ledger's own event-driven update point: this pass
        //    already walked /proc, so the cgroup sample is one extra file
        //    per active session. No timer is involved anywhere (6.3).
        let active = self.active_facts();
        let ledger_changed = self.ledger.refresh(&active, &now);
        let active_ids: Vec<String> = active.iter().map(|f| f.session_id.clone()).collect();
        let pruned = self.ledger.prune(&now, &active_ids);
        for (reason, count) in pruned.batches() {
            // One event per batch, naming the count — never one per file
            // (spec 6.4).
            self.audit(self.service_event(EventFacts {
                action: ACTION_LEDGER_PRUNE,
                agent: &format!("{RESOURCE_LEDGER}:{count}"),
                session_id: AGENT_SESSION_NONE,
                project: PROJECT_ID_SYSTEM,
                decision: Decision::Allow,
                result: reason,
            }));
        }
        let detections_pruned = self.prune_detections(&now);

        if registry_changed {
            self.publish_summary();
        } else if ledger_changed || !pruned.is_empty() || detections_pruned {
            // The registry did not change but the ledger did — republish
            // the panel's side file so the pane and the socket cannot
            // show different ledgers.
            self.publish_ledger_view();
        } else if !self.cfg.agents_file.exists() {
            // First pass of this boot: publish even with nothing to say,
            // so the panel reads a fresh empty view rather than a stale one.
            self.publish_summary();
        }
        registry_changed || ledger_changed || !pruned.is_empty() || detections_pruned
    }

    /// One `agents.scan` transition event. `resource` carries the agent
    /// name **and** the trigger, because `audit-event.json` has no field
    /// for a trigger and the M8 Decision-0 law says a shipped schema does
    /// not grow one for a later milestone. The composite is the same idiom
    /// M8 already uses for `ledger:<count>` on a prune batch.
    fn audit_scan_transition(&self, detection: &Detection, result: &str, trigger: ScanTrigger) {
        self.audit(self.service_event(EventFacts {
            action: ACTION_SCAN,
            agent: &format!("{}:{}", detection.record.agent, trigger.as_str()),
            session_id: &detection.record.session_id,
            project: &detection.record.project,
            decision: Decision::Allow,
            result,
        }));
    }

    /// Append the schema-exact records, update the sibling index, and
    /// open or close each detection's ledger. Writes only on a
    /// transition — an unchanged pass never reaches this function with
    /// anything to do.
    fn persist_detection_transitions(
        &self,
        appeared: &[Detection],
        disappeared: &[Detection],
        now: &str,
    ) {
        if appeared.is_empty() && disappeared.is_empty() {
            return;
        }
        {
            let mut index = self.detection_index.lock().unwrap();
            for detection in appeared {
                if let Err(e) = self.detections.append(&detection.record) {
                    eprintln!(
                        "punar-agentd: FAILED to persist the detected record for {}: {e}",
                        detection.record.session_id
                    );
                    continue;
                }
                index.rows.insert(
                    detection.record.session_id.clone(),
                    DetectionIndexRow {
                        detection_id: detection.record.session_id.clone(),
                        signature_id: detection.signature_id.clone(),
                        signature: detection.signature_name.clone(),
                        executable: detection.executable.clone(),
                        zone: detection.zone.to_string(),
                        user: detection.record.user.clone(),
                        observed_at: detection.observed_at.clone(),
                        cleared_at: None,
                        retention_expires_at: None,
                    },
                );
            }
            for detection in disappeared {
                let mut ended = detection.record.clone();
                ended.status = AgentStatus::Ended;
                if let Err(e) = self.detections.append(&ended) {
                    eprintln!(
                        "punar-agentd: FAILED to persist the cleared record for {}: {e}",
                        ended.session_id
                    );
                }
                if let Some(row) = index.rows.get_mut(&detection.record.session_id) {
                    crate::detections::clear_row(row, now);
                }
            }
            index.updated_at = now.to_string();
        }
        self.write_detection_index();

        // Ledgers second: `begin_detection` writes once, applying the
        // reference the drain in step 2 is already holding.
        for detection in appeared {
            self.ledger.begin_detection(
                &DetectionFacts {
                    detection_id: detection.record.session_id.clone(),
                    agent: detection.record.agent.clone(),
                    user: detection.record.user.clone(),
                    process_id: detection.record.process_id,
                    zone: detection.zone,
                    started_at: detection.record.started_at.clone(),
                },
                now,
            );
        }
        for detection in disappeared {
            self.ledger.end_detection(&detection.record.session_id, now);
        }
    }

    /// Retention for the detection **transition log** (7 days after a
    /// detection clears). The ledger records themselves are pruned by the
    /// M8 machinery, which already reads each record's own
    /// `retention_expires_at`.
    ///
    /// Checking costs an in-memory scan of the index; it writes only when
    /// something actually expired, so the steady state stays at zero
    /// bytes.
    fn prune_detections(&self, now: &str) -> bool {
        let expired = {
            let index = self.detection_index.lock().unwrap();
            crate::detections::expired(&index, now)
        };
        if expired.is_empty() {
            return false;
        }
        let keep = {
            let mut index = self.detection_index.lock().unwrap();
            for id in &expired {
                index.rows.remove(id);
            }
            index.updated_at = now.to_string();
            index
                .rows
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<String>>()
        };
        if let Err(e) = self.detections.rewrite_keeping(&keep) {
            eprintln!("punar-agentd: could not compact the detection log: {e}");
        }
        self.write_detection_index();
        self.audit(self.service_event(EventFacts {
            action: ACTION_LEDGER_PRUNE,
            agent: &format!("detections:{}", expired.len()),
            session_id: AGENT_SESSION_NONE,
            project: PROJECT_ID_SYSTEM,
            decision: Decision::Allow,
            result: "expired",
        }));
        true
    }

    /// Drop the persisted detection records (and index rows) for ids the
    /// user just purged. Silent when none of the targets is a detection —
    /// a managed session's purge touches nothing here.
    fn purge_detection_records(&self, targets: &[String], now: &str) {
        let keep = {
            let mut index = self.detection_index.lock().unwrap();
            let mut removed = 0usize;
            for id in targets {
                if index.rows.remove(id).is_some() {
                    removed += 1;
                }
            }
            if removed == 0 {
                return;
            }
            index.updated_at = now.to_string();
            index
                .rows
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<String>>()
        };
        if let Err(e) = self.detections.rewrite_keeping(&keep) {
            eprintln!("punar-agentd: could not compact the detection log after a purge: {e}");
        }
        self.write_detection_index();
    }

    fn write_detection_index(&self) {
        let index = self.detection_index.lock().unwrap().clone();
        if let Err(e) = self.detections.write_index(&index) {
            eprintln!("punar-agentd: could not write the detection index: {e}");
        }
    }

    /// Run the anti-nag rule over the current **unknown** detection set,
    /// audit each raise once, and write `alerts.json` only if the alert
    /// set changed.
    ///
    /// Only `unknown` detections raise a card. An `observed` detection is
    /// a *known* agent product running outside the managed runtime — the
    /// D-005 panel shows it, and putting it behind a card that reads
    /// "Unknown AI activity suspected" would be false (spec 1.22). It
    /// still gets a persisted record and a ledger, because the question
    /// "what ran on this device last week" is the same question.
    fn reconcile_alerts(&self, now: &str) {
        let citation = self.citation.citation();
        let live: Vec<Observation> = {
            let registry = self.registry.lock().unwrap();
            registry
                .detections()
                .filter(|detection| detection.record.classification == AgentClassification::Unknown)
                .map(|detection| Observation {
                    signature_id: detection.signature_id.clone(),
                    signature: detection.signature_name.clone(),
                    detection_id: detection.record.session_id.clone(),
                    agent: detection.record.agent.clone(),
                    executable: detection.executable.clone(),
                    owner: detection.record.user.clone(),
                    owner_uid: detection.owner_uid,
                })
                .collect()
        };
        let change = self.alerts.reconcile(&live, &citation, now);
        for row in &change.raised {
            self.audit(self.service_event(EventFacts {
                action: ACTION_ALERT_RAISE,
                agent: &format!("{}:{}", row.agent, row.signature),
                session_id: &row.detection_id,
                project: PROJECT_ID_SYSTEM,
                decision: Decision::Allow,
                result: RESULT_RAISED,
            }));
        }
        if change.changed {
            self.alerts.write(now);
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
            self.close_ledger(&session_id);
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
        let scanned_at = self.last_scan.lock().unwrap().changed_at.clone();
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
        // The ledger's own side file, written at the same points and for
        // the same sessions — so the panel's Ledger register and
        // `agents.json` can never disagree about which sessions exist.
        // It is `0640 root:punar` in the root-owned agentd runtime
        // directory: `agents.json` stays world-readable and carries no
        // ledger identifiers.
        self.publish_ledger_view();
    }

    /// Rewrite `/run/punar-agentd/ledger.json` for exactly the sessions
    /// `agents.json` lists, so the two side files always describe the
    /// same set.
    fn publish_ledger_view(&self) {
        let session_ids: Vec<String> = {
            let registry = self.registry.lock().unwrap();
            registry
                .sessions()
                .map(|session| session.record.session_id.clone())
                // Since M10 the current detections belong here too: the
                // two side files must describe the same set, and a
                // detection now has a ledger to describe.
                .chain(
                    registry
                        .detections()
                        .map(|detection| detection.record.session_id.clone()),
                )
                .collect()
        };
        self.ledger
            .write_runtime_view(&session_ids, &utc_now_rfc3339());
    }

    /// Compact and close a session's ledger, then republish. Called from
    /// both `agents.end` and the reaper: a session that died with its
    /// launcher gets the same final sample as one that was ended
    /// cleanly.
    fn close_ledger(&self, session_id: &str) {
        let Some(facts) = self.facts_of(session_id) else {
            return;
        };
        let now = utc_now_rfc3339();
        self.ledger.end_session(&facts, &now);
        self.publish_ledger_view();
        let active_ids: Vec<String> = self
            .active_facts()
            .iter()
            .map(|f| f.session_id.clone())
            .collect();
        let pruned = self.ledger.prune(&now, &active_ids);
        for (reason, count) in pruned.batches() {
            self.audit(self.service_event(EventFacts {
                action: ACTION_LEDGER_PRUNE,
                agent: &format!("{RESOURCE_LEDGER}:{count}"),
                session_id: AGENT_SESSION_NONE,
                project: PROJECT_ID_SYSTEM,
                decision: Decision::Allow,
                result: reason,
            }));
        }
    }

    /// One ledger audit event. `resource` is the session id (or `own`),
    /// `agent_session_id` the real `agt_` id when the action is scoped to
    /// one session.
    fn audit_ledger(
        &self,
        peer: &Peer,
        action: &str,
        resource: &str,
        session_id: &str,
        decision: Decision,
        result: &str,
    ) {
        self.audit(self.human_event(
            peer,
            EventFacts {
                action,
                agent: resource,
                session_id,
                project: PROJECT_ID_SYSTEM,
                decision,
                result,
            },
        ));
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

/// The registry session, as the ledger needs it (source **D**). One
/// place so `agent` and `project` cannot be swapped at a call site.
fn session_facts(session: &Session) -> SessionFacts {
    SessionFacts {
        session_id: session.record.session_id.clone(),
        agent: session.record.agent.clone(),
        user: session.record.user.clone(),
        project: session.record.project.clone(),
        classification: session.record.classification,
        process_id: session.record.process_id,
        scope_path: session.scope_path.clone(),
        started_at: session.record.started_at.clone(),
    }
}

fn to_value<T: serde::Serialize>(value: T) -> Value {
    serde_json::to_value(value).unwrap_or_else(|e| json!({ "serialization_error": e.to_string() }))
}
