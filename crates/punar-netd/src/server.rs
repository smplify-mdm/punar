//! Bounded NDJSON Unix-socket server for the closed network method table.

use std::io::{self, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use punar_common::audit::{AuditActor, AuditOutcome, AuditWriter};
use punar_common::ipc::{
    ErrorCode, IpcError, LineRead, MAX_REQUEST_LINE_BYTES, Response, SERVER_READ_TIMEOUT,
    read_line_bounded,
};
use punar_common::network::{NetworkMethod, NetworkRequest};
use punar_common::{AuditEvent, Decision};
use serde_json::{Value, json};

use crate::peer::{Peer, PeerSource};
use crate::runtime::{
    DenialEvent, ReconcileResult, Runtime, RuntimeError, SessionTransition, SessionTransitionKind,
};
use crate::util::{lookup_gid, username_or_uid};
use crate::watch;

pub const ACTION_NETWORK_APPLY: &str = "network.apply";
pub const ACTION_NETWORK_DENY: &str = "network.deny";
pub const ACTION_RELAY_SET: &str = "relay.set";
pub const DEVICE_ID_UNKNOWN: &str = "dev_unknown";

#[derive(Debug, Clone)]
pub struct NetdConfig {
    pub socket_path: PathBuf,
    pub audit_path: PathBuf,
    pub device_id_path: PathBuf,
    pub passwd_file: PathBuf,
    pub group_file: PathBuf,
    pub group: String,
    pub console_uid: u32,
    pub peer_source: PeerSource,
    pub max_connections: usize,
    pub io_timeout: Duration,
    /// Display-only file used solely as an inotify doorbell. `None` disables
    /// the watcher in isolated tests; production always supplies it.
    pub agent_doorbell: Option<PathBuf>,
    pub watch_wake_root: PathBuf,
}

impl NetdConfig {
    pub fn production() -> Self {
        Self {
            socket_path: PathBuf::from(punar_common::network::NETD_SOCKET_PATH),
            audit_path: PathBuf::from(punar_common::audit::AUDIT_LOG_PATH),
            device_id_path: PathBuf::from("/var/lib/punar/device-id"),
            passwd_file: PathBuf::from("/etc/passwd"),
            group_file: PathBuf::from("/etc/group"),
            group: "punar".into(),
            // The installer provisions the first interactive account at
            // uid 1000. This stays injectable so a future multi-seat source
            // can replace the single-console MVP assumption without
            // changing authorization code.
            console_uid: 1000,
            peer_source: PeerSource::SoPeercred,
            max_connections: 32,
            io_timeout: SERVER_READ_TIMEOUT,
            agent_doorbell: Some(PathBuf::from(punar_common::agent::AGENTS_SUMMARY_PATH)),
            watch_wake_root: PathBuf::from("/run/punar-netd"),
        }
    }
}

struct Inner {
    runtime: Mutex<Runtime>,
    audit: Mutex<AuditWriter>,
    device_id: String,
    cfg: NetdConfig,
    shutdown: AtomicBool,
    active: Mutex<usize>,
    slot_freed: Condvar,
}

pub struct Daemon {
    inner: Arc<Inner>,
}

pub struct DaemonHandle {
    inner: Arc<Inner>,
    accept_thread: JoinHandle<()>,
    watch_thread: Option<JoinHandle<()>>,
}

impl Daemon {
    pub fn new(cfg: NetdConfig, runtime: Runtime) -> io::Result<Self> {
        if let Some(parent) = cfg.audit_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let audit = AuditWriter::open(&cfg.audit_path)?;
        let device_id = read_device_id(&cfg.device_id_path);
        let daemon = Self {
            inner: Arc::new(Inner {
                runtime: Mutex::new(runtime),
                audit: Mutex::new(audit),
                device_id,
                cfg,
                shutdown: AtomicBool::new(false),
                active: Mutex::new(0),
                slot_freed: Condvar::new(),
            }),
        };
        // Reconcile before accepting clients. A failure remains visible in
        // status and does not masquerade as enforcement success.
        if let Err(error) = daemon.inner.reconcile_from_signal() {
            eprintln!("punar-netd: startup policy apply failed: {error}");
        }
        Ok(daemon)
    }

    pub fn spawn(self) -> io::Result<DaemonHandle> {
        let inner = self.inner;
        let gid = lookup_gid(&inner.cfg.group_file, &inner.cfg.group).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("admission group {:?} does not exist", inner.cfg.group),
            )
        })?;
        let listener = bind_with_perms(&inner.cfg.socket_path, gid)?;
        let accept_inner = Arc::clone(&inner);
        let accept_thread = std::thread::Builder::new()
            .name("punar-netd-accept".into())
            .spawn(move || accept_loop(accept_inner, listener))?;
        let watch_thread = inner.cfg.agent_doorbell.as_deref().and_then(|doorbell| {
            let stop_inner = Arc::clone(&inner);
            let change_inner = Arc::clone(&inner);
            watch::spawn_watch(
                doorbell,
                &inner.cfg.watch_wake_root,
                move || stop_inner.shutdown.load(Ordering::SeqCst),
                move || {
                    if let Err(error) = change_inner.reconcile_from_signal() {
                        eprintln!("punar-netd: session-change reconciliation failed: {error}");
                    }
                },
            )
        });
        // Registering the watch and immediately catching up closes the race
        // between startup reconciliation and watch establishment.
        if inner.cfg.agent_doorbell.is_some()
            && let Err(error) = inner.reconcile_from_signal()
        {
            eprintln!("punar-netd: post-watch reconciliation failed: {error}");
        }
        Ok(DaemonHandle {
            inner,
            accept_thread,
            watch_thread,
        })
    }
}

impl DaemonHandle {
    pub fn socket_path(&self) -> &Path {
        &self.inner.cfg.socket_path
    }

    pub fn stop(self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner.slot_freed.notify_all();
        watch::wake(&self.inner.cfg.watch_wake_root);
        let _ = UnixStream::connect(&self.inner.cfg.socket_path);
        let _ = self.accept_thread.join();
        if let Some(thread) = self.watch_thread {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.inner.cfg.socket_path);
    }
}

fn read_device_id(path: &Path) -> String {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| {
            value.strip_prefix("dev_").is_some_and(|rest| {
                !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric())
            })
        })
        .unwrap_or_else(|| DEVICE_ID_UNKNOWN.to_string())
}

fn bind_with_perms(path: &Path, gid: u32) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    use rustix::net::{AddressFamily, SocketType, bind, listen, socket};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750))?;
        require_group(parent, gid)?;
    }
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let fd = socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    let address = rustix::net::SocketAddrUnix::new(path)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    bind(&fd, &address)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    require_group(path, gid)?;
    listen(&fd, 16)?;
    Ok(UnixListener::from(fd))
}

fn require_group(path: &Path, expected_gid: u32) -> io::Result<()> {
    let actual_gid = std::fs::metadata(path)?.gid();
    if actual_gid != expected_gid {
        std::os::unix::fs::chown(path, None, Some(expected_gid))?;
    }
    let actual_gid = std::fs::metadata(path)?.gid();
    if actual_gid != expected_gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} has gid {actual_gid}, expected admission gid {expected_gid}",
                path.display()
            ),
        ));
    }
    Ok(())
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
            Ok((stream, _)) => {
                if inner.shutdown.load(Ordering::SeqCst) {
                    break;
                }
                *inner.active.lock().unwrap() += 1;
                let connection = Arc::clone(&inner);
                if std::thread::Builder::new()
                    .name("punar-netd-conn".into())
                    .spawn(move || {
                        handle_connection(&connection, stream);
                        *connection.active.lock().unwrap() -= 1;
                        connection.slot_freed.notify_all();
                    })
                    .is_err()
                {
                    *inner.active.lock().unwrap() -= 1;
                }
            }
            Err(error) => {
                if inner.shutdown.load(Ordering::SeqCst) {
                    break;
                }
                eprintln!("punar-netd: accept failed: {error}");
            }
        }
    }
}

fn handle_connection(inner: &Inner, mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(inner.cfg.io_timeout));
    let _ = stream.set_write_timeout(Some(inner.cfg.io_timeout));
    let peer = match inner.cfg.peer_source.peer_of(&stream) {
        Ok(peer) => peer,
        Err(error) => {
            eprintln!("punar-netd: peer credentials unavailable: {error}");
            return;
        }
    };
    let reader_stream = match stream.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let mut reader = BufReader::with_capacity(MAX_REQUEST_LINE_BYTES, reader_stream);
    loop {
        match read_line_bounded(&mut reader, MAX_REQUEST_LINE_BYTES) {
            Ok(LineRead::Eof) => break,
            Ok(LineRead::TooLong) => {
                let error = IpcError::new(
                    ErrorCode::MalformedRequest,
                    format!(
                        "The request exceeded the {MAX_REQUEST_LINE_BYTES}-byte limit. Next step: use punarctl; no network method needs a larger request."
                    ),
                );
                let _ = write_response(&mut stream, &Response::error(None, error));
                break;
            }
            Ok(LineRead::Line(line)) => match NetworkRequest::parse_json_line(&line) {
                Ok(request) => {
                    let result = inner.dispatch(peer, &request);
                    let response = match result {
                        Ok(value) => Response::result(request.id, value),
                        Err(error) => Response::error(Some(request.id), error),
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
            Err(_) => break,
        }
    }
}

fn write_response(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    stream.write_all(response.to_json_line().as_bytes())?;
    stream.flush()
}

impl Inner {
    fn reconcile_from_signal(&self) -> Result<(), RuntimeError> {
        let (outcome, should_observe, pass_denials) = {
            let mut runtime = self.runtime.lock().unwrap();
            let outcome = runtime.reconcile()?;
            let should_observe = !outcome.transitions.is_empty();
            let pass_denials = if should_observe {
                match runtime.connections() {
                    Ok(pass) => pass.denial_events,
                    Err(error) => {
                        eprintln!("punar-netd: transition observation failed: {error}");
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            };
            (outcome, should_observe, pass_denials)
        };
        self.audit_transitions(&outcome);
        self.audit_network_denials(outcome.denial_events.iter().chain(pass_denials.iter()));
        if should_observe {
            eprintln!(
                "punar-netd: reconciled {} managed-session transition(s)",
                outcome.transitions.len()
            );
        }
        Ok(())
    }

    fn audit_transitions(&self, outcome: &ReconcileResult) {
        if outcome.transitions.is_empty() {
            return;
        }
        let mut audit = self.audit.lock().unwrap();
        for transition in &outcome.transitions {
            let event = transition_event(&self.device_id, transition);
            if let Err(error) = audit.append(&event) {
                eprintln!("punar-netd: could not audit session transition: {error}");
            }
        }
    }

    fn audit_network_denials<'a>(&self, events: impl IntoIterator<Item = &'a DenialEvent>) {
        let actor = AuditActor::daemon();
        let mut audit = self.audit.lock().unwrap();
        for denial in events {
            // Audit is deliberately destination-free because it is not
            // user-purgeable. Zone + closed kind are sufficient for the
            // Level-4 ledger reference and the policy explanation.
            let mut event =
                AuditEvent::denial(&self.device_id, &actor, ACTION_NETWORK_DENY, &denial.zone);
            event.agent_session_id = Some(denial.session_id.clone());
            event.project_id = Some(denial.project.clone());
            event.result = match denial.kind {
                crate::model::ZoneKind::Production => "denied_production",
                crate::model::ZoneKind::Privileged => "denied_privileged",
                crate::model::ZoneKind::Internet | crate::model::ZoneKind::Corporate => "denied",
            }
            .to_string();
            if let Err(error) = audit.append(&event) {
                eprintln!("punar-netd: could not audit network denial: {error}");
            }
        }
    }

    fn dispatch(&self, peer: Peer, request: &NetworkRequest) -> Result<Value, IpcError> {
        match &request.method {
            NetworkMethod::Status => Ok(self.runtime.lock().unwrap().status_json()),
            NetworkMethod::Connections => {
                let pass = self
                    .runtime
                    .lock()
                    .unwrap()
                    .connections()
                    .map_err(runtime_error)?;
                self.audit_network_denials(pass.denial_events.iter());
                serde_json::to_value(pass.result).map_err(|error| internal(error.to_string()))
            }
            NetworkMethod::Zones => Ok(self.runtime.lock().unwrap().zones_json()),
            NetworkMethod::Policy(params) => self
                .runtime
                .lock()
                .unwrap()
                .policy_json(&params.project)
                .map_err(runtime_error),
            NetworkMethod::Explain(params) => self
                .runtime
                .lock()
                .unwrap()
                .explain_json(&params.project, &params.zone)
                .map_err(runtime_error),
            NetworkMethod::Apply(params) => {
                if !peer.is_root() {
                    self.audit_denial(
                        peer,
                        ACTION_NETWORK_APPLY,
                        params.project.as_deref().unwrap_or("all"),
                    );
                    return Err(denied(
                        "Applying network policy requires root because it changes the kernel nftables table. Next step: run `sudo punarctl network apply`.",
                    ));
                }
                let resource = params.project.as_deref().unwrap_or("all");
                let (result, pass_denials) = {
                    let mut runtime = self.runtime.lock().unwrap();
                    let result = runtime.reconcile();
                    let pass_denials = if result.is_ok() {
                        // Applying policy is one of M12's explicit on-demand
                        // observation triggers. Enforcement has already
                        // reached the kernel at this point, so a failed
                        // display/ledger refresh stays loud in the journal
                        // without falsely reporting that the nft transaction
                        // itself failed.
                        match runtime.connections() {
                            Ok(pass) => pass.denial_events,
                            Err(error) => {
                                eprintln!("punar-netd: post-apply observation failed: {error}");
                                Vec::new()
                            }
                        }
                    } else {
                        Vec::new()
                    };
                    (result, pass_denials)
                };
                if let Ok(outcome) = &result {
                    self.audit_transitions(outcome);
                    self.audit_network_denials(
                        outcome.denial_events.iter().chain(pass_denials.iter()),
                    );
                }
                self.audit_outcome(
                    peer,
                    ACTION_NETWORK_APPLY,
                    resource,
                    if result.is_ok() {
                        AuditOutcome::Success
                    } else {
                        AuditOutcome::Failure
                    },
                );
                let result = result.map_err(runtime_error)?.applied;
                serde_json::to_value(result).map_err(|error| internal(error.to_string()))
            }
            NetworkMethod::RelayStatus => {
                serde_json::to_value(self.runtime.lock().unwrap().relay_status())
                    .map_err(|error| internal(error.to_string()))
            }
            NetworkMethod::RelaySet(params) => {
                if !peer.is_root() && peer.uid != self.cfg.console_uid {
                    self.audit_denial(peer, ACTION_RELAY_SET, relay_name(params.mode));
                    return Err(denied(
                        "Changing the personal relay preference is limited to the signed-in console user or root. Next step: sign in locally, or ask the device owner to change it.",
                    ));
                }
                let result = self.runtime.lock().unwrap().set_relay(params.mode);
                self.audit_outcome(
                    peer,
                    ACTION_RELAY_SET,
                    relay_name(params.mode),
                    if result.is_ok() {
                        AuditOutcome::Success
                    } else {
                        AuditOutcome::Failure
                    },
                );
                serde_json::to_value(result.map_err(runtime_error)?)
                    .map_err(|error| internal(error.to_string()))
            }
        }
    }

    fn audit_denial(&self, peer: Peer, action: &str, resource: &str) {
        let actor = self.actor(peer);
        let event = AuditEvent::denial(&self.device_id, &actor, action, resource);
        let _ = self.audit.lock().unwrap().append(&event);
    }

    fn audit_outcome(&self, peer: Peer, action: &str, resource: &str, outcome: AuditOutcome) {
        let actor = self.actor(peer);
        let event = AuditEvent::action(
            &self.device_id,
            &actor,
            action,
            resource,
            Decision::Allow,
            outcome,
        );
        let _ = self.audit.lock().unwrap().append(&event);
    }

    fn actor(&self, peer: Peer) -> AuditActor {
        AuditActor::cli_peer(username_or_uid(&self.cfg.passwd_file, peer.uid))
    }
}

fn transition_event(device_id: &str, transition: &SessionTransition) -> AuditEvent {
    // The daemon observed and enforced the lifecycle change; the agent is
    // implicated, but is not falsely named as the actor that wrote the event.
    let actor = AuditActor::daemon();
    let action = match transition.kind {
        SessionTransitionKind::Attached => "network.session_attach",
        SessionTransitionKind::Detached => "network.session_detach",
    };
    let mut event = AuditEvent::action(
        device_id,
        &actor,
        action,
        transition.reason,
        Decision::Allow,
        AuditOutcome::Success,
    );
    event.agent_session_id = Some(transition.session_id.clone());
    event.project_id = Some(transition.project.clone());
    event
}

fn relay_name(mode: punar_common::network::RelayPreference) -> &'static str {
    match mode {
        punar_common::network::RelayPreference::Direct => "direct",
        punar_common::network::RelayPreference::PrivateRelay => "private_relay",
    }
}

fn runtime_error(error: RuntimeError) -> IpcError {
    match error {
        RuntimeError::ProjectNotActive(project) => IpcError::with_details(
            ErrorCode::NotFound,
            format!(
                "No active managed session uses project {project:?}, so there is no authoritative workspace policy to show. Next step: launch the project agent, then retry."
            ),
            json!({"project": project}),
        ),
        RuntimeError::EnforcementUnavailable(reason) => IpcError::with_details(
            ErrorCode::ApplyFailed,
            format!(
                "Network policy was declared but could not be installed because cgroup-v2 nftables matching is unavailable: {reason}. Next step: check `punarctl network status` and the kernel nft_socket support."
            ),
            json!({"reason": reason}),
        ),
        RuntimeError::Agentd(error) => IpcError::with_details(
            ErrorCode::UpstreamUnreachable,
            format!(
                "The authoritative AI session registry could not be reached: {error}. No session attribution was guessed. Next step: check `systemctl status punar-agentd.service`."
            ),
            json!({"upstream": "punar-agentd"}),
        ),
        RuntimeError::Exec(error) => IpcError::with_details(
            ErrorCode::ApplyFailed,
            format!(
                "The nftables transaction did not apply: {error}. Existing kernel policy was left intact. Next step: check `punarctl network status` and the punar-netd journal."
            ),
            json!({"backend": "nftables"}),
        ),
        other => internal(format!(
            "The network service could not complete the request: {other}. Next step: check `systemctl status punar-netd.service`."
        )),
    }
}

fn denied(message: &str) -> IpcError {
    IpcError::new(ErrorCode::Denied, message)
}

fn internal(message: String) -> IpcError {
    IpcError::new(ErrorCode::Internal, message)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicU64, Ordering};

    use punar_common::agent::{AgentsListResult, ScanTrigger};

    use crate::agentd::AgentdClient;
    use crate::model::{RelayMode, ZoneDefinition, ZoneKind};
    use crate::nft_exec::NftExecutor;
    use crate::policy::index_zones;
    use crate::project::ProjectLocator;
    use crate::relay::RelayStore;
    use crate::runtime::{NetworkData, RuntimeInputs};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "punar-netd-server-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn empty_agentd(socket: PathBuf) -> JoinHandle<()> {
        let listener = UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            assert!(request.contains("\"method\":\"agents.list\""));
            let list = AgentsListResult {
                scanned_at: "2026-08-29T00:00:00Z".into(),
                last_scan_at: "2026-08-29T00:00:00Z".into(),
                last_scan_trigger: ScanTrigger::Manual,
                changed: None,
                sessions: vec![],
                detections: vec![],
            };
            let response = Response::result("netd-agents", serde_json::to_value(list).unwrap());
            stream
                .write_all(response.to_json_line().as_bytes())
                .unwrap();
        })
    }

    fn call(stream: &mut UnixStream, id: &str, method: &str, params: Option<Value>) -> Value {
        let mut request = json!({"v": 1, "id": id, "method": method});
        if let Some(params) = params {
            request["params"] = params;
        }
        writeln!(stream, "{request}").unwrap();
        stream.flush().unwrap();
        let mut response = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut response)
            .unwrap();
        serde_json::from_str(&response).unwrap()
    }

    #[test]
    fn device_id_reader_never_emits_schema_invalid_data() {
        let root = std::env::temp_dir().join(format!("punar-netd-device-{}", std::process::id()));
        let _ = std::fs::remove_file(&root);
        assert_eq!(read_device_id(&root), DEVICE_ID_UNKNOWN);
        std::fs::write(&root, "../../secret\n").unwrap();
        assert_eq!(read_device_id(&root), DEVICE_ID_UNKNOWN);
        std::fs::write(&root, "dev_123abc\n").unwrap();
        assert_eq!(read_device_id(&root), "dev_123abc");
        std::fs::remove_file(root).unwrap();
    }

    #[test]
    fn runtime_errors_keep_unavailable_and_not_found_distinct() {
        assert_eq!(
            runtime_error(RuntimeError::ProjectNotActive("atlas".into())).code,
            ErrorCode::NotFound
        );
        assert_eq!(
            runtime_error(RuntimeError::EnforcementUnavailable("unsupported".into())).code,
            ErrorCode::ApplyFailed
        );
    }

    #[test]
    fn real_socket_enforces_auth_closed_methods_permissions_and_audit() {
        let root = root();
        let agentd_socket = root.join("agentd.sock");
        let agentd_thread = empty_agentd(agentd_socket.clone());
        let transaction_dir = root.join("transactions");
        std::fs::create_dir_all(&transaction_dir).unwrap();
        std::fs::set_permissions(&transaction_dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        let nft = root.join("nft");
        std::fs::write(
            &nft,
            "#!/bin/sh\nif [ \"$1\" = -j ]; then printf '%s\\n' '{\"nftables\":[]}'; fi\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&nft, std::fs::Permissions::from_mode(0o755)).unwrap();
        let trusted = std::fs::metadata(&transaction_dir).unwrap();
        let trusted_uid = trusted.uid();
        let trusted_gid = trusted.gid();
        let passwd = root.join("passwd");
        let group = root.join("group");
        std::fs::write(
            &passwd,
            format!("punar:x:1000:1000:Punar:{}:/bin/bash\n", root.display()),
        )
        .unwrap();
        std::fs::write(&group, format!("punar:x:{trusted_gid}:punar\n")).unwrap();
        let zones = index_zones(vec![ZoneDefinition {
            name: "internet".into(),
            display_name: Some("Internet".into()),
            description: None,
            kind: ZoneKind::Internet,
            relay_mode: Some(RelayMode::Direct),
        }])
        .unwrap();
        let runtime = Runtime::new(RuntimeInputs {
            data: NetworkData {
                zones,
                memberships: BTreeMap::new(),
            },
            agentd: AgentdClient::new(agentd_socket, root.join("proc"), Duration::from_secs(1)),
            projects: ProjectLocator::new(passwd.clone()),
            nft: NftExecutor::new(nft, transaction_dir, trusted_uid, Duration::from_secs(1)),
            proc_root: root.join("proc"),
            connections_file: root.join("run/connections.json"),
            relay: RelayStore::open(root.join("state/relay.json")).unwrap(),
            deny_log: None,
            status_file: root.join("status.json"),
        });
        let socket = root.join("run/netd.sock");
        let audit = root.join("audit.jsonl");
        let device_id = root.join("device-id");
        std::fs::write(&device_id, "dev_test1\n").unwrap();
        let config = NetdConfig {
            socket_path: socket.clone(),
            audit_path: audit.clone(),
            device_id_path: device_id,
            passwd_file: passwd,
            group_file: group,
            group: "punar".into(),
            console_uid: 1000,
            peer_source: PeerSource::Fixed(Peer::user(1000)),
            max_connections: 4,
            io_timeout: Duration::from_secs(1),
            agent_doorbell: None,
            watch_wake_root: root.join("watch"),
        };
        let handle = Daemon::new(config, runtime).unwrap().spawn().unwrap();
        agentd_thread.join().unwrap();
        assert_eq!(
            std::fs::metadata(socket.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o660
        );
        assert_eq!(
            std::fs::metadata(socket.parent().unwrap()).unwrap().gid(),
            trusted_gid
        );
        assert_eq!(std::fs::metadata(&socket).unwrap().gid(), trusted_gid);
        let mut stream = UnixStream::connect(&socket).unwrap();
        let status = call(&mut stream, "1", "network.status", None);
        assert_eq!(status["result"]["enforcement"]["state"], "available");
        let capture = call(&mut stream, "2", "network.capture", None);
        assert_eq!(capture["error"]["code"], "unknown_method");
        let apply = call(&mut stream, "3", "network.apply", Some(json!({})));
        assert_eq!(apply["error"]["code"], "denied");
        let relay = call(
            &mut stream,
            "4",
            "relay.set",
            Some(json!({"mode": "private_relay"})),
        );
        assert_eq!(relay["result"]["mode"], "private_relay");
        assert_eq!(relay["result"]["simulated"], true);
        assert!(
            relay["result"]["property_not_held"]
                .as_str()
                .unwrap()
                .contains("same process")
        );
        drop(stream);
        handle.stop();
        let audit_body = std::fs::read_to_string(audit).unwrap();
        let events: Vec<Value> = audit_body
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(events.iter().any(|event| {
            event["action"] == "network.apply"
                && event["decision"] == "deny"
                && event["result"] == "denied"
        }));
        assert!(events.iter().any(|event| {
            event["action"] == "relay.set"
                && event["decision"] == "allow"
                && event["result"] == "success"
        }));
        assert!(!audit_body.contains("destination"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
