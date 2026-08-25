//! The `punar-secrets` daemon: a UDS NDJSON server for the closed
//! `credential.*` table (docs/api/ipc.md section 16), the mock provider
//! behind it, and the audit events it writes.
//!
//! # Same mechanics as punard, third socket
//!
//! Framing, envelope, versioning, timeouts, error codes and the
//! bind-before-listen permission dance are `punar_common::ipc` and the M3
//! `punard` pattern verbatim. Threading is the same frugal shape: no async
//! runtime, a std accept loop, one thread per connection, a hard connection
//! cap, and per-connection memory bounded by the 4096-byte line limit.
//!
//! # No background work at all
//!
//! Between requests this daemon does *nothing*: no timer, no sweep, no
//! `/proc` polling (SPEC section 6.3). Credential expiry is computed when a
//! token is presented (`crate::store`), and the approval engine is dialled
//! only inside a `credential.request` on a `request`-policy class. Idle CPU
//! is zero and idle disk is zero — there is no state file to rewrite,
//! because there is no state directory.
//!
//! # What this daemon will never have
//!
//! No exec, no shell, no script method, and no method that returns an
//! issued token a second time (SPEC sections 10, 60; ipc.md section 16.2).

use std::io::{self, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use punar_common::audit::{
    AGENT_SESSION_NONE, AuditActor, AuditWriter, PROJECT_ID_SYSTEM, next_event_id,
};
use punar_common::ipc::{
    ErrorCode, IpcError, LineRead, MAX_REQUEST_LINE_BYTES, Response, SERVER_READ_TIMEOUT,
    read_line_bounded,
};
use punar_common::time::{unix_now_millis, utc_now_rfc3339};
use punar_common::{AuditEvent, Decision, PrincipalKind};
use serde_json::{Value, json};

use crate::approvals::{ApprovalClient, ApprovalError, CreateArgs};
use crate::attribution::{Peer, PeerSource, agent_session_of_peer};
use crate::classes::{
    ATTESTATION_SIMULATED, ClassCatalog, CredentialClass, PROVIDER_MOCK, class_id_ok,
};
use crate::policy::{AiPolicySet, CredentialGrant, credential_denied_message};
use crate::protocol::{
    ACTION_CREDENTIAL_EXPIRE, ACTION_CREDENTIAL_REQUEST, ACTION_CREDENTIAL_REVOKE,
    AI_DEFAULTS_PATH, AI_POLICY_DIR, CLASSES_PATH, CredentialMethod, CredentialRequestParams,
    CredentialRevokeParams, CredentialValidateParams, RESULT_DENIED, RESULT_EXPIRED,
    RESULT_ISSUANCE_FLOOD, RESULT_ISSUED, RESULT_PENDING, RESULT_REVOKED,
    RESULT_UPSTREAM_UNREACHABLE, SECRETS_SOCKET_PATH, SecretsRequest,
};
use crate::store::{FillBytes, IssueError, Presented, TokenStore, system_entropy};
use crate::util::{lookup_gid, username_or_uid};

/// Daemon configuration. Every path is injectable so the whole daemon runs
/// inside a tempdir under test — including `/proc`, which is what makes
/// agent attribution testable.
#[derive(Debug, Clone)]
pub struct SecretsConfig {
    pub socket_path: PathBuf,
    /// The credential-class catalog (data, not code).
    pub classes_path: PathBuf,
    /// The shipped AI authority document.
    pub ai_defaults_path: PathBuf,
    /// Organization AI authority layers, when a device has any.
    pub ai_policy_dir: PathBuf,
    /// The **shared** audit trail (ipc.md section 10.4). The broker's only
    /// disk writes go here.
    pub audit_path: PathBuf,
    /// punard's state directory — read-only, for the device id.
    pub state_dir: PathBuf,
    /// punard's socket: the approval engine.
    pub punard_socket: PathBuf,
    /// `/proc` in production, a fixture tree in tests.
    pub proc_root: PathBuf,
    pub group: String,
    pub group_file: PathBuf,
    pub passwd_file: PathBuf,
    pub peer_source: PeerSource,
    pub max_connections: usize,
    pub io_timeout: Duration,
    /// Token entropy source. The production value is
    /// [`system_entropy`] (`getrandom(2)`); tests substitute a
    /// deterministic filler. Not reachable from the CLI.
    pub entropy: FillBytes,
    /// Wall clock, in Unix seconds. [`Clock::System`] in production;
    /// tests substitute [`Clock::Fixed`] so that TTL expiry is proven
    /// **without** sleeping through a real TTL. Not reachable from the
    /// CLI — a daemon whose clock could be set from outside would be a
    /// daemon whose expiries could be, too.
    pub clock: Clock,
}

impl SecretsConfig {
    /// Everything derived from a socket path, an audit path and a data
    /// root — test-safe by construction.
    pub fn new(
        socket_path: PathBuf,
        classes_path: PathBuf,
        ai_defaults_path: PathBuf,
        audit_path: PathBuf,
    ) -> SecretsConfig {
        SecretsConfig {
            socket_path,
            classes_path,
            ai_defaults_path,
            ai_policy_dir: PathBuf::from(AI_POLICY_DIR),
            audit_path,
            state_dir: PathBuf::from("/var/lib/punar"),
            punard_socket: PathBuf::from(crate::approvals::PUNARD_SOCKET_PATH),
            proc_root: PathBuf::from("/proc"),
            group: "punar".to_string(),
            group_file: PathBuf::from("/etc/group"),
            passwd_file: PathBuf::from("/etc/passwd"),
            peer_source: PeerSource::SoPeercred,
            max_connections: 16,
            io_timeout: SERVER_READ_TIMEOUT,
            entropy: system_entropy,
            clock: Clock::System,
        }
    }

    /// The production contract paths (ipc.md section 16.1).
    pub fn production() -> SecretsConfig {
        SecretsConfig::new(
            PathBuf::from(SECRETS_SOCKET_PATH),
            PathBuf::from(CLASSES_PATH),
            PathBuf::from(AI_DEFAULTS_PATH),
            PathBuf::from(punar_common::audit::AUDIT_LOG_PATH),
        )
    }
}

struct Inner {
    cfg: SecretsConfig,
    catalog: ClassCatalog,
    policy: AiPolicySet,
    /// The whole persistent state of this daemon: an in-memory map that
    /// holds hashes, and dies with the process.
    store: Mutex<TokenStore>,
    audit: Mutex<AuditWriter>,
    approvals: ApprovalClient,
    /// punard's device id, read lazily — the broker never creates it.
    device_id: Mutex<Option<String>>,
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
    /// Load the catalog and the AI authority documents, open the audit
    /// trail — all **before** the socket exists, so the first request meets
    /// a fully-formed broker or none at all. A catalog or defaults document
    /// that cannot be trusted refuses start rather than serving a
    /// half-understood policy.
    pub fn new(cfg: SecretsConfig) -> io::Result<Daemon> {
        let catalog = ClassCatalog::load(&cfg.classes_path)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let policy = AiPolicySet::load(&cfg.ai_defaults_path, &cfg.ai_policy_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        for warning in &policy.warnings {
            eprintln!("punar-secrets: {warning}");
        }
        if let Some(parent) = cfg.audit_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let audit = AuditWriter::open(&cfg.audit_path)?;
        if let Some(gid) = lookup_gid(&cfg.group_file, &cfg.group) {
            // Group ownership of the shared trail (root:punar), the same
            // best-effort chown both other daemons do.
            let _ = std::os::unix::fs::chown(&cfg.audit_path, Some(0), Some(gid));
        }
        let approvals = ApprovalClient::new(cfg.punard_socket.clone());
        let store = TokenStore::new(cfg.entropy);

        Ok(Daemon {
            inner: Arc::new(Inner {
                catalog,
                policy,
                store: Mutex::new(store),
                audit: Mutex::new(audit),
                approvals,
                device_id: Mutex::new(None),
                shutdown: AtomicBool::new(false),
                active: Mutex::new(0),
                slot_freed: Condvar::new(),
                cfg,
            }),
        })
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
            .name("punar-secrets-accept".to_string())
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
    ///
    /// Every live token dies here, and that is the correct behaviour for a
    /// short-lived credential: the broker holds no state that could
    /// outlive it, so a restart cannot resurrect an authorization.
    pub fn stop(self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner.slot_freed.notify_all();
        let _ = UnixStream::connect(&self.inner.cfg.socket_path);
        let _ = self.accept_thread.join();
        let _ = std::fs::remove_file(&self.inner.cfg.socket_path);
    }
}

/// socket + bind + perms + listen, in that order (ipc.md sections 1.2,
/// 16.1). rustix keeps this free of `unsafe`; `UnixListener::bind` would
/// listen before permissions could be fixed.
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
                    .name("punar-secrets-conn".to_string())
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
                eprintln!("punar-secrets: accept failed: {e}");
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
            eprintln!("punar-secrets: could not read peer credentials: {e}");
            return;
        }
    };
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("punar-secrets: could not clone connection stream: {e}");
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
                         Policy: os default — punar-secrets bounds request size \
                         (docs/api/ipc.md sections 2, 16.1).\n\
                         Next step: no credential.* request needs more; use punarctl."
                    ),
                );
                let _ = write_response(&mut stream, &Response::error(None, err));
                break;
            }
            Ok(LineRead::Line(line)) => match SecretsRequest::parse_json_line(&line) {
                Ok(request) => {
                    let id = request.id.clone();
                    let response = match inner.dispatch(&peer, request.method) {
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

/// Who is asking, resolved once per request.
struct Requester {
    /// Audit attribution (`user_id` + `source` + `agent_session_id`).
    actor: AuditActor,
    /// The human this request belongs to (the approval is routed here).
    user: String,
    /// `agt_…` when the peer's cgroup proved a managed agent session.
    agent_session_id: Option<String>,
    uid: u32,
}

impl Requester {
    /// The principal that appears on an approval: the agent when there is
    /// one, otherwise the person.
    fn principal(&self) -> (PrincipalKind, &str) {
        match self.agent_session_id.as_deref() {
            Some(id) => (PrincipalKind::AiAgent, id),
            None => (PrincipalKind::Human, self.user.as_str()),
        }
    }

    /// The label used in prose (`agt_…` or the username).
    fn label(&self) -> &str {
        self.principal().1
    }
}

impl Inner {
    fn dispatch(&self, peer: &Peer, method: CredentialMethod) -> Result<Value, IpcError> {
        match method {
            CredentialMethod::Status => Ok(self.handle_status()),
            CredentialMethod::Classes => Ok(self.handle_classes()),
            CredentialMethod::Request(params) => self.handle_request(peer, &params),
            CredentialMethod::Validate(params) => self.handle_validate(peer, &params),
            CredentialMethod::Revoke(params) => self.handle_revoke(peer, &params),
        }
    }

    // -- reads ----------------------------------------------------------

    fn handle_status(&self) -> Value {
        let now = self.cfg.clock.now();
        let store = self.store.lock().unwrap();
        json!({
            "protocol": punar_common::ipc::PROTOCOL_VERSION,
            "provider": PROVIDER_MOCK,
            "attestation": ATTESTATION_SIMULATED,
            "classes": self.catalog.classes.len(),
            "issued": store.live(now),
            "persisted": false,
            "approval_engine": self.approvals.socket().display().to_string(),
        })
    }

    fn handle_classes(&self) -> Value {
        let classes: Vec<Value> = self
            .catalog
            .classes
            .iter()
            .map(|class| {
                let authority = self.policy.credential_decision(&class.policy_key);
                json!({
                    "id": class.id,
                    "display": class.display,
                    "risk": class.risk.as_str(),
                    "default_ttl": class.default_ttl,
                    "max_ttl": class.max_ttl,
                    "decision": authority.grant.as_str(),
                    "policy": {
                        "name": authority.policy_name,
                        "policy_id": authority.policy_id,
                    },
                })
            })
            .collect();
        json!({
            "provider": PROVIDER_MOCK,
            "attestation": ATTESTATION_SIMULATED,
            "classes": classes,
        })
    }

    // -- credential.request ---------------------------------------------

    fn handle_request(
        &self,
        peer: &Peer,
        params: &CredentialRequestParams,
    ) -> Result<Value, IpcError> {
        let requester = self.requester(peer);
        let Some(class) = self.catalog.get(&params.credential) else {
            return Err(self.unknown_class(&params.credential));
        };
        let authority = self.policy.credential_decision(&class.policy_key);

        match authority.grant {
            CredentialGrant::Deny => {
                // Audit first: the message quotes the event id, so the
                // sentence the agent reads and the line in the trail are
                // the same fact (Plate D-012 section II.03).
                let event_id = self.audit(
                    &requester.actor,
                    ACTION_CREDENTIAL_REQUEST,
                    &class.id,
                    Decision::Deny,
                    RESULT_DENIED,
                    std::slice::from_ref(&authority.policy_id),
                );
                Err(IpcError::with_details(
                    ErrorCode::Denied,
                    credential_denied_message(class, &authority, requester.label(), &event_id),
                    json!({
                        "decision": "deny",
                        "credential": class.id,
                        "policy_ids": [authority.policy_id],
                    }),
                ))
            }
            CredentialGrant::Allow => {
                self.issue(class, params.ttl, &requester, &authority.policy_id, None)
            }
            CredentialGrant::Request => self.gated_request(class, params, &requester, &authority),
        }
    }

    /// The `request` policy path: spend an approved approval if there is
    /// one, otherwise raise a new approval and issue **nothing**.
    fn gated_request(
        &self,
        class: &CredentialClass,
        params: &CredentialRequestParams,
        requester: &Requester,
        authority: &crate::policy::CredentialAuthority,
    ) -> Result<Value, IpcError> {
        let (kind, requester_id) = requester.principal();
        let candidates = match self.approvals.candidates(&class.id, requester_id) {
            Ok(candidates) => candidates,
            Err(err) => return Err(self.upstream_failure(class, requester, authority, err)),
        };

        for candidate in candidates {
            match self.approvals.consume(&candidate.approval_id) {
                Ok(_consumed_at) => {
                    return self.issue(
                        class,
                        params.ttl,
                        requester,
                        &authority.policy_id,
                        Some(&candidate.approval_id),
                    );
                }
                // `conflict` (already spent) and `expired` mean this
                // approval is not usable; try the next, then fall through
                // to raising a fresh one. Single use is enforced by the
                // engine, not by this loop.
                Err(ApprovalError::Refused(_)) => continue,
                Err(err) => return Err(self.upstream_failure(class, requester, authority, err)),
            }
        }

        let created = match self.approvals.create(&CreateArgs {
            credential: &class.id,
            display: &class.display,
            risk: class.risk,
            user: &requester.user,
            requester_kind: kind,
            requester_id,
            requester_uid: requester.uid,
            agent_session_id: requester.agent_session_id.as_deref(),
            policy_name: &authority.policy_name,
            policy_id: &authority.policy_id,
            requested_ttl: params.ttl,
        }) {
            Ok(created) => created,
            Err(ApprovalError::Refused(err)) => {
                // The engine refused to even record the request — an
                // approval flood, most likely. Its message is already in
                // the section 73 voice; pass it through rather than
                // paraphrasing a policy this daemon does not own.
                self.audit(
                    &requester.actor,
                    ACTION_CREDENTIAL_REQUEST,
                    &class.id,
                    Decision::Deny,
                    RESULT_DENIED,
                    std::slice::from_ref(&authority.policy_id),
                );
                return Err(err);
            }
            Err(err) => return Err(self.upstream_failure(class, requester, authority, err)),
        };

        let event_id = self.audit(
            &requester.actor,
            ACTION_CREDENTIAL_REQUEST,
            &class.id,
            Decision::ApprovalRequired,
            RESULT_PENDING,
            std::slice::from_ref(&authority.policy_id),
        );
        Err(IpcError::with_details(
            ErrorCode::ApprovalRequired,
            format!(
                "A {} credential needs a person to approve it.\n\
                 Nothing has been issued: the request is waiting as {} and expires at {}.\n\
                 Policy: {} ({}) — this credential class is issued on approval, and a \
                 human answers.\n\
                 Requested by: {}\n\
                 Recorded: {event_id}\n\
                 Next step: answer it in the approval overlay, or run \
                 `punarctl approvals wait {}`.",
                class.display,
                created.approval_id,
                created.expires_at,
                authority.policy_name,
                authority.policy_id,
                requester.label(),
                created.approval_id,
            ),
            json!({
                "approval_id": created.approval_id,
                "expires_at": created.expires_at,
                "capability": ACTION_CREDENTIAL_REQUEST,
                "resource": class.id,
                "credential": class.id,
                "decision": "approval_required",
                "policy_ids": [authority.policy_id],
            }),
        ))
    }

    /// The approval engine did not answer. Nothing is issued — an
    /// unreachable approval engine is never an implicit yes.
    fn upstream_failure(
        &self,
        class: &CredentialClass,
        requester: &Requester,
        authority: &crate::policy::CredentialAuthority,
        err: ApprovalError,
    ) -> IpcError {
        let event_id = self.audit(
            &requester.actor,
            ACTION_CREDENTIAL_REQUEST,
            &class.id,
            Decision::ApprovalRequired,
            RESULT_UPSTREAM_UNREACHABLE,
            std::slice::from_ref(&authority.policy_id),
        );
        eprintln!("punar-secrets: approvals unavailable: {err}");
        IpcError::with_details(
            ErrorCode::UpstreamUnreachable,
            format!(
                "A {} credential needs approval, and the approval service did not answer.\n\
                 Nothing has been issued: with no way to record a human's decision, Punar \
                 refuses rather than assuming a yes.\n\
                 Policy: {} ({}).\n\
                 Recorded: {event_id}\n\
                 Next step: check `systemctl status punard`, then ask again.",
                class.display, authority.policy_name, authority.policy_id,
            ),
            json!({
                "stage": "approvals",
                "credential": class.id,
                "policy_ids": [authority.policy_id],
            }),
        )
    }

    /// Mint a token, record the fact, hand the value over exactly once.
    fn issue(
        &self,
        class: &CredentialClass,
        requested_ttl: Option<u64>,
        requester: &Requester,
        policy_id: &str,
        approval_id: Option<&str>,
    ) -> Result<Value, IpcError> {
        let now = self.cfg.clock.now();
        let ttl = class.effective_ttl(requested_ttl);
        let issued = {
            let mut store = self.store.lock().unwrap();
            store.issue(
                class,
                ttl,
                requester.uid,
                requester.agent_session_id.as_deref(),
                now,
            )
        };
        let (token, record) = match issued {
            Ok(issued) => issued,
            Err(IssueError::NotIssuable) => {
                let event_id = self.audit(
                    &requester.actor,
                    ACTION_CREDENTIAL_REQUEST,
                    &class.id,
                    Decision::Deny,
                    RESULT_DENIED,
                    &[policy_id.to_string()],
                );
                return Err(IpcError::with_details(
                    ErrorCode::Denied,
                    format!(
                        "{} is never issued by this device.\n\
                         Policy: the credential catalog gives this class a maximum lifetime \
                         of zero seconds, which is a refusal that no policy setting can \
                         override.\n\
                         Recorded: {event_id}\n\
                         Next step: nothing to retry — this class exists so that requests \
                         for it are recorded, not fulfilled.",
                        class.display
                    ),
                    json!({"decision": "deny", "credential": class.id}),
                ));
            }
            Err(IssueError::Flood) => {
                self.audit(
                    &requester.actor,
                    ACTION_CREDENTIAL_REQUEST,
                    &class.id,
                    Decision::Deny,
                    RESULT_ISSUANCE_FLOOD,
                    &[policy_id.to_string()],
                );
                return Err(IpcError::with_details(
                    ErrorCode::Denied,
                    format!(
                        "This device is already holding {} live credentials, which is the \
                         limit.\n\
                         Policy: os default — an unbounded credential map is a local \
                         denial-of-service, so the broker refuses instead of growing.\n\
                         Next step: revoke a credential you no longer need \
                         (`punarctl secrets revoke`), or wait for one to expire.",
                        crate::store::MAX_LIVE_TOKENS
                    ),
                    json!({"decision": "deny", "credential": class.id}),
                ));
            }
            Err(IssueError::NoEntropy) => {
                return Err(IpcError::new(
                    ErrorCode::Internal,
                    "The kernel did not provide random bytes, so no credential was issued.\n\
                     Policy: os hard constraint — Punar does not fall back to a weaker \
                     source of randomness.\n\
                     Next step: this is a system fault; check the journal for punar-secrets."
                        .to_string(),
                ));
            }
        };

        // Audit before answering. If the trail cannot be written the token
        // is revoked and nothing is returned: an unrecorded credential is
        // worse than a failed request (SPEC section 53).
        let Some(event_id) = self.try_audit(
            &requester.actor,
            ACTION_CREDENTIAL_REQUEST,
            &class.id,
            Decision::Allow,
            RESULT_ISSUED,
            &[policy_id.to_string()],
        ) else {
            let mut store = self.store.lock().unwrap();
            store.revoke(&token);
            drop(token);
            return Err(IpcError::new(
                ErrorCode::Internal,
                "The credential could not be recorded in the audit trail, so it was \
                 withdrawn and nothing was issued.\n\
                 Policy: spec section 53 — a credential Punar cannot account for is not \
                 a credential Punar hands out.\n\
                 Next step: check the journal for punar-secrets, then ask again."
                    .to_string(),
            ));
        };

        let mut result = json!({
            "credential": record.credential,
            // The one place in Punar a secret is serialized (ipc.md section
            // 16.4). It is written to the response and dropped; nothing
            // persists it, and no method can produce it again.
            "value": token.expose_secret(),
            "expires_at": record.expires_at,
            "ttl": ttl,
            "provider": PROVIDER_MOCK,
            "attestation": ATTESTATION_SIMULATED,
            "audit_event_id": event_id,
        });
        if let Some(map) = result.as_object_mut() {
            if let Some(agent) = &record.agent_session_id {
                map.insert("agent_session_id".to_string(), json!(agent));
            }
            if let Some(approval_id) = approval_id {
                map.insert("approval_id".to_string(), json!(approval_id));
            }
        }
        drop(token);
        Ok(result)
    }

    // -- credential.validate / credential.revoke -------------------------

    fn handle_validate(
        &self,
        peer: &Peer,
        params: &CredentialValidateParams,
    ) -> Result<Value, IpcError> {
        let now = self.cfg.clock.now();
        let presented = {
            let mut store = self.store.lock().unwrap();
            store.present(&params.value, params.credential.as_deref(), now)
        };
        match presented {
            // A successful validate is deliberately **not** audited: it
            // reveals nothing new, and auditing every check would let any
            // local process flood the trail (SPEC section 6.4).
            Presented::Valid(record) => Ok(json!({
                "valid": true,
                "credential": record.credential,
                "expires_at": record.expires_at,
                "expires_in": record.remaining_secs(now),
                "provider": PROVIDER_MOCK,
                "attestation": ATTESTATION_SIMULATED,
            })),
            Presented::Expired(record) => {
                let requester = self.requester(peer);
                // Audited once, on the first presentation that observes
                // the lapse — the class only, never the value.
                //
                // `decision: allow` because this records a lifecycle fact,
                // not a refused authorization: recording it as a denial
                // would put a `denied_access` entry in the requester's AI
                // Access Ledger for a credential that simply grew old.
                let event_id = self.audit(
                    &requester.actor,
                    ACTION_CREDENTIAL_EXPIRE,
                    &record.credential,
                    Decision::Allow,
                    RESULT_EXPIRED,
                    &[punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string()],
                );
                Err(IpcError::with_details(
                    ErrorCode::Expired,
                    format!(
                        "That {} credential expired at {} and is no longer valid.\n\
                         Policy: os default — credentials are short-lived by design \
                         (spec section 29), and the broker has now forgotten this one.\n\
                         Recorded: {event_id}\n\
                         Next step: request a new one with \
                         `punarctl secrets get {}`.",
                        record.credential, record.expires_at, record.credential
                    ),
                    json!({
                        "credential": record.credential,
                        "expires_at": record.expires_at,
                    }),
                ))
            }
            Presented::Unknown => Err(unknown_token()),
        }
    }

    fn handle_revoke(
        &self,
        peer: &Peer,
        params: &CredentialRevokeParams,
    ) -> Result<Value, IpcError> {
        let revoked = {
            let mut store = self.store.lock().unwrap();
            store.revoke(&params.value)
        };
        let Some(record) = revoked else {
            return Err(unknown_token());
        };
        let requester = self.requester(peer);
        let event_id = self.audit(
            &requester.actor,
            ACTION_CREDENTIAL_REVOKE,
            &record.credential,
            Decision::Allow,
            RESULT_REVOKED,
            &[punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string()],
        );
        Ok(json!({
            "revoked": true,
            "credential": record.credential,
            "audit_event_id": event_id,
        }))
    }

    // -- identity, audit, prose -----------------------------------------

    fn requester(&self, peer: &Peer) -> Requester {
        let user = username_or_uid(&self.cfg.passwd_file, peer.uid);
        let agent_session_id = agent_session_of_peer(&self.cfg.proc_root, peer);
        let mut actor = AuditActor::cli_peer(user.clone());
        if let Some(session) = &agent_session_id {
            actor = actor.with_agent_session(session.clone());
        }
        Requester {
            actor,
            user,
            agent_session_id,
            uid: peer.uid,
        }
    }

    /// punard's device id, or the documented `dev_unknown` sentinel.
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

    /// Append one audit event and return its id. A write failure is logged
    /// and the id still returned — callers that must not proceed without a
    /// record use [`Inner::try_audit`].
    fn audit(
        &self,
        actor: &AuditActor,
        action: &str,
        resource: &str,
        decision: Decision,
        result: &str,
        policy_ids: &[String],
    ) -> String {
        self.write_event(actor, action, resource, decision, result, policy_ids)
            .0
    }

    /// The same append, but `None` when the event could not be written.
    fn try_audit(
        &self,
        actor: &AuditActor,
        action: &str,
        resource: &str,
        decision: Decision,
        result: &str,
        policy_ids: &[String],
    ) -> Option<String> {
        let (event_id, written) =
            self.write_event(actor, action, resource, decision, result, policy_ids);
        written.then_some(event_id)
    }

    fn write_event(
        &self,
        actor: &AuditActor,
        action: &str,
        resource: &str,
        decision: Decision,
        result: &str,
        policy_ids: &[String],
    ) -> (String, bool) {
        // Built by hand rather than through the M3 builders because the
        // citation is policy-dependent here: a credential decision may come
        // from an org layer, and `policy_ids` must name the layer that
        // actually decided (SPEC section 53).
        let event = AuditEvent {
            event_id: next_event_id(),
            timestamp: utc_now_rfc3339(),
            device_id: self.device_id(),
            user_id: Some(actor.user_id.clone()),
            agent_session_id: Some(
                actor
                    .agent_session_id
                    .clone()
                    .unwrap_or_else(|| AGENT_SESSION_NONE.to_string()),
            ),
            project_id: Some(PROJECT_ID_SYSTEM.to_string()),
            source: actor.source,
            action: action.to_string(),
            // The class name, and only ever the class name (ipc.md 16.3).
            resource: Some(resource.to_string()),
            decision,
            policy_ids: policy_ids.to_vec(),
            result: result.to_string(),
        };
        let event_id = event.event_id.clone();
        let written = match self.audit.lock().unwrap().append(&event) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("punar-secrets: audit append failed: {e}");
                false
            }
        };
        (event_id, written)
    }

    /// The answer to a class name this catalog does not carry.
    ///
    /// **The one place a caller-authored string could be quoted back**, so
    /// it is quoted back only when it is *shaped like a class id*
    /// ([`class_id_ok`]: `^[a-z][a-z0-9-]*$`, at most 64 bytes). The
    /// mistake this guards is ordinary and entirely plausible — swapping
    /// the arguments of `punarctl secrets get`, or piping a value where a
    /// name belongs — and Punar's own CLI writes this message to stderr,
    /// which a script may be capturing to a file. A token is not id-shaped
    /// (base64url carries uppercase and `_`), so the two cases separate
    /// cleanly, and SPEC section 53 settles which way to fail: name the
    /// mistake, never repeat the value, not even to explain it. The same
    /// rule the secret-bearing params parser already follows
    /// ([`crate::protocol::parse_secret_params`]).
    fn unknown_class(&self, requested: &str) -> IpcError {
        let known = self.catalog.ids().join(", ");
        if !class_id_ok(requested) {
            return IpcError::with_details(
                ErrorCode::NotFound,
                format!(
                    "That is not a credential class name, and Punar is not going to \
                     repeat it back.\n\
                     Policy: os default — a class id is kebab-case ({} bytes arrived, \
                     which is not that shape), and a string that is not a name may well \
                     be a value that was piped where a name belongs (SPEC section 53).\n\
                     Next step: this device can issue: {known}. The value goes on \
                     stdin, never in an argument.",
                    requested.len()
                ),
                json!({ "credential_shape": "not_a_class_id" }),
            );
        }
        IpcError::with_details(
            ErrorCode::NotFound,
            format!(
                "This device has no credential class named {requested:?}.\n\
                 Policy: the catalog is data \
                 (/usr/share/punar/secrets/classes.yaml) — a class that is not listed \
                 does not exist, and the broker does not invent one.\n\
                 Next step: this device can issue: {known}."
            ),
            json!({ "credential": requested }),
        )
    }
}

/// A source of wall-clock seconds.
///
/// An enum rather than a function pointer because a test clock has to be
/// *per-daemon* state: the daemon reads the clock on its own connection
/// threads, and a process-global test clock would make concurrently
/// running tests move each other's expiries. [`Clock::Fixed`] is not
/// reachable from the CLI — only code constructing a [`SecretsConfig`]
/// directly (the tests) can select it, so a shipped daemon always reads
/// the real clock.
#[derive(Debug, Clone)]
pub enum Clock {
    /// The wall clock (production).
    System,
    /// A clock the test moves by hand, so TTL expiry is proven without
    /// sleeping through a real TTL.
    Fixed(Arc<std::sync::atomic::AtomicU64>),
}

impl Clock {
    /// Unix seconds now.
    pub fn now(&self) -> u64 {
        match self {
            Clock::System => now_secs(),
            Clock::Fixed(secs) => secs.load(Ordering::SeqCst),
        }
    }
}

/// Wall-clock seconds since the Unix epoch.
///
/// `punar_common::time` exposes milliseconds (audit event ids) and RFC 3339
/// formatting; credential expiry is a whole-second comparison, so the
/// conversion lives here rather than widening the shared module for one
/// caller. A clock beyond `u64` seconds saturates instead of wrapping,
/// which makes every token look expired — the fail-closed direction.
fn now_secs() -> u64 {
    u64::try_from(unix_now_millis() / 1000).unwrap_or(u64::MAX)
}

/// The answer to a token this broker does not know. **Not audited** — see
/// [`Presented::Unknown`].
fn unknown_token() -> IpcError {
    IpcError::new(
        ErrorCode::NotFound,
        "That credential is not one this device is holding.\n\
         Policy: os default — the broker keeps only a hash of each live credential and \
         forgets it at expiry, at revocation and at restart, so an unknown value has no \
         history to report.\n\
         Next step: request a fresh credential with `punarctl secrets get <class>`."
            .to_string(),
    )
}
