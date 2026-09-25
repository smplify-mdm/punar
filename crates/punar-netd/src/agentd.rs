//! Authoritative managed-session snapshot from `punar-agentd`.
//!
//! `/run/punar/agents.json` is only a doorbell. This client asks the data
//! owner over its root-owned socket, then re-proves every active managed
//! session's live cgroup from procfs before it can reach nft generation.

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use punar_common::agent::{
    AGENTD_SOCKET_PATH, AgentMethod, AgentRequest, AgentStatus, AgentsListResult,
    LedgerNetworkParams, LedgerNetworkResult,
};
use punar_common::ipc::{Response, ResponseBody};
use thiserror::Error;

use crate::model::{
    validate_cgroup_path, validate_project_id, validate_session_id, validate_user_name,
};
use crate::view::ManagedSession;

pub const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum AgentdError {
    #[error("punar-agentd transport failed at {stage}: {source}")]
    Transport {
        stage: &'static str,
        source: io::Error,
    },
    #[error("punar-agentd closed the connection without answering")]
    EmptyResponse,
    #[error("punar-agentd returned malformed protocol data: {0}")]
    Protocol(String),
    #[error("punar-agentd refused the typed request with {code}: {message}")]
    Refused { code: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedSession {
    pub session_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub sessions: Vec<ManagedSession>,
    pub skipped: Vec<SkippedSession>,
}

#[derive(Debug, Clone)]
pub struct AgentdClient {
    socket: PathBuf,
    proc_root: PathBuf,
    timeout: Duration,
}

impl AgentdClient {
    pub fn production() -> Self {
        Self {
            socket: PathBuf::from(AGENTD_SOCKET_PATH),
            proc_root: PathBuf::from("/proc"),
            timeout: SNAPSHOT_TIMEOUT,
        }
    }

    pub fn new(socket: PathBuf, proc_root: PathBuf, timeout: Duration) -> Self {
        Self {
            socket,
            proc_root,
            timeout,
        }
    }

    pub fn snapshot(&self) -> Result<SessionSnapshot, AgentdError> {
        let result: AgentsListResult = self.call(AgentMethod::List, "agents")?;
        Ok(snapshot_from_list(result, &self.proc_root))
    }

    /// Publish an absolute, privacy-bounded destination aggregate. The
    /// agentd socket independently enforces root peer credentials and its
    /// ResourceClass boundary; this typed client is not an authorization
    /// shortcut.
    pub fn publish_network(
        &self,
        params: LedgerNetworkParams,
    ) -> Result<LedgerNetworkResult, AgentdError> {
        self.call(AgentMethod::LedgerNetwork(params), "network")
    }

    fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: AgentMethod,
        suffix: &str,
    ) -> Result<T, AgentdError> {
        let stream =
            UnixStream::connect(&self.socket).map_err(|source| AgentdError::Transport {
                stage: "connect",
                source,
            })?;
        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));
        let request = AgentRequest {
            id: format!("netd-{}-{suffix}", std::process::id()),
            method,
        };
        let mut writer = &stream;
        writer
            .write_all(request.to_json_line().as_bytes())
            .map_err(|source| AgentdError::Transport {
                stage: "send",
                source,
            })?;
        let mut line = String::new();
        let mut reader = BufReader::new(&stream);
        if reader
            .read_line(&mut line)
            .map_err(|source| AgentdError::Transport {
                stage: "receive",
                source,
            })?
            == 0
        {
            return Err(AgentdError::EmptyResponse);
        }
        decode_response(&line)
    }
}

fn decode_response<T: serde::de::DeserializeOwned>(line: &str) -> Result<T, AgentdError> {
    let response = Response::parse_json_line(line)
        .map_err(|error| AgentdError::Protocol(error.to_string()))?;
    if response.v != punar_common::ipc::PROTOCOL_VERSION {
        return Err(AgentdError::Protocol(format!(
            "unsupported response version {}",
            response.v
        )));
    }
    match response.body {
        ResponseBody::Result(value) => {
            serde_json::from_value(value).map_err(|error| AgentdError::Protocol(error.to_string()))
        }
        ResponseBody::Error(error) => Err(AgentdError::Refused {
            code: error.code.to_string(),
            message: error.message,
        }),
    }
}

fn snapshot_from_list(list: AgentsListResult, proc_root: &Path) -> SessionSnapshot {
    let mut sessions = Vec::new();
    let mut skipped = Vec::new();
    for listed in list.sessions {
        let record = listed.record;
        if record.status != AgentStatus::Active || record.classification.as_str() != "managed" {
            continue;
        }
        let result = (|| {
            validate_session_id(&record.session_id).map_err(|error| error.to_string())?;
            validate_project_id(&record.project).map_err(|error| error.to_string())?;
            validate_user_name(&record.user).map_err(|error| error.to_string())?;
            let cgroup_path = managed_scope_path(proc_root, record.process_id, &record.session_id)?
                .ok_or_else(|| {
                    "the root process is not in its registered managed scope".to_string()
                })?;
            Ok::<_, String>(ManagedSession {
                session_id: record.session_id.clone(),
                project_id: record.project,
                user: record.user,
                process_id: record.process_id,
                cgroup_id: cgroup_id(proc_root, &cgroup_path),
                uid: scope_owner_uid(&cgroup_path)
                    .or_else(|| process_uid(proc_root, record.process_id)),
                cgroup_path,
            })
        })();
        match result {
            Ok(session) => sessions.push(session),
            Err(reason) => skipped.push(SkippedSession {
                session_id: record.session_id,
                reason,
            }),
        }
    }
    sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
    skipped.sort_by(|left, right| left.session_id.cmp(&right.session_id));
    SessionSnapshot { sessions, skipped }
}

/// Whose session this is, from the scope's own place in the cgroup tree: the
/// `user-<uid>.slice` systemd made for that person, as the FIRST component
/// under `/user.slice` (F0 review). The path was just read from the kernel
/// and checked to hold this session's scope, and a person can create
/// cgroups only below their own delegated subtree — never a sibling
/// `user-<other>.slice` at that depth — so this names the owner for as long
/// as the scope exists, even after the process agentd registered has exited
/// and its children run on. `None` for a scope outside any user slice.
fn scope_owner_uid(cgroup_path: &str) -> Option<u32> {
    let mut components = cgroup_path.strip_prefix('/')?.split('/');
    if components.next()? != "user.slice" {
        return None;
    }
    let slice = components.next()?;
    let uid = slice.strip_prefix("user-")?.strip_suffix(".slice")?;
    (!uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()))
        .then(|| uid.parse().ok())
        .flatten()
}

/// The real uid of `pid`, from the kernel's own status file — the fallback
/// for a scope outside any user slice. `None` when it cannot be read; the
/// caller then shows that session's rows to root only.
fn process_uid(proc_root: &Path, pid: u32) -> Option<u32> {
    let status = fs::read_to_string(proc_root.join(pid.to_string()).join("status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().next())
        .and_then(|real| real.parse().ok())
}

fn cgroup_id(proc_root: &Path, cgroup_path: &str) -> Option<u64> {
    if proc_root != Path::new("/proc") {
        return None;
    }
    let relative = cgroup_path.strip_prefix('/')?;
    fs::metadata(Path::new("/sys/fs/cgroup").join(relative))
        .ok()
        .map(|metadata| metadata.ino())
        .filter(|id| *id != 0)
}

/// Read the live unified-cgroup path for `pid` and require one path component
/// to equal this session's scope unit. Substring matching would let a scope
/// such as `punar-agent-agt_good.scope-evil` impersonate the real one.
pub fn managed_scope_path(
    proc_root: &Path,
    pid: u32,
    session_id: &str,
) -> Result<Option<String>, String> {
    validate_session_id(session_id).map_err(|error| error.to_string())?;
    if pid == 0 {
        return Err("pid must be nonzero".to_string());
    }
    let body = match fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup")) {
        Ok(body) => body,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not read process cgroup: {error}")),
    };
    let unit = format!("punar-agent-{session_id}.scope");
    for line in body.lines() {
        let Some(path) = line.strip_prefix("0::") else {
            continue;
        };
        if path.split('/').any(|component| component == unit) {
            validate_cgroup_path(path).map_err(|error| error.to_string())?;
            return Ok(Some(path.to_string()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use punar_common::agent::{AgentClassification, ListedSession, RegistryRecord, ScanTrigger};
    use serde_json::json;

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "punar-netd-agentd-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn list(record: RegistryRecord) -> AgentsListResult {
        AgentsListResult {
            scanned_at: "2026-08-29T00:00:00Z".into(),
            last_scan_at: "2026-08-29T00:00:00Z".into(),
            last_scan_trigger: ScanTrigger::Manual,
            changed: None,
            sessions: vec![ListedSession::bare(record)],
            detections: vec![],
        }
    }

    fn record() -> RegistryRecord {
        RegistryRecord {
            session_id: "agt_4f21c09ab3e1".into(),
            agent: "claude-code".into(),
            version: "1".into(),
            process_id: 42,
            user: "punar".into(),
            project: "atlas".into(),
            environment: "host".into(),
            status: AgentStatus::Active,
            classification: AgentClassification::Managed,
            started_at: "2026-08-29T00:00:00Z".into(),
        }
    }

    #[test]
    fn only_exact_live_managed_scope_components_are_admitted() {
        let root = root();
        fs::create_dir_all(root.join("42")).unwrap();
        fs::write(
            root.join("42/cgroup"),
            "0::/user.slice/punar-agent-agt_4f21c09ab3e1.scope/child\n",
        )
        .unwrap();
        let snapshot = snapshot_from_list(list(record()), &root);
        assert_eq!(snapshot.sessions.len(), 1);
        assert!(snapshot.skipped.is_empty());
        // No status file: whose session it is stays unknown, and its rows
        // go to root only.
        assert_eq!(snapshot.sessions[0].uid, None);
        // The owner is the kernel's real uid of the root process, never the
        // name agentd was told.
        fs::write(
            root.join("42/status"),
            "Name:\tclaude\nUid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\n",
        )
        .unwrap();
        let snapshot = snapshot_from_list(list(record()), &root);
        assert_eq!(snapshot.sessions[0].uid, Some(1001));
        // F0 review: a scope in a person's slice names its owner from the
        // tree itself, so a registered process that has exited (no status
        // file) still leaves its session its owner's — never withheld as a
        // stranger's.
        fs::remove_file(root.join("42/status")).unwrap();
        fs::write(
            root.join("42/cgroup"),
            "0::/user.slice/user-1002.slice/user@1002.service/app.slice/\
punar-agent-agt_4f21c09ab3e1.scope\n",
        )
        .unwrap();
        let snapshot = snapshot_from_list(list(record()), &root);
        assert_eq!(snapshot.sessions[0].uid, Some(1002));
        fs::write(
            root.join("42/cgroup"),
            "0::/user.slice/punar-agent-agt_4f21c09ab3e1.scope-evil\n",
        )
        .unwrap();
        let snapshot = snapshot_from_list(list(record()), &root);
        assert!(snapshot.sessions.is_empty());
        assert_eq!(snapshot.skipped.len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ended_or_observed_sessions_never_become_enforcement_bindings() {
        let root = root();
        let mut ended = record();
        ended.status = AgentStatus::Ended;
        assert!(snapshot_from_list(list(ended), &root).sessions.is_empty());
        let mut observed = record();
        observed.classification = AgentClassification::Observed;
        assert!(
            snapshot_from_list(list(observed), &root)
                .sessions
                .is_empty()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn typed_success_and_error_frames_are_distinguished() {
        let result = serde_json::to_value(list(record())).unwrap();
        let response = Response::result("netd-1", result).to_json_line();
        assert_eq!(
            decode_response::<AgentsListResult>(&response)
                .unwrap()
                .sessions
                .len(),
            1
        );
        let response = Response::error(
            Some("netd-1".into()),
            punar_common::ipc::IpcError::new(punar_common::ipc::ErrorCode::Denied, "not allowed"),
        )
        .to_json_line();
        assert!(matches!(
            decode_response::<AgentsListResult>(&response),
            Err(AgentdError::Refused { code, .. }) if code == "denied"
        ));
        assert!(decode_response::<AgentsListResult>(&json!({"v": 1}).to_string()).is_err());
    }

    /// Only systemd's own slice at the top of the user tree names an owner:
    /// a `user-<n>.slice` a person made deeper in their delegated subtree
    /// never does.
    #[test]
    fn the_scope_owner_is_the_top_user_slice_and_nothing_deeper() {
        assert_eq!(
            scope_owner_uid(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/punar-agent-x.scope"
            ),
            Some(1000)
        );
        assert_eq!(
            scope_owner_uid(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/user-0.slice/x.scope"
            ),
            Some(1000)
        );
        assert_eq!(scope_owner_uid("/system.slice/user-0.slice/x.scope"), None);
        assert_eq!(scope_owner_uid("/user.slice/punar-agent-x.scope"), None);
        assert_eq!(scope_owner_uid("/user.slice/user-.slice/x"), None);
        assert_eq!(scope_owner_uid("/user.slice/user-10a0.slice/x"), None);
        assert_eq!(scope_owner_uid("user.slice/user-1000.slice/x"), None);
    }
}
