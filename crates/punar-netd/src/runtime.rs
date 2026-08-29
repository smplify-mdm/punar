//! Event-driven coordinator for policy apply and on-demand observation.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

use crate::agentd::{AgentdClient, AgentdError, SessionSnapshot, SkippedSession};
use crate::model::{Decision, ZoneDefinition, ZoneMembership};
use crate::nft::{NftError, SessionBinding, render_table};
use crate::nft_exec::{EnforcementCapability, ExecError, NftExecutor};
use crate::observe::{ObserveError, observe};
use crate::policy::{PolicyError, index_zones, parse_zone_memberships};
use crate::project::{ProjectLocator, deny_all};
use crate::view::{ConnectionReport, ViewError, build_report};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("network data could not be loaded: {0}")]
    Data(String),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Agentd(#[from] AgentdError),
    #[error(transparent)]
    Nft(#[from] NftError),
    #[error(transparent)]
    Exec(#[from] ExecError),
    #[error(transparent)]
    Observe(#[from] ObserveError),
    #[error(transparent)]
    View(#[from] ViewError),
    #[error("network policy enforcement is unavailable: {0}")]
    EnforcementUnavailable(String),
    #[error("connection side-file write failed: {0}")]
    SideFile(io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyWarning {
    pub session_id: String,
    pub project: String,
    pub fallback: &'static str,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyResult {
    pub installed_sessions: usize,
    pub skipped_sessions: Vec<SkippedSessionView>,
    pub warnings: Vec<ApplyWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedSessionView {
    pub session_id: String,
    pub reason: String,
}

impl From<SkippedSession> for SkippedSessionView {
    fn from(value: SkippedSession) -> Self {
        Self {
            session_id: value.session_id,
            reason: value.reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementStatus {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub installed_sessions: usize,
}

pub struct Runtime {
    pub zones: BTreeMap<String, ZoneDefinition>,
    pub memberships: BTreeMap<String, ZoneMembership>,
    agentd: AgentdClient,
    projects: ProjectLocator,
    nft: NftExecutor,
    proc_root: PathBuf,
    connections_file: PathBuf,
    capability: EnforcementCapability,
    last_apply: Option<ApplyResult>,
}

#[derive(Debug, Clone)]
pub struct NetworkData {
    pub zones: BTreeMap<String, ZoneDefinition>,
    pub memberships: BTreeMap<String, ZoneMembership>,
}

impl Runtime {
    pub fn new(
        zones: BTreeMap<String, ZoneDefinition>,
        memberships: BTreeMap<String, ZoneMembership>,
        agentd: AgentdClient,
        projects: ProjectLocator,
        nft: NftExecutor,
        proc_root: PathBuf,
        connections_file: PathBuf,
    ) -> Self {
        let capability = nft.probe_cgroup_v2();
        Self {
            zones,
            memberships,
            agentd,
            projects,
            nft,
            proc_root,
            connections_file,
            capability,
            last_apply: None,
        }
    }

    pub fn enforcement_status(&self) -> EnforcementStatus {
        let installed_sessions = self
            .last_apply
            .as_ref()
            .map_or(0, |result| result.installed_sessions);
        match &self.capability {
            EnforcementCapability::Available => EnforcementStatus {
                state: "available",
                reason: None,
                installed_sessions,
            },
            EnforcementCapability::Unavailable { reason } => EnforcementStatus {
                state: "unavailable",
                reason: Some(reason.clone()),
                installed_sessions: 0,
            },
        }
    }

    pub fn apply(&mut self) -> Result<ApplyResult, RuntimeError> {
        if let EnforcementCapability::Unavailable { reason } = &self.capability {
            return Err(RuntimeError::EnforcementUnavailable(reason.clone()));
        }
        let snapshot = self.agentd.snapshot()?;
        let (bindings, warnings) =
            compile_bindings(&snapshot, &self.zones, &self.memberships, &self.projects);
        let ruleset = render_table(true, &self.zones, &self.memberships, &bindings)?;
        self.nft.apply_checked(&ruleset)?;
        let result = ApplyResult {
            installed_sessions: bindings.len(),
            skipped_sessions: snapshot.skipped.into_iter().map(Into::into).collect(),
            warnings,
        };
        self.last_apply = Some(result.clone());
        Ok(result)
    }

    pub fn connections(&self) -> Result<ConnectionReport, RuntimeError> {
        let snapshot = self.agentd.snapshot()?;
        let observation = observe(&self.proc_root)?;
        let report = build_report(
            observation,
            &self.zones,
            &self.memberships,
            &snapshot.sessions,
        )?;
        write_report_if_changed(&self.connections_file, &report).map_err(RuntimeError::SideFile)?;
        Ok(report)
    }

    pub fn status_json(&self) -> Value {
        json!({
            "enforcement": self.enforcement_status(),
            "relay": {"mode": "direct", "simulated": false},
            "dns_protection": {"state": "not_configured", "milestone": "phase_2"},
            "observation": {
                "transport": "tcp",
                "udp_quic": "not_observed",
                "content_inspection": false,
                "dns_logging": false
            }
        })
    }
}

pub fn load_network_data(
    zones_dir: &Path,
    membership_file: &Path,
) -> Result<NetworkData, RuntimeError> {
    let entries = fs::read_dir(zones_dir)
        .map_err(|error| RuntimeError::Data(format!("{}: {error}", zones_dir.display())))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| RuntimeError::Data(error.to_string()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| RuntimeError::Data(error.to_string()))?;
        if file_type.is_file() && entry.path().extension().is_some_and(|ext| ext == "json") {
            paths.push(entry.path());
        }
    }
    paths.sort();
    if paths.is_empty() {
        return Err(RuntimeError::Data(format!(
            "{} contains no zone JSON files",
            zones_dir.display()
        )));
    }
    let mut zones = Vec::with_capacity(paths.len());
    for path in paths {
        let body = fs::read_to_string(&path)
            .map_err(|error| RuntimeError::Data(format!("{}: {error}", path.display())))?;
        let zone = serde_json::from_str::<ZoneDefinition>(&body)
            .map_err(|error| RuntimeError::Data(format!("{}: {error}", path.display())))?;
        zones.push(zone);
    }
    let zones = index_zones(zones)?;
    let memberships_body = fs::read_to_string(membership_file)
        .map_err(|error| RuntimeError::Data(format!("{}: {error}", membership_file.display())))?;
    let memberships = parse_zone_memberships(&memberships_body, &zones)?;
    Ok(NetworkData { zones, memberships })
}

fn compile_bindings(
    snapshot: &SessionSnapshot,
    zones: &BTreeMap<String, ZoneDefinition>,
    memberships: &BTreeMap<String, ZoneMembership>,
    projects: &ProjectLocator,
) -> (Vec<SessionBinding>, Vec<ApplyWarning>) {
    let mut bindings = Vec::with_capacity(snapshot.sessions.len());
    let mut warnings = Vec::new();
    for session in &snapshot.sessions {
        let mut compiled = match projects.load(session, zones) {
            Ok(loaded) => loaded.compiled,
            Err(error) => {
                warnings.push(ApplyWarning {
                    session_id: session.session_id.clone(),
                    project: session.project_id.clone(),
                    fallback: "deny_all",
                    reason: error.to_string(),
                });
                deny_all(&session.project_id, zones)
            }
        };
        let missing_block_membership = compiled.rules.iter().find(|rule| {
            rule.zone != "internet"
                && rule.decision != Decision::Allow
                && memberships
                    .get(&rule.zone)
                    .is_none_or(|membership| membership.cidrs.is_empty())
        });
        if let Some(rule) = missing_block_membership {
            warnings.push(ApplyWarning {
                session_id: session.session_id.clone(),
                project: session.project_id.clone(),
                fallback: "deny_all",
                reason: format!(
                    "blocked zone {:?} has no enforceable CIDR membership",
                    rule.zone
                ),
            });
            compiled = deny_all(&session.project_id, zones);
        }
        bindings.push(SessionBinding {
            session_id: session.session_id.clone(),
            project_id: session.project_id.clone(),
            cgroup_path: session.cgroup_path.clone(),
            policy: compiled,
        });
    }
    (bindings, warnings)
}

/// Persist only when the semantic connection set changes. `scanned_at` is
/// intentionally excluded from the comparison: an unchanged refresh is not
/// a disk-write event.
pub fn write_report_if_changed(path: &Path, report: &ConnectionReport) -> io::Result<bool> {
    let next = serde_json::to_value(report).expect("connection report serializes infallibly");
    let next_semantic = semantic_report(next.clone());
    if let Ok(previous) = fs::read_to_string(path)
        && let Ok(previous) = serde_json::from_str::<Value>(&previous)
        && semantic_report(previous) == next_semantic
    {
        return Ok(false);
    }
    let bytes = serde_json::to_vec(&next).expect("connection report serializes infallibly");
    write_atomic(path, &bytes, 0o640)?;
    Ok(true)
}

fn semantic_report(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("scanned_at");
    }
    value
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "side file has no name"))?;
    let temporary = parent.join(format!(".{name}.netd-tmp.{}", std::process::id()));
    let create = || {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)
    };
    let mut file = match create() {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(&temporary)?;
            create()?
        }
        Err(error) => return Err(error),
    };
    file.write_all(bytes)?;
    file.flush()?;
    drop(file);
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(temporary);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::model::{Cidr, RelayMode, ZoneKind};
    use crate::observe::{Connection, Observation, ProcessConnections, TcpState};
    use crate::view::ManagedSession;

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "punar-netd-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn zones() -> BTreeMap<String, ZoneDefinition> {
        index_zones(vec![
            ZoneDefinition {
                name: "internet".into(),
                display_name: Some("Internet".into()),
                description: None,
                kind: ZoneKind::Internet,
                relay_mode: Some(RelayMode::Direct),
            },
            ZoneDefinition {
                name: "corp_prod".into(),
                display_name: Some("Production".into()),
                description: None,
                kind: ZoneKind::Production,
                relay_mode: Some(RelayMode::EnterpriseRoute),
            },
        ])
        .unwrap()
    }

    fn session(root: &Path) -> (ManagedSession, ProjectLocator) {
        let passwd = root.join("passwd");
        fs::write(
            &passwd,
            format!("punar:x:1000:1000:Punar:{}:/bin/bash\n", root.display()),
        )
        .unwrap();
        (
            ManagedSession {
                session_id: "agt_1".into(),
                project_id: "atlas".into(),
                user: "punar".into(),
                process_id: 42,
                cgroup_path: "/user.slice/punar-agent-agt_1.scope".into(),
            },
            ProjectLocator::new(passwd),
        )
    }

    #[test]
    fn missing_project_or_unenforceable_block_falls_back_to_session_deny_all() {
        let root = root();
        let (session, locator) = session(&root);
        let snapshot = SessionSnapshot {
            sessions: vec![session],
            skipped: vec![],
        };
        let (bindings, warnings) =
            compile_bindings(&snapshot, &zones(), &BTreeMap::new(), &locator);
        assert_eq!(bindings.len(), 1);
        assert!(
            bindings[0]
                .policy
                .rules
                .iter()
                .all(|rule| rule.decision == Decision::Deny)
        );
        assert!(!warnings.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn network_data_is_strict_and_requires_the_internet_residual() {
        let root = root();
        let zone_dir = root.join("zones");
        fs::create_dir_all(&zone_dir).unwrap();
        fs::write(
            zone_dir.join("internet.json"),
            r#"{"name":"internet","display_name":"Internet","kind":"internet","relay_mode":"direct"}"#,
        )
        .unwrap();
        let membership = root.join("zone-members.json");
        fs::write(&membership, r#"{"v":1,"zones":{"internet":{"cidrs":[]}}}"#).unwrap();
        let loaded = load_network_data(&zone_dir, &membership).unwrap();
        assert!(loaded.zones.contains_key("internet"));
        assert!(loaded.memberships["internet"].cidrs.is_empty());
        fs::remove_file(zone_dir.join("internet.json")).unwrap();
        fs::write(
            zone_dir.join("corp.json"),
            r#"{"name":"corp_prod","kind":"production"}"#,
        )
        .unwrap();
        assert!(load_network_data(&zone_dir, &membership).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unchanged_refresh_does_not_rewrite_the_side_file() {
        let root = root();
        let path = root.join("connections.json");
        let (session, _) = session(&root);
        let memberships = BTreeMap::from([(
            "corp_prod".into(),
            ZoneMembership {
                cidrs: vec![Cidr::parse("10.30.0.0/16").unwrap()],
                names: BTreeMap::new(),
            },
        )]);
        let make = |scanned_at: &str| Observation {
            scanned_at: scanned_at.into(),
            transport: "tcp",
            limitations: vec!["udp_quic_not_observed"],
            processes: vec![ProcessConnections {
                name: "agent".into(),
                pid: Some(42),
                uid: 1000,
                cgroup_path: Some(session.cgroup_path.clone()),
                connections: vec![Connection {
                    destination: "10.30.0.7".parse().unwrap(),
                    state: TcpState::Established,
                }],
            }],
        };
        let first = build_report(
            make("first"),
            &zones(),
            &memberships,
            std::slice::from_ref(&session),
        )
        .unwrap();
        let second = build_report(
            make("second"),
            &zones(),
            &memberships,
            std::slice::from_ref(&session),
        )
        .unwrap();
        assert!(write_report_if_changed(&path, &first).unwrap());
        let before = fs::read(&path).unwrap();
        assert!(!write_report_if_changed(&path, &second).unwrap());
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }
}
