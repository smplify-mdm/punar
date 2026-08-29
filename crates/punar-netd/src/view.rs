//! Join an on-demand kernel observation to authoritative managed sessions.
//!
//! This is the serialization boundary. Raw pids and cgroup paths are useful
//! for attribution but are deliberately absent from every type in this
//! module that implements `Serialize`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    ModelError, RelayMode, ZoneDefinition, ZoneKind, ZoneMembership, validate_cgroup_path,
    validate_project_id, validate_session_id, validate_user_name,
};
use crate::observe::{Observation, TcpState};

#[derive(Debug, Error)]
pub enum ViewError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("managed session {0:?} has pid zero")]
    InvalidPid(String),
    #[error("managed session id {0:?} appears more than once")]
    DuplicateSession(String),
    #[error("managed cgroup path {0:?} appears more than once")]
    DuplicateCgroup(String),
    #[error("managed cgroup paths {left:?} and {right:?} overlap")]
    OverlappingCgroups { left: String, right: String },
    #[error("kernel cgroup id {0} appears on more than one managed session")]
    DuplicateCgroupId(u64),
    #[error("socket path and kernel cgroup id resolve to different managed sessions")]
    ConflictingAttribution,
    #[error("zone map key {key:?} does not match definition name {name:?}")]
    ZoneKeyMismatch { key: String, name: String },
    #[error("zone membership references unknown zone {0:?}")]
    UnknownMembership(String),
    #[error("the internet residual zone is missing")]
    MissingInternet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSession {
    pub session_id: String,
    pub project_id: String,
    pub user: String,
    pub process_id: u32,
    pub cgroup_path: String,
    pub cgroup_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessClass {
    Agent,
    Application,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionView {
    pub id: String,
    pub project: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionView {
    pub destination: IpAddr,
    pub name: Option<String>,
    pub zone: String,
    pub category: String,
    pub route: RelayMode,
    pub state: TcpState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeniedView {
    pub zone: String,
    pub kind: ZoneKind,
    pub attempts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_destination: Option<IpAddr>,
    pub explain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessView {
    pub name: String,
    pub pid_class: ProcessClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionView>,
    pub governed: bool,
    pub connections: Vec<ConnectionView>,
    pub denied: Vec<DeniedView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionReport {
    pub scanned_at: String,
    pub transport: &'static str,
    pub limitations: Vec<&'static str>,
    pub processes: Vec<ProcessView>,
}

/// Produce the truthful public connection view from one ephemeral procfs
/// observation. A process is governed only when its kernel cgroup is exactly
/// a registered scope or a descendant of one; process names and pids never
/// participate in that decision.
pub fn build_report(
    observation: Observation,
    zones: &BTreeMap<String, ZoneDefinition>,
    memberships: &BTreeMap<String, ZoneMembership>,
    sessions: &[ManagedSession],
) -> Result<ConnectionReport, ViewError> {
    validate_inputs(zones, memberships, sessions)?;

    let mut processes = Vec::with_capacity(observation.processes.len());
    for process in observation.processes {
        let path_session = process.cgroup_path.as_deref().and_then(|path| {
            sessions
                .iter()
                .find(|session| within(path, &session.cgroup_path))
        });
        let id_session = process.cgroup_id.and_then(|id| {
            sessions
                .iter()
                .find(|session| session.cgroup_id == Some(id))
        });
        let session = match (path_session, id_session) {
            (Some(left), Some(right)) if left.session_id != right.session_id => {
                return Err(ViewError::ConflictingAttribution);
            }
            (Some(session), _) | (None, Some(session)) => Some(session),
            (None, None) => None,
        };
        let mut connections = process
            .connections
            .into_iter()
            .map(|connection| {
                classify_connection(connection.destination, connection.state, zones, memberships)
            })
            .collect::<Result<Vec<_>, _>>()?;
        connections.sort_by(|left, right| {
            (left.destination, left.zone.as_str(), left.state as u8).cmp(&(
                right.destination,
                right.zone.as_str(),
                right.state as u8,
            ))
        });
        connections.dedup();
        processes.push(ProcessView {
            name: process.name,
            pid_class: if session.is_some() {
                ProcessClass::Agent
            } else if process.pid.is_some() {
                ProcessClass::Application
            } else {
                ProcessClass::Unknown
            },
            session: session.map(|session| SessionView {
                id: session.session_id.clone(),
                project: session.project_id.clone(),
            }),
            governed: session.is_some(),
            connections,
            denied: Vec::new(),
            note: None,
        });
    }
    processes.sort_by(|left, right| {
        (
            !left.governed,
            left.name.as_str(),
            left.session.as_ref().map(|s| s.id.as_str()),
        )
            .cmp(&(
                !right.governed,
                right.name.as_str(),
                right.session.as_ref().map(|s| s.id.as_str()),
            ))
    });

    Ok(ConnectionReport {
        scanned_at: observation.scanned_at,
        transport: observation.transport,
        limitations: observation.limitations,
        processes,
    })
}

fn classify_connection(
    destination: IpAddr,
    state: TcpState,
    zones: &BTreeMap<String, ZoneDefinition>,
    memberships: &BTreeMap<String, ZoneMembership>,
) -> Result<ConnectionView, ViewError> {
    let member = memberships
        .iter()
        .filter(|(name, _)| name.as_str() != "internet")
        .find(|(_, membership)| {
            membership
                .cidrs
                .iter()
                .any(|cidr| cidr.contains(destination))
        });
    let (zone_name, name) = match member {
        Some((zone, membership)) => (zone.as_str(), membership.names.get(&destination).cloned()),
        None => ("internet", None),
    };
    let zone = zones.get(zone_name).ok_or(ViewError::MissingInternet)?;
    Ok(ConnectionView {
        destination,
        name,
        zone: zone.name.clone(),
        category: zone.kind.as_str().to_string(),
        route: zone.relay_mode.unwrap_or(RelayMode::Direct),
        state,
    })
}

fn validate_inputs(
    zones: &BTreeMap<String, ZoneDefinition>,
    memberships: &BTreeMap<String, ZoneMembership>,
    sessions: &[ManagedSession],
) -> Result<(), ViewError> {
    for (key, zone) in zones {
        zone.validate()?;
        if key != &zone.name {
            return Err(ViewError::ZoneKeyMismatch {
                key: key.clone(),
                name: zone.name.clone(),
            });
        }
    }
    if !zones.contains_key("internet") {
        return Err(ViewError::MissingInternet);
    }
    for name in memberships.keys() {
        if !zones.contains_key(name) {
            return Err(ViewError::UnknownMembership(name.clone()));
        }
    }

    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut cgroup_ids = BTreeSet::new();
    for session in sessions {
        validate_session_id(&session.session_id)?;
        validate_project_id(&session.project_id)?;
        validate_user_name(&session.user)?;
        validate_cgroup_path(&session.cgroup_path)?;
        if session.process_id == 0 {
            return Err(ViewError::InvalidPid(session.session_id.clone()));
        }
        if !ids.insert(session.session_id.clone()) {
            return Err(ViewError::DuplicateSession(session.session_id.clone()));
        }
        if !paths.insert(session.cgroup_path.clone()) {
            return Err(ViewError::DuplicateCgroup(session.cgroup_path.clone()));
        }
        if let Some(id) = session.cgroup_id
            && (id == 0 || !cgroup_ids.insert(id))
        {
            return Err(ViewError::DuplicateCgroupId(id));
        }
    }
    let paths: Vec<_> = paths.into_iter().collect();
    for (index, left) in paths.iter().enumerate() {
        for right in paths.iter().skip(index + 1) {
            if within(left, right) || within(right, left) {
                return Err(ViewError::OverlappingCgroups {
                    left: left.clone(),
                    right: right.clone(),
                });
            }
        }
    }
    Ok(())
}

fn within(process_path: &str, scope_path: &str) -> bool {
    process_path == scope_path
        || process_path
            .strip_prefix(scope_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Cidr, ZoneKind};
    use crate::observe::{Connection, ProcessConnections};

    fn inputs() -> (
        BTreeMap<String, ZoneDefinition>,
        BTreeMap<String, ZoneMembership>,
        Vec<ManagedSession>,
    ) {
        let zones = BTreeMap::from([
            (
                "corp_dev".into(),
                ZoneDefinition {
                    name: "corp_dev".into(),
                    display_name: Some("Acme Dev".into()),
                    description: None,
                    kind: ZoneKind::Corporate,
                    relay_mode: Some(RelayMode::EnterpriseRoute),
                },
            ),
            (
                "internet".into(),
                ZoneDefinition {
                    name: "internet".into(),
                    display_name: Some("Internet".into()),
                    description: None,
                    kind: ZoneKind::Internet,
                    relay_mode: Some(RelayMode::Direct),
                },
            ),
        ]);
        let memberships = BTreeMap::from([(
            "corp_dev".into(),
            ZoneMembership {
                cidrs: vec![Cidr::parse("10.20.0.0/16").unwrap()],
                names: BTreeMap::from([("10.20.0.7".parse().unwrap(), "dev-api".into())]),
            },
        )]);
        let sessions = vec![ManagedSession {
            session_id: "agt_4f21c09ab3e1".into(),
            project_id: "atlas".into(),
            user: "punar".into(),
            process_id: 42,
            cgroup_path: "/user.slice/punar-agent-4f21.scope".into(),
            cgroup_id: Some(31337),
        }];
        (zones, memberships, sessions)
    }

    #[test]
    fn cgroup_descendant_is_governed_and_zone_data_is_the_only_name_source() {
        let (zones, memberships, sessions) = inputs();
        let observation = Observation {
            scanned_at: "2026-08-29T00:00:00Z".into(),
            transport: "tcp",
            limitations: vec!["udp_quic_not_observed"],
            processes: vec![ProcessConnections {
                name: "punar-mock-agent".into(),
                pid: Some(43),
                uid: 1000,
                cgroup_path: Some("/user.slice/punar-agent-4f21.scope/child".into()),
                cgroup_id: Some(31337),
                connections: vec![Connection {
                    destination: "10.20.0.7".parse().unwrap(),
                    state: TcpState::Established,
                }],
            }],
        };
        let report = build_report(observation, &zones, &memberships, &sessions).unwrap();
        assert!(report.processes[0].governed);
        assert_eq!(report.processes[0].pid_class, ProcessClass::Agent);
        assert_eq!(
            report.processes[0].session.as_ref().unwrap().project,
            "atlas"
        );
        let connection = &report.processes[0].connections[0];
        assert_eq!(connection.name.as_deref(), Some("dev-api"));
        assert_eq!(connection.zone, "corp_dev");
        assert_eq!(connection.category, "corporate");
        assert_eq!(connection.route, RelayMode::EnterpriseRoute);
    }

    #[test]
    fn unmanaged_process_is_explicit_and_wire_has_no_kernel_attribution_fields() {
        let (zones, memberships, sessions) = inputs();
        let observation = Observation {
            scanned_at: "2026-08-29T00:00:00Z".into(),
            transport: "tcp",
            limitations: vec![],
            processes: vec![ProcessConnections {
                name: "chromium".into(),
                pid: Some(900),
                uid: 1000,
                cgroup_path: Some("/user.slice/app-chromium.scope".into()),
                cgroup_id: Some(90001),
                connections: vec![Connection {
                    destination: "151.101.1.69".parse().unwrap(),
                    state: TcpState::Established,
                }],
            }],
        };
        let report = build_report(observation, &zones, &memberships, &sessions).unwrap();
        assert!(!report.processes[0].governed);
        assert_eq!(report.processes[0].pid_class, ProcessClass::Application);
        assert_eq!(report.processes[0].connections[0].name, None);
        assert_eq!(report.processes[0].connections[0].zone, "internet");
        let wire = serde_json::to_string(&report).unwrap();
        for forbidden in ["cgroup", "uid", "\"pid\"", "151.101.1.69:"] {
            assert!(!wire.contains(forbidden), "{forbidden} leaked in {wire}");
        }
        assert!(wire.contains("\"governed\":false"));
    }

    #[test]
    fn duplicate_or_nested_scope_attribution_fails_closed() {
        let (zones, memberships, mut sessions) = inputs();
        let mut nested = sessions[0].clone();
        nested.session_id = "agt_other".into();
        nested.cgroup_path.push_str("/child");
        nested.cgroup_id = Some(31338);
        sessions.push(nested);
        let observation = Observation {
            scanned_at: "now".into(),
            transport: "tcp",
            limitations: vec![],
            processes: vec![],
        };
        assert!(matches!(
            build_report(observation, &zones, &memberships, &sessions),
            Err(ViewError::OverlappingCgroups { .. })
        ));
    }

    #[test]
    fn kernel_cgroup_id_governs_when_cross_user_proc_fds_are_hidden() {
        let (zones, memberships, sessions) = inputs();
        let observation = Observation {
            scanned_at: "2026-08-29T00:00:00Z".into(),
            transport: "tcp",
            limitations: vec![],
            processes: vec![ProcessConnections {
                name: "unknown".into(),
                pid: None,
                uid: 1000,
                cgroup_path: None,
                cgroup_id: Some(31337),
                connections: vec![Connection {
                    destination: "10.20.0.7".parse().unwrap(),
                    state: TcpState::Established,
                }],
            }],
        };
        let report = build_report(observation, &zones, &memberships, &sessions).unwrap();
        assert!(report.processes[0].governed);
        assert_eq!(report.processes[0].pid_class, ProcessClass::Agent);
        assert_eq!(
            report.processes[0].session.as_ref().unwrap().id,
            "agt_4f21c09ab3e1"
        );
    }
}
