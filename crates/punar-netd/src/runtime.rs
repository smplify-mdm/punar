//! Event-driven coordinator for policy apply and on-demand observation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

use crate::agentd::{
    AgentdClient, AgentdError, SessionSnapshot, SkippedSession, managed_scope_path,
};
use crate::deny::DenyLogReader;
use punar_common::agent::{LedgerNetworkDestination, LedgerNetworkParams, LedgerNetworkSource};
use punar_common::ledger::{ResourceCategory, ResourceClass};
use punar_common::network::{
    NetworkSessionEnforcement, NetworkSessionReadyResult, NetworkSessionReadyState,
};

use crate::model::{Decision, ZoneDefinition, ZoneKind, ZoneMembership};
use crate::nft::{CounterBinding, NftError, SessionBinding, counter_bindings, render_table};
use crate::nft_exec::{EnforcementCapability, ExecError, NftExecutor};
use crate::observe::{ObserveError, observe};
use crate::policy::{PolicyError, index_zones, parse_zone_memberships};
use crate::project::{ProjectLocator, deny_all};
use crate::relay::{RelayError, RelayStatus, RelayStore};
use crate::view::{DeniedView, ProcessClass, ProcessView, SessionView, ViewError, build_report};

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
    #[error("no active managed session names project {0:?}")]
    ProjectNotActive(String),
    #[error("the readiness-gate peer is not in session {session_id:?}: {reason}")]
    SessionGateNotAttributed { session_id: String, reason: String },
    #[error("managed session {session_id:?} is not ready: {reason}")]
    SessionNotReady { session_id: String, reason: String },
    #[error(
        "the exact nftables cgroup rule for session {session_id:?} was not observed after apply: {reason}"
    )]
    SessionRuleNotVerified { session_id: String, reason: String },
    #[error("connection side-file write failed: {0}")]
    SideFile(io::Error),
    #[error(transparent)]
    Relay(#[from] RelayError),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionTransitionKind {
    Attached,
    Detached,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTransition {
    pub kind: SessionTransitionKind,
    pub session_id: String,
    pub project: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileResult {
    pub applied: ApplyResult,
    pub transitions: Vec<SessionTransition>,
    pub denial_events: Vec<DenialEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstalledSession {
    project: String,
    cgroup_path: String,
    counters: Vec<CounterBinding>,
}

struct AppliedState {
    result: ApplyResult,
    sessions: BTreeMap<String, InstalledSession>,
    skipped: BTreeMap<String, String>,
    denial_events: Vec<DenialEvent>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsProtectionStatus {
    pub state: &'static str,
    pub milestone: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionsResult {
    pub scanned_at: String,
    pub enforcement: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_reason: Option<String>,
    pub relay: RelayStatus,
    pub dns_protection: DnsProtectionStatus,
    pub transport: &'static str,
    pub limitations: Vec<&'static str>,
    pub processes: Vec<ProcessView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenialEvent {
    pub session_id: String,
    pub project: String,
    pub zone: String,
    pub kind: ZoneKind,
}

pub struct ConnectionPass {
    pub result: ConnectionsResult,
    pub denial_events: Vec<DenialEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DestinationKey {
    session_id: String,
    destination: String,
    zone: String,
}

#[derive(Debug, Clone)]
struct DestinationTotal {
    count: u64,
    first_seen: String,
    last_seen: String,
}

pub struct Runtime {
    pub zones: BTreeMap<String, ZoneDefinition>,
    pub memberships: BTreeMap<String, ZoneMembership>,
    data_source: Option<NetworkDataSource>,
    agentd: AgentdClient,
    projects: ProjectLocator,
    nft: NftExecutor,
    proc_root: PathBuf,
    connections_file: PathBuf,
    relay: RelayStore,
    deny_log: Option<DenyLogReader>,
    status_file: PathBuf,
    capability: EnforcementCapability,
    last_apply: Option<ApplyResult>,
    last_apply_error: Option<String>,
    installed_sessions: BTreeMap<String, InstalledSession>,
    counter_carry: BTreeMap<String, u64>,
    reported_denials: BTreeMap<String, u64>,
    last_denied_destinations: BTreeMap<(String, String), std::net::IpAddr>,
    active_destinations: BTreeSet<DestinationKey>,
    destination_totals: BTreeMap<DestinationKey, DestinationTotal>,
}

#[derive(Debug, Clone)]
struct NetworkDataSource {
    zones_dir: PathBuf,
    membership_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct NetworkData {
    pub zones: BTreeMap<String, ZoneDefinition>,
    pub memberships: BTreeMap<String, ZoneMembership>,
}

pub struct RuntimeInputs {
    pub data: NetworkData,
    pub agentd: AgentdClient,
    pub projects: ProjectLocator,
    pub nft: NftExecutor,
    pub proc_root: PathBuf,
    pub connections_file: PathBuf,
    pub relay: RelayStore,
    pub deny_log: Option<DenyLogReader>,
    pub status_file: PathBuf,
}

impl Runtime {
    pub fn production() -> Result<Self, RuntimeError> {
        let source = NetworkDataSource {
            zones_dir: PathBuf::from("/usr/share/punar/network/zones"),
            membership_file: PathBuf::from("/usr/share/punar/network/zone-members.json"),
        };
        let data = load_network_data(&source.zones_dir, &source.membership_file)?;
        let relay = RelayStore::open(PathBuf::from("/var/lib/punar/network/relay.json"))?;
        let deny_log = DenyLogReader::production();
        if let Err(error) = deny_log.initialize() {
            eprintln!("punar-netd: deny-log cursor initialization unavailable: {error}");
        }
        let mut runtime = Self::new(RuntimeInputs {
            data,
            agentd: AgentdClient::production(),
            projects: ProjectLocator::production(),
            nft: NftExecutor::production(),
            proc_root: PathBuf::from("/proc"),
            connections_file: PathBuf::from(punar_common::network::CONNECTIONS_PATH),
            relay,
            deny_log: Some(deny_log),
            status_file: PathBuf::from("/run/punar/status.json"),
        });
        runtime.data_source = Some(source);
        Ok(runtime)
    }

    pub fn new(inputs: RuntimeInputs) -> Self {
        let capability = inputs.nft.probe_cgroup_v2();
        Self {
            zones: inputs.data.zones,
            memberships: inputs.data.memberships,
            data_source: None,
            agentd: inputs.agentd,
            projects: inputs.projects,
            nft: inputs.nft,
            proc_root: inputs.proc_root,
            connections_file: inputs.connections_file,
            relay: inputs.relay,
            deny_log: inputs.deny_log,
            status_file: inputs.status_file,
            capability,
            last_apply: None,
            last_apply_error: None,
            installed_sessions: BTreeMap::new(),
            counter_carry: BTreeMap::new(),
            reported_denials: BTreeMap::new(),
            last_denied_destinations: BTreeMap::new(),
            active_destinations: BTreeSet::new(),
            destination_totals: BTreeMap::new(),
        }
    }

    pub fn enforcement_status(&self) -> EnforcementStatus {
        let installed_sessions = self
            .last_apply
            .as_ref()
            .map_or(0, |result| result.installed_sessions);
        match (&self.capability, &self.last_apply_error) {
            (EnforcementCapability::Available, None) => EnforcementStatus {
                state: "available",
                reason: None,
                installed_sessions,
            },
            (EnforcementCapability::Available, Some(reason)) => EnforcementStatus {
                state: "unavailable",
                reason: Some(reason.clone()),
                installed_sessions: 0,
            },
            (EnforcementCapability::Unavailable { reason }, _) => EnforcementStatus {
                state: "unavailable",
                reason: Some(reason.clone()),
                installed_sessions: 0,
            },
        }
    }

    pub fn apply(&mut self) -> Result<ApplyResult, RuntimeError> {
        self.reconcile().map(|result| result.applied)
    }

    /// Synchronous pre-exec barrier for a trusted launcher already inside
    /// the managed session scope.
    ///
    /// There is deliberately no retry, count comparison, or status-based
    /// release here. One request must prove all three facts: the socket peer
    /// is in the exact named scope, agentd currently reports that exact
    /// session as active+managed, and the exact cgroup selector/jump can be
    /// read back from the kernel after the atomic transaction. Any missing
    /// fact is an error and the caller must not execute untrusted code.
    pub fn session_ready(
        &mut self,
        session_id: &str,
        peer_pid: u32,
    ) -> Result<(NetworkSessionReadyResult, ReconcileResult), RuntimeError> {
        let before = gate_scope_path(&self.proc_root, peer_pid, session_id)?;
        // Unlike background reconciliation, this path is the authority that
        // releases untrusted code. Validate the production executable and
        // its complete path before invoking it at all.
        self.nft.validate_trusted_binary()?;
        let outcome = self.reconcile()?;
        let (project, cgroup_path) = self
            .installed_sessions
            .get(session_id)
            .map(|session| (session.project.clone(), session.cgroup_path.clone()))
            .ok_or_else(|| {
                let reason = outcome
                    .applied
                    .skipped_sessions
                    .iter()
                    .find(|session| session.session_id == session_id)
                    .map(|session| session.reason.clone())
                    .unwrap_or_else(|| {
                        "punar-agentd did not return this exact active managed session".into()
                    });
                RuntimeError::SessionNotReady {
                    session_id: session_id.to_string(),
                    reason,
                }
            })?;
        if before != cgroup_path {
            return Err(RuntimeError::SessionGateNotAttributed {
                session_id: session_id.to_string(),
                reason: "the socket peer and agentd's registered process are in different cgroups"
                    .into(),
            });
        }

        match self.nft.verify_session_rule(session_id, &cgroup_path) {
            Ok(true) => {}
            Ok(false) => {
                let error = RuntimeError::SessionRuleNotVerified {
                    session_id: session_id.to_string(),
                    reason: "the kernel table lacked the exact cgroup selector, jump target, or target chain"
                        .into(),
                };
                self.last_apply_error = Some(error.to_string());
                return Err(error);
            }
            Err(error) => {
                let error = RuntimeError::SessionRuleNotVerified {
                    session_id: session_id.to_string(),
                    reason: error.to_string(),
                };
                self.last_apply_error = Some(error.to_string());
                return Err(error);
            }
        }

        // Re-prove after the kernel read. A gate moved out of the scope while
        // policy was being applied must not use an acknowledgment for the
        // cgroup it left.
        let after = gate_scope_path(&self.proc_root, peer_pid, session_id)?;
        if after != cgroup_path {
            return Err(RuntimeError::SessionGateNotAttributed {
                session_id: session_id.to_string(),
                reason: "the socket peer left or changed cgroup during readiness verification"
                    .into(),
            });
        }

        Ok((
            NetworkSessionReadyResult {
                session_id: session_id.to_string(),
                project,
                state: NetworkSessionReadyState::Ready,
                enforcement: NetworkSessionEnforcement::NftablesCgroupV2,
            },
            outcome,
        ))
    }

    /// Re-read authoritative agent state, atomically replace the nft table,
    /// and report only transitions that actually reached the kernel.
    pub fn reconcile(&mut self) -> Result<ReconcileResult, RuntimeError> {
        match self.apply_inner() {
            Ok(state) => {
                let transitions =
                    session_transitions(&self.installed_sessions, &state.sessions, &state.skipped);
                self.last_apply = Some(state.result.clone());
                self.last_apply_error = None;
                self.installed_sessions = state.sessions;
                Ok(ReconcileResult {
                    applied: state.result,
                    transitions,
                    denial_events: state.denial_events,
                })
            }
            Err(error) => {
                self.last_apply_error = Some(error.to_string());
                Err(error)
            }
        }
    }

    fn apply_inner(&mut self) -> Result<AppliedState, RuntimeError> {
        if let EnforcementCapability::Unavailable { reason } = &self.capability {
            return Err(RuntimeError::EnforcementUnavailable(reason.clone()));
        }
        // Stage policy data afresh on every explicit or event-driven apply.
        // The live copy changes only after the complete replacement reaches
        // nftables, so a malformed edit cannot erase the last enforced table
        // or leak partially validated state into the privacy view.
        let staged_data = self
            .data_source
            .as_ref()
            .map(|source| load_network_data(&source.zones_dir, &source.membership_file))
            .transpose()?;
        let zones = staged_data.as_ref().map_or(&self.zones, |data| &data.zones);
        let memberships = staged_data
            .as_ref()
            .map_or(&self.memberships, |data| &data.memberships);
        let snapshot = self.agentd.snapshot()?;
        let skipped_reasons = snapshot
            .skipped
            .iter()
            .map(|skipped| (skipped.session_id.clone(), skipped.reason.clone()))
            .collect();
        let (bindings, warnings) = compile_bindings(&snapshot, zones, memberships, &self.projects);
        let ruleset = render_table(true, zones, memberships, &bindings)?;
        let next: BTreeMap<_, _> = bindings
            .iter()
            .map(|binding| {
                Ok((
                    binding.session_id.clone(),
                    InstalledSession {
                        project: binding.project_id.clone(),
                        cgroup_path: binding.cgroup_path.clone(),
                        counters: counter_bindings(zones, binding)?,
                    },
                ))
            })
            .collect::<Result<_, NftError>>()?;

        // A detach is the final flush point. Publish while the old kernel
        // table is still intact: if agentd is unavailable, returning here
        // preserves enforcement rather than deleting the session chain and
        // then discovering its purgeable aggregate could not be delivered.
        let detached: Vec<String> = self
            .installed_sessions
            .keys()
            .filter(|session_id| !next.contains_key(*session_id))
            .cloned()
            .collect();
        for session_id in &detached {
            self.publish_destinations(session_id)?;
        }

        // Full-table replacement resets named counters. Capture the kernel
        // totals first, but fold them into memory only after the atomic nft
        // transaction succeeds; a rejected transaction must not double-count
        // on the next reconcile.
        let kernel_before = self.nft.query_named_counters()?;
        let (_, denial_events) = collect_denials(
            &self.installed_sessions,
            &self.counter_carry,
            &kernel_before,
            &mut self.reported_denials,
        );
        self.nft.apply_checked(&ruleset)?;
        if let Some(data) = staged_data {
            self.zones = data.zones;
            self.memberships = data.memberships;
        }
        for (name, packets) in kernel_before {
            let total = self.counter_carry.entry(name).or_default();
            *total = total.saturating_add(packets);
        }
        for session_id in detached {
            self.active_destinations
                .retain(|key| key.session_id != session_id);
            self.destination_totals
                .retain(|key, _| key.session_id != session_id);
            self.last_denied_destinations
                .retain(|(id, _), _| id != &session_id);
        }
        let result = ApplyResult {
            installed_sessions: bindings.len(),
            skipped_sessions: snapshot.skipped.into_iter().map(Into::into).collect(),
            warnings,
        };
        Ok(AppliedState {
            result,
            sessions: next,
            skipped: skipped_reasons,
            denial_events,
        })
    }

    pub fn connections(&mut self) -> Result<ConnectionPass, RuntimeError> {
        // A read never rewrites a healthy table, but it is also the
        // user-visible self-heal trigger. If an external actor removed our
        // table, rebuild from authoritative sessions before claiming the
        // connection view is governed.
        if !self.nft.table_exists()? {
            self.reconcile()?;
        }
        let snapshot = self.agentd.snapshot()?;
        let observation = observe(&self.proc_root)?;
        let mut report = build_report(
            observation,
            &self.zones,
            &self.memberships,
            &snapshot.sessions,
        )?;
        let kernel = self.nft.query_named_counters()?;
        let (mut denials, denial_events) = collect_denials(
            &self.installed_sessions,
            &self.counter_carry,
            &kernel,
            &mut self.reported_denials,
        );
        if let Some(reader) = &self.deny_log {
            match reader.read_new() {
                Ok(records) => {
                    for record in records {
                        self.last_denied_destinations
                            .insert((record.session_id, record.zone), record.destination);
                    }
                    for (session_id, view) in &mut denials {
                        for row in &mut view.rows {
                            row.last_destination = self
                                .last_denied_destinations
                                .get(&(session_id.clone(), row.zone.clone()))
                                .copied();
                        }
                    }
                }
                Err(error) => {
                    eprintln!("punar-netd: deny-log observation unavailable: {error}");
                    report
                        .limitations
                        .push("denied_destination_log_unavailable");
                }
            }
        }
        attach_denials(&mut report.processes, denials);
        ensure_system_rows(&mut report.processes, device_is_enrolled(&self.status_file));
        let changed_sessions = self.refresh_destinations(&report.processes, &report.scanned_at);
        for session_id in changed_sessions {
            self.publish_destinations(&session_id)?;
        }
        let enforcement = self.enforcement_status();
        let result = ConnectionsResult {
            scanned_at: report.scanned_at,
            enforcement: enforcement.state,
            enforcement_reason: enforcement.reason,
            relay: self.relay.status(),
            dns_protection: DnsProtectionStatus {
                state: "not_configured",
                milestone: "phase_2",
            },
            transport: report.transport,
            limitations: report.limitations,
            processes: report.processes,
        };
        write_report_if_changed(&self.connections_file, &result).map_err(RuntimeError::SideFile)?;
        Ok(ConnectionPass {
            result,
            denial_events,
        })
    }

    fn refresh_destinations(
        &mut self,
        processes: &[ProcessView],
        observed_at: &str,
    ) -> BTreeSet<String> {
        let mut current = BTreeSet::new();
        for process in processes {
            let Some(session) = &process.session else {
                continue;
            };
            for connection in &process.connections {
                if connection.state != crate::observe::TcpState::Established {
                    continue;
                }
                let destination = ledger_destination(connection);
                let key = DestinationKey {
                    session_id: session.id.clone(),
                    destination,
                    zone: connection.zone.clone(),
                };
                current.insert(key);
            }
        }

        let mut changed_sessions = BTreeSet::new();
        for key in current.difference(&self.active_destinations) {
            let total = self
                .destination_totals
                .entry(key.clone())
                .or_insert_with(|| DestinationTotal {
                    count: 0,
                    first_seen: observed_at.to_string(),
                    last_seen: observed_at.to_string(),
                });
            total.count = total.count.saturating_add(1);
            total.last_seen = observed_at.to_string();
            changed_sessions.insert(key.session_id.clone());
        }
        for key in self.active_destinations.difference(&current) {
            changed_sessions.insert(key.session_id.clone());
        }
        self.active_destinations = current;
        changed_sessions
    }

    fn publish_destinations(&self, session_id: &str) -> Result<(), RuntimeError> {
        let destinations = self
            .destination_totals
            .iter()
            .filter(|(key, _)| key.session_id == session_id)
            .map(|(key, total)| LedgerNetworkDestination {
                destination: key.destination.clone(),
                zone: key.zone.clone(),
                count: total.count,
                first_seen: total.first_seen.clone(),
                last_seen: total.last_seen.clone(),
            })
            .collect::<Vec<_>>();
        if destinations.is_empty() {
            return Ok(());
        }
        let result = self.agentd.publish_network(LedgerNetworkParams {
            session_id: session_id.to_string(),
            destinations,
            source: LedgerNetworkSource::NetdAggregate,
        })?;
        if result.rejected > 0 {
            return Err(RuntimeError::Data(format!(
                "agentd rejected {} privacy-bounded destination row(s) for {session_id}",
                result.rejected
            )));
        }
        Ok(())
    }

    pub fn status_json(&self) -> Value {
        json!({
            "enforcement": self.enforcement_status(),
            "relay": self.relay.status(),
            "dns_protection": {"state": "not_configured", "milestone": "phase_2"},
            "observation": {
                "transport": "tcp",
                "udp_quic": "not_observed",
                "content_inspection": false,
                "dns_logging": false
            }
        })
    }

    pub fn relay_status(&self) -> RelayStatus {
        self.relay.status()
    }

    pub fn set_relay(
        &mut self,
        mode: punar_common::network::RelayPreference,
    ) -> Result<RelayStatus, RuntimeError> {
        Ok(self.relay.set(mode)?)
    }

    pub fn zones_json(&self) -> Value {
        serde_json::to_value(self.zones.values().collect::<Vec<_>>())
            .expect("zone definitions serialize infallibly")
    }

    pub fn policy_json(&self, project: &str) -> Result<Value, RuntimeError> {
        let snapshot = self.agentd.snapshot()?;
        let session = snapshot
            .sessions
            .iter()
            .find(|session| session.project_id == project)
            .ok_or_else(|| RuntimeError::ProjectNotActive(project.to_string()))?;
        let loaded = self.projects.load(session, &self.zones).map_err(|error| {
            RuntimeError::Data(format!("project {project:?} could not compile: {error}"))
        })?;
        serde_json::to_value(loaded.compiled).map_err(|error| RuntimeError::Data(error.to_string()))
    }

    pub fn explain_json(&self, project: &str, zone: &str) -> Result<Value, RuntimeError> {
        let snapshot = self.agentd.snapshot()?;
        let session = snapshot
            .sessions
            .iter()
            .find(|session| session.project_id == project)
            .ok_or_else(|| RuntimeError::ProjectNotActive(project.to_string()))?;
        let loaded = self.projects.load(session, &self.zones).map_err(|error| {
            RuntimeError::Data(format!("project {project:?} could not compile: {error}"))
        })?;
        let rule = loaded
            .compiled
            .rule(zone)
            .ok_or_else(|| RuntimeError::Data(format!("zone {zone:?} does not exist")))?;
        Ok(json!({
            "what": format!("Network access to zone {zone} is {}.", rule.decision),
            "why": format!("The effective decision is the strictest value from the project manifest and route policy (bound by {:?}).", rule.bound_by),
            "who": format!("Managed AI sessions in project {project}."),
            "which_policy": [
                loaded.policy_path.display().to_string(),
                loaded.manifest_path.display().to_string()
            ],
            "can_you_change_it": "Edit the project documents; organization policy may only further restrict access.",
            "next_step": format!("punarctl network policy {project}"),
            "decision": rule.decision,
            "zone": zone,
            "project": project,
            "enforcement": self.enforcement_status()
        }))
    }
}

fn gate_scope_path(
    proc_root: &Path,
    peer_pid: u32,
    session_id: &str,
) -> Result<String, RuntimeError> {
    managed_scope_path(proc_root, peer_pid, session_id)
        .map_err(|reason| RuntimeError::SessionGateNotAttributed {
            session_id: session_id.to_string(),
            reason,
        })?
        .ok_or_else(|| RuntimeError::SessionGateNotAttributed {
            session_id: session_id.to_string(),
            reason: format!("peer pid {peer_pid} is not in the exact named scope"),
        })
}

#[derive(Debug)]
struct DeniedSessionView {
    project: String,
    rows: Vec<DeniedView>,
}

fn collect_denials(
    sessions: &BTreeMap<String, InstalledSession>,
    carry: &BTreeMap<String, u64>,
    kernel: &BTreeMap<String, u64>,
    reported: &mut BTreeMap<String, u64>,
) -> (BTreeMap<String, DeniedSessionView>, Vec<DenialEvent>) {
    let mut views = BTreeMap::new();
    let mut events = Vec::new();
    for (session_id, session) in sessions {
        let mut rows = Vec::new();
        for binding in session
            .counters
            .iter()
            .filter(|binding| binding.decision.blocks())
        {
            let attempts = carry
                .get(&binding.name)
                .copied()
                .unwrap_or(0)
                .saturating_add(kernel.get(&binding.name).copied().unwrap_or(0));
            if attempts == 0 {
                continue;
            }
            let previous = reported.get(&binding.name).copied().unwrap_or(0);
            if attempts > previous {
                events.push(DenialEvent {
                    session_id: session_id.clone(),
                    project: session.project.clone(),
                    zone: binding.zone.clone(),
                    kind: binding.kind,
                });
                reported.insert(binding.name.clone(), attempts);
            }
            rows.push(DeniedView {
                zone: binding.zone.clone(),
                kind: binding.kind,
                attempts,
                last_destination: None,
                explain: format!(
                    "punarctl network explain {} {}",
                    session.project, binding.zone
                ),
            });
        }
        rows.sort_by(|left, right| left.zone.cmp(&right.zone));
        if !rows.is_empty() {
            views.insert(
                session_id.clone(),
                DeniedSessionView {
                    project: session.project.clone(),
                    rows,
                },
            );
        }
    }
    (views, events)
}

fn attach_denials(
    processes: &mut Vec<ProcessView>,
    mut denials: BTreeMap<String, DeniedSessionView>,
) {
    for process in processes.iter_mut() {
        let Some(session) = &process.session else {
            continue;
        };
        if let Some(view) = denials.remove(&session.id) {
            process.denied = view.rows;
        }
    }
    for (session_id, view) in denials {
        processes.push(ProcessView {
            name: "managed-agent".to_string(),
            pid_class: ProcessClass::Agent,
            session: Some(SessionView {
                id: session_id,
                project: view.project,
            }),
            governed: true,
            connections: Vec::new(),
            denied: view.rows,
            note: None,
        });
    }
    processes.sort_by(|left, right| {
        (
            !left.governed,
            left.name.as_str(),
            left.session.as_ref().map(|session| session.id.as_str()),
        )
            .cmp(&(
                !right.governed,
                right.name.as_str(),
                right.session.as_ref().map(|session| session.id.as_str()),
            ))
    });
}

fn ensure_system_rows(processes: &mut Vec<ProcessView>, enrolled: bool) {
    if !processes.iter().any(|process| process.name == "punard") {
        processes.push(ProcessView {
            name: "punard".to_string(),
            pid_class: ProcessClass::Application,
            session: None,
            governed: false,
            connections: Vec::new(),
            denied: Vec::new(),
            note: Some(if enrolled {
                "no current TCP connections observed".to_string()
            } else {
                "no connections · nothing to report home".to_string()
            }),
        });
    }
    if !processes.iter().any(|process| process.name == "punar-netd") {
        processes.push(ProcessView {
            name: "punar-netd".to_string(),
            pid_class: ProcessClass::Application,
            session: None,
            governed: false,
            connections: Vec::new(),
            denied: Vec::new(),
            note: Some("0 connections · cannot open one (AF_INET denied)".to_string()),
        });
    }
    processes.sort_by(|left, right| {
        (
            !left.governed,
            left.name.as_str(),
            left.session.as_ref().map(|session| session.id.as_str()),
        )
            .cmp(&(
                !right.governed,
                right.name.as_str(),
                right.session.as_ref().map(|session| session.id.as_str()),
            ))
    });
}

fn device_is_enrolled(path: &Path) -> bool {
    fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_json::from_str::<Value>(&body).ok())
        .and_then(|value| value.get("enrolled").and_then(Value::as_bool))
        .unwrap_or(false)
}

fn ledger_destination(connection: &crate::view::ConnectionView) -> String {
    let candidates = [
        connection.name.clone(),
        match connection.destination {
            std::net::IpAddr::V4(address) => Some(address.to_string()),
            std::net::IpAddr::V6(_) => None,
        },
        Some(connection.zone.clone()),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|candidate| {
            ResourceClass::new(ResourceCategory::NetworkDestinations, candidate).is_ok()
        })
        .expect("a validated zone name is a valid destination class")
}

fn session_transitions(
    previous: &BTreeMap<String, InstalledSession>,
    next: &BTreeMap<String, InstalledSession>,
    skipped: &BTreeMap<String, String>,
) -> Vec<SessionTransition> {
    let mut transitions = Vec::new();
    for (session_id, old) in previous {
        match next.get(session_id) {
            None => transitions.push(SessionTransition {
                kind: SessionTransitionKind::Detached,
                session_id: session_id.clone(),
                project: old.project.clone(),
                reason: if skipped
                    .get(session_id)
                    .is_some_and(|reason| reason.contains("not in its registered managed scope"))
                {
                    "cgroup_left"
                } else {
                    "session_ended"
                },
            }),
            Some(current)
                if old.cgroup_path != current.cgroup_path || old.project != current.project =>
            {
                transitions.push(SessionTransition {
                    kind: SessionTransitionKind::Detached,
                    session_id: session_id.clone(),
                    project: old.project.clone(),
                    reason: "session_rebound",
                });
                transitions.push(SessionTransition {
                    kind: SessionTransitionKind::Attached,
                    session_id: session_id.clone(),
                    project: current.project.clone(),
                    reason: "session_attached",
                });
            }
            Some(_) => {}
        }
    }
    for (session_id, current) in next {
        if !previous.contains_key(session_id) {
            transitions.push(SessionTransition {
                kind: SessionTransitionKind::Attached,
                session_id: session_id.clone(),
                project: current.project.clone(),
                reason: "session_attached",
            });
        }
    }
    transitions
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
pub fn write_report_if_changed<T: Serialize>(path: &Path, report: &T) -> io::Result<bool> {
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

    #[test]
    fn lifecycle_diff_is_closed_and_cgroup_escape_is_explicit() {
        let previous = BTreeMap::from([(
            "agt_old".to_string(),
            InstalledSession {
                project: "atlas".to_string(),
                cgroup_path: "/user.slice/punar-agent-agt_old.scope".to_string(),
                counters: Vec::new(),
            },
        )]);
        let next = BTreeMap::from([(
            "agt_new".to_string(),
            InstalledSession {
                project: "forge".to_string(),
                cgroup_path: "/user.slice/punar-agent-agt_new.scope".to_string(),
                counters: Vec::new(),
            },
        )]);
        let skipped = BTreeMap::from([(
            "agt_old".to_string(),
            "the root process is not in its registered managed scope".to_string(),
        )]);

        let transitions = session_transitions(&previous, &next, &skipped);
        assert_eq!(transitions.len(), 2);
        assert_eq!(transitions[0].kind, SessionTransitionKind::Detached);
        assert_eq!(transitions[0].reason, "cgroup_left");
        assert_eq!(transitions[0].project, "atlas");
        assert_eq!(transitions[1].kind, SessionTransitionKind::Attached);
        assert_eq!(transitions[1].reason, "session_attached");
        assert_eq!(transitions[1].project, "forge");
    }

    #[test]
    fn unchanged_installed_session_has_no_lifecycle_event() {
        let installed = BTreeMap::from([(
            "agt_same".to_string(),
            InstalledSession {
                project: "atlas".to_string(),
                cgroup_path: "/user.slice/punar-agent-agt_same.scope".to_string(),
                counters: Vec::new(),
            },
        )]);
        assert!(session_transitions(&installed, &installed, &BTreeMap::new()).is_empty());
    }

    #[test]
    fn readiness_gate_peer_must_be_inside_the_exact_named_scope() {
        let root = root();
        fs::create_dir_all(root.join("42")).unwrap();
        fs::write(
            root.join("42/cgroup"),
            "0::/user.slice/punar-agent-agt_4f21c09ab3e1.scope\n",
        )
        .unwrap();
        assert_eq!(
            gate_scope_path(&root, 42, "agt_4f21c09ab3e1").unwrap(),
            "/user.slice/punar-agent-agt_4f21c09ab3e1.scope"
        );

        fs::write(
            root.join("42/cgroup"),
            "0::/user.slice/punar-agent-agt_4f21c09ab3e1.scope-evil\n",
        )
        .unwrap();
        assert!(matches!(
            gate_scope_path(&root, 42, "agt_4f21c09ab3e1"),
            Err(RuntimeError::SessionGateNotAttributed { .. })
        ));
        assert!(matches!(
            gate_scope_path(&root, 43, "agt_4f21c09ab3e1"),
            Err(RuntimeError::SessionGateNotAttributed { .. })
        ));
        fs::remove_dir_all(root).unwrap();
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
                cgroup_id: None,
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
                cgroup_id: session.cgroup_id,
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
