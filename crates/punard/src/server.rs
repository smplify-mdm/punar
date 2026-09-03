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

use punar_common::aipolicy::{AiAuthority, AiRuling};
use punar_common::approval::{
    Approval, ApprovalEnvelope, ApprovalKind, ApprovalRequest, ApprovalStatus, Execution, Grant,
    MAX_PENDING_APPROVALS, MAX_PENDING_PER_REQUESTER, PolicyCitation, RESULT_AGENT_CREATE_REFUSED,
    RESULT_AGENT_PRIVILEGE_REFUSED, RESULT_APPROVAL_FLOOD, RESULT_SELF_APPROVAL_REFUSED, Requester,
    RequesterPeer, ResolvedBy,
};
use punar_common::audit::{
    AGENT_SESSION_NONE, AuditActor, AuditOutcome, AuditWriter, PROJECT_ID_SYSTEM,
    RESOURCE_CAPABILITY_REGISTRY, count_events, next_event_id, tail,
};
use punar_common::install::{
    InstallApplyParams, InstallEncryption, InstallOverallState, InstallPhase,
    InstallRecoveryAckParams, InstallRecoveryMode, InstallStatusResult,
};
use punar_common::ipc::{
    ApprovalIdParams, ApprovalsConsumeResult, ApprovalsCreateParams, ApprovalsListResult,
    ApprovalsResolveParams, AppsCatalogParams, AppsInstallParams, AppsRemoveParams,
    AppsUpdateParams, AuditStatus, AuditTailParams, CapabilitiesGetParams, CapabilitiesSetParams,
    CapabilityCompliance, Classification as WireClassification, ComplianceBlock, ComplianceState,
    EnrollStartParams, EnrollStartResult, EnrollStatusResult, EnrollStopResult, ErrorCode,
    FirstSync, IpcError, LastQuery, LastSync, MAX_REQUEST_LINE_BYTES, Method, Mode, OrgInfo,
    PROTOCOL_VERSION, PolicyEffectiveEntry, PolicyEffectiveResult, PolicyExplainParams,
    PolicyExplainResult, PolicySourceRef, PrivilegeRequestParams, PrivilegeRevokeParams,
    PrivilegeRevokeResult, PrivilegeStatusResult, ReconcileEntry, ReconcileResult,
    RemediationOutcome, Request, ResolveDecision, Response, SERVER_READ_TIMEOUT, StatusResult,
};
use punar_common::query::MAX_QUERIES_PER_SYNC;
use punar_common::time::utc_now_rfc3339;
use punar_common::update::{
    UpdateApplyParams, UpdateApplyResult, UpdateChannel, UpdateCheckParams, UpdateCheckResult,
    UpdateRollbackParams, UpdateStatusResult,
};
use punar_common::{AuditEvent, Decision, PrincipalKind, Redacted, Risk};
use punar_policy::{Classification, EffectiveEntry, Provenance};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::approvals::{self, ApprovalStore};
use crate::apps::{AppError, AppManager};
use crate::authz::{Peer, PeerSource, authorize_mutation};
use crate::capability::{Capability, Registry};
use crate::device::{DeviceSources, observe_profile};
use crate::enroll::{
    ControlPlaneClient, DEFAULT_CONTROL_PLANE_SOCKET, Enrollment, InventorySources,
    LastQueryRecord, LastSyncRecord, OrgRecord, StatusSummary, UpstreamError,
    compliance_report_body, inventory_body, load_device_token, load_enrollment, save_device_token,
    save_enrollment, write_status_summary,
};
use crate::install::{
    INSTALLER_SERVICE_ACTOR_ID, InstallAuditEvents, InstallError, Installer, InstallerSources,
};
use crate::pi_update::{PiUpdateEngine, PiUpdateError, PiUpdateSources};
use crate::policy::{
    ApplicationPolicyAction, ApplicationPolicyLayer, EffectiveDocument, Layer, compute_effective,
    evaluate_application_policy, load_policy_dir, write_effective_debug_copy,
};
use crate::state::{
    MigrationOutcome, OsDefaultsStore, PreferenceEntry, PreferencesStore, load_or_create_device_id,
    migrate_m3_store,
};
use crate::update_check::{UpdateCheckEngine, UpdateCheckError, UpdateCheckSources};
use crate::update_status::{UpdateStatusEngine, UpdateStatusSources};
use crate::update_transaction::{
    UpdateTransactionEngine, UpdateTransactionError, UpdateTransactionSources,
};
use crate::util::{lookup_gid, lookup_username, random_hex, sha256_hex};

mod m9;

use m9::MutationAuthority;

/// Audit `resource` for the M5 enrollment mutations (ipc.md section 6).
pub const RESOURCE_ENROLLMENT: &str = "enrollment";
/// M10 `--trigger` value punard sends to the data owner on an enrollment
/// transition (milestone-10.md sections 3.3, 13.1).
pub const SCAN_TRIGGER_ENROLL: &str = "enroll";

/// Audit `resource` for the M5 `enroll.sync` transition events.
pub const RESOURCE_CONTROL_PLANE: &str = "control_plane";

/// RAII guard serializing enrollment transitions (compare-exchange on a
/// flag; released on drop).
struct EnrollGuard<'a>(&'a AtomicBool);

impl<'a> EnrollGuard<'a> {
    fn acquire(flag: &'a AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| EnrollGuard(flag))
    }
}

impl Drop for EnrollGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// RAII guard for the one destructive installer transaction admitted by a
/// live boot. `install.status` and `install.recovery_ack` deliberately do not
/// take this guard: they must remain responsive while `install.apply` blocks
/// at the recovery checkpoint on another connection.
struct InstallGuard<'a>(&'a AtomicBool);

impl<'a> InstallGuard<'a> {
    fn acquire(flag: &'a AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| InstallGuard(flag))
    }
}

impl Drop for InstallGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

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
    /// `/proc` (injectable for tests). Read for exactly one thing: the
    /// connected peer's cgroup, to attribute a call made from inside a
    /// managed agent session (docs/api/ipc.md section 12.5).
    pub proc_root: PathBuf,
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
    /// M9: the approval summary the shell watches (docs/api/ipc.md section
    /// 15). `/run/punard/approvals.json` in production — deliberately
    /// inside the `0750 root:punar` runtime directory, not beside the
    /// world-readable `status.json` summary. Defaults to a
    /// state-dir file so embedded/test daemons never write outside their
    /// tempdir.
    pub approvals_file: PathBuf,
    /// M9: the shipped AI authority document (SPEC section 20).
    pub ai_defaults_file: PathBuf,
    /// M9: the uid an agent-raised approval is routed to — the console
    /// user. 1000 in the image (`punar`); injectable for tests. Not a
    /// presence check: see `Inner::console_user`.
    pub console_uid: u32,
    /// M10: the sibling `punar-agentd` socket — the single inter-daemon
    /// edge (milestone-10.md section 7.3). **Outbound only.** punard opens
    /// no listener for it, agentd never calls back, and the graph stays a
    /// DAG. Injectable for tests / overridable via `PUNAR_AGENTD_SOCKET`.
    pub agentd_socket: PathBuf,
    /// Read-only hardware observation paths (procfs/sysfs in production,
    /// ordinary files in tests).
    pub device_sources: DeviceSources,
    /// Typed CI seam. Production leaves this unset and reports `observed`.
    pub device_class_override: Option<punar_common::DeviceClass>,
    /// Immutable application catalog shipped in the signed OS image. `None`
    /// disables the surface for non-desktop builds and host tests.
    pub app_catalog_path: Option<PathBuf>,
    /// Flatpak client binary; injectable so tests can prove fixed argv and
    /// fail-closed verification without modifying the host.
    pub flatpak_bin: PathBuf,
    /// Cross-architecture integration-test seam. Production always leaves
    /// this unset and uses the compiled target architecture.
    pub app_arch_override: Option<String>,
    /// Installer methods are registered only in a UKI carrying the exact
    /// `punar.live=1` command-line token. Installed systems leave this false.
    pub live_mode: bool,
    /// Read-only block/release inputs. All paths are injectable for contract
    /// tests; no installer operation accepts a path from its caller.
    pub installer_sources: InstallerSources,
    /// Read-only local evidence consumed by `update.status`. Production uses
    /// fixed OS paths; tests inject ordinary files.
    pub update_status_sources: UpdateStatusSources,
    /// Fixed authenticated channel source, trust anchors and verified-cache
    /// paths consumed by `update.check`. No field is caller-controlled.
    pub update_check_sources: UpdateCheckSources,
    /// Fixed UEFI slot/ESP paths for the governed update transaction.
    pub update_transaction_sources: UpdateTransactionSources,
    /// Fixed Raspberry Pi firmware/slot paths for the same public method.
    pub pi_update_sources: PiUpdateSources,
}

impl DaemonConfig {
    pub fn new(socket_path: PathBuf, state_dir: PathBuf, audit_path: PathBuf) -> Self {
        let status_file = state_dir.join("status.json");
        let approvals_file = state_dir.join("approvals.json");
        let update_check_sources = UpdateCheckSources {
            cached_channel: state_dir.join("update/verified-channel.json"),
            cached_signature: state_dir.join("update/verified-channel.json.sig"),
            ..UpdateCheckSources::default()
        };
        let update_transaction_sources = UpdateTransactionSources {
            pending_uefi: state_dir.join("update/pending-uefi.json"),
            ..UpdateTransactionSources::default()
        };
        let pi_update_sources = PiUpdateSources {
            pending_state: state_dir.join("update/pending-pi.json"),
            ..PiUpdateSources::default()
        };
        DaemonConfig {
            socket_path,
            state_dir,
            audit_path,
            group: "punar".to_string(),
            group_file: PathBuf::from("/etc/group"),
            passwd_file: PathBuf::from("/etc/passwd"),
            proc_root: PathBuf::from("/proc"),
            peer_source: PeerSource::SoPeercred,
            max_connections: 16,
            io_timeout: SERVER_READ_TIMEOUT,
            control_plane_socket: PathBuf::from(DEFAULT_CONTROL_PLANE_SOCKET),
            status_file,
            os_release_path: PathBuf::from("/etc/os-release"),
            kernel_release_path: PathBuf::from("/proc/sys/kernel/osrelease"),
            approvals_file,
            ai_defaults_file: PathBuf::from(punar_common::aipolicy::AI_DEFAULTS_FILE),
            console_uid: DEFAULT_CONSOLE_UID,
            agentd_socket: PathBuf::from(crate::agentd::DEFAULT_AGENTD_SOCKET),
            device_sources: DeviceSources::default(),
            device_class_override: None,
            app_catalog_path: None,
            flatpak_bin: PathBuf::from("/usr/bin/flatpak"),
            app_arch_override: None,
            live_mode: false,
            installer_sources: InstallerSources::default(),
            update_status_sources: UpdateStatusSources::default(),
            update_check_sources,
            update_transaction_sources,
            pi_update_sources,
        }
    }
}

/// The image's session user (`punar`, uid 1000) — who an agent-raised
/// approval is routed to on an unenrolled personal device.
pub const DEFAULT_CONSOLE_UID: u32 = 1000;

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
    /// SPEC section 46 application lifecycle policy. Kept outside the scalar
    /// capability map because required/denied are set-membership decisions.
    application_policy: Mutex<Vec<ApplicationPolicyLayer>>,
    /// The merged effective document — in-memory truth, recomputed at
    /// startup and on every `capabilities.set`.
    effective: Mutex<EffectiveDocument>,
    tracker: Mutex<ComplianceTracker>,
    device_id: String,
    /// Read-only observed fact. Never enters the capability reconcile loop.
    device_profile: punar_common::DeviceProfile,
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
    /// M9: approvals and privilege grants — one store, one lock, one
    /// expiry sweep (crate::approvals).
    approvals: Mutex<ApprovalStore>,
    /// M9: the effective AI authority (SPEC section 20). Reloaded on every
    /// enrollment transition, because an org layer may carry one.
    ai: Mutex<AiAuthority>,
    /// Serializes `enroll.start`/`enroll.stop` without holding the state
    /// lock across the network + reconcile pipeline.
    enroll_in_progress: AtomicBool,
    /// One destructive install per live boot. This is a compare-exchange
    /// guard rather than a blocking mutex so a duplicate Apply receives an
    /// immediate, truthful conflict while status and recovery acknowledgement
    /// continue over separate connections.
    install_in_progress: AtomicBool,
    shutdown: AtomicBool,
    active: Mutex<usize>,
    slot_freed: Condvar,
    apps: AppManager,
    /// Flatpak has its own transaction lock, but serializing at the typed
    /// API also makes our inspect→mutate→verify chain indivisible.
    app_mutation: Mutex<()>,
    installer: Installer,
    update_status: UpdateStatusEngine,
    update_check: UpdateCheckEngine,
    update_transaction: UpdateTransactionEngine,
    pi_update: PiUpdateEngine,
    /// Discovery and slot mutation share one lock: a channel head cannot be
    /// replaced between release selection and staging.
    update_lock: Mutex<()>,
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
        let device_profile = observe_profile(&cfg.device_sources, cfg.device_class_override);
        let apps = AppManager::load_for_arch(
            cfg.app_catalog_path.as_deref(),
            cfg.flatpak_bin.clone(),
            cfg.app_arch_override.as_deref(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if let Err(error) = apps.reconcile_vendor_desktop_integration() {
            // A corrupt or full mutable app volume must not take down the
            // device control plane at boot. The signed catalog itself already
            // failed closed in `load_for_arch`; keep serving typed diagnostics
            // and let the next app install/remove retry this derived index.
            eprintln!("punard: vendor desktop integration repair failed: {error}");
        }
        let mut installer_sources = cfg.installer_sources.clone();
        installer_sources.live_device_id_path = cfg.state_dir.join("device-id");
        installer_sources.live_audit_path = cfg.audit_path.clone();
        let installer = Installer::new(installer_sources);
        let update_status = UpdateStatusEngine::new(cfg.update_status_sources.clone());
        let update_check = UpdateCheckEngine::new(cfg.update_check_sources.clone());
        let update_transaction =
            UpdateTransactionEngine::new(cfg.update_transaction_sources.clone());
        let pi_update = PiUpdateEngine::new(cfg.pi_update_sources.clone());
        if cfg.live_mode {
            installer
                .initialize_status_file()
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
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

        // M9: the approval store and the AI authority document. A store
        // that will not open is fatal — a daemon that cannot record an
        // approval must not serve a gate it cannot honour.
        let approvals = ApprovalStore::load(
            &cfg.state_dir,
            cfg.approvals_file.clone(),
            lookup_gid(&cfg.group_file, &cfg.group),
        )?;
        let ai =
            crate::aipolicy::load_authority(&cfg.ai_defaults_file, &cfg.state_dir.join("policy.d"));

        let daemon = Daemon {
            inner: Arc::new(Inner {
                cfg,
                registry,
                audit: Mutex::new(audit),
                audit_events: AtomicU64::new(audit_events),
                os_defaults,
                preferences,
                org_layers: Mutex::new(loaded.layers),
                application_policy: Mutex::new(loaded.applications),
                effective: Mutex::new(effective),
                tracker: Mutex::new(ComplianceTracker::default()),
                device_id,
                device_profile,
                started_at: utc_now_rfc3339(),
                last_reconcile: Mutex::new(None),
                enrollment: Mutex::new(enrollment),
                device_token: Mutex::new(device_token),
                pending_compliance: AtomicBool::new(false),
                pending_inventory: AtomicBool::new(false),
                last_sync_outcome: Mutex::new(None),
                status_written: Mutex::new(None),
                approvals: Mutex::new(approvals),
                ai: Mutex::new(ai),
                enroll_in_progress: AtomicBool::new(false),
                install_in_progress: AtomicBool::new(false),
                shutdown: AtomicBool::new(false),
                active: Mutex::new(0),
                slot_freed: Condvar::new(),
                apps,
                app_mutation: Mutex::new(()),
                installer,
                update_status,
                update_check,
                update_transaction,
                pi_update,
                update_lock: Mutex::new(()),
            }),
        };
        // First write of the ipc.md section 9 summary file (rewritten by
        // the boot reconcile moments later with computed compliance), and
        // of the section 15 approval summary — which must exist and read
        // "nothing pending" before the socket opens, so the overlay never
        // has to distinguish "no approvals" from "punard has not started".
        daemon.inner.publish_status_summary();
        {
            let store = daemon.inner.approvals.lock().unwrap();
            daemon.inner.publish_approvals_summary(&store);
        }
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

fn app_ipc_error(error: AppError) -> IpcError {
    let (code, what, next) = match &error {
        AppError::InvalidCatalog(_) => (
            ErrorCode::Internal,
            "The application catalog could not be trusted",
            "verify the signed OS image and restart punard",
        ),
        AppError::NotFound(_) => (
            ErrorCode::NotFound,
            "That application is not in this Punar catalog",
            "run `punarctl app search <words>` to see supported applications",
        ),
        AppError::Unsupported { .. } => (
            ErrorCode::Conflict,
            "That application has no native package for this device",
            "inspect the app card for its supported web or architecture-specific path",
        ),
        AppError::Verification(_) => (
            ErrorCode::VerifyFailed,
            "The application source changed after it was cataloged",
            "refresh to a newly signed Punar catalog before retrying",
        ),
        AppError::Policy(_) => (
            ErrorCode::Denied,
            "Application policy refused that package",
            "choose a sandboxed package or wait for the explicit broad-access approval surface",
        ),
        AppError::Backend(_) => (
            ErrorCode::ApplyFailed,
            "The application service could not complete the request",
            "check network connectivity and `flatpak remotes`, then retry",
        ),
    };
    IpcError::with_details(
        code,
        format!("{what}.\nWhy: {error}.\nNext step: {next}."),
        json!({ "component": "application_catalog" }),
    )
}

fn install_unknown_on_installed(method: &str) -> IpcError {
    IpcError::with_details(
        ErrorCode::UnknownMethod,
        format!(
            "The method {method:?} does not exist on an installed Punar system. Installer methods are registered only by a signed live environment carrying punar.live=1. Next step: boot the Punar installation medium."
        ),
        json!({ "method": method, "mode": "installed" }),
    )
}

fn install_ipc_error(error: InstallError) -> IpcError {
    let code = match error {
        InstallError::Refused(_) | InstallError::Invalid(_) => ErrorCode::InvalidParams,
        InstallError::Trust(_) => ErrorCode::VerifyFailed,
        InstallError::Io(_) => ErrorCode::Internal,
    };
    IpcError::with_details(
        code,
        format!(
            "The installation plan was not accepted: {error}. No disk bytes were changed. Next step: refresh disk targets and correct the named condition before trying again."
        ),
        json!({ "component": "installer", "disk_changed": false }),
    )
}

fn install_targets_ipc_error(error: InstallError) -> IpcError {
    IpcError::with_details(
        ErrorCode::Internal,
        format!(
            "Punar could not inspect the available installation disks: {error}. No disk bytes were changed. Next step: reconnect the installation media or storage device, then refresh the disk list."
        ),
        json!({ "component": "installer_discovery", "disk_changed": false }),
    )
}

fn install_apply_ipc_error(error: InstallError, disk_changed: bool) -> IpcError {
    let code = match &error {
        InstallError::Refused(_) | InstallError::Invalid(_) => ErrorCode::InvalidParams,
        InstallError::Trust(_) => ErrorCode::VerifyFailed,
        InstallError::Io(_) if disk_changed => ErrorCode::ApplyFailed,
        InstallError::Io(_) => ErrorCode::Internal,
    };
    let disk_state = if disk_changed {
        "The selected disk may be partially prepared and is not guaranteed to boot."
    } else {
        "No disk bytes were changed by the installer."
    };
    let next = if disk_changed {
        "Restart from the signed Punar installation medium and begin the installation again."
    } else {
        "Correct the reported condition, refresh the plan, and try again."
    };
    IpcError::with_details(
        code,
        format!("The installation did not complete: {error}. {disk_state} Next step: {next}"),
        json!({ "component": "installer", "disk_changed": disk_changed }),
    )
}

fn install_status_disk_changed(status: &InstallStatusResult) -> bool {
    matches!(
        status.phase,
        Some(
            InstallPhase::Partition
                | InstallPhase::Encrypt
                | InstallPhase::Format
                | InstallPhase::WriteSlotA
                | InstallPhase::ReRead
                | InstallPhase::Boot
                | InstallPhase::Seed
                | InstallPhase::VerifyInstalled
        )
    )
}

fn install_recovery_event(device_id: &str, actor: &AuditActor) -> AuditEvent {
    let mut event = AuditEvent::action(
        device_id,
        actor,
        "install.recovery_key",
        "system_disk",
        Decision::Allow,
        AuditOutcome::Success,
    );
    event.result = "enrolled".into();
    event
}

fn update_check_ipc_error(error: UpdateCheckError) -> IpcError {
    let stage = error.stage();
    if error.is_unreachable() {
        return IpcError::with_details(
            ErrorCode::UpstreamUnreachable,
            format!(
                "Punar could not reach its configured update source: {error}. The running release and verified cache were not changed.\n\
                 Policy: governed updates never fall through to another channel or an unverified mirror.\n\
                 Next step: reconnect the configured update source and retry `sudo punarctl update check`."
            ),
            json!({ "stage": stage }),
        );
    }
    if error.is_untrusted() {
        return IpcError::with_details(
            ErrorCode::UntrustedArtifact,
            "This release could not be verified. Punar will not install software it cannot check. The running release and verified cache were not changed.\n\
             Policy: every channel document must match this device and verify against the pinned release-key set.\n\
             Next step: do not retry from another mirror; inspect the release publication and trusted-key deployment.",
            json!({ "stage": stage }),
        );
    }
    IpcError::with_details(
        ErrorCode::Internal,
        format!(
            "Punar could not complete the authenticated update check: {error}. The running release was not changed.\n\
             Policy: incomplete local identity or an unwritable verified cache fails closed.\n\
             Next step: inspect `journalctl -u punard` and the root-owned update state, then retry."
        ),
        json!({ "stage": stage }),
    )
}

fn update_prepare_ipc_error(error: UpdateCheckError) -> IpcError {
    if let Some((required_bytes, available_bytes)) = error.insufficient_space() {
        return IpcError::with_details(
            ErrorCode::InsufficientSpace,
            "Punar does not have enough private cache space for the signed release. No root slot or boot entry was changed. Next step: free space under /var and retry.",
            json!({
                "stage": error.stage(),
                "required_bytes": required_bytes,
                "available_bytes": available_bytes,
            }),
        );
    }
    update_check_ipc_error(error)
}

fn update_transaction_ipc_error(error: UpdateTransactionError) -> IpcError {
    let stage = error.stage();
    match error {
        UpdateTransactionError::Trust { .. } => IpcError::with_details(
            ErrorCode::UntrustedArtifact,
            "This release could not be verified. Punar did not install its boot artifact. Next step: inspect the signed publication and do not substitute another mirror.",
            json!({ "stage": stage }),
        ),
        UpdateTransactionError::Verify(_) => IpcError::with_details(
            ErrorCode::VerifyFailed,
            format!(
                "Punar wrote the inactive slot but could not verify what the device retained: {error}. The new release was not made bootable. Next step: inspect storage health before retrying."
            ),
            json!({ "stage": stage }),
        ),
        UpdateTransactionError::InsufficientSpace {
            required_bytes,
            available_bytes,
        } => IpcError::with_details(
            ErrorCode::InsufficientSpace,
            "The fixed inactive root slot is too small for this signed release. No boot entry was installed.",
            json!({
                "stage": stage,
                "required_bytes": required_bytes,
                "available_bytes": available_bytes,
            }),
        ),
        UpdateTransactionError::Conflict(_) => IpcError::with_details(
            ErrorCode::Conflict,
            format!(
                "Punar did not change the boot selector because the device state conflicts with this update: {error}. Next step: inspect `punarctl update status`."
            ),
            json!({ "stage": stage }),
        ),
        UpdateTransactionError::NotFound(_) => IpcError::with_details(
            ErrorCode::NotFound,
            format!(
                "The requested last-known-good release is not present on the ESP: {error}. No selector was changed."
            ),
            json!({ "stage": stage }),
        ),
        UpdateTransactionError::Apply(_) | UpdateTransactionError::Io(_) => IpcError::with_details(
            ErrorCode::ApplyFailed,
            format!(
                "Punar could not finish the inactive-slot transaction: {error}. No unverified UKI was selected. Next step: inspect `journalctl -u punard` and retry after correcting the device error."
            ),
            json!({ "stage": stage }),
        ),
    }
}

fn pi_update_ipc_error(error: PiUpdateError) -> IpcError {
    match error {
        PiUpdateError::Trust(reason) => IpcError::with_details(
            ErrorCode::UntrustedArtifact,
            "This Raspberry Pi release could not be verified, so firmware was not pointed at it.",
            json!({ "stage": "pi_release", "reason": reason }),
        ),
        PiUpdateError::Conflict(reason) | PiUpdateError::Refused(reason) => IpcError::with_details(
            ErrorCode::Conflict,
            format!("Punar did not change the Raspberry Pi selector: {reason}."),
            json!({ "stage": "pi_device_state" }),
        ),
        PiUpdateError::Invalid(reason) => IpcError::with_details(
            ErrorCode::InvalidParams,
            format!("The signed Raspberry Pi update input is invalid: {reason}."),
            json!({ "stage": "pi_release" }),
        ),
        PiUpdateError::Io(error) | PiUpdateError::Install(InstallError::Io(error)) => {
            IpcError::with_details(
                ErrorCode::ApplyFailed,
                format!(
                    "Raspberry Pi update I/O failed: {error}. Firmware was not committed to the candidate."
                ),
                json!({ "stage": "pi_io" }),
            )
        }
        PiUpdateError::Install(error) => IpcError::with_details(
            ErrorCode::ApplyFailed,
            format!(
                "Raspberry Pi update staging failed: {error}. Firmware was not committed to the candidate."
            ),
            json!({ "stage": "pi_apply" }),
        ),
    }
}

fn write_personal_recovery_disclosure(
    output: &mut dyn Write,
    recovery_key: &str,
    challenge_groups: [u8; 2],
) -> Result<(), InstallError> {
    (|| -> io::Result<()> {
        output.write_all(b"PUNAR-RECOVERY-V1\n")?;
        output.write_all(recovery_key.as_bytes())?;
        output.write_all(b"\n")?;
        writeln!(output, "{} {}", challenge_groups[0], challenge_groups[1])?;
        output.flush()
    })()
    .map_err(|error| {
        InstallError::Io(io::Error::new(
            error.kind(),
            format!("personal recovery disclosure: {error}"),
        ))
    })
}

/// Disclose generated unattended-install custody material exclusively through
/// the caller's sealed recovery channel. The client must durably write and
/// re-read both secrets on the signed answer medium before acknowledging the
/// challenged recovery-key groups.
fn write_unattended_recovery_disclosure(
    output: &mut dyn Write,
    passphrase: &[u8],
    recovery_key: &str,
    challenge_groups: [u8; 2],
) -> Result<(), InstallError> {
    (|| -> io::Result<()> {
        output.write_all(b"PUNAR-UNATTENDED-CUSTODY-V1\n")?;
        output.write_all(passphrase)?;
        output.write_all(b"\n")?;
        output.write_all(recovery_key.as_bytes())?;
        output.write_all(b"\n")?;
        writeln!(output, "{} {}", challenge_groups[0], challenge_groups[1])?;
        output.flush()
    })()
    .map_err(|error| {
        InstallError::Io(io::Error::new(
            error.kind(),
            format!("unattended recovery disclosure: {error}"),
        ))
    })
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

    /// Installation cannot safely defer an audit write: the installed audit
    /// handoff requires the plan as its origin record, and discovering a
    /// missing origin only after partitioning would turn an audit outage into
    /// a partially destructive install. Other established mutation surfaces
    /// retain their response contract; the installer alone fails closed
    /// before it returns a usable plan token.
    fn log_install_plan_required(&self, event: AuditEvent) -> Result<(), IpcError> {
        match self.audit.lock().unwrap().append(&event) {
            Ok(()) => {
                self.audit_events.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                eprintln!("punard: FAILED to append required install.plan audit event: {error}");
                Err(IpcError::with_details(
                    ErrorCode::Internal,
                    "Installation planning stopped because Punar could not durably record its origin. No disk bytes were changed.\n\
                     Policy: os hard safety constraint — an installation cannot begin without its audit trail.\n\
                     Next step: verify free space and /var/log/punar permissions, then retry.",
                    json!({ "component": "installer_audit", "disk_changed": false }),
                ))
            }
        }
    }

    /// The audit attribution for one connected peer.
    ///
    /// M3: the resolved username, `source: human`. M8 adds the section-12.5
    /// rule on top — if the peer's own cgroup says it is running inside a
    /// `punar-agent-<id>.scope`, the event names that session and its
    /// source becomes `ai_agent`. The agent does not get asked and cannot
    /// opt out: the evidence is the kernel's, not the caller's. This is
    /// what makes a *denial* inside a managed session visible to the M8
    /// Access Ledger as a Level-4 `denied_access` event.
    fn actor_of(&self, peer: &Peer) -> AuditActor {
        let actor = match lookup_username(&self.cfg.passwd_file, peer.uid) {
            Some(name) => AuditActor::cli_peer(name),
            None => AuditActor::cli_peer_uid(peer.uid),
        };
        match crate::authz::agent_session_of_peer(&self.cfg.proc_root, peer) {
            Some(session_id) => actor.with_agent_session(session_id),
            None => actor,
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

    /// M9: re-read the AI authority documents (SPEC section 20) after an
    /// enrollment transition, so an organization that publishes one takes
    /// effect the moment its layer lands — the same live-reload the
    /// enrollment chain already does for desired-state layers.
    fn reload_ai_authority(&self) {
        let authority = crate::aipolicy::load_authority(
            &self.cfg.ai_defaults_file,
            &self.cfg.state_dir.join("policy.d"),
        );
        *self.ai.lock().unwrap() = authority;
    }

    /// Dispatch a typed request. The method table is closed at the type
    /// level ([`Method`]): unknown names never reach this point — they were
    /// already answered with `unknown_method` by the parse pipeline (SPEC
    /// sections 10, 60: no generic execution method exists, ever).
    fn dispatch(&self, peer: &Peer, request: &Request) -> Result<Value, IpcError> {
        if matches!(
            request.method,
            Method::InstallTargets
                | Method::InstallPlan(_)
                | Method::InstallApply(_)
                | Method::InstallRecoveryAck(_)
                | Method::InstallStatus
        ) && !self.cfg.live_mode
        {
            return Err(install_unknown_on_installed(request.method.name()));
        }
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
            // M9 (contract section 14.2).
            Method::ApprovalsList => self.handle_approvals_list(),
            Method::ApprovalsGet(params) => self.handle_approvals_get(params),
            Method::ApprovalsCreate(params) => self.handle_approvals_create(peer, params),
            Method::ApprovalsResolve(params) => self.handle_approvals_resolve(peer, params),
            Method::ApprovalsConsume(params) => self.handle_approvals_consume(peer, params),
            Method::PrivilegeRequest(params) => self.handle_privilege_request(peer, params),
            Method::PrivilegeStatus => self.handle_privilege_status(peer),
            Method::PrivilegeRevoke(params) => self.handle_privilege_revoke(peer, params),
            Method::AppsCatalog(params) => self.handle_apps_catalog(params),
            Method::AppsList => self.handle_apps_list(),
            Method::AppsInstall(params) => self.handle_apps_install(peer, params),
            Method::AppsRemove(params) => self.handle_apps_remove(peer, params),
            Method::AppsUpdate(params) => self.handle_apps_update(peer, params),
            Method::UpdateStatus => Ok(to_value(self.handle_update_status())),
            Method::UpdateCheck(params) => self.handle_update_check(peer, params),
            Method::UpdateApply(params) => self.handle_update_apply(peer, params),
            Method::UpdateRollback(params) => self.handle_update_rollback(peer, params),
            Method::InstallTargets => self
                .installer
                .targets()
                .map(to_value)
                .map_err(install_targets_ipc_error),
            Method::InstallPlan(params) => self.handle_install_plan(peer, params),
            Method::InstallApply(params) => self.handle_install_apply(peer, params),
            Method::InstallRecoveryAck(params) => self.handle_install_recovery_ack(peer, params),
            Method::InstallStatus => Ok(to_value(self.installer.status())),
        }
    }

    fn handle_update_status(&self) -> UpdateStatusResult {
        let mut status = self.update_status.status();
        if let Some(entry) = self.effective.lock().unwrap().get("system.update_channel") {
            if let Some(channel) = effective_update_channel(&entry.value) {
                status.channel.name = channel;
            } else {
                status.channel.reachable = false;
                status.channel.reason = Some(
                    "the effective update channel is invalid; no update will be selected"
                        .to_string(),
                );
            }
            status.channel.source = match entry.provenance.kind {
                punar_policy::SourceKind::LocalUserPreference => "personal-preference".into(),
                punar_policy::SourceKind::OsSecureDefault => "os-default".into(),
                other => other.as_str().to_string(),
            };
            status.channel.policy_ids = vec![entry.provenance.policy_id.clone()];
        }
        status
    }

    fn handle_update_check(
        &self,
        peer: &Peer,
        params: &UpdateCheckParams,
    ) -> Result<Value, IpcError> {
        const ACTION: &str = "update.check";
        const RESOURCE: &str = "update_channel";
        let actor = self.actor_of(peer);
        if authorize_mutation(peer) != Decision::Allow {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                ACTION,
                RESOURCE,
            ));
            return Err(IpcError::denied_needs_root(
                "checking the governed update channel",
                Some(RESOURCE),
                "sudo punarctl update check",
            ));
        }

        let channel = self
            .effective
            .lock()
            .unwrap()
            .get("system.update_channel")
            .and_then(|entry| effective_update_channel(&entry.value))
            .ok_or_else(|| {
                let mut event = AuditEvent::action(
                    &self.device_id,
                    &actor,
                    ACTION,
                    RESOURCE,
                    Decision::Allow,
                    AuditOutcome::Failure,
                );
                event.policy_ids = vec![punar_common::audit::POLICY_PERSONAL_DEFAULTS.into()];
                self.log_audit(event);
                IpcError::with_details(
                    ErrorCode::InvalidParams,
                    "Punar could not check for updates because the effective update channel is invalid. The running release was not changed.\n\
                     Policy: the precedence-resolved system.update_channel value must be stable, dev, or edge.\n\
                     Next step: inspect `punarctl policy explain system.update_channel` and correct the winning policy.",
                    json!({ "stage": "effective_channel" }),
                )
            })?;

        let _guard = self.update_lock.lock().unwrap();
        match self
            .update_check
            .check(channel, &self.device_id, params.force)
        {
            Ok(result) => {
                let outcome = if result.admissible {
                    AuditOutcome::Success
                } else {
                    AuditOutcome::Noop
                };
                self.log_audit(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    ACTION,
                    RESOURCE,
                    Decision::Allow,
                    outcome,
                ));
                Ok(to_value::<UpdateCheckResult>(result))
            }
            Err(error) => {
                let mut event = AuditEvent::action(
                    &self.device_id,
                    &actor,
                    ACTION,
                    RESOURCE,
                    Decision::Allow,
                    AuditOutcome::Failure,
                );
                if error.is_unreachable() {
                    event.result = "unreachable".into();
                }
                self.log_audit(event);
                Err(update_check_ipc_error(error))
            }
        }
    }

    fn authorize_system_update(&self, peer: &Peer, action: &str) -> Result<AuditActor, IpcError> {
        let actor = self.actor_of(peer);
        if actor.source == PrincipalKind::AiAgent {
            let ruling = self.ai.lock().unwrap().host_ruling("system_update");
            // An update/rollback is an OS hard-safety boundary for agents,
            // not an authority an organization can grant back. Cite a loaded
            // policy only when it actually denies the named rule; otherwise
            // cite the non-overridable boundary instead of falsely claiming
            // that an `allow` ruling caused this denial.
            let denying_ruling = ruling
                .as_ref()
                .filter(|value| value.decision == Decision::Deny);
            let policy_id = denying_ruling
                .map(|value| value.policy_id.as_str())
                .unwrap_or("os-hard-safety");
            let source_name = denying_ruling
                .map(|value| value.source_name.as_str())
                .unwrap_or("Punar OS hard safety constraint");
            let mut event = AuditEvent::action(
                &self.device_id,
                &actor,
                action,
                "system_image",
                Decision::Deny,
                AuditOutcome::Denied,
            );
            event.policy_ids = vec![policy_id.to_string()];
            self.log_audit(event);
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "An AI agent may not replace or roll back the operating system.\n\
                     Policy: {source_name} ({policy_id}) — host.system_update is denied to agents.\n\
                     Next step: make the change yourself with `sudo punarctl update apply <version>` or `sudo punarctl update rollback`."
                ),
                json!({
                    "decision": "deny",
                    "resource": "system_image",
                    "rule": "host.system_update",
                    "agent_session_id": actor.agent_session_id,
                    "policy_ids": [policy_id],
                }),
            ));
        }
        if authorize_mutation(peer) != Decision::Allow {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                action,
                "system_image",
            ));
            return Err(IpcError::denied_needs_root(
                "changing the operating-system boot slots",
                Some("system_image"),
                "sudo punarctl update apply <version>",
            ));
        }
        Ok(actor)
    }

    fn effective_update_channel(&self) -> Result<UpdateChannel, IpcError> {
        self.effective
            .lock()
            .unwrap()
            .get("system.update_channel")
            .and_then(|entry| effective_update_channel(&entry.value))
            .ok_or_else(|| {
                IpcError::with_details(
                    ErrorCode::InvalidParams,
                    "Punar cannot select a release because the effective update channel is invalid. No slot was changed. Next step: inspect `punarctl policy explain system.update_channel`.",
                    json!({ "stage": "effective_channel" }),
                )
            })
    }

    fn handle_update_apply(
        &self,
        peer: &Peer,
        params: &UpdateApplyParams,
    ) -> Result<Value, IpcError> {
        const ACTION: &str = "update.apply";
        let actor = self.authorize_system_update(peer, ACTION)?;
        let _guard = self.update_lock.lock().unwrap();
        let result = (|| -> Result<UpdateApplyResult, IpcError> {
            // Keep even a corrupt/missing effective channel inside the audited
            // transaction result; successful authorization must never produce
            // an unaudited update failure.
            let channel = self.effective_update_channel()?;
            // Applying is a security boundary, so it must not trust a channel
            // decision left in the cache by an earlier check. Refresh the
            // signed head while holding the transaction lock; prepare_release
            // then re-verifies those exact cached bytes and enforces halt,
            // rollout, minimum-version and downgrade admission before any slot
            // is opened for writing.
            self.update_check
                .check(channel, &self.device_id, true)
                .map_err(update_check_ipc_error)?;
            let is_pi = self.cfg.pi_update_sources.boot_partition_property.exists();
            let slot = if is_pi {
                None
            } else {
                Some(
                    self.update_transaction
                        .inactive_slot()
                        .map_err(update_transaction_ipc_error)?,
                )
            };
            let prepared = self
                .update_check
                .prepare_release(
                    channel,
                    &self.device_id,
                    params.version,
                    params.allow_downgrade,
                    slot,
                )
                .map_err(update_prepare_ipc_error)?;
            if is_pi {
                let target = self
                    .update_check
                    .release_target(channel)
                    .map_err(update_prepare_ipc_error)?;
                let current = self
                    .update_check
                    .current_version()
                    .map_err(update_prepare_ipc_error)?;
                let staged = self
                    .pi_update
                    .stage_bundle(
                        &prepared.release_dir,
                        self.update_check.trusted_keys_dir(),
                        &target,
                        current,
                    )
                    .map_err(pi_update_ipc_error)?;
                Ok(UpdateApplyResult {
                    v: 1,
                    staged_version: staged.version,
                    staged_slot: match staged.staged_slot {
                        crate::pi_update::PiSlot::A => punar_common::update::UpdateSlot::A,
                        crate::pi_update::PiSlot::B => punar_common::update::UpdateSlot::B,
                    },
                    requires_reboot: true,
                    bytes_written: staged.bytes_written,
                    verified: staged.verified,
                })
            } else {
                self.update_transaction
                    .stage(&prepared)
                    .map_err(update_transaction_ipc_error)
            }
        })();
        match result {
            Ok(result) => {
                self.log_audit(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    ACTION,
                    "system_image",
                    Decision::Allow,
                    AuditOutcome::Success,
                ));
                Ok(to_value(result))
            }
            Err(error) => {
                self.log_audit(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    ACTION,
                    "system_image",
                    Decision::Allow,
                    AuditOutcome::Failure,
                ));
                Err(error)
            }
        }
    }

    fn handle_update_rollback(
        &self,
        peer: &Peer,
        params: &UpdateRollbackParams,
    ) -> Result<Value, IpcError> {
        const ACTION: &str = "update.rollback";
        let actor = self.authorize_system_update(peer, ACTION)?;
        let _guard = self.update_lock.lock().unwrap();
        let result = if self.cfg.pi_update_sources.boot_partition_property.exists() {
            self.pi_update
                .rollback(params.to_version)
                .map(to_value)
                .map_err(pi_update_ipc_error)
        } else {
            self.update_transaction
                .rollback(params.to_version)
                .map(to_value)
                .map_err(update_transaction_ipc_error)
        };
        match result {
            Ok(value) => {
                self.log_audit(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    ACTION,
                    "system_image",
                    Decision::Allow,
                    AuditOutcome::Success,
                ));
                Ok(value)
            }
            Err(error) => {
                self.log_audit(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    ACTION,
                    "system_image",
                    Decision::Allow,
                    AuditOutcome::Failure,
                ));
                Err(error)
            }
        }
    }

    fn handle_install_plan(
        &self,
        peer: &Peer,
        params: &punar_common::install::InstallPlanParams,
    ) -> Result<Value, IpcError> {
        const ACTION: &str = "install.plan";
        const RESOURCE: &str = "system_disk";
        let actor = self.actor_of(peer);
        if authorize_mutation(peer) != Decision::Allow {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                ACTION,
                RESOURCE,
            ));
            return Err(IpcError::denied_needs_root(
                "installation planning",
                Some(RESOURCE),
                "run the installer through its privileged local service",
            ));
        }
        match self.installer.plan(params) {
            Ok(plan) => {
                self.log_install_plan_required(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    ACTION,
                    RESOURCE,
                    Decision::Allow,
                    AuditOutcome::Success,
                ))?;
                Ok(to_value(plan))
            }
            Err(error) => {
                let mut event = AuditEvent::action(
                    &self.device_id,
                    &actor,
                    ACTION,
                    RESOURCE,
                    Decision::Allow,
                    AuditOutcome::Failure,
                );
                if error.is_refusal() {
                    event.result = "refused".into();
                }
                self.log_audit(event);
                Err(install_ipc_error(error))
            }
        }
    }

    /// Execute the closed, disk-bound installation transaction. The AI
    /// attribution check intentionally precedes uid authorization: root
    /// inside an agent scope is still an AI agent and may not reinstall the
    /// machine. Descriptor reads and plan revalidation also precede the first
    /// status transition, so every admission refusal leaves the target
    /// byte-identical.
    #[cfg(target_os = "linux")]
    fn handle_install_apply(
        &self,
        peer: &Peer,
        params: &InstallApplyParams,
    ) -> Result<Value, IpcError> {
        const ACTION: &str = "install.apply";
        const RESOURCE: &str = "system_image";
        let peer_actor = self.actor_of(peer);
        if self.agent_shaped_peer(peer, &peer_actor).is_some() {
            self.log_audit(AuditEvent::action(
                &self.device_id,
                &peer_actor,
                ACTION,
                RESOURCE,
                Decision::Deny,
                AuditOutcome::Denied,
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                "An AI agent may not erase a disk or install Punar, even when its process has uid 0.\n\
                 Policy: os hard safety constraint — install.apply is reserved for the person at the device or the independently signed PUNAR_ANSWR provisioner.\n\
                 Next step: open the signed Punar installer and confirm the disk yourself, or use an authorized answer medium.",
                json!({
                    "decision": "deny",
                    "resource": RESOURCE,
                    "policy_ids": ["os-hard-safety-constraint"],
                    "disk_changed": false,
                }),
            ));
        }
        if authorize_mutation(peer) != Decision::Allow {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &peer_actor,
                ACTION,
                RESOURCE,
            ));
            return Err(IpcError::denied_needs_root(
                "installation",
                Some(RESOURCE),
                "run the signed installer through its privileged local service",
            ));
        }
        let Some(_guard) = InstallGuard::acquire(&self.install_in_progress) else {
            return Err(IpcError::with_details(
                ErrorCode::Conflict,
                "An installation transaction is already active in this live boot. Next step: keep this window open and follow install.status; do not start a second disk writer.",
                json!({ "component": "installer", "disk_changed": true }),
            ));
        };

        // Begin with the authenticated peer. The executor changes this to
        // the unattended service principal only after the independently
        // signed authorization has verified; a caller cannot spoof audit
        // attribution merely by setting `unattended: true`.
        let mut actor = peer_actor;

        match self.execute_install_apply(peer, params, &mut actor) {
            Ok(events) => {
                // The installed audit handoff already contains this exact
                // terminal event and was byte-verified before success. Keep
                // the live medium's copy too; an outage here cannot erase the
                // durable installed record or turn a completed install into a
                // fabricated failure.
                self.log_audit(events.apply_success);
                Ok(to_value(self.installer.status()))
            }
            Err(error) => {
                let status = self.installer.status();
                let disk_changed = install_status_disk_changed(&status);
                if matches!(
                    status.state,
                    InstallOverallState::Running | InstallOverallState::Awaiting
                ) && let Some(phase) = status.phase
                {
                    if let Err(status_error) = self.installer.fail_transaction_status(phase, &error)
                    {
                        eprintln!(
                            "punard: could not publish the terminal installer failure: {status_error}"
                        );
                    }
                }
                self.log_audit(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    ACTION,
                    RESOURCE,
                    Decision::Allow,
                    AuditOutcome::Failure,
                ));
                Err(install_apply_ipc_error(error, disk_changed))
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn execute_install_apply(
        &self,
        peer: &Peer,
        params: &InstallApplyParams,
        actor: &mut AuditActor,
    ) -> Result<InstallAuditEvents, InstallError> {
        let plan = self.installer.preflight_apply(params)?;
        let organization = if plan.recovery_mode == InstallRecoveryMode::OrganizationEscrow {
            let enrollment = self.enrollment.lock().unwrap().clone().ok_or_else(|| {
                InstallError::Refused(
                    "organization recovery requires an enrolled live environment".into(),
                )
            })?;
            let token = self.device_token.lock().unwrap().clone().ok_or_else(|| {
                InstallError::Refused(
                    "organization recovery requires the enrolled device credential".into(),
                )
            })?;
            Some((enrollment.org.id, token))
        } else {
            None
        };
        let mut inputs = self.installer.read_apply_inputs(peer.pid, params)?;
        if params.unattended {
            let _authorization = self
                .installer
                .verify_unattended_authorization(&plan, params, &inputs)?;
            *actor = AuditActor::service(INSTALLER_SERVICE_ACTOR_ID);
            self.log_install_event_required(AuditEvent::action(
                &self.device_id,
                actor,
                "install.plan",
                "system_disk",
                Decision::Allow,
                AuditOutcome::Success,
            ))?;
        }

        self.installer.start_transaction_status(
            &params.plan_token,
            &params.disk,
            plan.payload.uncompressed_size_bytes,
        )?;
        self.installer.verify_release_payload(&plan)?;
        self.installer.enter_phase(InstallPhase::Partition)?;
        self.installer.prepare_disk_layout(&plan, &inputs)?;

        let recovery_enrolled = match plan.recovery_mode {
            InstallRecoveryMode::PersonalCopy => {
                let (recovery_key, identity) =
                    self.installer.enroll_recovery_key(&plan, &inputs)?;
                let event = install_recovery_event(&self.device_id, actor);
                self.log_install_event_required(event.clone())?;
                if params.unattended {
                    let passphrase = Zeroizing::new(
                        inputs
                            .passphrase()
                            .ok_or_else(|| {
                                InstallError::Invalid(
                                    "the generated unattended passphrase was not retained".into(),
                                )
                            })?
                            .to_vec(),
                    );
                    let output = inputs.recovery_output_mut().ok_or_else(|| {
                        InstallError::Invalid(
                            "the unattended custody output descriptor was not retained".into(),
                        )
                    })?;
                    self.installer.begin_personal_recovery(
                        &params.plan_token,
                        recovery_key,
                        identity.recovery_keyslot,
                        |text, groups| {
                            write_unattended_recovery_disclosure(
                                output,
                                passphrase.as_slice(),
                                text,
                                groups,
                            )
                        },
                    )?;
                } else {
                    let output = inputs.recovery_output_mut().ok_or_else(|| {
                        InstallError::Invalid(
                            "the personal recovery output descriptor was not retained".into(),
                        )
                    })?;
                    self.installer.begin_personal_recovery(
                        &params.plan_token,
                        recovery_key,
                        identity.recovery_keyslot,
                        |text, groups| write_personal_recovery_disclosure(output, text, groups),
                    )?;
                }
                self.installer.await_recovery_status(
                    punar_common::install::InstallAwaiting::RecoveryKeyAck,
                )?;
                self.installer
                    .wait_for_personal_recovery(&params.plan_token)?;
                self.installer.resume_recovery_status()?;
                self.installer.enter_phase(InstallPhase::Format)?;
                self.installer.enter_phase(InstallPhase::WriteSlotA)?;
                Some(event)
            }
            InstallRecoveryMode::OrganizationEscrow => {
                let (organization_id, device_token) = organization
                    .as_ref()
                    .expect("organization context was checked before destructive work");
                let (recovery_key, identity) =
                    self.installer.enroll_recovery_key(&plan, &inputs)?;
                let event = install_recovery_event(&self.device_id, actor);
                self.log_install_event_required(event.clone())?;
                self.installer.begin_organization_recovery(
                    &plan,
                    &params.plan_token,
                    organization_id,
                    recovery_key,
                    identity,
                )?;
                let client = ControlPlaneClient::new(self.cfg.control_plane_socket.clone());
                loop {
                    match self.installer.attempt_organization_recovery(
                        &params.plan_token,
                        &client,
                        device_token,
                    ) {
                        Ok(_) => break,
                        // Network/control-plane absence cannot become an
                        // implicit continue and need not destroy an already
                        // enrolled key. Keep the typed checkpoint alive and
                        // retry at a quiet fixed cadence. Signature/binding
                        // failures are trust failures and stop immediately.
                        Err(InstallError::Io(_)) if !self.shutdown.load(Ordering::SeqCst) => {
                            std::thread::sleep(Duration::from_secs(5));
                        }
                        Err(error) => return Err(error),
                    }
                }
                self.installer.enter_phase(InstallPhase::Format)?;
                self.installer.enter_phase(InstallPhase::WriteSlotA)?;
                Some(event)
            }
            InstallRecoveryMode::None => {
                debug_assert_eq!(plan.encryption, InstallEncryption::None);
                None
            }
        };

        self.installer.write_slot_a(&plan)?;
        self.installer.enter_phase(InstallPhase::ReRead)?;
        self.installer.verify_written_slot_a(&plan)?;
        self.installer.enter_phase(InstallPhase::Boot)?;
        self.installer.install_boot_artifact(&plan)?;
        self.installer
            .seed_installed_system(&plan, params, &inputs)?;

        let events = InstallAuditEvents {
            recovery_enrolled,
            apply_success: AuditEvent::action(
                &self.device_id,
                actor,
                "install.apply",
                "system_image",
                Decision::Allow,
                AuditOutcome::Success,
            ),
        };
        self.installer
            .verify_installed_system(&plan, params, &inputs, &events)?;
        Ok(events)
    }

    #[cfg(not(target_os = "linux"))]
    fn handle_install_apply(
        &self,
        _peer: &Peer,
        _params: &InstallApplyParams,
    ) -> Result<Value, IpcError> {
        Err(IpcError::with_details(
            ErrorCode::Conflict,
            "The destructive installer executor is available only in the signed Linux live environment.",
            json!({ "component": "installer", "disk_changed": false }),
        ))
    }

    #[cfg(target_os = "linux")]
    fn handle_install_recovery_ack(
        &self,
        peer: &Peer,
        params: &InstallRecoveryAckParams,
    ) -> Result<Value, IpcError> {
        let actor = self.actor_of(peer);
        let disk_changed = install_status_disk_changed(&self.installer.status());
        if self.agent_shaped_peer(peer, &actor).is_some()
            || authorize_mutation(peer) != Decision::Allow
        {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                "install.recovery_ack",
                "system_disk",
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                "Only the privileged installer or the signed unattended provisioner may acknowledge recovery-key custody. Next step: type the challenged groups in the installer window, or verify the PUNAR_ANSWR medium remains writable.",
                json!({ "decision": "deny", "disk_changed": disk_changed }),
            ));
        }
        self.installer
            .acknowledge_personal_recovery(peer.pid, params)
            .map_err(|error| install_apply_ipc_error(error, disk_changed))?;
        Ok(json!({ "acknowledged": true }))
    }

    #[cfg(not(target_os = "linux"))]
    fn handle_install_recovery_ack(
        &self,
        _peer: &Peer,
        _params: &InstallRecoveryAckParams,
    ) -> Result<Value, IpcError> {
        Err(IpcError::with_details(
            ErrorCode::Conflict,
            "Recovery acknowledgement is available only in the signed Linux live environment.",
            json!({ "component": "installer", "disk_changed": false }),
        ))
    }

    /// Recovery enrollment happens after the disk has been repartitioned, so
    /// losing this event is a hard transaction failure. The exact event is
    /// retained and handed to final installed-audit verification as well.
    fn log_install_event_required(&self, event: AuditEvent) -> Result<(), InstallError> {
        match self.audit.lock().unwrap().append(&event) {
            Ok(()) => {
                self.audit_events.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                eprintln!("punard: FAILED to append required installer audit event: {error}");
                Err(InstallError::Io(io::Error::other(
                    "the required installer audit record could not be written",
                )))
            }
        }
    }

    fn handle_apps_catalog(&self, params: &AppsCatalogParams) -> Result<Value, IpcError> {
        if params.id.is_some() && params.query.is_some() {
            return Err(IpcError::with_details(
                ErrorCode::InvalidParams,
                "Choose one application id or one search query, not both. Next step: run `punarctl app search <words>` or `punarctl app show <id>`.".to_string(),
                json!({ "params": ["id", "query"] }),
            ));
        }
        if params
            .query
            .as_ref()
            .is_some_and(|q| q.len() > 80 || q.contains('\n') || q.contains('\r'))
        {
            return Err(IpcError::with_details(
                ErrorCode::InvalidParams,
                "The application search must be one line of at most 80 characters. Next step: shorten the search and retry.".to_string(),
                json!({ "param": "query" }),
            ));
        }
        self.apps
            .catalog(params.id.as_deref(), params.query.as_deref())
            .map_err(app_ipc_error)
    }

    fn handle_apps_list(&self) -> Result<Value, IpcError> {
        self.apps.list().map_err(app_ipc_error)
    }

    fn app_mutation_authorized(
        &self,
        peer: &Peer,
        action: &str,
        id: &str,
    ) -> Result<AuditActor, IpcError> {
        let actor = self.actor_of(peer);
        if actor.source == PrincipalKind::AiAgent {
            self.log_audit(AuditEvent::action(
                &self.device_id,
                &actor,
                action,
                id,
                Decision::Deny,
                AuditOutcome::Denied,
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                "An AI agent may not install, update, or remove desktop applications. Policy: personal defaults — application mutations require the person at the device. Next step: open Command Center and choose the application yourself.".to_string(),
                json!({ "application": id, "decision": "deny", "policy_ids": ["personal-defaults"] }),
            ));
        }
        if self.enrollment.lock().unwrap().is_some() {
            let decision = {
                let policy = self.application_policy.lock().unwrap();
                evaluate_application_policy(
                    &policy,
                    id,
                    if action == "system.remove_package" {
                        ApplicationPolicyAction::Remove
                    } else {
                        ApplicationPolicyAction::Install
                    },
                )
            };
            if decision.allowed {
                return Ok(actor);
            }
            self.log_audit(AuditEvent::action(
                &self.device_id,
                &actor,
                action,
                id,
                Decision::Deny,
                AuditOutcome::Denied,
            ));
            let policy_id = decision
                .provenance
                .as_ref()
                .map(|source| source.policy_id.as_str())
                .unwrap_or("organization-application-policy");
            let source_name = decision
                .provenance
                .as_ref()
                .map(|source| source.source_name.as_str())
                .unwrap_or("Organization application policy");
            let reason = decision.reason.as_str();
            let message = match decision.reason {
                crate::policy::ApplicationPolicyReason::Required => format!(
                    "{id} is required by {source_name}, so it cannot be uninstalled.\n\
                     Policy: {policy_id} — applications.required.\n\
                     Next step: contact your administrator if this requirement should change."
                ),
                crate::policy::ApplicationPolicyReason::Denied => format!(
                    "{id} is blocked by {source_name}, so Punar did not install it.\n\
                     Policy: {policy_id} — applications.denied.\n\
                     Next step: contact your administrator to request an exception."
                ),
                crate::policy::ApplicationPolicyReason::UserInstallBlocked => format!(
                    "Your organization does not allow optional application installs on this device.\n\
                     Policy: {policy_id} — applications.allowUserInstall is false.\n\
                     Next step: choose an organization-required application or contact your administrator."
                ),
                _ => "This enrolled device has no usable organization application policy, so Punar made no change.\n\
                      Policy: fail closed — an enrolled device never falls back to personal install rules.\n\
                      Next step: ask your administrator to publish an application policy."
                    .to_string(),
            };
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                message,
                json!({
                    "application": id,
                    "decision": "deny",
                    "reason": reason,
                    "policy_ids": [policy_id],
                }),
            ));
        }
        Ok(actor)
    }

    fn handle_apps_install(
        &self,
        peer: &Peer,
        params: &AppsInstallParams,
    ) -> Result<Value, IpcError> {
        let action = "system.install_package";
        let actor = self.app_mutation_authorized(peer, action, &params.id)?;
        if params.confirm_metadata_sha256.len() != 64
            || !params
                .confirm_metadata_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(IpcError::with_details(
                ErrorCode::InvalidParams,
                "The install confirmation is not a SHA-256 metadata digest. Nothing was installed. Next step: inspect the app again and confirm the digest shown on that card.".to_string(),
                json!({ "param": "confirm_metadata_sha256" }),
            ));
        }
        let _guard = self.app_mutation.lock().unwrap();
        match self
            .apps
            .install(&params.id, &params.confirm_metadata_sha256)
        {
            Ok(result) => {
                let outcome = if result["changed"] == true {
                    AuditOutcome::Success
                } else {
                    AuditOutcome::Noop
                };
                self.log_audit(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    action,
                    &params.id,
                    Decision::Allow,
                    outcome,
                ));
                Ok(result)
            }
            Err(error) => {
                let (decision, outcome) = match &error {
                    AppError::Verification(_) => (Decision::Allow, AuditOutcome::VerifyFailed),
                    AppError::Policy(_) => (Decision::Deny, AuditOutcome::Denied),
                    _ => (Decision::Allow, AuditOutcome::Failure),
                };
                self.log_audit(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    action,
                    &params.id,
                    decision,
                    outcome,
                ));
                Err(app_ipc_error(error))
            }
        }
    }

    fn handle_apps_remove(
        &self,
        peer: &Peer,
        params: &AppsRemoveParams,
    ) -> Result<Value, IpcError> {
        let action = "system.remove_package";
        let actor = self.app_mutation_authorized(peer, action, &params.id)?;
        let _guard = self.app_mutation.lock().unwrap();
        match self.apps.remove(&params.id) {
            Ok(result) => {
                let outcome = if result["changed"] == true {
                    AuditOutcome::Success
                } else {
                    AuditOutcome::Noop
                };
                self.log_audit(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    action,
                    &params.id,
                    Decision::Allow,
                    outcome,
                ));
                Ok(result)
            }
            Err(error) => {
                self.log_audit(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    action,
                    &params.id,
                    Decision::Allow,
                    AuditOutcome::Failure,
                ));
                Err(app_ipc_error(error))
            }
        }
    }

    fn handle_apps_update(
        &self,
        peer: &Peer,
        params: &AppsUpdateParams,
    ) -> Result<Value, IpcError> {
        if params.all == params.id.is_some() {
            return Err(IpcError::with_details(
                ErrorCode::InvalidParams,
                "Choose one application id or --all, not both. Nothing was updated. Next step: run `punarctl app update <id>` or `punarctl app update --all`.".to_string(),
                json!({ "params": ["id", "all"] }),
            ));
        }

        let action = "system.update_package";
        // Agent attribution is a method-level denial, including the no-op
        // case where no catalog app happens to be installed. An empty device
        // must not turn a forbidden mutation into a probing oracle.
        let requester = self.actor_of(peer);
        if requester.source == PrincipalKind::AiAgent {
            let resource = params.id.as_deref().unwrap_or("installed_applications");
            self.log_audit(AuditEvent::action(
                &self.device_id,
                &requester,
                action,
                resource,
                Decision::Deny,
                AuditOutcome::Denied,
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                "An AI agent may not update desktop applications. Policy: personal defaults — application mutations require the person at the device. Next step: open Command Center and select Update all yourself.".to_string(),
                json!({ "application": resource, "decision": "deny", "policy_ids": ["personal-defaults"] }),
            ));
        }
        // Hold the same transaction lock used by install/remove while
        // discovering installed state. Otherwise a concurrent removal could
        // make an app disappear between selection and update.
        let _guard = self.app_mutation.lock().unwrap();
        let candidates = self
            .apps
            .update_candidates(params.id.as_deref())
            .map_err(app_ipc_error)?;
        if !params.all && candidates.is_empty() {
            let id = params.id.as_deref().unwrap_or("application");
            return Err(IpcError::with_details(
                ErrorCode::Conflict,
                format!(
                    "Application {id:?} is not installed as a native Punar catalog app. Nothing was updated. Next step: install it from the App Store first."
                ),
                json!({ "application": id, "installed": false }),
            ));
        }
        let mut results = Vec::new();
        let mut failures = Vec::new();
        let mut updated = 0_u64;
        let mut current = 0_u64;

        for id in &candidates {
            let actor = match self.app_mutation_authorized(peer, action, id) {
                Ok(actor) => actor,
                Err(error) if params.all => {
                    failures.push(json!({
                        "id": id,
                        "status": "denied",
                        "error": error.message,
                    }));
                    continue;
                }
                Err(error) => return Err(error),
            };
            match self.apps.update(id) {
                Ok(result) => {
                    let changed = result["changed"] == true;
                    if changed {
                        updated += 1;
                    } else {
                        current += 1;
                    }
                    self.log_audit(AuditEvent::action(
                        &self.device_id,
                        &actor,
                        action,
                        id,
                        Decision::Allow,
                        if changed {
                            AuditOutcome::Success
                        } else {
                            AuditOutcome::Noop
                        },
                    ));
                    results.push(result);
                }
                Err(error) => {
                    let (decision, outcome) = match &error {
                        AppError::Verification(_) => (Decision::Allow, AuditOutcome::VerifyFailed),
                        AppError::Policy(_) => (Decision::Deny, AuditOutcome::Denied),
                        _ => (Decision::Allow, AuditOutcome::Failure),
                    };
                    self.log_audit(AuditEvent::action(
                        &self.device_id,
                        &actor,
                        action,
                        id,
                        decision,
                        outcome,
                    ));
                    if !params.all {
                        return Err(app_ipc_error(error));
                    }
                    failures.push(json!({
                        "id": id,
                        "status": "failed",
                        "error": error.to_string(),
                    }));
                }
            }
        }

        Ok(json!({
            "scope": if params.all { "all" } else { "one" },
            "requested_id": params.id,
            "eligible": candidates.len(),
            "updated": updated,
            "current": current,
            "failed": failures.len(),
            "changed": updated > 0,
            "apps": results,
            "failures": failures,
        }))
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
            device: Some(self.device_profile.clone()),
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
    ///
    /// **M9 (contract section 14.8): the request shape, validation, errors,
    /// result object and audit action are unchanged.** Only the
    /// authorization step grew — see [`Inner::authorize_capability_set`].
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
        let authorized = self.authorize_capability_set(peer, &actor, id, params)?;
        let extra_policy_ids = match &authorized {
            // A grant is a section 39 Temporary Approved Exception, so the
            // grant id belongs in `policy_ids` — it *is* the authority that
            // permitted this call. (`audit-event.json` is closed and has no
            // `details` field; M9 does not extend it, and inventing one to
            // carry a grant id would be the tail wagging the schema.)
            MutationAuthority::Grant { grant_id } => vec![grant_id.clone()],
            MutationAuthority::Root | MutationAuthority::AiAllowed { .. } => Vec::new(),
        };
        self.execute_capability_set(&actor, cap, params, &extra_policy_ids)
            .0
    }

    /// Run the authorized mutation: record the preference, recompute the
    /// merge, apply the **effective** value, verify, audit.
    ///
    /// Returns the wire result **and** the [`Execution`] record, because
    /// `approvals.resolve` runs exactly this pipeline and has to write down
    /// what happened — including the `evt_` id, which is the link from an
    /// approval into the audit trail (contract section 14.3).
    fn execute_capability_set(
        &self,
        actor: &AuditActor,
        cap: &dyn Capability,
        params: &CapabilitiesSetParams,
        extra_policy_ids: &[String],
    ) -> (Result<Value, IpcError>, Execution) {
        let id = params.capability.as_str();
        // Record the request as a User Preference layer entry (rank 5) and
        // recompute the merge. The preference is recorded even when a
        // higher layer overrides it — it becomes effective the moment the
        // override goes away (SPEC section 39).
        if let Err(e) = self.preferences.set(
            id,
            PreferenceEntry {
                value: params.desired_state.clone(),
                set_at: utc_now_rfc3339(),
                set_by: actor.user_id.clone(),
            },
        ) {
            let err = self.internal(&format!("persisting the preference failed: {e}"));
            let execution = Execution {
                result: "internal".to_string(),
                error: Some(err.message.clone()),
                ..Execution::default()
            };
            return (Err(err), execution);
        }
        self.recompute_effective();

        let (effective_value, winning_policy_id) = {
            let doc = self.effective.lock().unwrap();
            let entry = doc
                .get(id)
                .expect("registered capability has an effective entry");
            (entry.value.clone(), entry.provenance.policy_id.clone())
        };
        let overridden = effective_value != params.desired_state;
        let mut policy_ids = vec![winning_policy_id];
        policy_ids.extend(extra_policy_ids.iter().cloned());
        let audited = |outcome: AuditOutcome| {
            let mut event = AuditEvent::capabilities_set(
                &self.device_id,
                actor,
                &params.capability,
                Decision::Allow,
                outcome,
            );
            event.policy_ids = policy_ids.clone();
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
            let event_id = self.log_audit_id(audited(AuditOutcome::Noop));
            self.mark_settled(id);
            return (
                Ok(extend(
                    json!({ "descriptor": self.describe(cap), "changed": false }),
                )),
                Execution {
                    result: AuditOutcome::Noop.as_str().to_string(),
                    changed: Some(false),
                    audit_event_id: event_id,
                    ..Execution::default()
                },
            );
        }

        if let Err(apply_err) = cap.apply(&effective_value) {
            let event_id = self.log_audit_id(audited(AuditOutcome::Failure));
            let err = IpcError::with_details(
                ErrorCode::ApplyFailed,
                format!(
                    "Applying the new state for {id} failed: {apply_err}.\n\
                     Policy: personal defaults — the change was authorized but the backend could not complete it.\n\
                     Next step: check `journalctl -u punard` and retry."
                ),
                json!({ "capability": id, "stage": "apply" }),
            );
            let execution = Execution {
                result: AuditOutcome::Failure.as_str().to_string(),
                changed: Some(false),
                audit_event_id: event_id,
                error: Some(err.message.clone()),
                ..Execution::default()
            };
            return (Err(err), execution);
        }

        match cap.verify(&effective_value) {
            Ok(true) => {
                let event_id = self.log_audit_id(audited(AuditOutcome::Success));
                self.mark_settled(id);
                (
                    Ok(extend(
                        json!({ "descriptor": self.describe(cap), "changed": true }),
                    )),
                    Execution {
                        result: AuditOutcome::Success.as_str().to_string(),
                        changed: Some(true),
                        audit_event_id: event_id,
                        ..Execution::default()
                    },
                )
            }
            verify_outcome => {
                let observed = cap
                    .observe()
                    .unwrap_or(Value::String("unknown".to_string()));
                let event_id = self.log_audit_id(audited(AuditOutcome::VerifyFailed));
                let why = match verify_outcome {
                    Err(e) => format!("verification errored: {e}"),
                    _ => "the system did not reach the requested state".to_string(),
                };
                let err = IpcError::with_details(
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
                );
                let execution = Execution {
                    result: AuditOutcome::VerifyFailed.as_str().to_string(),
                    changed: Some(true),
                    audit_event_id: event_id,
                    error: Some(err.message.clone()),
                    ..Execution::default()
                };
                (Err(err), execution)
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
        // M9: the lazy expiry sweep rides the existing reconcile timer, so
        // an unattended device still retires lapsed approvals and grants
        // without punard growing a timer of its own (SPEC section 6.3).
        {
            let mut store = self.approvals.lock().unwrap();
            self.sweep_approvals(&mut store);
        }
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

        // M5 (milestone-5.md section 6): compliance/inventory sync
        // piggybacks every full pass while enrolled — the existing 120 s
        // reconcile timer is the sync cadence; no new timers, no new
        // wakeup sources. The section 9 summary file is refreshed
        // afterwards (write-on-change only).
        self.sync_if_enrolled(actor);
        self.publish_status_summary();

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

    // -----------------------------------------------------------------------
    // M5 enrollment (contract sections 5.9–5.11; milestone-5.md section 5)
    // -----------------------------------------------------------------------

    /// One schema-conformant enrollment audit event (`enroll.start`,
    /// `enroll.stop`, `enroll.sync`; docs/api/ipc.md section 6). The
    /// device token is [`Redacted`] by type elsewhere — no field here
    /// could carry it.
    fn enroll_event(
        &self,
        actor: &AuditActor,
        action: &str,
        resource: &str,
        result: &str,
        policy_ids: Vec<String>,
    ) -> AuditEvent {
        AuditEvent {
            event_id: next_event_id(),
            timestamp: utc_now_rfc3339(),
            device_id: self.device_id.clone(),
            user_id: Some(actor.user_id.clone()),
            agent_session_id: Some(AGENT_SESSION_NONE.to_string()),
            project_id: Some(PROJECT_ID_SYSTEM.to_string()),
            source: actor.source,
            action: action.to_string(),
            resource: Some(resource.to_string()),
            decision: Decision::Allow,
            policy_ids: if policy_ids.is_empty() {
                vec![punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string()]
            } else {
                policy_ids
            },
            result: result.to_string(),
        }
    }

    /// Map a control-plane failure during `enroll.start` to the contract
    /// error codes: an unknown domain is the caller's mistake
    /// (`invalid_params`); everything else is `upstream_unreachable` in
    /// the section 73 voice, with local state untouched.
    fn upstream_error(&self, stage: &str, error: UpstreamError) -> IpcError {
        match error {
            UpstreamError::Refused { code, message } if code == "not_found" => {
                IpcError::with_details(
                    ErrorCode::InvalidParams,
                    format!(
                        "The control plane does not know this organization: {message}\n\
                         Policy: os default — enrollment needs a discoverable organization \
                         (docs/api/ipc.md section 5.9).\n\
                         Next step: check the domain spelling with your administrator."
                    ),
                    json!({ "param": "org_domain", "reason": "unknown organization" }),
                )
            }
            UpstreamError::Refused { code, message } => IpcError::with_details(
                ErrorCode::UpstreamUnreachable,
                format!(
                    "The control plane refused the {stage} step ({code}): {message}\n\
                     Policy: os default — enrollment is all-or-nothing; nothing was changed.\n\
                     Next step: is the control plane running and serving this device?"
                ),
                json!({ "stage": stage }),
            ),
            UpstreamError::Unreachable(why) => IpcError::with_details(
                ErrorCode::UpstreamUnreachable,
                format!(
                    "The control plane at {} did not answer during the {stage} step: {why}.\n\
                     Policy: os default — enrollment is all-or-nothing; nothing was changed.\n\
                     Next step: is the control plane running?",
                    self.cfg.control_plane_socket.display()
                ),
                json!({ "stage": stage }),
            ),
        }
    }

    fn conflict(&self, state: &str, message: String) -> IpcError {
        IpcError::with_details(ErrorCode::Conflict, message, json!({ "state": state }))
    }

    /// `enroll.start` (contract section 5.9): guard → discover → register
    /// (fresh in-memory bootstrap secret; **attestation simulated and
    /// labeled**) → policy.fetch → strict-parse validation (the M4
    /// loader's own code path, run over a staging directory) → policy.d
    /// write → live recompute → one full section 42 pass (whose sync hook
    /// is the first compliance/inventory report) → persist → status file.
    /// All-or-nothing: any failure before the commit point leaves no
    /// trace.
    fn handle_enroll_start(
        &self,
        peer: &Peer,
        params: &EnrollStartParams,
    ) -> Result<Value, IpcError> {
        let actor = self.actor_of(peer);
        if authorize_mutation(peer) != Decision::Allow {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                "enroll.start",
                RESOURCE_ENROLLMENT,
            ));
            return Err(IpcError::denied_needs_root(
                "device enrollment",
                None,
                &format!("sudo punarctl enroll start {}", params.org_domain),
            ));
        }
        let domain = params.org_domain.trim();
        if !domain_syntax_ok(domain) {
            return Err(IpcError::with_details(
                ErrorCode::InvalidParams,
                format!(
                    "{:?} is not a domain name.\n\
                     Policy: os default — punard validates the organization domain before \
                     any discovery call (docs/api/ipc.md section 5.9).\n\
                     Next step: punarctl enroll start <domain>, e.g. acme.com.",
                    params.org_domain
                ),
                json!({ "param": "org_domain", "reason": "not a domain name" }),
            ));
        }
        // Serialize enrollment transitions without holding the state lock
        // across the network/reconcile pipeline.
        let _guard = match EnrollGuard::acquire(&self.enroll_in_progress) {
            Some(guard) => guard,
            None => {
                return Err(self.conflict(
                    "changing",
                    "An enrollment change is already in progress.\n\
                     Policy: os default — enrollment transitions run one at a time.\n\
                     Next step: retry in a moment."
                        .to_string(),
                ));
            }
        };
        if self.enrollment.lock().unwrap().is_some() {
            self.log_audit(self.enroll_event(
                &actor,
                "enroll.start",
                RESOURCE_ENROLLMENT,
                "failure",
                vec![],
            ));
            return Err(self.conflict(
                "enrolled",
                "This device is already enrolled.\n\
                 Policy: os default — one organization at a time (docs/api/ipc.md \
                 section 5.9).\n\
                 Next step: `punarctl enroll status` shows the current organization; \
                 `sudo punarctl enroll stop` unenrolls."
                    .to_string(),
            ));
        }

        let fail_audit = |stage_error: IpcError| {
            self.log_audit(self.enroll_event(
                &actor,
                "enroll.start",
                RESOURCE_ENROLLMENT,
                "failure",
                vec![],
            ));
            stage_error
        };

        // Discover.
        let client = ControlPlaneClient::new(&self.cfg.control_plane_socket);
        let org_doc = client
            .org_discover(domain)
            .map_err(|e| fail_audit(self.upstream_error("discover", e)))?;
        let field = |value: &Value, path: &[&str]| -> Option<String> {
            let mut cursor = value.clone();
            for key in path {
                cursor = cursor.get(key)?.clone();
            }
            cursor.as_str().map(str::to_string)
        };
        let (Some(org_id), Some(org_name)) = (field(&org_doc, &["id"]), field(&org_doc, &["name"]))
        else {
            return Err(fail_audit(self.upstream_error(
                "discover",
                UpstreamError::Unreachable("the organization document is missing id/name".into()),
            )));
        };
        // M10 (milestone-10.md section 9.2): the remote-query grant is read
        // out of the organization document **once, here, at enrollment**,
        // and written into `enrollment.json`. It is never taken from a
        // query, never widened at runtime, and never passed to the data
        // owner — agentd reads the file itself. An org document with no
        // `remote_query_scopes` grants nothing, and that is the correct
        // default: an organization that never asked for a scope never gets
        // one.
        let remote_query_scopes: Vec<String> = org_doc
            .get("enrollment")
            .and_then(|e| e.get("remote_query_scopes"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let org = OrgRecord {
            display_name: field(&org_doc, &["enrollment", "display_name"])
                .unwrap_or_else(|| org_name.clone()),
            domain: field(&org_doc, &["discovery", "domain"]).unwrap_or_else(|| domain.to_string()),
            id: org_id,
            name: org_name,
        };

        // Register. The bootstrap secret exists only in memory, only for
        // this call, and only behind Redacted; the returned token likewise
        // (SPEC section 53 — nothing that cannot be printed can leak).
        let bootstrap = Redacted::new(
            random_hex(crate::enroll::BOOTSTRAP_SECRET_BYTES)
                .map_err(|e| fail_audit(self.internal(&format!("bootstrap secret: {e}"))))?,
        );
        let (token, attestation) = client
            .register(&self.device_id, &bootstrap)
            .map_err(|e| fail_audit(self.upstream_error("register", e)))?;
        // The attestation step is SIMULATED (milestone-5.md section 5.2):
        // the label is stored and surfaced verbatim; nothing was measured.

        // Fetch and validate the policy envelopes with the M4 loader's own
        // strict parse, over a staging directory — enrollment is
        // all-or-nothing up through the policy.d write.
        let envelopes = client
            .policy_fetch(&token)
            .map_err(|e| fail_audit(self.upstream_error("policy.fetch", e)))?;
        let staging = self.cfg.state_dir.join(".policy.d.enroll-staging");
        let cleanup_staging = || {
            let _ = std::fs::remove_dir_all(&staging);
        };
        cleanup_staging();
        std::fs::create_dir_all(&staging)
            .map_err(|e| fail_audit(self.internal(&format!("staging dir: {e}"))))?;
        let mut policy_files: Vec<String> = Vec::new();
        for envelope in &envelopes {
            let policy_id = envelope
                .get("policy_id")
                .and_then(Value::as_str)
                .filter(|id| {
                    !id.is_empty()
                        && id
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
                })
                .ok_or_else(|| {
                    cleanup_staging();
                    fail_audit(IpcError::with_details(
                        ErrorCode::InvalidParams,
                        "The control plane served a policy envelope without a usable \
                         policy_id.\n\
                         Policy: os default — enrollment writes only validated envelopes \
                         (docs/api/ipc.md section 5.9).\n\
                         Next step: report this to your administrator; nothing was changed."
                            .to_string(),
                        json!({ "param": "policy", "reason": "envelope without policy_id" }),
                    ))
                })?;
            let file = format!("{policy_id}.json");
            let bytes =
                serde_json::to_vec_pretty(envelope).expect("fetched envelopes re-serialize");
            crate::util::write_atomic(&staging.join(&file), &bytes, 0o600).map_err(|e| {
                cleanup_staging();
                fail_audit(self.internal(&format!("staging write: {e}")))
            })?;
            policy_files.push(file);
        }
        let loaded = load_policy_dir(&staging).map_err(|e| {
            cleanup_staging();
            fail_audit(IpcError::with_details(
                ErrorCode::InvalidParams,
                format!(
                    "A fetched policy envelope failed validation: {e}.\n\
                     Policy: os default — enrollment is all-or-nothing; nothing was \
                     written (docs/api/ipc.md section 5.9).\n\
                     Next step: report this to your administrator."
                ),
                json!({ "param": "policy", "reason": "envelope failed the loader's validation" }),
            ))
        })?;
        for unmapped in &loaded.unmapped {
            eprintln!(
                "punard: enrollment policy: no registered capability for {unmapped}; \
                 ignored (its capability lands in a later milestone)"
            );
        }

        // Commit point: move the validated envelopes into policy.d, then
        // persist token + enrollment and flip the in-memory state.
        let policy_dir = self.cfg.state_dir.join("policy.d");
        if let Err(e) = std::fs::create_dir_all(&policy_dir) {
            cleanup_staging();
            return Err(fail_audit(self.internal(&format!("policy.d: {e}"))));
        }
        for file in &policy_files {
            if let Err(e) = std::fs::rename(staging.join(file), policy_dir.join(file)) {
                // Roll back anything moved so far — all-or-nothing.
                for moved in &policy_files {
                    let _ = std::fs::remove_file(policy_dir.join(moved));
                }
                cleanup_staging();
                return Err(fail_audit(self.internal(&format!("policy.d write: {e}"))));
            }
        }
        cleanup_staging();

        let enrollment = Enrollment {
            version: 1,
            org,
            enrolled_at: utc_now_rfc3339(),
            attestation,
            policy_files: policy_files.clone(),
            last_sync: LastSyncRecord::default(),
            last_inventory_hash: None,
            remote_query_scopes,
            last_query: None,
        };
        let rollback_files = |files: &[String]| {
            for file in files {
                let _ = std::fs::remove_file(policy_dir.join(file));
            }
        };
        if let Err(e) = save_device_token(&self.cfg.state_dir.join("device-token"), &token) {
            rollback_files(&policy_files);
            return Err(fail_audit(
                self.internal(&format!("device token store: {e}")),
            ));
        }
        if let Err(e) = save_enrollment(&self.cfg.state_dir.join("enrollment.json"), &enrollment) {
            rollback_files(&policy_files);
            let _ = std::fs::remove_file(self.cfg.state_dir.join("device-token"));
            return Err(fail_audit(self.internal(&format!("enrollment store: {e}"))));
        }

        let policy_ids = enrollment.policy_ids();
        let org_result = org_info(&enrollment.org);
        let enrolled_at = enrollment.enrolled_at.clone();
        let attestation_label = enrollment.attestation.clone();
        *self.device_token.lock().unwrap() = Some(token);
        *self.enrollment.lock().unwrap() = Some(enrollment);
        *self.org_layers.lock().unwrap() = loaded.layers;
        *self.application_policy.lock().unwrap() = loaded.applications;
        self.reload_ai_authority();
        self.recompute_effective();

        // M10 trigger 3 (milestone-10.md section 3.3): enrolling changes
        // what may be asked about this device, so the data owner gets a
        // chance to refresh its view before the first query arrives.
        // Fire-and-forget, 2 s, non-fatal — enrollment must never fail
        // because a bookkeeping daemon was busy.
        self.agentd()
            .scan_on_enrollment_transition(SCAN_TRIGGER_ENROLL);

        // One full section 42 pass. Its sync hook (now enrolled) performs
        // the first compliance + inventory report; failures there queue
        // per SPEC section 55 — they never fail enrollment.
        *self.last_sync_outcome.lock().unwrap() = None;
        let report = self.reconcile_and_remediate(&actor);
        *self.last_reconcile.lock().unwrap() = Some(report.reconciled_at.clone());
        let first_sync = self
            .last_sync_outcome
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(FirstSync {
                compliance: "unreachable".to_string(),
                inventory: "unreachable".to_string(),
            });

        self.log_audit(self.enroll_event(
            &actor,
            "enroll.start",
            RESOURCE_ENROLLMENT,
            AuditOutcome::Success.as_str(),
            policy_ids.clone(),
        ));
        Ok(to_value(EnrollStartResult {
            enrolled: true,
            org: org_result,
            policy_ids,
            attestation: attestation_label,
            enrolled_at,
            first_sync,
        }))
    }

    /// `enroll.status` (contract section 5.10): read-only, any connected
    /// peer, not audited. Never the token.
    fn handle_enroll_status(&self) -> EnrollStatusResult {
        match &*self.enrollment.lock().unwrap() {
            // Personal device: no organization, therefore no grant and no
            // query history — not an empty grant that could be widened, but
            // the absence of the concept (milestone-10.md section 11).
            None => EnrollStatusResult {
                enrolled: false,
                org: None,
                policy_ids: None,
                enrolled_at: None,
                attestation: None,
                last_sync: None,
                remote_query_scopes: None,
                last_query: None,
            },
            Some(e) => EnrollStatusResult {
                enrolled: true,
                org: Some(org_info(&e.org)),
                policy_ids: Some(e.policy_ids()),
                enrolled_at: Some(e.enrolled_at.clone()),
                attestation: Some(e.attestation.clone()),
                last_sync: Some(LastSync {
                    at: e.last_sync.at.clone(),
                    result: e.last_sync.result.clone(),
                    pending: self.pending_compliance.load(Ordering::SeqCst)
                        || self.pending_inventory.load(Ordering::SeqCst),
                }),
                // The grant, read back from the same array agentd enforces
                // (SPEC section 24.2 guarantee 8) — not a second copy that
                // could drift from the one that decides.
                remote_query_scopes: Some(e.granted_scopes().as_words()),
                last_query: e.last_query.as_ref().map(|q| LastQuery {
                    at: q.at.clone(),
                    scope: q.scope.clone(),
                    decision: q.decision.clone(),
                }),
            },
        }
    }

    /// `enroll.stop` (contract section 5.11): root-only local restore —
    /// remove exactly the policy.d files this enrollment wrote, delete the
    /// stores, recompute, one reconcile pass (recorded user preferences
    /// resurface per SPEC section 39), rewrite the status file. Local-only
    /// by design: M5 has no unregister RPC — the control plane keeps its
    /// device record and received history (unenrollment stops future flow;
    /// it cannot retract the past). Works with the control plane down.
    fn handle_enroll_stop(&self, peer: &Peer) -> Result<Value, IpcError> {
        let actor = self.actor_of(peer);
        if authorize_mutation(peer) != Decision::Allow {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                "enroll.stop",
                RESOURCE_ENROLLMENT,
            ));
            return Err(IpcError::denied_needs_root(
                "device enrollment",
                None,
                "sudo punarctl enroll stop",
            ));
        }
        let _guard = match EnrollGuard::acquire(&self.enroll_in_progress) {
            Some(guard) => guard,
            None => {
                return Err(self.conflict(
                    "changing",
                    "An enrollment change is already in progress.\n\
                     Policy: os default — enrollment transitions run one at a time.\n\
                     Next step: retry in a moment."
                        .to_string(),
                ));
            }
        };
        let Some(enrollment) = self.enrollment.lock().unwrap().take() else {
            self.log_audit(self.enroll_event(
                &actor,
                "enroll.stop",
                RESOURCE_ENROLLMENT,
                "failure",
                vec![],
            ));
            return Err(self.conflict(
                "personal",
                "This device is not enrolled.\n\
                 Policy: os default — there is no organization state to remove \
                 (docs/api/ipc.md section 5.11).\n\
                 Next step: `punarctl enroll status` shows the current state."
                    .to_string(),
            ));
        };

        let policy_dir = self.cfg.state_dir.join("policy.d");
        for file in &enrollment.policy_files {
            if let Err(e) = std::fs::remove_file(policy_dir.join(file)) {
                if e.kind() != io::ErrorKind::NotFound {
                    eprintln!(
                        "punard: enroll.stop could not remove policy.d/{file}: {e} \
                         (continuing; the in-memory layer is cleared regardless)"
                    );
                }
            }
        }
        for name in ["enrollment.json", "device-token"] {
            if let Err(e) = std::fs::remove_file(self.cfg.state_dir.join(name)) {
                if e.kind() != io::ErrorKind::NotFound {
                    eprintln!("punard: enroll.stop could not remove {name}: {e}");
                }
            }
        }
        *self.device_token.lock().unwrap() = None;
        self.org_layers.lock().unwrap().clear();
        self.application_policy.lock().unwrap().clear();
        self.reload_ai_authority();
        // M10 trigger 3, the other half: unenrolling changes what may be
        // asked back to *nothing*, and answering a stale view afterwards
        // would be worse than answering a fresh one late.
        self.agentd()
            .scan_on_enrollment_transition(SCAN_TRIGGER_ENROLL);
        self.pending_compliance.store(false, Ordering::SeqCst);
        self.pending_inventory.store(false, Ordering::SeqCst);
        *self.last_sync_outcome.lock().unwrap() = None;
        self.recompute_effective();

        // One pass against the restored personal document (the sync hook
        // no-ops — no enrollment — and the status file flips to personal).
        let report = self.reconcile_and_remediate(&actor);
        *self.last_reconcile.lock().unwrap() = Some(report.reconciled_at.clone());

        let removed_policy_ids = enrollment.policy_ids();
        self.log_audit(self.enroll_event(
            &actor,
            "enroll.stop",
            RESOURCE_ENROLLMENT,
            AuditOutcome::Success.as_str(),
            removed_policy_ids.clone(),
        ));
        Ok(to_value(EnrollStopResult {
            enrolled: false,
            removed_policy_ids,
        }))
    }

    /// The hostname as observed by the registry (shared by `status` and
    /// the inventory builder).
    fn observed_hostname(&self) -> String {
        self.registry
            .get(crate::backends::hostname::CAPABILITY_ID)
            .and_then(|cap| cap.observe().ok())
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// M5 sync hook (milestone-5.md sections 6, 7): runs at the end of
    /// every full reconcile pass **when enrolled** — compliance (category
    /// states only, SPEC sections 24/54), then inventory when its SHA-256
    /// changed or a resend is pending. Failures queue (bounded latest-wins
    /// booleans); `enroll.sync` is audited on **transitions only**.
    fn sync_if_enrolled(&self, actor: &AuditActor) {
        let Some(enrollment) = self.enrollment.lock().unwrap().clone() else {
            *self.last_sync_outcome.lock().unwrap() = None;
            return;
        };
        let token = self.device_token.lock().unwrap().clone();
        let client = ControlPlaneClient::new(&self.cfg.control_plane_socket);

        // Compliance: overall + per-category states. Nothing else — no
        // values, no hostnames, no events (SPEC sections 24, 54).
        let block = self.tracker.lock().unwrap().block(&self.registry);
        let report = compliance_report_body(
            block.overall.as_str(),
            block.capabilities.iter().map(|c| {
                (
                    c.capability.as_str().to_string(),
                    c.state.as_str().to_string(),
                )
            }),
        );
        let compliance_ok = match &token {
            Some(token) => client.compliance_report(token, &report).is_ok(),
            None => false,
        };
        self.pending_compliance
            .store(!compliance_ok, Ordering::SeqCst);

        // Inventory: device info + capability states, hash-gated.
        let sources = InventorySources {
            os_release_path: self.cfg.os_release_path.clone(),
            kernel_release_path: self.cfg.kernel_release_path.clone(),
        };
        let capabilities: Vec<(String, bool, Value)> = self
            .registry
            .iter()
            .map(|cap| {
                let descriptor = self.describe(cap);
                (
                    descriptor.capability.as_str().to_string(),
                    descriptor.supported,
                    descriptor.current_state,
                )
            })
            .collect();
        let inventory = inventory_body(&sources, &self.observed_hostname(), capabilities);
        let hash = sha256_hex(&serde_json::to_vec(&inventory).expect("inventory serializes"));
        let must_send = enrollment.last_inventory_hash.as_deref() != Some(hash.as_str())
            || self.pending_inventory.load(Ordering::SeqCst);
        let mut new_hash = enrollment.last_inventory_hash.clone();
        let inventory_outcome = if !must_send {
            "unchanged"
        } else {
            let sent = match &token {
                Some(token) => client.inventory_report(token, &inventory).is_ok(),
                None => false,
            };
            if sent {
                new_hash = Some(hash);
                "success"
            } else {
                "unreachable"
            }
        };
        self.pending_inventory
            .store(inventory_outcome == "unreachable", Ordering::SeqCst);

        // M10: the query pull, on the same hook and the same cadence. It is
        // deliberately last: compliance and inventory are this device's
        // obligations, and answering questions is a courtesy that must not
        // delay them.
        let last_query = match &token {
            Some(token) => self.drain_pending_queries(&client, token),
            None => None,
        };

        // Transition-only audit (milestone-5.md section 7): once on
        // reachable→unreachable, once on recovery — never one event per
        // 120 s retry.
        let overall = if compliance_ok && inventory_outcome != "unreachable" {
            "success"
        } else {
            "unreachable"
        };
        let previous = enrollment.last_sync.result.clone();
        if overall == "unreachable" && previous.as_deref() != Some("unreachable") {
            self.log_audit(self.enroll_event(
                actor,
                "enroll.sync",
                RESOURCE_CONTROL_PLANE,
                "unreachable",
                enrollment.policy_ids(),
            ));
        }
        if overall == "success" && previous.as_deref() == Some("unreachable") {
            self.log_audit(self.enroll_event(
                actor,
                "enroll.sync",
                RESOURCE_CONTROL_PLANE,
                AuditOutcome::Success.as_str(),
                enrollment.policy_ids(),
            ));
        }

        *self.last_sync_outcome.lock().unwrap() = Some(FirstSync {
            compliance: if compliance_ok {
                "success".to_string()
            } else {
                "unreachable".to_string()
            },
            inventory: inventory_outcome.to_string(),
        });

        // Persist last_sync / the inventory hash — only if still enrolled
        // (a concurrent enroll.stop wins).
        let mut slot = self.enrollment.lock().unwrap();
        if let Some(current) = slot.as_mut() {
            current.last_sync = LastSyncRecord {
                at: Some(utc_now_rfc3339()),
                result: Some(overall.to_string()),
            };
            current.last_inventory_hash = new_hash;
            if last_query.is_some() {
                current.last_query = last_query;
            }
            if let Err(e) = save_enrollment(&self.cfg.state_dir.join("enrollment.json"), current) {
                eprintln!("punard: could not persist enrollment sync state: {e}");
            }
        }
    }

    /// A client for the single inter-daemon edge. Constructed per use — it
    /// is one connection per call, like every other Punar client.
    fn agentd(&self) -> crate::agentd::AgentdClient {
        crate::agentd::AgentdClient::new(&self.cfg.agentd_socket)
    }

    /// M10: the query pull, riding the M5 sync piggyback
    /// (milestone-10.md section 7.2).
    ///
    /// ```text
    /// reconcile pass ends
    ///   └─ enrolled? ─ no ─→ nothing            (gate A — M5's existing gate)
    ///                 └ yes ─→ compliance.report          (M5)
    ///                        ├─ inventory.report          (M5, hash-gated)
    ///                        ├─ queries.pending  {device_token}
    ///                        └─ for each: query.answer → queries.answer
    /// ```
    ///
    /// **No new timer, no new listener, no new wakeup.** One extra request
    /// pair on a hook that already runs, at a cadence this device already
    /// chose. Answer latency is therefore one reconcile period plus the
    /// round trip, and the waiting happens on the administrator's side —
    /// which is where a request that a device did not initiate ought to
    /// wait.
    ///
    /// Offline behaviour is M5 section 7 unchanged: an unreachable control
    /// plane means the pull simply does not happen. Queries stay pending on
    /// the control plane and are answered on the next successful pass. No
    /// spool, no queue, no new state.
    ///
    /// The courier discipline, enforced here and worth reading as a whole:
    /// punard fetches, hands over, and posts back. If the data owner cannot
    /// be reached, or answers with an error frame, **punard produces
    /// nothing** — no synthesized refusal, no "assume denied", no partial
    /// answer. The query stays pending and is retried. The only bytes that
    /// ever reach the control plane are the bytes `punar-agentd` returned.
    fn drain_pending_queries(
        &self,
        client: &ControlPlaneClient,
        token: &Redacted<String>,
    ) -> Option<LastQueryRecord> {
        let pending = match client.queries_pending(token) {
            Ok(pending) => pending,
            Err(UpstreamError::Unreachable(_)) => return None,
            Err(UpstreamError::Refused { code, message }) => {
                // `unknown_method` here means the control plane predates
                // M10; anything else is a refusal on its side. Either way
                // there is nothing to answer, and nothing to record.
                eprintln!(
                    "punard: queries.pending refused by the control plane: {code}: {message}"
                );
                return None;
            }
        };
        if pending.is_empty() {
            return None;
        }

        let agentd = self.agentd();
        let mut last: Option<LastQueryRecord> = None;
        for query in pending.into_iter().take(MAX_QUERIES_PER_SYNC) {
            // The data owner decides. punard hands over the question as it
            // was fetched — no grant, no role, no policy, nothing that
            // could widen the answer (SPEC section 59.4).
            let answer = match agentd.query_answer(&query) {
                Ok(answer) => answer,
                Err(e) => {
                    eprintln!(
                        "punard: punar-agentd did not decide query {} ({e}) — it stays \
                         pending and is retried next pass; punard never answers on its \
                         behalf",
                        query.query_id
                    );
                    continue;
                }
            };
            // Posted back byte-identical. punard does not read the payload
            // and has no field in which it could edit one.
            if let Err(e) = client.queries_answer(token, &query.query_id, &answer) {
                let why = match e {
                    UpstreamError::Unreachable(why) => why,
                    UpstreamError::Refused { code, message } => format!("{code}: {message}"),
                };
                eprintln!(
                    "punard: could not post the answer to query {}: {why} — it stays \
                     pending",
                    query.query_id
                );
                continue;
            }
            // Metadata only, for `enroll.status`: when, at what scope, and
            // what the **device** decided. Never the payload — one exported
            // copy is enough to protect (milestone-10.md section 10.1).
            last = Some(LastQueryRecord {
                at: utc_now_rfc3339(),
                scope: query.requested_scope.clone(),
                decision: answer
                    .get("authorization_decision")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
            });
        }
        last
    }

    /// Rewrite the ipc.md section 9 summary file when the tuple changed
    /// (atomic tmp+rename, 0644). Best-effort: a write failure is logged,
    /// never fatal — the file is non-authoritative display data.
    fn publish_status_summary(&self) {
        let (enrolled, org_name) = match &*self.enrollment.lock().unwrap() {
            Some(e) => (true, Some(e.org.display_name.clone())),
            None => (false, None),
        };
        let overall = self
            .tracker
            .lock()
            .unwrap()
            .block(&self.registry)
            .overall
            .as_str()
            .to_string();
        let summary = StatusSummary {
            v: 1,
            enrolled,
            org_name,
            compliance_overall: overall,
            device_class: self.device_profile.class.as_str().to_string(),
            device_class_source: match self.device_profile.source {
                punar_common::DeviceClassSource::Observed => "observed",
                punar_common::DeviceClassSource::Forced => "forced",
            }
            .to_string(),
            ts: utc_now_rfc3339(),
        };
        let mut written = self.status_written.lock().unwrap();
        let unchanged = written.as_ref().is_some_and(|w| {
            w.enrolled == summary.enrolled
                && w.org_name == summary.org_name
                && w.compliance_overall == summary.compliance_overall
                && w.device_class == summary.device_class
                && w.device_class_source == summary.device_class_source
        });
        if unchanged {
            return;
        }
        match write_status_summary(&self.cfg.status_file, &summary) {
            Ok(()) => *written = Some(summary),
            Err(e) => eprintln!(
                "punard: could not write {}: {e}",
                self.cfg.status_file.display()
            ),
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

fn effective_update_channel(value: &Value) -> Option<UpdateChannel> {
    match value.as_str()? {
        "stable" => Some(UpdateChannel::Stable),
        "dev" => Some(UpdateChannel::Dev),
        "edge" => Some(UpdateChannel::Edge),
        _ => None,
    }
}

fn to_value<T: serde::Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("result structs serialize infallibly")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};

    use punar_common::audit::AUDIT_ROTATE_BYTES;

    #[test]
    fn update_status_channel_uses_only_the_closed_effective_value() {
        assert_eq!(
            effective_update_channel(&json!("stable")),
            Some(UpdateChannel::Stable)
        );
        assert_eq!(
            effective_update_channel(&json!("dev")),
            Some(UpdateChannel::Dev)
        );
        assert_eq!(
            effective_update_channel(&json!("edge")),
            Some(UpdateChannel::Edge)
        );
        assert_eq!(effective_update_channel(&json!("nightly")), None);
        assert_eq!(effective_update_channel(&json!(true)), None);
    }

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

    #[test]
    fn personal_recovery_disclosure_has_one_exact_pipe_grammar() {
        let mut output = Vec::new();
        write_personal_recovery_disclosure(
            &mut output,
            "aaaa-bbbb-cccc-dddd-eeee-ffff-gggg-hhhh",
            [2, 7],
        )
        .unwrap();
        assert_eq!(
            output,
            b"PUNAR-RECOVERY-V1\naaaa-bbbb-cccc-dddd-eeee-ffff-gggg-hhhh\n2 7\n"
        );
    }

    #[test]
    fn unattended_recovery_disclosure_has_one_exact_secret_channel_grammar() {
        let mut output = Vec::new();
        write_unattended_recovery_disclosure(
            &mut output,
            b"generated-disk-passphrase",
            "aaaa-bbbb-cccc-dddd-eeee-ffff-gggg-hhhh",
            [2, 7],
        )
        .unwrap();
        assert_eq!(
            output,
            b"PUNAR-UNATTENDED-CUSTODY-V1\ngenerated-disk-passphrase\naaaa-bbbb-cccc-dddd-eeee-ffff-gggg-hhhh\n2 7\n"
        );
    }

    #[test]
    fn installer_disk_change_claim_is_phase_conservative() {
        let mut status = InstallStatusResult::idle();
        assert!(!install_status_disk_changed(&status));
        status.phase = Some(InstallPhase::VerifyRelease);
        assert!(!install_status_disk_changed(&status));
        for phase in [
            InstallPhase::Partition,
            InstallPhase::Encrypt,
            InstallPhase::Format,
            InstallPhase::WriteSlotA,
            InstallPhase::ReRead,
            InstallPhase::Boot,
            InstallPhase::Seed,
            InstallPhase::VerifyInstalled,
        ] {
            status.phase = Some(phase);
            assert!(install_status_disk_changed(&status), "{phase:?}");
        }
    }

    #[test]
    fn install_plan_audit_failure_is_fail_closed_before_disk_changes() {
        let root = std::env::temp_dir().join(format!(
            "punard-install-audit-{}-{}",
            std::process::id(),
            next_event_id()
        ));
        fs::create_dir_all(&root).unwrap();
        let audit_path = root.join("audit.jsonl");
        let daemon = Daemon::new(
            DaemonConfig::new(
                root.join("punard.sock"),
                root.join("state"),
                audit_path.clone(),
            ),
            Registry::new(Vec::new()),
        )
        .unwrap();

        let before = daemon.inner.audit_events.load(Ordering::SeqCst);
        OpenOptions::new()
            .write(true)
            .open(&audit_path)
            .unwrap()
            .set_len(AUDIT_ROTATE_BYTES)
            .unwrap();
        fs::remove_file(&audit_path).unwrap();
        fs::create_dir(&audit_path).unwrap();

        let error = daemon
            .inner
            .log_install_plan_required(AuditEvent::action(
                &daemon.inner.device_id,
                &AuditActor::cli_peer("root"),
                "install.plan",
                "system_disk",
                Decision::Allow,
                AuditOutcome::Success,
            ))
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::Internal);
        assert_eq!(
            error.details,
            Some(json!({
                "component": "installer_audit",
                "disk_changed": false
            }))
        );
        assert_eq!(
            daemon.inner.audit_events.load(Ordering::SeqCst),
            before,
            "a failed durable append must not increment the audit count"
        );

        drop(daemon);
        fs::remove_dir_all(root).unwrap();
    }
}
