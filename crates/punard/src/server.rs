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
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use std::collections::{BTreeMap, BTreeSet};

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
    ENROLLMENT_TERMS_NOT_ACCEPTED, EnrollPolicyStatus, EnrollStartParams, EnrollStartResult,
    EnrollStatusResult, EnrollStopParams, EnrollStopResult, EnrollmentTerm, ErrorCode, FirstSync,
    IpcError, LastQuery, LastSync, LocalAdminStatus, MAX_REQUEST_LINE_BYTES, Method, Mode, OrgInfo,
    PROTOCOL_VERSION, PolicyEffectiveEntry, PolicyEffectiveResult, PolicyExplainParams,
    PolicyExplainResult, PolicyRefresh, PolicySetParams, PolicySetResult, PolicySourceRef,
    PrivilegeRequestParams, PrivilegeRevokeParams, PrivilegeRevokeResult, PrivilegeStatusResult,
    ReconcileEntry, ReconcileResult, RemediationOutcome, Request, ResolveDecision, Response,
    SERVER_READ_TIMEOUT, StatusResult, WebAppsContextCreateParams, WebAppsContextDeleteParams,
    WebAppsGetParams, WebAppsInstallParams, WebAppsListParams, WebAppsUninstallParams,
    organization_name, term_safe_name,
};
use punar_common::query::MAX_QUERIES_PER_SYNC;
use punar_common::time::utc_now_rfc3339;
use punar_common::update::{
    UpdateApplyParams, UpdateApplyResult, UpdateChannel, UpdateCheckParams, UpdateCheckResult,
    UpdateRollbackParams, UpdateStatusResult,
};
use punar_common::webapp::{
    BrowserContext, NotYetObserved, WebAppManifest, origin_from_start_url, validate_context_id,
};
use punar_common::{AuditEvent, Decision, PrincipalKind, Redacted, Risk};
use punar_policy::{Classification, EffectiveEntry, Provenance};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::approvals::{self, ApprovalStore};
use crate::apps::{AppError, AppManager};
use crate::authz::{Peer, PeerSource, authorize_mutation};
use crate::browser_policy::persist_rendered_browser_policy;
use crate::capability::{Capability, Registry};
use crate::device::{DeviceSources, observe_profile};
use crate::enroll::{
    AgentQueue, Assignment, CallBudget, ControlPlaneClient, DEFAULT_CONTROL_PLANE_SOCKET,
    ENROLL_CONTROL_PLANE_BUDGET, Enrollment, INVENTORY_RETRY_BASE, InventoryRetry,
    InventorySources, LastQueryRecord, LastSyncRecord, ORGANIZATION_VIEW_FILE, OrgRecord,
    OrganizationViewRecord, PolicyRefreshRecord, RECONCILE_CONTROL_PLANE_BUDGET, StatusSummary,
    UpstreamError, compliance_report_body, inventory_body, inventory_resend_due, load_device_token,
    load_enrollment, load_organization_view, organization_view_summary, save_device_token,
    save_enrollment, save_enrollment_durable, save_organization_view, write_status_summary,
};
use crate::install::{
    INSTALLER_SERVICE_ACTOR_ID, InstallAuditEvents, InstallError, Installer, InstallerSources,
};
use crate::inventory::{
    CollectorSources, ImageRelease, InventoryCollector, PassInputs, Withheld, patch_posture,
};
use crate::pi_update::{PiUpdateEngine, PiUpdateError, PiUpdateSources};
use crate::policy::{
    ApplicationPolicyAction, ApplicationPolicyLayer, ApplicationPolicyReason, DEVICE_ADMIN_RANK,
    EffectiveDocument, Layer, LocalAdminLayer, compute_effective, evaluate_application_policy,
    evaluate_webapp_policy, load_policy_dir, resolve_local_admin, write_effective_debug_copy,
};
use crate::policy_set::{self, CanonicalSet, PrepareError, Rejection};
use crate::state::{
    ADMIN_POLICY_FILE, AdminPolicyEntry, AdminPolicyStore, MigrationOutcome, OsDefaultsStore,
    PreferenceEntry, PreferencesStore, load_or_create_device_id, migrate_m3_store,
};
use crate::update_check::{UpdateCheckEngine, UpdateCheckError, UpdateCheckSources};
use crate::update_status::{UpdateStatusEngine, UpdateStatusSources};
use crate::update_transaction::{
    UpdateTransactionEngine, UpdateTransactionError, UpdateTransactionSources,
};
use crate::util::{
    lookup_gid, lookup_username, random_hex, remove_synced, sha256_hex, write_atomic_synced,
};
use crate::webapps::{WebAppError, WebAppManager};

mod m9;
mod policy_refresh;

use m9::MutationAuthority;
use policy_refresh::{
    REASON_ANSWER_TOO_LARGE, REASON_UNUSABLE_ASSIGNMENT, RefreshBackoff, RefreshResult,
};

/// Audit `resource` for the M5 enrollment mutations (ipc.md section 6).
pub const RESOURCE_ENROLLMENT: &str = "enrollment";

/// A registration enroll.start has not committed yet. The control plane
/// issues a device identity at `register`; a refusal after that (a policy
/// fetch the server answers badly, an envelope the loader rejects, a store
/// that will not write) used to leave the agent holding that identity while
/// punard reported the device unenrolled — so the next attempt met a stale
/// one. Dropping this releases it, best effort and exactly like
/// `enroll.stop`'s release: the local rollback never waits on the network.
struct UncommittedRegistration {
    client: ControlPlaneClient,
    token: Option<Redacted<String>>,
}

impl UncommittedRegistration {
    /// The enrollment is committed: keep the identity.
    fn commit(mut self) {
        self.token = None;
    }
}

impl Drop for UncommittedRegistration {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            if let Err(e) = self.client.unregister(&token) {
                eprintln!(
                    "punard: enroll.start could not release the uncommitted registration \
                     ({e:?}); the agent may still hold it"
                );
            }
        }
    }
}

/// How the enrollment gate names the change it is guarding, in its messages.
struct EnrollmentWords {
    /// Sentence-initial gerund: "Enrolling this device in an organization".
    doing: &'static str,
    /// Infinitive: "enroll this device in an organization".
    verb: &'static str,
    /// What the retry command asks the person for.
    asks: &'static str,
}

const ENROLL_START_WORDS: EnrollmentWords = EnrollmentWords {
    doing: "Enrolling this device in an organization",
    verb: "enroll this device in an organization",
    asks: "the enrollment code and then your password",
};

/// How an update verb names itself in its refusals.
struct UpdateWords {
    /// Sentence-initial gerund: "Installing an update".
    doing: &'static str,
    /// What an agent is refused: "replace or roll back the operating system".
    agent_may_not: &'static str,
    /// The command a person runs to do it themselves.
    retry: String,
}

const ENROLL_STOP_WORDS: EnrollmentWords = EnrollmentWords {
    doing: "Unenrolling this device",
    verb: "unenroll this device",
    asks: "your password",
};
/// M10 `--trigger` value punard sends to the data owner on an enrollment
/// transition (milestone-10.md sections 3.3, 13.1).
pub const SCAN_TRIGGER_ENROLL: &str = "enroll";

/// Audit `resource` for the M5 `enroll.sync` transition events.
pub const RESOURCE_CONTROL_PLANE: &str = "control_plane";

/// RAII guard serializing enrollment transitions and the commit of a policy
/// refresh (compare-exchange on a flag; released on drop).
struct EnrollGuard<'a>(&'a AtomicBool);

/// How long `enroll.start` and `enroll.stop` wait for the guard. A policy
/// refresh holds it only while it checks and commits files on this device,
/// and a person who already spent their password confirmation must not be
/// told "conflict" because a background pass happened to be committing.
const ENROLL_GUARD_PATIENCE: Duration = Duration::from_secs(2);

impl<'a> EnrollGuard<'a> {
    fn acquire(flag: &'a AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| EnrollGuard(flag))
    }

    /// [`EnrollGuard::acquire`], retried every 10 ms for up to `patience`.
    fn acquire_within(flag: &'a AtomicBool, patience: Duration) -> Option<Self> {
        let deadline = Instant::now() + patience;
        loop {
            if let Some(guard) = Self::acquire(flag) {
                return Some(guard);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
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
    /// Where the managed inventory's posture, hardware and application facts
    /// are read ([`crate::inventory`]). Production paths by default; tests
    /// inject a fixture tree so no assertion depends on the host.
    pub inventory_sources: CollectorSources,
    /// M9: the approval summary the shell watches (docs/api/ipc.md section
    /// 15). `/run/punard/approvals.json` in production — deliberately
    /// inside the `0750 root:punar` runtime directory, not beside the
    /// world-readable `status.json` summary. Defaults to a
    /// state-dir file so embedded/test daemons never write outside their
    /// tempdir.
    pub approvals_file: PathBuf,
    /// M9: the shipped AI authority document (SPEC section 20).
    pub ai_defaults_file: PathBuf,
    /// Where `punar-authd` mints re-authentication tickets
    /// ([`crate::reauth::TICKET_DIR`] in production). Injectable so a test can
    /// prove the ACCEPT half of `policy.set` — the half that matters and the
    /// one a hardcoded `/run` path leaves to the VM gate alone.
    pub reauth_ticket_dir: PathBuf,
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
    /// Root-only fixed broker used to hand least-privilege PIM and Wayland
    /// capabilities to first-party desktop applications. Production never
    /// accepts this path over IPC; the field is injectable only for tests.
    pub pim_launch_broker: PathBuf,
    /// Root-private, freshly rendered Chromium policy source consumed by
    /// the `browser.policy` capability backend.
    pub browser_policy_source: PathBuf,
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
    /// How long an inventory that failed to go out first waits before it is
    /// sent again ([`INVENTORY_RETRY_BASE`]); shorter in tests.
    pub inventory_retry_base: Duration,
    /// What one reconcile pass may spend on the control plane
    /// ([`RECONCILE_CONTROL_PLANE_BUDGET`]); shorter in tests.
    pub reconcile_control_plane_budget: Duration,
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
        let browser_policy_source = state_dir.join("browser-policy/rendered.json");
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
            inventory_sources: CollectorSources::default(),
            approvals_file,
            reauth_ticket_dir: PathBuf::from(crate::reauth::TICKET_DIR),
            ai_defaults_file: PathBuf::from(punar_common::aipolicy::AI_DEFAULTS_FILE),
            console_uid: DEFAULT_CONSOLE_UID,
            agentd_socket: PathBuf::from(crate::agentd::DEFAULT_AGENTD_SOCKET),
            device_sources: DeviceSources::default(),
            device_class_override: None,
            app_catalog_path: None,
            flatpak_bin: PathBuf::from("/usr/bin/flatpak"),
            app_arch_override: None,
            pim_launch_broker: PathBuf::from("/usr/lib/punar/punar-pim-launch"),
            browser_policy_source,
            live_mode: false,
            installer_sources: InstallerSources::default(),
            update_status_sources: UpdateStatusSources::default(),
            update_check_sources,
            update_transaction_sources,
            pi_update_sources,
            inventory_retry_base: INVENTORY_RETRY_BASE,
            reconcile_control_plane_budget: RECONCILE_CONTROL_PLANE_BUDGET,
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
    /// The device administrator's layer (device_specific_override, rank 4):
    /// beaten by both organization rungs, beats every user's preference.
    admin_policy: AdminPolicyStore,
    /// Organization opinions about whether this device's administrator may
    /// edit local policy at all (SPEC section 44.5). Reloaded with the org
    /// layers on every enrollment transition.
    local_admin: Mutex<Vec<LocalAdminLayer>>,
    /// Ranks 1–4 (and stored-rank overrides): policy.d drops. Loaded at
    /// startup; since M5 the **enrollment chain** reloads them live
    /// (`enroll.start` writes + reloads, `enroll.stop` empties), and every
    /// policy refresh that changes the organization's set reloads the whole
    /// directory as a restart would. A manual root file-drop into policy.d
    /// still takes effect only at the next restart or refresh commit —
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
    /// Which enrollment the slot holds: bumped, under the `enrollment` lock,
    /// whenever one is committed or ended. A sync pass works from a copy
    /// taken at its start and may outlive it (a report can be in flight for
    /// seconds while `enroll.stop` runs, and `enroll.start` after it). It
    /// writes back only while this is still the value it started with, so
    /// an ended enrollment is never written again and never into another
    /// one. Two enrollments of one organization in the same second carry the
    /// same `org.id` and `enrolled_at`; they never carry the same epoch.
    enrollment_epoch: AtomicU64,
    /// M5: the device token, [`Redacted`] the moment it exists in memory —
    /// no formatter or serializer can print it (SPEC section 53).
    device_token: Mutex<Option<Redacted<String>>>,
    /// M5 offline queue (SPEC section 55): bounded latest-wins — two
    /// booleans, not a spool. Compliance/inventory are state snapshots; a
    /// missed intermediate report carries nothing the next snapshot does
    /// not supersede.
    pending_compliance: AtomicBool,
    pending_inventory: AtomicBool,
    /// When a pending inventory may be sent again ([`InventoryRetry`]).
    inventory_retry: Mutex<Option<InventoryRetry>>,
    /// The managed inventory's collectors and their per-boot caches.
    inventory: InventoryCollector,
    /// Whether the last inventory went out with its application list
    /// withheld; the audit records the transitions, not every pass.
    applications_withheld: AtomicBool,
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
    /// Serializes `enroll.start`/`enroll.stop`, and a policy refresh's
    /// commit, without holding the state lock across the network + reconcile
    /// pipeline.
    enroll_in_progress: AtomicBool,
    /// Every control-plane call in flight, so each waits behind the others
    /// ([`AgentQueue`]).
    control_plane_queue: Arc<AgentQueue>,
    /// How many refresh opportunities a failing policy fetch still skips
    /// ([`RefreshBackoff`]). In memory: a restart tries at once.
    policy_refresh_backoff: Mutex<RefreshBackoff>,
    /// The last set this daemon refused, for which enrollment (its epoch),
    /// and why: the same set is not checked again on every pass. In memory,
    /// so a new build, whose checks may differ, looks at it once more.
    policy_rejected_offer: Mutex<Option<(u64, String, &'static str)>>,
    /// The last refusal that depended on this device's own files as well as
    /// on the set offered (a set that names a root drop, or cannot be loaded
    /// or installed beside what policy.d holds), and what it depended on: not
    /// staged again until the offer or policy.d changes.
    policy_local_refusal: Mutex<Option<policy_refresh::LocalRefusal>>,
    /// The revision of the organization's files the in-memory layers and the
    /// rendered browser document were made from. `None` when they may not
    /// match `policy.d` (a change that could not be undone): the next
    /// refresh then commits again, whatever it fetches.
    org_policy_loaded: Mutex<Option<String>>,
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
    /// User-created web-app records are separate from native package state,
    /// but their human-paced mutations still serialize per daemon.
    webapps: WebAppManager,
    webapp_mutation: Mutex<()>,
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
        let webapps = WebAppManager::new(cfg.state_dir.join("web-apps"));
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
        let inventory =
            InventoryCollector::new(cfg.inventory_sources.clone(), cfg.flatpak_bin.clone());
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
        let admin_policy = AdminPolicyStore::load(&cfg.state_dir.join(ADMIN_POLICY_FILE))?;
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
        // The paths are the organization's own keys, and a refresh can put
        // new ones in policy.d at any time: escaped, like every other string
        // from it that reaches the journal, on every boot.
        for unmapped in &loaded.unmapped {
            eprintln!(
                "punard: policy.d: no registered capability for {}; ignored \
                 (its capability lands in a later milestone)",
                journal_detail(unmapped)
            );
        }
        persist_rendered_browser_policy(
            &cfg.browser_policy_source,
            &loaded.applications,
            &loaded.browsers,
        )?;

        let effective = compute_effective(
            &registry,
            &os_defaults,
            &preferences,
            &admin_policy,
            &loaded.layers,
            utc_now_rfc3339(),
        );
        let _ = write_effective_debug_copy(&cfg.state_dir.join("effective.json"), &effective);

        // M5: enrollment persists as plain files (SPEC section 55 — no
        // control-plane liveness involved). A corrupt store refuses start,
        // same posture as the layer stores; a missing token on an enrolled
        // device degrades to unreachable syncs, never to a silent
        // unenroll.
        let mut enrollment = load_enrollment(&cfg.state_dir.join("enrollment.json"))?;
        // An enroll.start or policy refresh that was interrupted leaves its
        // staging directory beside policy.d, and a refresh leaves a record
        // naming both sets' files, its change pending. Both are settled from
        // what policy.d holds before anything reads them (policy_set::settle).
        let settled = match policy_set::settle(&cfg.state_dir, enrollment.as_mut()) {
            Ok(settled) => settled,
            Err(e) => {
                eprintln!("punard: could not clear an interrupted policy change: {e}");
                policy_set::Settled::default()
            }
        };
        let mut saved = true;
        if settled.changed {
            if let Some(record) = &enrollment {
                if let Err(e) =
                    save_enrollment_durable(&cfg.state_dir.join("enrollment.json"), record)
                {
                    saved = false;
                    eprintln!(
                        "punard: could not save the settled policy record ({e}); \
                         it is settled again at the next start"
                    );
                }
            }
        }
        // A change that landed before the crash is audited as the refresh
        // would have, under the event id it fixed before the swap: once,
        // whether the refresh got as far as writing it or not. Only once the
        // settled record is saved, or the next start settles it again.
        if let (Some(change), true) = (&settled.landed, saved) {
            if audit_log_holds(&cfg.audit_path, &change.event_id) {
                eprintln!(
                    "punard: the organization's policy was {} ({}) before the last stop",
                    change.result, change.revision
                );
            } else {
                let mut event = enrollment_event(
                    &device_id,
                    &AuditActor::daemon(),
                    "enroll.policy",
                    RESOURCE_CONTROL_PLANE,
                    &change.result,
                    change.policy_ids.clone(),
                );
                event.event_id = change.event_id.clone();
                match audit.append(&event) {
                    Ok(()) => {
                        audit_events += 1;
                        eprintln!(
                            "punard: the organization's policy was {} ({}) before the last \
                             stop; recorded now",
                            change.result, change.revision
                        );
                    }
                    Err(e) => eprintln!("punard: FAILED to append enroll.policy audit event: {e}"),
                }
            }
        }
        // What the in-memory layers below were loaded from, as far as the
        // organization's files go: a refresh that finds the same set commits
        // nothing only while this still names it.
        let org_policy_loaded = enrollment.as_ref().and_then(|record| {
            CanonicalSet::read_owned(&cfg.state_dir.join("policy.d"), &record.policy_files)
                .ok()
                .map(|owned| owned.revision())
        });
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
                admin_policy,
                org_layers: Mutex::new(loaded.layers),
                local_admin: Mutex::new(loaded.local_admin),
                application_policy: Mutex::new(loaded.applications),
                effective: Mutex::new(effective),
                tracker: Mutex::new(ComplianceTracker::default()),
                device_id,
                device_profile,
                started_at: utc_now_rfc3339(),
                last_reconcile: Mutex::new(None),
                enrollment: Mutex::new(enrollment),
                enrollment_epoch: AtomicU64::new(0),
                device_token: Mutex::new(device_token),
                pending_compliance: AtomicBool::new(false),
                pending_inventory: AtomicBool::new(false),
                inventory_retry: Mutex::new(None),
                inventory,
                applications_withheld: AtomicBool::new(false),
                last_sync_outcome: Mutex::new(None),
                status_written: Mutex::new(None),
                approvals: Mutex::new(approvals),
                ai: Mutex::new(ai),
                enroll_in_progress: AtomicBool::new(false),
                control_plane_queue: Arc::new(AgentQueue::default()),
                policy_refresh_backoff: Mutex::new(RefreshBackoff::default()),
                policy_rejected_offer: Mutex::new(None),
                policy_local_refusal: Mutex::new(None),
                org_policy_loaded: Mutex::new(org_policy_loaded),
                install_in_progress: AtomicBool::new(false),
                shutdown: AtomicBool::new(false),
                active: Mutex::new(0),
                slot_freed: Condvar::new(),
                apps,
                app_mutation: Mutex::new(()),
                webapps,
                webapp_mutation: Mutex::new(()),
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
        let budget = CallBudget::new(inner.cfg.reconcile_control_plane_budget);
        let report = inner.reconcile_and_remediate(&AuditActor::daemon(), &budget);
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

/// Whether the device administrator's layer could win this path.
///
/// The rule is one comparison and it is the same one the merge uses: a layer at
/// rank 4 beats anything numerically greater. So the administrator can move a
/// value that an OS default (6) or a user preference (5) currently wins, and
/// cannot move one an organization pins at 1, 2 or 3 — nor one already held by
/// a rank-4 approved exception, which wins that rung by push order.
///
/// This is what lets a surface OFFER editing only where editing would work,
/// instead of discovering the answer from a refusal after the fact.
fn admin_may_override(entry: &punar_policy::EffectiveEntry<Value>) -> bool {
    // The second clause is RANK-SCOPED, and the difference matters because
    // `device_specific_override` is not exclusively the local administrator's
    // kind: its rank is stored data, so an organization may publish one, and at
    // rank 1-3 that layer outranks this device exactly as an organization
    // baseline does. Matching on the kind alone would have handed an org's own
    // pinned value to the local administrator to edit, purely because of the
    // word it was labelled with.
    entry.provenance.rank > DEVICE_ADMIN_RANK
        || (entry.provenance.kind == punar_policy::SourceKind::DeviceSpecificOverride
            && entry.provenance.rank >= DEVICE_ADMIN_RANK)
}

fn source_ref(provenance: &Provenance) -> PolicySourceRef {
    PolicySourceRef {
        kind: provenance.kind.as_str().to_string(),
        rank: provenance.rank,
        policy_id: provenance.policy_id.clone(),
        name: provenance.source_name.clone(),
    }
}

/// Who can end this enrollment, said as a next step a person can act on
/// (docs/development/smplify-enrollment.md section 3.1).
fn unenroll_next_step(enrollment: &Enrollment) -> String {
    if enrollment.removable {
        "`punarctl enroll stop` unenrolls it; it asks for your password.".to_string()
    } else {
        format!(
            "{org} enrolled this device as not removable, so nobody on it can unenroll it: \
             only erasing and reinstalling the device ends the enrollment. A release sent by \
             {org} is not built yet.",
            org = enrollment.org.display_name
        )
    }
}

/// `enrollment.removable` from an organization document: whether a person on
/// the device may later unenroll it. Absent means removable — the organization
/// stated no restriction, and the device's owner administers it, as for
/// `spec.security.localAdmin`. A value that is present but not a boolean is an
/// error, never the permissive default: an organization that tried to say
/// something about removal and could not be understood must not get the
/// opposite of what it meant.
fn org_document_removable(org_doc: &Value) -> Result<bool, String> {
    match org_doc.get("enrollment").and_then(|e| e.get("removable")) {
        None => Ok(true),
        Some(Value::Bool(removable)) => Ok(*removable),
        Some(other) => Err(org_document_value_shown(other)),
    }
}

/// A value from the organization's document, as the refusal that names it
/// quotes it. The organization chose it, and punarctl prints the refusal to
/// a terminal, which obeys what is in it: a bidirectional override could
/// reorder the sentence around it, a line separator could start what looks
/// like a line of Punar's own, and a megabyte of text would bury the next
/// step. So it is cleaned and bounded exactly as the organization's name is
/// ([`organization_name`]).
fn org_document_value_shown(value: &Value) -> String {
    organization_name(&value.to_string()).unwrap_or_else(|| "unprintable".to_string())
}

/// `enrollment.ownership` from an organization document: whether the
/// organization owns this device, so that its inventory also carries the
/// serial number and every application installed for all users
/// (docs/development/smplify-enrollment.md section 3.2). Absent or
/// `"personal"` is personal; `"organization"` claims the device, which the
/// person must then accept. Anything else is an error, never either reading:
/// guessing personal would enroll a device its organization cannot manage as
/// it said, and guessing organization would report more than anyone agreed
/// to.
fn org_document_organization_owned(org_doc: &Value) -> Result<bool, String> {
    match org_doc.get("enrollment").and_then(|e| e.get("ownership")) {
        None => Ok(false),
        Some(Value::String(ownership)) if ownership == "personal" => Ok(false),
        Some(Value::String(ownership)) if ownership == "organization" => Ok(true),
        Some(other) => Err(org_document_value_shown(other)),
    }
}

/// How an organization states a term, as the first sentence of the refusal
/// that names it alone.
fn term_statement(term: EnrollmentTerm) -> &'static str {
    match term {
        EnrollmentTerm::NonRemovable => "enrolls devices so that nobody on them can unenroll them",
        EnrollmentTerm::OrganizationOwned => "enrolls devices as owned by the organization",
    }
}

/// The one `denied` refusal for every enrollment term the request did not
/// accept (docs/api/ipc.md section 5.9 step 6). Every term is named at once,
/// with what it means and the flag that accepts it, so a person is asked
/// once for everything rather than refused again after each yes.
/// `details.terms` lists them for a client to send back; `details.reason`
/// keeps the single term's own reason when there is one.
fn unaccepted_terms_refusal(
    org: &OrgRecord,
    domain: &str,
    unaccepted: &[EnrollmentTerm],
) -> IpcError {
    // The name is the organization's, quoted so it reads as a name, and it
    // stays out of the sentences a person agrees to: each term's meaning is
    // fixed text (EnrollmentTerm::meaning).
    let name = &format!("\"{}\"", term_safe_name(&org.display_name));
    let (statement, meaning, reason) = match unaccepted {
        [term] => (
            format!(
                "{name} {}, and this request did not accept that",
                term_statement(*term)
            ),
            term.meaning().to_string(),
            term.refusal_reason(),
        ),
        _ => (
            format!(
                "{name} enrolls devices on terms this request did not accept: {}",
                unaccepted
                    .iter()
                    .map(|term| term.title().to_lowercase())
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
            unaccepted
                .iter()
                .map(|term| format!("{}: {}", term.title(), term.meaning()))
                .collect::<Vec<_>>()
                .join(". "),
            ENROLLMENT_TERMS_NOT_ACCEPTED,
        ),
    };
    let flags = unaccepted
        .iter()
        .map(|term| term.flag())
        .collect::<Vec<_>>()
        .join(" ");
    IpcError::with_details(
        ErrorCode::Denied,
        format!(
            "{statement}. Nothing was changed: this device was not registered with {name}.\n\
             Policy: the organization's enrollment terms — {meaning}.\n\
             Next step: if that is what you want, run `punarctl enroll start {domain} {flags}`."
        ),
        json!({
            "decision": "deny",
            "reason": reason,
            "terms": unaccepted.iter().map(|term| term.as_str()).collect::<Vec<_>>(),
            "organization": org.id,
            "organization_name": org.display_name,
        }),
    )
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

/// The longest reason a `policy.set` may carry. Generous for a sentence,
/// bounded because it is persisted and re-rendered in a refusal message.
const MAX_POLICY_REASON_CHARS: usize = 500;

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

fn mail_launch_unavailable(reason: &str) -> IpcError {
    IpcError::with_details(
        ErrorCode::ApplyFailed,
        "Mail could not establish its protected desktop connection. No mailbox capability was issued. Next step: sign in to the desktop again, then reopen Mail.",
        json!({ "component": "pim_mail_launch", "reason": reason }),
    )
}

fn webapp_ipc_error(error: WebAppError) -> IpcError {
    let (code, next) = match &error {
        WebAppError::Invalid(_) => (
            ErrorCode::InvalidParams,
            "correct the web-app name, URL, context, workspace, or icon and retry",
        ),
        WebAppError::NotFound(_) => (
            ErrorCode::NotFound,
            "list your web apps and browser contexts, then retry with an existing id",
        ),
        WebAppError::Conflict(_) => (
            ErrorCode::Conflict,
            "choose a different id or remove the conflicting reference first",
        ),
        WebAppError::Denied(_) => (
            ErrorCode::Denied,
            "use a user-created context, or change the organization enrollment that owns it",
        ),
        WebAppError::Io(_) => (
            ErrorCode::ApplyFailed,
            "verify free space and /var/lib/punar permissions, then retry",
        ),
    };
    IpcError::with_details(
        code,
        format!("Punar could not complete the web-app request.\nWhy: {error}.\nNext step: {next}."),
        json!({ "component": "web_app_inventory" }),
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
                 Next step: reconnect the configured update source and retry `punarctl update check`."
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
        UpdateTransactionError::EspInsufficientSpace {
            required_bytes,
            available_bytes,
        } => IpcError::with_details(
            ErrorCode::InsufficientSpace,
            "The EFI System Partition does not have enough room for the candidate UKI and the fixed update reserve. The boot selector was not changed.",
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

    /// Pi recovery is complete only after its exact outcome is durable. The
    /// writer validates, appends, and `fdatasync`s each event; propagating an
    /// error here deliberately leaves the pending record for an idempotent
    /// boot-time retry.
    fn log_pi_reconcile_required(&self, event: AuditEvent) -> Result<(), IpcError> {
        match self.audit.lock().unwrap().append(&event) {
            Ok(()) => {
                self.audit_events.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                eprintln!("punard: FAILED to append required Pi reconcile audit event: {error}");
                Err(IpcError::with_details(
                    ErrorCode::Internal,
                    "Punar reconciled the Raspberry Pi selector but could not durably record the outcome. The pending transaction was retained and the boot service will retry.",
                    json!({
                        "component": "pi_reconcile_audit",
                        "pending_retained": true,
                    }),
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
        meta.describe(current, desired, cap.mutable())
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
    /// `capabilities.set`, the M5 enrollment transitions and every policy
    /// refresh that changes the set) and refresh the debug copy.
    ///
    /// A capability whose effective value or classification changed leaves
    /// remediation suppression here: the loop-protection promise is "until the
    /// effective value changes" (contract section 5.6), and a new value is a
    /// new thing to try, not the fourth attempt at the old one. The two locks
    /// are taken one after the other, never together.
    fn recompute_effective(&self) {
        let doc = {
            let org_layers = self.org_layers.lock().unwrap();
            compute_effective(
                &self.registry,
                &self.os_defaults,
                &self.preferences,
                &self.admin_policy,
                &org_layers,
                utc_now_rfc3339(),
            )
        };
        let _ = write_effective_debug_copy(&self.cfg.state_dir.join("effective.json"), &doc);
        let changed = {
            let mut effective = self.effective.lock().unwrap();
            let changed = changed_effective_paths(&effective, &doc);
            *effective = doc;
            changed
        };
        if !changed.is_empty() {
            let mut tracker = self.tracker.lock().unwrap();
            for path in changed {
                tracker.fail_counts.remove(&path);
            }
        }
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
            Method::PolicySet(params) => self.handle_policy_set(peer, params),
            Method::EnrollStart(params) => self.handle_enroll_start(peer, params),
            Method::EnrollStatus => Ok(to_value(self.handle_enroll_status())),
            Method::EnrollStop(params) => self.handle_enroll_stop(peer, params),
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
            Method::WebAppsList(params) => self.handle_webapps_list(peer, params),
            Method::WebAppsGet(params) => self.handle_webapps_get(peer, params),
            Method::WebAppsInstall(params) => self.handle_webapps_install(peer, params),
            Method::WebAppsUninstall(params) => self.handle_webapps_uninstall(peer, params),
            Method::WebAppsContextCreate(params) => {
                self.handle_webapps_context_create(peer, params)
            }
            Method::WebAppsContextDelete(params) => {
                self.handle_webapps_context_delete(peer, params)
            }
            Method::PimMailOpen => self.handle_pim_mail_open(peer),
            Method::PimMailAccountAdd => self.handle_pim_mail_account_add(peer),
            Method::PimMailAccountManage => self.handle_pim_mail_account_manage(peer),
            Method::UpdateStatus => Ok(to_value(self.handle_update_status())),
            Method::UpdateCheck(params) => self.handle_update_check(peer, params),
            Method::UpdateApply(params) => self.handle_update_apply(peer, params),
            Method::UpdateReconcileCandidate => self.handle_update_reconcile_candidate(peer),
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
        let actor = self.admit_update_change(
            peer,
            ACTION,
            RESOURCE,
            params.ticket.as_deref(),
            &UpdateWords {
                doing: "Checking for updates",
                agent_may_not: "check this device's update channel",
                retry: "punarctl update check".to_string(),
            },
        )?;

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

    /// Who may change what the operating system runs (docs/development/
    /// update-and-rollback.md section 7.3): root, or a person who has just
    /// confirmed their password — the `enroll.start` shape. Order:
    ///
    /// 1. **No agent, at any uid** — the M9 `host.system_update` boundary,
    ///    widened to any peer whose cgroup names an agent scope. A ticket the
    ///    agent carried is left unspent.
    /// 2. **A non-root peer must carry a ticket**, refused before anything is
    ///    read or fetched.
    /// 3. **The ticket is spent** before any update-source request and before
    ///    any allow-shaped audit event, so every later outcome names a caller
    ///    who proved who they are.
    ///
    /// A person gets exactly root's authority and no more: the same channel,
    /// halt, rollout, minimum-version and downgrade admission run after this,
    /// and the channel is still the precedence-resolved
    /// `system.update_channel`, which an organization pins.
    fn admit_update_change(
        &self,
        peer: &Peer,
        action: &str,
        resource: &str,
        ticket: Option<&str>,
        words: &UpdateWords,
    ) -> Result<AuditActor, IpcError> {
        let actor = self.actor_of(peer);
        self.refuse_agent_system_update(peer, &actor, action, resource, words.agent_may_not)?;
        if peer.uid != 0 && ticket.is_none() {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                action,
                resource,
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "{} needs your password, and this request did not carry a \
                     confirmation.\n\
                     Policy: personal defaults — what the operating system runs is an \
                     administrative change, confirmed at the moment it is made.\n\
                     Next step: run `{}` in a terminal; it asks for your password.",
                    words.doing, words.retry
                ),
                json!({ "decision": "deny", "reason": "reauthentication_required" }),
            ));
        }
        self.spend_reauth_ticket(peer, &actor, action, resource, ticket, &words.retry)?;
        Ok(actor)
    }

    /// The M9 boundary for every update verb: an AI agent never replaces,
    /// rolls back or checks the operating system, at any uid, whatever a
    /// policy says.
    fn refuse_agent_system_update(
        &self,
        peer: &Peer,
        actor: &AuditActor,
        action: &str,
        resource: &str,
        agent_may_not: &str,
    ) -> Result<(), IpcError> {
        if actor.source != PrincipalKind::AiAgent && self.agent_shaped_peer(peer, actor).is_none() {
            return Ok(());
        }
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
            actor,
            action,
            resource,
            Decision::Deny,
            AuditOutcome::Denied,
        );
        event.policy_ids = vec![policy_id.to_string()];
        self.log_audit(event);
        Err(IpcError::with_details(
            ErrorCode::Denied,
            format!(
                "An AI agent may not {agent_may_not}.\n\
                 Policy: {source_name} ({policy_id}) — host.system_update is denied to agents.\n\
                 Next step: leave it to a person; `punarctl update status` shows what is available."
            ),
            json!({
                "decision": "deny",
                "resource": resource,
                "rule": "host.system_update",
                "agent_session_id": actor.agent_session_id,
                "policy_ids": [policy_id],
            }),
        ))
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
        let actor = self.admit_update_change(
            peer,
            ACTION,
            "system_image",
            params.ticket.as_deref(),
            &UpdateWords {
                doing: "Installing an update",
                agent_may_not: "replace or roll back the operating system",
                retry: format!("punarctl update apply {}", params.version),
            },
        )?;
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
                    one_shot_trial: staged.requires_tryboot_reboot,
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

    /// Reconcile native Raspberry Pi boot state. There are no caller-supplied
    /// slots, paths, digests or health values: firmware observation, the
    /// exact pending record and local readback are the only inputs. Success
    /// ordering is selector operation/observation, required durable audit,
    /// then exact pending-record removal.
    fn handle_update_reconcile_candidate(&self, peer: &Peer) -> Result<Value, IpcError> {
        const ACTION: &str = "update.reconcile_candidate";
        let actor = self.actor_of(peer);
        self.refuse_agent_system_update(
            peer,
            &actor,
            ACTION,
            "system_image",
            "replace or roll back the operating system",
        )?;
        // Not a person's verb: it blesses or reverts a Raspberry Pi candidate
        // from firmware observation, and the boot health service calls it.
        if authorize_mutation(peer) != Decision::Allow {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                ACTION,
                "system_image",
            ));
            return Err(IpcError::denied_root_only(
                "Settling a Raspberry Pi update candidate",
                "system_image",
                "none needed — punar-update-health.service settles it at boot, after \
                 the health checks it depends on have run.",
            ));
        }
        let _guard = self.update_lock.lock().unwrap();
        let result = if !self.cfg.pi_update_sources.boot_partition_property.exists() {
            Err(PiUpdateError::Conflict(
                "candidate blessing is available only on native Raspberry Pi firmware".into(),
            ))
        } else {
            self.pi_update.reconcile_candidate()
        };
        match result {
            Ok(reconciled) => {
                let resource = format!(
                    "pi_release:{}:{}:{}",
                    reconciled.release_id, reconciled.version, reconciled.manifest_sha256
                );
                self.log_pi_reconcile_required(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    reconciled.outcome.audit_action(),
                    &resource,
                    Decision::Allow,
                    AuditOutcome::Success,
                ))?;
                self.pi_update
                    .finalize_pending(&reconciled.pending_state_sha256)
                    .map_err(|error| {
                        IpcError::with_details(
                            ErrorCode::ApplyFailed,
                            format!(
                                "The Pi outcome was audited, but its exact pending record could not be finalized: {error}. The retained record will be retried safely."
                            ),
                            json!({
                                "component": "pi_pending_finalize",
                                "audit_recorded": true,
                                "pending_retained": true,
                            }),
                        )
                    })?;
                Ok(to_value(reconciled))
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
                Err(pi_update_ipc_error(error))
            }
        }
    }

    fn handle_update_rollback(
        &self,
        peer: &Peer,
        params: &UpdateRollbackParams,
    ) -> Result<Value, IpcError> {
        const ACTION: &str = "update.rollback";
        let actor = self.admit_update_change(
            peer,
            ACTION,
            "system_image",
            params.ticket.as_deref(),
            &UpdateWords {
                doing: "Rolling back the operating system",
                agent_may_not: "replace or roll back the operating system",
                retry: "punarctl update rollback".to_string(),
            },
        )?;
        let _guard = self.update_lock.lock().unwrap();
        let result = if self.cfg.pi_update_sources.boot_partition_property.exists() {
            self.pi_update
                .rollback(params.to_version)
                .map(to_value)
                .map_err(pi_update_ipc_error)
        } else {
            // The running root's own release: the one fact that settles which
            // release its slot holds when an older build left more than one
            // entry bound to it.
            match self.update_check.current_version() {
                Ok(running) => self
                    .update_transaction
                    .rollback(params.to_version, running)
                    .map(to_value)
                    .map_err(update_transaction_ipc_error),
                Err(error) => Err(IpcError::with_details(
                    ErrorCode::Internal,
                    format!(
                        "Punar could not read the running release's version ({error}), so it \
                         cannot tell which boot entry is safe to select. No selector was \
                         changed.\n\
                         Next step: inspect `punarctl update status`."
                    ),
                    json!({ "stage": "local_identity" }),
                )),
            }
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
            return Err(IpcError::denied_root_only(
                "Planning an installation",
                RESOURCE,
                "use the installer on the Punar live medium, which runs as root there; \
                 an installed device's accounts never plan a disk install.",
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
            return Err(IpcError::denied_root_only(
                "Installing Punar to a disk",
                RESOURCE,
                "use the signed installer on the Punar live medium, which runs as root \
                 there; an installed device's accounts never write a disk install.",
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

        let root_write_bytes = self.installer.root_write_bytes_total(&plan)?;
        self.installer.start_transaction_status(
            &params.plan_token,
            &params.disk,
            root_write_bytes,
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
                let client = self.control_plane();
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

        self.installer.write_root_slots(&plan)?;
        self.installer.enter_phase(InstallPhase::ReRead)?;
        self.installer.verify_written_root_slots(&plan)?;
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

    /// Open Mail through a fixed, root-only broker. The caller contributes
    /// only its kernel-attested uid and pid; it cannot select an executable,
    /// path, account, endpoint, environment value, or capability.
    #[cfg(target_os = "linux")]
    fn handle_pim_mail_open(&self, peer: &Peer) -> Result<Value, IpcError> {
        self.handle_pim_launch(peer, "pim.mail.open", "mail", "mail")
    }

    #[cfg(target_os = "linux")]
    fn handle_pim_mail_account_add(&self, peer: &Peer) -> Result<Value, IpcError> {
        self.handle_pim_launch(
            peer,
            "pim.mail.account_add",
            "account-add",
            "mail-account-setup",
        )
    }

    #[cfg(target_os = "linux")]
    fn handle_pim_mail_account_manage(&self, peer: &Peer) -> Result<Value, IpcError> {
        self.handle_pim_launch(
            peer,
            "pim.mail.account_manage",
            "account-manage",
            "mail-accounts",
        )
    }

    #[cfg(target_os = "linux")]
    fn handle_pim_launch(
        &self,
        peer: &Peer,
        action: &str,
        broker_mode: &str,
        application: &str,
    ) -> Result<Value, IpcError> {
        let actor = self.actor_of(peer);
        if actor.source == PrincipalKind::AiAgent {
            self.log_audit(AuditEvent::action(
                &self.device_id,
                &actor,
                action,
                "mail",
                Decision::Deny,
                AuditOutcome::Denied,
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                "An AI agent may not open a personal mailbox. Policy: personal defaults — Mail must be opened by the person at the device. Next step: open Mail from Command Center yourself.",
                json!({ "decision": "deny", "policy_ids": ["personal-defaults"] }),
            ));
        }
        let pid = peer.pid.filter(|pid| *pid > 0).ok_or_else(|| {
            IpcError::with_details(
                ErrorCode::Denied,
                "Mail could not verify the desktop session that requested it. No mailbox capability was issued. Next step: open Mail from the signed desktop session.",
                json!({ "decision": "deny", "reason": "missing_peer_pid" }),
            )
        })?;
        if peer.uid == 0 {
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                "Mail does not open inside the system account. No mailbox capability was issued. Next step: sign in to your desktop account and open Mail there.",
                json!({ "decision": "deny", "reason": "system_profile" }),
            ));
        }
        let status = Command::new(&self.cfg.pim_launch_broker)
            .args([broker_mode, &peer.uid.to_string(), &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            // The fixed, root-owned broker emits only a closed error category;
            // keep it in punard's journal so a refused desktop handoff is
            // diagnosable without ever reflecting process paths, account data,
            // or credentials into the user-facing protocol response.
            .stderr(Stdio::inherit())
            .status()
            .map_err(|_| mail_launch_unavailable("broker_spawn_failed"))?;
        if !status.success() {
            let reason = status
                .code()
                .map(|code| format!("broker_exit_{code}"))
                .unwrap_or_else(|| "broker_signal".to_string());
            return Err(mail_launch_unavailable(&reason));
        }
        Ok(json!({ "opening": true, "application": application }))
    }

    #[cfg(not(target_os = "linux"))]
    fn handle_pim_mail_open(&self, _peer: &Peer) -> Result<Value, IpcError> {
        Err(mail_launch_unavailable("unsupported_platform"))
    }

    #[cfg(not(target_os = "linux"))]
    fn handle_pim_mail_account_add(&self, _peer: &Peer) -> Result<Value, IpcError> {
        Err(mail_launch_unavailable("unsupported_platform"))
    }

    #[cfg(not(target_os = "linux"))]
    fn handle_pim_mail_account_manage(&self, _peer: &Peer) -> Result<Value, IpcError> {
        Err(mail_launch_unavailable("unsupported_platform"))
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
        match self.apps.install(
            &params.id,
            &params.confirm_metadata_sha256,
            params.acknowledge_host_access,
        ) {
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

    fn webapp_event(
        &self,
        actor: &AuditActor,
        action: &str,
        resource: &str,
        decision: Decision,
        result: &str,
        policy_ids: Vec<String>,
    ) -> AuditEvent {
        AuditEvent {
            event_id: next_event_id(),
            timestamp: utc_now_rfc3339(),
            device_id: self.device_id.clone(),
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
            resource: Some(resource.to_string()),
            decision,
            policy_ids: if policy_ids.is_empty() {
                vec![punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string()]
            } else {
                policy_ids
            },
            result: result.to_string(),
        }
    }

    fn webapp_human_actor(
        &self,
        peer: &Peer,
        action: &str,
        resource: &str,
    ) -> Result<AuditActor, IpcError> {
        let actor = self.actor_of(peer);
        if actor.source != PrincipalKind::AiAgent {
            return Ok(actor);
        }
        self.log_audit(self.webapp_event(
            &actor,
            action,
            resource,
            Decision::Deny,
            "denied",
            vec![punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string()],
        ));
        Err(IpcError::with_details(
            ErrorCode::Denied,
            "An AI agent cannot create, change, or remove a persistent web-app identity.\n\
             Policy: personal defaults — these mutations require the person at the device.\n\
             Next step: use `punarctl web-apps` yourself, or choose the web app in Command Center.",
            json!({
                "decision": "deny",
                "reason": "agent_attributed",
                "policy_ids": ["personal-defaults"]
            }),
        ))
    }

    fn webapp_policy_summary(&self) -> (bool, Vec<String>, bool) {
        let enrollment = self.enrollment.lock().unwrap().clone();
        let Some(enrollment) = enrollment else {
            return (
                false,
                vec![punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string()],
                true,
            );
        };
        let policy_ids = enrollment.policy_ids();
        let allow_user_install = self
            .application_policy
            .lock()
            .unwrap()
            .iter()
            .filter(|layer| layer.allow_user_install.is_some())
            .min_by_key(|layer| layer.provenance.rank)
            .and_then(|layer| layer.allow_user_install)
            .unwrap_or(false);
        (true, policy_ids, allow_user_install)
    }

    fn effective_required_webapps(&self) -> Vec<WebAppManifest> {
        let layers = self.application_policy.lock().unwrap();
        let mut ids = BTreeSet::new();
        for layer in layers.iter() {
            ids.extend(layer.required_web_apps.keys().cloned());
        }

        let mut required = Vec::new();
        for id in ids {
            let Some((_, manifest)) = layers
                .iter()
                .filter_map(|layer| layer.required_web_apps.get(&id).map(|app| (layer, app)))
                .min_by_key(|(layer, _)| layer.provenance.rank)
            else {
                continue;
            };
            let Ok(origin) = origin_from_start_url(&manifest.start_url) else {
                continue;
            };
            let decision =
                evaluate_webapp_policy(&layers, &id, &origin, ApplicationPolicyAction::Install);
            if decision.allowed && decision.reason == ApplicationPolicyReason::RequiredWebApp {
                required.push(manifest.clone());
            }
        }
        required.sort_by(|a, b| a.id.cmp(&b.id));
        required
    }

    fn webapp_contexts_with_enrollment(
        &self,
        uid: u32,
        include_artifacts: bool,
    ) -> Result<Value, IpcError> {
        let mut local = self
            .webapps
            .list(uid, include_artifacts)
            .map_err(webapp_ipc_error)?;
        if let Some(enrollment) = self.enrollment.lock().unwrap().clone() {
            let id = format!("org-{}", enrollment.org.id);
            validate_context_id(&id).map_err(|reason| {
                IpcError::with_details(
                    ErrorCode::Internal,
                    "The enrolled organization has an invalid browser-context identity.\n\
                     Policy: fail closed — Punar will not derive a filesystem path from it.\n\
                     Next step: correct the organization id in Smplify and re-enroll.",
                    json!({ "component": "enrollment", "reason": reason }),
                )
            })?;
            local.contexts.push(BrowserContext {
                id: id.clone(),
                name: enrollment.org.display_name,
                derived: true,
                deletable: false,
                isolates: vec![
                    "cookies".into(),
                    "storage".into(),
                    "sign_ins".into(),
                    "history".into(),
                    "extensions".into(),
                ],
                profile_path_rel: format!("punar/browser/contexts/{id}"),
                simulated: vec!["certificate_roots".into()],
                not_yet_observed: vec![NotYetObserved {
                    category: "per_context_network_policy".into(),
                    milestone: "phase_2".into(),
                }],
                source: Some("enrollment".into()),
            });
            local.contexts.sort_by(|a, b| a.id.cmp(&b.id));
        }
        let (managed, policy_ids, allow_user_install) = self.webapp_policy_summary();
        let required_web_apps = self.effective_required_webapps();
        Ok(json!({
            "apps": local.apps,
            "contexts": local.contexts,
            "required_web_apps": required_web_apps,
            "policy": {
                "managed": managed,
                "policy_ids": policy_ids,
                "allow_user_install": allow_user_install,
            }
        }))
    }

    fn handle_webapps_list(
        &self,
        peer: &Peer,
        params: &WebAppsListParams,
    ) -> Result<Value, IpcError> {
        self.webapp_contexts_with_enrollment(peer.uid, params.include_artifacts)
    }

    fn handle_webapps_get(
        &self,
        peer: &Peer,
        params: &WebAppsGetParams,
    ) -> Result<Value, IpcError> {
        self.webapps
            .get(peer.uid, &params.id, params.include_artifacts)
            .map(to_value)
            .map_err(webapp_ipc_error)
    }

    fn webapp_install_policy(
        &self,
        id: &str,
        origin: &str,
        action: ApplicationPolicyAction,
    ) -> Result<(bool, bool, Vec<String>), IpcError> {
        if self.enrollment.lock().unwrap().is_none() {
            return Ok((
                false,
                false,
                vec![punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string()],
            ));
        }
        let decision =
            evaluate_webapp_policy(&self.application_policy.lock().unwrap(), id, origin, action);
        let policy_id = decision
            .provenance
            .as_ref()
            .map(|source| source.policy_id.clone())
            .unwrap_or_else(|| "organization-application-policy".into());
        if decision.allowed {
            return Ok((
                true,
                decision.reason == ApplicationPolicyReason::RequiredWebApp,
                vec![policy_id],
            ));
        }
        let reason = decision.reason.as_str();
        Err(IpcError::with_details(
            ErrorCode::Denied,
            format!(
                "Your organization did not allow this persistent web-app change.\n\
                 Policy: {policy_id} — applications policy for origin {origin} ({reason}).\n\
                 Next step: choose an allowed app or contact your administrator."
            ),
            json!({
                "application": id,
                "origin": origin,
                "decision": "deny",
                "reason": reason,
                "policy_ids": [policy_id],
                "enforcement": "courtesy_gate"
            }),
        ))
    }

    fn handle_webapps_install(
        &self,
        peer: &Peer,
        params: &WebAppsInstallParams,
    ) -> Result<Value, IpcError> {
        let action = "webapp.install";
        let resource = format!("webapp:{}", params.app.id);
        let actor = self.webapp_human_actor(peer, action, &resource)?;
        let origin = origin_from_start_url(&params.app.start_url).map_err(|reason| {
            IpcError::with_details(
                ErrorCode::InvalidParams,
                "The web app start URL is not a safe HTTPS or local fixture URL.\n\
                 Policy: Punar browser input boundary — URLs cannot carry credentials, whitespace, or flag-like tokens.\n\
                 Next step: use a canonical https:// URL and retry.",
                json!({ "param": "app.start_url", "reason": reason }),
            )
        })?;
        let (policy_file_managed, required, policy_ids) = match self.webapp_install_policy(
            &params.app.id,
            &origin,
            ApplicationPolicyAction::Install,
        ) {
            Ok(value) => value,
            Err(error) => {
                let ids = error
                    .details
                    .as_ref()
                    .and_then(|details| details.get("policy_ids"))
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                self.log_audit(self.webapp_event(
                    &actor,
                    action,
                    &resource,
                    Decision::Deny,
                    "denied",
                    ids,
                ));
                return Err(error);
            }
        };
        let derived_context = self
            .enrollment
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|enrollment| params.app.context == format!("org-{}", enrollment.org.id));
        let _guard = self.webapp_mutation.lock().unwrap();
        match self.webapps.install(
            peer.uid,
            &params.app,
            policy_ids.clone(),
            required,
            policy_file_managed,
            derived_context,
        ) {
            Ok(result) => {
                self.log_audit(self.webapp_event(
                    &actor,
                    action,
                    &resource,
                    Decision::Allow,
                    "installed",
                    policy_ids,
                ));
                Ok(to_value(result))
            }
            Err(error) => {
                self.log_audit(self.webapp_event(
                    &actor,
                    action,
                    &resource,
                    Decision::Allow,
                    "failure",
                    policy_ids,
                ));
                Err(webapp_ipc_error(error))
            }
        }
    }

    fn handle_webapps_uninstall(
        &self,
        peer: &Peer,
        params: &WebAppsUninstallParams,
    ) -> Result<Value, IpcError> {
        let action = "webapp.uninstall";
        let resource = format!("webapp:{}", params.id);
        let actor = self.webapp_human_actor(peer, action, &resource)?;
        let installed = self
            .webapps
            .get(peer.uid, &params.id, false)
            .map_err(webapp_ipc_error)?;
        let (_policy_file_managed, _required, policy_ids) = match self.webapp_install_policy(
            &params.id,
            &installed.app.origin,
            ApplicationPolicyAction::Remove,
        ) {
            Ok(value) => value,
            Err(error) => {
                self.log_audit(self.webapp_event(
                    &actor,
                    action,
                    &resource,
                    Decision::Deny,
                    "denied",
                    vec![],
                ));
                return Err(error);
            }
        };
        let _guard = self.webapp_mutation.lock().unwrap();
        match self
            .webapps
            .uninstall(peer.uid, &params.id, params.purge_data)
        {
            Ok(result) => {
                self.log_audit(self.webapp_event(
                    &actor,
                    action,
                    &resource,
                    Decision::Allow,
                    if params.purge_data {
                        "purged"
                    } else {
                        "uninstalled"
                    },
                    policy_ids,
                ));
                Ok(result)
            }
            Err(error) => {
                self.log_audit(self.webapp_event(
                    &actor,
                    action,
                    &resource,
                    Decision::Allow,
                    "failure",
                    policy_ids,
                ));
                Err(webapp_ipc_error(error))
            }
        }
    }

    fn handle_webapps_context_create(
        &self,
        peer: &Peer,
        params: &WebAppsContextCreateParams,
    ) -> Result<Value, IpcError> {
        let action = "webapp.context_create";
        let resource = format!("browser-context:{}", params.id);
        let actor = self.webapp_human_actor(peer, action, &resource)?;
        let (_managed, policy_ids, _allow) = self.webapp_policy_summary();
        let _guard = self.webapp_mutation.lock().unwrap();
        match self
            .webapps
            .context_create(peer.uid, &params.id, &params.name)
        {
            Ok(context) => {
                self.log_audit(self.webapp_event(
                    &actor,
                    action,
                    &resource,
                    Decision::Allow,
                    "created",
                    policy_ids,
                ));
                Ok(json!({ "context": context }))
            }
            Err(error) => {
                self.log_audit(self.webapp_event(
                    &actor,
                    action,
                    &resource,
                    Decision::Allow,
                    "failure",
                    policy_ids,
                ));
                Err(webapp_ipc_error(error))
            }
        }
    }

    fn handle_webapps_context_delete(
        &self,
        peer: &Peer,
        params: &WebAppsContextDeleteParams,
    ) -> Result<Value, IpcError> {
        let action = "webapp.context_delete";
        let resource = format!("browser-context:{}", params.id);
        let actor = self.webapp_human_actor(peer, action, &resource)?;
        let (_managed, policy_ids, _allow) = self.webapp_policy_summary();
        let _guard = self.webapp_mutation.lock().unwrap();
        match self
            .webapps
            .context_delete(peer.uid, &params.id, params.purge_data)
        {
            Ok(result) => {
                self.log_audit(self.webapp_event(
                    &actor,
                    action,
                    &resource,
                    Decision::Allow,
                    if params.purge_data {
                        "purged"
                    } else {
                        "deleted"
                    },
                    policy_ids,
                ));
                Ok(result)
            }
            Err(error) => {
                let denied = matches!(error, WebAppError::Denied(_));
                self.log_audit(self.webapp_event(
                    &actor,
                    action,
                    &resource,
                    if denied {
                        Decision::Deny
                    } else {
                        Decision::Allow
                    },
                    if denied { "denied" } else { "failure" },
                    policy_ids,
                ));
                Err(webapp_ipc_error(error))
            }
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
        self.settle_layer_change(
            actor,
            cap,
            id,
            Some(&params.desired_state),
            "capabilities.set",
            extra_policy_ids,
        )
    }

    /// Apply the effective value for `id` after a layer store has changed:
    /// recompute the merge, apply, verify, audit under `audit_action`.
    ///
    /// SHARED BY `capabilities.set` AND `policy.set` on purpose. The two differ
    /// only in which layer they wrote and what the audit trail calls the
    /// action; everything after that — apply the value the MERGE chose rather
    /// than the one the caller named, re-observe, and record the outcome — is
    /// the same sequence, and having one copy of it is what stops the
    /// administrator's path from quietly drifting into a weaker one.
    ///
    /// `requested` is what the caller asked for, or `None` when they cleared an
    /// entry. It is used for one thing: deciding whether the result should say
    /// the value was overridden by a higher layer.
    fn settle_layer_change(
        &self,
        actor: &AuditActor,
        cap: &dyn Capability,
        id: &str,
        requested: Option<&Value>,
        audit_action: &str,
        extra_policy_ids: &[String],
    ) -> (Result<Value, IpcError>, Execution) {
        self.recompute_effective();

        let (effective_value, winning_policy_id) = {
            let doc = self.effective.lock().unwrap();
            let entry = doc
                .get(id)
                .expect("registered capability has an effective entry");
            (entry.value.clone(), entry.provenance.policy_id.clone())
        };
        let overridden = requested.is_some_and(|want| effective_value != *want);
        let mut policy_ids = vec![winning_policy_id];
        policy_ids.extend(extra_policy_ids.iter().cloned());
        let audited = |outcome: AuditOutcome| {
            // `AuditEvent::action` is what `AuditEvent::capabilities_set` is
            // built from, so a `capabilities.set` event through this path is
            // byte-identical to the one M3 shipped.
            let mut event = AuditEvent::action(
                &self.device_id,
                actor,
                audit_action,
                id,
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
            return Err(IpcError::denied_root_only(
                "Reconciling the capability registry",
                RESOURCE_CAPABILITY_REGISTRY,
                "none needed — punard reconciles on its own at boot and every two \
                 minutes (punard-reconcile.timer). `punarctl status` shows when it \
                 last ran; `punarctl policy explain <capability>` shows what it enforces.",
            ));
        }

        // The organization's policy first, so a changed set is what this
        // pass enforces and reports (SPEC section 42: load desired state,
        // then diff). A no-op on a personal device.
        // One budget for the pass's calls to the control plane, the fetch
        // and the reports together (RECONCILE_CONTROL_PLANE_BUDGET), so a
        // pass on a slow or black-holed link still answers inside
        // punarctl's wait for it.
        let budget = CallBudget::new(self.cfg.reconcile_control_plane_budget);
        self.refresh_policy_if_enrolled(&actor, &budget);
        let report = self.reconcile_and_remediate(&actor, &budget);
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
    fn reconcile_and_remediate(&self, actor: &AuditActor, budget: &CallBudget) -> ReconcileResult {
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
        self.sync_if_enrolled(actor, budget);
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
        if !cap.mutable() {
            // DRIFT THAT NOTHING ON THIS DEVICE CAN FIX. Retrying an apply here
            // would fail once per reconcile cycle forever, filling the audit
            // trail with a failure that is not a fault — the value is a
            // property of the image, and the honest report is the same one
            // alert_only makes: this is not compliant, and remediation was not
            // attempted. An organization reading the compliance report learns
            // the true state; nobody is told a lie about it being fixable.
            // No audit event, deliberately: the classification-driven
            // alert_only branch below emits none either, and reconcile runs on
            // a timer — an event per cycle for a state that cannot change would
            // be the trail's loudest entry and its least informative. The
            // reconcile result carries `remediation: alert_only` and the
            // tracker records non_compliant, which is what the compliance
            // report an organization reads is built from.
            return (RemediationOutcome::AlertOnly, ComplianceState::NonCompliant);
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
        let local_admin = self.local_admin_status();
        let admin_editable = local_admin.allowed;
        let tracker = self.tracker.lock().unwrap();
        let entries = doc
            .entries
            .iter()
            .map(|(path, entry)| PolicyEffectiveEntry {
                path: path.clone(),
                effective_value: entry.value.clone(),
                source: source_ref(&entry.provenance),
                user_override_permitted: entry.user_override_permitted,
                admin_override_permitted: admin_editable && admin_may_override(entry),
                compliance_state: tracker.state_of(path),
            })
            .collect();
        PolicyEffectiveResult {
            computed_at: doc.computed_at,
            entries,
            local_admin,
        }
    }

    /// The device-wide half of the answer: whether an administrator may edit
    /// anything, and which organization document said otherwise.
    fn local_admin_status(&self) -> LocalAdminStatus {
        let layers = self.local_admin.lock().unwrap();
        match resolve_local_admin(&layers) {
            Some(layer) => LocalAdminStatus {
                allowed: layer.allowed,
                source: Some(source_ref(&layer.provenance)),
            },
            None => LocalAdminStatus::default(),
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
            admin_override_permitted: self.local_admin_status().allowed
                && admin_may_override(&entry),
            compliance_state: self.tracker.lock().unwrap().state_of(path),
        };
        Ok(to_value(result))
    }

    /// `policy.set`: the device administrator pins (or clears) one capability
    /// for everyone on this machine.
    ///
    /// WHAT THIS IS, AND WHAT IT IS NOT. It is an ADMINISTRATIVE control, not a
    /// security boundary. docs/design/execution-trust.md says it plainly — "A
    /// local root user defeats local policy" — and nothing here changes that. A
    /// person who can become root on this machine can edit
    /// `/var/lib/punar/local-policy.json` directly. What this method adds is
    /// that the ORDINARY route is authenticated, bounded, explained and
    /// recorded, so a change has an author and a reason attached to it.
    ///
    /// THE LADDER IT ENFORCES, in the order the checks run, because each one
    /// answers a different person's question:
    ///
    /// ```text
    /// 1. an agent scope?          -> denied outright. No re-auth path exists
    ///                                for an agent, and SPEC 60 forbids
    ///                                root-ness inside a scope buying a bypass.
    /// 2. a stated reason?         -> required. A pinned value with no reason
    ///                                is the thing the next person will ask
    ///                                about, and the answer belongs in the file.
    /// 3. does the value validate? -> the capability decides, as it does for
    ///                                capabilities.set. Closed vocabulary.
    /// 4. may a local admin edit?  -> the organization decides (SPEC 44.5).
    /// 5. may THIS path move?      -> the ladder decides: rank 4 cannot displace
    ///                                ranks 1-3, nor a rank-4 approved exception.
    /// 6. who is asking?           -> uid 0, or a re-authenticated caller
    ///                                holding a ticket punar-authd minted for
    ///                                their own uid in the last two minutes.
    /// ```
    ///
    /// Order matters for what a refusal SAYS. Asking for a password and then
    /// refusing the change on policy grounds would be a small cruelty; every
    /// reason that does not depend on who is asking is settled first.
    fn handle_policy_set(&self, peer: &Peer, params: &PolicySetParams) -> Result<Value, IpcError> {
        let cap = self.lookup(&params.capability)?;
        let id = params.capability.as_str();
        let actor = self.actor_of(peer);
        let deny = |details: Value, message: String| -> IpcError {
            IpcError::with_details(ErrorCode::Denied, message, details)
        };

        // 1. No agent, at any uid.
        if let Some(session) = actor.agent_session_id.clone() {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                "policy.set",
                id,
            ));
            return Err(deny(
                json!({
                    "decision": "deny",
                    "capability": id,
                    "agent_session_id": session,
                    "reason": "agent_scope",
                }),
                format!(
                    "An AI agent may not set device policy.\n\
                     Requested by: {session}\n\
                     Policy: personal defaults — device administration requires a \
                     person who has just proved their password, and an agent has no \
                     password to prove.\n\
                     Next step: make the change yourself in System Control · Policy."
                ),
            ));
        }

        // 2. A reason, in the administrator's own words.
        let reason = params.reason.trim();
        if reason.is_empty() || reason.chars().count() > MAX_POLICY_REASON_CHARS {
            return Err(IpcError::with_details(
                ErrorCode::InvalidParams,
                format!(
                    "A device policy change needs a reason of 1 to {MAX_POLICY_REASON_CHARS} \
                     characters.\n\
                     Policy: personal defaults — a pinned value outlives the moment it \
                     was pinned, and the next person to meet it deserves to know why.\n\
                     Next step: repeat the change with --reason \"...\"."
                ),
                json!({ "param": "reason", "capability": id }),
            ));
        }

        // 3. The value is the capability's to accept, exactly as for
        //    capabilities.set. Clearing skips this: there is nothing to check.
        if let Some(value) = &params.value {
            cap.validate(value).map_err(|why| invalid_state(&why))?;
        }

        // 4. The organization's opinion about local administration.
        let local_admin = self.local_admin_status();
        if !local_admin.allowed {
            let (name, policy_id) = local_admin
                .source
                .as_ref()
                .map(|src| (src.name.clone(), src.policy_id.clone()))
                .unwrap_or_else(|| ("your organization".into(), "unknown".into()));
            let mut event = AuditEvent::denial(&self.device_id, &actor, "policy.set", id);
            event.policy_ids = vec![policy_id.clone()];
            self.log_audit(event);
            return Err(deny(
                json!({
                    "decision": "deny",
                    "capability": id,
                    "policy_ids": [policy_id],
                    "reason": "local_admin_disabled",
                }),
                format!(
                    "Local policy editing is turned off on this device by {name} \
                     ({policy_id}).\n\
                     User override: not permitted.\n\
                     Next step: ask {name} to change the policy centrally — this device \
                     will pick it up on its next sync."
                ),
            ));
        }

        // 5. Whether this particular path is one the administrator's rung can
        //    move. A value an organization pins is not editable here, and the
        //    refusal names who pinned it rather than saying "no".
        //
        //    WITHDRAWING IS EXEMPT, and it has to be. This test looks at who
        //    wins *now*, and an organization can come to outrank an entry the
        //    administrator recorded earlier — at which point the same test that
        //    stops them pinning also stops them removing what they already
        //    pinned. The entry then sits in the store, inert while enrolled and
        //    silently reactivating the day the device unenrolls: a rule nobody
        //    can see, nobody can delete, and that comes back. A clear can only
        //    ever remove a local opinion, so it can never contest the layer
        //    that outranks it, and there is nothing for this check to protect.
        let current = self
            .effective
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| self.internal(&format!("{id} has no effective entry")))?;
        let pinning = params.value.is_some();
        if pinning && !admin_may_override(&current) {
            let mut event = AuditEvent::denial(&self.device_id, &actor, "policy.set", id);
            event.policy_ids = vec![current.provenance.policy_id.clone()];
            self.log_audit(event);
            return Err(IpcError::denied_org_pinned(
                id,
                &current.provenance.source_name,
                &current.provenance.policy_id,
            ));
        }

        // 6. Who is asking. Root needs no ticket — it has no lock screen to
        //    re-authenticate against, and it could edit the store directly in
        //    any case, so demanding one would be theatre.
        if peer.uid != 0 {
            let Some(ticket) = params.ticket.as_deref() else {
                self.log_audit(AuditEvent::denial(
                    &self.device_id,
                    &actor,
                    "policy.set",
                    id,
                ));
                let command = if params.value.is_some() {
                    format!("punarctl policy set {id} <value> --reason \"<why>\"")
                } else {
                    format!("punarctl policy clear {id} --reason \"<why>\"")
                };
                return Err(deny(
                    json!({
                        "decision": "deny",
                        "capability": id,
                        "reason": "reauthentication_required",
                    }),
                    format!(
                        "Changing device policy needs your password again, and this \
                         request did not carry a confirmation.\n\
                         Policy: personal defaults — an administrative change is \
                         confirmed at the moment it is made, not by having been \
                         signed in for a while.\n\
                         Next step: run `{command}` in a terminal, which asks for your \
                         password, or make the change from System Control · Policy."
                    ),
                ));
            };
            if let Err(why) = crate::reauth::consume(
                &self.cfg.reauth_ticket_dir,
                peer.uid,
                ticket,
                SystemTime::now(),
            ) {
                self.log_audit(AuditEvent::denial(
                    &self.device_id,
                    &actor,
                    "policy.set",
                    id,
                ));
                return Err(deny(
                    json!({
                        "decision": "deny",
                        "capability": id,
                        "reason": format!("reauthentication_{}", why.as_str()),
                    }),
                    format!(
                        "Your password confirmation was not accepted: {}.\n\
                         Policy: personal defaults — a confirmation is good once, for \
                         two minutes, for the account that made it.\n\
                         Next step: try the change again and enter your password when \
                         asked.",
                        why.as_message()
                    ),
                ));
            }
        }

        // Authorized. Record the entry, then let the shared settle path apply
        // whatever the MERGE now says — which may not be what was just pinned,
        // if a higher layer wins, and the result says so rather than implying
        // the change took effect.
        let entry = params.value.as_ref().map(|value| AdminPolicyEntry {
            value: value.clone(),
            set_at: utc_now_rfc3339(),
            set_by: actor.user_id.clone(),
            reason: reason.to_string(),
        });
        self.admin_policy
            .set(id, entry)
            .map_err(|e| self.internal(&format!("persisting the policy entry failed: {e}")))?;

        let (result, execution) =
            self.settle_layer_change(&actor, cap, id, params.value.as_ref(), "policy.set", &[]);
        result?;

        let settled = self
            .effective
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| self.internal(&format!("{id} has no effective entry")))?;
        Ok(to_value(PolicySetResult {
            capability: id.to_string(),
            pinned_value: params.value.clone(),
            effective_value: settled.value,
            source: source_ref(&settled.provenance),
            changed: execution.changed.unwrap_or(false),
        }))
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
        enrollment_event(&self.device_id, actor, action, resource, result, policy_ids)
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
            // It answered, with more than this device reads: asking again
            // gets the same answer, so it is not reported as unreachable.
            UpstreamError::TooLarge => IpcError::with_details(
                ErrorCode::InvalidParams,
                format!(
                    "The control plane's answer to the {stage} step is larger than this \
                     device reads ({} MiB).\n\
                     Policy: os default — punard bounds what it reads from the control plane \
                     (docs/api/ipc.md section 5.9), and enrollment is all-or-nothing; nothing \
                     was changed.\n\
                     Next step: report this to your administrator.",
                    crate::enroll::MAX_ANSWER_BYTES / (1024 * 1024)
                ),
                json!({ "stage": stage, "reason": REASON_ANSWER_TOO_LARGE }),
            ),
        }
    }

    fn conflict(&self, state: &str, message: String) -> IpcError {
        IpcError::with_details(ErrorCode::Conflict, message, json!({ "state": state }))
    }

    /// Who may change this device's enrollment (contract sections 5.9, 5.11).
    ///
    /// Root has no account for Punar's lock screen to re-authenticate against,
    /// so it needs no ticket, exactly as for `policy.set`. A person is never
    /// root on a Punar device: root is locked and no account holds sudo
    /// (onboarding.md section 1.6). A person therefore proves their password
    /// to punar-authd, which mints a single-use ticket for their uid, and
    /// [`Inner::spend_enrollment_ticket`] spends it. Reaching punar-authd at
    /// all takes membership of the `punar` group, so a ticket also says "this
    /// is the device's administrator".
    ///
    /// This half runs first and costs the caller nothing: an agent-shaped
    /// peer is refused at any uid (enrollment decides who manages the device,
    /// and SPEC section 60 gives an agent no say in that), and a person who
    /// brought no confirmation is refused before anything is parsed or sent.
    /// `enroll.stop` runs the two checks separately, so that a refusal which
    /// does not depend on who is asking (a non-removable enrollment) comes
    /// between them and nobody is asked for a password only to be refused.
    fn admit_enrollment_change(
        &self,
        peer: &Peer,
        actor: &AuditActor,
        action: &str,
        ticket: Option<&str>,
        words: &EnrollmentWords,
        retry: &str,
    ) -> Result<(), IpcError> {
        self.refuse_agent_enrollment_change(peer, actor, action, words, retry)?;
        self.require_enrollment_ticket(peer, actor, action, ticket, words, retry)
    }

    /// An agent-shaped peer may not change who manages the device, at any
    /// uid. First, always.
    fn refuse_agent_enrollment_change(
        &self,
        peer: &Peer,
        actor: &AuditActor,
        action: &str,
        words: &EnrollmentWords,
        retry: &str,
    ) -> Result<(), IpcError> {
        if let Some(who) = self.agent_shaped_peer(peer, actor) {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                actor,
                action,
                RESOURCE_ENROLLMENT,
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "An AI agent may not {}.\n\
                     Requested by: {who}\n\
                     Policy: personal defaults — enrollment decides who manages this \
                     device, and only a person who has just proved their password may \
                     change it (SPEC section 60).\n\
                     Next step: run `{retry}` yourself.",
                    words.verb
                ),
                json!({ "decision": "deny", "reason": "agent_scope" }),
            ));
        }
        Ok(())
    }

    /// A person must bring a confirmation; root has none to bring.
    fn require_enrollment_ticket(
        &self,
        peer: &Peer,
        actor: &AuditActor,
        action: &str,
        ticket: Option<&str>,
        words: &EnrollmentWords,
        retry: &str,
    ) -> Result<(), IpcError> {
        if peer.uid != 0 && ticket.is_none() {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                actor,
                action,
                RESOURCE_ENROLLMENT,
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "{} needs your password, and this request did not carry a \
                     confirmation.\n\
                     Policy: personal defaults — who manages a device is an \
                     administrative change, confirmed at the moment it is made.\n\
                     Next step: run `{retry}` in a terminal; it asks for {}.",
                    words.doing, words.asks
                ),
                json!({ "decision": "deny", "reason": "reauthentication_required" }),
            ));
        }
        Ok(())
    }

    /// Refuse to end an enrollment its organization made non-removable, for
    /// every caller. Audited as a denial.
    fn refuse_kept_enrollment(&self, actor: &AuditActor) -> Result<(), IpcError> {
        let terms = self
            .enrollment
            .lock()
            .unwrap()
            .as_ref()
            .filter(|e| !e.removable)
            .map(|e| (e.org.id.clone(), e.org.display_name.clone()));
        let Some((org_id, org_name)) = terms else {
            return Ok(());
        };
        self.log_audit(AuditEvent::denial(
            &self.device_id,
            actor,
            "enroll.stop",
            RESOURCE_ENROLLMENT,
        ));
        Err(IpcError::with_details(
            ErrorCode::Denied,
            format!(
                "This device's enrollment with {org_name} cannot be undone from the \
                 device.\n\
                 Policy: {org_name}'s enrollment terms — it enrolls devices as not \
                 removable, and that was accepted when this device enrolled \
                 (docs/development/smplify-enrollment.md section 3.1).\n\
                 Next step: only erasing and reinstalling the device ends the \
                 enrollment. A release sent by {org_name} is not built yet."
            ),
            json!({
                "decision": "deny",
                "reason": "enrollment_not_removable",
                "organization": org_id,
            }),
        ))
    }

    /// Spend a person's confirmation (root has none to spend). The unlink is
    /// the commit, so a replayed ticket finds nothing; a ticket is never
    /// forwarded, audited, stored or returned.
    fn spend_enrollment_ticket(
        &self,
        peer: &Peer,
        actor: &AuditActor,
        action: &str,
        ticket: Option<&str>,
        retry: &str,
    ) -> Result<(), IpcError> {
        self.spend_reauth_ticket(peer, actor, action, RESOURCE_ENROLLMENT, ticket, retry)
    }

    /// Spend a person's `punar-authd` confirmation for `action` on `resource`
    /// (root has none to spend). Shared by every method a person reaches with
    /// their password: the rule — good once, for two minutes, for the account
    /// that made it — is one rule, not one per method.
    fn spend_reauth_ticket(
        &self,
        peer: &Peer,
        actor: &AuditActor,
        action: &str,
        resource: &str,
        ticket: Option<&str>,
        retry: &str,
    ) -> Result<(), IpcError> {
        if peer.uid == 0 {
            return Ok(());
        }
        let Err(why) = crate::reauth::consume(
            &self.cfg.reauth_ticket_dir,
            peer.uid,
            ticket.unwrap_or_default(),
            SystemTime::now(),
        ) else {
            return Ok(());
        };
        self.log_audit(AuditEvent::denial(&self.device_id, actor, action, resource));
        Err(IpcError::with_details(
            ErrorCode::Denied,
            format!(
                "Your password confirmation was not accepted: {}.\n\
                 Policy: personal defaults — a confirmation is good once, for two \
                 minutes, for the account that made it.\n\
                 Next step: run `{retry}` again and enter your password when asked.",
                why.as_message()
            ),
            json!({
                "decision": "deny",
                "reason": format!("reauthentication_{}", why.as_str()),
            }),
        ))
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
        let shown = if domain_syntax_ok(params.org_domain.trim()) {
            params.org_domain.trim()
        } else {
            "<domain>"
        };
        let retry = format!("punarctl enroll start {shown}");
        self.admit_enrollment_change(
            peer,
            &actor,
            "enroll.start",
            params.ticket.as_deref(),
            &ENROLL_START_WORDS,
            &retry,
        )?;
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
        // The confirmation is spent here: after the one refusal that costs
        // nothing to check (a malformed domain, which a person fixes by
        // retyping), and before anything else, so every later outcome — the
        // conflict below included — is audited against a caller who proved
        // who they are, and nothing leaves the device for one who did not.
        // punarctl reads `enroll.status` first, so a person is not asked for
        // a password on a device that is already enrolled.
        self.spend_enrollment_ticket(
            peer,
            &actor,
            "enroll.start",
            params.ticket.as_deref(),
            &retry,
        )?;
        // Serialize enrollment transitions without holding the state lock
        // across the network/reconcile pipeline.
        let _guard =
            match EnrollGuard::acquire_within(&self.enroll_in_progress, ENROLL_GUARD_PATIENCE) {
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
        let current = self
            .enrollment
            .lock()
            .unwrap()
            .as_ref()
            .map(unenroll_next_step);
        if let Some(unenroll) = current {
            self.log_audit(self.enroll_event(
                &actor,
                "enroll.start",
                RESOURCE_ENROLLMENT,
                "failure",
                vec![],
            ));
            return Err(self.conflict(
                "enrolled",
                format!(
                    "This device is already enrolled.\n\
                     Policy: os default — one organization at a time (docs/api/ipc.md \
                     section 5.9).\n\
                     Next step: `punarctl enroll status` shows the current organization. \
                     {unenroll}"
                ),
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

        // The enrollment code exists only in memory, only for the register
        // call, and is never audited, logged or returned (SPEC section 49).
        let code = params
            .code
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(|c| Redacted::new(c.to_string()));
        // Discover.
        let client = self
            .control_plane()
            .within(CallBudget::new(ENROLL_CONTROL_PLANE_BUDGET));
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
        // Every string here is the organization's choice, and punard shows
        // the names to a person: beside the terms they are asked to accept,
        // in every view of the enrollment, in the shell's bar. They are
        // cleaned once, here, before anything stores or prints them —
        // invisible and control characters dropped, whitespace collapsed,
        // at most 64 characters (punar_common::ipc::organization_name) — and
        // a domain that is not a domain name is the one the person typed.
        let name = organization_name(&org_name);
        let display_name = field(&org_doc, &["enrollment", "display_name"])
            .as_deref()
            .and_then(organization_name)
            .or_else(|| name.clone())
            .unwrap_or_else(|| domain.to_string());
        let org = OrgRecord {
            name: name.unwrap_or_else(|| display_name.clone()),
            display_name,
            domain: field(&org_doc, &["discovery", "domain"])
                .filter(|shown| domain_syntax_ok(shown))
                .unwrap_or_else(|| domain.to_string()),
            id: org_id,
        };
        // Removability is the organization's decision, read from its document
        // once, here, and fixed in enrollment.json — like the remote-query
        // grant above, never re-read from a later policy fetch, so it cannot be
        // tightened after the person agreed to it. A non-removable enrollment
        // needs the person's explicit yes; both refusals come before register,
        // so the organization never learns of a device that did not enroll.
        let removable = match org_document_removable(&org_doc) {
            Ok(removable) => removable,
            Err(found) => {
                return Err(fail_audit(IpcError::with_details(
                    ErrorCode::InvalidParams,
                    format!(
                        "{}'s organization document says enrollment.removable is {found}, \
                         which is not true or false, so this device cannot tell whether it \
                         could be unenrolled later. Nothing was changed.\n\
                         Policy: os default — an unreadable enrollment term refuses \
                         enrollment rather than guessing (docs/development/\
                         smplify-enrollment.md section 3.1).\n\
                         Next step: ask {} to correct its organization document.",
                        org.display_name, org.display_name
                    ),
                    json!({ "stage": "discover", "reason": "enrollment.removable" }),
                )));
            }
        };
        // Ownership is read the same way, once and here. Punar has no
        // Automated Device Enrollment, so nothing proves an organization owns
        // the hardware: its document can claim the device, and only the
        // person's acceptance makes the claim widen what the inventory
        // carries (docs/development/smplify-enrollment.md section 3.2).
        let organization_owned = match org_document_organization_owned(&org_doc) {
            Ok(owned) => owned,
            Err(found) => {
                return Err(fail_audit(IpcError::with_details(
                    ErrorCode::InvalidParams,
                    format!(
                        "{}'s organization document says enrollment.ownership is {found}, \
                         which is neither \"personal\" nor \"organization\", so this device \
                         cannot tell what the organization would receive from it. Nothing was \
                         changed.\n\
                         Policy: os default — an unreadable enrollment term refuses \
                         enrollment rather than guessing (docs/development/\
                         smplify-enrollment.md section 3.2).\n\
                         Next step: ask {} to correct its organization document.",
                        org.display_name, org.display_name
                    ),
                    json!({ "stage": "discover", "reason": "enrollment.ownership" }),
                )));
            }
        };
        // Every term the request left unaccepted is named in one refusal, so
        // a person who says yes once is not refused again for the next one.
        let unaccepted: Vec<EnrollmentTerm> = EnrollmentTerm::ALL
            .into_iter()
            .filter(|term| match term {
                EnrollmentTerm::NonRemovable => !removable,
                EnrollmentTerm::OrganizationOwned => organization_owned,
            })
            .filter(|term| !params.accepts(*term))
            .collect();
        if !unaccepted.is_empty() {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                "enroll.start",
                RESOURCE_ENROLLMENT,
            ));
            return Err(unaccepted_terms_refusal(&org, domain, &unaccepted));
        }

        // Register. The bootstrap secret exists only in memory, only for
        // this call, and only behind Redacted; the returned token likewise
        // (SPEC section 53 — nothing that cannot be printed can leak).
        let bootstrap = Redacted::new(
            random_hex(crate::enroll::BOOTSTRAP_SECRET_BYTES)
                .map_err(|e| fail_audit(self.internal(&format!("bootstrap secret: {e}"))))?,
        );
        let (token, attestation) = client
            .register(&self.device_id, &bootstrap, code.as_ref())
            .map_err(|e| fail_audit(self.upstream_error("register", e)))?;
        // From here to the commit point every refusal releases the identity
        // the control plane just issued; see [`UncommittedRegistration`].
        let registration = UncommittedRegistration {
            // Its own client, outside the budget: a registration is released
            // however long enrolling took.
            client: self.control_plane(),
            token: Some(token.clone()),
        };
        // The attestation step is SIMULATED (milestone-5.md section 5.2):
        // the label is stored and surfaced verbatim; nothing was measured.

        // Fetch the organization's policy and check it by the rules every
        // later refresh applies too (crate::policy_set): the set is staged
        // beside policy.d, loaded and rendered there exactly as startup would
        // load it, together with any file a root administrator dropped, and
        // only a set that passed all of it replaces policy.d, whole.
        // Enrollment is all-or-nothing up to that swap.
        let fetched = client
            .policy_fetch(&token)
            .map_err(|e| fail_audit(self.upstream_error("policy.fetch", e)))?;
        // Something is assigned that the control plane cannot turn into Punar
        // policy. The device enrolls with none and says so, rather than
        // refusing an enrollment the organization asked for; a later refresh
        // picks the policy up once it is usable.
        let held_unusable =
            fetched.assignment == Assignment::Unusable && fetched.policies.is_empty();
        let set = CanonicalSet::from_envelopes(&fetched.policies, fetched.assignment)
            .map_err(|rejection| fail_audit(enroll_policy_refusal(&rejection)))?;
        let prepared = match policy_set::prepare(&self.cfg.state_dir, &set, &[]) {
            Ok(prepared) => prepared,
            Err(error) => {
                policy_set::discard_staging(&self.cfg.state_dir);
                return Err(fail_audit(match error {
                    PrepareError::Rejected(rejection) => enroll_policy_refusal(&rejection),
                    PrepareError::Local(failure) => {
                        self.internal(&format!("staging the organization's policy: {failure}"))
                    }
                }));
            }
        };
        for unmapped in &prepared.loaded.unmapped {
            eprintln!(
                "punard: enrollment policy: no registered capability for {}; \
                 ignored (its capability lands in a later milestone)",
                journal_detail(unmapped)
            );
        }

        // Commit point (install_enrollment): the record first, durably, then
        // policy.d swapped in whole, then the browser document.
        let enrolled_at = utc_now_rfc3339();
        let enrollment = Enrollment {
            version: 1,
            org,
            enrolled_at: enrolled_at.clone(),
            attestation,
            policy_files: set.names(),
            last_sync: LastSyncRecord::default(),
            last_inventory_hash: None,
            remote_query_scopes,
            last_query: None,
            removable,
            organization_owned,
            last_inventory_sent_at: None,
            policy_hash: Some(set.revision()),
            policy_fetched_at: Some(enrolled_at.clone()),
            policy_changed_at: Some(enrolled_at.clone()),
            policy_refresh: held_unusable.then(|| PolicyRefreshRecord {
                at: enrolled_at.clone(),
                result: RefreshResult::Held.as_str().to_string(),
                reason: Some(REASON_UNUSABLE_ASSIGNMENT.to_string()),
                offered_hash: None,
            }),
            policy_pending: None,
        };
        let installed = self
            .install_enrollment(&enrollment, &token, &prepared)
            .map_err(fail_audit)?;
        let loaded = prepared.loaded;

        let policy_ids = enrollment.policy_ids();
        let org_result = org_info(&enrollment.org);
        let attestation_label = enrollment.attestation.clone();
        registration.commit();
        *self.device_token.lock().unwrap() = Some(token);
        {
            let mut slot = self.enrollment.lock().unwrap();
            *slot = Some(enrollment);
            self.enrollment_epoch.fetch_add(1, Ordering::SeqCst);
        }
        // A new enrollment's first refresh is not held back by the last one's
        // failures.
        *self.policy_refresh_backoff.lock().unwrap() = RefreshBackoff::default();
        // What startup would load from the new policy.d: the organization's
        // set with every root drop beside it, not the set alone. When the
        // browser document could not be written, and the directory could not
        // be put back either, nothing names what was loaded, and the first
        // refresh commits the set again, document included.
        *self.org_layers.lock().unwrap() = loaded.layers;
        *self.local_admin.lock().unwrap() = loaded.local_admin;
        *self.application_policy.lock().unwrap() = loaded.applications;
        *self.org_policy_loaded.lock().unwrap() = match installed {
            Installed::Whole => Some(set.revision()),
            Installed::WithoutBrowserDocument => None,
        };
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
        let report = self.reconcile_and_remediate(
            &actor,
            &CallBudget::new(self.cfg.reconcile_control_plane_budget),
        );
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
            removable: Some(removable),
            organization_owned: Some(organization_owned),
        }))
    }

    /// Put an enrollment on disk: the token, then the record, durably, so no
    /// crash can leave the organization's files enforced on a device whose
    /// record says it is personal or owns none of them; then policy.d,
    /// swapped in whole; then the browser document. Each step undoes the ones
    /// before it, and `Err` means nothing of the enrollment is left. The one
    /// exception is a directory that could not be verifiably put back: then
    /// the organization's files may be live, so the enrollment stands, record
    /// and token included, and the caller commits it without the browser
    /// document ([`Installed::WithoutBrowserDocument`]).
    fn install_enrollment(
        &self,
        enrollment: &Enrollment,
        token: &Redacted<String>,
        prepared: &policy_set::Prepared,
    ) -> Result<Installed, IpcError> {
        let enrollment_path = self.cfg.state_dir.join("enrollment.json");
        let token_path = self.cfg.state_dir.join("device-token");
        let policy_dir = self.cfg.state_dir.join(policy_set::POLICY_DIR);
        let unwind_stores = || {
            let _ = remove_synced(&token_path);
            let _ = crate::enroll::remove_terms(&enrollment_path);
            let _ = remove_synced(&enrollment_path);
        };
        let refuse = |detail: String| {
            policy_set::discard_staging(&self.cfg.state_dir);
            self.internal(&detail)
        };
        if let Err(e) = save_device_token(&token_path, token) {
            return Err(refuse(format!("device token store: {e}")));
        }
        if let Err(e) = policy_set::step(policy_set::Step::RecordBoth)
            .and_then(|()| save_enrollment_durable(&enrollment_path, enrollment))
        {
            unwind_stores();
            return Err(refuse(format!("enrollment store: {e}")));
        }
        // A root drop added, replaced or removed since the set was staged
        // would be lost with the directory it was changed in.
        if let Err(failure) = prepared.still_current(&policy_dir, &[]) {
            unwind_stores();
            return Err(refuse(format!("policy.d swap: {failure}")));
        }
        let swapped = match policy_set::step(policy_set::Step::Swap)
            .map_err(policy_set::LocalFailure::Io)
            .and_then(|()| policy_set::swap_in(prepared.staging(), &policy_dir))
        {
            Ok(swapped) => swapped,
            Err(failure) => {
                unwind_stores();
                return Err(refuse(format!("policy.d swap: {failure}")));
            }
        };
        let previous_rendered = read_if_present(&self.cfg.browser_policy_source);
        let failed = match swapped.replaced_only_what_was_carried(prepared, &[]) {
            Err(failure) => Some(failure.to_string()),
            Ok(()) => policy_set::step(policy_set::Step::Render)
                .and_then(|()| {
                    persist_rendered_browser_policy(
                        &self.cfg.browser_policy_source,
                        &prepared.loaded.applications,
                        &prepared.loaded.browsers,
                    )
                })
                .err()
                .map(|e| format!("rendered browser policy store: {e}")),
        };
        if let Some(detail) = failed {
            return match swapped.roll_back() {
                Ok(()) => {
                    restore_rendered(&self.cfg.browser_policy_source, previous_rendered);
                    unwind_stores();
                    Err(self.internal(&detail))
                }
                Err(stuck) => {
                    // policy.d may hold the organization's files, which the
                    // durable record owns: unwinding it now would leave them
                    // enforced on a device that reads as personal after the
                    // next start. The enrollment stands; the previous
                    // directory stays where the exchange left it, for the
                    // next start or change to remove.
                    eprintln!(
                        "punard: enroll.start could not put policy.d back after {detail} \
                         ({stuck}); the enrollment stands, and its first policy refresh \
                         writes the browser document"
                    );
                    Ok(Installed::WithoutBrowserDocument)
                }
            };
        }
        if let Err(e) = swapped.finish() {
            // The previous directory is left beside policy.d, where the next
            // start removes it (policy_set::settle).
            eprintln!("punard: enroll.start could not remove the replaced policy.d: {e}");
        }
        Ok(Installed::Whole)
    }

    /// `enroll.status` (contract section 5.10): read-only, any connected
    /// peer, not audited. Never the token.
    fn handle_enroll_status(&self) -> EnrollStatusResult {
        // Cloned so the view file below is read without holding the lock a
        // sync pass needs.
        let enrollment = self.enrollment.lock().unwrap().clone();
        match &enrollment {
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
                removable: None,
                organization_owned: None,
                organization_view: None,
                policy: None,
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
                removable: Some(e.removable),
                organization_owned: Some(e.organization_owned),
                // What the organization can see, read from what actually
                // left (SPEC section 24.2), not from what the tier says
                // should have.
                organization_view: Some(organization_view_summary(
                    load_organization_view(&self.cfg.state_dir.join(ORGANIZATION_VIEW_FILE), e)
                        .as_ref(),
                )),
                // An enrollment made before these were recorded has enforced
                // the policy it enrolled with since it enrolled.
                policy: Some(EnrollPolicyStatus {
                    revision: e.policy_hash.clone(),
                    fetched_at: e
                        .policy_fetched_at
                        .clone()
                        .unwrap_or_else(|| e.enrolled_at.clone()),
                    changed_at: e
                        .policy_changed_at
                        .clone()
                        .unwrap_or_else(|| e.enrolled_at.clone()),
                    last_refresh: e.policy_refresh.as_ref().map(|r| PolicyRefresh {
                        at: r.at.clone(),
                        result: r.result.clone(),
                        reason: r.reason.clone(),
                    }),
                }),
            },
        }
    }

    /// `enroll.stop` (contract section 5.11): local restore — remove exactly
    /// the policy.d files this enrollment wrote, delete the stores,
    /// recompute, one reconcile pass (recorded user preferences resurface per
    /// SPEC section 39), rewrite the status file. The control plane is asked
    /// to forget the device best-effort; unenrollment cannot retract what it
    /// already received, and works with it down.
    ///
    /// Who may: no agent at any uid; nobody at all for an enrollment its
    /// organization made non-removable; otherwise root, or a person with a
    /// fresh confirmation (docs/development/smplify-enrollment.md section 3.1).
    fn handle_enroll_stop(
        &self,
        peer: &Peer,
        params: &EnrollStopParams,
    ) -> Result<Value, IpcError> {
        let actor = self.actor_of(peer);
        let retry = "punarctl enroll stop";
        self.refuse_agent_enrollment_change(
            peer,
            &actor,
            "enroll.stop",
            &ENROLL_STOP_WORDS,
            retry,
        )?;
        // An organization may keep its device: an enrollment it made
        // non-removable, with the enrolling person's explicit yes, cannot be
        // undone here by anyone — root included, because the term is enforced
        // by the one process that can end an enrollment, not merely implied by
        // nobody holding root (docs/development/smplify-enrollment.md section
        // 3.1). Checked here, before a password is asked for or spent: the
        // answer does not depend on who is asking, and `enroll.status` already
        // tells anyone. Checked again under the guard below, because this read
        // holds no lock against an enroll.start that commits a non-removable
        // enrollment in between.
        self.refuse_kept_enrollment(&actor)?;
        self.require_enrollment_ticket(
            peer,
            &actor,
            "enroll.stop",
            params.ticket.as_deref(),
            &ENROLL_STOP_WORDS,
            retry,
        )?;
        self.spend_enrollment_ticket(peer, &actor, "enroll.stop", params.ticket.as_deref(), retry)?;
        let _guard =
            match EnrollGuard::acquire_within(&self.enroll_in_progress, ENROLL_GUARD_PATIENCE) {
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
        // The authoritative check: under the guard no enrollment can be
        // committed or ended, so what is taken next is what was judged.
        self.refuse_kept_enrollment(&actor)?;
        let taken = {
            let mut slot = self.enrollment.lock().unwrap();
            let taken = slot.take();
            if taken.is_some() {
                self.enrollment_epoch.fetch_add(1, Ordering::SeqCst);
                // The organization view describes this enrollment only, and
                // goes with it here, under the same lock a sync pass must
                // hold to write it: a pass whose report is still in flight
                // finds the slot changed and cannot write it back. What the
                // organization received is not retracted by removing it;
                // enroll.status simply has no enrollment to describe any more.
                if let Err(e) =
                    std::fs::remove_file(self.cfg.state_dir.join(ORGANIZATION_VIEW_FILE))
                {
                    if e.kind() != io::ErrorKind::NotFound {
                        eprintln!(
                            "punard: enroll.stop could not remove {ORGANIZATION_VIEW_FILE}: {e}"
                        );
                    }
                }
            }
            taken
        };
        let Some(enrollment) = taken else {
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
        // Ask the control plane to forget the device identity — best effort:
        // unenrollment is a local restore that must succeed offline (SPEC
        // section 55), so a failure here is logged and never blocks it.
        if let Some(token) = self.device_token.lock().unwrap().as_ref() {
            let client = self.control_plane();
            if let Err(e) = client.unregister(token) {
                eprintln!(
                    "punard: enroll.stop could not release the upstream identity ({e:?}); \
                     local unenrollment continues"
                );
            }
        }
        if let Err(e) = crate::enroll::remove_terms(&self.cfg.state_dir.join("enrollment.json")) {
            eprintln!("punard: enroll.stop could not remove the enrollment terms: {e}");
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
        *self.org_policy_loaded.lock().unwrap() = None;
        self.application_policy.lock().unwrap().clear();
        // AND THE LOCAL-ADMIN VETO, which is the one that would otherwise
        // outlive the organization that set it. An org document may turn local
        // policy editing off; leaving that opinion in memory after its files
        // are gone locks an unenrolled device's owner out of their own machine,
        // citing a policy that no longer exists anywhere, until the daemon
        // happens to restart. Every layer this enrollment installed is cleared
        // in the same breath, and this one belongs in that list.
        self.local_admin.lock().unwrap().clear();
        if let Err(e) = persist_rendered_browser_policy(&self.cfg.browser_policy_source, &[], &[]) {
            eprintln!("punard: enroll.stop could not remove rendered browser policy: {e}");
        }
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
        let report = self.reconcile_and_remediate(
            &actor,
            &CallBudget::new(self.cfg.reconcile_control_plane_budget),
        );
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

    /// Keep what the organization just received as the person's view of it
    /// (SPEC section 24.2). A failure to write it is logged and costs nothing
    /// else: the send happened, and `enroll.status` then says nothing was
    /// recorded rather than something untrue.
    fn record_organization_view(&self, enrollment: &Enrollment, sent_at: &str, sent: Value) {
        let record = OrganizationViewRecord {
            version: 1,
            org_id: enrollment.org.id.clone(),
            enrolled_at: enrollment.enrolled_at.clone(),
            sent_at: sent_at.to_string(),
            sent,
        };
        if let Err(e) = save_organization_view(
            &self.cfg.state_dir.join(ORGANIZATION_VIEW_FILE),
            &record,
            lookup_gid(&self.cfg.group_file, &self.cfg.group),
        ) {
            eprintln!("punard: could not record what the organization received: {e}");
        }
    }

    /// An application list sent as `null` is a fact the device's owner can
    /// see in the audit: once when withholding starts, once when a full list
    /// goes out again — never once per pass, which would encode nothing new
    /// (the `enroll.sync` precedent).
    fn audit_applications_withheld(
        &self,
        actor: &AuditActor,
        withheld: Option<Withheld>,
        enrollment: &Enrollment,
    ) {
        let was_withheld = self
            .applications_withheld
            .swap(withheld.is_some(), Ordering::SeqCst);
        let result = match (withheld, was_withheld) {
            (Some(reason), false) => {
                eprintln!(
                    "punard: the inventory's application list is withheld ({}); \
                     it is sent as null, never truncated",
                    reason.as_str()
                );
                "applications_withheld"
            }
            (None, true) => AuditOutcome::Success.as_str(),
            _ => return,
        };
        self.log_audit(self.enroll_event(
            actor,
            "enroll.inventory",
            RESOURCE_CONTROL_PLANE,
            result,
            enrollment.policy_ids(),
        ));
    }

    /// M5 sync hook (milestone-5.md sections 6, 7): runs at the end of
    /// every full reconcile pass **when enrolled** — compliance (category
    /// states only, SPEC sections 24/54), then inventory when its SHA-256
    /// changed, a resend is pending, or a day has passed since the last one
    /// arrived. Failures queue (bounded latest-wins booleans), and an
    /// inventory that failed waits before it is sent again unless it changed
    /// ([`InventoryRetry`]); `enroll.sync` is audited on **transitions
    /// only**.
    fn sync_if_enrolled(&self, actor: &AuditActor, budget: &CallBudget) {
        let (enrollment, epoch) = {
            let slot = self.enrollment.lock().unwrap();
            (slot.clone(), self.enrollment_epoch.load(Ordering::SeqCst))
        };
        let Some(enrollment) = enrollment else {
            // Only while the device is still personal, and under the lock
            // enroll.start commits under: one committed since this pass
            // looked has its own first sync coming, whose outcome this must
            // not erase.
            let slot = self.enrollment.lock().unwrap();
            if slot.is_none() {
                *self.last_sync_outcome.lock().unwrap() = None;
                self.applications_withheld.store(false, Ordering::SeqCst);
            }
            return;
        };
        let token = self.device_token.lock().unwrap().clone();
        let client = self.control_plane().within(budget.clone());
        // Whether the last pass got nothing through: then a report that
        // gets through now means the link is back.
        let link_was_down = self.pending_compliance.load(Ordering::SeqCst);

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
        // The link is back. The waits an inventory built up while nothing
        // got through say nothing about the inventory, and would hold a
        // changed one back for up to half an hour after the device is
        // online again.
        if compliance_ok && link_was_down {
            *self.inventory_retry.lock().unwrap() = None;
        }

        // Inventory: device facts, which capabilities are supported, posture
        // states, and the tier's applications. Sent when its hash changed,
        // when a resend is pending, or when a day has passed without one.
        let sources = InventorySources {
            os_release_path: self.cfg.os_release_path.clone(),
            kernel_release_path: self.cfg.kernel_release_path.clone(),
        };
        let descriptors: Vec<_> = self.registry.iter().map(|cap| self.describe(cap)).collect();
        // The firewall's posture is the observation this pass already made,
        // not a second nft run. It reaches the body only as a posture state:
        // no capability's observed value is in the body (see inventory_body).
        let firewall_state = descriptors
            .iter()
            .find(|d| d.capability.as_str() == crate::backends::firewall::CAPABILITY_ID)
            .map(|d| d.current_state.clone());
        let capabilities = descriptors
            .iter()
            .map(|d| (d.capability.as_str().to_string(), d.supported));
        let collected = self.inventory.collect(
            &PassInputs {
                organization_owned: enrollment.organization_owned,
                architecture: self.apps.architecture().to_string(),
                firewall_state,
                patch: patch_posture(self.update_status.staged_release()),
            },
            || ImageRelease {
                version: sources.image_version(),
                browser_version: self.update_status.browser_version(),
            },
            || self.apps.installed_vendor_apps(),
        );
        let (inventory, withheld) = inventory_body(
            &sources,
            capabilities,
            &collected,
            enrollment.organization_owned,
        );
        // The gate hashes exactly the body the control plane is handed,
        // which carries nothing that may not leave the device: a value that
        // is never sent must never be able to trigger a send.
        let hash = sha256_hex(&serde_json::to_vec(&inventory).expect("inventory serializes"));
        let now = utc_now_rfc3339();
        let due = enrollment.last_inventory_hash.as_deref() != Some(hash.as_str())
            || self.pending_inventory.load(Ordering::SeqCst)
            || inventory_resend_due(enrollment.last_inventory_sent_at.as_deref(), &now);
        // An inventory that failed to go out waits before the same body goes
        // again (InventoryRetry), and stays pending while it waits, rather
        // than going up on every pass.
        let attempted_at = Instant::now();
        let deferred = due
            && self
                .inventory_retry
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|retry| retry.defers(epoch, &hash, attempted_at));
        let mut delivered = None;
        let mut failed_hash = None;
        let inventory_outcome = if deferred {
            "unreachable"
        } else if !due {
            "unchanged"
        } else {
            let answer = match &token {
                Some(token) => client.inventory_report(token, &inventory).ok(),
                None => None,
            };
            match answer {
                Some(sent) => {
                    // The agent's account of what it posted, or, from a
                    // control plane that gives none (the development mock,
                    // which keeps the inventory itself), what it was handed.
                    // Recorded below, only if this enrollment is still the
                    // one in the slot.
                    delivered = Some((hash, now, sent.unwrap_or(inventory)));
                    "success"
                }
                None => {
                    failed_hash = Some(hash);
                    "unreachable"
                }
            }
        };

        // M10: the query pull, on the same hook and the same cadence. It is
        // deliberately last: compliance and inventory are this device's
        // obligations, and answering questions is a courtesy that must not
        // delay them.
        let last_query = match &token {
            Some(token) => self.drain_pending_queries(&client, token),
            None => None,
        };

        // Everything this pass learned is written back only while the
        // enrollment it began with is still the one in the slot: the pending
        // flags, the outcome `enroll.start` reports, the transitions it
        // audits, last_sync, the inventory hash, and what the organization
        // received as the person's view of it. A pass can outlive its
        // enrollment (a report may still be in flight while enroll.stop runs,
        // and enroll.start after it), and then it writes nothing: not into the
        // ended enrollment, whose view enroll.stop removed under this lock,
        // and not over the state of one started since, whose own passes keep
        // it. Its failure, against a token that no longer exists, would
        // otherwise show the new enrollment as pending, audit a sync failure
        // that was not its own, and send its unchanged inventory again.
        let mut slot = self.enrollment.lock().unwrap();
        let still_current = self.enrollment_epoch.load(Ordering::SeqCst) == epoch;
        let Some(current) = slot.as_mut().filter(|_| still_current) else {
            return;
        };
        self.pending_compliance
            .store(!compliance_ok, Ordering::SeqCst);
        self.pending_inventory
            .store(inventory_outcome == "unreachable", Ordering::SeqCst);
        {
            let mut retry = self.inventory_retry.lock().unwrap();
            // A failure counts toward the inventory's wait only when the
            // compliance report of the same pass got through: a link that
            // carries a report but not the inventory. When nothing got
            // through, the device is offline, and the failure says nothing
            // about the inventory.
            if let Some(hash) = failed_hash.filter(|_| compliance_ok) {
                let next = InventoryRetry::after_failure(
                    retry.as_ref(),
                    epoch,
                    &hash,
                    attempted_at,
                    self.cfg.inventory_retry_base,
                );
                eprintln!(
                    "punard: the inventory did not reach the control plane; it is sent again \
                     in {} s, or at once if it changes",
                    next.wait_from(attempted_at).as_secs()
                );
                *retry = Some(next);
            } else if inventory_outcome == "success" {
                *retry = None;
            }
        }
        *self.last_sync_outcome.lock().unwrap() = Some(FirstSync {
            compliance: if compliance_ok {
                "success".to_string()
            } else {
                "unreachable".to_string()
            },
            inventory: inventory_outcome.to_string(),
        });
        self.audit_applications_withheld(actor, withheld, current);

        // Transition-only audit (milestone-5.md section 7): once on
        // reachable→unreachable, once on recovery — never one event per
        // 120 s retry.
        let overall = if compliance_ok && inventory_outcome != "unreachable" {
            "success"
        } else {
            "unreachable"
        };
        let previous = current.last_sync.result.clone();
        if overall == "unreachable" && previous.as_deref() != Some("unreachable") {
            self.log_audit(self.enroll_event(
                actor,
                "enroll.sync",
                RESOURCE_CONTROL_PLANE,
                "unreachable",
                current.policy_ids(),
            ));
        }
        if overall == "success" && previous.as_deref() == Some("unreachable") {
            self.log_audit(self.enroll_event(
                actor,
                "enroll.sync",
                RESOURCE_CONTROL_PLANE,
                AuditOutcome::Success.as_str(),
                current.policy_ids(),
            ));
        }

        // Only a send this pass made moves the hash and the send time: two
        // passes of this one enrollment can overlap, and one that sent
        // nothing, or failed, must not put back the values it read at its
        // start over what the other recorded meanwhile.
        if let Some((hash, at, received)) = delivered {
            self.record_organization_view(current, &at, received);
            current.last_inventory_hash = Some(hash);
            current.last_inventory_sent_at = Some(at);
        }
        current.last_sync = LastSyncRecord {
            at: Some(utc_now_rfc3339()),
            result: Some(overall.to_string()),
        };
        if last_query.is_some() {
            current.last_query = last_query;
        }
        if let Err(e) = save_enrollment(&self.cfg.state_dir.join("enrollment.json"), current) {
            eprintln!("punard: could not persist enrollment sync state: {e}");
        }
    }

    /// A control-plane client whose calls wait behind every other call this
    /// daemon has in flight ([`AgentQueue`]).
    fn control_plane(&self) -> ControlPlaneClient {
        ControlPlaneClient::new(&self.cfg.control_plane_socket)
            .behind(Arc::clone(&self.control_plane_queue))
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
            Err(UpstreamError::TooLarge) => {
                eprintln!(
                    "punard: queries.pending answered with more than this device reads; \
                     nothing is answered this pass"
                );
                return None;
            }
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
                    UpstreamError::TooLarge => "its answer was too large".to_string(),
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
            architecture: self.apps.architecture().to_string(),
            ts: utc_now_rfc3339(),
        };
        let mut written = self.status_written.lock().unwrap();
        let unchanged = written.as_ref().is_some_and(|w| {
            w.enrolled == summary.enrolled
                && w.org_name == summary.org_name
                && w.compliance_overall == summary.compliance_overall
                && w.device_class == summary.device_class
                && w.device_class_source == summary.device_class_source
                && w.architecture == summary.architecture
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

/// `enroll.start`'s refusal of a policy set the organization served. The
/// two cases enrollment always refused keep their words; the rules the live
/// refresh brought (docs/api/ipc.md section 5.9) say which one failed.
fn enroll_policy_refusal(rejection: &Rejection) -> IpcError {
    match rejection {
        Rejection::UnusablePolicyId => IpcError::with_details(
            ErrorCode::InvalidParams,
            "The control plane served a policy envelope without a usable \
             policy_id.\n\
             Policy: os default — enrollment writes only validated envelopes \
             (docs/api/ipc.md section 5.9).\n\
             Next step: report this to your administrator; nothing was changed."
                .to_string(),
            json!({ "param": "policy", "reason": "envelope without policy_id" }),
        ),
        Rejection::InvalidEnvelope(e) => IpcError::with_details(
            ErrorCode::InvalidParams,
            format!(
                "A fetched policy envelope failed validation: {e}.\n\
                 Policy: os default — enrollment is all-or-nothing; nothing was \
                 written (docs/api/ipc.md section 5.9).\n\
                 Next step: report this to your administrator."
            ),
            json!({ "param": "policy", "reason": "envelope failed the loader's validation" }),
        ),
        Rejection::BrowserPolicyRefused(e) => IpcError::with_details(
            ErrorCode::InvalidParams,
            format!(
                "The fetched browser policy could not be rendered safely: {e}.\n\
                 Policy: browser/integration/policy-allowlist.json — enrollment is all-or-nothing.\n\
                 Next step: correct the browser policy in Smplify; nothing was changed."
            ),
            json!({ "param": "policy.spec.browser", "reason": "browser policy refused" }),
        ),
        // The one refusal a person on the device can resolve: the file may
        // be left from an earlier enrollment. It is theirs to remove; punard
        // never takes over a file it did not write.
        Rejection::ForeignFileCollision(name) => IpcError::with_details(
            ErrorCode::InvalidParams,
            format!(
                "The organization's policy set uses the name of a file already in \
                 policy.d that this device did not receive from it: {name}.\n\
                 Policy: os default — enrollment never overwrites a file an \
                 administrator put in /var/lib/punar/policy.d (docs/api/ipc.md section \
                 5.9); nothing was written.\n\
                 Next step: if /var/lib/punar/policy.d/{name} is left from an earlier \
                 enrollment, remove it and enroll again; otherwise ask your \
                 administrator to rename the policy."
            ),
            json!({ "param": "policy", "reason": rejection.reason() }),
        ),
        other => IpcError::with_details(
            ErrorCode::InvalidParams,
            format!(
                "The control plane served a policy set this device refuses: {}.\n\
                 Policy: os default — enrollment writes only a set that passes every \
                 policy check, and nothing was written (docs/api/ipc.md section 5.9).\n\
                 Next step: report this to your administrator.",
                other.describe()
            ),
            json!({ "param": "policy", "reason": other.reason() }),
        ),
    }
}

/// An enrollment audit event ([`Inner::enroll_event`]), for a caller that has
/// no daemon yet: startup, recording a policy change that landed before a
/// crash.
fn enrollment_event(
    device_id: &str,
    actor: &AuditActor,
    action: &str,
    resource: &str,
    result: &str,
    policy_ids: Vec<String>,
) -> AuditEvent {
    AuditEvent {
        event_id: next_event_id(),
        timestamp: utc_now_rfc3339(),
        device_id: device_id.to_string(),
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

/// Whether the audit log holds an event with this id. Read line by line,
/// and only at a start that found a policy change landed.
fn audit_log_holds(path: &Path, event_id: &str) -> bool {
    use std::io::BufRead;
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .any(|line| {
            serde_json::from_str::<Value>(&line)
                .is_ok_and(|event| event.get("event_id").and_then(Value::as_str) == Some(event_id))
        })
}

/// How far [`Inner::install_enrollment`] got.
enum Installed {
    Whole,
    /// Everything but the browser document, which could not be written, and
    /// the directory could not be verifiably put back.
    WithoutBrowserDocument,
}

/// The longest control-plane or loader text the journal repeats.
const JOURNAL_DETAIL_CHARS: usize = 512;

/// Text the device did not write, fit for one journal line: cut to
/// [`JOURNAL_DETAIL_CHARS`] and escaped, so it cannot forge a line of its own.
/// For every line that repeats what an organization's policy or control plane
/// chose, at startup as on a refresh.
fn journal_detail(text: &str) -> String {
    let cut: String = text.chars().take(JOURNAL_DETAIL_CHARS).collect();
    format!("{cut:?}")
}

/// A file's bytes, or `None` when it is absent or unreadable: what to put
/// back if a change after this point has to be undone.
fn read_if_present(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

/// Put the rendered browser document back as it was before a policy change
/// that is being undone: the same bytes, or no file.
fn restore_rendered(path: &Path, previous: Option<Vec<u8>>) {
    let restored = match previous {
        Some(bytes) => write_atomic_synced(path, &bytes, 0o600),
        None => remove_synced(path),
    };
    if let Err(e) = restored {
        eprintln!(
            "punard: could not restore the rendered browser policy ({e}); the next start \
             renders it again from policy.d"
        );
    }
}

/// The capability paths whose effective value or classification differs
/// between two documents, including a path only one of them has. Provenance
/// alone moving (the same value, now from another layer) is not a change a
/// capability could act on.
fn changed_effective_paths(old: &EffectiveDocument, new: &EffectiveDocument) -> Vec<String> {
    let differs = |a: &EffectiveEntry<Value>, b: &EffectiveEntry<Value>| {
        a.value != b.value || a.classification != b.classification
    };
    let mut changed: BTreeSet<String> = BTreeSet::new();
    for (path, entry) in &new.entries {
        if old
            .entries
            .get(path)
            .is_none_or(|before| differs(before, entry))
        {
            changed.insert(path.clone());
        }
    }
    for path in old.entries.keys() {
        if !new.entries.contains_key(path) {
            changed.insert(path.clone());
        }
    }
    changed.into_iter().collect()
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
    /// Suppression lifts when the value a capability is asked to reach
    /// changes, or how it is classified; the same value from another source
    /// is not a change.
    #[test]
    fn a_changed_effective_value_or_classification_is_a_change() {
        use punar_policy::SourceKind;
        let entry = |value: &str, classification: Classification, policy_id: &str| EffectiveEntry {
            value: json!(value),
            provenance: Provenance {
                kind: SourceKind::OrganizationBaseline,
                rank: 2,
                policy_id: policy_id.to_string(),
                source_name: policy_id.to_string(),
            },
            classification,
            user_override_permitted: false,
        };
        let doc = |entries: Vec<(&str, EffectiveEntry<Value>)>| EffectiveDocument {
            computed_at: "2026-09-24T00:00:00Z".to_string(),
            entries: entries
                .into_iter()
                .map(|(path, entry)| (path.to_string(), entry))
                .collect(),
        };
        let old = doc(vec![
            ("a", entry("x", Classification::AutoRemediate, "p1")),
            ("b", entry("x", Classification::AutoRemediate, "p1")),
            ("c", entry("x", Classification::AutoRemediate, "p1")),
            ("gone", entry("x", Classification::AutoRemediate, "p1")),
        ]);
        let new = doc(vec![
            ("a", entry("x", Classification::AutoRemediate, "p2")),
            ("b", entry("y", Classification::AutoRemediate, "p1")),
            ("c", entry("x", Classification::AlertOnly, "p1")),
            ("new", entry("x", Classification::AutoRemediate, "p1")),
        ]);
        assert_eq!(
            changed_effective_paths(&old, &new),
            ["b", "c", "gone", "new"]
        );
        assert!(changed_effective_paths(&old, &old).is_empty());
    }

    /// enroll.start and enroll.stop wait a moment for a refresh that is
    /// committing, rather than answer "conflict", and no longer.
    #[test]
    fn the_enrollment_guard_waits_briefly_for_a_commit_in_progress() {
        let flag = AtomicBool::new(false);
        let held = EnrollGuard::acquire(&flag).unwrap();
        let started = Instant::now();
        assert!(EnrollGuard::acquire_within(&flag, Duration::from_millis(60)).is_none());
        assert!(started.elapsed() >= Duration::from_millis(60));
        let waited = std::thread::scope(|scope| {
            scope.spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                drop(held);
            });
            EnrollGuard::acquire_within(&flag, Duration::from_secs(2))
        });
        assert!(waited.is_some(), "released within its patience");
        assert!(flag.load(Ordering::SeqCst), "held by the waiter");
        drop(waited);
        assert!(!flag.load(Ordering::SeqCst));
    }

    /// The refusal that asks for the organization's terms states every one of
    /// them in words the organization cannot tamper with: its display name is
    /// its own choice, and an escape sequence in it must not be able to
    /// conceal the term after it on the person's terminal.
    #[test]
    fn a_terms_refusal_cannot_be_rewritten_by_the_organizations_name() {
        use punar_common::ipc::EnrollmentTerm;

        let org = crate::enroll::OrgRecord {
            id: "acme".into(),
            name: "Acme".into(),
            display_name: "Acme\u{1b}[8m\u{202e}".into(),
            domain: "acme.com".into(),
        };
        let error = super::unaccepted_terms_refusal(&org, "acme.com", &EnrollmentTerm::ALL);
        assert!(
            !error.message.contains('\u{1b}') && !error.message.contains('\u{202e}'),
            "{:?}",
            error.message
        );
        assert!(error.message.contains("serial number"), "{}", error.message);
        assert!(
            error.message.contains("you included, can unenroll it"),
            "{}",
            error.message
        );
    }

    /// `device_specific_override` is not exclusively the local administrator's
    /// kind — its rank is stored data, so an organization may publish one. At
    /// rank 1-3 that layer outranks this device exactly as a baseline does, and
    /// matching on the kind alone would hand an organization's own pinned value
    /// to the local administrator to edit because of the word it was labelled
    /// with.
    #[test]
    fn admin_may_override_is_decided_by_rank_and_not_by_a_label() {
        use punar_policy::{Classification, EffectiveEntry, Provenance, SourceKind};
        use serde_json::json;

        let entry = |kind: SourceKind, rank: u32| EffectiveEntry {
            value: json!("x"),
            provenance: Provenance {
                kind,
                rank,
                policy_id: "p".to_string(),
                source_name: "s".to_string(),
            },
            classification: Classification::AutoRemediate,
            user_override_permitted: rank >= 5,
        };

        // Below the administrator's rung: theirs to move.
        assert!(super::admin_may_override(&entry(
            SourceKind::LocalUserPreference,
            5
        )));
        assert!(super::admin_may_override(&entry(
            SourceKind::OsSecureDefault,
            6
        )));
        // Their own entry, at their own rank.
        assert!(super::admin_may_override(&entry(
            SourceKind::DeviceSpecificOverride,
            super::DEVICE_ADMIN_RANK
        )));

        // Above it: not theirs, whatever the kind is called.
        for rank in 1..super::DEVICE_ADMIN_RANK {
            assert!(
                !super::admin_may_override(&entry(SourceKind::DeviceSpecificOverride, rank)),
                "an organization-published device_specific_override at rank {rank} \
                 must not be treated as the local administrator's own pin"
            );
        }
        assert!(!super::admin_may_override(&entry(
            SourceKind::OrganizationBaseline,
            2
        )));
        assert!(!super::admin_may_override(&entry(
            SourceKind::OrganizationRolePolicy,
            3
        )));
        // A rank-4 approved exception wins the tie by push order, so it is not
        // the administrator's to displace either.
        assert!(!super::admin_may_override(&entry(
            SourceKind::TemporaryApprovedException,
            4
        )));
    }

    use super::*;
    use std::fs::{self, OpenOptions};

    use punar_common::audit::AUDIT_ROTATE_BYTES;

    /// enroll.start is all-or-nothing up to the swap, and after it too while
    /// the directory can be put back: a browser document that cannot be
    /// written leaves no record, token or file of the enrollment. When the
    /// directory cannot be verifiably put back, the organization's files may
    /// be live, and then the enrollment stands whole (record, token and
    /// files together): never its files on a device that reads as personal
    /// after the next start.
    #[test]
    fn an_enrollment_whose_directory_cannot_be_put_back_stands_whole() {
        use crate::policy_set::{Step, faults};
        const ACME_ENVELOPE: &str = include_str!(
            "../../../fixtures/organizations/acme/policy-source-eng-baseline-v12.json"
        );
        let root = std::env::temp_dir().join(format!(
            "punard-install-enrollment-{}-{}",
            std::process::id(),
            next_event_id()
        ));
        let state = root.join("state");
        fs::create_dir_all(state.join("policy.d")).unwrap();
        fs::write(state.join("policy.d/local.note"), b"root's own").unwrap();
        let config = DaemonConfig::new(
            root.join("punard.sock"),
            state.clone(),
            root.join("audit.jsonl"),
        );
        let daemon = Daemon::new(config, Registry::new(Vec::new())).unwrap();
        let envelope: Value = serde_json::from_str(ACME_ENVELOPE).unwrap();
        let set =
            CanonicalSet::from_envelopes(&[envelope], crate::enroll::Assignment::Policies).unwrap();
        let enrollment: Enrollment = serde_json::from_value(json!({
            "version": 1,
            "org": {"id": "acme", "name": "Acme", "display_name": "Acme", "domain": "acme.com"},
            "enrolled_at": "2026-09-24T00:00:00Z",
            "attestation": "simulated",
            "policy_files": set.names(),
            "last_sync": {"at": null, "result": null},
            "last_inventory_hash": null,
            "policy_hash": set.revision(),
        }))
        .unwrap();
        let token = Redacted::new("tok_install".to_string());
        let org_file = state.join("policy.d/eng-baseline-v12.json");

        let prepared = policy_set::prepare(&state, &set, &[]).unwrap();
        {
            let _hook = faults::install(|step| match step {
                Step::Render => Err(io::Error::other("no space left on device")),
                _ => Ok(()),
            });
            assert!(
                daemon
                    .inner
                    .install_enrollment(&enrollment, &token, &prepared)
                    .is_err()
            );
        }
        assert!(!state.join("enrollment.json").exists());
        assert!(!state.join("device-token").exists());
        assert!(!org_file.exists());
        assert!(!state.join(policy_set::STAGING_DIR).exists());
        assert_eq!(
            fs::read(state.join("policy.d/local.note")).unwrap(),
            b"root's own"
        );

        let prepared = policy_set::prepare(&state, &set, &[]).unwrap();
        let installed = {
            let _hook = faults::install(|step| match step {
                Step::Render | Step::RollBack => Err(io::Error::other("no space left on device")),
                _ => Ok(()),
            });
            daemon
                .inner
                .install_enrollment(&enrollment, &token, &prepared)
        };
        assert!(matches!(installed, Ok(Installed::WithoutBrowserDocument)));
        assert!(org_file.exists(), "the organization's files are live");
        let saved = load_enrollment(&state.join("enrollment.json"))
            .unwrap()
            .unwrap();
        assert_eq!(saved.policy_files, ["eng-baseline-v12.json"], "and owned");
        assert!(state.join("device-token").exists());
        assert_eq!(
            fs::read(state.join("policy.d/local.note")).unwrap(),
            b"root's own"
        );
        let _ = fs::remove_dir_all(&root);
    }

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

    #[cfg(target_os = "linux")]
    #[test]
    fn pi_reconcile_is_authorized_health_gated_and_audit_durable() {
        use crate::install::ROOT_B_PARTUUID;
        use crate::pi_update::{PendingPiUpdate, PiSlot};

        let root = std::env::temp_dir().join(format!(
            "punard-pi-reconcile-{}-{}",
            std::process::id(),
            next_event_id()
        ));
        let state = root.join("state");
        let selector = root.join("selector");
        let boot_b = root.join("boot-b");
        let root_b_mount = root.join("root-b-mount");
        fs::create_dir_all(state.join("update")).unwrap();
        fs::create_dir_all(&selector).unwrap();
        fs::create_dir_all(&boot_b).unwrap();
        fs::create_dir_all(root_b_mount.join("etc")).unwrap();
        fs::write(
            selector.join("autoboot.txt"),
            b"[all]\ntryboot_a_b=1\nboot_partition=2\n[tryboot]\nboot_partition=4\n",
        )
        .unwrap();
        fs::write(
            boot_b.join("cmdline-a.txt"),
            format!(
                "root=PARTUUID={} rootfstype=ext4 ro rootwait\n",
                crate::install::ROOT_A_PARTUUID
            ),
        )
        .unwrap();
        fs::write(
            boot_b.join("cmdline-b.txt"),
            format!("root=PARTUUID={ROOT_B_PARTUUID} rootfstype=ext4 ro rootwait\n"),
        )
        .unwrap();
        fs::write(
            boot_b.join("config.txt"),
            "[all]\narm_64bit=1\nkernel=kernel8.img\ninitramfs initramfs8 followkernel\n[boot_partition=2]\ncmdline=cmdline-a.txt\n[boot_partition=4]\ncmdline=cmdline-b.txt\n",
        )
        .unwrap();
        fs::write(boot_b.join("kernel8.img"), b"test kernel").unwrap();
        fs::write(boot_b.join("initramfs8"), b"test initramfs").unwrap();
        fs::write(
            root_b_mount.join("etc/os-release"),
            "ID=punar\nIMAGE_VERSION=2026.09.04.1\n",
        )
        .unwrap();

        let root_bytes = vec![0x51_u8; 4096];
        let boot_bytes = vec![0x52_u8; 4096];
        let root_b_device = root.join("root-b-device");
        let boot_b_device = root.join("boot-b-device");
        fs::write(&root_b_device, &root_bytes).unwrap();
        fs::write(&boot_b_device, &boot_bytes).unwrap();

        let partition = root.join("partition");
        let tryboot = root.join("tryboot");
        let cmdline = root.join("cmdline");
        let mountinfo = root.join("mountinfo");
        let health = root.join("health.json");
        let pending = state.join("update/pending-pi.json");
        fs::write(&partition, 4_u32.to_be_bytes()).unwrap();
        fs::write(&tryboot, 1_u32.to_be_bytes()).unwrap();
        fs::write(
            &cmdline,
            format!("root=PARTUUID={ROOT_B_PARTUUID} rootfstype=ext4 ro rootwait\n"),
        )
        .unwrap();
        fs::write(
            &mountinfo,
            "29 23 0:25 / / ro,relatime - ext4 /dev/mmcblk0p5 ro\n",
        )
        .unwrap();
        fs::write(
            &pending,
            serde_json::to_vec(&PendingPiUpdate {
                schema_version: 1,
                release_id: "punar-test-pi-release".into(),
                version: "2026.09.04.1".parse().unwrap(),
                previous_slot: PiSlot::A,
                candidate_slot: PiSlot::B,
                candidate_boot_partition: 4,
                candidate_root_partition: 5,
                candidate_root_partuuid: ROOT_B_PARTUUID.into(),
                manifest_sha256: "a".repeat(64),
                payload_sha256: sha256_hex(&root_bytes),
                payload_size_bytes: root_bytes.len() as u64,
                boot_sha256: sha256_hex(&boot_bytes),
                boot_size_bytes: boot_bytes.len() as u64,
                staged_at: utc_now_rfc3339(),
            })
            .unwrap(),
        )
        .unwrap();
        let pending_bytes = fs::read(&pending).unwrap();
        fs::write(
            &health,
            br#"{"schema_version":1,"health":{"boot_completed":true,"control_plane_answers":true,"desktop_ready":false,"capabilities_verified":true},"waited_seconds":7}"#,
        )
        .unwrap();

        let audit_path = root.join("audit.jsonl");
        let mut config = DaemonConfig::new(root.join("punard.sock"), state, audit_path.clone());
        let proc_root = root.join("proc");
        fs::create_dir_all(proc_root.join("4242")).unwrap();
        fs::write(
            proc_root.join("4242/cgroup"),
            "0::/user.slice/punar-agent-agt_0011aabb2233.scope\n",
        )
        .unwrap();
        config.proc_root = proc_root;
        config.pi_update_sources = PiUpdateSources {
            boot_partition_property: partition.clone(),
            tryboot_property: tryboot.clone(),
            cmdline_path: cmdline,
            mountinfo_path: mountinfo,
            health_report: health.clone(),
            pending_state: pending.clone(),
            root_b_partition: root_b_device,
            boot_b_partition: boot_b_device,
            allow_regular_targets: true,
            selector_mount_override: Some(selector.clone()),
            boot_b_mount_override: Some(boot_b),
            root_b_mount_override: Some(root_b_mount),
            reboot_parameter: root.join("reboot-param"),
            staged_marker: root.join("pi-update-staged"),
            ..PiUpdateSources::default()
        };
        let daemon = Daemon::new(config, Registry::new(Vec::new())).unwrap();
        let selector_before = fs::read(selector.join("autoboot.txt")).unwrap();

        let nonroot = Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        };
        let refused = daemon
            .inner
            .handle_update_reconcile_candidate(&nonroot)
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::Denied);
        let agent = Peer {
            uid: 0,
            gid: 0,
            pid: Some(4242),
        };
        let refused = daemon
            .inner
            .handle_update_reconcile_candidate(&agent)
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::Denied);

        fs::write(&partition, 2_u32.to_be_bytes()).unwrap();
        fs::write(&tryboot, 0_u32.to_be_bytes()).unwrap();
        let fallback = daemon
            .inner
            .handle_update_reconcile_candidate(&Peer::root())
            .unwrap();
        assert_eq!(fallback["outcome"], "firmware_fallback");
        assert_eq!(fallback["selector_committed"], false);
        assert_eq!(fallback["requires_normal_reboot"], false);
        assert!(!pending.exists());
        assert_eq!(
            fs::read(selector.join("autoboot.txt")).unwrap(),
            selector_before
        );
        assert!(
            tail(&audit_path, 20)
                .unwrap()
                .events
                .into_iter()
                .any(|event| {
                    event.action == "update.reconcile_candidate.firmware_fallback"
                        && event.result == "success"
                })
        );

        fs::write(&pending, &pending_bytes).unwrap();
        fs::write(&partition, 4_u32.to_be_bytes()).unwrap();
        fs::write(&tryboot, 1_u32.to_be_bytes()).unwrap();

        let refused = daemon
            .inner
            .handle_update_reconcile_candidate(&Peer::root())
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::Conflict);
        assert!(pending.exists());
        assert_eq!(
            fs::read(selector.join("autoboot.txt")).unwrap(),
            selector_before
        );

        fs::write(
            &health,
            br#"{"schema_version":1,"health":{"boot_completed":true,"control_plane_answers":true,"desktop_ready":true,"capabilities_verified":true},"waited_seconds":8}"#,
        )
        .unwrap();

        // Force the required success append to fail only after the engine has
        // replaced and re-read the selector. The pending state must survive.
        OpenOptions::new()
            .write(true)
            .open(&audit_path)
            .unwrap()
            .set_len(AUDIT_ROTATE_BYTES)
            .unwrap();
        fs::remove_file(&audit_path).unwrap();
        fs::create_dir(&audit_path).unwrap();
        let audit_failure = daemon
            .inner
            .handle_update_reconcile_candidate(&Peer::root())
            .unwrap_err();
        assert_eq!(audit_failure.code, ErrorCode::Internal);
        assert_eq!(
            audit_failure.details,
            Some(json!({
                "component": "pi_reconcile_audit",
                "pending_retained": true,
            }))
        );
        assert!(pending.exists(), "audit failure must retain pending state");
        assert_eq!(
            fs::read(selector.join("autoboot.txt")).unwrap(),
            b"[all]\ntryboot_a_b=1\nboot_partition=4\n[tryboot]\nboot_partition=2\n"
        );

        // Restore the live audit path. The retry recognizes the already
        // committed selector, revalidates candidate bytes/version/health,
        // durably records post-commit recovery, then removes exact pending.
        fs::remove_dir(&audit_path).unwrap();
        fs::write(&audit_path, b"").unwrap();
        let recovered = daemon
            .inner
            .handle_update_reconcile_candidate(&Peer::root())
            .unwrap();
        assert_eq!(recovered["outcome"], "postcommit_recovery");
        assert_eq!(recovered["candidate_slot"], "b");
        assert_eq!(recovered["selector_committed"], true);
        assert_eq!(recovered["requires_normal_reboot"], true);
        assert!(!pending.exists());

        let events = tail(&audit_path, 20)
            .unwrap()
            .events
            .into_iter()
            .filter(|event| event.action == "update.reconcile_candidate.postcommit_recovery")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].result, "success");
        assert!(events[0].resource.as_deref().is_some_and(|resource| {
            resource.contains("punar-test-pi-release:2026.09.04.1:")
                && resource.ends_with(&"a".repeat(64))
        }));

        drop(daemon);
        fs::remove_dir_all(root).unwrap();
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
