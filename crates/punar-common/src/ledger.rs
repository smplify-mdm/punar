//! The AI Access Ledger types (SPEC sections 21, 24; Milestone 8).
//!
//! Binding contracts: `schemas/ai-agent/ledger-summary.json` (the shipped
//! document schema — **not modified by M8**), `docs/api/ipc.md` sections
//! 12–13 (the `agents.access` / `ledger.purge` wire contract and the
//! ledger's side contract), and `docs/development/milestone-8.md`.
//!
//! # Two layers, and why
//!
//! The shipped summary schema encodes SPEC 21.2 *structurally*: resource
//! arrays are de-duplicated sets of identifiers, not per-access entries;
//! `directory_zones` rejects `/`; `network_destinations` rejects `:` and
//! `/`; credentials appear as classes only; and there is no field anywhere
//! for prompt text, file contents, source code, or a secret. It therefore
//! has nowhere to put a count or a first/last-seen pair — which Plate
//! D-005 renders (`git × 12`) and an incident review needs.
//!
//! So there are two layers:
//!
//! 1. [`LedgerRecord`] — the internal, on-disk aggregate:
//!    `entries[] = {category, resource_class, count, first_seen,
//!    last_seen, evidence}`.
//! 2. [`LedgerSummary`] — a **total projection** of that record onto the
//!    shipped schema ([`LedgerRecord::summary`]): group entries by
//!    category, emit the distinct `resource_class` values into the six
//!    required arrays, carry the event references verbatim.
//!
//! Because [`ResourceCategory`] is a closed enum of exactly the six
//! schema keys, the projection is *total* — every entry lands in a real
//! array, and conformance is guaranteed by construction rather than by
//! review. Counts and the rest travel as **sibling fields** of the IPC
//! result ([`AgentsAccessResult::detail`]), which is an additive contract
//! change; a new schema field would not be.
//!
//! # Privacy in types, not in documentation (SPEC 21.2)
//!
//! [`ResourceClass`] is a newtype with **no** `From<String>` and no public
//! field. Every constructor — including the `Deserialize` impl, so a
//! hand-edited file cannot smuggle one in — rejects any value containing
//! `/`, `:`, whitespace, a leading `.`, a non-ASCII or non-graphic byte,
//! or more than [`MAX_RESOURCE_CLASS_BYTES`] bytes. A filesystem path, a
//! URL, a command line, or a prompt is therefore **unrepresentable** as a
//! ledger resource, at the type level, for every category.
//!
//! There is no field in any type here for a pid, a `comm`, an argv, a
//! cwd, an environment variable, a prompt, file contents, or a secret.
//! Level 4 events are stored as *references* ([`SecurityEventRef`]) —
//! `{event_id, event_type, timestamp}` — because the payload belongs to
//! the audit trail (SPEC 53), which is the single source of truth and,
//! deliberately, is not purgeable.

use serde::{Deserialize, Serialize};

use crate::agent::{AgentClassification, AgentStatus};

// ---------------------------------------------------------------------------
// Contract paths and constants (docs/api/ipc.md sections 12–13)
// ---------------------------------------------------------------------------

/// Ledger storage directory, `0700 root:root` (tmpfiles).
pub const LEDGER_DIR: &str = "/var/lib/punar/agents/ledger";

/// Rollup + audit-tail position, `0640 root:root`, inside [`LEDGER_DIR`].
pub const LEDGER_INDEX_FILE: &str = "index.json";

/// The AI panel's read-only view (docs/api/ipc.md section 13.2).
///
/// Deliberately **not** in the world-readable `/run/punar` beside
/// `status.json`/`agents.json`: a ledger is personal data, so it lives in
/// the root-owned agentd runtime directory as `0640 root:punar` — only
/// the socket's own admission set may read it, and a local user cannot
/// unlink it to substitute a forgery.
pub const LEDGER_RUNTIME_PATH: &str = "/run/punar-agentd/ledger.json";

/// `comm` → process-class table (data, not code — the M7
/// adapters-as-data precedent). Missing or unparsable falls back to the
/// built-in table compiled into `punar-agentd`.
pub const PROCESS_CLASSES_PATH: &str = "/usr/share/punar/agents/process-classes.json";

/// Version field of [`LedgerRecord`], [`LedgerIndex`] and
/// [`LedgerRuntimeFile`].
pub const LEDGER_RECORD_VERSION: u32 = 1;

/// Days a ledger is kept **after the session ends** (milestone-8.md
/// section 6.1). Active sessions are never pruned; the clock starts at
/// `ended_at`. Argued as a privacy decision, not a disk decision: SPEC
/// section 24's principle is minimization, and two weeks covers the
/// working memory of the question the ledger answers.
pub const LEDGER_RETENTION_DAYS: u64 = 14;

/// Distinct `resource_class` values kept per category per session; the
/// overflow sets `truncated` rather than being silently dropped.
pub const MAX_CLASSES_PER_CATEGORY: usize = 32;

/// Security-event references kept per session.
pub const MAX_SECURITY_EVENT_REFS: usize = 256;

/// On overflow the **first** this many refs are kept…
pub const SECURITY_EVENT_KEEP_HEAD: usize = 128;

/// …and the **last** this many, so neither the onset nor the present of a
/// noisy session is lost.
pub const SECURITY_EVENT_KEEP_TAIL: usize = 128;

/// Sessions carried in [`LedgerIndex`]; oldest **ended** evicted first.
pub const MAX_INDEXED_SESSIONS: usize = 200;

/// Bytes of audit log read per drain — bounds a cold start behind a large
/// trail.
pub const MAX_AUDIT_DRAIN_BYTES: u64 = 4 * 1024 * 1024;

/// Longest permitted `resource_class`. A class name is a vocabulary
/// entry, not free text.
pub const MAX_RESOURCE_CLASS_BYTES: usize = 64;

/// The class an unmapped `comm` becomes. The raw `comm` is **never**
/// stored — a script named `deploy-prod-hotfix.sh` cannot reach the
/// ledger.
pub const CLASS_UNKNOWN: &str = "unknown";

/// The one directory zone M8 can honestly claim: the managed launch's
/// realized project workspace grant.
pub const ZONE_WORKSPACE: &str = "workspace";

/// Days a **detection** ledger is kept after the detection clears
/// (milestone-10.md decision 11) — half the managed window.
///
/// Shorter on purpose: a detection is a record about a process the user
/// never asked for, and the shortest window that still answers *what ran
/// on this device last week* is the right one. Seven days covers a full
/// working week plus a weekend — the realistic span of "we found
/// something on Friday, look into it Monday" — and halves the window in
/// which any administrator query can reach it.
pub const DETECTION_RETENTION_DAYS: u64 = 7;

/// Zone classes for the **executable's own** location, the only zone an
/// unknown-agent ledger can honestly carry (milestone-10.md section 6.3).
///
/// A class, never a path: `/proc/<pid>/cwd` is trivially readable by the
/// root daemon and would tell us the project, but recording it would put
/// a filesystem path from inside the user's home into a file an
/// administrator can later ask about — exactly what SPEC 21.2's
/// never-record list protects. Refused; the zone below is derived from
/// the executable path the detection already matched on, and the path
/// itself never crosses into ledger storage.
pub const ZONE_DOWNLOADS: &str = "downloads";
/// The executable lives under `/tmp` or `/var/tmp`.
pub const ZONE_TMP: &str = "tmp";
/// The executable lives somewhere else under a user's home.
pub const ZONE_HOME: &str = "home";
/// The executable lives in a system location (`/usr`, `/bin`, `/opt`, …).
pub const ZONE_SYSTEM: &str = "system";

/// The SPEC 21.2 never-recorded list, verbatim, carried in every result
/// so no surface has to remember it.
pub const NEVER_RECORDED: [&str; 5] = [
    "file paths inside the workspace",
    "prompts",
    "source code",
    "secret values",
    "individual file reads",
];

// ---------------------------------------------------------------------------
// Resource categories — the six schema keys, closed
// ---------------------------------------------------------------------------

/// The six `resources` keys of `ledger-summary.json`, in schema order.
///
/// Closed on purpose: [`LedgerRecord::summary`] matches exhaustively, so
/// a seventh category cannot be added without the projection failing to
/// compile — which is what makes conformance structural.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceCategory {
    Repositories,
    DirectoryZones,
    NetworkDestinations,
    McpServers,
    CredentialClasses,
    ProcessClasses,
}

impl ResourceCategory {
    /// All six, in schema `required` order.
    pub const ALL: [ResourceCategory; 6] = [
        ResourceCategory::Repositories,
        ResourceCategory::DirectoryZones,
        ResourceCategory::NetworkDestinations,
        ResourceCategory::McpServers,
        ResourceCategory::CredentialClasses,
        ResourceCategory::ProcessClasses,
    ];

    /// The JSON key.
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceCategory::Repositories => "repositories",
            ResourceCategory::DirectoryZones => "directory_zones",
            ResourceCategory::NetworkDestinations => "network_destinations",
            ResourceCategory::McpServers => "mcp_servers",
            ResourceCategory::CredentialClasses => "credential_classes",
            ResourceCategory::ProcessClasses => "process_classes",
        }
    }
}

// ---------------------------------------------------------------------------
// ResourceClass — the privacy rule, in the type
// ---------------------------------------------------------------------------

/// Why a candidate string is not a resource class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceClassError {
    Empty,
    TooLong(usize),
    /// The character that disqualified it, named so the refusal is
    /// debuggable without echoing the whole (possibly sensitive) value.
    Forbidden(char),
    /// Fails the category's own `ledger-summary.json` pattern.
    Pattern(ResourceCategory),
}

impl std::fmt::Display for ResourceClassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceClassError::Empty => write!(f, "a resource class must be non-empty"),
            ResourceClassError::TooLong(n) => write!(
                f,
                "a resource class is at most {MAX_RESOURCE_CLASS_BYTES} bytes, got {n}"
            ),
            ResourceClassError::Forbidden(c) => write!(
                f,
                "the character {c:?} may never appear in a ledger resource class \
                 (spec section 21.2: no paths, no URLs, no free text)"
            ),
            ResourceClassError::Pattern(category) => write!(
                f,
                "value does not match the ledger-summary.json pattern for {}",
                category.as_str()
            ),
        }
    }
}

impl std::error::Error for ResourceClassError {}

/// A validated resource identifier — a *class*, never a path, a URL, a
/// command line, or a prompt.
///
/// There is no `From<String>`, no `new(&str)` without a category, and no
/// public field: the only ways in are [`ResourceClass::new`] (category
/// pattern + the universal rules) and `Deserialize` (the universal rules
/// alone, because the category is not in scope while parsing a bare
/// string — [`LedgerRecord::validate`] re-checks the pairing on load).
/// Either way the universal rules hold, so **no** `ResourceClass` that
/// exists anywhere in the process can contain a path separator.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ResourceClass(String);

impl ResourceClass {
    /// Construct a class for `category`, applying the universal privacy
    /// rules **and** the category's shipped-schema pattern.
    pub fn new(
        category: ResourceCategory,
        value: &str,
    ) -> Result<ResourceClass, ResourceClassError> {
        let class = ResourceClass::from_untrusted(value)?;
        if !category_pattern_ok(category, class.as_str()) {
            return Err(ResourceClassError::Pattern(category));
        }
        Ok(class)
    }

    /// The universal rules only — the floor every class clears whatever
    /// its category. Used by `Deserialize` and by [`ResourceClass::new`].
    pub fn from_untrusted(value: &str) -> Result<ResourceClass, ResourceClassError> {
        if value.is_empty() {
            return Err(ResourceClassError::Empty);
        }
        if value.len() > MAX_RESOURCE_CLASS_BYTES {
            return Err(ResourceClassError::TooLong(value.len()));
        }
        if value.starts_with('.') {
            return Err(ResourceClassError::Forbidden('.'));
        }
        for c in value.chars() {
            // The three that carry paths, URLs and free text, plus
            // anything that is not a plain printable ASCII glyph.
            if c == '/' || c == ':' || c == '\\' || c.is_whitespace() || !c.is_ascii_graphic() {
                return Err(ResourceClassError::Forbidden(c));
            }
        }
        Ok(ResourceClass(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ResourceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ResourceClass {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<ResourceClass, D::Error> {
        let raw = String::deserialize(d)?;
        ResourceClass::from_untrusted(&raw).map_err(serde::de::Error::custom)
    }
}

/// The per-category patterns of `schemas/ai-agent/ledger-summary.json`.
///
/// `repositories` is the one array the schema leaves unpatterned (a
/// repository identity may be `host/org/name` in a later milestone). M8
/// constrains it to the **project-manifest name** pattern, because M8's
/// only source is the project identity a managed session was bound to —
/// and an unpatterned array is exactly where a path would otherwise fit.
fn category_pattern_ok(category: ResourceCategory, value: &str) -> bool {
    match category {
        // ^[a-z][a-z0-9_-]*$ — the manifest project-name pattern.
        ResourceCategory::Repositories | ResourceCategory::CredentialClasses => {
            lower_start_then(value, |c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-'
            })
        }
        // ^[a-z][a-z0-9_]*$
        ResourceCategory::DirectoryZones => lower_start_then(value, |c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
        }),
        // ^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$
        ResourceCategory::NetworkDestinations | ResourceCategory::McpServers => {
            let edge = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
            let inner = |c: char| edge(c) || c == '.' || c == '_' || c == '-';
            let bytes: Vec<char> = value.chars().collect();
            match bytes.as_slice() {
                [] => false,
                [only] => edge(*only),
                [first, mid @ .., last] => {
                    edge(*first) && edge(*last) && mid.iter().all(|c| inner(*c))
                }
            }
        }
        // ^[a-z0-9][a-z0-9._+-]*$
        ResourceCategory::ProcessClasses => {
            let mut chars = value.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                && chars.all(|c| {
                    c.is_ascii_lowercase()
                        || c.is_ascii_digit()
                        || c == '.'
                        || c == '_'
                        || c == '+'
                        || c == '-'
                })
        }
    }
}

/// `^evt_[A-Za-z0-9]+$` — the `common/defs.json` `event_id` pattern, the
/// one shape a [`SecurityEventRef`] may carry into the shipped summary.
pub fn event_id_ok(value: &str) -> bool {
    value
        .strip_prefix("evt_")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn lower_start_then(value: &str, rest_ok: impl Fn(char) -> bool) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase()) && chars.all(rest_ok)
}

// ---------------------------------------------------------------------------
// Level 4 — security event references (never payloads)
// ---------------------------------------------------------------------------

/// The seven Level-4 categories of SPEC section 21.2, exactly the
/// `security_events[].event_type` enum of the shipped schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    DeniedAccess,
    SensitiveResourceAccess,
    PrivilegeRequest,
    ProductionAccess,
    CredentialRequest,
    PolicyBypassAttempt,
    UnknownAiExecution,
}

impl SecurityEventType {
    /// All seven, schema order.
    pub const ALL: [SecurityEventType; 7] = [
        SecurityEventType::DeniedAccess,
        SecurityEventType::SensitiveResourceAccess,
        SecurityEventType::PrivilegeRequest,
        SecurityEventType::ProductionAccess,
        SecurityEventType::CredentialRequest,
        SecurityEventType::PolicyBypassAttempt,
        SecurityEventType::UnknownAiExecution,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            SecurityEventType::DeniedAccess => "denied_access",
            SecurityEventType::SensitiveResourceAccess => "sensitive_resource_access",
            SecurityEventType::PrivilegeRequest => "privilege_request",
            SecurityEventType::ProductionAccess => "production_access",
            SecurityEventType::CredentialRequest => "credential_request",
            SecurityEventType::PolicyBypassAttempt => "policy_bypass_attempt",
            SecurityEventType::UnknownAiExecution => "unknown_ai_execution",
        }
    }
}

/// A reference to one Level-4 event. The payload — action, resource,
/// decision, policy ids, result — stays in `/var/log/punar/audit.jsonl`
/// (SPEC 53): one place to redact, one place that can be wrong, and no
/// resource name lands in a per-session file the user can purge while the
/// audit trail deliberately is not purgeable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEventRef {
    pub event_id: String,
    pub event_type: SecurityEventType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

// ---------------------------------------------------------------------------
// The schema-exact summary document
// ---------------------------------------------------------------------------

/// The six required resource arrays of `ledger-summary.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerResources {
    pub repositories: Vec<ResourceClass>,
    pub directory_zones: Vec<ResourceClass>,
    pub network_destinations: Vec<ResourceClass>,
    pub mcp_servers: Vec<ResourceClass>,
    pub credential_classes: Vec<ResourceClass>,
    pub process_classes: Vec<ResourceClass>,
}

impl LedgerResources {
    /// The array for a category — the half of the projection that makes
    /// it total.
    pub fn get_mut(&mut self, category: ResourceCategory) -> &mut Vec<ResourceClass> {
        match category {
            ResourceCategory::Repositories => &mut self.repositories,
            ResourceCategory::DirectoryZones => &mut self.directory_zones,
            ResourceCategory::NetworkDestinations => &mut self.network_destinations,
            ResourceCategory::McpServers => &mut self.mcp_servers,
            ResourceCategory::CredentialClasses => &mut self.credential_classes,
            ResourceCategory::ProcessClasses => &mut self.process_classes,
        }
    }

    pub fn get(&self, category: ResourceCategory) -> &[ResourceClass] {
        match category {
            ResourceCategory::Repositories => &self.repositories,
            ResourceCategory::DirectoryZones => &self.directory_zones,
            ResourceCategory::NetworkDestinations => &self.network_destinations,
            ResourceCategory::McpServers => &self.mcp_servers,
            ResourceCategory::CredentialClasses => &self.credential_classes,
            ResourceCategory::ProcessClasses => &self.process_classes,
        }
    }

    /// Distinct resource classes across all six categories.
    pub fn total(&self) -> u64 {
        ResourceCategory::ALL
            .iter()
            .map(|c| self.get(*c).len() as u64)
            .sum()
    }
}

/// A document that validates against `schemas/ai-agent/ledger-summary.json`
/// as-is. Produced only by [`LedgerRecord::summary`] — never hand-built by
/// a request handler, so there is one place conformance can be reasoned
/// about.
///
/// This is also the **exportable artifact**: whatever Milestone 10's
/// authorized administrator query ever returns is this object, and the
/// user already has it today (milestone-8.md section 10, guarantee 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerSummary {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    pub generated_at: String,
    pub resources: LedgerResources,
    pub security_events: Vec<SecurityEventRef>,
}

// ---------------------------------------------------------------------------
// The internal record (docs/api/ipc.md section 13.1)
// ---------------------------------------------------------------------------

/// Which owned mediation point proved an entry. Five values, closed —
/// there is no `inferred`, no `traced`, no `heuristic`: M8 derives the
/// ledger only from points Punar already terminates (SPEC 1.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// The session's `punar-agent-<id>.scope` cgroup (SPEC 22).
    CgroupScope,
    /// An audit event tagged with this `agent_session_id` (SPEC 53).
    AuditEvent,
    /// The managed launch's realized workspace grant.
    WorkspaceBind,
    /// Adapter / registry metadata captured at launch.
    AdapterMetadata,
    /// The `/proc` read of one **detection pass** (Milestone 10).
    ///
    /// Added rather than folded into [`Evidence::AdapterMetadata`],
    /// because this enum exists to say *how we know* and a detection was
    /// never launched: there is no adapter and no registration behind it,
    /// only the pass that saw the process. It is still not tracing — the
    /// same `/proc` walk the registry has always done, reading the same
    /// `comm` the class table maps and discards. Nothing here observes an
    /// event as it happens; a pass observes what is running when it runs,
    /// and the honest limitation (a process that starts and exits between
    /// passes is never seen) is stated on every surface that claims
    /// continuous detection.
    DetectionScan,
}

impl Evidence {
    pub const ALL: [Evidence; 5] = [
        Evidence::CgroupScope,
        Evidence::AuditEvent,
        Evidence::WorkspaceBind,
        Evidence::AdapterMetadata,
        Evidence::DetectionScan,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Evidence::CgroupScope => "cgroup_scope",
            Evidence::AuditEvent => "audit_event",
            Evidence::WorkspaceBind => "workspace_bind",
            Evidence::AdapterMetadata => "adapter_metadata",
            Evidence::DetectionScan => "detection_scan",
        }
    }
}

/// One aggregated row: a class, how many distinct things of that class
/// were observed, and the window they were observed in.
///
/// `count` for [`ResourceCategory::ProcessClasses`] means **distinct
/// `(pid, starttime)` pairs of that class observed alive at a sampling
/// point** — not a spawn count. Short-lived children between samples are
/// missed, and every surface that renders the number says so
/// (milestone-8.md section 3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    pub category: ResourceCategory,
    pub resource_class: ResourceClass,
    pub count: u64,
    pub first_seen: String,
    pub last_seen: String,
    pub evidence: Evidence,
}

/// The per-session on-disk aggregate (`<session_id>.json`, `0640
/// root:root`).
///
/// Note what is **absent**, permanently: no path, no argv, no cwd, no
/// pid, no `comm`, no environment, no prompt, no file content, no secret,
/// and no per-access event. Adding any of them would require a field, and
/// there is nowhere to put one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRecord {
    pub v: u32,
    pub session_id: String,
    pub agent: String,
    pub user: String,
    /// The project the session was bound to, **as a validated repository
    /// class** — never the free-text `project` the launcher sent.
    ///
    /// `agents.register` pattern-checks `session_id` and `agent`, but the
    /// registry-record schema leaves `project` unpatterned, so a caller
    /// may register `project: "/home/punar/clients/acme"`. Typing this
    /// field as [`ResourceClass`] makes that path unrepresentable in the
    /// ledger: a project the repository pattern rejects lands here as
    /// `None`, and the session simply claims no repository. The raw
    /// string stays where it was already accepted — the M7 registry
    /// record — and never crosses into ledger storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<ResourceClass>,
    pub classification: AgentClassification,
    pub status: AgentStatus,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purged_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_expires_at: Option<String>,
    /// The scope cgroup's `pids.peak` — peak **concurrent** pids, the
    /// kernel's own high-water mark. Rendered as "peak concurrent
    /// processes", never as a spawn total.
    pub process_peak: u64,
    /// A bound in section 5.3 was hit; renderers say
    /// "… and more (truncated)" rather than implying completeness.
    pub truncated: bool,
    pub entries: Vec<LedgerEntry>,
    pub security_events: Vec<SecurityEventRef>,
}

impl LedgerRecord {
    /// A fresh record for a session that has just registered.
    pub fn new(
        session_id: &str,
        agent: &str,
        user: &str,
        project: Option<ResourceClass>,
        classification: AgentClassification,
        started_at: &str,
    ) -> LedgerRecord {
        LedgerRecord {
            v: LEDGER_RECORD_VERSION,
            session_id: session_id.to_string(),
            agent: agent.to_string(),
            user: user.to_string(),
            project,
            classification,
            status: AgentStatus::Active,
            started_at: started_at.to_string(),
            ended_at: None,
            updated_at: started_at.to_string(),
            purged_at: None,
            retention_expires_at: None,
            process_peak: 0,
            truncated: false,
            entries: Vec::new(),
            security_events: Vec::new(),
        }
    }

    /// Record one observation of `class` in `category` at `now`,
    /// attributing it to `evidence`. `increment` is added to the entry's
    /// count (0 refreshes `last_seen` without counting again).
    ///
    /// Returns `false` when the per-category bound was already reached
    /// and this class is new — the caller's cue that `truncated` is now
    /// true.
    pub fn observe(
        &mut self,
        category: ResourceCategory,
        class: ResourceClass,
        increment: u64,
        evidence: Evidence,
        now: &str,
    ) -> bool {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.category == category && e.resource_class == class)
        {
            entry.count = entry.count.saturating_add(increment);
            if now > entry.last_seen.as_str() {
                entry.last_seen = now.to_string();
            }
            if now < entry.first_seen.as_str() {
                entry.first_seen = now.to_string();
            }
            return true;
        }
        let distinct = self
            .entries
            .iter()
            .filter(|e| e.category == category)
            .count();
        if distinct >= MAX_CLASSES_PER_CATEGORY {
            self.truncated = true;
            return false;
        }
        self.entries.push(LedgerEntry {
            category,
            resource_class: class,
            count: increment,
            first_seen: now.to_string(),
            last_seen: now.to_string(),
            evidence,
        });
        true
    }

    /// Append a Level-4 reference unless its `event_id` is already
    /// present (ingestion must be idempotent: a re-read of the same audit
    /// bytes may not double-count). Applies the section 5.3 bound,
    /// keeping the first [`SECURITY_EVENT_KEEP_HEAD`] and the last
    /// [`SECURITY_EVENT_KEEP_TAIL`] references so neither the onset nor
    /// the present of a noisy session is lost.
    pub fn observe_security_event(&mut self, reference: SecurityEventRef) -> bool {
        if self
            .security_events
            .iter()
            .any(|existing| existing.event_id == reference.event_id)
        {
            return false;
        }
        self.security_events.push(reference);
        if self.security_events.len() > MAX_SECURITY_EVENT_REFS {
            let tail_start = self.security_events.len() - SECURITY_EVENT_KEEP_TAIL;
            let mut kept: Vec<SecurityEventRef> =
                self.security_events[..SECURITY_EVENT_KEEP_HEAD].to_vec();
            kept.extend_from_slice(&self.security_events[tail_start..]);
            self.security_events = kept;
            self.truncated = true;
        }
        true
    }

    /// Stable rendering order: category (schema order), then descending
    /// count, then class name. Applied once at compaction so an ended
    /// record renders identically forever.
    pub fn sort_entries(&mut self) {
        self.entries.sort_by(|a, b| {
            a.category
                .cmp(&b.category)
                .then(b.count.cmp(&a.count))
                .then(a.resource_class.cmp(&b.resource_class))
        });
    }

    /// The **total projection** onto the shipped schema: group entries by
    /// category, emit distinct classes, carry the event refs verbatim.
    /// Conformance by construction — see the module docs.
    pub fn summary(&self, generated_at: &str) -> LedgerSummary {
        let mut resources = LedgerResources::default();
        for entry in &self.entries {
            let bucket = resources.get_mut(entry.category);
            if !bucket.contains(&entry.resource_class) {
                bucket.push(entry.resource_class.clone());
            }
        }
        for category in ResourceCategory::ALL {
            resources.get_mut(category).sort();
        }
        LedgerSummary {
            session_id: self.session_id.clone(),
            agent: (!self.agent.is_empty()).then(|| self.agent.clone()),
            generated_at: generated_at.to_string(),
            resources,
            security_events: self.security_events.clone(),
        }
    }

    /// Counts-only fingerprint (docs/api/ipc.md section 12.4): what
    /// `agents.list` and the world-readable summary may show. No class
    /// names, no `evt_` ids, no zones.
    pub fn fingerprint(&self) -> LedgerFingerprint {
        LedgerFingerprint {
            counts: self.counts(),
            updated_at: self.updated_at.clone(),
        }
    }

    pub fn counts(&self) -> LedgerCounts {
        LedgerCounts {
            resources: self.entries.len() as u64,
            process_classes: self
                .entries
                .iter()
                .filter(|e| e.category == ResourceCategory::ProcessClasses)
                .count() as u64,
            security_events: self.security_events.len() as u64,
        }
    }

    /// True once the user has deleted this ledger. A purged record must
    /// render as *purged*, never as "nothing recorded".
    pub fn is_purged(&self) -> bool {
        self.purged_at.is_some()
    }

    /// Re-check a record loaded from disk: category/class pairing, the
    /// six-category closure, and the record version. The universal
    /// privacy rules were already enforced by `ResourceClass`'s
    /// `Deserialize`; this catches the one thing it cannot see — whether
    /// a class matches *its own category's* pattern.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut violations = Vec::new();
        if self.v != LEDGER_RECORD_VERSION {
            violations.push(format!(
                "record version {} is not the supported version {LEDGER_RECORD_VERSION}",
                self.v
            ));
        }
        if !crate::agent::session_id_ok(&self.session_id) {
            violations.push(format!(
                "session_id {:?} must match ^agt_[A-Za-z0-9]+$",
                self.session_id
            ));
        }
        // `agent` is projected verbatim into `LedgerSummary.agent`, whose
        // shipped-schema pattern is the registry's `agent` pattern. Empty
        // is allowed (a purged shell has no agent and the summary omits
        // the key); anything else must be a real agent name, so the
        // projection stays conformant by construction rather than by
        // trusting whoever wrote the file.
        if !self.agent.is_empty() && !crate::agent::agent_name_ok(&self.agent) {
            violations.push(format!(
                "agent {:?} must match ^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$",
                self.agent
            ));
        }
        if let Some(project) = &self.project {
            if !category_pattern_ok(ResourceCategory::Repositories, project.as_str()) {
                violations.push(format!(
                    "project {:?} does not match the repositories pattern",
                    project.as_str()
                ));
            }
        }
        // Every reference is projected into `security_events[].event_id`,
        // which the schema pins to `^evt_[A-Za-z0-9]+$`.
        for reference in &self.security_events {
            if !event_id_ok(&reference.event_id) {
                violations.push(format!(
                    "event_id {:?} must match ^evt_[A-Za-z0-9]+$",
                    reference.event_id
                ));
            }
        }
        for entry in &self.entries {
            if !category_pattern_ok(entry.category, entry.resource_class.as_str()) {
                violations.push(format!(
                    "resource_class {:?} does not match the {} pattern",
                    entry.resource_class.as_str(),
                    entry.category.as_str()
                ));
            }
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

// ---------------------------------------------------------------------------
// Index (rollup + audit tail position)
// ---------------------------------------------------------------------------

/// The counts-only rollup carried by the index and the fingerprint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerCounts {
    pub resources: u64,
    pub process_classes: u64,
    pub security_events: u64,
}

/// The per-session `ledger` field of `agents.list` — **counts only**
/// (docs/api/ipc.md section 12.4). Identifiers require `agents.access`
/// and its ownership check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerFingerprint {
    #[serde(flatten)]
    pub counts: LedgerCounts,
    pub updated_at: String,
}

/// Where the audit drain resumes. `(dev, ino)` detect rotation; `offset`
/// is the byte position already consumed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailPosition {
    pub dev: u64,
    pub ino: u64,
    pub offset: u64,
}

/// One index row. On a **tombstone** (a purged session) `agent` and
/// `project` are `None` and the counts are zero: the row's whole purpose
/// afterwards is to remember that the user deleted this, and to floor
/// audit re-ingestion so a later drain cannot resurrect it. A tombstone
/// carries no resource data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerIndexRow {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The repository class, never the launcher's free-text project
    /// string — same rule, and same type, as [`LedgerRecord::project`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<ResourceClass>,
    pub user: String,
    pub classification: AgentClassification,
    pub status: AgentStatus,
    pub first_seen: String,
    pub last_seen: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purged_at: Option<String>,
    pub counts: LedgerCounts,
}

impl LedgerIndexRow {
    pub fn is_tombstone(&self) -> bool {
        self.purged_at.is_some()
    }
}

/// `index.json` — the rollup `agents.list` and retention read without
/// opening every session file, plus the audit tail position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerIndex {
    pub v: u32,
    pub updated_at: String,
    pub tail: TailPosition,
    pub sessions: Vec<LedgerIndexRow>,
}

impl Default for LedgerIndex {
    fn default() -> LedgerIndex {
        LedgerIndex {
            v: LEDGER_RECORD_VERSION,
            updated_at: String::new(),
            tail: TailPosition::default(),
            sessions: Vec::new(),
        }
    }
}

impl LedgerIndex {
    pub fn row(&self, session_id: &str) -> Option<&LedgerIndexRow> {
        self.sessions.iter().find(|r| r.session_id == session_id)
    }

    pub fn row_mut(&mut self, session_id: &str) -> Option<&mut LedgerIndexRow> {
        self.sessions
            .iter_mut()
            .find(|r| r.session_id == session_id)
    }

    /// Insert or replace one row, keeping `sessions` sorted by
    /// `session_id` so the file is deterministic and diffable.
    pub fn upsert(&mut self, row: LedgerIndexRow) {
        match self.row_mut(&row.session_id) {
            Some(existing) => *existing = row,
            None => {
                self.sessions.push(row);
                self.sessions
                    .sort_by(|a, b| a.session_id.cmp(&b.session_id));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Honest absence (SPEC 1.22)
// ---------------------------------------------------------------------------

/// One category that has **no producer yet** — the row that keeps an
/// empty array from reading as "nothing happened". No surface may render
/// an empty ledger category without its label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotYetObserved {
    /// 3 (resource summary) or 4 (security events).
    pub level: u8,
    /// A [`ResourceCategory`] key (level 3) or a [`SecurityEventType`]
    /// value (level 4).
    pub category: String,
    /// The milestone that ships the producer.
    pub milestone: String,
    pub reason: String,
}

/// The canonical, complete not-yet-observed set as of Milestone 9.
///
/// Naming a producerless category — with the milestone and the reason —
/// is the difference between an honest empty array and a lie by omission
/// (SPEC 1.22). When a producer ships, its row leaves this list.
///
/// **Milestone 9 changed this list in both directions** (milestone-9.md
/// section 9.3), which is the point of the idiom:
///
/// - *Left, because the producer shipped*: `credential_classes` (L3) and
///   `credential_request` (L4) — `punar-secrets` now emits
///   `credential.request` audit events carrying an `agent_session_id`;
///   and `policy_bypass_attempt` (L4) — an AI agent that tries to resolve
///   an approval is refused, audited, and classified
///   ([`crate::ledger`] consumers see it through
///   `punar_agentd::ledger::tail::classify`).
/// - *Re-milestoned, because the honest date moved*: `mcp_servers`
///   M9+ → M11+ (M9 ships no MCP or tool gateway; SPEC section 26 has no
///   section 76 milestone of its own) and `sensitive_resource_access`
///   M9/M12 → M12 (no mediation point observes sensitive zones in M9).
///   Re-milestoning is the honest move; leaving a row that quietly
///   promises the wrong milestone is not.
///
/// **Milestone 10 removes one row, because the producer shipped**:
/// `unknown_ai_execution` (L4). M8 wrote the row as *"the audit event
/// exists, but a detected unmanaged process has no registered session, so
/// it attaches to no ledger; M10 owns the unknown-agent ledger"* — and
/// M10 built exactly that (milestone-10.md section 6). A detection now
/// gets a persisted record and a bounded ledger, and the `agents.scan`
/// transition that produced it is referenced there as a Level-4
/// `unknown_ai_execution` event. The row leaves this list, which is the
/// documented idiom: *when a producer ships, its row leaves*. It has to
/// leave — a list that keeps promising a milestone which already shipped
/// is the same lie by omission, wearing the opposite mask.
///
/// A **managed** session's ledger still carries no `unknown_ai_execution`
/// event, and that is not an absent producer: a managed session is by
/// construction not an unknown AI execution. See
/// [`not_yet_observed_for`] for the per-classification set.
pub fn not_yet_observed() -> Vec<NotYetObserved> {
    let row = |level: u8, category: &str, milestone: &str, reason: &str| NotYetObserved {
        level,
        category: category.to_string(),
        milestone: milestone.to_string(),
        reason: reason.to_string(),
    };
    vec![
        row(
            3,
            ResourceCategory::NetworkDestinations.as_str(),
            "M12",
            "punar-netd does not exist yet; no owned mediation point observes network \
             destinations, and M6 containers run with --network none",
        ),
        row(
            3,
            ResourceCategory::McpServers.as_str(),
            "M11+",
            "no tool or MCP gateway mediates MCP traffic yet (spec section 26); Milestone 9 \
             shipped the credential broker, not a tool gateway",
        ),
        row(
            4,
            SecurityEventType::ProductionAccess.as_str(),
            "M12",
            "no network mediation exists yet",
        ),
        row(
            4,
            SecurityEventType::SensitiveResourceAccess.as_str(),
            "M12",
            "no mediation point observes sensitive zones yet",
        ),
    ]
}

/// The not-yet-observed set for one session, by **classification**
/// (milestone-10.md section 6.3).
///
/// An unmanaged detection has strictly fewer sources than a managed
/// session, so its honest empty list is strictly longer. Two categories
/// that have a producer for a *managed* session have none for a process
/// Punar never launched, and saying so is the whole idiom:
///
/// - `repositories` — nothing granted an unmanaged agent a workspace, and
///   `cwd` is never read, so there is no repository to name;
/// - `credential_classes` — `punar-secrets` mediates *managed* sessions,
///   so an unmanaged agent's credential use may never be observable by
///   this mechanism at all. That is a permanent limitation, not a
///   pending milestone, and the row says so.
///
/// `directory_zones` is **not** listed: an unknown ledger does carry one
/// zone — the class of where the *executable* lives ([`ZONE_DOWNLOADS`]
/// and friends), derived from the path the signature already matched.
pub fn not_yet_observed_for(classification: AgentClassification) -> Vec<NotYetObserved> {
    let mut rows = not_yet_observed();
    // The dividing line is **managed**, not "unknown": both extra rows
    // are about mediation points that exist only for a session Punar
    // itself launched. An `observed` detection — a known agent product
    // running outside the managed runtime — has no workspace grant and no
    // brokered credentials either, so it gets the same honest rows.
    if classification == AgentClassification::Managed {
        return rows;
    }
    rows.push(NotYetObserved {
        level: 3,
        category: ResourceCategory::Repositories.as_str().to_string(),
        milestone: "none".to_string(),
        reason: "nothing granted this process a workspace, and Punar never reads \
                 /proc/<pid>/cwd to infer one (milestone-10.md section 6.3): there is no \
                 producer for an unmanaged agent's repository, in this milestone or a \
                 later one"
            .to_string(),
    });
    rows.push(NotYetObserved {
        level: 3,
        category: ResourceCategory::CredentialClasses.as_str().to_string(),
        milestone: "none".to_string(),
        reason: "punar-secrets mediates managed sessions only, so an unmanaged agent's \
                 credential use may never be observable by this mechanism at all — an \
                 honest permanent limitation, not a pending producer"
            .to_string(),
    });
    rows
}

// ---------------------------------------------------------------------------
// IPC result shapes (docs/api/ipc.md section 12.2)
// ---------------------------------------------------------------------------

/// The counts and windows the shipped schema cannot hold, carried as a
/// **sibling** of the schema-exact `summary`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerDetail {
    /// `active` or `ended`.
    pub status: String,
    pub process_peak: u64,
    pub truncated: bool,
    pub entries: Vec<LedgerEntry>,
}

/// How long this ledger is kept. `active` while the session runs (the
/// clock has not started), `expires_at` once it has ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionInfo {
    pub days: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl RetentionInfo {
    pub fn active() -> RetentionInfo {
        RetentionInfo::active_for(LEDGER_RETENTION_DAYS)
    }

    pub fn expiring(at: &str) -> RetentionInfo {
        RetentionInfo::expiring_for(LEDGER_RETENTION_DAYS, at)
    }

    /// The same, for a window that is not the managed one — a detection's
    /// is seven days (milestone-10.md decision 11). The number is
    /// rendered on the privacy surface, so it has to be the number that
    /// actually applies rather than the default one.
    pub fn active_for(days: u64) -> RetentionInfo {
        RetentionInfo {
            days,
            active: Some(true),
            expires_at: None,
        }
    }

    pub fn expiring_for(days: u64, at: &str) -> RetentionInfo {
        RetentionInfo {
            days,
            active: None,
            expires_at: Some(at.to_string()),
        }
    }
}

/// How long this classification's ledger is kept.
///
/// A managed session's is fourteen days; a detection's is seven. Shorter
/// on purpose: a detection is a record about a process the user never
/// asked for, so the shortest window that still answers *what ran on this
/// device last week* is the right one — and it halves the window in which
/// any administrator query can reach it.
pub fn retention_days_for(classification: AgentClassification) -> u64 {
    match classification {
        AgentClassification::Managed => LEDGER_RETENTION_DAYS,
        AgentClassification::Observed | AgentClassification::Unknown => DETECTION_RETENTION_DAYS,
    }
}

/// The six-point guarantee's machine-readable half (milestone-8.md
/// section 10): what is never recorded, where the data lives, how to
/// delete it, and that deleting it does not touch the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyNotice {
    pub local_only: bool,
    pub purge_command: String,
    pub never_recorded: Vec<String>,
    /// Always true: SPEC 53's log records decisions the *system* made and
    /// is outside a user's delete authority; the ledger, derived from it,
    /// is not.
    pub audit_trail_separate: bool,
}

impl PrivacyNotice {
    pub fn for_session(session_id: &str) -> PrivacyNotice {
        PrivacyNotice {
            local_only: true,
            purge_command: format!("punarctl privacy purge --session {session_id}"),
            never_recorded: NEVER_RECORDED.iter().map(|s| s.to_string()).collect(),
            audit_trail_separate: true,
        }
    }
}

/// `agents.access` result (docs/api/ipc.md section 12.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentsAccessResult {
    /// Schema-exact `ledger-summary.json` document.
    pub summary: LedgerSummary,
    pub detail: LedgerDetail,
    pub not_yet_observed: Vec<NotYetObserved>,
    pub retention: RetentionInfo,
    pub privacy: PrivacyNotice,
    /// Present when the user deleted this ledger. Renderers must say
    /// *purged*, never *nothing recorded*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purged_at: Option<String>,
}

impl AgentsAccessResult {
    /// Build the whole result from a record. One constructor so no
    /// surface can accidentally drop the honesty rows or the privacy
    /// notice.
    pub fn from_record(record: &LedgerRecord, generated_at: &str) -> AgentsAccessResult {
        AgentsAccessResult {
            summary: record.summary(generated_at),
            detail: LedgerDetail {
                status: record.status.as_str().to_string(),
                process_peak: record.process_peak,
                truncated: record.truncated,
                entries: record.entries.clone(),
            },
            // Per classification since M10: an unmanaged detection has
            // strictly fewer sources than a managed session, so its
            // honest empty list is strictly longer.
            not_yet_observed: not_yet_observed_for(record.classification),
            // A purged record still has the date its tombstone
            // disappears on, and the panel's side file must carry the
            // same answer the socket gives — otherwise the two surfaces
            // this builds disagree about one ledger.
            retention: {
                let days = retention_days_for(record.classification);
                match (&record.purged_at, &record.retention_expires_at) {
                    (_, Some(at)) => RetentionInfo::expiring_for(days, at),
                    (Some(_), None) => RetentionInfo::expiring_for(days, ""),
                    (None, None) => RetentionInfo::active_for(days),
                }
            },
            privacy: PrivacyNotice::for_session(&record.session_id),
            purged_at: record.purged_at.clone(),
        }
    }
}

/// `ledger.purge` result (docs/api/ipc.md section 12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerPurgeResult {
    pub purged: u64,
    pub resource_classes: u64,
    pub security_events: u64,
}

/// `/run/punar-agentd/ledger.json` (docs/api/ipc.md section 13.2) — the
/// panel's event-driven view. Literally the rows `agents.access`
/// returns, so the pane and the CLI cannot render different ledgers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRuntimeFile {
    pub v: u32,
    pub ts: String,
    pub sessions: Vec<AgentsAccessResult>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn class(category: ResourceCategory, value: &str) -> ResourceClass {
        ResourceClass::new(category, value).expect("fixture class is valid")
    }

    fn populated_record() -> LedgerRecord {
        let mut record = LedgerRecord::new(
            "agt_4f21c09ab3e1",
            "claude-code",
            "punar",
            Some(class(ResourceCategory::Repositories, "atlas")),
            AgentClassification::Managed,
            "2026-08-27T09:58:40Z",
        );
        record.observe(
            ResourceCategory::Repositories,
            class(ResourceCategory::Repositories, "atlas"),
            1,
            Evidence::WorkspaceBind,
            "2026-08-27T09:58:40Z",
        );
        record.observe(
            ResourceCategory::DirectoryZones,
            class(ResourceCategory::DirectoryZones, ZONE_WORKSPACE),
            1,
            Evidence::WorkspaceBind,
            "2026-08-27T09:58:40Z",
        );
        record.observe(
            ResourceCategory::ProcessClasses,
            class(ResourceCategory::ProcessClasses, "git"),
            2,
            Evidence::CgroupScope,
            "2026-08-27T09:58:44Z",
        );
        record.observe(
            ResourceCategory::ProcessClasses,
            class(ResourceCategory::ProcessClasses, "shell"),
            3,
            Evidence::CgroupScope,
            "2026-08-27T10:00:02Z",
        );
        record.observe_security_event(SecurityEventRef {
            event_id: "evt_502".into(),
            event_type: SecurityEventType::DeniedAccess,
            timestamp: Some("2026-08-27T09:59:12Z".into()),
        });
        record.process_peak = 6;
        record
    }

    // -- the shipped schema is the contract -----------------------------

    const LEDGER_SUMMARY_SCHEMA: &str =
        include_str!("../../../schemas/ai-agent/ledger-summary.json");

    /// The projection must produce exactly the schema's field set, and
    /// the six required resource arrays must be exactly the six
    /// [`ResourceCategory`] variants — that is what makes the projection
    /// total rather than merely conventional.
    #[test]
    fn the_summary_type_matches_the_shipped_schema() {
        let schema: Value = serde_json::from_str(LEDGER_SUMMARY_SCHEMA).unwrap();

        let mut required: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        required.sort_unstable();
        assert_eq!(
            required,
            vec!["generated_at", "resources", "security_events", "session_id"]
        );
        assert_eq!(schema["additionalProperties"], Value::Bool(false));

        // Every serialized key is a schema property (agent is optional).
        let value =
            serde_json::to_value(populated_record().summary("2026-08-27T10:00:02Z")).unwrap();
        for key in value.as_object().unwrap().keys() {
            assert!(
                schema["properties"].get(key).is_some(),
                "summary key {key:?} is not in ledger-summary.json"
            );
        }
        for key in required {
            assert!(value.get(key).is_some(), "required key {key} missing");
        }

        // The six resource arrays are the six categories, in order.
        let schema_required: Vec<&str> = schema["properties"]["resources"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let ours: Vec<&str> = ResourceCategory::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            schema_required, ours,
            "category enum drifted from the schema"
        );
        assert_eq!(
            schema["properties"]["resources"]["additionalProperties"],
            Value::Bool(false)
        );

        // The seven Level-4 categories are the seven enum variants.
        let schema_events: Vec<&str> =
            schema["properties"]["security_events"]["items"]["properties"]["event_type"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
        let ours: Vec<&str> = SecurityEventType::ALL.iter().map(|t| t.as_str()).collect();
        assert_eq!(
            schema_events, ours,
            "event-type enum drifted from the schema"
        );
    }

    #[test]
    fn every_category_appears_even_when_empty() {
        let record = LedgerRecord::new(
            "agt_empty01",
            "claude-code",
            "punar",
            Some(class(ResourceCategory::Repositories, "atlas")),
            AgentClassification::Managed,
            "2026-08-27T09:58:40Z",
        );
        let value = serde_json::to_value(record.summary("2026-08-27T10:00:02Z")).unwrap();
        for category in ResourceCategory::ALL {
            let array = value["resources"][category.as_str()].as_array().unwrap();
            assert!(array.is_empty(), "{} should be empty", category.as_str());
        }
        assert!(value["security_events"].as_array().unwrap().is_empty());
    }

    #[test]
    fn projection_is_total_and_deduplicated() {
        let summary = populated_record().summary("2026-08-27T10:00:02Z");
        assert_eq!(
            summary
                .resources
                .process_classes
                .iter()
                .map(ResourceClass::as_str)
                .collect::<Vec<_>>(),
            vec!["git", "shell"]
        );
        assert_eq!(summary.resources.repositories.len(), 1);
        assert_eq!(summary.resources.network_destinations.len(), 0);
        assert_eq!(summary.resources.total(), 4);
        assert_eq!(summary.security_events.len(), 1);
    }

    // -- privacy in the type -------------------------------------------

    #[test]
    fn a_path_a_url_and_a_command_line_are_unrepresentable() {
        for hostile in [
            "/home/punar/atlas",
            "atlas/.git/config",
            "https://api.example.com/v1",
            "api.example.com:443",
            "git hash-object --stdin-paths",
            "summarize the secret quarterly numbers",
            ".punar-agent-touch",
            "C:\\Users\\punar",
            "deploy prod",
        ] {
            assert!(
                ResourceClass::from_untrusted(hostile).is_err(),
                "{hostile:?} must never become a resource class"
            );
            for category in ResourceCategory::ALL {
                assert!(
                    ResourceClass::new(category, hostile).is_err(),
                    "{hostile:?} must never become a {} class",
                    category.as_str()
                );
            }
            // And it cannot be smuggled in through the file, either.
            let json = serde_json::to_string(hostile).unwrap();
            assert!(
                serde_json::from_str::<ResourceClass>(&json).is_err(),
                "{hostile:?} must not deserialize into a resource class"
            );
        }
    }

    /// The launcher's `project` is the one client-controlled free-text
    /// field that used to reach ledger storage verbatim: the
    /// registry-record schema leaves it unpatterned, so
    /// `agents.register` accepts `"/home/punar/clients/acme"`. Typing
    /// [`LedgerRecord::project`] as a [`ResourceClass`] makes that
    /// unrepresentable — including through the file, which is the path a
    /// hand-edited record would take.
    #[test]
    fn a_path_shaped_project_cannot_be_smuggled_into_a_record() {
        for hostile in [
            "/home/punar/clients/acme",
            "../../etc/shadow",
            "atlas/.git",
            "Q3 merger workspace",
        ] {
            assert!(
                ResourceClass::new(ResourceCategory::Repositories, hostile).is_err(),
                "{hostile:?} must not become a project class"
            );
            let text = serde_json::to_string(&serde_json::json!({
                "v": LEDGER_RECORD_VERSION,
                "session_id": "agt_4f21c09ab3e1",
                "agent": "claude-code",
                "user": "punar",
                "project": hostile,
                "classification": "managed",
                "status": "active",
                "started_at": "2026-08-27T09:58:40Z",
                "updated_at": "2026-08-27T09:58:40Z",
                "process_peak": 0,
                "truncated": false,
                "entries": [],
                "security_events": [],
            }))
            .unwrap();
            assert!(
                serde_json::from_str::<LedgerRecord>(&text).is_err(),
                "{hostile:?} deserialized into a record's project field"
            );
        }
    }

    /// `agent` and `event_id` are projected verbatim into the shipped
    /// summary, so `validate` — which gates every write and every load —
    /// has to hold them to their schema patterns too. Otherwise
    /// "conformance by construction" would depend on the daemon never
    /// having a bug upstream.
    #[test]
    fn validate_holds_the_projected_identifiers_to_their_schema_patterns() {
        let mut record = populated_record();
        record.agent = "../../etc/passwd".to_string();
        assert_eq!(record.validate().unwrap_err().len(), 1);

        // The purged shell carries no agent, and that stays legal.
        record.agent = String::new();
        assert!(record.validate().is_ok());

        record.agent = "claude-code".to_string();
        record.security_events.push(SecurityEventRef {
            event_id: "/var/log/punar/audit.jsonl".into(),
            event_type: SecurityEventType::DeniedAccess,
            timestamp: None,
        });
        assert_eq!(record.validate().unwrap_err().len(), 1);

        assert!(event_id_ok("evt_1787243462x7"));
        assert!(!event_id_ok("evt_"));
        assert!(!event_id_ok("502"));
    }

    #[test]
    fn category_patterns_match_the_schema_examples() {
        // Schema `examples`, which must all be constructible.
        for value in ["workspace", "home", "ssh", "aws"] {
            assert!(
                ResourceClass::new(ResourceCategory::DirectoryZones, value).is_ok(),
                "{value}"
            );
        }
        for value in ["api.anthropic.com", "corp_dev"] {
            assert!(
                ResourceClass::new(ResourceCategory::NetworkDestinations, value).is_ok(),
                "{value}"
            );
        }
        for value in ["github", "aws_dev", "aws-dev"] {
            assert!(
                ResourceClass::new(ResourceCategory::CredentialClasses, value).is_ok(),
                "{value}"
            );
        }
        for value in ["bash", "git", "node", "cargo", "unknown"] {
            assert!(
                ResourceClass::new(ResourceCategory::ProcessClasses, value).is_ok(),
                "{value}"
            );
        }
        // Zones reject '-' (the schema pattern does), destinations reject
        // a leading '-', repositories reject uppercase.
        assert!(ResourceClass::new(ResourceCategory::DirectoryZones, "my-zone").is_err());
        assert!(ResourceClass::new(ResourceCategory::NetworkDestinations, "-lead").is_err());
        assert!(ResourceClass::new(ResourceCategory::Repositories, "Atlas").is_err());
    }

    /// `repositories` is the one schema array with no pattern — the hole
    /// is closed here, one level down, and this test is what pins it.
    #[test]
    fn repositories_are_constrained_even_though_the_schema_does_not() {
        assert!(ResourceClass::new(ResourceCategory::Repositories, "atlas").is_ok());
        assert!(
            ResourceClass::new(ResourceCategory::Repositories, "github.com/acme/atlas").is_err()
        );
        assert!(ResourceClass::new(ResourceCategory::Repositories, "/srv/atlas").is_err());
    }

    #[test]
    fn a_serialized_record_contains_no_separators_and_no_argv_tokens() {
        let text = serde_json::to_string(&populated_record()).unwrap();
        for forbidden in [
            "cmdline",
            "argv",
            "prompt",
            "comm",
            "cwd",
            "\"path\"",
            "executable",
            "pid",
            "/home/",
            "--stdin-paths",
            "hash-object",
        ] {
            assert!(!text.contains(forbidden), "{forbidden} leaked: {text}");
        }
    }

    // -- aggregation semantics -----------------------------------------

    #[test]
    fn observing_the_same_class_accumulates_and_widens_the_window() {
        let mut record = populated_record();
        record.observe(
            ResourceCategory::ProcessClasses,
            class(ResourceCategory::ProcessClasses, "git"),
            3,
            Evidence::CgroupScope,
            "2026-08-27T10:05:00Z",
        );
        let git = record
            .entries
            .iter()
            .find(|e| e.resource_class.as_str() == "git")
            .unwrap();
        assert_eq!(git.count, 5);
        assert_eq!(git.first_seen, "2026-08-27T09:58:44Z");
        assert_eq!(git.last_seen, "2026-08-27T10:05:00Z");
    }

    #[test]
    fn the_per_category_bound_truncates_rather_than_lying() {
        let mut record = populated_record();
        for n in 0..MAX_CLASSES_PER_CATEGORY + 4 {
            let name = format!("cls{n}");
            let _ = record.observe(
                ResourceCategory::ProcessClasses,
                class(ResourceCategory::ProcessClasses, &name),
                1,
                Evidence::CgroupScope,
                "2026-08-27T10:05:00Z",
            );
        }
        let kept = record
            .entries
            .iter()
            .filter(|e| e.category == ResourceCategory::ProcessClasses)
            .count();
        assert_eq!(kept, MAX_CLASSES_PER_CATEGORY);
        assert!(record.truncated, "the bound is disclosed, not hidden");
    }

    #[test]
    fn security_event_ingestion_is_idempotent_and_bounded() {
        let mut record = populated_record();
        assert!(!record.observe_security_event(SecurityEventRef {
            event_id: "evt_502".into(),
            event_type: SecurityEventType::DeniedAccess,
            timestamp: Some("2026-08-27T09:59:12Z".into()),
        }));
        assert_eq!(record.security_events.len(), 1);

        for n in 0..MAX_SECURITY_EVENT_REFS + 10 {
            record.observe_security_event(SecurityEventRef {
                event_id: format!("evt_x{n}"),
                event_type: SecurityEventType::PrivilegeRequest,
                timestamp: None,
            });
        }
        assert_eq!(
            record.security_events.len(),
            SECURITY_EVENT_KEEP_HEAD + SECURITY_EVENT_KEEP_TAIL
        );
        // The onset survived…
        assert_eq!(record.security_events[0].event_id, "evt_502");
        // …and so did the present.
        assert_eq!(
            record.security_events.last().unwrap().event_id,
            format!("evt_x{}", MAX_SECURITY_EVENT_REFS + 9)
        );
        assert!(record.truncated);
    }

    #[test]
    fn compaction_sorts_by_category_then_descending_count() {
        let mut record = populated_record();
        record.sort_entries();
        let order: Vec<(&str, &str)> = record
            .entries
            .iter()
            .map(|e| (e.category.as_str(), e.resource_class.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("repositories", "atlas"),
                ("directory_zones", "workspace"),
                ("process_classes", "shell"),
                ("process_classes", "git"),
            ]
        );
    }

    #[test]
    fn a_record_round_trips_through_disk_and_validates() {
        let record = populated_record();
        let text = serde_json::to_string(&record).unwrap();
        let back: LedgerRecord = serde_json::from_str(&text).unwrap();
        assert_eq!(back, record);
        assert!(back.validate().is_ok());
    }

    #[test]
    fn a_record_with_a_mismatched_category_is_refused_on_load() {
        // Zones may not contain '-' by the schema pattern; the universal
        // rules alone would let it through, so `validate` is the layer
        // that catches it.
        let mut record = populated_record();
        record.entries.push(LedgerEntry {
            category: ResourceCategory::DirectoryZones,
            resource_class: ResourceClass::from_untrusted("not-a-zone").unwrap(),
            count: 1,
            first_seen: "2026-08-27T09:58:40Z".into(),
            last_seen: "2026-08-27T09:58:40Z".into(),
            evidence: Evidence::WorkspaceBind,
        });
        let violations = record.validate().unwrap_err();
        assert_eq!(violations.len(), 1, "{violations:?}");
    }

    // -- honesty --------------------------------------------------------

    #[test]
    fn every_category_without_a_producer_is_named() {
        let rows = not_yet_observed();
        let level3: Vec<&str> = rows
            .iter()
            .filter(|r| r.level == 3)
            .map(|r| r.category.as_str())
            .collect();
        // M9 shipped punar-secrets, so `credential_classes` left this
        // list. `mcp_servers` was re-milestoned M9+ -> M11+ rather than
        // left promising a milestone that does not own it.
        assert_eq!(level3, vec!["network_destinations", "mcp_servers"]);
        assert_eq!(
            rows.iter()
                .find(|r| r.category == "mcp_servers")
                .unwrap()
                .milestone,
            "M11+"
        );
        let level4: Vec<&str> = rows
            .iter()
            .filter(|r| r.level == 4)
            .map(|r| r.category.as_str())
            .collect();
        // M10 shipped the unknown-agent ledger, so `unknown_ai_execution`
        // left this list for the same reason `credential_classes` left it
        // in M9: a category with a producer is not "not yet observed".
        assert_eq!(
            level4,
            vec!["production_access", "sensitive_resource_access"]
        );
        // The invariant this test actually exists for: **all seven**
        // Level-4 categories are accounted for — each either has a
        // producer or is named here with a milestone. None is quietly
        // absent (spec 1.22). Asserting the list's exact contents is
        // asserting a snapshot; asserting the partition is asserting the
        // rule, and the rule is what must survive the next milestone.
        let named: Vec<&str> = level4.clone();
        for event_type in SecurityEventType::ALL {
            let has_producer = matches!(
                event_type,
                SecurityEventType::DeniedAccess
                    | SecurityEventType::PrivilegeRequest
                    | SecurityEventType::CredentialRequest
                    | SecurityEventType::PolicyBypassAttempt
                    // M10: the detection pass itself
                    // (`crate::ledger` consumers see it through
                    // `punar_agentd::ledger::tail::classify`).
                    | SecurityEventType::UnknownAiExecution
            );
            assert!(
                has_producer != named.contains(&event_type.as_str()),
                "{} must be produced or named as pending, never both and never neither",
                event_type.as_str()
            );
        }
        for row in &rows {
            assert!(!row.reason.is_empty());
            assert!(row.milestone.starts_with('M'), "{}", row.milestone);
        }
    }

    /// An unmanaged detection's honest empty list is strictly longer
    /// than a managed session's, because it has strictly fewer sources
    /// (milestone-10.md section 6.3).
    #[test]
    fn an_unmanaged_ledger_names_the_two_sources_it_can_never_have() {
        let base = not_yet_observed();
        for classification in [AgentClassification::Unknown, AgentClassification::Observed] {
            let rows = not_yet_observed_for(classification);
            assert!(rows.len() > base.len(), "{classification:?}");
            let categories: Vec<&str> = rows.iter().map(|r| r.category.as_str()).collect();
            assert!(categories.contains(&"repositories"), "{categories:?}");
            assert!(categories.contains(&"credential_classes"), "{categories:?}");
            // `directory_zones` is NOT listed: an unknown ledger does
            // carry one — the zone class of where the executable lives.
            assert!(!categories.contains(&"directory_zones"), "{categories:?}");
            // The two extra rows are permanent limitations, not pending
            // producers, and they say so rather than promising a date.
            for row in rows
                .iter()
                .filter(|r| r.category == "repositories" || r.category == "credential_classes")
            {
                assert_eq!(row.milestone, "none", "{row:?}");
                assert!(!row.reason.is_empty());
            }
        }
        assert_eq!(
            not_yet_observed_for(AgentClassification::Managed),
            base,
            "a managed session has the workspace grant and the broker"
        );
    }

    #[test]
    fn the_result_always_carries_the_privacy_notice_and_the_honesty_rows() {
        let result = AgentsAccessResult::from_record(&populated_record(), "2026-08-27T10:00:02Z");
        // A **managed** session gets the base list; every row names a
        // milestone. The count is not asserted — it moves whenever a
        // producer ships, which is the idiom working, not a regression.
        assert!(!result.not_yet_observed.is_empty());
        assert!(
            result
                .not_yet_observed
                .iter()
                .all(|row| !row.milestone.is_empty() && !row.reason.is_empty())
        );
        assert!(result.privacy.local_only);
        assert!(result.privacy.audit_trail_separate);
        assert_eq!(
            result.privacy.purge_command,
            "punarctl privacy purge --session agt_4f21c09ab3e1"
        );
        assert_eq!(result.privacy.never_recorded.len(), NEVER_RECORDED.len());
        assert_eq!(result.retention.days, LEDGER_RETENTION_DAYS);
        assert_eq!(result.retention.active, Some(true));
        assert_eq!(result.detail.process_peak, 6);
        assert!(result.purged_at.is_none());
    }

    #[test]
    fn a_purged_record_says_purged_rather_than_empty() {
        let mut record = populated_record();
        record.entries.clear();
        record.security_events.clear();
        record.purged_at = Some("2026-08-27T11:00:00Z".into());
        record.status = AgentStatus::Ended;
        let result = AgentsAccessResult::from_record(&record, "2026-08-27T11:00:01Z");
        assert_eq!(result.purged_at.as_deref(), Some("2026-08-27T11:00:00Z"));
        assert_eq!(result.summary.resources.total(), 0);
        assert!(result.summary.security_events.is_empty());
    }

    #[test]
    fn the_fingerprint_is_counts_only() {
        let record = populated_record();
        let value = serde_json::to_value(record.fingerprint()).unwrap();
        let object = value.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "process_classes",
                "resources",
                "security_events",
                "updated_at"
            ]
        );
        // Numbers plus exactly one timestamp — no class names, no evt ids.
        assert_eq!(object["resources"], 4);
        assert_eq!(object["process_classes"], 2);
        assert_eq!(object["security_events"], 1);
        let text = serde_json::to_string(&value).unwrap();
        for leak in ["git", "shell", "atlas", "evt_", "workspace"] {
            assert!(!text.contains(leak), "{leak} leaked into the fingerprint");
        }
    }

    #[test]
    fn the_index_upserts_deterministically() {
        let mut index = LedgerIndex::default();
        let row = |id: &str| LedgerIndexRow {
            session_id: id.to_string(),
            agent: Some("claude-code".into()),
            project: Some(class(ResourceCategory::Repositories, "atlas")),
            user: "punar".into(),
            classification: AgentClassification::Managed,
            status: AgentStatus::Active,
            first_seen: "2026-08-27T09:58:40Z".into(),
            last_seen: "2026-08-27T10:00:02Z".into(),
            updated_at: "2026-08-27T10:00:02Z".into(),
            retention_expires_at: None,
            purged_at: None,
            counts: LedgerCounts::default(),
        };
        index.upsert(row("agt_b2"));
        index.upsert(row("agt_a1"));
        index.upsert(row("agt_b2"));
        assert_eq!(index.sessions.len(), 2);
        assert_eq!(index.sessions[0].session_id, "agt_a1");
        assert!(!index.sessions[0].is_tombstone());
    }
}
