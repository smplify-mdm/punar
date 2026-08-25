//! The Milestone 10 remote-query vocabulary: scopes, the pulled-query
//! wire shapes, the three-way authorization intersection, and the local
//! query-log record (SPEC sections 24.1, 24.2, 51, 51.1, 59.4, 73;
//! `docs/development/milestone-10.md` sections 7–10).
//!
//! # Why this lives in the shared crate
//!
//! milestone-10.md section 8.1 requires the scope field to be "a closed
//! enum on the wire **and a Rust enum in both daemons**". Two independent
//! copies of a closed enum are two things that can drift, and the thing
//! they would drift about is an authorization boundary. So the enum, its
//! wire spellings, and the intersection that consumes it are defined once,
//! here — the same discipline [`crate::principal`] applies to "is this peer
//! an agent?" (docs/api/ipc.md section 12.5).
//!
//! # The architectural laws this module encodes
//!
//! - **Law 1 — Punar is not a server.** Nothing in this module binds,
//!   listens, or accepts. The only types here are the ones a device fills
//!   in *after it went and fetched a question* on the sync piggyback
//!   (milestone-10.md section 7.2). There is no inbound anything.
//! - **Law 2 — the transport is not the authority.** [`authorize`] takes
//!   the requested scope as an untrusted `&str` and the granted scope from
//!   an [`OrgGrant`] that [`read_org_granted_scopes`] read **from the local
//!   `enrollment.json`**. There is no parameter through which a courier —
//!   or a compromised control plane (SPEC section 59.4) — can widen its own
//!   authority, because no such parameter exists.
//! - **Law 3 — the user can always read the record.** [`QueryRecord`]
//!   carries the six SPEC 51.1 fields and is what `punarctl privacy
//!   queries` prints (milestone-10.md section 10.3).
//!
//! # Privacy in the types (the M8 Decision-0 law, fifth application)
//!
//! The refusal list of milestone-10.md section 8.3 is *structural* here,
//! not filtered: [`PendingQuery`] and [`QueryRecord`] have no field that
//! could carry a prompt, a file path, a command line, a pid, a cgroup path
//! or an audit payload — so there is nothing to forget to strip. A filter
//! can be forgotten; a missing field cannot.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Names and bounds the two daemons, the CLI and the mock must agree on
// ---------------------------------------------------------------------------

/// `punar-agentd` method: punard hands one fetched query to the data owner
/// (root peer only — milestone-10.md section 13.1).
pub const METHOD_QUERY_ANSWER: &str = "query.answer";

/// `punar-agentd` method: the user's own query log (any admitted peer, SPEC
/// section 24.2 — milestone-10.md section 13.1).
pub const METHOD_QUERIES_LIST: &str = "queries.list";

/// Control-plane method the **device calls outward** to collect questions
/// addressed to it (milestone-10.md section 13.3). The device dials; the
/// control plane never dials the device.
pub const CP_METHOD_QUERIES_PENDING: &str = "queries.pending";

/// Control-plane method the device calls outward to post one answer back.
pub const CP_METHOD_QUERIES_ANSWER: &str = "queries.answer";

/// The local query log (milestone-10.md section 10.1), `0600 root`,
/// append-only. Not deleted by `punarctl privacy purge`.
pub const QUERIES_LOG_PATH: &str = "/var/lib/punar/agents/queries.jsonl";

/// Query-log retention, age half (milestone-10.md section 10.1): longer
/// than any data it describes, on purpose.
pub const QUERY_LOG_RETENTION_DAYS: u32 = 365;

/// Query-log retention, size half — whichever binds first.
pub const QUERY_LOG_MAX_RECORDS: usize = 10_000;

/// `enrollment.json` key carrying the scopes the organization asked for at
/// enrollment. Absent key ⇒ **empty set**, never a permissive default
/// (milestone-10.md section 9.2).
pub const ENROLLMENT_SCOPES_KEY: &str = "remote_query_scopes";

/// Hard cap on queries drained in one sync pass. A pull is a courtesy on a
/// hook that already runs; an unbounded drain would let the control plane
/// decide how long a reconcile pass takes.
pub const MAX_QUERIES_PER_SYNC: usize = 16;

/// The section 8.3 refusal list, in the user's words. Printed by `punarctl
/// privacy queries` and by every surface that renders what an
/// administrator may never receive. The daemon's copy always wins so the
/// CLI and the daemon cannot drift apart.
pub const NEVER_ANSWERED: &[&str] = &[
    "prompts and conversation content",
    "source code, file contents, diffs",
    "file paths (zone classes only)",
    "per-file access records",
    "command lines, argv, environment variables",
    "secret values and credential material",
    "pids, cgroup paths, process trees",
    "audit event payloads",
    "anything outside the granted scope",
];

// ---------------------------------------------------------------------------
// The closed scope enum (milestone-10.md section 8.1, SPEC section 21.2)
// ---------------------------------------------------------------------------

/// The four remote-query scopes — one per SPEC section 21.2 observation
/// level. There is no wildcard, no `all`, and no free text; `device_builtin_max`
/// of milestone-10.md section 9.2 *is* this enum, and no configuration can
/// add a fifth value.
///
/// Declaration order is level order, and [`Ord`] follows it, so a
/// [`ScopeSet`] prints and compares from coarsest to most sensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryScope {
    /// Level 1 — which agents are active, which are unmanaged, what is
    /// suspected.
    Inventory,
    /// Level 2 — effective permissions, read back from the org's own
    /// policy.
    Authority,
    /// Level 3 — the `ledger-summary.json` projection verbatim.
    ResourceSummary,
    /// Level 4 — Level-4 event *references* only (`{event_id, event_type,
    /// timestamp}`).
    SecurityEvents,
}

impl QueryScope {
    /// Every scope this device can ever answer, coarsest first. This slice
    /// is `device_builtin_max`.
    pub const ALL: [QueryScope; 4] = [
        QueryScope::Inventory,
        QueryScope::Authority,
        QueryScope::ResourceSummary,
        QueryScope::SecurityEvents,
    ];

    /// The wire spelling (snake_case).
    pub fn as_str(self) -> &'static str {
        match self {
            QueryScope::Inventory => "inventory",
            QueryScope::Authority => "authority",
            QueryScope::ResourceSummary => "resource_summary",
            QueryScope::SecurityEvents => "security_events",
        }
    }

    /// The SPEC section 21.2 observation level this scope corresponds to.
    pub fn level(self) -> u8 {
        match self {
            QueryScope::Inventory => 1,
            QueryScope::Authority => 2,
            QueryScope::ResourceSummary => 3,
            QueryScope::SecurityEvents => 4,
        }
    }

    /// Parse a wire value. An unrecognised string is **`None`** — the
    /// caller refuses it as `out_of_scope` rather than answering
    /// best-effort (milestone-10.md section 8.1).
    pub fn from_wire(value: &str) -> Option<QueryScope> {
        QueryScope::ALL.into_iter().find(|s| s.as_str() == value)
    }

    /// The closed vocabulary as one human phrase, for refusal messages.
    pub fn vocabulary() -> String {
        join_words(&QueryScope::ALL.map(|s| s.as_str().to_string()))
    }
}

/// A sorted, de-duplicated set of scopes. Serializes as a JSON array of
/// wire spellings; deserializes leniently is **not** offered — use
/// [`ScopeSet::parse_json`], which reports what it could not recognise
/// instead of silently dropping it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScopeSet(Vec<QueryScope>);

impl ScopeSet {
    /// The empty set — the fail-closed value (milestone-10.md section 9.2).
    pub fn empty() -> ScopeSet {
        ScopeSet(Vec::new())
    }

    /// Parse a JSON array of scope strings. Returns the recognised set and,
    /// separately, every value that was **not** recognised — a caller that
    /// wants to complain can, and a caller that fails closed still gets a
    /// set that contains only real scopes.
    pub fn parse_json(value: Option<&Value>) -> (ScopeSet, Vec<String>) {
        let Some(Value::Array(items)) = value else {
            return (ScopeSet::empty(), Vec::new());
        };
        let mut scopes = Vec::new();
        let mut unrecognised = Vec::new();
        for item in items {
            match item.as_str() {
                Some(text) => match QueryScope::from_wire(text) {
                    Some(scope) => scopes.push(scope),
                    None => unrecognised.push(text.to_string()),
                },
                None => unrecognised.push(item.to_string()),
            }
        }
        (ScopeSet::from_iter(scopes), unrecognised)
    }

    pub fn contains(&self, scope: QueryScope) -> bool {
        self.0.contains(&scope)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = QueryScope> + '_ {
        self.0.iter().copied()
    }

    /// Set intersection — the operation authorization is made of.
    pub fn intersect(&self, other: &ScopeSet) -> ScopeSet {
        ScopeSet::from_iter(self.iter().filter(|s| other.contains(*s)))
    }

    /// Wire spellings, coarsest first.
    pub fn as_words(&self) -> Vec<String> {
        self.0.iter().map(|s| s.as_str().to_string()).collect()
    }

    /// `"inventory and authority"` / `"nothing"` — refusal-message prose.
    pub fn to_prose(&self) -> String {
        if self.0.is_empty() {
            "nothing".to_string()
        } else {
            join_words(&self.as_words())
        }
    }
}

/// Build from any iterator, sorting and de-duplicating.
///
/// The standard trait rather than an inherent `from_iter`: an inherent
/// method with that name shadows `FromIterator` at every call site and is
/// exactly what `clippy::should_implement_trait` warns about. Call sites
/// are unchanged — `ScopeSet::from_iter(…)` resolves here.
impl FromIterator<QueryScope> for ScopeSet {
    fn from_iter<I: IntoIterator<Item = QueryScope>>(items: I) -> ScopeSet {
        let mut scopes: Vec<QueryScope> = items.into_iter().collect();
        scopes.sort_unstable();
        scopes.dedup();
        ScopeSet(scopes)
    }
}

fn join_words(words: &[String]) -> String {
    match words {
        [] => String::new(),
        [one] => one.clone(),
        [head @ .., last] => format!("{} and {last}", head.join(", ")),
    }
}

// ---------------------------------------------------------------------------
// What the device fetched (milestone-10.md sections 7.2, 13.3)
// ---------------------------------------------------------------------------

/// One question the device **pulled** from the control plane.
///
/// `requested_scope` is deliberately a `String`, not a [`QueryScope`]: an
/// unrecognised value must be *refusable* (and auditable, and printable in
/// the user's query log), not unparseable. Untrusted input keeps its
/// untrusted type until [`authorize`] has looked at it.
///
/// The field list is the whole field list. There is no `payload`, no
/// `filter`, no `path`, no `expression` — nothing an administrator could
/// use to ask for something the scope vocabulary cannot name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingQuery {
    pub query_id: String,
    /// A fixture string asserted by the organization — **not** an
    /// authenticated principal. Every surface that renders it says so
    /// (milestone-10.md section 9.1); there is no IdP in M10.
    pub requesting_admin: String,
    pub organization: String,
    /// Untrusted. See the struct docs.
    pub requested_scope: String,
    /// Optionally narrows the answer to one session. It may never widen it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub received_at: String,
}

/// Longest identifier, admin string or organization name this device will
/// accept from a control plane. Generous for a real identity, far too small
/// to be a payload.
pub const QUERY_FIELD_MAX_BYTES: usize = 256;

/// Longest `requested_scope` string. It is refused as `out_of_scope` unless
/// it is one of four short words; the bound exists so the *refusal* is also
/// cheap to log and safe to print.
pub const QUERY_SCOPE_MAX_BYTES: usize = 64;

impl PendingQuery {
    /// Validate a question **fetched from a control plane** before this
    /// device does anything with it.
    ///
    /// # Why this exists (SPEC section 59.4)
    ///
    /// milestone-10.md law 2 says the transport is not the authority, and
    /// [`authorize`] makes that true for *scope*. It is not, by itself,
    /// true for the rest of the record: every other field of a
    /// [`PendingQuery`] is chosen by whatever answered `queries.pending`,
    /// and those fields do not merely get logged — they are used as
    /// **keys and identifiers** by the data owner. A compromised control
    /// plane that can choose them can therefore reach past the scope
    /// check without ever widening a scope:
    ///
    /// - `session_id` is a ledger lookup key. The shipped
    ///   `audit-event.json` pattern for it is `^agt_[A-Za-z0-9]+$`; a
    ///   value outside that pattern is both a schema violation and, because
    ///   ledger records are files named after the session, a **path**.
    /// - `requesting_admin`, `requested_scope` and the timestamp are
    ///   required, non-empty, pattern-checked audit fields. An empty or
    ///   malformed one makes the `admin.ai_query` event fail
    ///   [`crate::audit::validate_event_schema`], so the writer refuses it
    ///   — and a remote party that can suppress its own audit record has
    ///   defeated SPEC 51.1 while still receiving an answer.
    /// - All of them are rendered by `punarctl privacy queries`, the SPEC
    ///   24.2 surface. Control characters there are a terminal-forgery
    ///   primitive against the one screen that tells a user who asked
    ///   about them — the same class of harm that put `alerts.json` in a
    ///   root-owned directory (milestone-10.md section 5.3).
    /// - All of them are appended to a 365-day log. Unbounded strings on a
    ///   hook that runs every reconcile period are a disk-fill primitive
    ///   handed to the control plane.
    ///
    /// The rule is the M9 one, verbatim (`approval::validate_reason`):
    /// **bounded, single-line, printable** — plus the shipped
    /// `agt_` pattern where the field is an agent session id.
    ///
    /// A question that fails here is **not** recorded as a refusal. A
    /// refusal is a decision about a question; this is a thing that never
    /// became a question. Recording it would mean writing attacker-chosen
    /// bytes into the user's privacy log to prove that someone sent
    /// garbage, which is the disk-fill primitive rather than a defence
    /// against it. The caller answers with an error frame, the query stays
    /// pending on the control plane, and nothing leaves this device.
    pub fn validate(&self) -> Result<(), String> {
        printable_field("query_id", &self.query_id, QUERY_FIELD_MAX_BYTES)?;
        printable_field(
            "requesting_admin",
            &self.requesting_admin,
            QUERY_FIELD_MAX_BYTES,
        )?;
        printable_field("organization", &self.organization, QUERY_FIELD_MAX_BYTES)?;
        printable_field(
            "requested_scope",
            &self.requested_scope,
            QUERY_SCOPE_MAX_BYTES,
        )?;
        if !crate::time::is_rfc3339_timestamp(&self.received_at) {
            return Err(format!(
                "received_at {:?} must be an RFC 3339 timestamp",
                self.received_at
            ));
        }
        // The narrowing key is an agent session id or it is nothing. This
        // single line is what stops a control-plane string from becoming a
        // filesystem path and from becoming an unwritable audit event.
        if let Some(session_id) = self.session_id.as_deref()
            && !crate::agent::session_id_ok(session_id)
        {
            return Err(format!(
                "session_id {session_id:?} must match ^agt_[A-Za-z0-9]+$ (the shipped \
                 audit-event.json pattern); a narrowing key is an agent session id or \
                 it is nothing"
            ));
        }
        Ok(())
    }
}

/// One bounded, single-line, printable field. Non-empty after trimming,
/// at most `max` bytes, and free of control characters.
fn printable_field(name: &str, value: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{name} is required and must not be blank"));
    }
    if value.len() > max {
        return Err(format!(
            "{name} must be at most {max} bytes; this one is {}",
            value.len()
        ));
    }
    if let Some(c) = value.chars().find(|c| c.is_control()) {
        return Err(format!(
            "{name} must be a single line of printable text; found {c:?}"
        ));
    }
    Ok(())
}

/// `allow` | `deny` — the shipped `audit-event.json` decision spelling, so
/// the query log and the audit event cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDecision {
    Allow,
    Deny,
}

impl AuthorizationDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthorizationDecision::Allow => "allow",
            AuthorizationDecision::Deny => "deny",
        }
    }
}

/// What came back, in one word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultCategory {
    Answered,
    Refused,
}

impl ResultCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            ResultCategory::Answered => "answered",
            ResultCategory::Refused => "refused",
        }
    }
}

/// The single refusal reason M10 ships, and the new wire error code
/// (milestone-10.md section 13.1). It is deliberately **not** `denied`:
/// `denied` means *you* may not, `out_of_scope` means *this device* was
/// never granted it, and collapsing them would make the query log unable to
/// tell an admin's missing role from a device's missing grant.
pub const REFUSAL_OUT_OF_SCOPE: &str = "out_of_scope";

/// The outcome of the section 9.2 intersection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    pub decision: AuthorizationDecision,
    /// The scope that may be answered — `Some` only on `allow`.
    pub granted_scope: Option<QueryScope>,
    /// `out_of_scope` on a refusal, `None` on an allow.
    pub refusal_reason: Option<&'static str>,
    /// The SPEC section 73 refusal text: what was asked, what is
    /// permitted, which policy, and who can change it. Empty on an allow.
    pub message: String,
}

impl Authorization {
    pub fn is_allowed(&self) -> bool {
        self.decision == AuthorizationDecision::Allow
    }

    pub fn result_category(&self) -> ResultCategory {
        match self.decision {
            AuthorizationDecision::Allow => ResultCategory::Answered,
            AuthorizationDecision::Deny => ResultCategory::Refused,
        }
    }
}

// ---------------------------------------------------------------------------
// org_granted — read from local state, never from the request
// ---------------------------------------------------------------------------

/// What *this device's own* `enrollment.json` says the organization was
/// granted. Constructed only by [`read_org_granted_scopes`]; there is no
/// public constructor that takes a scope set off the wire, because a
/// courier that can widen its own authority is not a courier
/// (SPEC section 59.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgGrant {
    pub enrolled: bool,
    /// The organization's display name, for refusal prose.
    pub organization: Option<String>,
    /// `Acme · eng-ai-v3` — the policy citation the refusal cites.
    pub policy_citation: Option<String>,
    /// The intersection's middle term.
    pub scopes: ScopeSet,
    /// Values in `remote_query_scopes` this build does not recognise. Kept
    /// so a surface can say "the organization asked for something this
    /// device has no name for" instead of silently ignoring it.
    pub unrecognised: Vec<String>,
}

impl OrgGrant {
    /// The personal-device value: not enrolled, nothing granted. This is
    /// also what a missing, unreadable or corrupt `enrollment.json`
    /// produces — **fail closed** (milestone-10.md section 9.2, gate B).
    pub fn none() -> OrgGrant {
        OrgGrant {
            enrolled: false,
            organization: None,
            policy_citation: None,
            scopes: ScopeSet::empty(),
            unrecognised: Vec::new(),
        }
    }
}

/// Read `org_granted` from the local `enrollment.json`.
///
/// This function is the reason law 2 is structural rather than aspirational:
/// the data owner calls it with a **path**, not with anything that arrived
/// over a wire. Absent file ⇒ [`OrgGrant::none`]. Absent
/// `remote_query_scopes` key ⇒ empty set, not a permissive default: an
/// organization that never asked for a scope never gets one. A corrupt file
/// ⇒ empty set as well; refusing everything is the safe reading of an
/// unreadable grant.
pub fn read_org_granted_scopes(enrollment_path: &Path) -> OrgGrant {
    let Ok(text) = std::fs::read_to_string(enrollment_path) else {
        return OrgGrant::none();
    };
    let Ok(document) = serde_json::from_str::<Value>(&text) else {
        return OrgGrant::none();
    };
    let organization = document
        .get("org")
        .and_then(|o| o.get("display_name").or_else(|| o.get("name")))
        .and_then(Value::as_str)
        .map(str::to_string);
    let policy_id = document
        .get("policy_files")
        .and_then(Value::as_array)
        .and_then(|files| files.first())
        .and_then(Value::as_str)
        .map(|f| f.trim_end_matches(".json").to_string());
    let policy_citation = match (&organization, policy_id) {
        (Some(org), Some(policy)) => Some(format!("{org} · {policy}")),
        (Some(org), None) => Some(org.clone()),
        _ => None,
    };
    let (scopes, unrecognised) = ScopeSet::parse_json(document.get(ENROLLMENT_SCOPES_KEY));
    OrgGrant {
        enrolled: true,
        organization,
        policy_citation,
        scopes,
        unrecognised,
    }
}

// ---------------------------------------------------------------------------
// The three-way intersection (milestone-10.md section 9.2)
// ---------------------------------------------------------------------------

/// `answered_scope = requested ∩ org_granted ∩ device_builtin_max`.
///
/// `device_builtin_max` is [`QueryScope::ALL`] and enters the computation
/// by construction: an unrecognised `requested` string cannot become a
/// [`QueryScope`] at all, so it can never survive the intersection.
///
/// Fail closed at every step, with a SPEC section 73 message naming what
/// was asked, what is permitted, which policy carries it, and who can
/// change it.
pub fn authorize(requested: &str, grant: &OrgGrant) -> Authorization {
    let refuse = |message: String| Authorization {
        decision: AuthorizationDecision::Deny,
        granted_scope: None,
        refusal_reason: Some(REFUSAL_OUT_OF_SCOPE),
        message,
    };

    // Step 1 — requested ∩ device_builtin_max. An unrecognised value is
    // refused, never answered best-effort.
    let Some(scope) = QueryScope::from_wire(requested) else {
        return refuse(refusal_message(requested, grant, UnknownScope::Yes));
    };

    // Step 2 — ∩ org_granted, read from local state by the caller.
    if !grant.scopes.contains(scope) {
        return refuse(refusal_message(scope.as_str(), grant, UnknownScope::No));
    }

    Authorization {
        decision: AuthorizationDecision::Allow,
        granted_scope: Some(scope),
        refusal_reason: None,
        message: String::new(),
    }
}

enum UnknownScope {
    Yes,
    No,
}

/// The section 73 refusal text. Five lines: what happened, what this device
/// does answer, why this one is not among them, which policy says so, and
/// the next step — including the sentence that matters most, that neither
/// the device nor the administrator can widen the grant locally.
fn refusal_message(requested: &str, grant: &OrgGrant, unknown: UnknownScope) -> String {
    let mut out = format!("Refused · {requested}\n");
    match (&grant.organization, grant.enrolled) {
        (Some(org), true) if !grant.scopes.is_empty() => {
            out.push_str(&format!(
                "This device answers {} queries for {org}.\n",
                grant.scopes.to_prose()
            ));
        }
        (_, true) => {
            out.push_str(
                "This device answers no remote queries: no scope was granted at \
                 enrollment.\n",
            );
        }
        (_, false) => {
            out.push_str("This device answers no remote queries: no organization is enrolled.\n");
        }
    }
    match unknown {
        UnknownScope::Yes => out.push_str(&format!(
            "{requested:?} is not a scope this device has a name for · the vocabulary \
             is {}.\n",
            QueryScope::vocabulary()
        )),
        UnknownScope::No => out.push_str(&format!("{requested} was not granted at enrollment.\n")),
    }
    out.push_str(&format!(
        "Policy · {} · {ENROLLMENT_SCOPES_KEY}\n",
        grant
            .policy_citation
            .clone()
            .unwrap_or_else(|| "personal defaults".to_string())
    ));
    out.push_str(
        "Next step · the organization grants the scope at enrollment; the device does \
         not widen it locally, and neither can an administrator.",
    );
    out
}

// ---------------------------------------------------------------------------
// The local query log (milestone-10.md section 10.1, SPEC section 51.1)
// ---------------------------------------------------------------------------

/// How many records of each kind an answer carried. The *shape* of what
/// left the device, deliberately without a second copy of the contents
/// (milestone-10.md section 10.1: "the answered payload is not stored").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordCounts {
    pub sessions: u32,
    pub detections: u32,
    pub security_events: u32,
}

/// One line of `/var/lib/punar/agents/queries.jsonl`.
///
/// All six SPEC 51.1 fields are present — requesting admin, requested
/// scope, device, timestamp, result category, authorization decision — plus
/// the granted scope (without which the decision is not reconstructable)
/// and the honesty flag on the admin identity (milestone-10.md section 9.1).
///
/// What is *not* present is the point: no payload, no paths, no pids, no
/// prompts. The record says who asked what and what was decided, and that
/// is all it is able to say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRecord {
    pub query_id: String,
    pub received_at: String,
    pub answered_at: String,
    pub requesting_admin: String,
    /// Always `false` in M10: there is no IdP, and pretending otherwise
    /// would be the exact dishonesty SPEC section 1.22 forbids.
    pub admin_identity_verified: bool,
    pub organization: String,
    pub device_id: String,
    pub requested_scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_scope: Option<QueryScope>,
    pub authorization_decision: AuthorizationDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
    pub result_category: ResultCategory,
    pub record_counts: RecordCounts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_event_id: Option<String>,
}

/// The `query.answer` result punard posts back to the control plane
/// **verbatim** (milestone-10.md section 13.1). The transport never
/// assembles it and never edits it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryAnswerResult {
    pub query_id: String,
    pub authorization_decision: AuthorizationDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_scope: Option<QueryScope>,
    pub result_category: ResultCategory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
    /// The section 73 refusal text, so the administrator's client renders
    /// the same words the user's query log shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_event_id: Option<String>,
}

/// Where the query log lives and how long it is kept — rendered by
/// `punarctl privacy queries` from the daemon's own values, never from a
/// CLI-side constant that could drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryLogStorage {
    pub path: String,
    pub retention_days: u32,
    pub max_records: usize,
    /// The boundary sentence: this log is a record of what the
    /// **organization** did, so a purge of the user's own data does not
    /// remove it (milestone-10.md section 10.1).
    pub purged_by_privacy_purge: bool,
}

impl Default for QueryLogStorage {
    fn default() -> Self {
        QueryLogStorage {
            path: QUERIES_LOG_PATH.to_string(),
            retention_days: QUERY_LOG_RETENTION_DAYS,
            max_records: QUERY_LOG_MAX_RECORDS,
            purged_by_privacy_purge: false,
        }
    }
}

/// `queries.list` params — both optional, both filters, neither able to
/// widen anything. The filtering happens **daemon-side** so a scripted
/// consumer and the human renderer cannot disagree about what `--since`
/// means.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueriesListParams {
    /// Only queries decided at or after this RFC 3339 timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// At most this many, most recent last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// The `queries.list` result (milestone-10.md sections 10.3, 13.1). It
/// carries everything the section 24.2 surface prints, so the CLI invents
/// nothing: the daemon's `never_answered` and `granted_scopes` are the same
/// values the daemon enforces.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueriesListResult {
    pub queries: Vec<QueryRecord>,
    pub enrolled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_citation: Option<String>,
    pub granted_scopes: ScopeSet,
    /// Always `false` in M10 (section 9.1).
    pub admin_identity_verified: bool,
    pub never_answered: Vec<String>,
    pub storage: QueryLogStorage,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn grant(scopes: &[QueryScope]) -> OrgGrant {
        OrgGrant {
            enrolled: true,
            organization: Some("Acme Engineering".to_string()),
            policy_citation: Some("Acme Engineering · eng-baseline-v12".to_string()),
            scopes: ScopeSet::from_iter(scopes.iter().copied()),
            unrecognised: Vec::new(),
        }
    }

    #[test]
    fn the_scope_vocabulary_is_closed_and_level_ordered() {
        assert_eq!(QueryScope::ALL.len(), 4);
        let levels: Vec<u8> = QueryScope::ALL.iter().map(|s| s.level()).collect();
        assert_eq!(levels, vec![1, 2, 3, 4]);
        for scope in QueryScope::ALL {
            assert_eq!(QueryScope::from_wire(scope.as_str()), Some(scope));
        }
        // No wildcard, no "all", no free text.
        for probe in ["all", "*", "everything", "", "INVENTORY", "inventory "] {
            assert_eq!(
                QueryScope::from_wire(probe),
                None,
                "{probe:?} must not parse"
            );
        }
    }

    fn pending() -> PendingQuery {
        PendingQuery {
            query_id: "qry_7c1a".into(),
            requesting_admin: "secops@acme.com".into(),
            organization: "acme.com".into(),
            requested_scope: "inventory".into(),
            session_id: None,
            received_at: "2026-08-25T14:02:09Z".into(),
        }
    }

    /// Law 2's other half: the fields that are not the scope are still
    /// chosen by the control plane, and they are used as keys — a ledger
    /// lookup key, three pattern-checked audit fields, and four strings on
    /// the SPEC 24.2 surface. Each probe below is one way to reach past the
    /// scope check without widening a scope (SPEC 59.4).
    #[test]
    fn a_question_this_device_cannot_read_is_not_a_question_it_answers() {
        assert_eq!(pending().validate(), Ok(()));

        let mut blank = pending();
        blank.requesting_admin = String::new();
        assert!(
            blank.validate().is_err(),
            "an empty admin makes the audit event unwritable, and a remote party \
             that can suppress its own audit record has defeated SPEC 51.1"
        );

        let mut blank_scope = pending();
        blank_scope.requested_scope = String::new();
        assert!(
            blank_scope.validate().is_err(),
            "audit `resource` is minLength 1"
        );

        for bad in [
            "not-an-agt-id",
            "../../../etc/passwd",
            "agt_ok/../../elsewhere",
            "",
        ] {
            let mut narrowed = pending();
            narrowed.session_id = Some(bad.to_string());
            assert!(
                narrowed.validate().is_err(),
                "a narrowing key is an agent session id or it is nothing: {bad:?}"
            );
        }
        let mut good = pending();
        good.session_id = Some("agt_4f21c09ab3e1".into());
        assert_eq!(good.validate(), Ok(()));

        for escape in ["\u{1b}[2J", "line one\nline two", "tab\there"] {
            let mut forged = pending();
            forged.requesting_admin = format!("cio@acme.com{escape}");
            assert!(
                forged.validate().is_err(),
                "a terminal escape on the section 24.2 surface is a forged card \
                 arriving through a different door: {escape:?}"
            );
        }

        let mut huge = pending();
        huge.organization = "a".repeat(QUERY_FIELD_MAX_BYTES + 1);
        assert!(
            huge.validate().is_err(),
            "a 365-day log is not a payload store"
        );

        let mut whenever = pending();
        whenever.received_at = "whenever".into();
        assert!(
            whenever.validate().is_err(),
            "audit `timestamp` is RFC 3339"
        );
    }

    #[test]
    fn an_unrecognised_scope_is_refused_not_best_effort_answered() {
        let auth = authorize("everything", &grant(&QueryScope::ALL));
        assert_eq!(auth.decision, AuthorizationDecision::Deny);
        assert_eq!(auth.refusal_reason, Some(REFUSAL_OUT_OF_SCOPE));
        assert!(auth.granted_scope.is_none());
        assert!(auth.message.contains("everything"), "{}", auth.message);
        assert!(auth.message.contains("inventory"), "{}", auth.message);
    }

    #[test]
    fn a_granted_scope_is_allowed_and_carries_nothing_else() {
        let auth = authorize("inventory", &grant(&[QueryScope::Inventory]));
        assert!(auth.is_allowed());
        assert_eq!(auth.granted_scope, Some(QueryScope::Inventory));
        assert_eq!(auth.result_category(), ResultCategory::Answered);
        assert!(auth.message.is_empty());
        // Requesting `inventory` never yields more than `inventory`.
        assert_ne!(auth.granted_scope, Some(QueryScope::ResourceSummary));
    }

    #[test]
    fn an_ungranted_scope_is_refused_naming_what_is_permitted() {
        let auth = authorize(
            "resource_summary",
            &grant(&[QueryScope::Inventory, QueryScope::Authority]),
        );
        assert_eq!(auth.decision, AuthorizationDecision::Deny);
        // SPEC section 73: what was asked, what is permitted, which policy,
        // and the next step.
        assert!(auth.message.starts_with("Refused · resource_summary"));
        assert!(
            auth.message.contains("inventory and authority"),
            "{}",
            auth.message
        );
        assert!(
            auth.message.contains("Acme Engineering"),
            "{}",
            auth.message
        );
        assert!(
            auth.message.contains("remote_query_scopes"),
            "{}",
            auth.message
        );
        assert!(auth.message.contains("Next step ·"), "{}", auth.message);
        assert!(
            auth.message.contains("neither can an administrator"),
            "{}",
            auth.message
        );
    }

    #[test]
    fn absent_grant_key_is_the_empty_set_not_a_permissive_default() {
        let dir = std::env::temp_dir().join(format!("punar-query-grant-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("enrollment.json");

        // Enrolled, but the organization never asked for a scope.
        std::fs::write(
            &path,
            json!({
                "version": 1,
                "org": {"id": "acme", "name": "Acme", "display_name": "Acme Engineering",
                        "domain": "acme.com"},
                "policy_files": ["eng-baseline-v12.json"]
            })
            .to_string(),
        )
        .unwrap();
        let read = read_org_granted_scopes(&path);
        assert!(read.enrolled);
        assert!(read.scopes.is_empty(), "absent key must mean nothing");
        for scope in QueryScope::ALL {
            assert_eq!(
                authorize(scope.as_str(), &read).decision,
                AuthorizationDecision::Deny
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// SPEC section 59.4, the load-bearing test: a grant that was revoked
    /// **locally** is gone, whatever the request or the control plane says.
    /// There is no parameter through which the claim could arrive, which is
    /// why this test reads as a file rewrite rather than as a forged field.
    #[test]
    fn a_locally_revoked_grant_is_refused_however_the_request_is_dressed() {
        let dir = std::env::temp_dir().join(format!("punar-query-revoke-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("enrollment.json");
        let document = |scopes: Value| {
            json!({
                "version": 1,
                "org": {"id": "acme", "name": "Acme", "display_name": "Acme Engineering",
                        "domain": "acme.com"},
                "policy_files": ["eng-baseline-v12.json"],
                "remote_query_scopes": scopes
            })
            .to_string()
        };

        std::fs::write(&path, document(json!(["inventory", "resource_summary"]))).unwrap();
        assert!(authorize("resource_summary", &read_org_granted_scopes(&path)).is_allowed());

        // The organization's grant is narrowed on this device.
        std::fs::write(&path, document(json!(["inventory"]))).unwrap();
        let after = read_org_granted_scopes(&path);
        assert!(!authorize("resource_summary", &after).is_allowed());
        assert!(authorize("inventory", &after).is_allowed());

        // And with the file gone entirely, nothing is answerable at all —
        // gate B of milestone-10.md section 11, independent of gate A.
        std::fs::remove_file(&path).unwrap();
        let none = read_org_granted_scopes(&path);
        assert_eq!(none, OrgGrant::none());
        for scope in QueryScope::ALL {
            let auth = authorize(scope.as_str(), &none);
            assert_eq!(auth.decision, AuthorizationDecision::Deny);
            assert!(
                auth.message.contains("no organization is enrolled"),
                "{}",
                auth.message
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_corrupt_enrollment_file_fails_closed() {
        let dir = std::env::temp_dir().join(format!("punar-query-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("enrollment.json");
        std::fs::write(&path, "{ not json").unwrap();
        assert_eq!(read_org_granted_scopes(&path), OrgGrant::none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unrecognised_grant_values_are_reported_not_silently_dropped() {
        let (scopes, unrecognised) =
            ScopeSet::parse_json(Some(&json!(["inventory", "telepathy", 7])));
        assert_eq!(scopes.as_words(), vec!["inventory"]);
        assert_eq!(unrecognised, vec!["telepathy".to_string(), "7".to_string()]);
    }

    #[test]
    fn scope_sets_sort_dedup_and_intersect() {
        let set = ScopeSet::from_iter([
            QueryScope::SecurityEvents,
            QueryScope::Inventory,
            QueryScope::Inventory,
        ]);
        assert_eq!(set.as_words(), vec!["inventory", "security_events"]);
        assert_eq!(set.len(), 2);
        let other = ScopeSet::from_iter([QueryScope::Inventory, QueryScope::Authority]);
        assert_eq!(set.intersect(&other).as_words(), vec!["inventory"]);
        assert_eq!(ScopeSet::empty().to_prose(), "nothing");
        assert_eq!(other.to_prose(), "inventory and authority");
    }

    /// The refusal list of milestone-10.md section 8.3 is structural: the
    /// wire types have no field that could carry the forbidden things, so
    /// there is nothing for a filter to forget.
    #[test]
    fn the_wire_types_have_no_field_for_the_never_answered_list() {
        let query = PendingQuery {
            query_id: "qry_1".into(),
            requesting_admin: "cio@acme.com".into(),
            organization: "acme.com".into(),
            requested_scope: "inventory".into(),
            session_id: None,
            received_at: "2026-08-25T14:02:09Z".into(),
        };
        let mut keys: Vec<String> = serde_json::to_value(&query)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "organization",
                "query_id",
                "received_at",
                "requested_scope",
                "requesting_admin"
            ]
        );
        for forbidden in [
            "prompt", "path", "cmdline", "argv", "env", "pid", "cgroup", "payload", "file",
            "secret", "token",
        ] {
            assert!(
                !keys.iter().any(|k| k.contains(forbidden)),
                "PendingQuery must have no {forbidden} field"
            );
        }

        let record = QueryRecord {
            query_id: "qry_1".into(),
            received_at: "2026-08-25T14:02:09Z".into(),
            answered_at: "2026-08-25T14:02:11Z".into(),
            requesting_admin: "secops@acme.com".into(),
            admin_identity_verified: false,
            organization: "acme.com".into(),
            device_id: "dev_1".into(),
            requested_scope: "resource_summary".into(),
            granted_scope: None,
            authorization_decision: AuthorizationDecision::Deny,
            refusal_reason: Some(REFUSAL_OUT_OF_SCOPE.to_string()),
            result_category: ResultCategory::Refused,
            record_counts: RecordCounts::default(),
            audit_event_id: Some("evt_611".into()),
        };
        let value = serde_json::to_value(&record).unwrap();
        // All six SPEC 51.1 fields survive a round trip.
        assert_eq!(value["requesting_admin"], "secops@acme.com");
        assert_eq!(value["requested_scope"], "resource_summary");
        assert_eq!(value["device_id"], "dev_1");
        assert_eq!(value["answered_at"], "2026-08-25T14:02:11Z");
        assert_eq!(value["result_category"], "refused");
        assert_eq!(value["authorization_decision"], "deny");
        assert_eq!(value["admin_identity_verified"], false);
        assert_eq!(record, serde_json::from_value(value).unwrap());
    }

    #[test]
    fn the_never_answered_list_is_the_section_8_3_list() {
        assert_eq!(NEVER_ANSWERED.len(), 9);
        let joined = NEVER_ANSWERED.join(" · ");
        for expected in [
            "prompts",
            "source code",
            "file paths",
            "command lines",
            "secret values",
            "audit event payloads",
            "outside the granted scope",
        ] {
            assert!(
                joined.contains(expected),
                "{expected} missing from {joined}"
            );
        }
    }

    #[test]
    fn the_query_log_is_not_deleted_by_a_privacy_purge() {
        let storage = QueryLogStorage::default();
        assert!(!storage.purged_by_privacy_purge);
        assert_eq!(storage.retention_days, 365);
        assert_eq!(storage.max_records, 10_000);
        assert_eq!(storage.path, QUERIES_LOG_PATH);
    }
}
