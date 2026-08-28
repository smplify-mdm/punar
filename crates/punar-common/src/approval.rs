//! Approval gates and just-in-time privilege grants (SPEC sections 28, 48;
//! docs/api/ipc.md sections 14–15; Milestone 9).
//!
//! # The schema is the contract, and it is not extended
//!
//! `schemas/audit/approval.json` shipped before this milestone with exactly
//! nine required properties and `additionalProperties: false`. It has no
//! field for the originating request, the resolver, an execution result, a
//! consumption marker, or a TTL. **M9 conforms to it; it does not conform
//! to M9.** [`Approval`] is that document, byte for byte. Everything else
//! travels as a **sibling field of [`ApprovalEnvelope`]**, outside the
//! document — the same law M8 applied to the ledger summary schema.
//!
//! Two consequences downstream code must not "fix":
//!
//! - [`ApprovalStatus`] is exactly `pending | approved | denied | expired`.
//!   Consumption of an approved credential approval is the sibling
//!   [`ApprovalEnvelope::consumed_at`], **not** a fifth status; execution of
//!   an approved capability approval is the sibling
//!   [`ApprovalEnvelope::execution`], **not** a status.
//! - `schemas/audit/audit-event.json` is not extended either. The link
//!   between an approval and the trail runs approval → event
//!   ([`Execution::audit_event_id`], exactly as Plate D-003 prints "audit
//!   evt_501"), plus the `approval.resolve` event whose `resource` **is**
//!   the `apr_` id. Both directions exist; zero schema bytes changed.
//!
//! # What a secret never touches
//!
//! Nothing in this module can hold a secret value. A credential approval
//! names its **class** (`aws-dev`) in `resource` and nothing else: no token,
//! no token id, no hash (SPEC section 53). The `reason` is requester-authored
//! free text and *is* displayed (SPEC section 73 requires "why" and "who
//! requested it"); [`validate_reason`] bounds it to one printable line so it
//! cannot forge a dialog, and the honest limit — Punar cannot redact a
//! secret a requester types into their own justification — is stated in
//! docs/api/ipc.md section 15 rather than papered over.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::descriptor::Risk;
use crate::principal::PrincipalKind;

// ---------------------------------------------------------------------------
// Constants (docs/api/ipc.md section 14.4; design plan sections 4.1–4.2, 7)
// ---------------------------------------------------------------------------

/// Id prefix bound by `schemas/common/defs.json#/$defs/approval_id`.
pub const APPROVAL_ID_PREFIX: &str = "apr_";
/// Id prefix for a just-in-time privilege grant (SPEC section 48).
pub const GRANT_ID_PREFIX: &str = "gnt_";

/// Default seconds a pending approval stays answerable — Plate D-003's
/// countdown verbatim (`Expires 04:59`, amber under a minute).
pub const APPROVAL_TTL_DEFAULT_SECS: u64 = 300;
/// Floor for a requester-supplied TTL.
pub const APPROVAL_TTL_MIN_SECS: u64 = 15;
/// Ceiling for a requester-supplied TTL. **The maximum is policy-owned**: a
/// requester may ask for less and never for more.
pub const APPROVAL_TTL_MAX_SECS: u64 = APPROVAL_TTL_DEFAULT_SECS;

/// Pending approvals allowed device-wide before `approvals.create` refuses.
/// Approval fatigue is the classic attack on an approval gate, so the
/// refusal is in code, not in advice.
pub const MAX_PENDING_APPROVALS: usize = 8;
/// Pending approvals allowed per requester id.
pub const MAX_PENDING_PER_REQUESTER: usize = 2;
/// Retained records (pending + recently resolved) before the oldest
/// resolved/expired record is evicted.
pub const MAX_APPROVAL_RECORDS: usize = 200;
/// Bound on one persisted record (design plan section 4.1).
pub const APPROVAL_RECORD_MAX_BYTES: usize = 4096;
/// `result` string for a refusal caused by the pending bounds.
pub const RESULT_APPROVAL_FLOOD: &str = "approval_flood";
/// `result` string for an AI agent trying to answer an approval.
pub const RESULT_SELF_APPROVAL_REFUSED: &str = "self_approval_refused";
/// `result` string for an AI agent asking for a privilege window.
pub const RESULT_AGENT_PRIVILEGE_REFUSED: &str = "agent_privilege_refused";
/// `result` string for an AI agent trying to **author** an approval — the
/// card's requester line, its reason and its contract are what a human
/// reads before consenting, so writing them is a human's act, not an
/// agent's (docs/api/ipc.md section 14.2).
pub const RESULT_AGENT_CREATE_REFUSED: &str = "agent_create_refused";

/// Maximum bytes of requester-authored justification.
pub const REASON_MAX_BYTES: usize = 512;

/// Default minutes of privilege a grant carries (SPEC section 48:
/// "Approved for 15 minutes.").
pub const GRANT_DEFAULT_MINUTES: u64 = 15;
/// Shortest grant window.
pub const GRANT_MIN_MINUTES: u64 = 1;
/// Longest grant window. A policy value, not a constant of nature — but a
/// value M9 owns, because "how long may privilege last" is not a requester's
/// decision (SPEC sections 48, 60).
pub const GRANT_MAX_MINUTES: u64 = 60;

/// The shell's approval summary file (docs/api/ipc.md section 15).
///
/// Deliberately **not** `/run/punar/approvals.json`: that directory contains
/// world-readable display summaries. Approval details are group-readable and
/// live behind `/run/punard`'s `0750 root:punar` traversal boundary, so an
/// unrelated local account cannot even name them. Root ownership of both
/// directories prevents replacement by an unprivileged process.
pub const APPROVALS_SUMMARY_FILE: &str = "/run/punard/approvals.json";

/// Subdirectory of the punard state directory holding approval records.
pub const APPROVALS_DIR_NAME: &str = "approvals";
/// Subdirectory of the punard state directory holding privilege grants.
pub const GRANTS_DIR_NAME: &str = "grants";

// ---------------------------------------------------------------------------
// The schema document (schemas/audit/approval.json), unmodified
// ---------------------------------------------------------------------------

/// Approval lifecycle status — the shipped enum, not one value wider.
///
/// `approved`, `denied` and `expired` are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

impl ApprovalStatus {
    /// Every status, in schema order.
    pub const ALL: [ApprovalStatus; 4] = [
        ApprovalStatus::Pending,
        ApprovalStatus::Approved,
        ApprovalStatus::Denied,
        ApprovalStatus::Expired,
    ];

    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
            ApprovalStatus::Expired => "expired",
        }
    }

    /// Whether the status can still change (only `pending` can).
    pub fn is_terminal(self) -> bool {
        self != ApprovalStatus::Pending
    }
}

/// The principal that raised the request (`requester` in the schema).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requester {
    /// `type` on the wire; `kind` in Rust, where `type` is a keyword.
    #[serde(rename = "type")]
    pub kind: PrincipalKind,
    /// Agent session id (`agt_…`) for an AI agent, the username for a human.
    pub id: String,
}

/// **The section 28 approval object.** Serializes to exactly the nine
/// properties of `schemas/audit/approval.json`, in schema order, and
/// deserializes strictly — an unknown key here would mean someone extended
/// the document instead of the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub approval_id: String,
    pub requester: Requester,
    /// The human this approval is **routed to**. Only that person (or root)
    /// may answer it (docs/api/ipc.md section 14.5).
    pub user: String,
    /// The typed capability or method being requested.
    pub capability: String,
    /// The concrete argument, defined once for all three kinds so that
    /// `capability(resource)` reads as Plate D-003's contract block:
    /// desired state · credential class · grant window.
    pub resource: String,
    pub reason: String,
    pub risk: Risk,
    pub status: ApprovalStatus,
    pub expires_at: String,
}

// ---------------------------------------------------------------------------
// The envelope — every sibling field lives outside the document
// ---------------------------------------------------------------------------

/// Which request raised the approval; selects the sibling fields that are
/// meaningful and **who executes** (docs/api/ipc.md section 14.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// A `capabilities.set` gated by AI authority policy. punard executes it
    /// itself, immediately, when a human approves.
    CapabilitySet,
    /// A `credential.request` whose class policy is `request`. punard only
    /// flips the status; `punar-secrets` later calls `approvals.consume` and
    /// issues. The plaintext token never enters the daemon that writes
    /// `/etc` — which is the whole reason the broker is a separate service.
    CredentialRequest,
    /// A human's `punarctl privilege request`. punard writes the grant.
    PrivilegeRequest,
}

impl ApprovalKind {
    /// Every kind, in contract-table order.
    pub const ALL: [ApprovalKind; 3] = [
        ApprovalKind::CapabilitySet,
        ApprovalKind::CredentialRequest,
        ApprovalKind::PrivilegeRequest,
    ];

    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalKind::CapabilitySet => "capability_set",
            ApprovalKind::CredentialRequest => "credential_request",
            ApprovalKind::PrivilegeRequest => "privilege_request",
        }
    }

    /// Whether resolving this kind makes punard *do* something beyond
    /// flipping a status (section 14.6).
    pub fn executes_on_resolve(self) -> bool {
        match self {
            ApprovalKind::CapabilitySet | ApprovalKind::PrivilegeRequest => true,
            ApprovalKind::CredentialRequest => false,
        }
    }
}

/// The originating typed call, recorded verbatim so that resolution
/// re-derives what to execute **from punard's own record** — never from
/// what the approving client sends back (docs/api/ipc.md section 15: the
/// overlay's Approve sends only the `approval_id`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub method: String,
    pub params: Value,
}

/// The policy source that made this an approval rather than an allow or a
/// deny — the citation every surface prints (DESIGN_LANGUAGE section 8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCitation {
    /// Human-readable source name, e.g. `Personal defaults`.
    pub name: String,
    /// Machine id, e.g. `personal-defaults` or `eng-ai-v3`.
    pub policy_id: String,
}

/// Identity of the peer that answered the approval, recorded in full.
///
/// M9 cannot *prevent* an agent that launches a helper outside its own scope
/// from presenting as the console user (docs/api/ipc.md section 14.5 states
/// that limit rather than implying cryptographic proof of a human). What it
/// can do is make the escape **visible after the fact** — which is what this
/// record is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedBy {
    pub uid: u32,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    /// The peer's `/proc/<pid>/cgroup` body, verbatim, when readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
}

/// What happened when punard executed an approved request.
///
/// [`Execution::audit_event_id`] is **the link from an approval into the
/// audit trail**, and the pointer deliberately runs approval → event, as
/// Plate D-003 prints it and as the M8 ledger references events.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    /// `success` · `noop` · `apply_failed` · `verify_failed` · `denied`.
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_event_id: Option<String>,
    /// Set for a resolved `privilege_request`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// SPEC section 73 prose when the execution failed. Never an errno, and
    /// never anything a backend printed that could carry a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The record punard persists and serves: the schema document plus every
/// sibling M9 needs (docs/api/ipc.md section 14.3).
///
/// `jq .approval <file>` validates against `schemas/audit/approval.json`
/// unmodified — asserted in-VM by `m9-check` and on the host by
/// `tools/validate_schemas.py`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEnvelope {
    pub v: u64,
    /// **The** section 28 approval object. Nothing may be added to it.
    pub approval: Approval,
    pub kind: ApprovalKind,
    pub created_at: String,
    pub request: ApprovalRequest,
    /// The requesting peer's kernel-attested identity, for forensics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_peer: Option<RequesterPeer>,
    pub policy: PolicyCitation,
    /// The Plate D-003 contract line, e.g. `SetFirewall(disabled)`.
    pub contract: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<ResolvedBy>,
    /// Set when a `credential_request` approval is spent. A sibling field —
    /// **not** a fifth status value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<Execution>,
}

/// The requesting peer's credentials at `accept()` time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterPeer {
    pub uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_session_id: Option<String>,
}

impl ApprovalEnvelope {
    /// Whether this approval can still be answered at `now_secs`.
    pub fn is_answerable(&self, now_secs: u64) -> bool {
        self.approval.status == ApprovalStatus::Pending && !self.has_lapsed(now_secs)
    }

    /// Whether the wall clock has passed `expires_at`.
    ///
    /// An unparsable `expires_at` counts as **lapsed**: a record whose
    /// expiry cannot be reasoned about must not authorize anything.
    pub fn has_lapsed(&self, now_secs: u64) -> bool {
        match crate::time::unix_seconds_from_rfc3339(&self.approval.expires_at) {
            Some(expires) => now_secs >= expires,
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Privilege grants (SPEC section 48; docs/api/ipc.md section 14.8)
// ---------------------------------------------------------------------------

/// A time-boxed, single-capability privilege grant.
///
/// A grant is **only** ever produced by resolving a `privilege_request`
/// approval: there is no `privilege.grant` method and no `privilege.extend`
/// (docs/api/ipc.md section 14.2), so privilege cannot be minted without a
/// recorded human decision. It names exactly one capability — no wildcard,
/// no `--all` — and it is **never issued to an AI agent** (SPEC sections 48,
/// 60: agents get per-request approvals, never a time window).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub v: u64,
    pub grant_id: String,
    pub approval_id: String,
    pub uid: u32,
    pub user: String,
    pub capability: String,
    /// The justification, verbatim from the request (Plate D-012: it travels
    /// verbatim into the audit event).
    pub reason: String,
    pub granted_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

impl Grant {
    /// Whether this grant authorizes anything at `now_secs`.
    ///
    /// An unparsable `expires_at` counts as expired — fail closed.
    pub fn is_live(&self, now_secs: u64) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        crate::time::unix_seconds_from_rfc3339(&self.expires_at)
            .is_some_and(|expires| now_secs < expires)
    }
}

// ---------------------------------------------------------------------------
// The shell summary file (docs/api/ipc.md section 15)
// ---------------------------------------------------------------------------

/// One approval as the overlay renders it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SummaryApproval {
    pub approval_id: String,
    pub kind: ApprovalKind,
    pub status: ApprovalStatus,
    pub requester: SummaryRequester,
    pub user: String,
    pub capability: String,
    pub resource: String,
    pub risk: Risk,
    pub reason: String,
    pub contract: String,
    pub policy: PolicyCitation,
    pub created_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<Execution>,
}

/// The requester block of a summary row.
///
/// `agent_name` is **always `null` in Milestone 9**, deliberately. The
/// friendly name lives in `/run/punar/agents.json`, a `0644 punar:punar`
/// display file any local process can rewrite; copying a spoofable name into
/// the root-owned file whose entire purpose is to be unspoofable would
/// reintroduce the attack this file exists to prevent (a benign name over a
/// dangerous `apr_` id). The `agt_` id here is kernel-attested and is what
/// the identity-chain line must key on; a renderer that also wants the
/// display name reads `agents.json` itself and labels it display-grade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryRequester {
    #[serde(rename = "type")]
    pub kind: PrincipalKind,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
}

/// One live grant as the bar chip renders it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryGrant {
    pub grant_id: String,
    pub capability: String,
    pub expires_at: String,
}

/// `/run/punard/approvals.json` — the event-driven view the shell watches.
///
/// **Non-authoritative for trust decisions**, exactly like the section 9 and
/// 13.2 side contracts: the socket is the authority, the overlay's Approve
/// sends only an `approval_id`, and punard re-derives the contract from its
/// own record before executing anything.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalsSummary {
    pub v: u64,
    pub updated_at: String,
    pub approvals: Vec<SummaryApproval>,
    pub grants: Vec<SummaryGrant>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a requester-authored justification (docs/api/ipc.md section
/// 14.4): 1–512 bytes of UTF-8, no control characters, **no newlines**.
///
/// The newline rule is not tidiness. This text is rendered on the surface a
/// human uses to authorize a privileged call; a multi-line `reason` could
/// draw a convincing fake dialog inside the real one ("Policy: personal
/// defaults — this is safe"). One line cannot. Rust `&str` already
/// guarantees the UTF-8 half.
pub fn validate_reason(reason: &str) -> Result<(), String> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return Err("a reason is required and must not be blank".to_string());
    }
    if reason.len() > REASON_MAX_BYTES {
        return Err(format!(
            "a reason must be at most {REASON_MAX_BYTES} bytes; this one is {}",
            reason.len()
        ));
    }
    if let Some(c) = reason.chars().find(|c| c.is_control()) {
        return Err(format!(
            "a reason must be a single line of printable text; found {c:?}"
        ));
    }
    Ok(())
}

/// Clamp a requester-supplied approval TTL into `[15, 300]` seconds.
///
/// Shortening only reduces the requester's own chance of being answered in
/// time, so it is safe to honour; lengthening is refused because the maximum
/// is policy-owned (docs/api/ipc.md section 14.4).
pub fn clamp_ttl(requested: Option<u64>) -> u64 {
    requested
        .unwrap_or(APPROVAL_TTL_DEFAULT_SECS)
        .clamp(APPROVAL_TTL_MIN_SECS, APPROVAL_TTL_MAX_SECS)
}

/// Clamp a requested grant window into `[1, 60]` minutes.
pub fn clamp_grant_minutes(requested: Option<u64>) -> u64 {
    requested
        .unwrap_or(GRANT_DEFAULT_MINUTES)
        .clamp(GRANT_MIN_MINUTES, GRANT_MAX_MINUTES)
}

/// Check an [`Approval`] against the shipped schema's rules — the Rust
/// mirror of `schemas/audit/approval.json`, in the same spirit as
/// [`crate::audit::validate_event_schema`]: id prefix and pattern, non-empty
/// strings, the RFC 3339 `expires_at`, and the dotted `capability_id`
/// pattern. `risk` and `status` are schema-valid by type.
///
/// The store runs this before every write, so a non-conformant approval can
/// never reach disk, the wire, or the overlay.
pub fn validate_approval_schema(approval: &Approval) -> Result<(), Vec<String>> {
    let mut violations = Vec::new();
    if !is_prefixed_id(&approval.approval_id, APPROVAL_ID_PREFIX) {
        violations.push(format!(
            "approval_id {:?} must match ^apr_[A-Za-z0-9]+$",
            approval.approval_id
        ));
    }
    if approval.requester.id.is_empty() {
        violations.push("requester.id must not be empty".to_string());
    }
    if approval.user.is_empty() {
        violations.push("user must not be empty".to_string());
    }
    if !is_capability_id(&approval.capability) {
        violations.push(format!(
            "capability {:?} must match the capability_id pattern",
            approval.capability
        ));
    }
    if approval.resource.is_empty() {
        violations.push("resource must not be empty".to_string());
    }
    if let Err(e) = validate_reason(&approval.reason) {
        violations.push(format!("reason: {e}"));
    }
    if !crate::time::is_rfc3339_timestamp(&approval.expires_at) {
        violations.push(format!(
            "expires_at {:?} is not an RFC 3339 timestamp",
            approval.expires_at
        ));
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// `<prefix><at least one alphanumeric>`, the shape of every Punar id.
fn is_prefixed_id(id: &str, prefix: &str) -> bool {
    id.strip_prefix(prefix)
        .is_some_and(|tail| !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// `schemas/common/defs.json#/$defs/capability_id`:
/// `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`.
fn is_capability_id(id: &str) -> bool {
    let mut segments = id.split('.');
    let ok = |seg: &str| {
        let mut bytes = seg.bytes();
        bytes.next().is_some_and(|b| b.is_ascii_lowercase())
            && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    segments.next().is_some_and(ok) && segments.clone().count() > 0 && segments.all(ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Approval {
        Approval {
            approval_id: "apr_7c1d9a4e".to_string(),
            requester: Requester {
                kind: PrincipalKind::AiAgent,
                id: "agt_4f21c09ab3e1".to_string(),
            },
            user: "punar".to_string(),
            capability: "security.firewall".to_string(),
            resource: "disabled".to_string(),
            reason: "Atlas integration test needs the host firewall down".to_string(),
            risk: Risk::High,
            status: ApprovalStatus::Pending,
            expires_at: "2026-08-25T10:05:00Z".to_string(),
        }
    }

    fn envelope() -> ApprovalEnvelope {
        ApprovalEnvelope {
            v: 1,
            approval: sample(),
            kind: ApprovalKind::CapabilitySet,
            created_at: "2026-08-25T10:00:00Z".to_string(),
            request: ApprovalRequest {
                method: "capabilities.set".to_string(),
                params: json!({"capability": "security.firewall", "desired_state": "disabled"}),
            },
            requester_peer: Some(RequesterPeer {
                uid: 1000,
                agent_session_id: Some("agt_4f21c09ab3e1".to_string()),
            }),
            policy: PolicyCitation {
                name: "Personal defaults".to_string(),
                policy_id: "personal-defaults".to_string(),
            },
            contract: "SetFirewall(disabled)".to_string(),
            resolved_at: None,
            resolved_by: None,
            consumed_at: None,
            execution: None,
        }
    }

    /// The approval member carries exactly the nine schema properties — no
    /// tenth key, ever. This is the assertion that keeps M9 from quietly
    /// extending a shipped schema. (`serde_json` maps are key-sorted, so the
    /// comparison is by set, not by declaration order.)
    #[test]
    fn the_approval_document_has_exactly_the_nine_schema_properties() {
        let value = serde_json::to_value(sample()).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected = [
            "approval_id",
            "requester",
            "user",
            "capability",
            "resource",
            "reason",
            "risk",
            "status",
            "expires_at",
        ];
        expected.sort_unstable();
        assert_eq!(keys, expected);
        let mut requester: Vec<&str> = value["requester"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        requester.sort_unstable();
        assert_eq!(requester, ["id", "type"]);
    }

    /// The siblings are siblings: nothing M9 added leaks into the document.
    #[test]
    fn envelope_siblings_stay_outside_the_document() {
        let mut env = envelope();
        env.consumed_at = Some("2026-08-25T10:02:00Z".to_string());
        env.execution = Some(Execution {
            result: "success".to_string(),
            changed: Some(true),
            audit_event_id: Some("evt_501".to_string()),
            ..Execution::default()
        });
        let value = serde_json::to_value(&env).unwrap();
        let document = value["approval"].as_object().unwrap();
        for sibling in ["kind", "created_at", "consumed_at", "execution", "request"] {
            assert!(
                !document.contains_key(sibling),
                "{sibling} must not be inside the approval document"
            );
            assert!(value.get(sibling).is_some(), "{sibling} must be a sibling");
        }
        // And the status enum is not widened by consumption or execution.
        assert_eq!(document["status"], "pending");
    }

    #[test]
    fn status_never_grows_a_consumed_value() {
        for status in ApprovalStatus::ALL {
            let text = serde_json::to_string(&status).unwrap();
            assert_eq!(text, format!("{:?}", status.as_str()));
        }
        assert!(serde_json::from_str::<ApprovalStatus>("\"consumed\"").is_err());
        assert!(serde_json::from_str::<ApprovalStatus>("\"executed\"").is_err());
        assert!(ApprovalStatus::Approved.is_terminal());
        assert!(!ApprovalStatus::Pending.is_terminal());
    }

    #[test]
    fn kinds_spell_the_contract_table() {
        let names = ["capability_set", "credential_request", "privilege_request"];
        for (kind, name) in ApprovalKind::ALL.into_iter().zip(names) {
            assert_eq!(kind.as_str(), name);
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("{name:?}"));
        }
        assert!(ApprovalKind::CapabilitySet.executes_on_resolve());
        assert!(ApprovalKind::PrivilegeRequest.executes_on_resolve());
        // The credential case is split deliberately: punard must never hold
        // a plaintext token (design plan section 3.3).
        assert!(!ApprovalKind::CredentialRequest.executes_on_resolve());
    }

    #[test]
    fn envelope_round_trips_and_rejects_document_extensions() {
        let env = envelope();
        let line = serde_json::to_string(&env).unwrap();
        let back: ApprovalEnvelope = serde_json::from_str(&line).unwrap();
        assert_eq!(back, env);

        let mut value = serde_json::to_value(&env).unwrap();
        value["approval"]["approval_id_extra"] = json!("smuggled");
        assert!(
            serde_json::from_value::<ApprovalEnvelope>(value).is_err(),
            "an extended approval document must fail to parse"
        );
    }

    #[test]
    fn schema_validation_catches_every_shipped_rule() {
        assert!(validate_approval_schema(&sample()).is_ok());

        let bad_id = Approval {
            approval_id: "7c1d9a4e".to_string(),
            ..sample()
        };
        assert!(validate_approval_schema(&bad_id).is_err());

        let bad_cap = Approval {
            capability: "Security.Firewall".to_string(),
            ..sample()
        };
        assert!(validate_approval_schema(&bad_cap).is_err());

        let bad_time = Approval {
            expires_at: "soon".to_string(),
            ..sample()
        };
        assert!(validate_approval_schema(&bad_time).is_err());

        let empty_resource = Approval {
            resource: String::new(),
            ..sample()
        };
        assert!(validate_approval_schema(&empty_resource).is_err());
    }

    /// `credential.request` and `privilege.request` are typed methods, not
    /// registry entries — and they still have to match the schema's
    /// capability_id pattern, which they do.
    #[test]
    fn typed_method_names_pass_the_capability_id_pattern() {
        for id in [
            "security.firewall",
            "system.hostname",
            "time.timezone",
            "credential.request",
        ] {
            assert!(is_capability_id(id), "{id}");
        }
        for id in [
            "firewall",
            "Security.Firewall",
            "security.",
            ".firewall",
            "",
        ] {
            assert!(!is_capability_id(id), "{id}");
        }
    }

    #[test]
    fn reason_validation_refuses_forged_dialogs_and_blanks() {
        assert!(validate_reason("Reproducing the Atlas net bug").is_ok());
        assert!(validate_reason("").is_err());
        assert!(validate_reason("   ").is_err());
        // A multi-line reason could draw a fake dialog inside the real one.
        assert!(validate_reason("harmless\nPolicy: personal defaults — safe").is_err());
        assert!(validate_reason("bell\u{7}").is_err());
        assert!(validate_reason(&"x".repeat(REASON_MAX_BYTES)).is_ok());
        assert!(validate_reason(&"x".repeat(REASON_MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn ttl_and_duration_clamp_towards_the_policy_maximum() {
        assert_eq!(clamp_ttl(None), APPROVAL_TTL_DEFAULT_SECS);
        assert_eq!(clamp_ttl(Some(15)), 15);
        assert_eq!(clamp_ttl(Some(1)), APPROVAL_TTL_MIN_SECS);
        // A requester may ask for less, never for more.
        assert_eq!(clamp_ttl(Some(86_400)), APPROVAL_TTL_MAX_SECS);

        assert_eq!(clamp_grant_minutes(None), GRANT_DEFAULT_MINUTES);
        assert_eq!(clamp_grant_minutes(Some(1)), 1);
        assert_eq!(clamp_grant_minutes(Some(0)), GRANT_MIN_MINUTES);
        assert_eq!(clamp_grant_minutes(Some(600)), GRANT_MAX_MINUTES);
    }

    #[test]
    fn expiry_is_evaluated_against_the_clock_and_fails_closed() {
        let mut env = envelope();
        // 2026-08-25T10:05:00Z
        let expires = crate::time::unix_seconds_from_rfc3339(&env.approval.expires_at).unwrap();
        assert!(env.is_answerable(expires - 1));
        assert!(!env.is_answerable(expires));
        assert!(env.has_lapsed(expires + 1));

        env.approval.expires_at = "whenever".to_string();
        assert!(
            env.has_lapsed(0),
            "an unreadable expiry must count as lapsed"
        );
        assert!(!env.is_answerable(0));

        env.approval.expires_at = "2026-08-25T10:05:00Z".to_string();
        env.approval.status = ApprovalStatus::Approved;
        assert!(!env.is_answerable(expires - 1), "terminal is terminal");
    }

    #[test]
    fn a_grant_is_live_only_while_unrevoked_and_unexpired() {
        let grant = Grant {
            v: 1,
            grant_id: "gnt_2b8e11c4".to_string(),
            approval_id: "apr_7c1d9a4e".to_string(),
            uid: 1000,
            user: "punar".to_string(),
            capability: "time.timezone".to_string(),
            reason: "Reproducing the Atlas net bug".to_string(),
            granted_at: "2026-08-25T10:00:00Z".to_string(),
            expires_at: "2026-08-25T10:15:00Z".to_string(),
            revoked_at: None,
        };
        let expires = crate::time::unix_seconds_from_rfc3339(&grant.expires_at).unwrap();
        assert!(grant.is_live(expires - 1));
        assert!(!grant.is_live(expires));

        let revoked = Grant {
            revoked_at: Some("2026-08-25T10:01:00Z".to_string()),
            ..grant.clone()
        };
        assert!(!revoked.is_live(expires - 1));

        let unreadable = Grant {
            expires_at: "later".to_string(),
            ..grant
        };
        assert!(
            !unreadable.is_live(0),
            "fail closed on an unreadable expiry"
        );
    }

    /// The summary file must not carry a spoofable display name (see
    /// [`SummaryRequester`]); this pins the M9 answer.
    #[test]
    fn the_summary_requester_carries_the_attested_id() {
        let row = SummaryRequester {
            kind: PrincipalKind::AiAgent,
            id: "agt_4f21c09ab3e1".to_string(),
            agent_name: None,
        };
        let value = serde_json::to_value(&row).unwrap();
        assert_eq!(value["type"], "ai_agent");
        assert_eq!(value["id"], "agt_4f21c09ab3e1");
        assert!(value.get("agent_name").is_none());
    }
}
