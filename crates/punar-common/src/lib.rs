//! Core domain types shared by every Punar service and CLI.
//!
//! Milestone 0 laid down the domain types; Milestone 3 adds the typed IPC
//! contract and the audit-trail plumbing shared by `punard` and `punarctl`,
//! per `docs/product/SPEC_v0.2.md` and the binding wire contract
//! `docs/api/ipc.md`. Still no daemon logic here — only types, parsing, and
//! file plumbing both sides must agree on.
//!
//! - [`principal`] — identity types recognized by the OS (SPEC section 18),
//!   plus the shared agent-session attribution rule (docs/api/ipc.md section
//!   12.5): one implementation of "is this peer an agent?", so `punard` and
//!   `punar-secrets` cannot disagree about a privilege boundary (M9).
//! - [`Decision`] — authorization decision values (SPEC section 20).
//! - [`CapabilityId`] — validated dotted capability path such as
//!   `security.firewall` (SPEC sections 10 and 41).
//! - [`CapabilityDescriptor`] / [`Risk`] — typed capability registry entry
//!   (SPEC section 41; `schemas/capability/capability-descriptor.json`).
//! - [`AuditEvent`] — structured audit record (SPEC section 53), with the
//!   [`audit`] module's writer, tail reader, and builders.
//! - [`ipc`] — the typed request/response envelope, closed method table, and
//!   error codes (SPEC sections 10, 60, 61, 73; docs/api/ipc.md).
//! - [`agent`] — the AI Agent Registry record (SPEC section 19.2;
//!   `schemas/ai-agent/registry-record.json`), the closed `agents.*` method
//!   table of the sibling `punar-agentd` socket, and the
//!   `/run/punar/agents.json` summary shape (docs/api/ipc.md sections
//!   10-11; Milestone 7).
//! - [`ledger`] — the AI Access Ledger types (SPEC sections 21, 24;
//!   `schemas/ai-agent/ledger-summary.json`, docs/api/ipc.md sections
//!   12-13; Milestone 8). Privacy is enforced in the types: a
//!   [`ledger::ResourceClass`] cannot hold a path, a URL, or free text,
//!   whichever way it is constructed.
//! - [`aipolicy`] — the section 20 AI authority document, the capability ↔
//!   policy-token map, and the layered evaluation that answers `allow` /
//!   `deny` / `approval_required` for an agent-originated call (M9).
//! - [`approval`] — the section 28 approval object, its M9 envelope, and
//!   just-in-time privilege grants (SPEC sections 28, 48; docs/api/ipc.md
//!   sections 14-15; Milestone 9). `schemas/audit/approval.json` is not
//!   extended: everything M9 needs that the document cannot hold travels as
//!   a sibling of the envelope.
//! - [`time`] — RFC 3339 UTC helpers (deliberately no time crate).
//! - [`Redacted`] — wrapper that keeps secret values out of logs and
//!   serialized output (SPEC sections 1.19 and 53).
//!
//! Dependency policy (budget + supply chain, PERFORMANCE_BUDGETS.md section
//! 6.2): `serde`/`serde_json`/`thiserror`, plus `rustix` since M7.
//! `serde_json` graduated from dev-dependency in M3 because the IPC
//! envelope carries params/results and capability state values as
//! structured JSON and the audit writer emits JSONL. `rustix` (already in
//! the workspace tree for `punard`'s `SO_PEERCRED`, feature-gated, no new
//! crate) buys the `flock` behind [`AuditWriter`]'s rotation lock: two
//! daemons now append to one trail (docs/api/ipc.md section 10.4), and
//! `flock` is not reachable from safe `std`.

#![forbid(unsafe_code)]

pub mod agent;
pub mod aipolicy;
pub mod approval;
pub mod audit;
mod capability;
mod decision;
mod descriptor;
pub mod ipc;
pub mod ledger;
pub mod principal;
mod redacted;
pub mod time;

pub use agent::{AgentClassification, AgentStatus, RegistryRecord};
pub use approval::{Approval, ApprovalEnvelope, ApprovalKind, ApprovalStatus, Grant, Requester};
pub use audit::{AuditEvent, AuditWriter};
pub use capability::{CapabilityId, CapabilityIdError};
pub use decision::Decision;
pub use descriptor::{CapabilityDescriptor, Risk};
pub use principal::PrincipalKind;
pub use redacted::{REDACTED_PLACEHOLDER, Redacted};
