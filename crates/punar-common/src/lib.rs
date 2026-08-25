//! Core domain types shared by every Punar service and CLI.
//!
//! Milestone 0 laid down the domain types; Milestone 3 adds the typed IPC
//! contract and the audit-trail plumbing shared by `punard` and `punarctl`,
//! per `docs/product/SPEC_v0.2.md` and the binding wire contract
//! `docs/api/ipc.md`. Still no daemon logic here — only types, parsing, and
//! file plumbing both sides must agree on.
//!
//! - [`PrincipalKind`] — identity types recognized by the OS (SPEC section 18).
//! - [`Decision`] — authorization decision values (SPEC section 20).
//! - [`CapabilityId`] — validated dotted capability path such as
//!   `security.firewall` (SPEC sections 10 and 41).
//! - [`CapabilityDescriptor`] / [`Risk`] — typed capability registry entry
//!   (SPEC section 41; `schemas/capability/capability-descriptor.json`).
//! - [`AuditEvent`] — structured audit record (SPEC section 53), with the
//!   [`audit`] module's writer, tail reader, and builders.
//! - [`ipc`] — the typed request/response envelope, closed method table, and
//!   error codes (SPEC sections 10, 60, 61, 73; docs/api/ipc.md).
//! - [`time`] — RFC 3339 UTC helpers (deliberately no time crate).
//! - [`Redacted`] — wrapper that keeps secret values out of logs and
//!   serialized output (SPEC sections 1.19 and 53).
//!
//! Dependency policy (budget + supply chain, PERFORMANCE_BUDGETS.md section
//! 6.2): `serde`/`serde_json`/`thiserror` only. `serde_json` graduated from
//! dev-dependency in M3 because the IPC envelope carries params/results and
//! capability state values as structured JSON and the audit writer emits
//! JSONL — no new crate enters the tree.

#![forbid(unsafe_code)]

pub mod audit;
mod capability;
mod decision;
mod descriptor;
pub mod ipc;
mod principal;
mod redacted;
pub mod time;

pub use audit::{AuditEvent, AuditWriter};
pub use capability::{CapabilityId, CapabilityIdError};
pub use decision::Decision;
pub use descriptor::{CapabilityDescriptor, Risk};
pub use principal::PrincipalKind;
pub use redacted::{REDACTED_PLACEHOLDER, Redacted};
