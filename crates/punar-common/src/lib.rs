//! Core domain types shared by every Punar service and CLI.
//!
//! Milestone 0 scope: type definitions with serde support and tests, per
//! `docs/product/SPEC_v0.2.md`. No daemon logic lives here.
//!
//! - [`PrincipalKind`] — identity types recognized by the OS (SPEC section 18).
//! - [`Decision`] — authorization decision values (SPEC section 20).
//! - [`CapabilityId`] — validated dotted capability path such as
//!   `security.firewall` (SPEC sections 10 and 41).
//! - [`AuditEvent`] — structured audit record (SPEC section 53).
//! - [`Redacted`] — wrapper that keeps secret values out of logs and
//!   serialized output (SPEC sections 1.19 and 53).

#![forbid(unsafe_code)]

mod audit;
mod capability;
mod decision;
mod principal;
mod redacted;

pub use audit::AuditEvent;
pub use capability::{CapabilityId, CapabilityIdError};
pub use decision::Decision;
pub use principal::PrincipalKind;
pub use redacted::{REDACTED_PLACEHOLDER, Redacted};
