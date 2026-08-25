//! `punard` — Punar's primary privileged local control-plane daemon.
//!
//! Milestone 3 scope (SPEC section 76): UDS NDJSON server with a closed,
//! typed method table (`docs/api/ipc.md` is the binding wire contract), a
//! capability registry with three real backends (`security.firewall`,
//! `system.hostname`, `time.timezone`), an append-only audit log
//! (`schemas/audit/audit-event.json` conformant), and report-only reconcile.
//!
//! Architectural law (SPEC sections 10, 60): privileged changes go through
//! typed capability APIs only — there is **no** generic root-command RPC, no
//! exec/shell method, ever. Authorization: socket filesystem admission +
//! `SO_PEERCRED` per connection; mutations are root-only in M3
//! (`personal-defaults` rule; JIT elevation is Milestone 9).
//!
//! Budget note (PERFORMANCE_BUDGETS.md sections 1.2/2.3): no async runtime —
//! std threads, one per connection, capped; per-connection buffers are bounded
//! by the 4096-byte wire line limit.

#![forbid(unsafe_code)]

pub mod audit;
pub mod authz;
pub mod backends;
pub mod capability;
pub mod server;
pub mod state;
pub mod timeutil;
pub mod util;
pub mod wire;
