//! `punard` — Punar's primary privileged local control-plane daemon.
//!
//! Milestone 3 scope (SPEC section 76): UDS NDJSON server with a closed,
//! typed method table (`docs/api/ipc.md` is the binding wire contract), a
//! capability registry with three real backends (`security.firewall`,
//! `system.hostname`, `time.timezone`), and an append-only audit log
//! (`schemas/audit/audit-event.json` conformant).
//!
//! Milestone 4 (SPEC sections 38–40, 42, 43, 52): desired state became a
//! layered store (compiled/seeded OS defaults, `preferences.json`, reserved
//! `policy.d/` org drops) merged through `punar-policy` into an effective
//! document with provenance; `reconcile` runs the full section 42 chain and
//! **remediates** per the section 43 classification (loop-protected);
//! `policy.effective` / `policy.explain` expose the section 40
//! explainability set; `status` carries personal-scope section 52
//! compliance. Design: docs/development/milestone-4.md.
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

pub mod authz;
pub mod backends;
pub mod capability;
pub mod enroll;
pub mod policy;
pub mod server;
pub mod state;
pub mod util;
