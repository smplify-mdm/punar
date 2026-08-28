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
//! Milestone 9 (SPEC sections 20, 28, 48, 60): approvals became a real
//! gate. `capabilities.set` from inside a managed agent session is
//! evaluated against the section 20 AI authority document *before* the uid
//! test — root-ness inside an agent scope buys no bypass — and an
//! `approval_required` verdict raises a section 28 approval that only a
//! human can answer ([`approvals`], [`aipolicy`], `server::m9`). A resolved
//! privilege request mints a time-boxed, single-capability grant; there is
//! still no path to persistent unrestricted root, and never a generic
//! shell. Design: docs/development/milestone-9.md.
//!
//! Milestone 10 (SPEC sections 24.1, 51, 59.4): `punard` became the
//! **courier** for the Smplify remote query. It fetches pending questions
//! on the existing M5 sync piggyback — no new timer, no new listener, no
//! inbound path of any kind — hands each one to `punar-agentd` over the
//! single inter-daemon edge ([`agentd`]), and posts the daemon's answer
//! back verbatim. It never assembles an answer, never reads a ledger, and
//! never sees a byte it was not handed. Design:
//! docs/development/milestone-10.md sections 7, 11.
//!
//! Architectural law (SPEC sections 10, 60): privileged changes go through
//! typed capability APIs only — there is **no** generic root-command RPC, no
//! exec/shell method, ever. Authorization: socket filesystem admission +
//! `SO_PEERCRED` per connection; mutations are root-only for humans without
//! a live section 48 grant, and agent-originated mutations answer to the
//! section 20 AI authority document.
//!
//! Budget note (PERFORMANCE_BUDGETS.md sections 1.2/2.3): no async runtime —
//! std threads, one per connection, capped; per-connection buffers are bounded
//! by the 4096-byte wire line limit.

#![forbid(unsafe_code)]

pub mod agentd;
pub mod aipolicy;
pub mod approvals;
pub mod apps;
pub mod authz;
pub mod backends;
pub mod capability;
pub mod device;
pub mod enroll;
pub mod install;
pub mod policy;
pub mod server;
pub mod state;
pub mod util;
