//! `punar-agentd` — the AI Agent Registry service (SPEC section 11.3),
//! Milestone 7 build: managed session registry, agent identity and
//! classification (SPEC sections 18–19), process attribution (section 22),
//! and heuristic shadow-AI detection (section 23).
//!
//! # Why a second daemon
//!
//! `punard` is the privileged system control plane; the registry is a
//! different concern with a different lifetime, a different socket, and a
//! different audience (SPEC section 11.3 names it as its own service). The
//! wire contract is the sibling section of the same document —
//! `docs/api/ipc.md` section 10 — and it reuses `punar-common::ipc`
//! envelope, framing, error codes, and timeouts verbatim: a second socket,
//! not a second protocol. Design rationale: `docs/development/milestone-7.md`.
//!
//! # What this milestone does and does not claim
//!
//! - **Does**: register managed sessions launched through `punar-env`,
//!   prove their `managed` classification from the launch scope's cgroup,
//!   persist every lifecycle transition as a schema-exact registry record,
//!   detect known agents running outside the managed runtime (`observed`)
//!   and suspected agentic processes (`unknown`) on demand, and publish a
//!   summary for the AI panel.
//! - **Does not**: enforce anything. Authority rows are display-level and
//!   carry their `declared · M9/M12` labels (SPEC section 1.22). There is
//!   no continuous detection, alerting, or response (Milestone 10), and
//!   detection is a heuristic that says *suspected*, never certain (SPEC
//!   section 23).
//!
//! # Milestone 8: the AI Access Ledger ([`ledger`])
//!
//! M8 adds the per-session Access Ledger (SPEC sections 21, 24) —
//! `agents.access`, `ledger.purge`, and the counts-only fingerprint on
//! `agents.list`. It is **derived** from mediation points this daemon
//! already owns (the scope cgroup, the audit stream, the workspace grant,
//! registry metadata): no eBPF, no fanotify, no ptrace, no `LD_PRELOAD`,
//! and no filesystem or network tracing anywhere (SPEC 1.14). The
//! categories with no producer yet — network destinations (M12), MCP
//! servers (M9+), credential classes (M9) — are rendered as *not yet
//! observed* rather than invented (SPEC 1.22).

#![forbid(unsafe_code)]

pub mod adapters;
pub mod authz;
pub mod detect;
pub mod ledger;
pub mod proc;
pub mod registry;
pub mod server;
pub mod summary;
pub mod util;

pub mod testsupport;
