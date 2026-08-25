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
//!
//! # Milestone 10: periodic detection and the local alert
//!
//! M10 makes the device notice on its own and tell the user first (SPEC
//! sections 12.1, 23, 73; `docs/development/milestone-10.md`):
//!
//! - **[`identity`]** — `detection_id` (one running process) and
//!   `signature_id` (one thing seen). Two identities, deliberately: the
//!   set-diff and the ledger bind to the process, the alert binds to the
//!   thing.
//! - **The scan diff is the event.** `agents.scan` gains a `--trigger`
//!   that travels into the audit trail, and a pass whose detection set is
//!   unchanged writes **nothing at all** — no `agents.json` rewrite, no
//!   audit line, no disk I/O (SPEC 6.4). The periodic pass is a systemd
//!   timer calling `punarctl`, not a thread in this daemon (SPEC 6.3).
//! - **[`detections`]** — persisted detection records and bounded
//!   unknown-agent ledgers, closing the question M8 wrote down and left
//!   open. The ledger is strictly *smaller* than a managed one: a process
//!   class, a zone class, and the Level-4 event references. No child
//!   walk, no `cwd`, no cmdline, ever.
//! - **[`alerts`]** — one alert per signature, a 24 h quiet window, a
//!   root-owned state file, and dismissal that files rather than
//!   destroys.
//!
//! **Still does not**: block, kill, quarantine, or throttle anything.
//! M10 detects, records and alerts. A red card that cannot act is honest;
//! a red card that silently acts is not (SPEC 23, 1.22).

#![forbid(unsafe_code)]

pub mod adapters;
pub mod alerts;
pub mod authz;
pub mod detect;
pub mod detections;
pub mod identity;
pub mod ledger;
pub mod proc;
pub mod queries;
pub mod registry;
pub mod server;
pub mod sha256;
pub mod summary;
pub mod util;

pub mod testsupport;
