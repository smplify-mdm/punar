//! `punar-mock-smplify` — **dev/CI mock — not a product component.**
//!
//! An in-VM stand-in for the Smplify control plane, with the same standing
//! as the `m*-check.sh` scripts: the CI VM has no network (`-nic none`),
//! and Milestone 5 (SPEC section 76; docs/development/milestone-5.md
//! section 4) needs a counterparty for enrollment, policy fetch, and
//! category-level compliance/inventory reporting. It ships in the CI/dev
//! desktop image only because the check needs it in-VM; its unit is never
//! enabled and only `m5-check.sh` starts it.
//!
//! # Trust boundary, stated honestly (SPEC section 61)
//!
//! In production this hop is Punar ⇄ Smplify cloud over mutually
//! authenticated TLS. The mock replaces that transport with **filesystem
//! admission**: a `SOCK_STREAM` Unix socket chmod'd `0600` root **before**
//! `listen()`, inside a `0750` runtime directory — only root connects
//! (`punard` and the check), and no TCP listener exists anywhere. The
//! `device_token` issued by [`enroll.register`] is still enforced at the
//! protocol layer even though transport admission already implies root,
//! because the token flow is the thing M5 rehearses: the mock must reject a
//! wrong token so `punard`'s error path is testable. Attestation is
//! **simulated** — the register result says so literally, and nothing here
//! measures, quotes, or verifies anything. The mock performs no
//! `SO_PEERCRED` authorization beyond the filesystem; it is not an
//! authority.
//!
//! # Wire protocol
//!
//! NDJSON over the UDS with the established `docs/api/ipc.md` sections 2/3
//! framing verbatim — `{"v":1,"id":…,"method":…,"params":…}` requests
//! (strict envelope, 4096-byte lines, sequential per connection, 10 s
//! timeouts), `result` XOR `error` responses. The method table
//! ([`server`]): `org.discover`, `enroll.register`, `policy.fetch`,
//! `compliance.report`, `inventory.report` (M5); `recovery.key` /
//! `recovery.escrow` (device-side recovery custody); `queries.pending` /
//! `queries.answer` (M10, device-facing — the device dials outward and
//! collects questions addressed to it); and the admin surface
//! `admin.devices`, `admin.device`, `admin.ai_query`, `admin.query_result`,
//! `admin.fleet` (M10, SPEC section 51), plus the separately permissioned
//! and audited `admin.recovery_release`, role-gated by [`rbac`].
//!
//! # The law this crate must not break (milestone-10.md law 1)
//!
//! **Nothing here ever dials a device.** An `admin.ai_query` enqueues a
//! question and returns `{query_id, status: "pending"}` immediately; the
//! *administrator's* client is the thing that waits, by polling
//! `admin.query_result`. The device answers when it next runs its own
//! reconcile-piggybacked sync and pulls the queue. There is no push
//! channel, no callback, no device address stored anywhere in this crate,
//! and no code path that opens a connection to an endpoint. That is not a
//! policy this crate follows — it is a capability it does not have.
//!
//! # Data posture
//!
//! Fixtures ([`fixtures`]) are served **verbatim** from the staged Acme
//! tree; the one mechanical composition is the `policy.fetch` envelope +
//! embedded `policy` payload (the shape a `policy.d/` drop carries).
//! Received state ([`state`]) persists across restarts deliberately: the
//! m5-check offline stop→start must not invalidate the device token, and
//! the kept history after unenroll is the honest record that M5
//! unenrollment is local-only.
//! Recovery custody persists only tenant-wrapped envelopes. The dev release
//! proof uses public RFC test private material, requires an explicitly
//! permitted role plus a structured reason, and writes a non-secret audit
//! record before returning a one-time plaintext response. Production replaces
//! the fixture identity and key with authenticated portal identity, step-up
//! authorization, and tenant-scoped KMS/HSM custody.
//!
//! [`enroll.register`]: server::MockServer

#![forbid(unsafe_code)]

pub mod config;
pub mod fixtures;
pub mod fleet;
pub mod protocol;
pub mod rbac;
pub mod server;
pub mod state;
