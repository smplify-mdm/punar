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
//! `compliance.report`, `inventory.report`; `admin.devices`/`admin.device`
//! are **reserved for Milestone 10** (SPEC section 51) and answer
//! `unknown_method` — m5-check asserts the received side by reading
//! `/var/lib/punar-mock-smplify/` directly instead.
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
//!
//! [`enroll.register`]: server::MockServer

#![forbid(unsafe_code)]

pub mod config;
pub mod fixtures;
pub mod protocol;
pub mod server;
pub mod state;
