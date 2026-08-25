//! `punar-secrets` — the short-lived credential broker (SPEC sections
//! 11.4, 29), Milestone 9 build.
//!
//! The binding wire contract is `docs/api/ipc.md` section 16; the design
//! rationale is `docs/development/milestone-9.md` sections 3.1 and 6.
//!
//! # Four sentences that describe the whole daemon
//!
//! 1. A caller asks for a **credential class** by name; classes are data
//!    ([`classes`]), read from `usr/share/punar/secrets/classes.yaml`.
//! 2. The effective AI credentials policy ([`policy`]) answers `allow`,
//!    `request` or `deny`; `request` means punard raises an approval
//!    ([`approvals`]) and **nothing is issued** until a human resolves it.
//! 3. On `allow` — or on spending an approved approval — the broker mints a
//!    mock token, keeps `sha256(token)` and forgets the value
//!    ([`store`]).
//! 4. Every step writes an audit event carrying **the class name only**
//!    ([`server`]); the value appears in exactly one place, the response to
//!    the caller who asked for it.
//!
//! # Why this is a separate daemon (SPEC 11.4)
//!
//! `punard` writes `/etc`, shells out to `nft` and holds enrollment state.
//! A broker folded into it would put plaintext tokens inside that blast
//! radius. Separated, `punar-secrets` can be hardened in ways punard
//! cannot (`ProtectSystem=strict`, `PrivateNetwork=yes`,
//! `MemoryDenyWriteExecute`, a `ReadWritePaths=` of exactly
//! `/run/punar-secrets /var/log/punar`) and — the load-bearing part — it
//! has **no state directory at all**, which is the strongest available
//! form of the promise "never written to disk".
//!
//! # What cannot be built out of this crate
//!
//! There is no method that runs a command and no method that returns an
//! issued token a second time; the second is structural rather than a
//! policy setting, because after issuance the broker holds only a hash.
//! Nothing here persists a credential value, and the redaction tests in
//! `tests/broker.rs` round-trip every emitted and retained structure to
//! prove it.

#![forbid(unsafe_code)]

pub mod approvals;
pub mod attribution;
pub mod classes;
pub mod policy;
pub mod protocol;
pub mod server;
pub mod sha256;
pub mod store;
pub mod testsupport;
pub mod util;

pub use classes::{ClassCatalog, CredentialClass};
pub use policy::{AiPolicySet, CredentialAuthority, CredentialGrant};
pub use protocol::{CredentialMethod, SECRETS_SOCKET_PATH, SecretsRequest};
pub use server::{Daemon, DaemonHandle, SecretsConfig};
pub use store::{IssuedRecord, Presented, TokenStore};
