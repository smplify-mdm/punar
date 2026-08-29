//! `punar-netd` — project network policy, local network observability, and
//! relay orchestration (SPEC sections 33–37; Milestone 12).
//!
//! The first implemented seam is deliberately below every UI and daemon
//! claim: [`policy`] parses the two user-authored policy sources and resolves
//! disagreement restrictively; [`nft`] turns a closed set of validated zone,
//! CIDR, session, and cgroup types into one deterministic nftables table.
//! [`nft_exec`] is the only installation boundary: bounded direct execution
//! with fixed argv and a private transaction file. Keeping generation pure
//! makes the dangerous properties—deny-before-allow, log-before-unlimited-
//! reject, zone-before-loopback, residual-last, and table-name partitioning—
//! unit-testable independently of that root-only boundary.

#![forbid(unsafe_code)]

pub mod agentd;
pub mod model;
pub mod nft;
pub mod nft_exec;
pub mod observe;
pub mod peer;
pub mod policy;
pub mod project;
pub mod relay;
pub mod runtime;
pub mod server;
mod util;
pub mod view;
pub mod watch;
