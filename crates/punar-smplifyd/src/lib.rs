//! The part of punar-smplifyd that code outside it may use: the bodies it
//! sends to Smplify, the clock they carry, how long each of punard's calls
//! may spend on Smplify, and the constants its lifetime is held to. They are
//! a library so that punard's tests can put punard's real inventory through
//! the agent's real translation and check exactly what an organization
//! receives (crates/punard/tests/enroll.rs), and hold punard's timeouts
//! above the agent's budgets. Identity, transport and the socket stay in the
//! binary.
pub mod activation;
pub mod budget;
pub mod clock;
pub mod status;
