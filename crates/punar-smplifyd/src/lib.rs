//! The part of punar-smplifyd that code outside it may use: the bodies it
//! sends to Smplify, and the clock they carry. They are a library so that
//! punard's tests can put punard's real inventory through the agent's real
//! translation and check exactly what an organization receives
//! (crates/punard/tests/enroll.rs). Identity, transport and the socket stay
//! in the binary.
pub mod clock;
pub mod status;
