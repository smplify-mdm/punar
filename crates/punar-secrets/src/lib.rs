//! `punar-secrets` — short-lived credential broker (SPEC section 11.4).
//!
//! Future role: issue scoped, short-lived credentials to approved principals
//! (SPEC section 29), never handing raw long-lived secrets to AI agents, and
//! guarantee redaction of secret material from logs and audit output
//! (secrets travel as `punar_common::Redacted` values; SPEC section 53).
//!
//! Milestone 0 status: intentionally empty. The approval-gated broker with
//! short-lived mock credentials and redaction tests is a Milestone 9
//! deliverable (SPEC section 76). No stub logic is provided, so nothing here
//! can be mistaken for a working implementation.

#![forbid(unsafe_code)]

// Intentionally empty module tree until Milestone 9.
