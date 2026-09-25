//! How long the agent may spend on Smplify inside one of punard's calls.
//!
//! punard reads each answer within its own timeout for the method
//! (`call_timeout` in crates/punard/src/enroll.rs), and an answer that
//! arrives later reads there as a failure even when Smplify acted on the
//! request. A report Smplify kept is then sent again on every pass; a
//! registration Smplify recorded leaves a device record that refuses the
//! next attempt from the same machine. So each budget here is the whole of
//! one call, however many requests it makes, and punard's tests hold every
//! one of its timeouts above the budget for the same method.
use std::time::Duration;

/// One request to Smplify: a status POST, the bundle fetch.
pub const CALL_BUDGET: Duration = Duration::from_millis(4000);

/// The check-in that pins the tenant's signing key, before a compliance
/// report's status POST and apart from its [`CALL_BUDGET`]: a TCP connect, a
/// TLS 1.3 handshake with the client certificate and the request are three
/// round trips, which a satellite or poor cellular link, at around a second
/// each, could never fit into the quarter second of a shared budget.
pub const PIN_BUDGET: Duration = Duration::from_millis(4000);

/// `org.discover`'s fetch of the organization's well-known document.
pub const DISCOVERY_BUDGET: Duration = Duration::from_millis(3500);

/// `enroll.register`: `/os-identifiers/resolve` and `/enroll` against one
/// deadline. Each is a TCP connect, a TLS handshake and a request, three
/// round trips before Smplify's own time, and `/enroll` also signs a
/// certificate: a link with a second of latency needs most of this.
/// Resolving is optional (an unresolved image enrolls under the canonical
/// identifier), so it may spend at most a third, and `/enroll` always has the
/// rest.
pub const REGISTER_BUDGET: Duration = Duration::from_secs(12);

/// The calls the agent answers from this device alone, asking Smplify
/// nothing: a file read, or a wipe. They cannot wait on a link, so punard
/// reads a call of these that goes unanswered as the agent itself not
/// answering (`punard::enroll::AgentFault::NotAnswering`), never as the
/// network.
pub const LOCAL_METHODS: [&str; 2] = ["identity.status", "enroll.unregister"];

/// Whether the agent answers `method` without asking Smplify anything
/// ([`LOCAL_METHODS`]).
pub fn is_local(method: &str) -> bool {
    LOCAL_METHODS.contains(&method)
}

/// The most one call of `method` may spend on Smplify, all of its requests
/// together: nothing for the calls it answers locally ([`LOCAL_METHODS`]).
/// Every other method that asks Smplify nothing stays far inside
/// [`CALL_BUDGET`].
pub fn call_budget(method: &str) -> Duration {
    match method {
        "org.discover" => DISCOVERY_BUDGET,
        "enroll.register" => REGISTER_BUDGET,
        "compliance.report" => PIN_BUDGET + CALL_BUDGET,
        local if is_local(local) => Duration::ZERO,
        _ => CALL_BUDGET,
    }
}
