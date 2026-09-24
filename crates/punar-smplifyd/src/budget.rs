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

/// The most one call of `method` may spend on Smplify, all of its requests
/// together. Methods that ask Smplify nothing stay far inside
/// [`CALL_BUDGET`].
pub fn call_budget(method: &str) -> Duration {
    match method {
        "org.discover" => DISCOVERY_BUDGET,
        "enroll.register" => REGISTER_BUDGET,
        _ => CALL_BUDGET,
    }
}
