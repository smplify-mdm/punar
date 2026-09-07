//! The wire contract, in one place so both ends and the tests agree.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

/// A password is bounded far below this; the limit exists so a peer cannot make
/// the daemon allocate on demand.
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_RESPONSE_BYTES: usize = 4096;

/// THE REQUEST CARRIES NO USERNAME, and that absence is the security design
/// rather than an omission. The account is whatever `SO_PEERCRED` says the peer
/// is. `deny_unknown_fields` makes a username field a hard parse error, so a
/// later well-meaning addition fails loudly instead of quietly turning this
/// service into a device-wide password oracle. There is a test.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub v: u32,
    pub password: String,
}

/// The three outcomes, and deliberately only three.
///
/// `Denied` and `Unavailable` are separated because collapsing them is how a
/// stranded owner gets told their password is wrong on a machine they cannot
/// get into. The distinction is about the DEVICE's ability to answer, never
/// about the secret: for a fixed peer, two requests differing only in the
/// password can differ only between `ok` and `denied`, never in whether
/// `unavailable` appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The stack accepted the secret.
    Ok,
    /// The stack refused: a wrong secret, an expired account, or a lockout.
    /// Which of those is deliberately not distinguished.
    Denied,
    /// The device could not ask. Never a statement about the secret.
    Unavailable,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub v: u32,
    pub verdict: Verdict,
}

impl VerifyResponse {
    pub fn new(verdict: Verdict) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            verdict,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_shape_carries_no_username() {
        // The security argument is that a caller cannot choose who they are. A
        // username field appearing here later would silently undo it, so the
        // shape itself is asserted rather than trusted to review.
        let with_username = br#"{"v":1,"username":"root","password":"x"}"#;
        assert!(serde_json::from_slice::<VerifyRequest>(with_username).is_err());
        let with_uid = br#"{"v":1,"uid":0,"password":"x"}"#;
        assert!(serde_json::from_slice::<VerifyRequest>(with_uid).is_err());
        let correct = br#"{"v":1,"password":"x"}"#;
        assert!(serde_json::from_slice::<VerifyRequest>(correct).is_ok());
    }

    #[test]
    fn a_verdict_serializes_to_a_closed_set_of_words() {
        let words: Vec<String> = [Verdict::Ok, Verdict::Denied, Verdict::Unavailable]
            .into_iter()
            .map(|v| serde_json::to_string(&VerifyResponse::new(v)).unwrap())
            .collect();
        assert_eq!(words[0], r#"{"v":1,"verdict":"ok"}"#);
        assert_eq!(words[1], r#"{"v":1,"verdict":"denied"}"#);
        assert_eq!(words[2], r#"{"v":1,"verdict":"unavailable"}"#);
    }
}
