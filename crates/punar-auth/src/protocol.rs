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
    /// What the caller intends to do with a successful answer. Defaults to
    /// [`Purpose::Unlock`], so every existing lock-screen client is unchanged
    /// and a client that does not know about tickets cannot accidentally mint
    /// one.
    #[serde(default)]
    pub purpose: Purpose,
    /// For [`Purpose::Admin`], and required there: the IPC method the ticket
    /// may be spent on (`policy.set`). punard spends the ticket on that
    /// method and no other (docs/api/ipc.md section 23.1).
    #[serde(default)]
    pub action: Option<String>,
    /// For [`Purpose::Admin`]: the process that will spend the ticket, when
    /// it is not the caller itself — a graphical surface asks on behalf of
    /// the `punarctl` it started. It must be a live process running entirely
    /// as the caller's own uid; the ticket then names it (pid and start
    /// time), and punard spends it for that process only. Absent means the
    /// caller itself.
    #[serde(default)]
    pub for_pid: Option<u32>,
}

/// How a request arrived, and so how its answer is sent.
///
/// `Length` is the original framing: a 4-byte little-endian length, then the
/// JSON body; the answer comes back the same way. `Line` is one JSON object
/// on one line, answered by one JSON line: what a graphical surface can write
/// on a socket it connects itself, so that a password typed into it goes to
/// this daemon directly and never through a pipe (F0-S4). The two cannot be
/// confused: a line request starts `{"`, and as a length header those two
/// bytes would announce at least 0x227B bytes — more than
/// [`MAX_REQUEST_BYTES`], so no valid length frame starts that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Length,
    Line,
}

/// The first two bytes of every line-framed request.
pub const LINE_REQUEST_START: [u8; 2] = *b"{\"";

/// What a successful verification is FOR.
///
/// The distinction exists because the two answers have different lifetimes. An
/// unlock is spent the instant it is given — the screen opens, and nothing is
/// carried forward. An administrative change has to be proved to a *different*
/// process (punard), which cannot itself run PAM for an unprivileged caller, so
/// something durable enough to hand over has to exist. That something is a
/// ticket, and it is minted only when the caller said in advance that it wanted
/// one: a lock screen never leaves a credential-shaped object lying in /run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    /// Open a locked session. No ticket.
    #[default]
    Unlock,
    /// Re-authenticate before a device-administration change. On `ok`, a
    /// single-use ticket is minted for this caller's uid.
    Admin,
}

/// Where minted tickets live. Root-owned and root-only: a ticket is a bearer
/// object, and the whole reason punard can trust one is that no unprivileged
/// process could have created the file.
pub const TICKET_DIR: &str = "/run/punar-authd/tickets";

/// How long a ticket may be presented for. Short on purpose — this is the
/// window between typing a password and pressing the button next to it, not a
/// session. Long enough that a slow confirmation dialog does not strand
/// somebody who typed correctly.
pub const TICKET_MAX_AGE_SECS: u64 = 120;

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
    /// Present only for a [`Purpose::Admin`] request that succeeded. Omitted
    /// entirely otherwise, so an unlock response stays byte-identical to the
    /// one every shipped lock screen already parses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
}

impl VerifyResponse {
    pub fn new(verdict: Verdict) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            verdict,
            ticket: None,
        }
    }

    pub fn with_ticket(verdict: Verdict, ticket: Option<String>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            verdict,
            ticket,
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
    fn a_request_without_a_purpose_is_an_unlock() {
        // Every shipped lock screen sends exactly these two fields. If the
        // default ever became Admin, every unlock would leave a bearer ticket
        // in /run — so the default is asserted, not assumed.
        let plain: VerifyRequest = serde_json::from_slice(br#"{"v":1,"password":"x"}"#).unwrap();
        assert_eq!(plain.purpose, Purpose::Unlock);
        let admin: VerifyRequest =
            serde_json::from_slice(br#"{"v":1,"password":"x","purpose":"admin"}"#).unwrap();
        assert_eq!(admin.purpose, Purpose::Admin);
        assert!(
            serde_json::from_slice::<VerifyRequest>(br#"{"v":1,"password":"x","purpose":"root"}"#)
                .is_err()
        );
        let bound: VerifyRequest = serde_json::from_slice(
            br#"{"v":1,"password":"x","purpose":"admin","action":"policy.set","for_pid":4242}"#,
        )
        .unwrap();
        assert_eq!(bound.action.as_deref(), Some("policy.set"));
        assert_eq!(bound.for_pid, Some(4242));
    }

    /// The two framings cannot be mistaken for each other: a line request's
    /// first two bytes, read as a length header, announce more than any
    /// request may hold.
    #[test]
    fn a_line_request_can_never_be_a_valid_length_frame() {
        let smallest = u32::from_le_bytes([LINE_REQUEST_START[0], LINE_REQUEST_START[1], 0, 0]);
        assert!(smallest as usize > MAX_REQUEST_BYTES);
    }

    #[test]
    fn an_unlock_response_carries_no_ticket_field_at_all() {
        // Not "carries null" — carries nothing. The lock surface parses this
        // string today and must keep seeing exactly what it saw before.
        let body = serde_json::to_string(&VerifyResponse::new(Verdict::Ok)).unwrap();
        assert_eq!(body, r#"{"v":1,"verdict":"ok"}"#);
        let with = serde_json::to_string(&VerifyResponse::with_ticket(
            Verdict::Ok,
            Some("abc".to_string()),
        ))
        .unwrap();
        assert_eq!(with, r#"{"v":1,"verdict":"ok","ticket":"abc"}"#);
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
