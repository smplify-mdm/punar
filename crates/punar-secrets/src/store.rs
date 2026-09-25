//! Issuance and the in-memory token map — the structural half of the
//! section 53 promise (ipc.md section 16.4).
//!
//! # What the broker keeps, and what it cannot keep
//!
//! For every live credential the broker holds
//! `{sha256(token), class, owner_uid, agent_session_id, issued_at,
//! expires_at, revoked}` — [`IssuedRecord`] — and **not the token**. The
//! value exists in this process for the length of one request: it is
//! generated, hashed, wrapped in [`Redacted`], written to the response, and
//! dropped. That is why there is no method to fetch it again (see
//! [`crate::protocol`]): the broker could not answer one.
//!
//! Nothing here writes to disk. `punar-secrets` has **no state
//! directory**; its only disk writes are audit events through the shared
//! `punar_common::audit` writer, and an audit event carries the class name
//! only. A restart drops every live token, which is the correct failure
//! mode for a short-lived credential: the caller asks again.
//!
//! # Expiry has no timer (SPEC section 6.3)
//!
//! Expiry is computed **when a token is presented**. There is no sweep
//! thread, no `punar-secrets.timer`, and zero idle CPU. The honest
//! consequence, stated rather than hidden: a token that is never presented
//! again produces no `credential.expire` event. The event records the moment
//! expiry was *observed*; `expires_at` records the moment it *occurred*, so
//! the instant is always recoverable — the same rule the approval sweep
//! states in ipc.md section 14.4.
//!
//! # Expiry reads the boot clock (SMP-1405)
//!
//! Each record's TTL is a [`BootWindow`] opened at issuance and judged on the
//! boot clock ([`punar_common::trusted_time`]), shortened by the drift
//! allowance so it closes early and never late, and closed by a suspend or a
//! reboot. A wall clock rolled back cannot stretch a credential, and a broker that cannot read the boot clock
//! issues nothing and validates nothing. `issued_at` and `expires_at` stay on
//! the wall clock, for people to read.

use std::io;

use punar_common::Redacted;
use punar_common::time::rfc3339_utc_from_unix_seconds;
use punar_common::trusted_time::{BootStamp, BootWindow};
use serde::Serialize;

use crate::classes::CredentialClass;
use crate::sha256::sha256_hex;

/// Prefix on every value this build issues, so a leaked token is
/// identifiable as a **mock** in any grep, on any machine, forever
/// (ipc.md section 16.4). The class id follows, then the random part.
pub const TOKEN_PREFIX: &str = "punar-mock-";

/// Bytes of entropy per token (ipc.md section 16.4).
pub const TOKEN_ENTROPY_BYTES: usize = 32;

/// Live-token ceiling, device-wide.
///
/// Not in ipc.md section 16: it is a memory bound, not a wire behaviour.
/// The reasoning is the one behind every other bound in Milestone 9 — an
/// unbounded in-memory map is a local denial-of-service primitive, and
/// credential issuance is human/agent-paced, so a ceiling this high is
/// unreachable in normal use. On reaching it the broker first drops
/// records that have already expired (they authorize nothing) and only
/// then refuses, audited, with `result: "issuance_flood"`.
pub const MAX_LIVE_TOKENS: usize = 128;

/// One live credential, as the broker remembers it.
///
/// `Serialize` is derived deliberately: the crate's redaction test
/// round-trips this struct through `serde_json` and asserts the token
/// value cannot appear, which is only a meaningful assertion if the struct
/// *can* be serialized. There is no `Deserialize`, because nothing ever
/// reads one back — there is no file to read it from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssuedRecord {
    /// Lowercase hex SHA-256 of the token. The only thing that survives
    /// issuance.
    pub token_sha256: String,
    /// Kebab-case class id — also the audit `resource` and the M8 ledger's
    /// `credential_classes` entry.
    pub credential: String,
    pub owner_uid: u32,
    /// The managed agent session that asked, when the peer's cgroup proved
    /// one (docs/api/ipc.md section 12.5).
    pub agent_session_id: Option<String>,
    /// Wall clock, for people to read.
    pub issued_at: String,
    /// Wall clock, for people to read. The decision is `lifetime`.
    pub expires_at: String,
    /// **What decides expiry**: the TTL on the boot clock, opened at
    /// issuance. Lapses at the drift-shortened edge, at suspend and at
    /// reboot.
    pub lifetime: BootWindow,
    /// Set on the record handed to the audit path when a token is revoked.
    /// The map entry itself is dropped at the same moment — a tombstone
    /// would be a record of a credential that no longer exists.
    pub revoked: bool,
}

impl IssuedRecord {
    /// Past its window, or not judgeable at all (`now` is `None`, another
    /// boot, a clock that went backwards) — every one of those is expired.
    pub fn is_expired(&self, now: Option<&BootStamp>) -> bool {
        !self.lifetime.is_open(now)
    }

    /// Whole seconds left on the drift-shortened window, floored, and zero
    /// once it has closed — never more than the window will honour.
    pub fn remaining_secs(&self, now: Option<&BootStamp>) -> u64 {
        self.lifetime
            .remaining_ms(now)
            .map_or(0, |ms| u64::try_from(ms / 1_000).unwrap_or(0))
    }
}

/// "Now", read twice: the wall clock for the timestamps people read, and
/// the boot clock for every expiry decision. `trusted` is `None` when the
/// boot clock cannot be read, and then nothing is issued and nothing
/// validates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Now {
    pub wall_secs: u64,
    pub trusted: Option<BootStamp>,
}

/// What a presented token turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presented {
    /// Live, unexpired, unrevoked.
    Valid(IssuedRecord),
    /// Known, but its TTL had lapsed. The entry is dropped by the call
    /// that observed this, and the observation is audited **once**.
    Expired(IssuedRecord),
    /// Not a token this broker issued (or one it has already dropped).
    /// **Never audited** — there is nothing to attribute, and auditing it
    /// would hand any local process an audit-flood primitive (SPEC 6.4).
    Unknown,
}

/// Why an issuance was refused by the store itself (policy refusals happen
/// earlier, in [`crate::policy`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueError {
    /// The live-token ceiling was reached and nothing could be reclaimed.
    Flood,
    /// The class declares `max_ttl: 0` — never issuable, whatever policy
    /// says (`aws-prod` ships this way).
    NotIssuable,
    /// `getrandom(2)` failed. A broker that cannot get entropy must refuse,
    /// never fall back to a weaker source.
    NoEntropy,
    /// The boot clock could not be read, so the credential's lifetime could
    /// not be dated. A token whose expiry cannot be judged is not issued.
    NoClock,
}

/// Fills a buffer with cryptographic random bytes. A function pointer, so
/// the production source and the deterministic test source are the same
/// shape and neither can accidentally become the other.
pub type FillBytes = fn(&mut [u8]) -> io::Result<()>;

/// Production entropy: `getrandom(2)` via `rustix` (no `unsafe`, no
/// fallback to a userspace PRNG).
pub fn system_entropy(buffer: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let n =
            rustix::rand::getrandom(&mut buffer[filled..], rustix::rand::GetRandomFlags::empty())
                .map_err(io::Error::from)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "getrandom(2) returned no bytes",
            ));
        }
        filled += n;
    }
    Ok(())
}

/// The in-memory token map.
#[derive(Debug)]
pub struct TokenStore {
    entries: Vec<IssuedRecord>,
    max_live: usize,
    fill: FillBytes,
}

impl TokenStore {
    pub fn new(fill: FillBytes) -> TokenStore {
        TokenStore {
            entries: Vec::new(),
            max_live: MAX_LIVE_TOKENS,
            fill,
        }
    }

    /// A store with a lowered ceiling (tests of the bound).
    pub fn with_capacity_limit(fill: FillBytes, max_live: usize) -> TokenStore {
        TokenStore {
            entries: Vec::new(),
            max_live,
            fill,
        }
    }

    /// Live entries (including ones whose TTL has lapsed but that nobody
    /// has presented yet — see the module docs on observation).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries that are still within their TTL at `now`.
    pub fn live(&self, now: Option<&BootStamp>) -> usize {
        self.entries.iter().filter(|e| !e.is_expired(now)).count()
    }

    /// Mint a token for `class`.
    ///
    /// Returns the value **once** — the caller writes it to the response
    /// and drops it — together with the record the broker keeps. There is
    /// no second call that can return the same value.
    pub fn issue(
        &mut self,
        class: &CredentialClass,
        ttl_secs: u64,
        owner_uid: u32,
        agent_session_id: Option<&str>,
        now: &Now,
    ) -> Result<(Redacted<String>, IssuedRecord), IssueError> {
        if !class.issuable() || ttl_secs == 0 {
            return Err(IssueError::NotIssuable);
        }
        let Some(opened) = now.trusted.clone() else {
            return Err(IssueError::NoClock);
        };
        if self.entries.len() >= self.max_live {
            // Reclaim what has already lapsed before refusing.
            self.entries
                .retain(|entry| !entry.is_expired(Some(&opened)));
            if self.entries.len() >= self.max_live {
                return Err(IssueError::Flood);
            }
        }

        let mut bytes = [0u8; TOKEN_ENTROPY_BYTES];
        (self.fill)(&mut bytes).map_err(|_| IssueError::NoEntropy)?;
        let token = format!("{TOKEN_PREFIX}{}-{}", class.id, base64url(&bytes));

        let record = IssuedRecord {
            token_sha256: sha256_hex(token.as_bytes()),
            credential: class.id.clone(),
            owner_uid,
            agent_session_id: agent_session_id.map(str::to_string),
            issued_at: rfc3339_utc_from_unix_seconds(now.wall_secs),
            expires_at: rfc3339_utc_from_unix_seconds(now.wall_secs.saturating_add(ttl_secs)),
            lifetime: BootWindow::of_secs(opened, ttl_secs),
            revoked: false,
        };
        self.entries.push(record.clone());
        Ok((Redacted::new(token), record))
    }

    /// Present a token: the single place a token value is compared against
    /// what the broker knows, and it compares **hashes**.
    ///
    /// `expect_class`, when given, must match the class the token was
    /// issued for; a mismatch answers [`Presented::Unknown`] rather than
    /// confirming that the token exists under another class.
    pub fn present(
        &mut self,
        token: &Redacted<String>,
        expect_class: Option<&str>,
        now: Option<&BootStamp>,
    ) -> Presented {
        let digest = sha256_hex(token.expose_secret().as_bytes());
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.token_sha256 == digest)
        else {
            return Presented::Unknown;
        };
        if expect_class.is_some_and(|class| class != self.entries[index].credential) {
            return Presented::Unknown;
        }
        if self.entries[index].is_expired(now) {
            return Presented::Expired(self.entries.remove(index));
        }
        Presented::Valid(self.entries[index].clone())
    }

    /// Drop a token immediately. Returns the record (marked `revoked`) when
    /// the token was live, so the caller can audit the class; `None` for a
    /// token this broker does not know, which is not audited.
    pub fn revoke(&mut self, token: &Redacted<String>) -> Option<IssuedRecord> {
        let digest = sha256_hex(token.expose_secret().as_bytes());
        let index = self
            .entries
            .iter()
            .position(|entry| entry.token_sha256 == digest)?;
        let mut record = self.entries.remove(index);
        record.revoked = true;
        Some(record)
    }

    /// Every record, for the redaction test and the `status` count. The
    /// records contain no token values by construction.
    pub fn records(&self) -> &[IssuedRecord] {
        &self.entries
    }
}

/// URL-safe base64 without padding (RFC 4648 section 5), ~15 lines rather
/// than a dependency — the `sha256` module's reasoning, same trade.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let indices = [
            (triple >> 18) & 0x3f,
            (triple >> 12) & 0x3f,
            (triple >> 6) & 0x3f,
            triple & 0x3f,
        ];
        let keep = chunk.len() + 1; // 3 bytes -> 4 chars, 2 -> 3, 1 -> 2
        for index in indices.iter().take(keep) {
            out.push(ALPHABET[*index as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};

    use super::*;
    use crate::classes::ClassCatalog;

    static COUNTER: AtomicU8 = AtomicU8::new(0);

    /// Deterministic, distinct-per-call bytes. Never reachable from the
    /// daemon wiring — [`TokenStore::new`] takes the production source.
    fn test_entropy(buffer: &mut [u8]) -> io::Result<()> {
        let seed = COUNTER.fetch_add(1, Ordering::SeqCst);
        for (i, slot) in buffer.iter_mut().enumerate() {
            *slot = seed.wrapping_mul(31).wrapping_add(i as u8);
        }
        Ok(())
    }

    fn no_entropy(_buffer: &mut [u8]) -> io::Result<()> {
        Err(io::Error::other("no entropy in this test"))
    }

    fn catalog() -> ClassCatalog {
        ClassCatalog::parse(include_str!("../share/classes.yaml")).unwrap()
    }

    fn store() -> TokenStore {
        TokenStore::new(test_entropy)
    }

    const BOOT: &str = "0f2a6c1e-7d3b-4a59-9c8e-1b2d3e4f5a6b";
    const NEXT_BOOT: &str = "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b";

    /// This boot's raw clock at `raw_bt_ms`.
    fn at(raw_bt_ms: i64) -> BootStamp {
        BootStamp {
            boot_id: BOOT.to_string(),
            raw_bt_ms,
            sleep_ms: 0,
            suspends: 0,
        }
    }

    /// Both clocks at second `secs`: the wall clock for the display strings,
    /// the boot clock (in ms) for the decisions.
    fn now(secs: u64) -> Now {
        Now {
            wall_secs: secs,
            trusted: Some(at(secs as i64 * 1_000)),
        }
    }

    fn at_secs(secs: i64) -> Option<BootStamp> {
        Some(at(secs * 1_000))
    }

    #[test]
    fn an_issued_token_is_marked_mock_carries_its_class_and_is_high_entropy() {
        let catalog = catalog();
        let class = catalog.get("aws-dev").unwrap();
        let mut store = store();
        let (token, record) = store.issue(class, 60, 1000, None, &now(1_000_000)).unwrap();
        let value = token.expose_secret();

        assert!(value.starts_with("punar-mock-aws-dev-"), "{value}");
        // 32 bytes -> 43 base64url characters, no padding.
        assert_eq!(value.len(), "punar-mock-aws-dev-".len() + 43);
        assert!(!value.contains('='));
        assert_eq!(record.credential, "aws-dev");
        assert_eq!(
            record.lifetime,
            BootWindow::of_secs(at(1_000_000_000), 60),
            "the decision is a window on the boot clock"
        );
        assert_eq!(record.expires_at, "1970-01-12T13:47:40Z");
        assert!(!record.revoked);
    }

    #[test]
    fn the_record_the_broker_keeps_is_a_hash_not_a_token() {
        let catalog = catalog();
        let mut store = store();
        let (token, record) = store
            .issue(catalog.get("github").unwrap(), 60, 0, None, &now(10))
            .unwrap();
        assert_eq!(
            record.token_sha256,
            crate::sha256::sha256_hex(token.expose_secret().as_bytes())
        );
        // The store cannot produce the value again by any route.
        let serialized = serde_json::to_string(store.records()).unwrap();
        assert!(!serialized.contains(token.expose_secret()));
        assert!(serialized.contains(&record.token_sha256));
    }

    #[test]
    fn two_issues_never_collide() {
        let catalog = catalog();
        let class = catalog.get("github").unwrap();
        let mut store = store();
        let (a, _) = store.issue(class, 60, 0, None, &now(10)).unwrap();
        let (b, _) = store.issue(class, 60, 0, None, &now(10)).unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn a_live_token_validates_and_an_expired_one_is_dropped_when_observed() {
        let catalog = catalog();
        let class = catalog.get("github").unwrap();
        let mut store = store();
        let (token, record) = store
            .issue(class, 5, 1000, Some("agt_x1"), &now(100))
            .unwrap();

        match store.present(&token, Some("github"), at_secs(103).as_ref()) {
            Presented::Valid(found) => {
                assert_eq!(found.token_sha256, record.token_sha256);
                assert_eq!(found.agent_session_id.as_deref(), Some("agt_x1"));
                // 2 000 ms less the 1 ms drift allowance, floored: never more
                // than the window will honour.
                assert_eq!(found.remaining_secs(at_secs(103).as_ref()), 1);
                assert_eq!(found.remaining_secs(at_secs(104).as_ref()), 0);
            }
            other => panic!("expected valid, got {other:?}"),
        }
        // The last live millisecond: 5 000 ms less the 1 ms allowance.
        assert!(matches!(
            store.present(&token, None, Some(&at(100_000 + 4_998))),
            Presented::Valid(_)
        ));

        // At the drift-shortened edge the token is already gone: a TTL is a
        // deadline, not a grace period, and the edge comes early, never late.
        match store.present(&token, None, Some(&at(100_000 + 4_999))) {
            Presented::Expired(found) => assert_eq!(found.credential, "github"),
            other => panic!("expected expired, got {other:?}"),
        }
        assert_eq!(store.len(), 0, "an observed expiry drops the entry");
        assert_eq!(
            store.present(&token, None, at_secs(106).as_ref()),
            Presented::Unknown
        );
    }

    /// Another boot, a clock that went backwards, or no readable clock: the
    /// credential cannot be judged, so it is expired.
    #[test]
    fn a_token_that_cannot_be_judged_is_expired() {
        let catalog = catalog();
        let class = catalog.get("github").unwrap();
        let rebooted = BootStamp {
            boot_id: NEXT_BOOT.to_string(),
            raw_bt_ms: 100_001,
            sleep_ms: 0,
            suspends: 0,
        };
        for judged_at in [Some(rebooted), Some(at(99_999)), None] {
            let mut store = store();
            let (token, _) = store.issue(class, 3600, 0, None, &now(100)).unwrap();
            assert!(
                matches!(
                    store.present(&token, None, judged_at.as_ref()),
                    Presented::Expired(_)
                ),
                "{judged_at:?}"
            );
            assert_eq!(store.live(judged_at.as_ref()), 0);
        }
    }

    /// A broker that cannot read the boot clock issues nothing: a token whose
    /// expiry cannot be judged would be either immortal or born dead.
    #[test]
    fn no_readable_clock_issues_nothing() {
        let catalog = catalog();
        let mut store = store();
        let blind = Now {
            wall_secs: 100,
            trusted: None,
        };
        assert_eq!(
            store
                .issue(catalog.get("github").unwrap(), 60, 0, None, &blind)
                .err(),
            Some(IssueError::NoClock)
        );
        assert!(store.is_empty());
    }

    #[test]
    fn a_token_presented_under_the_wrong_class_is_simply_unknown() {
        let catalog = catalog();
        let mut store = store();
        let (token, _) = store
            .issue(catalog.get("github").unwrap(), 60, 0, None, &now(10))
            .unwrap();
        assert_eq!(
            store.present(&token, Some("aws-dev"), at_secs(11).as_ref()),
            Presented::Unknown
        );
        // …and the entry is untouched, so the real class still validates.
        assert!(matches!(
            store.present(&token, Some("github"), at_secs(11).as_ref()),
            Presented::Valid(_)
        ));
    }

    #[test]
    fn an_unknown_token_is_unknown_not_an_error() {
        let mut store = store();
        assert_eq!(
            store.present(
                &Redacted::new("punar-mock-github-nope".to_string()),
                None,
                at_secs(10).as_ref()
            ),
            Presented::Unknown
        );
        assert!(store.revoke(&Redacted::new("nope".to_string())).is_none());
    }

    #[test]
    fn revoke_drops_the_entry_immediately_and_marks_the_record() {
        let catalog = catalog();
        let mut store = store();
        let (token, _) = store
            .issue(catalog.get("aws-dev").unwrap(), 3600, 1000, None, &now(10))
            .unwrap();
        let record = store.revoke(&token).expect("live token revokes");
        assert!(record.revoked);
        assert_eq!(record.credential, "aws-dev");
        assert_eq!(store.len(), 0);
        assert_eq!(
            store.present(&token, None, at_secs(11).as_ref()),
            Presented::Unknown
        );
        assert!(store.revoke(&token).is_none(), "revoking twice is a no-op");
    }

    #[test]
    fn a_class_that_is_never_issuable_is_refused_by_the_store_too() {
        let catalog = catalog();
        let mut store = store();
        assert_eq!(
            store
                .issue(catalog.get("aws-prod").unwrap(), 60, 0, None, &now(10))
                .err(),
            Some(IssueError::NotIssuable)
        );
        assert_eq!(
            store
                .issue(catalog.get("github").unwrap(), 0, 0, None, &now(10))
                .err(),
            Some(IssueError::NotIssuable)
        );
    }

    #[test]
    fn entropy_failure_refuses_rather_than_weakening_the_token() {
        let catalog = catalog();
        let mut store = TokenStore::new(no_entropy);
        assert_eq!(
            store
                .issue(catalog.get("github").unwrap(), 60, 0, None, &now(10))
                .err(),
            Some(IssueError::NoEntropy)
        );
        assert!(store.is_empty());
    }

    #[test]
    fn the_live_ceiling_reclaims_expired_entries_before_refusing() {
        let catalog = catalog();
        let class = catalog.get("github").unwrap();
        let mut store = TokenStore::with_capacity_limit(test_entropy, 2);
        store.issue(class, 5, 0, None, &now(100)).unwrap();
        store.issue(class, 3600, 0, None, &now(100)).unwrap();
        // Full, and nothing has lapsed yet.
        assert_eq!(
            store.issue(class, 60, 0, None, &now(101)).err(),
            Some(IssueError::Flood)
        );
        // Once the short one lapses it is reclaimed and issuance resumes.
        assert!(store.issue(class, 60, 0, None, &now(200)).is_ok());
        assert_eq!(store.len(), 2);
        assert_eq!(store.live(at_secs(200).as_ref()), 2);
    }

    #[test]
    fn base64url_is_rfc4648_url_safe_and_unpadded() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64url(&[0xfb, 0xff, 0xfe]), "-__-");
        assert!(!base64url(&[0xff; 32]).contains('+'));
        assert!(!base64url(&[0xff; 32]).contains('/'));
    }

    /// `Redacted` covers the value; this pins that the *store* never has a
    /// field that could hold one in the first place.
    #[test]
    fn no_serialized_form_of_the_store_can_contain_a_token() {
        let catalog = catalog();
        let mut store = store();
        let (token, _) = store
            .issue(
                catalog.get("aws-dev").unwrap(),
                60,
                1000,
                Some("agt_a1"),
                &now(10),
            )
            .unwrap();
        let value = token.expose_secret().clone();
        for record in store.records() {
            let json = serde_json::to_string(record).unwrap();
            assert!(!json.contains(&value), "{json}");
            let debug = format!("{record:?}");
            assert!(!debug.contains(&value), "{debug}");
        }
        assert!(!format!("{store:?}").contains(&value));
        assert!(!format!("{token:?}").contains(&value));
    }
}
