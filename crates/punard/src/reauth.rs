//! Spending a `punar-authd` re-authentication ticket.
//!
//! WHY A TICKET AT ALL. punard is root and cannot verify a desktop user's
//! password itself: `punar-authd` refuses uid 0 by design (it exists so that a
//! caller can only ever attempt their own account, and root has no account to
//! attempt), and re-implementing PAM inside a long-running root daemon would
//! put authentication authority in a resident process — the exact thing
//! punar-auth's one-process-per-attempt design avoids. So the person
//! re-authenticates against punar-authd, which mints a ticket, and punard spends
//! it.
//!
//! WHY THE TICKET NEEDS NO SIGNATURE. The directory is root-owned and mode
//! 0700. An unprivileged process cannot create an entry in it, so a name found
//! there was written by punar-authd after a real PAM success. The uid is the
//! *subdirectory*, not a field, so `tickets/1000/<token>` can only ever mean
//! "uid 1000 proved itself". A signature would add key management to protect a
//! fact the filesystem already states.
//!
//! WHAT THE TICKET SAYS: WHEN, ON THE BOOT CLOCK (SMP-1405). The file holds one
//! [`BootStamp`] — `{"boot_id": …, "raw_bt_ms": …, "sleep_ms": …,
//! "suspends": …}` — taken by punar-authd at the moment of the PAM success,
//! and its age is judged against punard's own boot clock
//! ([`punar_common::trusted_time`]). It used to be the file's mtime against
//! the wall clock, which anyone who could step that clock back could stretch.
//! A ticket is refused as expired when it is from another boot, when the
//! machine has suspended since it was minted, when its stamp is in the future
//! of this clock, when it carries no readable stamp (an empty ticket an older
//! punar-authd minted during an upgrade: the person types their password
//! again), or when punard cannot read its own clock.
//!
//! WHAT THE TICKET SAYS: FOR WHICH CALL, AND BY WHOM (F0-S1, F0-S4). Since
//! the F0 review the body is a [`TicketBody`]: the mint stamp above, the one
//! IPC method the person typed their password for, and the one process — pid
//! and start time — that may present it. A ticket is spent only on that
//! method, and only when the connection's peer (`SO_PEERCRED`) is that
//! process. So a confirmation given to approve a time-zone change cannot be
//! spent on `admins.set`, and a ticket copied out of the process it was meant
//! for — however it was copied — is worth nothing to the copier. An older
//! punar-authd's bare stamp binds nothing and is refused as expired.
//!
//! WHAT SPENDING MEANS. The unlink is the commit, and it happens before the age
//! is judged. Two callers racing on one token may both read the file; only one
//! `remove_file` succeeds, and that one is the spender. Judging the age first
//! and removing afterwards would leave a window where both proceed.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use punar_common::reauth_ticket::{Spender, TICKET_MAX_BYTES, TicketBody};
use punar_common::trusted_time::{BootWindow, TrustedClock};

/// Where `punar-authd` mints tickets (`punar_auth::protocol::TICKET_DIR`, not
/// imported: punard does not link libpam and must not grow a dependency on the
/// authenticator crate to read a directory name).
pub const TICKET_DIR: &str = "/run/punar-authd/tickets";

/// How long a ticket may be presented for. Mirrors
/// `punar_auth::protocol::TICKET_MAX_AGE_SECS`; the minting side sweeps at this
/// age too, so the two agreeing is belt and braces rather than a single point.
/// Measured on the boot clock and shortened by the drift allowance, so a
/// ticket is refused a few milliseconds before two minutes, never after.
pub const TICKET_MAX_AGE_SECS: u64 = 120;

/// A token is 256 bits of hex and nothing else. Checked before the name is
/// joined to a path, so `..`, `/` and every other traversal shape is refused as
/// a malformed token rather than resolved.
const TOKEN_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReauthError {
    /// The token is not the shape punar-authd mints. Never reaches the
    /// filesystem.
    Malformed,
    /// No such ticket for this uid — never minted, already spent, or minted for
    /// somebody else.
    Missing,
    /// It existed, and it was too old — or could not be dated at all, which is
    /// the same answer for the same reason. Distinguished from `Missing`
    /// because the remedy differs: this one says "type your password again",
    /// and saying "no such ticket" there would send a person looking for a
    /// fault.
    Expired,
    /// It was typed for a different call than the one presenting it.
    WrongAction,
    /// It was minted for a different process than the one presenting it —
    /// the mark of a ticket copied out of the program it was meant for.
    WrongProcess,
}

impl ReauthError {
    /// The sentence a person should read. Second person, and it says what to do
    /// next rather than what the daemon observed.
    pub fn as_message(self) -> &'static str {
        match self {
            ReauthError::Malformed => {
                "the confirmation was not in a form this device could check, so nothing was changed"
            }
            ReauthError::Missing => {
                "this device has no record of you confirming your password just now, so nothing was changed"
            }
            ReauthError::Expired => {
                "the confirmation took longer than two minutes and has expired, so nothing was changed"
            }
            ReauthError::WrongAction => {
                "the confirmation was given for a different change, so nothing was changed"
            }
            ReauthError::WrongProcess => {
                "the confirmation was given to a different program than the one that sent it, so nothing was changed"
            }
        }
    }

    /// A stable word for audit details and tests.
    pub fn as_str(self) -> &'static str {
        match self {
            ReauthError::Malformed => "malformed",
            ReauthError::Missing => "missing",
            ReauthError::Expired => "expired",
            ReauthError::WrongAction => "wrong_action",
            ReauthError::WrongProcess => "wrong_process",
        }
    }
}

/// Spend `token` on behalf of `uid` for the call `action`, presented by the
/// process `spender` (the connection's peer, as the kernel names it; `None`
/// when it could not be resolved, which no ticket matches), judging its age on
/// `clock`. Consumes the ticket whether or not it turns out to be good: a
/// presented ticket is spent.
pub fn consume(
    dir: &Path,
    uid: u32,
    token: &str,
    clock: &dyn TrustedClock,
    action: &str,
    spender: Option<Spender>,
) -> Result<(), ReauthError> {
    if token.len() != TOKEN_LEN
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ReauthError::Malformed);
    }
    let path: PathBuf = dir.join(uid.to_string()).join(token);
    let mut body = Vec::new();
    fs::File::open(&path)
        .and_then(|file| file.take(TICKET_MAX_BYTES + 1).read_to_end(&mut body))
        .map_err(|_| ReauthError::Missing)?;
    // The unlink IS the spend. Losing this race means somebody else spent it.
    fs::remove_file(&path).map_err(|_| ReauthError::Missing)?;

    let Some(ticket) = TicketBody::parse(&body) else {
        return Err(ReauthError::Expired);
    };
    if !BootWindow::of_secs(ticket.minted, TICKET_MAX_AGE_SECS).is_open(clock.now().as_ref()) {
        return Err(ReauthError::Expired);
    }
    if ticket.action != action {
        return Err(ReauthError::WrongAction);
    }
    if spender != Some(ticket.spender) {
        return Err(ReauthError::WrongProcess);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::DirBuilderExt;

    use punar_common::trusted_time::{ManualClock, live_budget_ms};

    use super::*;

    const BOOT: &str = "0f2a6c1e-7d3b-4a59-9c8e-1b2d3e4f5a6b";
    const NEXT_BOOT: &str = "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b";
    const T0: i64 = 5_000_000;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("punard-reauth-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// Write a ticket body exactly where punar-authd would.
    fn mint_body(dir: &Path, uid: u32, token: &str, body: &[u8]) -> PathBuf {
        let per_uid = dir.join(uid.to_string());
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&per_uid)
            .unwrap();
        let path = per_uid.join(token);
        fs::write(&path, body).unwrap();
        path
    }

    const ACTION: &str = "policy.set";
    const SPENDER: Spender = Spender {
        pid: 4242,
        start: 98_765,
    };

    /// A ticket stamped at `clock`'s current reading, for [`ACTION`] by
    /// [`SPENDER`], as punar-authd mints it.
    fn mint(dir: &Path, uid: u32, token: &str, clock: &ManualClock) -> PathBuf {
        let body = TicketBody {
            minted: clock.now().unwrap(),
            action: ACTION.to_string(),
            spender: SPENDER,
        };
        mint_body(dir, uid, token, &serde_json::to_vec(&body).unwrap())
    }

    /// Present `token` as [`SPENDER`] making the [`ACTION`] call.
    fn spend(
        dir: &Path,
        uid: u32,
        token: &str,
        clock: &dyn TrustedClock,
    ) -> Result<(), ReauthError> {
        consume(dir, uid, token, clock, ACTION, Some(SPENDER))
    }

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn a_fresh_ticket_is_accepted_exactly_once() {
        let dir = scratch("once");
        let clock = ManualClock::new(BOOT, T0);
        let path = mint(&dir, 1000, TOKEN, &clock);
        assert_eq!(spend(&dir, 1000, TOKEN, &clock), Ok(()));
        assert!(!path.exists(), "spending a ticket removes it");
        assert_eq!(
            spend(&dir, 1000, TOKEN, &clock),
            Err(ReauthError::Missing),
            "a second presentation of the same ticket is not a second authorization"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The property the whole design rests on: a ticket belongs to the uid whose
    /// directory it is in, and no other caller can present it. If this ever
    /// stopped holding, one person's password would authorize another person's
    /// administrative change.
    #[test]
    fn a_ticket_minted_for_one_uid_is_invisible_to_another() {
        let dir = scratch("uid");
        let clock = ManualClock::new(BOOT, T0);
        let path = mint(&dir, 1000, TOKEN, &clock);
        assert_eq!(spend(&dir, 1001, TOKEN, &clock), Err(ReauthError::Missing));
        assert!(path.exists(), "and the real owner's ticket was not spent");
        assert_eq!(spend(&dir, 1000, TOKEN, &clock), Ok(()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_expired_ticket_is_refused_and_still_spent() {
        let dir = scratch("expired");
        let clock = ManualClock::new(BOOT, T0);
        let path = mint(&dir, 1000, TOKEN, &clock);
        clock.advance_secs(TICKET_MAX_AGE_SECS + 1);
        assert_eq!(spend(&dir, 1000, TOKEN, &clock), Err(ReauthError::Expired));
        assert!(
            !path.exists(),
            "an expired ticket must not survive to be retried against a lenient clock"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The window is two minutes less the drift allowance (24 ms), and the
    /// edge is exact: the last live millisecond is accepted, the next refused.
    #[test]
    fn the_window_edge_is_exact_and_early() {
        let dir = scratch("edge");
        let budget = live_budget_ms(120_000);
        assert_eq!(budget, 119_976);

        let clock = ManualClock::new(BOOT, T0);
        mint(&dir, 1000, TOKEN, &clock);
        clock.advance_ms(budget - 1);
        assert_eq!(spend(&dir, 1000, TOKEN, &clock), Ok(()));

        let clock = ManualClock::new(BOOT, T0);
        mint(&dir, 1000, TOKEN, &clock);
        clock.advance_ms(budget);
        assert_eq!(spend(&dir, 1000, TOKEN, &clock), Err(ReauthError::Expired));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A ticket from another boot cannot be dated here. /run is a tmpfs, so
    /// one should never survive a reboot, and if one somehow does it is dead.
    #[test]
    fn a_ticket_from_another_boot_is_refused() {
        let dir = scratch("boot");
        let clock = ManualClock::new(BOOT, T0);
        let path = mint(&dir, 1000, TOKEN, &clock);
        clock.reboot(NEXT_BOOT, T0 + 1);
        assert_eq!(spend(&dir, 1000, TOKEN, &clock), Err(ReauthError::Expired));
        assert!(!path.exists(), "and it was spent all the same");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A ticket minted before a suspend is refused after it, however little
    /// time passed awake: the kernel may have under-counted the sleep.
    #[test]
    fn a_ticket_from_before_a_suspend_is_refused() {
        let dir = scratch("suspend");
        let clock = ManualClock::new(BOOT, T0);
        let path = mint(&dir, 1000, TOKEN, &clock);
        clock.advance_secs(5);
        clock.suspend(3_000);
        assert_eq!(spend(&dir, 1000, TOKEN, &clock), Err(ReauthError::Expired));
        assert!(!path.exists(), "and it was spent all the same");
        // One minted after the resume is good.
        mint(&dir, 1000, TOKEN, &clock);
        clock.advance_secs(5);
        assert_eq!(spend(&dir, 1000, TOKEN, &clock), Ok(()));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A stamp in this clock's future is a forgery or a clock that moved;
    /// either way it is not "infinitely fresh".
    #[test]
    fn a_ticket_stamped_in_the_future_is_refused() {
        let dir = scratch("future");
        let clock = ManualClock::new(BOOT, T0);
        clock.advance_secs(30);
        mint(&dir, 1000, TOKEN, &clock);
        let earlier = ManualClock::new(BOOT, T0);
        assert_eq!(
            spend(&dir, 1000, TOKEN, &earlier),
            Err(ReauthError::Expired)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// No wall clock is consulted: a ticket whose file mtime says 1970, or
    /// next century, is judged by its stamp alone.
    #[test]
    fn the_file_mtime_is_not_an_input() {
        let dir = scratch("mtime");
        let clock = ManualClock::new(BOOT, T0);
        let path = mint(&dir, 1000, TOKEN, &clock);
        let file = fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(std::time::UNIX_EPOCH).unwrap();
        drop(file);
        assert_eq!(spend(&dir, 1000, TOKEN, &clock), Ok(()));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A ticket that cannot be dated is refused as expired and spent: the
    /// empty ticket an older punar-authd mints, a damaged body, a stamp with
    /// extra fields, an oversized file — and any ticket at all while punard
    /// cannot read its own clock.
    #[test]
    fn a_ticket_that_cannot_be_dated_is_refused() {
        let dir = scratch("undated");
        let clock = ManualClock::new(BOOT, T0);
        let stamp = serde_json::to_string(&clock.now().unwrap()).unwrap();
        let oversized = format!("{stamp}{}", " ".repeat(TICKET_MAX_BYTES as usize));
        for body in [
            String::new(),
            // An older punar-authd's ticket: a perfectly good stamp that
            // binds no call and no process.
            stamp.clone(),
            "not json".to_string(),
            format!(r#"{{"boot_id":"{BOOT}"}}"#),
            format!(r#"{{"boot_id":"{BOOT}","raw_bt_ms":{T0}}}"#),
            format!(
                r#"{{"boot_id":"{BOOT}","raw_bt_ms":{T0},"sleep_ms":0,"suspends":0,"extra":1}}"#
            ),
            format!(r#"{{"boot_id":"not-a-boot","raw_bt_ms":{T0},"sleep_ms":0,"suspends":0}}"#),
            format!(r#"{{"boot_id":"{BOOT}","raw_bt_ms":-1,"sleep_ms":0,"suspends":0}}"#),
            format!(r#"{{"boot_id":"{BOOT}","raw_bt_ms":{T0},"sleep_ms":-1,"suspends":0}}"#),
            oversized,
        ] {
            let path = mint_body(&dir, 1000, TOKEN, body.as_bytes());
            assert_eq!(
                spend(&dir, 1000, TOKEN, &clock),
                Err(ReauthError::Expired),
                "{body:?}"
            );
            assert!(!path.exists(), "an undatable ticket is still spent");
        }

        mint(&dir, 1000, TOKEN, &clock);
        clock.set(None);
        assert_eq!(spend(&dir, 1000, TOKEN, &clock), Err(ReauthError::Expired));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A token is checked for shape BEFORE it is joined to a path, so no
    /// traversal ever reaches the filesystem. The assertion is that these are
    /// `Malformed` — not `Missing`, which is what a path-joining implementation
    /// would return for most of them and which would mean the join happened.
    #[test]
    fn a_token_that_is_not_hex_never_becomes_a_path() {
        let dir = scratch("shape");
        let clock = ManualClock::new(BOOT, T0);
        for bad in [
            "",
            "short",
            "../../../../etc/shadow",
            "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde/",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefg",
        ] {
            assert_eq!(
                spend(&dir, 1000, bad, &clock),
                Err(ReauthError::Malformed),
                "token {bad:?}"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_directory_is_a_missing_ticket_and_not_a_crash() {
        let dir = scratch("absent");
        let clock = ManualClock::new(BOOT, T0);
        assert_eq!(spend(&dir, 1000, TOKEN, &clock), Err(ReauthError::Missing));
    }

    /// F0 review: a confirmation is spent by the call it was typed for, and
    /// by the process it was minted for, or not at all — and a presentation
    /// that fails either test still spends it, so the copier cannot retry.
    #[test]
    fn a_ticket_is_spent_only_on_its_call_by_its_process() {
        let dir = scratch("bound");
        let clock = ManualClock::new(BOOT, T0);

        let path = mint(&dir, 1000, TOKEN, &clock);
        assert_eq!(
            consume(&dir, 1000, TOKEN, &clock, "admins.set", Some(SPENDER)),
            Err(ReauthError::WrongAction)
        );
        assert!(
            !path.exists(),
            "a ticket presented for another call is spent"
        );

        for (who, what) in [
            (None, "a peer whose process could not be resolved"),
            (
                Some(Spender {
                    pid: 4243,
                    ..SPENDER
                }),
                "another process",
            ),
            (
                Some(Spender {
                    start: SPENDER.start + 1,
                    ..SPENDER
                }),
                "a later process that reused the pid",
            ),
        ] {
            let path = mint(&dir, 1000, TOKEN, &clock);
            assert_eq!(
                consume(&dir, 1000, TOKEN, &clock, ACTION, who),
                Err(ReauthError::WrongProcess),
                "{what}"
            );
            assert!(!path.exists(), "{what}: spent all the same");
        }

        mint(&dir, 1000, TOKEN, &clock);
        assert_eq!(spend(&dir, 1000, TOKEN, &clock), Ok(()));
        let _ = fs::remove_dir_all(&dir);
    }
}
