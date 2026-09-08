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
//! WHY THE TICKET NEEDS NO SIGNATURE, AND HAS NO CONTENTS. The directory is
//! root-owned and mode 0700. An unprivileged process cannot create an entry in
//! it, so a name found there was written by punar-authd after a real PAM
//! success. The uid is the *subdirectory*, not a field, so there is no format
//! to parse and no parse to get wrong — `tickets/1000/<token>` can only ever
//! mean "uid 1000 proved itself". A signature would add key management to
//! protect a fact the filesystem already states.
//!
//! WHAT SPENDING MEANS. The unlink is the commit, and it happens before the age
//! is judged. Two callers racing on one token both see the file; only one
//! `remove_file` succeeds, and that one is the spender. Checking the age first
//! and removing afterwards would leave a window where both proceed.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Where `punar-authd` mints tickets (`punar_auth::protocol::TICKET_DIR`, not
/// imported: punard does not link libpam and must not grow a dependency on the
/// authenticator crate to read a directory name).
pub const TICKET_DIR: &str = "/run/punar-authd/tickets";

/// How long a ticket may be presented for. Mirrors
/// `punar_auth::protocol::TICKET_MAX_AGE_SECS`; the minting side sweeps at this
/// age too, so the two agreeing is belt and braces rather than a single point.
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
    /// It existed, and it was too old. Distinguished from `Missing` because the
    /// remedy differs: this one says "type your password again", and saying
    /// "no such ticket" there would send a person looking for a fault.
    Expired,
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
        }
    }

    /// A stable word for audit details and tests.
    pub fn as_str(self) -> &'static str {
        match self {
            ReauthError::Malformed => "malformed",
            ReauthError::Missing => "missing",
            ReauthError::Expired => "expired",
        }
    }
}

/// Spend `token` on behalf of `uid`. Consumes the ticket whether or not it
/// turns out to be fresh: a presented ticket is spent.
pub fn consume(dir: &Path, uid: u32, token: &str, now: SystemTime) -> Result<(), ReauthError> {
    if token.len() != TOKEN_LEN
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ReauthError::Malformed);
    }
    let path: PathBuf = dir.join(uid.to_string()).join(token);
    let minted_at = fs::metadata(&path)
        .and_then(|meta| meta.modified())
        .map_err(|_| ReauthError::Missing)?;
    // The unlink IS the spend. Losing this race means somebody else spent it.
    fs::remove_file(&path).map_err(|_| ReauthError::Missing)?;

    let age = now
        .duration_since(minted_at)
        // A ticket stamped in the future is a clock that moved. Treat it as
        // unusable rather than as infinitely fresh.
        .unwrap_or_else(|_| Duration::from_secs(TICKET_MAX_AGE_SECS + 1));
    if age.as_secs() > TICKET_MAX_AGE_SECS {
        return Err(ReauthError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::fs::DirBuilderExt;

    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("punard-reauth-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn mint(dir: &Path, uid: u32, token: &str) -> PathBuf {
        let per_uid = dir.join(uid.to_string());
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&per_uid)
            .unwrap();
        let path = per_uid.join(token);
        File::create(&path).unwrap();
        path
    }

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn a_fresh_ticket_is_accepted_exactly_once() {
        let dir = scratch("once");
        let path = mint(&dir, 1000, TOKEN);
        assert_eq!(consume(&dir, 1000, TOKEN, SystemTime::now()), Ok(()));
        assert!(!path.exists(), "spending a ticket removes it");
        assert_eq!(
            consume(&dir, 1000, TOKEN, SystemTime::now()),
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
        let path = mint(&dir, 1000, TOKEN);
        assert_eq!(
            consume(&dir, 1001, TOKEN, SystemTime::now()),
            Err(ReauthError::Missing)
        );
        assert!(path.exists(), "and the real owner's ticket was not spent");
        assert_eq!(consume(&dir, 1000, TOKEN, SystemTime::now()), Ok(()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_expired_ticket_is_refused_and_still_spent() {
        let dir = scratch("expired");
        let path = mint(&dir, 1000, TOKEN);
        let later = SystemTime::now() + Duration::from_secs(TICKET_MAX_AGE_SECS + 1);
        assert_eq!(consume(&dir, 1000, TOKEN, later), Err(ReauthError::Expired));
        assert!(
            !path.exists(),
            "an expired ticket must not survive to be retried against a lenient clock"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_ticket_exactly_at_the_window_edge_is_still_good() {
        let dir = scratch("edge");
        mint(&dir, 1000, TOKEN);
        let edge = SystemTime::now() + Duration::from_secs(TICKET_MAX_AGE_SECS);
        assert_eq!(consume(&dir, 1000, TOKEN, edge), Ok(()));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A token is checked for shape BEFORE it is joined to a path, so no
    /// traversal ever reaches the filesystem. The assertion is that these are
    /// `Malformed` — not `Missing`, which is what a path-joining implementation
    /// would return for most of them and which would mean the join happened.
    #[test]
    fn a_token_that_is_not_hex_never_becomes_a_path() {
        let dir = scratch("shape");
        for bad in [
            "",
            "short",
            "../../../../etc/shadow",
            "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde/",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefg",
        ] {
            assert_eq!(
                consume(&dir, 1000, bad, SystemTime::now()),
                Err(ReauthError::Malformed),
                "token {bad:?}"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_directory_is_a_missing_ticket_and_not_a_crash() {
        let dir = scratch("absent");
        assert_eq!(
            consume(&dir, 1000, TOKEN, SystemTime::now()),
            Err(ReauthError::Missing)
        );
    }
}
