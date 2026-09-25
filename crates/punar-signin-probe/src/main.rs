//! `punar-signin-probe` — **dev/CI harness — not a product component.**
//!
//! Signs the calling account in through one PAM service's whole stack, in the
//! order greetd runs it at a password sign-in: authenticate, account,
//! credentials and session open, then session close and credentials delete,
//! as a sign-out does. The password is read from stdin, never from argv,
//! where every process on the machine could read it.
//!
//! WHY IT EXISTS. The desktop gate's keyring check (surfaces-check.sh group
//! 8k) must prove what a password sign-in writes: the login keyring
//! pam_gnome_keyring creates under that password. The development image
//! autologins, and greetd's `initial_session` skips the whole `auth` stack, so
//! no password ever goes through PAM there otherwise. `pamtester`, which the
//! Debian lanes used for this, is not packaged for Arch, so the Arch lane
//! stood in for the stack with `gnome-keyring-daemon --unlock`, which proved
//! the daemon rather than the sign-in. This runs the same stack on every lane.
//!
//! It holds no privilege: it runs as the account it signs in, so `pam_unix`
//! verifies that account's own password through `unix_chkpwd`, exactly as the
//! lock screen's stack would for an unprivileged caller, and a module that
//! needs root fails as it would for any user. Staged only into the
//! development image; release-image policy A5 refuses it anywhere else.
//!
//! Exit status: 0 when every stage succeeded, 1 naming the stage that failed
//! on stderr, 2 for a usage error.

#![forbid(unsafe_code)]

use std::io::Read;
use std::process::ExitCode;

use pam_client2::conv_mock::Conversation;
use pam_client2::{Context, Flag};
use zeroize::{Zeroize, Zeroizing};

/// A password longer than this is refused rather than truncated.
const MAX_PASSWORD_BYTES: usize = 4096;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [service, user] = args.as_slice() else {
        eprintln!("usage: punar-signin-probe <pam-service> <user>  (the password on stdin)");
        return ExitCode::from(2);
    };
    let password = match read_password(std::io::stdin().lock()) {
        Ok(password) => password,
        Err(why) => {
            eprintln!("punar-signin-probe: {why}");
            return ExitCode::from(2);
        }
    };
    match sign_in(service, user, &password) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("punar-signin-probe: {why}");
            ExitCode::from(1)
        }
    }
}

/// The first line of `input`: what `printf '%s\n'` or a here-string hands
/// over, without its newline.
fn read_password(input: impl Read) -> Result<Zeroizing<String>, String> {
    let mut raw = Zeroizing::new(Vec::new());
    input
        .take(MAX_PASSWORD_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("the password could not be read from stdin ({})", e.kind()))?;
    if raw.len() > MAX_PASSWORD_BYTES {
        return Err(format!(
            "the password on stdin is longer than {MAX_PASSWORD_BYTES} bytes"
        ));
    }
    let line = raw.split(|&b| b == b'\n').next().unwrap_or_default();
    let password = String::from_utf8(line.to_vec()).map_err(|e| {
        e.into_bytes().zeroize();
        "the password on stdin is not UTF-8".to_string()
    })?;
    let password = Zeroizing::new(password);
    if password.is_empty() {
        return Err("no password on stdin".to_string());
    }
    Ok(password)
}

/// The sign-in, stage by stage; the first stage PAM refuses is the error.
fn sign_in(service: &str, user: &str, password: &str) -> Result<(), String> {
    let conversation = Conversation::with_credentials(user, password);
    let mut context = Context::new(service, Some(user), conversation)
        .map_err(|e| format!("the {service} stack could not be started ({e})"))?;
    let authenticated = context.authenticate(Flag::DISALLOW_NULL_AUTHTOK);
    // No later stage asks for anything, so the conversation's copy of the
    // password goes now; a module that kept the token has its own.
    context.conversation_mut().password.zeroize();
    authenticated.map_err(|e| format!("{service}: authenticate failed ({e})"))?;
    context
        .acct_mgmt(Flag::DISALLOW_NULL_AUTHTOK)
        .map_err(|e| format!("{service}: account failed ({e})"))?;
    let session = context
        .open_session(Flag::NONE)
        .map_err(|e| format!("{service}: open_session failed ({e})"))?;
    // Closing the session and deleting the credentials, as signing out does.
    drop(session);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_password_is_the_first_line_of_stdin() {
        let password = read_password(&b"punar\n"[..]).unwrap();
        assert_eq!(password.as_str(), "punar");
        let password = read_password(&b"no newline"[..]).unwrap();
        assert_eq!(password.as_str(), "no newline");
        let password = read_password(&b"first\nsecond\n"[..]).unwrap();
        assert_eq!(password.as_str(), "first");
    }

    #[test]
    fn an_empty_long_or_undecodable_password_is_refused() {
        assert!(read_password(&b""[..]).is_err());
        assert!(read_password(&b"\n"[..]).is_err());
        assert!(read_password(&b"\xff\xfe\n"[..]).is_err());
        let long = vec![b'a'; MAX_PASSWORD_BYTES + 1];
        assert!(read_password(&long[..]).is_err());
        let longest = vec![b'a'; MAX_PASSWORD_BYTES];
        assert_eq!(
            read_password(&longest[..]).unwrap().len(),
            MAX_PASSWORD_BYTES
        );
    }
}
