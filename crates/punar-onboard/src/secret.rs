//! Secret-bearing helpers. No function in this module logs, formats, or
//! returns a plaintext password.

use std::io::Write;
use std::process::{Command, Stdio};

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error)]
pub enum HashError {
    #[error("password hashing service could not start")]
    Spawn,
    #[error("password hashing service did not accept the request")]
    Write,
    #[error("password hashing service failed")]
    Failed,
    #[error("password hashing service returned an invalid result")]
    Invalid,
}

/// Hash with the substrate's libxcrypt yescrypt implementation. The secret
/// crosses the child boundary only through an anonymous stdin pipe; argv,
/// environment, temporary files, stderr, and logs never carry it.
pub fn yescrypt(password: &str) -> Result<Zeroizing<String>, HashError> {
    let mut child = Command::new("/usr/bin/mkpasswd")
        .args(["--method=yescrypt", "--stdin"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| HashError::Spawn)?;

    let mut input = Zeroizing::new(password.as_bytes().to_vec());
    input.push(b'\n');
    child
        .stdin
        .take()
        .ok_or(HashError::Write)?
        .write_all(&input)
        .map_err(|_| HashError::Write)?;
    input.zeroize();

    let output = child.wait_with_output().map_err(|_| HashError::Failed)?;
    if !output.status.success() || output.stdout.len() > 512 {
        return Err(HashError::Failed);
    }
    let mut hash = String::from_utf8(output.stdout).map_err(|_| HashError::Invalid)?;
    while hash.ends_with(['\n', '\r']) {
        hash.pop();
    }
    if !hash.starts_with("$y$") || hash.contains(char::is_whitespace) {
        hash.zeroize();
        return Err(HashError::Invalid);
    }
    Ok(Zeroizing::new(hash))
}

/// Verify a secret against a stored yescrypt hash by re-hashing it with that
/// hash as the crypt(3) setting: libxcrypt parses the algorithm, parameters and
/// salt out of the prefix, so a matching secret reproduces the stored string
/// exactly and a non-matching one cannot.
///
/// WHY NOT A SEPARATE VERIFIER. There is no verify binary on the substrate, and
/// re-deriving parameters here would mean this file deciding what "yescrypt"
/// means — which is exactly the decision `mkpasswd` already owns for the
/// hashing side. Using the same tool for both directions keeps one definition.
///
/// The comparison is constant-time in the length of the stored hash. A stored
/// hash is not itself a secret, but an early return here leaks how far a
/// candidate matched, which over enough attempts is a search hint; the recovery
/// path is attempt-limited precisely because that budget should not also be
/// spendable on timing.
pub fn yescrypt_verify(secret: &str, stored: &str) -> Result<bool, HashError> {
    if !stored.starts_with("$y$") || stored.contains(char::is_whitespace) {
        return Err(HashError::Invalid);
    }

    let mut child = Command::new("/usr/bin/mkpasswd")
        .args(["--method=yescrypt", "--stdin"])
        .arg(format!("--salt={stored}"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| HashError::Spawn)?;

    let mut input = Zeroizing::new(secret.as_bytes().to_vec());
    input.push(b'\n');
    child
        .stdin
        .take()
        .ok_or(HashError::Write)?
        .write_all(&input)
        .map_err(|_| HashError::Write)?;
    input.zeroize();

    let output = child.wait_with_output().map_err(|_| HashError::Failed)?;
    if !output.status.success() || output.stdout.len() > 512 {
        return Err(HashError::Failed);
    }
    let mut candidate = String::from_utf8(output.stdout).map_err(|_| HashError::Invalid)?;
    while candidate.ends_with(['\n', '\r']) {
        candidate.pop();
    }

    let matches = constant_time_eq(candidate.as_bytes(), stored.as_bytes());
    candidate.zeroize();
    Ok(matches)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_only_identical_slices() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abcdef", b"abcde"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn verify_rejects_a_stored_value_that_is_not_a_yescrypt_hash() {
        // A malformed record must not reach mkpasswd at all: passing an
        // attacker-influenced string as --salt is how a hash store becomes an
        // argument-injection surface.
        assert!(matches!(
            yescrypt_verify("secret", "not-a-hash"),
            Err(HashError::Invalid)
        ));
        assert!(matches!(
            yescrypt_verify("secret", "$y$ has whitespace"),
            Err(HashError::Invalid)
        ));
    }
}
