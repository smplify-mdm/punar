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
