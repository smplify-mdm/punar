//! Hyprland's request socket, spoken directly: the bytes `hyprctl` sends and
//! the ones Quickshell's `Hyprland.dispatch` sends, with no helper binary in
//! between.
//!
//! The compositor is the person's own, reached as the person: the socket is
//! `$XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket.sock`, a
//! directory only this uid can open. Nothing here elevates anything, and a
//! dispatcher expression is built only from fixed text plus values quoted as
//! Lua string literals ([`lua_string`]), the rule HyprlandActions.qml keeps.
//!
//! One request per connection, as Hyprland expects: write the request, read
//! the reply to end of stream. A reply is capped so a confused socket cannot
//! hand this process an unbounded answer.

use std::env;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;

/// Hyprland answers in milliseconds; this only bounds a wedged compositor.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Larger than any real `j/clients` answer.
const MAX_REPLY: u64 = 4 * 1024 * 1024;

/// Why a request did not get an answer, sorted by what the person can do.
#[derive(Debug)]
pub enum HyprError {
    /// No compositor to talk to: not a Hyprland session, or its socket did
    /// not answer. Exit 5, the "not reachable" code every verb shares.
    Unreachable(String),
    /// Hyprland answered and refused. Exit 1.
    Refused(String),
}

impl HyprError {
    pub fn message(&self) -> String {
        match self {
            HyprError::Unreachable(why) => format!(
                "The compositor is not reachable.\nWhy: {why}.\n\
                 Next step: run this inside your desktop session, where Hyprland is running."
            ),
            HyprError::Refused(answer) => format!(
                "The compositor refused the request, and nothing was changed.\nWhy: {answer}."
            ),
        }
    }

    pub fn exit_code(&self) -> u8 {
        match self {
            HyprError::Unreachable(_) => crate::ipc::EXIT_UNREACHABLE,
            HyprError::Refused(_) => 1,
        }
    }
}

/// The request socket of the session this process runs in.
pub fn socket_path() -> Result<PathBuf, HyprError> {
    let signature = env::var("HYPRLAND_INSTANCE_SIGNATURE").map_err(|_| {
        HyprError::Unreachable(
            "HYPRLAND_INSTANCE_SIGNATURE is not set, so this is not a Hyprland session".into(),
        )
    })?;
    if signature.is_empty() || signature.contains('/') || signature.starts_with('.') {
        return Err(HyprError::Unreachable(
            "HYPRLAND_INSTANCE_SIGNATURE is not a signature".into(),
        ));
    }
    let runtime = env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| HyprError::Unreachable("XDG_RUNTIME_DIR is not set".into()))?;
    Ok(runtime.join("hypr").join(signature).join(".socket.sock"))
}

/// One request, one reply.
pub fn request(command: &str) -> Result<String, HyprError> {
    let path = socket_path()?;
    let mut stream = UnixStream::connect(&path).map_err(|error| {
        HyprError::Unreachable(format!("{} did not answer ({error})", path.display()))
    })?;
    let _ = stream.set_read_timeout(Some(TIMEOUT));
    let _ = stream.set_write_timeout(Some(TIMEOUT));
    stream.write_all(command.as_bytes()).map_err(|error| {
        HyprError::Unreachable(format!("the request could not be sent ({error})"))
    })?;
    let mut reply = String::new();
    stream
        .take(MAX_REPLY)
        .read_to_string(&mut reply)
        .map_err(|error| {
            HyprError::Unreachable(format!("the reply could not be read ({error})"))
        })?;
    Ok(reply)
}

/// A JSON read: `j/<command>`.
pub fn json(command: &str) -> Result<Value, HyprError> {
    let reply = request(&format!("j/{command}"))?;
    serde_json::from_str(&reply).map_err(|_| {
        HyprError::Refused(format!(
            "`{command}` did not answer with JSON: {}",
            reply.lines().next().unwrap_or("").trim()
        ))
    })
}

/// A dispatcher. Hyprland answers `ok`, or says why not.
pub fn dispatch(expression: &str) -> Result<(), HyprError> {
    let reply = request(&format!("dispatch {expression}"))?;
    match reply.trim() {
        "ok" => Ok(()),
        "" => Err(HyprError::Refused("the dispatcher gave no answer".into())),
        other => Err(HyprError::Refused(
            other.lines().next().unwrap_or(other).to_string(),
        )),
    }
}

/// HyprlandActions.qml's `luaString`: a single-quoted Lua literal, so a value
/// can never end the string or start an expression.
pub fn lua_string(value: &str) -> String {
    let mut out = String::from("'");
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A value is data: it cannot close the literal or smuggle a newline.
    #[test]
    fn lua_strings_cannot_be_escaped() {
        assert_eq!(lua_string("atlas"), "'atlas'");
        assert_eq!(lua_string("a'b"), r"'a\'b'");
        assert_eq!(lua_string("a\\b"), r"'a\\b'");
        assert_eq!(lua_string("a\nb"), r"'a\nb'");
    }
}
