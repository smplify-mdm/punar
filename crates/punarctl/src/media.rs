//! `punarctl media` — play, pause and skip whatever is playing, over MPRIS
//! (SMP-1405 WP-02).
//!
//! The media keys run these verbs, so the keyboard and a terminal do the
//! same thing one way. Client-side, as the person, on the person's own
//! session bus: `busctl --user` with a closed argv, never a shell string.
//! A player's bus name reaches that argv only after it matched the MPRIS
//! name grammar, and a title or an artist reaches the terminal only through
//! the terminal-safe filter.
//!
//! **Which player.** The one playing now; else one that is paused (the
//! thing a person most likely means by "play"); else the first by name.
//! Nothing is remembered between calls, so nothing is written anywhere.
//!
//! Exit codes follow D-014, plus 6 when no media player is running: the
//! hardware-or-software-absent code `display brightness` also uses.

use std::process::{Command, ExitCode, Stdio};

use clap::Subcommand;
use serde_json::{Value, json};

use crate::fmt::{self, Row, Slot, Style};
use crate::session::safe;

const MPRIS_PREFIX: &str = "org.mpris.MediaPlayer2.";
const MPRIS_PATH: &str = "/org/mpris/MediaPlayer2";
const PLAYER_IFACE: &str = "org.mpris.MediaPlayer2.Player";
const ROOT_IFACE: &str = "org.mpris.MediaPlayer2";

#[derive(Subcommand)]
pub enum MediaCommand {
    /// What is playing: the player, its state, the title and artist.
    Status,
    /// Play or pause.
    PlayPause,
    /// Skip to the next track.
    Next,
    /// Go back to the previous track.
    Previous,
}

/// `busctl --user --json=short <args>`, from PATH as `wpctl` is.
fn busctl(args: &[&str]) -> Result<Value, String> {
    let output = Command::new("busctl")
        .arg("--user")
        .arg("--json=short")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("busctl could not start ({e})"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();
    if text.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(text).map_err(|_| format!("busctl answered something unreadable: {text}"))
}

/// An MPRIS bus name: the prefix, then a well-formed D-Bus name tail.
pub fn valid_player(name: &str) -> bool {
    name.len() <= 255
        && name.strip_prefix(MPRIS_PREFIX).is_some_and(|tail| {
            !tail.is_empty()
                && tail.split('.').all(|element| {
                    !element.is_empty()
                        && !element.starts_with(|c: char| c.is_ascii_digit())
                        && element
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                })
        })
}

fn players() -> Result<Vec<String>, String> {
    let names = busctl(&[
        "call",
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "ListNames",
    ])?;
    let mut out: Vec<String> = names
        .pointer("/data/0")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|name| valid_player(name))
        .map(str::to_string)
        .collect();
    out.sort();
    Ok(out)
}

fn property(player: &str, iface: &str, name: &str) -> Value {
    busctl(&["get-property", player, MPRIS_PATH, iface, name])
        .ok()
        .and_then(|v| v.get("data").cloned())
        .unwrap_or(Value::Null)
}

/// One player's state, read now.
fn describe(player: &str) -> Value {
    let status = property(player, PLAYER_IFACE, "PlaybackStatus");
    let metadata = property(player, PLAYER_IFACE, "Metadata");
    let field = |key: &str| metadata.pointer(&format!("/{key}/data")).cloned();
    let title = field("xesam:title")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let artist = field("xesam:artist")
        .map(|v| match v {
            Value::Array(names) => names
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            Value::String(name) => name,
            _ => String::new(),
        })
        .unwrap_or_default();
    let identity = property(player, ROOT_IFACE, "Identity")
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| player.trim_start_matches(MPRIS_PREFIX).to_string());
    json!({
        "player": player,
        "identity": identity,
        "status": status.as_str().unwrap_or("Unknown"),
        "title": title,
        "artist": artist,
    })
}

/// Playing beats paused beats stopped; ties go to the first by name.
fn choose(states: &[Value]) -> Option<&Value> {
    let rank = |state: &Value| match state.get("status").and_then(Value::as_str) {
        Some("Playing") => 0,
        Some("Paused") => 1,
        _ => 2,
    };
    states.iter().min_by_key(|state| rank(state))
}

fn refuse(message: &str, code: u8) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(code)
}

fn unreachable(why: &str) -> ExitCode {
    refuse(
        &format!(
            "The session bus is not reachable, so no media player could be asked.\nWhy: {}.\n\
             Next step: run this inside your desktop session.",
            if why.is_empty() {
                "busctl gave no reason"
            } else {
                why
            }
        ),
        crate::ipc::EXIT_UNREACHABLE,
    )
}

pub fn media(command: MediaCommand, style: &Style, json_output: bool) -> ExitCode {
    let names = match players() {
        Ok(names) => names,
        Err(why) => return unreachable(&why),
    };
    let states: Vec<Value> = names.iter().map(|name| describe(name)).collect();
    let Some(chosen) = choose(&states).cloned() else {
        if json_output && matches!(command, MediaCommand::Status) {
            println!("{}", json!({ "player": null, "players": [] }));
            return ExitCode::from(crate::ipc::EXIT_ABSENT);
        }
        return refuse(
            "No media player is running, so there is nothing to play or pause.\n\
             Next step: start playback in an application; it appears here when it does.",
            crate::ipc::EXIT_ABSENT,
        );
    };
    let player = chosen["player"].as_str().unwrap_or_default().to_string();
    let method = match command {
        MediaCommand::Status => None,
        MediaCommand::PlayPause => Some("PlayPause"),
        MediaCommand::Next => Some("Next"),
        MediaCommand::Previous => Some("Previous"),
    };
    let state = match method {
        None => chosen,
        Some(method) => {
            if let Err(why) = busctl(&["call", &player, MPRIS_PATH, PLAYER_IFACE, method]) {
                return refuse(
                    &format!(
                        "{} did not accept {method}, and nothing changed.\nWhy: {why}.",
                        safe(chosen["identity"].as_str().unwrap_or(&player))
                    ),
                    1,
                );
            }
            describe(&player)
        }
    };
    if json_output {
        println!(
            "{}",
            json!({
                "player": state,
                "players": names,
            })
        );
        return ExitCode::SUCCESS;
    }
    let mut out = fmt::masthead(style, "Media", "this session");
    let status = state["status"].as_str().unwrap_or("Unknown");
    let title = safe(state["title"].as_str().unwrap_or(""));
    let artist = safe(state["artist"].as_str().unwrap_or(""));
    let what = match (title.is_empty(), artist.is_empty()) {
        (true, _) => String::new(),
        (false, true) => title,
        (false, false) => format!("{title} · {artist}"),
    };
    out.push_str(&fmt::rows(
        style,
        &[Row::new(
            &safe(state["identity"].as_str().unwrap_or("")),
            status,
            if status == "Playing" {
                Slot::Ok
            } else {
                Slot::Neutral
            },
            &what,
        )],
    ));
    if names.len() > 1 {
        out.push_str(&fmt::note(
            style,
            &format!(
                "{} players are running; the keys reach the one playing",
                names.len()
            ),
        ));
    }
    print!("{out}");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_mpris_names_reach_busctl() {
        assert!(valid_player("org.mpris.MediaPlayer2.chromium.instance4242"));
        assert!(valid_player("org.mpris.MediaPlayer2.mpv"));
        for bad in [
            "org.mpris.MediaPlayer2.",
            "org.mpris.MediaPlayer2..x",
            "org.mpris.MediaPlayer2.1abc",
            "org.freedesktop.DBus",
            "org.mpris.MediaPlayer2.a b",
            "org.mpris.MediaPlayer2.a;reboot",
            ":1.42",
        ] {
            assert!(!valid_player(bad), "{bad}");
        }
    }

    #[test]
    fn a_playing_player_wins_over_a_paused_one() {
        let states = vec![
            json!({"player": "org.mpris.MediaPlayer2.a", "status": "Paused"}),
            json!({"player": "org.mpris.MediaPlayer2.b", "status": "Playing"}),
            json!({"player": "org.mpris.MediaPlayer2.c", "status": "Stopped"}),
        ];
        assert_eq!(
            choose(&states).unwrap()["player"],
            "org.mpris.MediaPlayer2.b"
        );
        let states = vec![
            json!({"player": "org.mpris.MediaPlayer2.a", "status": "Stopped"}),
            json!({"player": "org.mpris.MediaPlayer2.b", "status": "Paused"}),
        ];
        assert_eq!(
            choose(&states).unwrap()["player"],
            "org.mpris.MediaPlayer2.b"
        );
        assert!(choose(&[]).is_none());
    }
}
