//! `punarctl window look` — this person's window cosmetics (SMP-1405 WP-02,
//! Omarchy K83-K85): translucent windows, the gaps between windows, and a
//! square shape for a window alone on its workspace.
//!
//! **Kept as data, never as code.** The three answers live in
//! `~/.config/punar/look.json` as three booleans, written here atomically.
//! The compositor reads them back with a pattern each time it loads its
//! configuration (`hyprland.lua`, `look()`), so a toggle survives a reload
//! and the next session, as Omarchy's do. Omarchy keeps its toggles by
//! copying Lua files into `~/.local/state` that its configuration then RUNS,
//! the code-as-state pattern it had to patch in 4.0.1; nothing here is run.
//!
//! PUNAR+CTRL+T, G and A run this verb (`toggle`), so a key and a terminal
//! change the look one way. The live session takes the change through one
//! `hyprctl eval` of `hl.config`, built only from the three booleans.

use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::{Value, json};

use crate::fmt::{self, Row, Slot, Style};

/// Below the person's configuration directory.
pub const LOOK_FILE: &str = "punar/look.json";

/// The session's defaults, as `punar-look.lua` sets them: opaque windows,
/// 4 px between windows and 8 px at the edges, no forced shape.
const GAPS_IN: u32 = 4;
const GAPS_OUT: u32 = 8;
const ACTIVE_TRANSLUCENT: &str = "0.96";
const INACTIVE_TRANSLUCENT: &str = "0.88";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Look {
    pub transparency: bool,
    pub gaps: bool,
    pub square: bool,
}

impl Default for Look {
    fn default() -> Self {
        Look {
            transparency: false,
            gaps: true,
            square: false,
        }
    }
}

impl Look {
    /// A document's booleans; anything missing or malformed is the default.
    pub fn from_json(text: &str) -> Look {
        let doc: Value = serde_json::from_str(text).unwrap_or(Value::Null);
        let default = Look::default();
        let flag =
            |key: &str, fallback: bool| doc.get(key).and_then(Value::as_bool).unwrap_or(fallback);
        if doc.get("version").and_then(Value::as_u64) != Some(1) {
            return default;
        }
        Look {
            transparency: flag("transparency", default.transparency),
            gaps: flag("gaps", default.gaps),
            square: flag("square", default.square),
        }
    }

    pub fn to_json(self) -> Value {
        json!({
            "version": 1,
            "transparency": self.transparency,
            "gaps": self.gaps,
            "square": self.square,
        })
    }

    fn get(self, which: &str) -> bool {
        match which {
            "transparency" => self.transparency,
            "gaps" => self.gaps,
            _ => self.square,
        }
    }

    fn with(mut self, which: &str, on: bool) -> Look {
        match which {
            "transparency" => self.transparency = on,
            "gaps" => self.gaps = on,
            _ => self.square = on,
        }
        self
    }

    /// The one `hl.config` that makes the live session look like this. Built
    /// from three booleans and fixed numbers only.
    pub fn expression(self) -> String {
        let (active, inactive) = if self.transparency {
            (ACTIVE_TRANSLUCENT, INACTIVE_TRANSLUCENT)
        } else {
            ("1.0", "1.0")
        };
        let (gaps_in, gaps_out) = if self.gaps {
            (GAPS_IN, GAPS_OUT)
        } else {
            (0, 0)
        };
        let ratio = if self.square { "{ 1, 1 }" } else { "{ 0, 0 }" };
        format!(
            "hl.config({{ decoration = {{ active_opacity = {active}, inactive_opacity = {inactive} }}, \
             general = {{ gaps_in = {gaps_in}, gaps_out = {gaps_out} }}, \
             layout = {{ single_window_aspect_ratio = {ratio} }} }})"
        )
    }
}

fn look_path() -> Option<PathBuf> {
    crate::input::config_home().map(|dir| dir.join(LOOK_FILE))
}

/// This person's look, from the file; the defaults when there is none.
pub fn current() -> Look {
    look_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|text| Look::from_json(&text))
        .unwrap_or_default()
}

fn refuse(message: &str, code: u8) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(code)
}

fn apply_live(look: Look) -> Option<Result<(), String>> {
    crate::input::in_hyprland().then(|| crate::input::hyprctl(&["eval", &look.expression()]))
}

pub fn look(
    which: Option<String>,
    state: Option<String>,
    style: &Style,
    json_output: bool,
) -> ExitCode {
    let before = current();
    let mut applied = None;
    let after = match which.as_deref() {
        None => before,
        Some(which) => {
            let on = match state.as_deref() {
                Some("on") => true,
                Some("off") => false,
                _ => !before.get(which),
            };
            let after = before.with(which, on);
            let Some(path) = look_path() else {
                return refuse(
                    "The look was not changed.\nWhy: neither XDG_CONFIG_HOME nor HOME is set.",
                    1,
                );
            };
            if let Err(e) =
                crate::input::write_private(&path, &format!("{:#}\n", after.to_json()), 0o644)
            {
                return refuse(
                    &format!(
                        "The look was not changed.\nWhy: {} could not be written ({e}).",
                        path.display()
                    ),
                    1,
                );
            }
            applied = apply_live(after);
            after
        }
    };
    if let Some(Err(why)) = &applied {
        eprintln!(
            "The look is saved, but this session did not take it yet.\nWhy: {why}.\n\
             Next step: it applies at the next sign-in, or run the command again."
        );
    }
    if json_output {
        let mut doc = after.to_json();
        doc["applied"] = json!(applied.as_ref().map(Result::is_ok));
        println!("{doc}");
        return ExitCode::SUCCESS;
    }
    let row = |name: &str, on: bool, chord: &str| {
        Row::new(
            name,
            if on { "on" } else { "off" },
            if on { Slot::Ok } else { Slot::Neutral },
            chord,
        )
    };
    let mut out = fmt::masthead(style, "Look", "this person");
    out.push_str(&fmt::rows(
        style,
        &[
            row("Transparency", after.transparency, "Punar + Ctrl + T"),
            row("Gaps", after.gaps, "Punar + Ctrl + G"),
            row("Square lone window", after.square, "Punar + Ctrl + A"),
        ],
    ));
    out.push_str(&fmt::note(
        style,
        "punarctl window look transparency|gaps|square [on|off|toggle]",
    ));
    print!("{out}");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_or_malformed_file_is_the_defaults() {
        assert_eq!(Look::from_json(""), Look::default());
        assert_eq!(Look::from_json("not json"), Look::default());
        assert_eq!(
            Look::from_json(r#"{"transparency": true}"#),
            Look::default(),
            "no version"
        );
        assert_eq!(
            Look::from_json(r#"{"version": 1, "transparency": "yes", "gaps": false}"#),
            Look {
                transparency: false,
                gaps: false,
                square: false
            }
        );
    }

    #[test]
    fn the_file_round_trips() {
        let look = Look {
            transparency: true,
            gaps: false,
            square: true,
        };
        assert_eq!(Look::from_json(&look.to_json().to_string()), look);
    }

    #[test]
    fn the_expression_is_built_from_the_booleans_only() {
        assert_eq!(
            Look::default().expression(),
            "hl.config({ decoration = { active_opacity = 1.0, inactive_opacity = 1.0 }, \
             general = { gaps_in = 4, gaps_out = 8 }, \
             layout = { single_window_aspect_ratio = { 0, 0 } } })"
        );
        let all = Look {
            transparency: true,
            gaps: false,
            square: true,
        };
        let expression = all.expression();
        assert!(expression.contains("active_opacity = 0.96"), "{expression}");
        assert!(
            expression.contains("gaps_in = 0, gaps_out = 0"),
            "{expression}"
        );
        assert!(
            expression.contains("single_window_aspect_ratio = { 1, 1 }"),
            "{expression}"
        );
    }

    #[test]
    fn toggling_flips_only_the_one_named() {
        let look = Look::default();
        assert_eq!(
            look.with("gaps", false).get("transparency"),
            look.transparency
        );
        assert!(!look.with("gaps", false).gaps);
        assert!(look.with("square", true).square);
    }
}
