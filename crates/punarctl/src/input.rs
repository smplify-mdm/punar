//! `punarctl keyboard` and `punarctl keys` (SMP-1405 WP-02).
//!
//! **Keyboard layout.** The device's layout is punard's `system.keymap`
//! capability (`/etc/vconsole.conf`); the person in the active local session
//! may set it, and the change is audited. This session loads it from a data
//! file, `$XDG_RUNTIME_DIR/punar/session/input.lua`, which `render` writes
//! at session start and `set` rewrites before applying the same three values
//! to the live compositor. The file is under the person's own runtime
//! directory rather than `/run/punar`, which is root's and which no desktop
//! process may write. Its values pass [`keymap`]'s grammar and the installed
//! XKB list first; the compositor matches them with a pattern and never runs
//! the file.
//!
//! **The greeter's choice.** The layout a person picks at the login screen
//! travels into the session as `PUNAR_KEYMAP` (set only on a successful
//! sign-in), and `render --adopt` makes it the device's layout through the
//! same audited capability. Nobody who has not signed in can change the
//! device: an unauthenticated login screen only chooses what it types with.
//!
//! **Clipboard keys.** An optional grammar: PUNAR+C, V and X copy, paste and
//! cut, as on a Mac, and the two floating-window binds they displace move to
//! PUNAR+ALT+C and PUNAR+ALT+V. It is the person's own preference, in
//! `~/.config/punar/keyboard.json`, read by the compositor as data.
//!
//! **Keys.** `keys list` is the compositor's own bind table (`j/binds`), the
//! one source the shortcut help renders, so a terminal and PUNAR+/ can never
//! disagree about what a chord does.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use clap::Subcommand;
use punar_common::keymap::{self, Catalog, Layout};
use serde_json::{Value, json};

use crate::fmt::{self, Row, Slot, Style};
use crate::hypr;
use crate::ipc::{Client, Target};
use crate::session::safe;

/// Test seams for the two read-only inputs, like `PUNARD_SOCKET`. They
/// change what this client reads; punard validates against the image's own
/// list whatever this process was told.
const VCONSOLE_ENV: &str = "PUNAR_VCONSOLE_CONF";
const XKB_LIST_ENV: &str = "PUNAR_XKB_LIST";

/// The session file, below the person's runtime directory.
const SESSION_INPUT: &str = "punar/session/input.lua";

/// The person's keyboard preferences.
const PREFERENCES: &str = "punar/keyboard.json";

/// How long session start waits for the seat to name the person before the
/// greeter's choice is adopted: greetd hands the seat over while the
/// session's first process is already running.
const ADOPT_ATTEMPTS: u32 = 10;
const ADOPT_PAUSE: Duration = Duration::from_millis(300);

#[derive(Subcommand)]
pub enum KeyboardCommand {
    /// The keyboard layout: this device's, this session's, and every one
    /// installed. Without a subcommand, `status`.
    Layout {
        #[command(subcommand)]
        command: Option<LayoutCommand>,
    },
    /// Mac-style clipboard keys: PUNAR+C, V and X copy, paste and cut. The
    /// floating-window binds they replace move to PUNAR+ALT+C and V.
    ClipboardKeys {
        #[arg(value_parser = ["on", "off", "status"])]
        mode: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum LayoutCommand {
    /// The device's layout, what this session loaded, and the switch chord.
    Status,
    /// Every installed layout, or one layout's variants.
    List {
        /// A layout whose variants to list, like `de`.
        layout: Option<String>,
        /// Only rows whose name or description contains this text.
        #[arg(long)]
        filter: Option<String>,
    },
    /// Set the device's layout: one to four layouts, comma-separated, each
    /// with an optional `+variant`, like `de`, `de+nodeadkeys` or `us,ru`.
    /// The person at the machine may; the change is audited.
    Set { layouts: String },
    /// Write this session's input file (run by session start).
    #[command(hide = true)]
    Render {
        /// Where to write; the session's runtime file by default.
        #[arg(long)]
        output: Option<PathBuf>,
        /// The layout chosen at the login screen, made the device's.
        #[arg(long)]
        adopt: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum KeysCommand {
    /// Every key bind in this session, as the shortcut help shows them.
    List {
        /// Only binds whose description or chord contains this text.
        #[arg(long)]
        filter: Option<String>,
        /// Only the chords of features this person has not tried yet, as the
        /// shortcut help's hint shows them (kept on this machine only, in
        /// ~/.local/state/punar/shortcuts-tried.json).
        #[arg(long)]
        untried: bool,
    },
}

fn refuse(message: &str, code: u8) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(code)
}

fn env_path(name: &str, default: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from(default))
}

fn catalog() -> Result<Catalog, String> {
    let path = env_path(XKB_LIST_ENV, keymap::XKB_LIST);
    let catalog = Catalog::load(&path).map_err(|e| {
        format!(
            "the keyboard layout list {} could not be read ({e})",
            path.display()
        )
    })?;
    if catalog.layouts.is_empty() {
        return Err(format!("{} names no keyboard layouts", path.display()));
    }
    Ok(catalog)
}

/// The device's layout as `/etc/vconsole.conf` records it; the default when
/// the file names none or cannot be read as a layout.
pub fn device_layout() -> String {
    std::fs::read_to_string(env_path(VCONSOLE_ENV, keymap::VCONSOLE))
        .ok()
        .and_then(|text| keymap::from_vconsole(&text).ok().flatten())
        .unwrap_or_else(|| keymap::DEFAULT.to_string())
}

fn runtime_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

fn session_input_path() -> Option<PathBuf> {
    runtime_dir().map(|dir| dir.join(SESSION_INPUT))
}

fn config_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|home| home.join(".config"))
        })
}

/// Write a file the person owns, atomically, private to them.
fn write_private(path: &Path, text: &str, mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent directory"))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let tmp = parent.join(format!(
        ".{}.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("tmp"),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp);
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(text.as_bytes())?;
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// The Lua `hl.config` for three validated input values.
pub fn input_expression(input: &keymap::SessionInput) -> String {
    format!(
        "hl.config({{ input = {{ kb_layout = {}, kb_variant = {}, kb_options = {} }} }})",
        hypr::lua_string(&input.kb_layout),
        hypr::lua_string(&input.kb_variant),
        hypr::lua_string(&input.kb_options)
    )
}

/// `hyprctl eval <expr>`, the path punar-layout.sh proves in every gate.
fn hyprctl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("hyprctl")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("hyprctl could not start ({e})"))?;
    let answer = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if output.status.success() && (answer.is_empty() || answer == "ok") {
        Ok(())
    } else {
        let why = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if why.is_empty() { answer } else { why })
    }
}

fn in_hyprland() -> bool {
    std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some_and(|s| !s.is_empty())
}

/// Render `chosen` into the session file, and apply it live when asked.
fn render_session(
    chosen: &[Layout],
    output: &Path,
    live: bool,
) -> Result<(keymap::SessionInput, Option<String>), String> {
    let input = keymap::session_input(chosen);
    for value in [&input.kb_layout, &input.kb_variant, &input.kb_options] {
        if !keymap::rendered_value_ok(value) {
            return Err(format!("{value:?} is not a value the compositor accepts"));
        }
    }
    write_private(
        output,
        &keymap::render_input_file(&keymap::format(chosen), &input),
        0o600,
    )
    .map_err(|e| format!("{} could not be written ({e})", output.display()))?;
    let live_error = if live && in_hyprland() {
        hyprctl(&["eval", &input_expression(&input)]).err()
    } else {
        None
    };
    Ok((input, live_error))
}

/// Ask punard to make `value` the device's layout. The effective value
/// comes back: an organization's pin can outrank the person.
fn set_device(
    client: &Client,
    value: &str,
    timeout: Duration,
) -> Result<String, crate::ipc::CallError> {
    let result = client.call_with_timeout(
        "capabilities.set",
        Some(json!({ "capability": keymap::CAPABILITY_ID, "desired_state": value })),
        timeout,
    )?;
    Ok(result
        .get("effective_state")
        .and_then(Value::as_str)
        .unwrap_or(value)
        .to_string())
}

// ---------------------------------------------------------------------------
// keyboard layout
// ---------------------------------------------------------------------------

fn layouts_json(catalog: Option<&Catalog>, layouts: &[Layout]) -> Value {
    Value::Array(
        layouts
            .iter()
            .map(|l| {
                json!({
                    "layout": l.layout,
                    "variant": l.variant,
                    "description": catalog.map(|c| c.describe(l)).unwrap_or_else(|| l.to_string()),
                    "latin": l.is_latin(),
                })
            })
            .collect(),
    )
}

/// The main keyboard's active keymap and loaded layouts, from the live
/// compositor (`j/devices`).
fn live_keyboard() -> Option<Value> {
    let devices = hypr::json("devices").ok()?;
    let keyboards = devices.get("keyboards")?.as_array()?;
    let main = keyboards
        .iter()
        .find(|k| k.get("main").and_then(Value::as_bool) == Some(true))
        .or_else(|| keyboards.first())?;
    Some(json!({
        "name": main.get("name").cloned().unwrap_or(Value::Null),
        "layout": main.get("layout").cloned().unwrap_or(Value::Null),
        "variant": main.get("variant").cloned().unwrap_or(Value::Null),
        "options": main.get("options").cloned().unwrap_or(Value::Null),
        "active_keymap": main.get("active_keymap").cloned().unwrap_or(Value::Null),
    }))
}

fn status(style: &Style, json_output: bool) -> ExitCode {
    let catalog = catalog().ok();
    let device = device_layout();
    let chosen = keymap::parse(&device).unwrap_or_else(|_| vec![Layout::new(keymap::DEFAULT, "")]);
    let session = session_input_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| keymap::parse_input_file(&text));
    let live = live_keyboard();
    let switchable = session
        .as_ref()
        .map(|s| s.kb_layout.contains(','))
        .unwrap_or_else(|| keymap::session_groups(&chosen).len() > 1);
    if json_output {
        println!(
            "{}",
            json!({
                "device": device,
                "layouts": layouts_json(catalog.as_ref(), &chosen),
                "session": session.as_ref().map(|s| json!({
                    "kb_layout": s.kb_layout,
                    "kb_variant": s.kb_variant,
                    "kb_options": s.kb_options,
                })),
                "live": live,
                "switch_chord": switchable.then_some(keymap::SWITCH_CHORD),
            })
        );
        return ExitCode::SUCCESS;
    }
    let mut out = fmt::masthead(style, "Keyboard", "this device");
    let mut rows: Vec<Row> = chosen
        .iter()
        .enumerate()
        .map(|(index, layout)| {
            Row::new(
                if index == 0 { "Layout" } else { "" },
                &layout.to_string(),
                Slot::Neutral,
                &catalog
                    .as_ref()
                    .map(|c| c.describe(layout))
                    .unwrap_or_default(),
            )
        })
        .collect();
    if let Some(session) = &session {
        rows.push(Row::new(
            "Session",
            &session.kb_layout,
            Slot::Neutral,
            if session.kb_layout.contains(',') {
                "Latin letters first, so every key bind works"
            } else {
                "loaded at sign-in"
            },
        ));
    }
    if let Some(active) = live
        .as_ref()
        .and_then(|l| l.get("active_keymap"))
        .and_then(Value::as_str)
    {
        rows.push(Row::new("Typing", &safe(active), Slot::Ok, "now"));
    }
    if switchable {
        rows.push(Row::new(
            "Switch",
            "Alt + Alt",
            Slot::Neutral,
            keymap::SWITCH_CHORD,
        ));
    }
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::note(
        style,
        "punarctl keyboard layout list · punarctl keyboard layout set <layouts>",
    ));
    print!("{out}");
    ExitCode::SUCCESS
}

fn list(
    layout: Option<String>,
    filter: Option<String>,
    style: &Style,
    json_output: bool,
) -> ExitCode {
    let catalog = match catalog() {
        Ok(catalog) => catalog,
        Err(why) => return refuse(&format!("No layout could be listed.\nWhy: {why}."), 1),
    };
    let needle = filter.unwrap_or_default().to_lowercase();
    let keep = |name: &str, description: &str| {
        needle.is_empty()
            || name.to_lowercase().contains(&needle)
            || description.to_lowercase().contains(&needle)
    };
    let entries: Vec<(String, String)> = match &layout {
        Some(owner) => {
            if !catalog.layouts.contains_key(owner) {
                return refuse(
                    &keymap::KeymapError::UnknownLayout(owner.clone()).to_string(),
                    2,
                );
            }
            catalog
                .variants_of(owner)
                .into_iter()
                .map(|(variant, description)| (format!("{owner}+{variant}"), description))
                .filter(|(name, description)| keep(name, description))
                .collect()
        }
        None => catalog
            .layouts
            .iter()
            .filter(|(name, description)| keep(name, description))
            .map(|(name, description)| (name.clone(), description.clone()))
            .collect(),
    };
    if json_output {
        let rows: Vec<Value> = entries
            .iter()
            .map(|(name, description)| json!({ "name": name, "description": description }))
            .collect();
        println!("{}", json!({ "layouts": rows }));
        return ExitCode::SUCCESS;
    }
    let mut out = fmt::masthead(
        style,
        "Keyboard layouts",
        layout.as_deref().unwrap_or("installed"),
    );
    if entries.is_empty() {
        out.push_str(&fmt::note(style, "No layout matches"));
    } else {
        let rows: Vec<Row> = entries
            .iter()
            .map(|(name, description)| Row::new(name, "", Slot::Neutral, description))
            .collect();
        out.push_str(&fmt::rows(style, &rows));
    }
    print!("{out}");
    ExitCode::SUCCESS
}

fn set(layouts: &str, socket: Option<&Path>, style: &Style, json_output: bool) -> ExitCode {
    let catalog = match catalog() {
        Ok(catalog) => catalog,
        Err(why) => {
            return refuse(
                &format!("The keyboard layout was not changed.\nWhy: {why}."),
                1,
            );
        }
    };
    let chosen = match catalog.validate(layouts) {
        Ok(chosen) => chosen,
        Err(error) => {
            return refuse(
                &format!("The keyboard layout was not changed.\nWhy: {error}."),
                2,
            );
        }
    };
    let value = keymap::format(&chosen);
    let client = Client::for_target(Target::Punard, socket);
    let effective = match set_device(&client, &value, Duration::from_secs(15)) {
        Ok(effective) => effective,
        Err(error) => {
            eprintln!("{}", error.message());
            return ExitCode::from(error.exit_code());
        }
    };
    let effective_layouts = keymap::parse(&effective).unwrap_or(chosen);
    let (session, live_error) = match session_input_path() {
        Some(path) => match render_session(&effective_layouts, &path, true) {
            Ok((input, live_error)) => (Some(input), live_error),
            Err(why) => (None, Some(why)),
        },
        None => (None, None),
    };
    if let Some(why) = &live_error {
        eprintln!(
            "The device's layout is saved, but this session did not take it yet.\nWhy: {why}.\n\
             Next step: sign out and back in, or run `punarctl keyboard layout set {effective}` again."
        );
    }
    if json_output {
        println!(
            "{}",
            json!({
                "device": effective,
                "requested": value,
                "overridden": effective != value,
                "session": session.as_ref().map(|s| json!({
                    "kb_layout": s.kb_layout,
                    "kb_variant": s.kb_variant,
                    "kb_options": s.kb_options,
                })),
                "session_applied": session.is_some() && live_error.is_none() && in_hyprland(),
            })
        );
        return ExitCode::SUCCESS;
    }
    let what = if effective == value {
        format!("Keyboard · {effective}")
    } else {
        format!("Keyboard · {effective} · your organization's choice; {value} is recorded")
    };
    print!("{}", fmt::verdict(style, Slot::Ok, &what));
    if session.as_ref().is_some_and(|s| s.kb_layout.contains(',')) {
        print!(
            "{}",
            fmt::note(
                style,
                &format!("Switch layouts with {}", keymap::SWITCH_CHORD)
            )
        );
    }
    ExitCode::SUCCESS
}

/// Session start. Adoption failing never blocks the session: the greeter's
/// choice is then used for this session only, and the reason is logged.
fn render(
    output: Option<PathBuf>,
    adopt: Option<String>,
    socket: Option<&Path>,
    json_output: bool,
) -> ExitCode {
    let Some(output) = output.or_else(session_input_path) else {
        return refuse(
            "The session's keyboard file was not written.\nWhy: XDG_RUNTIME_DIR is not set.",
            1,
        );
    };
    let catalog = catalog().ok();
    let valid = |value: &str| -> Option<Vec<Layout>> {
        match &catalog {
            Some(catalog) => catalog.validate(value).ok(),
            None => keymap::parse(value).ok(),
        }
    };
    let device = device_layout();
    let mut chosen = valid(&device).unwrap_or_else(|| vec![Layout::new(keymap::DEFAULT, "")]);
    let mut adopted = false;
    if let Some(wanted) = adopt.as_deref().filter(|w| !w.is_empty()) {
        match valid(wanted) {
            None => eprintln!(
                "punar-session: the login screen's keyboard layout {wanted:?} is not installed; using {device}"
            ),
            Some(layouts) if keymap::format(&layouts) == device => {}
            Some(layouts) => {
                let value = keymap::format(&layouts);
                let client = Client::for_target(Target::Punard, socket);
                let mut last = String::new();
                for attempt in 0..ADOPT_ATTEMPTS {
                    match set_device(&client, &value, Duration::from_secs(3)) {
                        Ok(effective) => {
                            chosen = valid(&effective).unwrap_or_else(|| layouts.clone());
                            adopted = true;
                            break;
                        }
                        // The seat may not name the person yet: wait for it,
                        // briefly. Any other answer is final.
                        Err(error) if error.exit_code() == crate::ipc::EXIT_DENIED => {
                            last = error.message();
                            if attempt + 1 < ADOPT_ATTEMPTS {
                                std::thread::sleep(ADOPT_PAUSE);
                            }
                        }
                        Err(error) => {
                            last = error.message();
                            break;
                        }
                    }
                }
                if !adopted {
                    eprintln!(
                        "punar-session: this session uses {value} from the login screen; the device \
                         keeps {device}: {}",
                        last.lines().next().unwrap_or("punard did not answer")
                    );
                    chosen = layouts;
                }
            }
        }
    }
    match render_session(&chosen, &output, false) {
        Ok((input, _)) => {
            if json_output {
                println!(
                    "{}",
                    json!({
                        "file": output,
                        "chosen": keymap::format(&chosen),
                        "adopted": adopted,
                        "kb_layout": input.kb_layout,
                        "kb_variant": input.kb_variant,
                        "kb_options": input.kb_options,
                    })
                );
            }
            ExitCode::SUCCESS
        }
        Err(why) => refuse(
            &format!("The session's keyboard file was not written.\nWhy: {why}."),
            1,
        ),
    }
}

// ---------------------------------------------------------------------------
// clipboard keys
// ---------------------------------------------------------------------------

/// `standard` or `mac`, from the preferences file; `standard` when absent.
pub fn clipboard_mode() -> &'static str {
    let mode = config_home()
        .and_then(|dir| std::fs::read_to_string(dir.join(PREFERENCES)).ok())
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|doc| {
            doc.get("clipboardKeys")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    match mode.as_deref() {
        Some("mac") => "mac",
        _ => "standard",
    }
}

fn clipboard_keys(mode: Option<String>, style: &Style, json_output: bool) -> ExitCode {
    let wanted = match mode.as_deref() {
        Some("on") => Some("mac"),
        Some("off") => Some("standard"),
        _ => None,
    };
    let mut reloaded = None;
    if let Some(wanted) = wanted {
        let Some(path) = config_home().map(|dir| dir.join(PREFERENCES)) else {
            return refuse(
                "The clipboard keys were not changed.\nWhy: neither XDG_CONFIG_HOME nor HOME is set.",
                1,
            );
        };
        let document = json!({ "version": 1, "clipboardKeys": wanted });
        if let Err(e) = write_private(&path, &format!("{document:#}\n"), 0o644) {
            return refuse(
                &format!(
                    "The clipboard keys were not changed.\nWhy: {} could not be written ({e}).",
                    path.display()
                ),
                1,
            );
        }
        // Binds are registered when the compositor reads its configuration,
        // so a reload is what moves them; the layout presets come back on
        // Hyprland's own `config.reloaded` event.
        if in_hyprland() {
            reloaded = Some(hyprctl(&["reload"]));
        }
    }
    let current = clipboard_mode();
    if json_output {
        println!(
            "{}",
            json!({
                "clipboard_keys": current,
                "reloaded": reloaded.as_ref().map(Result::is_ok),
            })
        );
        return ExitCode::SUCCESS;
    }
    if let Some(Err(why)) = &reloaded {
        eprintln!(
            "The setting is saved, but this session still has the old keys.\nWhy: {why}.\n\
             Next step: sign out and back in."
        );
    }
    let mut out = fmt::masthead(style, "Clipboard keys", "this person");
    let rows = if current == "mac" {
        vec![
            Row::new(
                "Copy",
                "Punar + C",
                Slot::Ok,
                "Ctrl + Shift + C in a terminal",
            ),
            Row::new(
                "Paste",
                "Punar + V",
                Slot::Ok,
                "Ctrl + Shift + V in a terminal",
            ),
            Row::new("Cut", "Punar + X", Slot::Ok, ""),
            Row::new(
                "Float",
                "Punar + Alt + V",
                Slot::Neutral,
                "moved from Punar + V",
            ),
            Row::new(
                "Centre",
                "Punar + Alt + C",
                Slot::Neutral,
                "moved from Punar + C",
            ),
        ]
    } else {
        vec![
            Row::new(
                "Mode",
                "standard",
                Slot::Neutral,
                "Ctrl + C and Ctrl + V, as each app defines",
            ),
            Row::new("Float", "Punar + V", Slot::Neutral, ""),
            Row::new("Centre", "Punar + C", Slot::Neutral, ""),
        ]
    };
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::note(style, "punarctl keyboard clipboard-keys on|off"));
    print!("{out}");
    ExitCode::SUCCESS
}

pub fn keyboard(
    command: KeyboardCommand,
    socket: Option<&Path>,
    style: &Style,
    json_output: bool,
) -> ExitCode {
    match command {
        KeyboardCommand::Layout { command } => match command.unwrap_or(LayoutCommand::Status) {
            LayoutCommand::Status => status(style, json_output),
            LayoutCommand::List { layout, filter } => list(layout, filter, style, json_output),
            LayoutCommand::Set { layouts } => set(&layouts, socket, style, json_output),
            LayoutCommand::Render { output, adopt } => render(output, adopt, socket, json_output),
        },
        KeyboardCommand::ClipboardKeys { mode } => clipboard_keys(mode, style, json_output),
    }
}

// ---------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------

/// The chord as the shortcut help writes it: modifiers in one fixed order.
pub fn chord(bind: &Value) -> String {
    let mask = bind.get("modmask").and_then(Value::as_u64).unwrap_or(0);
    let mut parts: Vec<String> = Vec::new();
    for (bit, name) in [(64, "Punar"), (4, "Ctrl"), (1, "Shift"), (8, "Alt")] {
        if mask & bit != 0 {
            parts.push(name.to_string());
        }
    }
    let key = bind.get("key").and_then(Value::as_str).unwrap_or("");
    parts.push(if key.is_empty() {
        format!(
            "code {}",
            bind.get("keycode").and_then(Value::as_u64).unwrap_or(0)
        )
    } else {
        key.to_string()
    });
    parts.join(" + ")
}

/// The families the shell has not seen tried, from its own state file: the
/// file names every family it tracks, so this list cannot drift from the
/// shell's. No file: nothing is known, so nothing is suggested.
fn untried_families() -> Vec<String> {
    let path = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .map(|home| home.join(".local/state/punar/shortcuts-tried.json"));
    let Some(doc) = path
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(|doc| doc.get("version").and_then(Value::as_u64) == Some(1))
    else {
        return Vec::new();
    };
    let list = |key: &str| -> Vec<String> {
        doc.get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|family| !family.is_empty() && family.len() <= 64)
            .map(str::to_string)
            .collect()
    };
    let tried = list("tried");
    list("families")
        .into_iter()
        .filter(|family| !tried.contains(family))
        .collect()
}

pub fn keys(command: KeysCommand, style: &Style, json_output: bool) -> ExitCode {
    let KeysCommand::List { filter, untried } = command;
    let families = if untried {
        untried_families()
    } else {
        Vec::new()
    };
    let binds = match hypr::json("binds") {
        Ok(Value::Array(binds)) => binds,
        Ok(_) => return refuse("The compositor's bind table was not a list.", 1),
        Err(error) => return refuse(&error.message(), error.exit_code()),
    };
    let needle = filter.unwrap_or_default().to_lowercase();
    let kept: Vec<Value> = binds
        .into_iter()
        .filter(|bind| {
            needle.is_empty()
                || bind
                    .get("description")
                    .and_then(Value::as_str)
                    .is_some_and(|d| d.to_lowercase().contains(&needle))
                || chord(bind).to_lowercase().contains(&needle)
        })
        .filter(|bind| {
            !untried
                || bind
                    .get("description")
                    .and_then(Value::as_str)
                    .is_some_and(|d| families.iter().any(|f| d.starts_with(f.as_str())))
        })
        .collect();
    if json_output {
        println!("{}", Value::Array(kept));
        return ExitCode::SUCCESS;
    }
    let mut out = fmt::masthead(style, "Keys", "this session");
    let rows: Vec<Row> = kept
        .iter()
        .filter(|bind| {
            bind.get("description")
                .and_then(Value::as_str)
                .is_some_and(|d| !d.is_empty())
        })
        .map(|bind| {
            let submap = bind.get("submap").and_then(Value::as_str).unwrap_or("");
            Row::new(
                &safe(&chord(bind)),
                "",
                Slot::Neutral,
                &if submap.is_empty() {
                    safe(bind["description"].as_str().unwrap_or(""))
                } else {
                    format!(
                        "{} · in {} mode",
                        safe(bind["description"].as_str().unwrap_or("")),
                        safe(submap)
                    )
                },
            )
        })
        .collect();
    if rows.is_empty() {
        out.push_str(&fmt::note(style, "No key bind matches"));
    } else {
        out.push_str(&fmt::rows(style, &rows));
    }
    print!("{out}");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_live_expression_quotes_every_value() {
        let input = keymap::session_input(&keymap::parse("ru").unwrap());
        assert_eq!(
            input_expression(&input),
            "hl.config({ input = { kb_layout = 'us,ru', kb_variant = '', kb_options = 'grp:alts_toggle' } })"
        );
    }

    #[test]
    fn chords_render_in_one_modifier_order() {
        assert_eq!(
            chord(&json!({"modmask": 65, "key": "Q"})),
            "Punar + Shift + Q"
        );
        assert_eq!(chord(&json!({"modmask": 8, "key": "Tab"})), "Alt + Tab");
        assert_eq!(
            chord(&json!({"modmask": 64, "key": "", "keycode": 272})),
            "Punar + code 272"
        );
        assert_eq!(
            chord(&json!({"modmask": 0, "key": "XF86AudioPlay"})),
            "XF86AudioPlay"
        );
    }
}
