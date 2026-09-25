//! The session verbs: workspaces, layout presets, windows, the session
//! itself, displays and audio.
//!
//! Client-side, as the person's own uid, over the person's own compositor,
//! logind and PipeWire. None of it is a punard method, because none of it is
//! a system capability: it is the session's own state. System Control, the
//! command center, the overview and the window and session menus run these
//! same verbs, so the terminal and the GUI do each thing one way.
//!
//! Exit codes follow D-014: 0 done, 1 refused or failed, 2 usage, 3 denied
//! (polkit said no), 5 not reachable (no compositor, no PipeWire).

use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use clap::Subcommand;
use serde_json::{Value, json};

use crate::desktop;
use crate::fmt::{self, Row, Slot, Style};
use crate::hypr::{self, HyprError};

/// The layout presets' one implementation: the compositor binds, session
/// start and CI run it too (docs/development/milestone-2.md section 4).
const LAYOUT_SCRIPT: &str = "/usr/lib/punar/punar-layout.sh";
/// What `layout <preset>` accepts: the five presets and the script's verbs.
/// `default` is for `--workspace` only: it gives a workspace back to the
/// session's preset.
pub const LAYOUT_ARGS: [&str; 10] = [
    "balanced", "columns", "rows", "focus", "stack", "next", "prev", "restore", "status", "default",
];
const PRESETS: [&str; 5] = ["balanced", "columns", "rows", "focus", "stack"];

#[derive(Subcommand)]
pub enum WorkspaceCommand {
    /// Live workspaces, and the named projects stored for this session.
    List,
    /// Switch to a workspace: its number, or a project's name.
    Focus { target: String },
    /// Name a workspace, or clear its name by giving no NAME.
    Rename { id: i64, name: Option<String> },
    /// Open a named project workspace: switch to it, creating it on the
    /// first free workspace when it does not exist yet.
    New { name: String },
}

#[derive(Subcommand)]
pub enum WindowCommand {
    /// Every open window.
    List,
    /// The focused window.
    Active,
    /// Raise a window, by its application class or its exact address.
    Focus {
        #[arg(long, conflicts_with = "address", required_unless_present = "address")]
        class: Option<String>,
        #[arg(long)]
        address: Option<String>,
    },
    /// Ask a window to close, as its close button would. Without --address,
    /// the focused window.
    Close {
        #[arg(long)]
        address: Option<String>,
    },
    /// Kill the process that owns one window (SIGKILL). It needs the exact
    /// address, so it can never reach a window nobody named.
    Kill {
        #[arg(long)]
        address: String,
    },
    /// Pop a window out: float it at 60% of its display, centre it and pin
    /// it over every workspace; or put a popped-out window back in the
    /// layout. Without --address, the focused window.
    Pop {
        #[arg(long)]
        address: Option<String>,
    },
    /// This person's window look: transparency, the gaps between windows,
    /// and a square shape for a window alone on its workspace. Kept across
    /// sessions. Without arguments, the current look; with one, `toggle`.
    Look {
        #[arg(value_parser = ["transparency", "gaps", "square"])]
        which: Option<String>,
        #[arg(value_parser = ["on", "off", "toggle"], requires = "which")]
        state: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum SessionCommand {
    /// Lock the screen now, through `loginctl lock-session`, the one lock
    /// path idle and suspend also take.
    Lock,
    /// End this desktop session.
    End,
    /// Restart the device. logind asks polkit whether this session may.
    Restart,
    /// Shut the device down. logind asks polkit whether this session may.
    Shutdown,
}

#[derive(Subcommand)]
pub enum NotificationsCommand {
    /// Every notification, newest first, with the actions it offers.
    List,
    /// Dismiss one notification, by the id `list` shows.
    Dismiss { id: String },
    /// Dismiss every notification.
    Clear,
    /// Invoke one of a notification's own actions, by the key `list` shows.
    Action { id: String, key: String },
    /// Do not disturb: on, off, or status.
    Dnd {
        #[arg(value_parser = ["on", "off", "status"])]
        mode: String,
    },
}

#[derive(Subcommand)]
pub enum DisplayCommand {
    /// Every connected display: mode, scale and position.
    List,
    /// The backlight: `get`, `set 40%`, `40%`, `+5%` or `-5%`. Through this
    /// session's own logind object; a machine with no backlight exits 6.
    Brightness {
        #[arg(allow_hyphen_values = true, num_args = 0..=2)]
        change: Vec<String>,
        /// The keyboard backlight instead of the display's.
        #[arg(long)]
        keyboard: bool,
    },
}

#[derive(Subcommand)]
pub enum AudioCommand {
    /// The default output and input: volume and mute.
    Status,
    /// Change the output volume: `+5%`, `-5%`, or `40%`. Capped at 100%,
    /// as the volume keys are.
    Volume {
        #[arg(allow_hyphen_values = true)]
        change: String,
    },
    /// Mute the output, or the microphone with --input: on, off, or toggle
    /// (the default).
    Mute {
        #[arg(value_parser = ["on", "off", "toggle"])]
        state: Option<String>,
        /// The default input (the microphone) instead of the output.
        #[arg(long)]
        input: bool,
    },
}

fn refuse(message: &str, code: u8) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(code)
}

fn hypr_fail(error: HyprError) -> ExitCode {
    refuse(&error.message(), error.exit_code())
}

fn print_json(value: &Value) -> ExitCode {
    println!("{value}");
    ExitCode::SUCCESS
}

/// Window titles, classes and names come from applications: print them
/// through the terminal-safe filter.
pub fn safe(value: &str) -> String {
    punar_common::ipc::term_safe_name(value)
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

// ---------------------------------------------------------------------------
// Workspaces
// ---------------------------------------------------------------------------

/// The shell's workspace store, read where the shell (its only writer)
/// writes it (WorkspaceState.qml).
fn workspaces_file() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .map(|home| home.join(".local/state/punar/workspaces.json"))
}

/// A live workspace carries a real name when it is not just its number
/// (WorkspaceState.qml `isNamed`).
fn named(workspace: &Value) -> Option<(i64, String)> {
    let id = workspace.get("id").and_then(Value::as_i64)?;
    let name = text(workspace, "name");
    (id >= 1 && !name.is_empty() && name != id.to_string()).then(|| (id, name.to_string()))
}

/// Project names are lower-cased identifiers, and a bare number is an
/// address, never a name (CommandCenter/Actions.qml).
fn project_name(raw: &str) -> Option<String> {
    let name = raw
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    punar_workspace::is_valid_workspace_name(&name).then_some(name)
}

/// A workspace number: a positive integer without leading zeros, so "007"
/// stays available as a project name.
fn workspace_address(raw: &str) -> Option<i64> {
    let bytes = raw.as_bytes();
    let well_formed = !bytes.is_empty()
        && bytes.len() <= 9
        && bytes[0] != b'0'
        && bytes.iter().all(u8::is_ascii_digit);
    well_formed.then(|| raw.parse().ok()).flatten()
}

/// Every project this device knows: live named workspaces, then stored names
/// not open this session. Live names win.
fn known_projects(live: &[Value]) -> Vec<(i64, String, bool)> {
    let mut out: Vec<(i64, String, bool)> = Vec::new();
    for workspace in live {
        if let Some((id, name)) = named(workspace) {
            let name = name.to_lowercase();
            if !out.iter().any(|(_, known, _)| *known == name) {
                out.push((id, name, true));
            }
        }
    }
    if let Some(stored) =
        workspaces_file().and_then(|path| punar_workspace::WorkspacesFile::load(&path).ok())
    {
        for entry in stored.workspaces {
            let name = entry.name.to_lowercase();
            let live_id = live
                .iter()
                .any(|w| w.get("id").and_then(Value::as_i64) == Some(entry.id));
            if !live_id && !out.iter().any(|(_, known, _)| *known == name) {
                out.push((entry.id, name, false));
            }
        }
    }
    out.sort_by_key(|(id, _, _)| *id);
    out
}

/// The lowest id not taken by a live workspace or a stored name, inside 1-9
/// while it can be, since those are the ids PUNAR+1..9 reach.
fn free_workspace_id(live: &[Value], known: &[(i64, String, bool)]) -> i64 {
    (1..=99)
        .find(|n| {
            !live
                .iter()
                .any(|w| w.get("id").and_then(Value::as_i64) == Some(*n))
                && !known.iter().any(|(id, _, _)| id == n)
        })
        .unwrap_or(1)
}

fn focus_workspace(id: i64) -> Result<(), HyprError> {
    hypr::dispatch(&format!(
        "hl.dsp.focus({{ workspace = {} }})",
        hypr::lua_string(&id.to_string())
    ))
}

fn rename_workspace(id: i64, name: &str) -> Result<(), HyprError> {
    let mut expression = format!(
        "hl.dsp.workspace.rename({{ workspace = {}",
        hypr::lua_string(&id.to_string())
    );
    if !name.is_empty() {
        expression.push_str(&format!(", name = {}", hypr::lua_string(name)));
    }
    expression.push_str(" })");
    hypr::dispatch(&expression)
}

pub fn workspace(command: WorkspaceCommand, style: &Style, json_output: bool) -> ExitCode {
    let live = match hypr::json("workspaces") {
        Ok(Value::Array(rows)) => rows,
        Ok(_) => {
            return hypr_fail(HyprError::Refused(
                "the workspace list was not a list".into(),
            ));
        }
        Err(error) => return hypr_fail(error),
    };
    match command {
        WorkspaceCommand::List => {
            let active = hypr::json("activeworkspace")
                .ok()
                .and_then(|w| w.get("id").and_then(Value::as_i64));
            let stored: Vec<Value> = known_projects(&live)
                .into_iter()
                .filter(|(_, _, is_live)| !is_live)
                .map(|(id, name, _)| json!({ "id": id, "name": name }))
                .collect();
            if json_output {
                return print_json(
                    &json!({ "workspaces": live, "active": active, "stored": stored }),
                );
            }
            let mut out = fmt::masthead(style, "Workspaces", "this session");
            let mut rows: Vec<Row> = live
                .iter()
                .filter(|w| {
                    w.get("id")
                        .and_then(Value::as_i64)
                        .is_some_and(|id| id >= 1)
                })
                .map(|w| {
                    let id = w.get("id").and_then(Value::as_i64).unwrap_or(0);
                    let windows = w.get("windows").and_then(Value::as_u64).unwrap_or(0);
                    let mut detail = format!(
                        "{windows} window{} · {}",
                        if windows == 1 { "" } else { "s" },
                        safe(text(w, "monitor"))
                    );
                    if active == Some(id) {
                        detail.push_str(" · focused");
                    }
                    let name = named(w)
                        .map(|(_, name)| name)
                        .unwrap_or_else(|| "unnamed".into());
                    Row::new(
                        &id.to_string(),
                        &safe(&name),
                        if active == Some(id) {
                            Slot::Ok
                        } else {
                            Slot::Neutral
                        },
                        &detail,
                    )
                })
                .collect();
            rows.extend(stored.iter().map(|w| {
                Row::new(
                    &w["id"].to_string(),
                    &safe(text(w, "name")),
                    Slot::Neutral,
                    "stored · not open this session",
                )
            }));
            out.push_str(&fmt::rows(style, &rows));
            out.push_str(&fmt::note(
                style,
                "punarctl workspace focus <id|name> · punarctl workspace new <name>",
            ));
            print!("{out}");
            ExitCode::SUCCESS
        }
        WorkspaceCommand::Focus { target } => {
            if let Some(id) = workspace_address(&target) {
                return match focus_workspace(id) {
                    Ok(()) => report(style, json_output, id, None, false),
                    Err(error) => hypr_fail(error),
                };
            }
            let Some(name) = project_name(&target) else {
                return refuse(&bad_name(&target), 2);
            };
            let known = known_projects(&live);
            match known.iter().find(|(_, known, _)| *known == name) {
                Some((id, _, is_live)) => {
                    open_project(style, json_output, *id, &name, *is_live, false)
                }
                None => refuse(
                    &format!(
                        "No workspace is named {name}, so nothing was switched.\n\
                         Next step: `punarctl workspace new {name}` opens it."
                    ),
                    1,
                ),
            }
        }
        WorkspaceCommand::New { name: raw } => {
            let Some(name) = project_name(&raw) else {
                return refuse(&bad_name(&raw), 2);
            };
            let known = known_projects(&live);
            match known.iter().find(|(_, known, _)| *known == name) {
                Some((id, _, is_live)) => {
                    open_project(style, json_output, *id, &name, *is_live, false)
                }
                None => {
                    let id = free_workspace_id(&live, &known);
                    open_project(style, json_output, id, &name, false, true)
                }
            }
        }
        WorkspaceCommand::Rename { id, name } => {
            if id < 1 {
                return refuse(
                    "A workspace number is 1 or more; special workspaces are not renamed.",
                    2,
                );
            }
            let name = name.unwrap_or_default();
            if !name.is_empty() && !punar_workspace::is_valid_workspace_name(&name) {
                return refuse(&bad_name(&name), 2);
            }
            match rename_workspace(id, &name) {
                Ok(()) => report(style, json_output, id, Some(&name), false),
                Err(error) => hypr_fail(error),
            }
        }
    }
}

fn bad_name(raw: &str) -> String {
    format!(
        "{raw:?} is not a workspace name, so nothing was changed.\n\
         Why: a name is 1 to 32 letters, digits, spaces, `_` or `-`, starts with a \
         letter or digit, and does not start with `special`.\n\
         Next step: choose a name like `atlas`."
    )
}

/// Switch to a project, naming its workspace when it is not open under that
/// name yet (the command center's `openProject`).
fn open_project(
    style: &Style,
    json_output: bool,
    id: i64,
    name: &str,
    live: bool,
    created: bool,
) -> ExitCode {
    if let Err(error) = focus_workspace(id) {
        return hypr_fail(error);
    }
    if !live {
        if let Err(error) = rename_workspace(id, name) {
            return hypr_fail(error);
        }
    }
    report(style, json_output, id, Some(name), created)
}

fn report(
    style: &Style,
    json_output: bool,
    id: i64,
    name: Option<&str>,
    created: bool,
) -> ExitCode {
    if json_output {
        return print_json(&json!({ "id": id, "name": name, "created": created }));
    }
    let what = match name {
        Some("") => format!("Workspace {id} · name cleared"),
        Some(name) if created => format!("Workspace {id} · {name} · created"),
        Some(name) => format!("Workspace {id} · {name}"),
        None => format!("Workspace {id}"),
    };
    print!("{}", fmt::verdict(style, Slot::Ok, &what));
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Layout presets
// ---------------------------------------------------------------------------

fn layout_cache() -> Option<PathBuf> {
    std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|dir| dir.join("punar/layout-preset"))
}

/// The preset the script last applied, as it records it.
fn current_preset() -> (String, &'static str) {
    let cached = layout_cache()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|text| text.trim().to_string())
        .filter(|preset| PRESETS.contains(&preset.as_str()));
    match cached {
        Some(preset) => (preset, "applied this session"),
        None => (
            "balanced".to_string(),
            "default · no preset applied this session",
        ),
    }
}

/// The per-workspace presets punar-layout.sh keeps, validated as the script
/// validates them: a workspace number and one of the five presets.
fn workspace_presets() -> Vec<(i64, String)> {
    let path = std::env::var("XDG_STATE_HOME")
        .ok()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(PathBuf::from)
                .filter(|home| home.is_absolute())
                .map(|home| home.join(".local/state"))
        })
        .map(|dir| dir.join("punar/workspace-layouts.json"));
    let Some(document) = path
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
    else {
        return Vec::new();
    };
    let mut out: Vec<(i64, String)> = document
        .get("workspaces")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(id, preset)| {
            let id = workspace_address(id).filter(|id| *id <= 9999)?;
            let preset = preset.as_str().filter(|p| PRESETS.contains(p))?;
            Some((id, preset.to_string()))
        })
        .collect();
    out.sort();
    out
}

/// `active`, or a workspace number, as the script takes it.
fn workspace_target(raw: &str) -> Option<String> {
    if raw == "active" {
        return Some(raw.to_string());
    }
    workspace_address(raw)
        .filter(|id| *id <= 9999)
        .map(|id| id.to_string())
}

pub fn layout(preset: &str, workspace: Option<&str>, style: &Style, json_output: bool) -> ExitCode {
    let target = match workspace {
        None if preset == "default" => {
            return refuse(
                "`default` gives one workspace back to the session's preset, so it needs \
                 --workspace <number|active>.",
                2,
            );
        }
        None => None,
        Some(raw) => match workspace_target(raw) {
            Some(target) => Some(target),
            None => {
                return refuse(
                    &format!(
                        "{raw:?} is not a workspace, so no layout was changed.\n\
                         Next step: give a workspace number, or `active`."
                    ),
                    2,
                );
            }
        },
    };
    if target.is_some() && preset == "restore" {
        return refuse("`restore` covers every workspace; drop --workspace.", 2);
    }
    if preset != "status" {
        // Refuse before running anything when there is no compositor.
        if let Err(error) = hypr::request("version") {
            return hypr_fail(error);
        }
        let mut command = Command::new(LAYOUT_SCRIPT);
        if let Some(target) = &target {
            command.args(["--workspace", target]);
        }
        let result = command
            .arg(preset)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output();
        match result {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                return refuse(
                    &format!(
                        "The {preset} layout was not applied.\nWhy: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    ),
                    1,
                );
            }
            Err(error) => {
                return refuse(
                    &format!(
                        "The {preset} layout was not applied.\nWhy: {LAYOUT_SCRIPT} could not start ({error})."
                    ),
                    1,
                );
            }
        }
    }
    let (current, source) = current_preset();
    let workspaces = workspace_presets();
    let active = hypr::json("activeworkspace")
        .ok()
        .and_then(|w| w.get("id").and_then(Value::as_i64));
    let active_preset = active.and_then(|id| {
        workspaces
            .iter()
            .find(|(ws, _)| *ws == id)
            .map(|(_, preset)| preset.clone())
    });
    if json_output {
        let map: serde_json::Map<String, Value> = workspaces
            .iter()
            .map(|(id, preset)| (id.to_string(), json!(preset)))
            .collect();
        return print_json(&json!({
            "preset": current,
            "source": source,
            "workspaces": map,
            "active": active.map(|id| json!({
                "id": id,
                "preset": active_preset.clone().unwrap_or_else(|| current.clone()),
                "own": active_preset.is_some(),
            })),
        }));
    }
    let mut out = fmt::masthead(style, "Layout", "this session");
    let mut rows = vec![Row::new("Preset", &current, Slot::Ok, source)];
    for (id, preset) in &workspaces {
        rows.push(Row::new(
            &format!("Workspace {id}"),
            preset,
            Slot::Neutral,
            if active == Some(*id) {
                "its own preset · focused"
            } else {
                "its own preset"
            },
        ));
    }
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::note(
        style,
        "balanced · columns · rows · focus · stack · next · prev · --workspace <n|active>",
    ));
    print!("{out}");
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

fn valid_address(address: &str) -> bool {
    address.len() <= 18
        && address
            .strip_prefix("0x")
            .is_some_and(|hex| !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()))
}

fn bad_address(address: &str) -> ExitCode {
    refuse(
        &format!(
            "{address:?} is not a window address, so nothing was changed.\n\
             Next step: `punarctl window list` prints each window's address (0x…)."
        ),
        2,
    )
}

fn window_rows(windows: &[Value]) -> Vec<Row> {
    windows
        .iter()
        .map(|w| {
            let workspace = w
                .pointer("/workspace/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            Row::new(
                text(w, "address"),
                &safe(text(w, "class")),
                Slot::Neutral,
                &format!("{} · workspace {}", safe(text(w, "title")), safe(workspace)),
            )
        })
        .collect()
}

pub fn window(command: WindowCommand, style: &Style, json_output: bool) -> ExitCode {
    match command {
        WindowCommand::List => match hypr::json("clients") {
            Ok(Value::Array(windows)) => {
                if json_output {
                    return print_json(&json!({ "windows": windows }));
                }
                let mut out = fmt::masthead(style, "Windows", "this session");
                if windows.is_empty() {
                    out.push_str(&fmt::note(style, "No window is open"));
                } else {
                    out.push_str(&fmt::rows(style, &window_rows(&windows)));
                }
                print!("{out}");
                ExitCode::SUCCESS
            }
            Ok(_) => hypr_fail(HyprError::Refused("the window list was not a list".into())),
            Err(error) => hypr_fail(error),
        },
        WindowCommand::Active => match hypr::json("activewindow") {
            Ok(active) => {
                if json_output {
                    return print_json(&active);
                }
                let mut out = fmt::masthead(style, "Window", "focused");
                if valid_address(text(&active, "address")) {
                    out.push_str(&fmt::rows(
                        style,
                        &window_rows(std::slice::from_ref(&active)),
                    ));
                } else {
                    out.push_str(&fmt::note(style, "No application window is focused"));
                }
                print!("{out}");
                ExitCode::SUCCESS
            }
            Err(error) => hypr_fail(error),
        },
        WindowCommand::Focus { class, address } => {
            let expression = match (class, address) {
                (_, Some(address)) if !valid_address(&address) => return bad_address(&address),
                (_, Some(address)) => format!(
                    "hl.dsp.focus({{ window = {} }})",
                    hypr::lua_string(&format!("address:{address}"))
                ),
                (Some(class), None) if !class.trim().is_empty() && class.len() <= 128 => {
                    desktop::focus_expression(class.trim())
                }
                _ => return refuse("Name the window with --class or --address.", 2),
            };
            window_result(hypr::dispatch(&expression), style, json_output, "focused")
        }
        WindowCommand::Close { address } => {
            let address = match address {
                Some(address) if !valid_address(&address) => return bad_address(&address),
                Some(address) => address,
                None => match hypr::json("activewindow") {
                    Ok(active) if valid_address(text(&active, "address")) => {
                        text(&active, "address").to_string()
                    }
                    Ok(_) => {
                        return refuse(
                            "No application window is focused, so nothing was closed.",
                            1,
                        );
                    }
                    Err(error) => return hypr_fail(error),
                },
            };
            // The compositor's normal close request, not a signal.
            let expression = format!(
                "hl.dsp.window.close({{ window = {} }})",
                hypr::lua_string(&format!("address:{address}"))
            );
            window_result(
                hypr::dispatch(&expression),
                style,
                json_output,
                "close requested",
            )
        }
        WindowCommand::Kill { address } => {
            if !valid_address(&address) {
                return bad_address(&address);
            }
            let expression = format!(
                "hl.dsp.window.kill({{ window = {} }})",
                hypr::lua_string(&format!("address:{address}"))
            );
            window_result(hypr::dispatch(&expression), style, json_output, "killed")
        }
        WindowCommand::Pop { address } => pop_window(address, style, json_output),
        WindowCommand::Look { which, state } => crate::look::look(which, state, style, json_output),
    }
}

/// The dispatchers that pop a window out or put it back, in order. Pinning
/// needs a floating window and tiling needs an unpinned one, so the order
/// depends on which way the window is going.
pub fn pop_expressions(
    address: &str,
    floating: bool,
    pinned: bool,
    display: Option<(f64, f64)>,
) -> (Vec<String>, &'static str) {
    let window = hypr::lua_string(&format!("address:{address}"));
    if floating && pinned {
        return (
            vec![
                format!("hl.dsp.window.pin({{ window = {window}, action = 'toggle' }})"),
                format!("hl.dsp.window.float({{ window = {window}, action = 'toggle' }})"),
            ],
            "back in the layout",
        );
    }
    let mut out = Vec::new();
    if !floating {
        out.push(format!(
            "hl.dsp.window.float({{ window = {window}, action = 'toggle' }})"
        ));
    }
    if let Some((width, height)) = display {
        out.push(format!(
            "hl.dsp.window.resize({{ window = {window}, x = {}, y = {} }})",
            (width * 0.6).round() as i64,
            (height * 0.6).round() as i64
        ));
    }
    out.push(format!("hl.dsp.window.center({{ window = {window} }})"));
    if !pinned {
        out.push(format!(
            "hl.dsp.window.pin({{ window = {window}, action = 'toggle' }})"
        ));
    }
    out.push(format!(
        "hl.dsp.window.alter_zorder({{ window = {window}, mode = 'top' }})"
    ));
    (out, "popped out")
}

/// The focused display's logical size, for a pop-out's 60%.
fn focused_display() -> Option<(f64, f64)> {
    let monitors = hypr::json("monitors").ok()?;
    let monitor = monitors
        .as_array()?
        .iter()
        .find(|m| m.get("focused").and_then(Value::as_bool) == Some(true))?;
    let scale = monitor
        .get("scale")
        .and_then(Value::as_f64)
        .filter(|s| *s > 0.0)
        .unwrap_or(1.0);
    let width = monitor.get("width").and_then(Value::as_f64)? / scale;
    let height = monitor.get("height").and_then(Value::as_f64)? / scale;
    (width > 0.0 && height > 0.0).then_some((width, height))
}

fn pop_window(address: Option<String>, style: &Style, json_output: bool) -> ExitCode {
    let window = match address {
        Some(address) if !valid_address(&address) => return bad_address(&address),
        Some(address) => match hypr::json("clients") {
            Ok(Value::Array(windows)) => match windows
                .into_iter()
                .find(|w| text(w, "address") == address)
            {
                Some(window) => window,
                None => {
                    return refuse(
                        &format!("No window has the address {address}, so nothing was changed."),
                        1,
                    );
                }
            },
            Ok(_) => return hypr_fail(HyprError::Refused("the window list was not a list".into())),
            Err(error) => return hypr_fail(error),
        },
        None => match hypr::json("activewindow") {
            Ok(active) if valid_address(text(&active, "address")) => active,
            Ok(_) => {
                return refuse(
                    "No application window is focused, so nothing was popped out.",
                    1,
                );
            }
            Err(error) => return hypr_fail(error),
        },
    };
    let address = text(&window, "address").to_string();
    let flag = |key: &str| window.get(key).and_then(Value::as_bool) == Some(true);
    let (expressions, what) = pop_expressions(
        &address,
        flag("floating"),
        flag("pinned"),
        focused_display(),
    );
    for expression in &expressions {
        if let Err(error) = hypr::dispatch(expression) {
            return hypr_fail(error);
        }
    }
    window_result(Ok(()), style, json_output, what)
}

fn window_result(
    result: Result<(), HyprError>,
    style: &Style,
    json_output: bool,
    what: &str,
) -> ExitCode {
    match result {
        Ok(()) if json_output => print_json(&json!({ "result": what })),
        Ok(()) => {
            print!(
                "{}",
                fmt::verdict(style, Slot::Ok, &format!("Window · {what}"))
            );
            ExitCode::SUCCESS
        }
        Err(error) => hypr_fail(error),
    }
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

/// The fixed argv behind each verb, the one SessionMenu used. Absolute: this
/// must not depend on whatever PATH the session was handed.
fn session_argv(command: &SessionCommand) -> Option<[&'static str; 2]> {
    match command {
        SessionCommand::Lock => Some(["/usr/bin/loginctl", "lock-session"]),
        SessionCommand::Restart => Some(["/usr/bin/systemctl", "reboot"]),
        SessionCommand::Shutdown => Some(["/usr/bin/systemctl", "poweroff"]),
        SessionCommand::End => None,
    }
}

pub fn session(command: SessionCommand, style: &Style, json_output: bool) -> ExitCode {
    let what = match command {
        SessionCommand::Lock => "Locked",
        SessionCommand::End => "Session ending",
        SessionCommand::Restart => "Restarting",
        SessionCommand::Shutdown => "Shutting down",
    };
    let Some([program, verb]) = session_argv(&command) else {
        // Ending the session is the compositor's own exit, sent as the Lua
        // dispatcher the End-session bind uses: Hyprland 0.56's request
        // socket refuses the legacy `exit` grammar at runtime.
        return match hypr::dispatch("hl.dsp.exit()") {
            Ok(()) => done(style, json_output, what),
            Err(error) => hypr_fail(error),
        };
    };
    match Command::new(program)
        .arg(verb)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) if output.status.success() => done(style, json_output, what),
        Ok(output) => {
            let why = String::from_utf8_lossy(&output.stderr).trim().to_string();
            // polkit's answer, through logind: a decision, not a fault.
            let denied = why.contains("Access denied")
                || why.contains("authentication required")
                || why.contains("Authorization");
            refuse(
                &format!(
                    "{} was refused, and nothing happened.\nWhy: {}.\nNext step: {}",
                    what,
                    if why.is_empty() {
                        "no reason was given"
                    } else {
                        &why
                    },
                    if denied {
                        "polkit decides this for the active local session; run it from your desktop session."
                    } else {
                        "check `systemctl status systemd-logind`."
                    }
                ),
                if denied { crate::ipc::EXIT_DENIED } else { 1 },
            )
        }
        Err(error) => refuse(
            &format!("{what} failed: {program} could not start ({error})."),
            1,
        ),
    }
}

fn done(style: &Style, json_output: bool, what: &str) -> ExitCode {
    if json_output {
        return print_json(&json!({ "result": what.to_lowercase() }));
    }
    print!("{}", fmt::verdict(style, Slot::Ok, what));
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

/// The installed shell's config path: the `-p` every `qs ipc call` uses.
const SHELL_PATH: &str = "/usr/share/punar/shell";

/// `qs -p <shell> ipc call <target> <function> [args]`, from PATH as the
/// compositor binds run it. The shell answers with the function's return
/// value on stdout; a shell that is not running is not reachable.
fn shell_call(target: &str, function: &str, args: &[&str]) -> Result<String, String> {
    match Command::new("qs")
        .args(["-p", SHELL_PATH, "ipc", "call", target, function])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) if output.status.success() => {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
        Ok(output) => Err(String::from_utf8_lossy(&output.stderr).trim().to_string()),
        Err(error) => Err(format!("qs could not start ({error})")),
    }
}

fn shell_unreachable(why: &str) -> ExitCode {
    refuse(
        &format!(
            "The desktop shell is not reachable.
Why: {}.
             Next step: run this inside your desktop session, where punar-shell is running.",
            if why.is_empty() {
                "qs gave no reason"
            } else {
                why
            }
        ),
        crate::ipc::EXIT_UNREACHABLE,
    )
}

/// A notification id is the daemon's own number.
fn valid_notification_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 10 && id.bytes().all(|b| b.is_ascii_digit())
}

pub fn notifications(command: NotificationsCommand, style: &Style, json_output: bool) -> ExitCode {
    let id_of = |id: &str| -> Option<ExitCode> {
        (!valid_notification_id(id)).then(|| {
            refuse(
                &format!(
                    "{id:?} is not a notification id, so nothing was changed.
                     Next step: `punarctl notifications list` shows each id."
                ),
                2,
            )
        })
    };
    match command {
        NotificationsCommand::List => {
            let answer = match shell_call("notifications", "list", &[]) {
                Ok(answer) => answer,
                Err(why) => return shell_unreachable(&why),
            };
            let Ok(document) = serde_json::from_str::<Value>(&answer) else {
                return refuse("The shell's notification list could not be read.", 1);
            };
            if json_output {
                return print_json(&document);
            }
            let mut out = fmt::masthead(style, "Notifications", "this session");
            let rows: Vec<Row> = document
                .get("notifications")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|n| {
                    let urgency = text(n, "urgency");
                    let mut detail =
                        format!("{} · {}", safe(text(n, "source")), safe(text(n, "summary")));
                    let actions: Vec<String> = n
                        .get("actions")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .map(|a| safe(text(a, "key")))
                        .collect();
                    if !actions.is_empty() {
                        detail.push_str(&format!(" · actions {}", actions.join(", ")));
                    }
                    Row::new(
                        text(n, "id"),
                        urgency,
                        if urgency == "critical" {
                            Slot::Bad
                        } else {
                            Slot::Neutral
                        },
                        &detail,
                    )
                })
                .collect();
            if rows.is_empty() {
                out.push_str(&fmt::note(style, "No notification"));
            } else {
                out.push_str(&fmt::rows(style, &rows));
            }
            let dnd = document.get("dnd").and_then(Value::as_bool) == Some(true);
            out.push_str(&fmt::note(
                style,
                &format!("Do not disturb {}", if dnd { "on" } else { "off" }),
            ));
            print!("{out}");
            ExitCode::SUCCESS
        }
        NotificationsCommand::Dismiss { id } => {
            if let Some(code) = id_of(&id) {
                return code;
            }
            match shell_call("notifications", "dismissId", &[&id]) {
                Ok(answer) if answer == id => done(style, json_output, "Dismissed"),
                Ok(_) => refuse(
                    &format!("No notification has the id {id}, so nothing was dismissed."),
                    1,
                ),
                Err(why) => shell_unreachable(&why),
            }
        }
        NotificationsCommand::Clear => match shell_call("notifications", "clear", &[]) {
            Ok(count) if json_output => {
                print_json(&json!({ "cleared": count.parse::<u64>().unwrap_or(0) }))
            }
            Ok(count) => {
                print!(
                    "{}",
                    fmt::verdict(style, Slot::Ok, &format!("Cleared · {count}"))
                );
                ExitCode::SUCCESS
            }
            Err(why) => shell_unreachable(&why),
        },
        NotificationsCommand::Action { id, key } => {
            if let Some(code) = id_of(&id) {
                return code;
            }
            if key.is_empty() || key.chars().count() > 32 || key.chars().any(char::is_control) {
                return refuse("An action key is the short name `list` shows.", 2);
            }
            match shell_call("notifications", "invoke", &[&id, &key]).as_deref() {
                Ok("ok") => done(style, json_output, "Action invoked"),
                Ok("no-action") => refuse(
                    &format!("Notification {id} offers no action {key:?}, so nothing was invoked."),
                    1,
                ),
                Ok(_) => refuse(
                    &format!("No notification has the id {id}, so nothing was invoked."),
                    1,
                ),
                Err(why) => shell_unreachable(why),
            }
        }
        NotificationsCommand::Dnd { mode } => match shell_call("notifications", "dnd", &[&mode]) {
            Ok(state) if json_output => print_json(&json!({ "dnd": state == "on" })),
            Ok(state) => {
                print!(
                    "{}",
                    fmt::verdict(style, Slot::Ok, &format!("Do not disturb · {state}"))
                );
                ExitCode::SUCCESS
            }
            Err(why) => shell_unreachable(&why),
        },
    }
}

// ---------------------------------------------------------------------------
// Displays
// ---------------------------------------------------------------------------

pub fn display(command: DisplayCommand, style: &Style, json_output: bool) -> ExitCode {
    if let DisplayCommand::Brightness { change, keyboard } = command {
        return crate::brightness::brightness(&change, keyboard, style, json_output);
    }
    match hypr::json("monitors") {
        Ok(Value::Array(monitors)) => {
            if json_output {
                return print_json(&json!({ "monitors": monitors }));
            }
            let mut out = fmt::masthead(style, "Displays", "this session");
            let rows: Vec<Row> = monitors
                .iter()
                .map(|m| {
                    let number = |key: &str| m.get(key).and_then(Value::as_f64).unwrap_or(0.0);
                    let mode = format!(
                        "{}x{}@{:.0}",
                        number("width"),
                        number("height"),
                        number("refreshRate")
                    );
                    let mut detail = format!(
                        "{} · scale {} · at {},{}",
                        safe(text(m, "description")),
                        number("scale"),
                        number("x"),
                        number("y")
                    );
                    if m.get("focused").and_then(Value::as_bool) == Some(true) {
                        detail.push_str(" · focused");
                    }
                    Row::new(&safe(text(m, "name")), &mode, Slot::Neutral, &detail)
                })
                .collect();
            if rows.is_empty() {
                out.push_str(&fmt::note(style, "No display is connected"));
            } else {
                out.push_str(&fmt::rows(style, &rows));
            }
            print!("{out}");
            ExitCode::SUCCESS
        }
        Ok(_) => hypr_fail(HyprError::Refused("the display list was not a list".into())),
        Err(error) => hypr_fail(error),
    }
}

// ---------------------------------------------------------------------------
// Audio
// ---------------------------------------------------------------------------

/// `wpctl`, from PATH as the volume keys run it (punar-binds.lua).
fn wpctl(args: &[&str]) -> Result<String, String> {
    match Command::new("wpctl")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) if output.status.success() => {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        Ok(output) => Err(String::from_utf8_lossy(&output.stderr).trim().to_string()),
        Err(error) => Err(format!("wpctl could not start ({error})")),
    }
}

fn audio_unreachable(why: &str) -> ExitCode {
    refuse(
        &format!(
            "PipeWire is not reachable.\nWhy: {}.\n\
             Next step: run this inside your desktop session.",
            if why.is_empty() {
                "wpctl gave no reason"
            } else {
                why
            }
        ),
        crate::ipc::EXIT_UNREACHABLE,
    )
}

/// `Volume: 0.40 [MUTED]` → (40, true).
fn parse_volume(line: &str) -> Option<(u32, bool)> {
    let rest = line.trim().strip_prefix("Volume:")?.trim();
    let number = rest.split_whitespace().next()?;
    let fraction: f64 = number.parse().ok()?;
    Some(((fraction * 100.0).round() as u32, rest.contains("[MUTED]")))
}

/// `+5%` → `5%+`, `-5%` → `5%-`, `40%` → `40%`, within 0-100.
fn volume_arg(change: &str) -> Option<String> {
    let (sign, rest) = match change.as_bytes().first()? {
        b'+' => ("+", &change[1..]),
        b'-' => ("-", &change[1..]),
        _ => ("", change),
    };
    let digits = rest.strip_suffix('%')?;
    if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u32 = digits.parse().ok()?;
    (value <= 100).then(|| format!("{value}%{sign}"))
}

/// A device the verb would drive is not there, while PipeWire itself
/// answers: exit 6, like `display brightness` with no backlight, rather
/// than blaming PipeWire (SMP-1405 WP-02).
fn audio_absent(what: &str, why: &str) -> ExitCode {
    refuse(
        &format!(
            "This machine has no {what} PipeWire can use, so nothing was changed.
             Why: PipeWire answers but reports no default {what} ({}).
             Next step: connect one; the key works as soon as PipeWire sees it.",
            if why.is_empty() {
                "wpctl gave no reason"
            } else {
                why
            }
        ),
        crate::ipc::EXIT_ABSENT,
    )
}

/// Whether PipeWire answers at all.
fn pipewire_reachable() -> bool {
    wpctl(&["status"]).is_ok()
}

/// Both default devices, `null` where there is none. An error only when
/// PipeWire itself does not answer.
fn audio_state() -> Result<Value, String> {
    let read = |node: &str| -> Result<Value, String> {
        let line = wpctl(&["get-volume", node])?;
        Ok(match parse_volume(&line) {
            Some((percent, muted)) => json!({ "volume_percent": percent, "muted": muted }),
            None => Value::Null,
        })
    };
    let output = read("@DEFAULT_AUDIO_SINK@");
    let input = read("@DEFAULT_AUDIO_SOURCE@");
    if let (Err(why), Err(_)) = (&output, &input) {
        // Neither device answered: PipeWire is down, or has no devices.
        if !pipewire_reachable() {
            return Err(why.clone());
        }
    }
    Ok(json!({
        "output": output.unwrap_or(Value::Null),
        "input": input.unwrap_or(Value::Null),
    }))
}

pub fn audio(command: AudioCommand, style: &Style, json_output: bool) -> ExitCode {
    let change = match &command {
        AudioCommand::Status => None,
        AudioCommand::Volume { change } => match volume_arg(change) {
            Some(arg) => Some(vec![
                "set-volume".to_string(),
                "-l".into(),
                "1.0".into(),
                "@DEFAULT_AUDIO_SINK@".into(),
                arg,
            ]),
            None => {
                return refuse(
                    &format!(
                        "{change:?} is not a volume change, so nothing was changed.\n\
                         Next step: give `+5%`, `-5%` or a level like `40%` (0-100)."
                    ),
                    2,
                );
            }
        },
        AudioCommand::Mute { state, input } => Some(vec![
            "set-mute".to_string(),
            if *input {
                "@DEFAULT_AUDIO_SOURCE@"
            } else {
                "@DEFAULT_AUDIO_SINK@"
            }
            .into(),
            match state.as_deref() {
                Some("on") => "1",
                Some("off") => "0",
                _ => "toggle",
            }
            .into(),
        ]),
    };
    if let Some(args) = change {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        if let Err(why) = wpctl(&args) {
            if !pipewire_reachable() {
                return audio_unreachable(&why);
            }
            let what = if matches!(command, AudioCommand::Mute { input: true, .. }) {
                "microphone"
            } else {
                "audio output"
            };
            return audio_absent(what, &why);
        }
    }
    let state = match audio_state() {
        Ok(state) => state,
        Err(why) => return audio_unreachable(&why),
    };
    if json_output {
        return print_json(&state);
    }
    let mut out = fmt::masthead(style, "Audio", "this session");
    let row = |label: &str, node: &Value| match node.get("volume_percent").and_then(Value::as_u64) {
        Some(percent) => {
            let muted = node.get("muted").and_then(Value::as_bool) == Some(true);
            Row::new(
                label,
                &format!("{percent} %"),
                if muted { Slot::Warn } else { Slot::Neutral },
                if muted { "muted" } else { "" },
            )
        }
        None => Row::new(label, "unknown", Slot::Neutral, "no default device"),
    };
    out.push_str(&fmt::rows(
        style,
        &[
            row("Output", &state["output"]),
            row("Input", &state["input"]),
        ],
    ));
    print!("{out}");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bare number is an address, never a name; leading zeros stay names.
    #[test]
    fn numbers_are_addresses_and_names_are_projects() {
        assert_eq!(workspace_address("3"), Some(3));
        assert_eq!(workspace_address("99"), Some(99));
        assert_eq!(workspace_address("007"), None);
        assert_eq!(workspace_address("100"), Some(100));
        assert_eq!(workspace_address("-3"), None);
        assert_eq!(project_name("  Atlas   Dev "), Some("atlas dev".into()));
        assert_eq!(project_name("special-x"), None);
        assert_eq!(project_name("a,b"), None);
    }

    /// The volume keys' grammar: relative or absolute, never past 100%.
    #[test]
    fn volume_changes_are_bounded() {
        assert_eq!(volume_arg("+5%").as_deref(), Some("5%+"));
        assert_eq!(volume_arg("-10%").as_deref(), Some("10%-"));
        assert_eq!(volume_arg("40%").as_deref(), Some("40%"));
        for bad in ["101%", "5", "+%", "5%%", "-", "1e2%", "+1000%"] {
            assert_eq!(volume_arg(bad), None, "{bad}");
        }
        assert_eq!(parse_volume("Volume: 0.40 [MUTED]\n"), Some((40, true)));
        assert_eq!(parse_volume("Volume: 1.00"), Some((100, false)));
        assert_eq!(parse_volume("nonsense"), None);
    }

    /// The session verbs run exactly the argv SessionMenu ran, by absolute path.
    #[test]
    fn session_verbs_are_fixed_argv() {
        assert_eq!(
            session_argv(&SessionCommand::Restart),
            Some(["/usr/bin/systemctl", "reboot"])
        );
        assert_eq!(
            session_argv(&SessionCommand::Shutdown),
            Some(["/usr/bin/systemctl", "poweroff"])
        );
        assert_eq!(
            session_argv(&SessionCommand::Lock),
            Some(["/usr/bin/loginctl", "lock-session"])
        );
        assert_eq!(session_argv(&SessionCommand::End), None);
    }

    /// Pop out floats, sizes, centres, pins and raises; putting it back
    /// unpins before it tiles, because a pinned window cannot tile.
    #[test]
    fn pop_out_and_back_send_the_dispatchers_in_order() {
        let (out, what) = pop_expressions("0x1a", false, false, Some((1920.0, 1080.0)));
        assert_eq!(what, "popped out");
        assert_eq!(
            out,
            [
                "hl.dsp.window.float({ window = 'address:0x1a', action = 'toggle' })",
                "hl.dsp.window.resize({ window = 'address:0x1a', x = 1152, y = 648 })",
                "hl.dsp.window.center({ window = 'address:0x1a' })",
                "hl.dsp.window.pin({ window = 'address:0x1a', action = 'toggle' })",
                "hl.dsp.window.alter_zorder({ window = 'address:0x1a', mode = 'top' })",
            ]
        );
        // Already floating: no float toggle, which would tile it.
        let (out, _) = pop_expressions("0x1a", true, false, None);
        assert!(!out.iter().any(|e| e.contains("float")), "{out:?}");
        let (out, what) = pop_expressions("0x1a", true, true, None);
        assert_eq!(what, "back in the layout");
        assert!(
            out[0].starts_with("hl.dsp.window.pin(") && out[1].starts_with("hl.dsp.window.float(")
        );
    }

    #[test]
    fn window_addresses_are_hex_only() {
        assert!(valid_address("0x55d1c3a0"));
        for bad in ["0x", "55d1", "0xZZ", "0x1' })", "0x11111111111111111"] {
            assert!(!valid_address(bad), "{bad}");
        }
    }
}
