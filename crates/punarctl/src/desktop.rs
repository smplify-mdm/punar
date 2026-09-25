//! The installed-application index the launcher shows, and the "raise the
//! open window first" half of opening an app — the terminal side of
//! `shell/punar-shell/Services/Apps.qml`.
//!
//! **Read-only, and never a shell.** The index is the freedesktop one: every
//! `applications/*.desktop` under the user's `$XDG_DATA_HOME` and
//! `$XDG_DATA_DIRS`, first id wins, `Hidden` and `NoDisplay` entries left
//! out. `Exec` becomes argv by the Desktop Entry Specification's own quoting
//! rules; nothing is ever handed to `/bin/sh`.
//!
//! **Focus before launch.** Like the launcher, `app open` raises a window the
//! app already has instead of starting a second copy. The candidates are the
//! ones Apps.qml derives (the desktop id, the executable, and the catalog's
//! own window ids), and the focus request is the same Hyprland dispatcher
//! expression HyprlandActions.qml sends. Outside a Hyprland session there is
//! nothing to raise and the app simply starts.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

/// The compositor's CLI, absolute for the reason ControlData.qml gives: this
/// must not depend on whatever PATH the session handed us.
const HYPRCTL: &str = "/usr/bin/hyprctl";

/// Bounds on the scan, so a hostile or enormous data directory costs a
/// bounded amount of work.
const MAX_DEPTH: usize = 3;
const MAX_ENTRIES: usize = 4096;
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// One launchable application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopEntry {
    /// The desktop file id: the path under `applications/` with `/` as `-`
    /// and without `.desktop`.
    pub id: String,
    pub name: String,
    pub exec: Vec<String>,
    pub terminal: bool,
    pub path: Option<String>,
}

impl DesktopEntry {
    /// The catalog id when this entry is a catalog app's own launcher
    /// (`punarctl app open <id>`): the catalog row already stands for it.
    pub fn catalog_id(&self) -> Option<&str> {
        match self.exec.as_slice() {
            [program, app, open, id, ..]
                if executable_name(program) == "punarctl" && app == "app" && open == "open" =>
            {
                Some(id)
            }
            _ => None,
        }
    }
}

/// `$XDG_DATA_HOME` then `$XDG_DATA_DIRS`, each only when absolute, with the
/// specification's defaults.
fn data_dirs() -> Vec<PathBuf> {
    let absolute = |value: String| {
        let path = PathBuf::from(value);
        path.is_absolute().then_some(path)
    };
    let mut dirs = Vec::new();
    match env::var("XDG_DATA_HOME").ok().and_then(absolute) {
        Some(home) => dirs.push(home),
        None => {
            if let Some(home) = env::var("HOME").ok().and_then(absolute) {
                dirs.push(home.join(".local/share"));
            }
        }
    }
    let system: Vec<PathBuf> = env::var("XDG_DATA_DIRS")
        .ok()
        .map(|value| {
            value
                .split(':')
                .filter_map(|part| absolute(part.to_string()))
                .collect()
        })
        .filter(|parts: &Vec<PathBuf>| !parts.is_empty())
        .unwrap_or_else(|| vec!["/usr/local/share".into(), "/usr/share".into()]);
    dirs.extend(system);
    dirs
}

/// Every visible application, in the order the specification gives
/// precedence: the first file for an id wins, even when it hides the entry.
pub fn index() -> Vec<DesktopEntry> {
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    for dir in data_dirs() {
        scan(&dir.join("applications"), "", 0, &mut seen, &mut entries);
    }
    entries.sort_by_key(|entry| entry.name.to_lowercase());
    entries
}

fn scan(
    dir: &Path,
    prefix: &str,
    depth: usize,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<DesktopEntry>,
) {
    let Ok(listing) = fs::read_dir(dir) else {
        return;
    };
    let mut names: Vec<(String, PathBuf, bool)> = listing
        .flatten()
        .filter_map(|item| {
            let name = item.file_name().to_str()?.to_string();
            let is_dir = item.file_type().ok()?.is_dir();
            Some((name, item.path(), is_dir))
        })
        .collect();
    names.sort();
    for (name, path, is_dir) in names {
        if seen.len() >= MAX_ENTRIES {
            return;
        }
        if is_dir {
            if depth < MAX_DEPTH {
                scan(&path, &format!("{prefix}{name}-"), depth + 1, seen, out);
            }
            continue;
        }
        let Some(stem) = name.strip_suffix(".desktop") else {
            continue;
        };
        let id = format!("{prefix}{stem}");
        // First file for an id wins, including one that hides it.
        if !seen.insert(id.clone()) {
            continue;
        }
        let small = fs::metadata(&path).is_ok_and(|meta| meta.len() <= MAX_FILE_BYTES);
        if let Some(text) = small.then(|| fs::read_to_string(&path).ok()).flatten() {
            if let Some(entry) = parse(&id, &path, &text) {
                out.push(entry);
            }
        }
    }
}

/// The `[Desktop Entry]` group of one file, or `None` when it is not a
/// visible application the launcher would show.
pub fn parse(id: &str, file: &Path, text: &str) -> Option<DesktopEntry> {
    let mut in_group = false;
    let mut keys = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_group = line == "[Desktop Entry]";
            continue;
        }
        if !in_group {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            // Localized keys (`Name[fr]`) are not the entry's own name.
            keys.entry(key.trim().to_string())
                .or_insert_with(|| value.trim().to_string());
        }
    }
    let flag = |key: &str| keys.get(key).is_some_and(|value| value == "true");
    if keys.get("Type").map(String::as_str) != Some("Application")
        || flag("Hidden")
        || flag("NoDisplay")
    {
        return None;
    }
    let name = unescape(keys.get("Name")?);
    let exec = split_exec(
        keys.get("Exec")?,
        &name,
        keys.get("Icon").map(String::as_str),
        file,
    )
    .ok()?;
    Some(DesktopEntry {
        id: id.to_string(),
        name,
        exec,
        terminal: flag("Terminal"),
        path: keys
            .get("Path")
            .map(|value| unescape(value))
            .filter(|path| !path.is_empty()),
    })
}

/// The string-value escapes (`\s \n \t \r \\`), applied before quoting.
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('s') => out.push(' '),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// `Exec` to argv, by the Desktop Entry Specification: string escapes first,
/// then double-quote quoting with `\" \` \$ \\` inside quotes, then field
/// codes. Nothing is passed as a file or URL, so `%f %F %u %U` (and the
/// deprecated codes) drop out; `%i`, `%c` and `%k` expand; an unknown code
/// makes the entry invalid.
pub fn split_exec(
    value: &str,
    name: &str,
    icon: Option<&str>,
    file: &Path,
) -> Result<Vec<String>, String> {
    let value = unescape(value);
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quoted = false;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' => quoted = false,
                '\\' => match chars.next() {
                    Some(escaped @ ('"' | '`' | '$' | '\\')) => current.push(escaped),
                    Some(other) => {
                        current.push('\\');
                        current.push(other);
                    }
                    None => return Err("Exec ends inside an escape".into()),
                },
                other => current.push(other),
            }
            continue;
        }
        match c {
            ' ' | '\t' => {
                if started {
                    tokens.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            '"' => {
                quoted = true;
                started = true;
            }
            other => {
                current.push(other);
                started = true;
            }
        }
    }
    if quoted {
        return Err("Exec has an unterminated quote".into());
    }
    if started {
        tokens.push(current);
    }

    let mut argv = Vec::new();
    for token in tokens {
        match token.as_str() {
            "%f" | "%F" | "%u" | "%U" | "%d" | "%D" | "%n" | "%N" | "%v" | "%m" => continue,
            "%i" => {
                if let Some(icon) = icon.filter(|icon| !icon.is_empty()) {
                    argv.push("--icon".to_string());
                    argv.push(icon.to_string());
                }
                continue;
            }
            _ => {}
        }
        let mut expanded = String::new();
        let mut chars = token.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                expanded.push(c);
                continue;
            }
            match chars.next() {
                Some('%') => expanded.push('%'),
                Some('c') => expanded.push_str(name),
                Some('k') => expanded.push_str(&file.to_string_lossy()),
                Some('f' | 'F' | 'u' | 'U' | 'd' | 'D' | 'n' | 'N' | 'v' | 'm') => {}
                Some(other) => return Err(format!("Exec uses an unknown field code %{other}")),
                None => return Err("Exec ends with a lone %".into()),
            }
        }
        argv.push(expanded);
    }
    if argv.is_empty() {
        return Err("Exec names no program".into());
    }
    Ok(argv)
}

/// Apps.qml's `normalizedWindowId`: trimmed, lower-case, no `.desktop`.
pub fn normalized_window_id(value: &str) -> String {
    let id = value.trim().to_lowercase();
    match id.strip_suffix(".desktop") {
        Some(stem) if !stem.is_empty() => stem.to_string(),
        _ => id,
    }
}

/// Apps.qml's `executableName`: the last path component, normalized.
pub fn executable_name(value: &str) -> String {
    normalized_window_id(value.trim().rsplit('/').next().unwrap_or(""))
}

/// Apps.qml's `addWindowCandidate`, including the `punar-` packaging
/// namespace an application's own Wayland id does not carry.
fn add_candidate(candidates: &mut BTreeSet<String>, value: &str) {
    let id = normalized_window_id(value);
    if id.is_empty() {
        return;
    }
    if let Some(bare) = id.strip_prefix("punar-").filter(|bare| !bare.is_empty()) {
        candidates.insert(bare.to_string());
    }
    candidates.insert(id);
}

/// The window ids a catalog app may show up as: Apps.qml's
/// `catalogWindowCandidates` over an `apps.catalog` detail object.
pub fn catalog_candidates(app: &Value) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    let text = |key: &str| app.get(key).and_then(Value::as_str).unwrap_or("");
    for key in ["id", "app_id", "desktop_id", "package_name"] {
        add_candidate(&mut candidates, text(key));
    }
    add_candidate(&mut candidates, &executable_name(text("launch_executable")));
    for id in app
        .get("window_app_ids")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        add_candidate(&mut candidates, id);
    }
    candidates
}

/// The window ids a desktop entry may show up as: Apps.qml's
/// `entryWindowCandidates` without the catalog join (a catalog launcher is
/// opened through the catalog instead).
pub fn entry_candidates(entry: &DesktopEntry) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    add_candidate(&mut candidates, &entry.id);
    if let Some(program) = entry.exec.first() {
        add_candidate(&mut candidates, &executable_name(program));
    }
    candidates
}

/// The class of the first open window whose class matches a candidate, from
/// `hyprctl -j clients`.
pub fn matching_class(clients: &Value, candidates: &BTreeSet<String>) -> Option<String> {
    clients.as_array()?.iter().find_map(|client| {
        let class = client.get("class").and_then(Value::as_str)?.trim();
        let normalized = normalized_window_id(class);
        (!normalized.is_empty() && candidates.contains(&normalized)).then(|| class.to_string())
    })
}

/// HyprlandActions.qml's `focusWindow("class:^<class>$")`: the class is a
/// regex-escaped literal inside a Lua string literal.
pub fn focus_expression(class: &str) -> String {
    let mut pattern = String::new();
    for c in class.chars() {
        if ".*+?^${}()|[]\\".contains(c) {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    let selector = format!("class:^{pattern}$");
    let mut lua = String::from("'");
    for c in selector.chars() {
        match c {
            '\\' => lua.push_str("\\\\"),
            '\'' => lua.push_str("\\'"),
            '\r' => lua.push_str("\\r"),
            '\n' => lua.push_str("\\n"),
            other => lua.push(other),
        }
    }
    lua.push('\'');
    format!("hl.dsp.focus({{ window = {lua} }})")
}

/// Raise an open window of the app, when this is a Hyprland session and one
/// is open. `true` only when Hyprland answered `ok`, so the caller never
/// claims a focus that did not happen and launches instead.
pub fn focus_existing(candidates: &BTreeSet<String>) -> bool {
    if env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none() || candidates.is_empty() {
        return false;
    }
    let Ok(output) = Command::new(HYPRCTL)
        .args(["-j", "clients"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    let Ok(clients) = serde_json::from_slice::<Value>(&output.stdout) else {
        return false;
    };
    let Some(class) = matching_class(&clients, candidates) else {
        return false;
    };
    Command::new(HYPRCTL)
        .args(["dispatch", &focus_expression(&class)])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|done| {
            done.status.success() && String::from_utf8_lossy(&done.stdout).trim() == "ok"
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn exec(value: &str) -> Result<Vec<String>, String> {
        split_exec(
            value,
            "Files",
            Some("folder"),
            Path::new("/usr/share/applications/files.desktop"),
        )
    }

    /// Quoting follows the specification, not a shell: spaces inside quotes
    /// stay, the four escapes unescape, and `$` is never expanded.
    #[test]
    fn exec_splits_by_the_specification_quoting_rules() {
        assert_eq!(
            exec(r#"/usr/bin/app --title "Two words" "a\"b" "$HOME" plain"#).unwrap(),
            [
                "/usr/bin/app",
                "--title",
                "Two words",
                "a\"b",
                "$HOME",
                "plain"
            ]
        );
        // A literal backslash in a quoted argument takes four in the file.
        assert_eq!(exec(r#"app "c:\\\\dir""#).unwrap(), ["app", r"c:\dir"]);
        assert_eq!(exec(r#"app """#).unwrap(), ["app", ""]);
        assert!(exec(r#"app "open"#).is_err());
        assert!(exec("   ").is_err());
    }

    /// Nothing is passed as a file or URL, so those codes drop out; `%i`,
    /// `%c`, `%k` and `%%` expand; an unknown code refuses the entry.
    #[test]
    fn exec_field_codes_expand_or_drop() {
        assert_eq!(
            exec("app %U --name=%c %i 100%% %k").unwrap(),
            [
                "app",
                "--name=Files",
                "--icon",
                "folder",
                "100%",
                "/usr/share/applications/files.desktop"
            ]
        );
        assert_eq!(exec("app --open=%f").unwrap(), ["app", "--open="]);
        assert!(exec("app %z").is_err());
        assert!(exec("app 50%").is_err());
    }

    /// The launcher's index: applications only, `Hidden`/`NoDisplay` out,
    /// localized names ignored, `Terminal` and `Path` kept.
    #[test]
    fn parse_keeps_what_the_launcher_shows() {
        let file = Path::new("/x/htop.desktop");
        let entry = parse(
            "htop",
            file,
            "[Desktop Entry]\nType=Application\nName[fr]=Moniteur\nName=htop\n\
             Exec=htop\nTerminal=true\nPath=/tmp\n[Desktop Action new]\nName=Other\n",
        )
        .unwrap();
        assert_eq!(entry.name, "htop");
        assert!(entry.terminal);
        assert_eq!(entry.path.as_deref(), Some("/tmp"));
        for hidden in [
            "Type=Application\nNoDisplay=true",
            "Type=Application\nHidden=true",
            "Type=Link",
        ] {
            let text = format!("[Desktop Entry]\n{hidden}\nName=x\nExec=x\n");
            assert!(parse("x", file, &text).is_none(), "{hidden}");
        }
    }

    /// A catalog app's own launcher is recognised, so `--all` does not list
    /// it twice.
    #[test]
    fn a_catalog_launcher_names_its_catalog_id() {
        let entry = parse(
            "punar-spotify",
            Path::new("/x/punar-spotify.desktop"),
            "[Desktop Entry]\nType=Application\nName=Spotify\nExec=/usr/bin/punarctl app open spotify %U\n",
        )
        .unwrap();
        assert_eq!(entry.catalog_id(), Some("spotify"));
    }

    /// The candidates are Apps.qml's, and a match picks the window's own
    /// class for the focus request.
    #[test]
    fn candidates_and_matching_mirror_the_launcher() {
        let app = json!({
            "id": "spotify", "desktop_id": "com.spotify.Client.desktop",
            "launch_executable": "/opt/punar/vendor/spotify/spotify",
            "window_app_ids": ["Spotify"]
        });
        let candidates = catalog_candidates(&app);
        assert!(candidates.contains("com.spotify.client"));
        assert!(candidates.contains("spotify"));
        let clients = json!([
            {"class": "foot", "address": "0x1"},
            {"class": "Spotify", "address": "0x2"}
        ]);
        assert_eq!(
            matching_class(&clients, &candidates).as_deref(),
            Some("Spotify")
        );
        assert_eq!(matching_class(&json!([]), &candidates), None);

        let entry = DesktopEntry {
            id: "punar-notes".into(),
            name: "Notes".into(),
            exec: vec!["/usr/bin/gnome-text-editor".into()],
            terminal: false,
            path: None,
        };
        let candidates = entry_candidates(&entry);
        assert!(candidates.contains("notes"));
        assert!(candidates.contains("gnome-text-editor"));
    }

    /// A window class is data: it is regex-escaped and then Lua-quoted, so
    /// it can neither widen the selector nor end the string.
    #[test]
    fn focus_expression_escapes_the_class() {
        assert_eq!(
            focus_expression("org.gnome.Nautilus"),
            r"hl.dsp.focus({ window = 'class:^org\\.gnome\\.Nautilus$' })"
        );
        assert_eq!(
            focus_expression("a'b"),
            r"hl.dsp.focus({ window = 'class:^a\'b$' })"
        );
    }
}
