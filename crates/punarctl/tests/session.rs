//! The session verbs against a fake compositor: a Unix socket at the path
//! Hyprland uses, answering the requests `punarctl` sends and logging every
//! one, so each test asserts the exact dispatcher expression the GUI now
//! relies on. PipeWire is a fake `wpctl` on PATH.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use serde_json::{Value, json};

static SEQ: AtomicUsize = AtomicUsize::new(0);

struct Session {
    root: PathBuf,
}

impl Session {
    /// A runtime dir with a fake Hyprland answering by `responder`, and a
    /// home with the shell's workspace store.
    fn start(responder: fn(&str) -> String) -> Session {
        let root = std::env::temp_dir().join(format!(
            "punarctl-session-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&root);
        let socket_dir = root.join("run/hypr/test-sig");
        fs::create_dir_all(&socket_dir).unwrap();
        fs::create_dir_all(root.join("home/.local/state/punar")).unwrap();
        let listener = UnixListener::bind(socket_dir.join(".socket.sock")).unwrap();
        let log = root.join("requests.log");
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buffer = [0u8; 65536];
                let read = stream.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log)
                    .unwrap();
                writeln!(file, "{request}").unwrap();
                let _ = stream.write_all(responder(&request).as_bytes());
            }
        });
        Session { root }
    }

    fn requests(&self) -> Vec<String> {
        fs::read_to_string(self.root.join("requests.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_punarctl"));
        command
            .args(args)
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("HYPRLAND_INSTANCE_SIGNATURE", "test-sig")
            .env("HOME", self.root.join("home"))
            .env("NO_COLOR", "1");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Workspace 1 (unnamed) and 3 (atlas) are open, 3 focused; two displays.
fn desktop(request: &str) -> String {
    match request {
        "j/workspaces" => json!([
            {"id": 1, "name": "1", "windows": 2, "monitor": "Virtual-1"},
            {"id": 3, "name": "atlas", "windows": 1, "monitor": "Virtual-1"}
        ])
        .to_string(),
        "j/activeworkspace" => json!({"id": 3, "name": "atlas"}).to_string(),
        "j/activewindow" => json!({
            "address": "0x55d1c3a0", "class": "foot", "title": "punar@atlas: ~",
            "workspace": {"id": 3, "name": "atlas"}
        })
        .to_string(),
        "j/clients" => json!([
            {"address": "0x55d1c3a0", "class": "foot", "title": "punar@atlas: ~",
             "workspace": {"id": 3, "name": "atlas"}}
        ])
        .to_string(),
        "j/monitors" => json!([
            {"name": "Virtual-1", "description": "QEMU Monitor", "width": 1920, "height": 1080,
             "refreshRate": 60.0, "scale": 1.0, "x": 0, "y": 0, "focused": true}
        ])
        .to_string(),
        other if other.starts_with("dispatch ") => "ok".to_string(),
        _ => "unknown request".to_string(),
    }
}

/// Every dispatcher is refused.
fn refusing(request: &str) -> String {
    if request.starts_with("dispatch ") {
        "Invalid dispatcher".to_string()
    } else {
        desktop(request)
    }
}

fn store(session: &Session, entries: Value) {
    fs::write(
        session.root.join("home/.local/state/punar/workspaces.json"),
        json!({"version": 1, "updated": "2026-09-24T00:00:00Z", "layoutPreset": "balanced",
               "workspaces": entries})
        .to_string(),
    )
    .unwrap();
}

/// Live and stored projects, the focused one marked, and the Hyprland
/// answer verbatim under --json.
#[test]
fn workspace_list_shows_live_and_stored_projects() {
    let session = Session::start(desktop);
    store(&session, json!([{"id": 5, "name": "notes"}]));
    let output = session.run(&["workspace", "list"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    let atlas = text.lines().find(|l| l.starts_with("3 ")).expect(&text);
    assert!(
        atlas.contains("ATLAS") && atlas.contains("focused"),
        "{atlas}"
    );
    let notes = text.lines().find(|l| l.starts_with("5 ")).expect(&text);
    assert!(
        notes.contains("NOTES") && notes.contains("stored"),
        "{notes}"
    );

    let output = session.run(&["--json", "workspace", "list"]);
    let document: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(document["active"], 3);
    assert_eq!(document["workspaces"][1]["name"], "atlas");
    assert_eq!(document["stored"], json!([{"id": 5, "name": "notes"}]));
}

/// `workspace new` is the command center's "Open <name>": a new project
/// takes the first id no live or stored workspace holds, then gets its name;
/// an open one is only focused.
#[test]
fn workspace_new_and_focus_send_the_command_centers_dispatchers() {
    let session = Session::start(desktop);
    store(&session, json!([{"id": 2, "name": "notes"}]));
    let output = session.run(&["--json", "workspace", "new", "  Payments  "]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let document: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(
        document,
        json!({"id": 4, "name": "payments", "created": true})
    );
    let dispatched: Vec<String> = session
        .requests()
        .into_iter()
        .filter(|r| r.starts_with("dispatch "))
        .collect();
    assert_eq!(
        dispatched,
        [
            "dispatch hl.dsp.focus({ workspace = '4' })",
            "dispatch hl.dsp.workspace.rename({ workspace = '4', name = 'payments' })"
        ]
    );

    let session = Session::start(desktop);
    let output = session.run(&["workspace", "focus", "Atlas"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        session
            .requests()
            .contains(&"dispatch hl.dsp.focus({ workspace = '3' })".to_string())
    );
    assert!(!session.requests().iter().any(|r| r.contains("rename")));

    let output = session.run(&["workspace", "focus", "7"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        session
            .requests()
            .contains(&"dispatch hl.dsp.focus({ workspace = '7' })".to_string())
    );
}

/// A name outside the grammar, a special workspace, an unknown project and
/// a refused dispatcher each change nothing and say why.
#[test]
fn workspace_refusals_send_no_dispatcher() {
    let session = Session::start(desktop);
    for args in [
        &["workspace", "rename", "3", "a,b"][..],
        &["workspace", "rename", "0", "atlas"][..],
        &["workspace", "new", "special-x"][..],
    ] {
        let output = session.run(args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    let output = session.run(&["workspace", "focus", "nowhere"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("punarctl workspace new nowhere"),
        "{}",
        stderr(&output)
    );
    assert!(
        !session
            .requests()
            .iter()
            .any(|r| r.starts_with("dispatch "))
    );

    let session = Session::start(refusing);
    let output = session.run(&["workspace", "rename", "3", "Atlas Dev"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("Invalid dispatcher"),
        "{}",
        stderr(&output)
    );
}

/// Close and kill name one exact window, quoted as data; kill never guesses.
#[test]
fn window_close_and_kill_address_one_window() {
    let session = Session::start(desktop);
    let output = session.run(&["window", "close"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let output = session.run(&["window", "kill", "--address", "0x55d1c3a0"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let output = session.run(&["window", "focus", "--class", "org.gnome.Nautilus"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let dispatched: Vec<String> = session
        .requests()
        .into_iter()
        .filter(|r| r.starts_with("dispatch "))
        .collect();
    assert_eq!(
        dispatched,
        [
            "dispatch hl.dsp.window.close({ window = 'address:0x55d1c3a0' })",
            "dispatch hl.dsp.window.kill({ window = 'address:0x55d1c3a0' })",
            r"dispatch hl.dsp.focus({ window = 'class:^org\\.gnome\\.Nautilus$' })"
        ]
    );
    for bad in ["0x1' }) hl.dsp.exec_cmd('x", "55d1"] {
        let output = session.run(&["window", "kill", "--address", bad]);
        assert_eq!(output.status.code(), Some(2), "{bad}");
    }
    let output = session.run(&["window", "kill"]);
    assert_eq!(output.status.code(), Some(2), "kill needs --address");

    let output = session.run(&["--json", "window", "active"]);
    let active: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(active["address"], "0x55d1c3a0");
}

/// Ending the session is the compositor's own exit; displays are listed.
#[test]
fn session_end_and_display_list_use_the_compositor() {
    let session = Session::start(desktop);
    let output = session.run(&["session", "end"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(session.requests().contains(&"dispatch exit".to_string()));

    let output = session.run(&["display", "list"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    let row = text
        .lines()
        .find(|l| l.starts_with("VIRTUAL-1"))
        .expect(&text);
    assert!(
        row.contains("1920X1080@60") && row.contains("focused"),
        "{row}"
    );
}

/// No compositor: exit 5, the not-reachable code, and a next step.
#[test]
fn without_a_compositor_every_session_verb_exits_5() {
    for args in [
        &["workspace", "list"][..],
        &["window", "close"][..],
        &["session", "end"][..],
        &["display", "list"][..],
        &["layout", "columns"][..],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_punarctl"))
            .args(args)
            .env_remove("HYPRLAND_INSTANCE_SIGNATURE")
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(5),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(stderr(&output).contains("Next step:"), "{args:?}");
    }
}

/// `layout status` reads the preset the layout script last recorded.
#[test]
fn layout_status_reads_the_scripts_record() {
    let session = Session::start(desktop);
    let output = session.run(&["--json", "layout", "status"]);
    let status: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(status["preset"], "balanced");
    fs::create_dir_all(session.root.join("run/punar")).unwrap();
    fs::write(session.root.join("run/punar/layout-preset"), "columns\n").unwrap();
    let output = session.run(&["--json", "layout", "status"]);
    let status: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(status["preset"], "columns");
    assert_eq!(status["source"], "applied this session");
}

fn fake_wpctl(dir: &Path, working: bool) -> PathBuf {
    let bin = dir.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let script = bin.join("wpctl");
    let body = if working {
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n\
             case \"$1\" in get-volume) echo 'Volume: 0.40';; esac\n",
            dir.join("wpctl.log").display()
        )
    } else {
        "#!/bin/sh\necho 'Could not connect to PipeWire' >&2\nexit 1\n".to_string()
    };
    fs::write(&script, body).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

/// The volume keys' grammar, through wpctl, capped at 100%.
#[test]
fn audio_volume_runs_wpctl_capped_and_reports_the_level() {
    let session = Session::start(desktop);
    let bin = fake_wpctl(&session.root, true);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = session
        .command(&["--json", "audio", "volume", "+5%"])
        .env("PATH", &path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let state: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(
        state["output"],
        json!({"volume_percent": 40, "muted": false})
    );
    let log = fs::read_to_string(session.root.join("wpctl.log")).unwrap();
    assert_eq!(
        log.lines().next(),
        Some("set-volume -l 1.0 @DEFAULT_AUDIO_SINK@ 5%+")
    );

    let output = session
        .command(&["audio", "volume", "150%"])
        .env("PATH", &path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));

    let broken = fake_wpctl(&session.root.join("broken"), false);
    let output = session
        .command(&["audio", "status"])
        .env(
            "PATH",
            format!(
                "{}:{}",
                broken.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("Could not connect to PipeWire"),
        "{}",
        stderr(&output)
    );
}
