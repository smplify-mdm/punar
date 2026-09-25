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
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_STATE_HOME")
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
    assert!(
        session
            .requests()
            .contains(&"dispatch hl.dsp.exit()".to_string())
    );

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

/// A fake `qs` that logs its argv and answers like the shell's IPC.
fn fake_qs(dir: &Path) -> PathBuf {
    let bin = dir.join("qsbin");
    fs::create_dir_all(&bin).unwrap();
    let script = bin.join("qs");
    let list = json!({
        "notifications": [
            {"id": "12", "source": "Mail", "summary": "Standup moved to 10:30",
             "detail": "", "urgency": "normal", "sticky": false,
             "arrived_at": "2026-09-24T09:00:00.000Z",
             "actions": [{"key": "open", "label": "Open"}]},
            {"id": "7", "source": "evil\u{1b}[2J", "summary": "hi",
             "detail": "", "urgency": "critical", "sticky": true,
             "arrived_at": null, "actions": []}
        ],
        "dnd": false
    });
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\n\
             case \"$6\" in\n\
               list) printf '%s\\n' '{list}' ;;\n\
               dismissId) [ \"$7\" = 12 ] && echo 12 || echo ;;\n\
               clear) echo 2 ;;\n\
               invoke) if [ \"$7\" = 12 ] && [ \"$8\" = open ]; then echo ok; else echo no-action; fi ;;\n\
               dnd) echo on ;;\n\
             esac\n",
            log = dir.join("qs.log").display(),
            list = list.to_string().replace('\'', "")
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

/// The shell's own notification IPC, called with the installed shell path;
/// sender text is printed through the terminal-safe filter.
#[test]
fn notifications_verbs_call_the_shells_ipc() {
    let session = Session::start(desktop);
    let bin = fake_qs(&session.root);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let run = |args: &[&str]| session.command(args).env("PATH", &path).output().unwrap();

    let output = run(&["notifications", "list"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.lines()
            .any(|l| l.starts_with("12")
                && l.contains("Mail · Standup moved to 10:30 · actions open")),
        "{text}"
    );
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(text.contains("DO NOT DISTURB OFF"), "{text}");

    assert_eq!(
        run(&["notifications", "dismiss", "12"]).status.code(),
        Some(0)
    );
    assert_eq!(
        run(&["notifications", "dismiss", "99"]).status.code(),
        Some(1)
    );
    assert_eq!(
        run(&["notifications", "dismiss", "12;rm"]).status.code(),
        Some(2)
    );
    assert_eq!(
        run(&["notifications", "action", "12", "open"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        run(&["notifications", "action", "12", "nope"])
            .status
            .code(),
        Some(1)
    );
    let output = run(&["--json", "notifications", "dnd", "on"]);
    assert_eq!(
        serde_json::from_str::<Value>(&stdout(&output)).unwrap(),
        json!({"dnd": true})
    );

    let log = fs::read_to_string(session.root.join("qs.log")).unwrap();
    assert!(
        log.lines()
            .all(|l| l.starts_with("-p /usr/share/punar/shell ipc call notifications ")),
        "{log}"
    );
    assert!(
        log.contains("ipc call notifications invoke 12 open"),
        "{log}"
    );

    // No shell: exit 5.
    let output = session
        .command(&["notifications", "list"])
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5), "{}", stderr(&output));
}

// ---------------------------------------------------------------------------
// SMP-1405 WP-02: media, the microphone, brightness, keyboard layout, keys.
// ---------------------------------------------------------------------------

/// A fake `busctl` that plays both roles this crate uses it for: the
/// person's session bus (MPRIS) and logind's SetBrightness. It logs every
/// argv; SetBrightness also writes the value into the fake sysfs, so the
/// verb's read-back sees what "the device" now holds.
fn fake_busctl(dir: &Path, players: &[(&str, &str)]) -> PathBuf {
    let bin = dir.join("busbin");
    fs::create_dir_all(&bin).unwrap();
    let mut names: Vec<String> = vec!["\"org.freedesktop.DBus\"".into(), "\":1.7\"".into()];
    names.extend(players.iter().map(|(name, _)| format!("\"{name}\"")));
    let mut status_cases = String::new();
    for (name, status) in players {
        status_cases.push_str(&format!(
            "    {name}) echo '{{\"type\":\"s\",\"data\":\"{status}\"}}' ;;\n"
        ));
    }
    let script = bin.join("busctl");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\n\
             [ \"$1\" = --user ] && shift && shift\n\
             case \"$1 $5\" in\n\
               'call ListNames') echo '{{\"type\":\"as\",\"data\":[[{names}]]}}' ;;\n\
               *' SetBrightness')\n\
                 printf '%s\\n' \"$9\" > '{sys}/class/'\"$7\"'/'\"$8\"'/brightness' ;;\n\
               'get-property PlaybackStatus')\n\
                 case \"$2\" in\n{status_cases}    esac ;;\n\
               'get-property Metadata') echo '{{\"type\":\"a{{sv}}\",\"data\":{{\"xesam:title\":{{\"type\":\"s\",\"data\":\"Song\\u001b[2J\"}},\"xesam:artist\":{{\"type\":\"as\",\"data\":[\"Band\"]}}}}}}' ;;\n\
               'get-property Identity') echo '{{\"type\":\"s\",\"data\":\"Player\"}}' ;;\n\
             esac\n",
            log = dir.join("busctl.log").display(),
            sys = dir.join("sys").display(),
            names = names.join(","),
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

fn with_path(bins: &[&PathBuf]) -> String {
    let mut parts: Vec<String> = bins.iter().map(|b| b.display().to_string()).collect();
    parts.push(std::env::var("PATH").unwrap_or_default());
    parts.join(":")
}

/// The media keys reach the player that is playing, by its bus name, and
/// the title a player sends is printed through the terminal-safe filter.
#[test]
fn media_keys_reach_the_playing_player_over_mpris() {
    let session = Session::start(desktop);
    let bin = fake_busctl(
        &session.root,
        &[
            ("org.mpris.MediaPlayer2.mpv", "Paused"),
            ("org.mpris.MediaPlayer2.chromium.instance42", "Playing"),
        ],
    );
    let path = with_path(&[&bin]);
    let output = session
        .command(&["media", "play-pause"])
        .env("PATH", &path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!stdout(&output).contains('\u{1b}'), "{:?}", stdout(&output));
    let log = fs::read_to_string(session.root.join("busctl.log")).unwrap();
    assert!(
        log.lines().any(|l| l
            == "--user --json=short call org.mpris.MediaPlayer2.chromium.instance42 \
                /org/mpris/MediaPlayer2 org.mpris.MediaPlayer2.Player PlayPause"),
        "{log}"
    );
    assert!(
        log.lines().all(|l| l.starts_with("--user --json=short ")),
        "{log}"
    );

    let output = session
        .command(&["--json", "media", "status"])
        .env("PATH", &path)
        .output()
        .unwrap();
    let state: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(state["player"]["status"], "Playing");
    assert_eq!(state["player"]["artist"], "Band");
    assert_eq!(state["players"].as_array().unwrap().len(), 2);

    // Nothing playing anywhere: exit 6, the "not present" code.
    let empty = fake_busctl(&session.root.join("empty"), &[]);
    let output = session
        .command(&["media", "next"])
        .env("PATH", with_path(&[&empty]))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(6), "{}", stderr(&output));
    assert!(stderr(&output).contains("No media player is running"));
}

/// The microphone key mutes the default source, never the output.
#[test]
fn mic_mute_targets_the_default_input() {
    let session = Session::start(desktop);
    let bin = fake_wpctl(&session.root, true);
    let output = session
        .command(&["audio", "mute", "--input"])
        .env("PATH", with_path(&[&bin]))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let log = fs::read_to_string(session.root.join("wpctl.log")).unwrap();
    assert_eq!(
        log.lines().next(),
        Some("set-mute @DEFAULT_AUDIO_SOURCE@ toggle")
    );
}

fn fake_backlight(root: &Path, class: &str, name: &str, current: u64, max: u64) {
    let dir = root.join("sys/class").join(class).join(name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("brightness"), format!("{current}\n")).unwrap();
    fs::write(dir.join("max_brightness"), format!("{max}\n")).unwrap();
    fs::write(dir.join("type"), "raw\n").unwrap();
}

/// Brightness is logind's SetBrightness on this session's own object, with
/// a closed argv; the answer is what sysfs holds afterwards, and the OSD is
/// raised with that value.
#[test]
fn brightness_goes_through_the_sessions_own_logind_object() {
    let session = Session::start(desktop);
    fake_backlight(&session.root, "backlight", "intel_backlight", 9600, 19200);
    fake_backlight(&session.root, "leds", "tpacpi::kbd_backlight", 1, 2);
    let bus = fake_busctl(&session.root, &[]);
    let qs = fake_qs(&session.root);
    let path = with_path(&[&bus, &qs]);
    let run = |args: &[&str]| {
        session
            .command(args)
            .env("PATH", &path)
            .env("PUNAR_SYSFS_ROOT", session.root.join("sys"))
            .output()
            .unwrap()
    };

    let output = run(&["--json", "display", "brightness", "+10%"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let state: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(state["percent"], 60);
    assert_eq!(state["brightness"], 11520);
    let log = fs::read_to_string(session.root.join("busctl.log")).unwrap();
    assert_eq!(
        log.lines().last(),
        Some(
            "call org.freedesktop.login1 /org/freedesktop/login1/session/auto \
             org.freedesktop.login1.Session SetBrightness ssu backlight intel_backlight 11520"
        )
    );
    let osd = fs::read_to_string(session.root.join("qs.log")).unwrap();
    assert_eq!(
        osd.lines().last(),
        Some("-p /usr/share/punar/shell ipc call osd brightness 60 display")
    );

    // A key never drives the panel dark: -100% lands on the 1% floor.
    let output = run(&["--json", "display", "brightness", "-100%"]);
    let state: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(state["brightness"], 192);

    let output = run(&["--json", "display", "brightness", "--keyboard", "0%"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let log = fs::read_to_string(session.root.join("busctl.log")).unwrap();
    assert!(
        log.lines()
            .last()
            .unwrap()
            .ends_with("SetBrightness ssu leds tpacpi::kbd_backlight 0"),
        "{log}"
    );

    // Reading moves nothing.
    let before = log.lines().count();
    let output = run(&["--json", "display", "brightness"]);
    assert_eq!(output.status.code(), Some(0));
    let after = fs::read_to_string(session.root.join("busctl.log")).unwrap();
    assert_eq!(after.lines().count(), before);

    assert_eq!(
        run(&["display", "brightness", "150%"]).status.code(),
        Some(2)
    );
    assert_eq!(run(&["display", "brightness", "up"]).status.code(), Some(2));
}

/// A virtual machine has no backlight: the verb says so and exits 6.
#[test]
fn without_a_backlight_brightness_exits_six_and_says_why() {
    let session = Session::start(desktop);
    fs::create_dir_all(session.root.join("sys/class/backlight")).unwrap();
    let bus = fake_busctl(&session.root, &[]);
    let output = session
        .command(&["display", "brightness", "+5%"])
        .env("PATH", with_path(&[&bus]))
        .env("PUNAR_SYSFS_ROOT", session.root.join("sys"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(6), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no display backlight"),
        "{}",
        stderr(&output)
    );
    assert!(
        !session.root.join("busctl.log").exists(),
        "nothing was sent"
    );
}

const XKB_FIXTURE: &str = "! layout\n  us  English (US)\n  de  German\n  ru  Russian\n\
                           ! variant\n  nodeadkeys  de: German (no dead keys)\n  phonetic  ru: Russian (phonetic)\n";

/// A fake punard answering `capabilities.set` (and logging the request),
/// with `deny` choosing a refusal instead.
fn fake_punard(dir: &Path, deny: bool) -> PathBuf {
    use std::io::{BufRead, BufReader};
    fs::create_dir_all(dir).unwrap();
    let socket = dir.join("punard.sock");
    let log = dir.join("punard.log");
    let listener = UnixListener::bind(&socket).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let request: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .unwrap();
            writeln!(file, "{request}").unwrap();
            let answer = if deny {
                json!({"v": 1, "id": request["id"], "error": {"code": "denied",
                    "message": "Setting system.keymap requires an administrator.",
                    "details": {"capability": "system.keymap"}}})
            } else {
                json!({"v": 1, "id": request["id"], "result": {"changed": true, "descriptor": {
                    "capability": "system.keymap",
                    "current_state": request["params"]["desired_state"]}}})
            };
            let mut stream = stream;
            let _ = writeln!(stream, "{answer}");
        }
    });
    socket
}

fn fake_hyprctl(dir: &Path) -> PathBuf {
    let bin = dir.join("hyprbin");
    fs::create_dir_all(&bin).unwrap();
    let script = bin.join("hyprctl");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\necho ok\n",
            dir.join("hyprctl.log").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

fn keyboard_env(session: &Session) -> (PathBuf, PathBuf) {
    let xkb = session.root.join("evdev.lst");
    fs::write(&xkb, XKB_FIXTURE).unwrap();
    let vconsole = session.root.join("vconsole.conf");
    (xkb, vconsole)
}

/// The person sets their layout: punard is asked (the capability, the
/// canonical value), the session file is rewritten as data with the Latin
/// lead and the switch chord, and the live compositor gets the same three
/// values, each quoted as a Lua string.
#[test]
fn keyboard_layout_set_asks_punard_renders_and_applies_live() {
    let session = Session::start(desktop);
    let (xkb, vconsole) = keyboard_env(&session);
    let punard = fake_punard(&session.root, false);
    let hypr = fake_hyprctl(&session.root);
    let run = |args: &[&str]| {
        session
            .command(args)
            .env("PATH", with_path(&[&hypr]))
            .env("PUNARD_SOCKET", &punard)
            .env("PUNAR_XKB_LIST", &xkb)
            .env("PUNAR_VCONSOLE_CONF", &vconsole)
            .output()
            .unwrap()
    };
    let output = run(&["--json", "keyboard", "layout", "set", "ru"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let result: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(result["device"], "ru");
    assert_eq!(result["session"]["kb_layout"], "us,ru");
    assert_eq!(result["session"]["kb_options"], "grp:alts_toggle");
    assert_eq!(result["session_applied"], true);

    let request: Value = serde_json::from_str(
        fs::read_to_string(session.root.join("punard.log"))
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(request["method"], "capabilities.set");
    assert_eq!(
        request["params"],
        json!({"capability": "system.keymap", "desired_state": "ru"})
    );
    let file = fs::read_to_string(session.root.join("run/punar/session/input.lua")).unwrap();
    assert!(file.contains("kb_layout = \"us,ru\","), "{file}");
    assert!(file.contains("DATA ONLY"), "{file}");
    let hyprctl = fs::read_to_string(session.root.join("hyprctl.log")).unwrap();
    assert_eq!(
        hyprctl.lines().last(),
        Some(
            "eval hl.config({ input = { kb_layout = 'us,ru', kb_variant = '', \
             kb_options = 'grp:alts_toggle' } })"
        )
    );

    // Not installed, or not a layout at all: refused before punard is asked.
    let asked = fs::read_to_string(session.root.join("punard.log")).unwrap();
    for bad in ["fr", "us+nodeadkeys", "us'); os.execute('x", "us,de,ru,us"] {
        let output = run(&["keyboard", "layout", "set", bad]);
        assert_eq!(output.status.code(), Some(2), "{bad}: {}", stderr(&output));
    }
    assert_eq!(
        fs::read_to_string(session.root.join("punard.log")).unwrap(),
        asked
    );
}

/// A refusal from punard is the answer: exit 3, nothing rendered.
#[test]
fn keyboard_layout_set_refused_by_punard_changes_nothing() {
    let session = Session::start(desktop);
    let (xkb, vconsole) = keyboard_env(&session);
    let punard = fake_punard(&session.root, true);
    let hypr = fake_hyprctl(&session.root);
    let output = session
        .command(&["keyboard", "layout", "set", "de"])
        .env("PATH", with_path(&[&hypr]))
        .env("PUNARD_SOCKET", &punard)
        .env("PUNAR_XKB_LIST", &xkb)
        .env("PUNAR_VCONSOLE_CONF", &vconsole)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(!session.root.join("run/punar/session/input.lua").exists());
    assert!(!session.root.join("hyprctl.log").exists());
}

/// Session start: the device's layout from vconsole; the greeter's choice
/// adopted through punard when it is given; used for this session alone when
/// punard will not take it.
#[test]
fn keyboard_layout_render_adopts_the_login_screens_choice() {
    let session = Session::start(desktop);
    let (xkb, vconsole) = keyboard_env(&session);
    fs::write(&vconsole, "XKBLAYOUT=de\nXKBVARIANT=nodeadkeys\n").unwrap();
    let render = |punard: &Path, adopt: Option<&str>| {
        let mut args = vec!["--json", "keyboard", "layout", "render"];
        if let Some(adopt) = adopt {
            args.extend(["--adopt", adopt]);
        }
        session
            .command(&args)
            .env("PUNARD_SOCKET", punard)
            .env("PUNAR_XKB_LIST", &xkb)
            .env("PUNAR_VCONSOLE_CONF", &vconsole)
            .env_remove("HYPRLAND_INSTANCE_SIGNATURE")
            .output()
            .unwrap()
    };
    let nowhere = session.root.join("no-punard.sock");
    let output = render(&nowhere, None);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let result: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(result["kb_layout"], "de");
    assert_eq!(result["kb_variant"], "nodeadkeys");
    assert_eq!(result["adopted"], false);

    let accepting = fake_punard(&session.root.join("ok"), false);
    let output = render(&accepting, Some("ru"));
    let result: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(
        (result["kb_layout"].as_str(), result["adopted"].as_bool()),
        (Some("us,ru"), Some(true))
    );

    // punard unreachable: this session still types what was chosen.
    let output = render(&nowhere, Some("ru"));
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let result: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(
        (result["kb_layout"].as_str(), result["adopted"].as_bool()),
        (Some("us,ru"), Some(false))
    );
    assert!(
        stderr(&output).contains("the device keeps de+nodeadkeys"),
        "{}",
        stderr(&output)
    );

    // A value nobody installed is never adopted or rendered.
    let output = render(&accepting, Some("xx"));
    let result: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(result["kb_layout"], "de");
}

fn keyboards(request: &str) -> String {
    match request {
        "j/devices" => json!({"keyboards": [
            {"name": "virtual-keyboard", "main": false, "layout": "us", "active_keymap": "English (US)"},
            {"name": "at-translated-set-2-keyboard", "main": true, "layout": "us,ru",
             "variant": ",", "options": "grp:alts_toggle", "active_keymap": "Russian"}
        ]})
        .to_string(),
        "j/binds" => json!([
            {"modmask": 64, "key": "Return", "description": "Open terminal", "submap": ""},
            {"modmask": 64, "key": "Q", "description": "Close window", "submap": ""},
            {"modmask": 0, "key": "H", "description": "Resize narrower", "submap": "resize"},
            {"modmask": 64, "key": "mouse:272", "description": "", "submap": ""}
        ])
        .to_string(),
        other => desktop(other),
    }
}

#[test]
fn keyboard_layout_status_reports_the_device_the_session_and_what_is_typing() {
    let session = Session::start(keyboards);
    let (xkb, vconsole) = keyboard_env(&session);
    fs::write(&vconsole, "XKBLAYOUT=ru\n").unwrap();
    let output = session
        .command(&["--json", "keyboard", "layout"])
        .env("PUNAR_XKB_LIST", &xkb)
        .env("PUNAR_VCONSOLE_CONF", &vconsole)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let status: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(status["device"], "ru");
    assert_eq!(status["layouts"][0]["description"], "Russian");
    assert_eq!(status["layouts"][0]["latin"], false);
    assert_eq!(status["live"]["active_keymap"], "Russian");
    assert_eq!(status["switch_chord"], "both Alt keys together");

    let output = session
        .command(&["--json", "keyboard", "layout", "list", "de"])
        .env("PUNAR_XKB_LIST", &xkb)
        .output()
        .unwrap();
    let list: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(
        list["layouts"],
        json!([{"name": "de+nodeadkeys", "description": "German (no dead keys)"}])
    );
}

/// `keys list` is the compositor's own table: the one PUNAR+/ renders.
#[test]
fn keys_list_is_the_compositors_bind_table() {
    let session = Session::start(keyboards);
    let output = session.run(&["--json", "keys", "list", "--filter", "TERMINAL"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let binds: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(binds.as_array().unwrap().len(), 1);
    assert_eq!(binds[0]["key"], "Return");
    let output = session.run(&["keys", "list"]);
    let text = stdout(&output);
    assert!(
        text.contains("PUNAR + RETURN") || text.contains("Punar + Return"),
        "{text}"
    );
    assert!(text.contains("in resize mode"), "{text}");
    assert!(
        !text.to_lowercase().contains("mouse:272"),
        "undescribed binds stay out: {text}"
    );
}

/// A per-workspace preset needs a workspace, and names only real ones; the
/// status reads the script's store, validated.
#[test]
fn layout_per_workspace_refusals_and_status() {
    let session = Session::start(desktop);
    assert_eq!(session.run(&["layout", "default"]).status.code(), Some(2));
    assert_eq!(
        session
            .run(&["layout", "columns", "--workspace", "0"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        session
            .run(&["layout", "columns", "--workspace", "special:x"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        session
            .run(&["layout", "restore", "--workspace", "3"])
            .status
            .code(),
        Some(2)
    );
    fs::create_dir_all(session.root.join("home/.local/state/punar")).unwrap();
    fs::write(
        session
            .root
            .join("home/.local/state/punar/workspace-layouts.json"),
        r#"{"version":1,"workspaces":{"3":"columns","4":"evil","x":"stack","0":"rows"}}"#,
    )
    .unwrap();
    let output = session.run(&["--json", "layout", "status"]);
    let status: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(status["workspaces"], json!({"3": "columns"}));
    assert_eq!(
        status["active"],
        json!({"id": 3, "preset": "columns", "own": true})
    );
}

/// The Mac-style grammar is the person's preference file, and the compositor
/// re-reads its binds.
#[test]
fn clipboard_keys_write_the_preference_and_reload_the_binds() {
    let session = Session::start(desktop);
    let hypr = fake_hyprctl(&session.root);
    let run = |args: &[&str]| {
        session
            .command(args)
            .env("PATH", with_path(&[&hypr]))
            .env_remove("XDG_CONFIG_HOME")
            .output()
            .unwrap()
    };
    let output = run(&["--json", "keyboard", "clipboard-keys"]);
    assert_eq!(
        serde_json::from_str::<Value>(&stdout(&output)).unwrap()["clipboard_keys"],
        "standard"
    );
    let output = run(&["--json", "keyboard", "clipboard-keys", "on"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let result: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(result, json!({"clipboard_keys": "mac", "reloaded": true}));
    let saved: Value = serde_json::from_str(
        &fs::read_to_string(session.root.join("home/.config/punar/keyboard.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(saved, json!({"version": 1, "clipboardKeys": "mac"}));
    assert_eq!(
        fs::read_to_string(session.root.join("hyprctl.log")).unwrap(),
        "reload\n"
    );
    run(&["keyboard", "clipboard-keys", "off"]);
    let saved: Value = serde_json::from_str(
        &fs::read_to_string(session.root.join("home/.config/punar/keyboard.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(saved["clipboardKeys"], "standard");
}
