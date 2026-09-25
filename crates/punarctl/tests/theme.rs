//! `punarctl theme` and `punarctl wallpaper` against a temporary home: the
//! shipped themes installed as user themes, a fake `qs` for the shell, and
//! the pointer file the shell watches.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

static SEQ: AtomicUsize = AtomicUsize::new(0);
const REPO_THEMES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../shell/theme/themes");

struct Home {
    root: PathBuf,
}

impl Home {
    fn new() -> Home {
        let root = std::env::temp_dir().join(format!(
            "punarctl-theme-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&root);
        let themes = root.join("home/.config/punar/themes");
        fs::create_dir_all(&themes).unwrap();
        for id in ["paper", "nocturne", "contrast"] {
            fs::copy(
                Path::new(REPO_THEMES).join(format!("{id}.theme.json")),
                themes.join(format!("{id}.theme.json")),
            )
            .unwrap();
        }
        // A fake shell: logs each call, answers the wallpaper target.
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let qs = bin.join("qs");
        fs::write(
            &qs,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\n\
                 case \"$5 $6\" in\n\
                   'wallpaper list') echo '{list}' ;;\n\
                   'wallpaper set') if [ \"$7\" = zion ]; then echo '{set_ok}'; else echo '{set_no}'; fi ;;\n\
                   'wallpaper state') echo '{state}' ;;\n\
                 esac\n",
                log = root.join("qs.log").display(),
                list = json!({"default": "daybreak", "active": "daybreak", "wallpapers": [
                    {"id": "daybreak", "name": "Daybreak", "intent": "Alpine twilight", "vector": false},
                    {"id": "zion", "name": "Zion", "intent": "Zion Canyon", "vector": true}]}),
                set_ok = json!({"applied": true, "active": "zion", "reason": "active wallpaper is now zion"}),
                set_no = json!({"applied": false, "active": "daybreak", "reason": "wallpaper id is not installed or the preference is not writable"}),
                state = json!({"active": "daybreak", "name": "Daybreak", "source": "shipped default"}),
            ),
        )
        .unwrap();
        fs::set_permissions(&qs, fs::Permissions::from_mode(0o755)).unwrap();
        Home { root }
    }

    fn themes(&self) -> PathBuf {
        self.root.join("home/.config/punar/themes")
    }

    fn pointer(&self) -> PathBuf {
        self.root.join("home/.config/punar/theme.json")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_punarctl"))
            .args(args)
            .env("HOME", self.root.join("home"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.root.join("bin").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("NO_COLOR", "1")
            .output()
            .unwrap()
    }

    fn shell_calls(&self) -> String {
        fs::read_to_string(self.root.join("qs.log")).unwrap_or_default()
    }
}

impl Drop for Home {
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

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(bytes);
    format!(
        "sha256:{}",
        hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// `set` validates, then writes the pointer the shell watches — private, with
/// the complete receipt — and asks the shell to reload it. `status` reads it
/// back and notices a hand edit afterwards.
#[test]
fn theme_set_writes_a_private_pointer_with_a_complete_receipt() {
    let home = Home::new();
    let output = home.run(&["theme", "set", "nocturne"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("THEME · NOCTURNE · PANEL MOOD"),
        "{}",
        stdout(&output)
    );

    let pointer: Value =
        serde_json::from_str(&fs::read_to_string(home.pointer()).unwrap()).unwrap();
    assert_eq!(pointer["kind"], "PunarThemePointer");
    assert_eq!(pointer["active"], "nocturne");
    assert_eq!(pointer["mood"], "default");
    let file = fs::read(home.themes().join("nocturne.theme.json")).unwrap();
    assert_eq!(pointer["validated"]["digest"], sha256(&file));
    assert_eq!(pointer["validated"]["minText"], 4.7);
    assert_eq!(
        fs::metadata(home.pointer()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        home.shell_calls()
            .contains("-p /usr/share/punar/shell ipc call theme reload"),
        "{}",
        home.shell_calls()
    );

    let output = home.run(&["--json", "theme", "status"]);
    let status: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(status["active"], "nocturne");
    assert_eq!(status["source"], "user preference");
    assert_eq!(status["effective_mood"], "panel");
    assert_eq!(status["digest"]["state"], "matches");

    // A hand edit after validation is reported, not revoked.
    let edited = String::from_utf8(file)
        .unwrap()
        .replace("Nocturne", "Nocturne!");
    fs::write(home.themes().join("nocturne.theme.json"), edited).unwrap();
    let output = home.run(&["--json", "theme", "status"]);
    let status: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(status["digest"]["state"], "modified since validated");

    let output = home.run(&["theme", "reset"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!home.pointer().exists());
}

/// A theme that fails the contract is refused with exit 6 — not 3 — naming
/// each failing pair, and nothing is written.
#[test]
fn a_refused_theme_exits_6_and_writes_nothing() {
    let home = Home::new();
    let mut doc: Value =
        serde_json::from_str(&fs::read_to_string(home.themes().join("paper.theme.json")).unwrap())
            .unwrap();
    doc["meta"]["id"] = json!("moss");
    doc["color"]["paper"]["ink3"] = json!("#9A9A9A");
    fs::write(home.themes().join("moss.theme.json"), doc.to_string()).unwrap();

    let output = home.run(&["--json", "theme", "validate", "moss"]);
    assert_eq!(output.status.code(), Some(6), "{}", stderr(&output));
    let result: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(result["pass"], false);
    let r3 = result["failures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["pair"] == "paper · ink3 on raise2")
        .expect("the tightest pair fails first");
    assert_eq!(r3["fg"], "#9A9A9A");
    assert_eq!(r3["floor"], 4.5);

    let output = home.run(&["theme", "set", "moss"]);
    assert_eq!(output.status.code(), Some(6), "{}", stderr(&output));
    let text = stderr(&output);
    assert!(
        text.contains("It was not selected; the active theme is unchanged"),
        "{text}"
    );
    assert!(text.contains("not an organization policy"), "{text}");
    assert!(!home.pointer().exists());

    // A path can be validated too, and an unknown id is not a refusal.
    let path = home.themes().join("moss.theme.json");
    let output = home.run(&["theme", "validate", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(6));
    let output = home.run(&["theme", "set", "nothing-here"]);
    assert_eq!(output.status.code(), Some(1));
}

/// `list` marks the active theme and each theme's state; `show` prints the
/// 24 pairs and the derived terminal.
#[test]
fn theme_list_and_show_measure_every_theme() {
    let home = Home::new();
    let output = home.run(&["--json", "theme", "list"]);
    let list: Value = serde_json::from_str(&stdout(&output)).unwrap();
    let ids: Vec<&str> = list["themes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap())
        .collect();
    for id in ["paper", "nocturne", "contrast"] {
        assert!(ids.contains(&id), "{ids:?}");
    }
    let paper = list["themes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == "paper")
        .unwrap();
    assert_eq!(paper["state"], "ok");
    assert_eq!(paper["active"], true);
    assert_eq!(paper["min_text"], 4.78);

    let output = home.run(&["--json", "theme", "show", "paper"]);
    let shown: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(shown["validation"]["pairs"].as_array().unwrap().len(), 24);
    assert_eq!(shown["ansi"][4], "#9BAECD");
}

/// The §7 derivations, printed for inspection.
#[test]
fn theme_render_prints_the_derived_artefacts() {
    let home = Home::new();
    let foot = stdout(&home.run(&["theme", "render", "paper", "--target", "foot"]));
    assert!(
        foot.contains("[colors-dark]") && foot.contains("regular4=9BAECD"),
        "{foot}"
    );
    assert!(
        foot.contains("bright1=FB9C9C") && foot.contains("cursor=08090A A3E047"),
        "{foot}"
    );
    let hypr = stdout(&home.run(&["theme", "render", "paper", "--target", "hypr"]));
    assert!(
        hypr.contains("misc:background_color = rgb(FAF9F6)"),
        "{hypr}"
    );
    assert!(
        hypr.contains("general:col.active_border = rgb(000000)"),
        "{hypr}"
    );
    let portal = stdout(&home.run(&["theme", "render", "nocturne", "--target", "portal"]));
    assert_eq!(portal, "prefer-dark\n");
    let wallpaper: Value = serde_json::from_str(&stdout(&home.run(&[
        "theme",
        "render",
        "paper",
        "--target",
        "wallpaper",
    ])))
    .unwrap();
    assert_eq!(wallpaper["paper"]["field"], "#FAF9F6");
}

/// Wallpaper choices are the shell's own catalog, asked over its IPC.
#[test]
fn wallpaper_verbs_ask_the_shells_catalog() {
    let home = Home::new();
    let output = home.run(&["wallpaper", "list"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output)
            .lines()
            .any(|l| l.starts_with("DAYBREAK") && l.contains("ACTIVE"))
    );
    assert_eq!(
        home.run(&["wallpaper", "set", "zion"]).status.code(),
        Some(0)
    );
    assert_eq!(
        home.run(&["wallpaper", "set", "nowhere"]).status.code(),
        Some(1)
    );
    assert_eq!(
        home.run(&["wallpaper", "set", "../x"]).status.code(),
        Some(2)
    );
    assert!(home.shell_calls().contains("ipc call wallpaper set zion"));

    let output = Command::new(env!("CARGO_BIN_EXE_punarctl"))
        .args(["wallpaper", "status"])
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5), "{}", stderr(&output));
}
