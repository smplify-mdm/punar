//! `punarctl display brightness` — the display and keyboard backlight
//! (SMP-1405 WP-02).
//!
//! **Through the session's own logind object, and nothing else.** Reading is
//! the world-readable sysfs `brightness`/`max_brightness` pair. Writing is
//! `org.freedesktop.login1.Session.SetBrightness` on
//! `/org/freedesktop/login1/session/auto`, the caller's own session, sent
//! with a closed `busctl` argv. logind checks that the caller owns the
//! session and that the device sits on its seat, so this needs no root, no
//! polkit prompt, no `video` group (WP-01 took that away) and no udev rule
//! loosening the backlight's permissions. A device name reaches that argv
//! only after it matched the sysfs name grammar.
//!
//! The brightness keys run this verb, and a change raises the OSD with the
//! value the device settled on, read back from sysfs, never the value asked
//! for. A machine with no backlight (every VM) says so and exits 6, the code
//! for hardware that is not present; the OSD then shows nothing rather than a
//! simulated row.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use serde_json::json;

use crate::fmt::{self, Row, Slot, Style};

/// Test seam, like `PUNARD_SOCKET`: where sysfs is. It only changes what is
/// READ; a write still names a device logind resolves against the real
/// sysfs, so pointing this elsewhere can move nothing.
const SYSFS_ENV: &str = "PUNAR_SYSFS_ROOT";

/// The display is never driven fully dark by a key: a black panel looks
/// exactly like a machine that died. 1% is Omarchy's floor too. The keyboard
/// backlight may go to zero; that is what "off" means for it.
const DISPLAY_FLOOR_PERCENT: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    Display,
    Keyboard,
}

impl Which {
    fn subsystem(self) -> &'static str {
        match self {
            Which::Display => "backlight",
            Which::Keyboard => "leds",
        }
    }

    fn word(self) -> &'static str {
        match self {
            Which::Display => "display",
            Which::Keyboard => "keyboard",
        }
    }
}

/// What the person asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Get,
    Set(u32),
    Up(u32),
    Down(u32),
}

/// `get`, `set 40%`, `40%`, `+5%`, `-5%`. Percentages only, 0-100.
pub fn parse_change(args: &[String]) -> Option<Change> {
    let percent = |text: &str| -> Option<u32> {
        let digits = text.strip_suffix('%')?;
        if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok().filter(|value| *value <= 100)
    };
    match args {
        [] => Some(Change::Get),
        [only] if only == "get" => Some(Change::Get),
        [verb, value] if verb == "set" => percent(value).map(Change::Set),
        [only] => {
            if let Some(rest) = only.strip_prefix('+') {
                percent(rest).map(Change::Up)
            } else if let Some(rest) = only.strip_prefix('-') {
                percent(rest).map(Change::Down)
            } else {
                percent(only).map(Change::Set)
            }
        }
        _ => None,
    }
}

/// A sysfs device name as logind accepts it: no path separator, no dot
/// segments, nothing a shell would care about (there is no shell anyway).
fn valid_device(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':' | '.'))
}

fn sysfs_root() -> PathBuf {
    std::env::var_os(SYSFS_ENV)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from("/sys"))
}

fn read_number(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// A backlight device and its range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub name: String,
    pub kind: String,
    pub current: u64,
    pub max: u64,
}

impl Device {
    pub fn percent(&self) -> u32 {
        if self.max == 0 {
            return 0;
        }
        ((self.current as f64 / self.max as f64) * 100.0).round() as u32
    }
}

/// The device a key should drive. Display: firmware before platform before
/// raw, the order systemd-backlight and brightnessctl use, because a raw GPU
/// interface next to a firmware one is usually the one that does nothing.
/// Keyboard: the first `*::kbd_backlight` LED.
pub fn find(root: &Path, which: Which) -> Option<Device> {
    let class = root.join("class").join(which.subsystem());
    let mut candidates: Vec<Device> = std::fs::read_dir(&class)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            if !valid_device(&name) {
                return None;
            }
            if which == Which::Keyboard && !name.ends_with("::kbd_backlight") {
                return None;
            }
            let dir = class.join(&name);
            let max = read_number(&dir.join("max_brightness"))?;
            let current = read_number(&dir.join("brightness"))?;
            let kind = std::fs::read_to_string(dir.join("type"))
                .map(|t| t.trim().to_string())
                .unwrap_or_default();
            (max > 0).then_some(Device {
                name,
                kind,
                current,
                max,
            })
        })
        .collect();
    let rank = |kind: &str| match kind {
        "firmware" => 0,
        "platform" => 1,
        "raw" => 2,
        _ => 3,
    };
    candidates.sort_by(|a, b| {
        rank(&a.kind)
            .cmp(&rank(&b.kind))
            .then_with(|| a.name.cmp(&b.name))
    });
    candidates.into_iter().next()
}

/// The raw value a change lands on, clamped to the floor and the maximum.
///
/// A step is taken from the exact raw value the device holds, never from its
/// rounded percentage, and moves at least one raw level. Many firmware
/// backlights have eight to sixteen levels; there, 5% of the range rounds to
/// nothing, and a step computed from the rounded percentage rounds back to
/// the level it started on, so the key did nothing (review finding: at 4 of
/// 7, both +5% and -5% stayed at 4).
pub fn target(device: &Device, which: Which, change: &Change) -> Option<u64> {
    let raw_of = |percent: u32| (device.max * u64::from(percent) + 50) / 100;
    // The display's floor is 1% of its range, and never zero on a coarse
    // device: 1% of a seven-level panel rounds to 0, which is off, not dim.
    let floor = match which {
        Which::Display => raw_of(DISPLAY_FLOOR_PERCENT).max(1),
        Which::Keyboard => 0,
    };
    let step = |percent: u32| raw_of(percent).max(u64::from(percent > 0));
    let raw = match change {
        Change::Get => return None,
        Change::Set(p) => raw_of(*p),
        Change::Up(p) => device.current.saturating_add(step(*p)),
        Change::Down(p) => device.current.saturating_sub(step(*p)),
    };
    Some(raw.clamp(floor, device.max))
}

fn refuse(message: &str, code: u8) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(code)
}

/// logind's SetBrightness for this session: `busctl call … ssu`.
fn set_brightness(which: Which, name: &str, value: u64) -> Result<(), String> {
    let value = value.to_string();
    let output = Command::new("busctl")
        .args([
            "call",
            "org.freedesktop.login1",
            "/org/freedesktop/login1/session/auto",
            "org.freedesktop.login1.Session",
            "SetBrightness",
            "ssu",
            which.subsystem(),
            name,
            &value,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("busctl could not start ({e})"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

/// Raise the OSD with the settled value. Best effort: from a terminal
/// outside the desktop there is no shell to show it, and that is fine.
fn show_osd(which: Which, percent: u32) {
    let _ = Command::new("qs")
        .args([
            "-p",
            "/usr/share/punar/shell",
            "ipc",
            "call",
            "osd",
            "brightness",
            &percent.to_string(),
            which.word(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub fn brightness(args: &[String], keyboard: bool, style: &Style, json_output: bool) -> ExitCode {
    let which = if keyboard {
        Which::Keyboard
    } else {
        Which::Display
    };
    let Some(change) = parse_change(args) else {
        return refuse(
            &format!(
                "{:?} is not a brightness change, so nothing was changed.\n\
                 Next step: give `get`, `set 40%`, `40%`, `+5%` or `-5%` (0-100).",
                args.join(" ")
            ),
            2,
        );
    };
    let root = sysfs_root();
    let Some(device) = find(&root, which) else {
        if json_output && change == Change::Get {
            println!("{}", json!({ "which": which.word(), "device": null }));
            return ExitCode::from(crate::ipc::EXIT_ABSENT);
        }
        return refuse(
            &format!(
                "This machine has no {} backlight Punar can control, so nothing was changed.\n\
                 Why: no device under {}/class/{} reports a brightness range. Virtual \
                 machines and most external monitors have none.\n\
                 Next step: an external monitor's brightness is set on the monitor itself.",
                which.word(),
                root.display(),
                which.subsystem()
            ),
            crate::ipc::EXIT_ABSENT,
        );
    };
    let device = match target(&device, which, &change) {
        None => device,
        Some(value) => {
            if let Err(why) = set_brightness(which, &device.name, value) {
                let denied = why.contains("Access denied")
                    || why.contains("not allowed")
                    || why.contains("Permission denied");
                return refuse(
                    &format!(
                        "The {} brightness was not changed.\nWhy: {}.\nNext step: {}",
                        which.word(),
                        if why.is_empty() {
                            "logind gave no reason"
                        } else {
                            &why
                        },
                        if denied {
                            "logind lets only the person in the active local session change \
                             it; run this from your desktop session."
                        } else {
                            "check `systemctl status systemd-logind`."
                        }
                    ),
                    if denied { crate::ipc::EXIT_DENIED } else { 1 },
                );
            }
            // What the device holds now, not what was asked for.
            find(&root, which).unwrap_or(device)
        }
    };
    let changed = change != Change::Get;
    if changed {
        show_osd(which, device.percent());
    }
    if json_output {
        println!(
            "{}",
            json!({
                "which": which.word(),
                "device": device.name,
                "type": device.kind,
                "brightness": device.current,
                "max_brightness": device.max,
                "percent": device.percent(),
                "changed": changed,
            })
        );
        return ExitCode::SUCCESS;
    }
    let mut out = fmt::masthead(style, "Brightness", which.word());
    out.push_str(&fmt::rows(
        style,
        &[Row::new(
            &device.name,
            &format!("{} %", device.percent()),
            Slot::Neutral,
            &format!("{} of {} · {}", device.current, device.max, device.kind),
        )],
    ));
    print!("{out}");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn changes_are_percentages_within_bounds() {
        assert_eq!(parse_change(&args(&[])), Some(Change::Get));
        assert_eq!(parse_change(&args(&["get"])), Some(Change::Get));
        assert_eq!(parse_change(&args(&["set", "40%"])), Some(Change::Set(40)));
        assert_eq!(parse_change(&args(&["40%"])), Some(Change::Set(40)));
        assert_eq!(parse_change(&args(&["+5%"])), Some(Change::Up(5)));
        assert_eq!(parse_change(&args(&["-10%"])), Some(Change::Down(10)));
        for bad in [
            &["101%"][..],
            &["5"],
            &["+"],
            &["set"],
            &["set", "x%"],
            &["1e2%"],
            &["get", "now"],
        ] {
            assert_eq!(parse_change(&args(bad)), None, "{bad:?}");
        }
    }

    fn device(current: u64, max: u64) -> Device {
        Device {
            name: "intel_backlight".into(),
            kind: "raw".into(),
            current,
            max,
        }
    }

    #[test]
    fn the_display_never_goes_fully_dark_and_never_past_its_maximum() {
        let d = device(960, 19200);
        assert_eq!(d.percent(), 5);
        assert_eq!(target(&d, Which::Display, &Change::Down(20)), Some(192));
        assert_eq!(target(&d, Which::Display, &Change::Set(0)), Some(192));
        assert_eq!(target(&d, Which::Display, &Change::Up(200)), Some(19200));
        assert_eq!(target(&d, Which::Display, &Change::Set(100)), Some(19200));
        assert_eq!(target(&d, Which::Display, &Change::Get), None);
        // A coarse panel still keeps its lowest step lit.
        assert_eq!(
            target(&device(1, 7), Which::Display, &Change::Set(1)),
            Some(1)
        );
        // The keyboard light may go off.
        assert_eq!(
            target(&device(2, 3), Which::Keyboard, &Change::Down(100)),
            Some(0)
        );
    }

    /// Review finding: on a coarse backlight the keys froze, because a step
    /// was computed from the rounded percentage and rounded back.
    #[test]
    fn every_step_moves_a_coarse_backlight_at_least_one_level() {
        // Seven levels at 4: 5% of the range is less than one level.
        let seven = device(4, 7);
        assert_eq!(target(&seven, Which::Display, &Change::Up(5)), Some(5));
        assert_eq!(target(&seven, Which::Display, &Change::Down(5)), Some(3));
        assert_eq!(target(&seven, Which::Display, &Change::Up(1)), Some(5));
        // Ten levels at 6: -5% used to land back on 6.
        let ten = device(6, 10);
        assert_eq!(target(&ten, Which::Display, &Change::Down(5)), Some(5));
        assert_eq!(target(&ten, Which::Display, &Change::Up(5)), Some(7));
        // The ends still hold: never past the top, never below the floor.
        assert_eq!(
            target(&device(7, 7), Which::Display, &Change::Up(5)),
            Some(7)
        );
        assert_eq!(
            target(&device(1, 7), Which::Display, &Change::Down(5)),
            Some(1)
        );
        // A three-level keyboard light walks one level per key.
        assert_eq!(
            target(&device(1, 3), Which::Keyboard, &Change::Up(34)),
            Some(2)
        );
        assert_eq!(
            target(&device(1, 3), Which::Keyboard, &Change::Down(34)),
            Some(0)
        );
        // A fine panel keeps the percentage step it always had.
        assert_eq!(
            target(&device(960, 19200), Which::Display, &Change::Up(5)),
            Some(1920)
        );
    }

    #[test]
    fn device_names_are_sysfs_names_only() {
        assert!(valid_device("intel_backlight"));
        assert!(valid_device("tpacpi::kbd_backlight"));
        assert!(valid_device("amdgpu_bl1"));
        for bad in ["", ".", "..", "../x", "a/b", "a b", "a;b"] {
            assert!(!valid_device(bad), "{bad}");
        }
    }

    #[test]
    fn firmware_beats_raw_and_the_keyboard_needs_its_suffix() {
        let root = std::env::temp_dir().join(format!("punarctl-bl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let make = |class: &str, name: &str, kind: &str, current: u64, max: u64| {
            let dir = root.join("class").join(class).join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("brightness"), format!("{current}\n")).unwrap();
            std::fs::write(dir.join("max_brightness"), format!("{max}\n")).unwrap();
            if !kind.is_empty() {
                std::fs::write(dir.join("type"), format!("{kind}\n")).unwrap();
            }
        };
        assert_eq!(find(&root, Which::Display), None);
        make("backlight", "amdgpu_bl0", "raw", 10, 255);
        make("backlight", "acpi_video0", "firmware", 50, 100);
        make("backlight", "dead", "firmware", 0, 0);
        make("leds", "input3::capslock", "", 0, 1);
        make("leds", "asus::kbd_backlight", "", 1, 3);
        assert_eq!(find(&root, Which::Display).unwrap().name, "acpi_video0");
        let kbd = find(&root, Which::Keyboard).unwrap();
        assert_eq!(
            (kbd.name.as_str(), kbd.percent()),
            ("asus::kbd_backlight", 33)
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
