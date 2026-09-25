#!/usr/bin/env bash
# The key grammar's contract (SMP-1405 WP-02):
#
#   1. every bind has a description — the shortcut help renders only what is
#      described, so an undescribed chord is one nobody can find;
#   2. no chord is bound twice in one mode — Hyprland fires both binds when
#      two share a chord, which is how PUNAR+SHIFT+L once meant three things;
#   3. every Omarchy key (Appendix B of the Punar-vs-Omarchy plan, K1-K193)
#      is either bound in Punar, named by the live description that binds
#      it, or unbound with a stated reason, ONE KEY AT A TIME, so parity is a
#      table a reviewer can read rather than a claim;
#   4. every chord works under every keyboard layout: a key is a letter, a
#      named key every layout spells the same (Return, Tab, F1, arrows, the
#      media keys), or a key CODE; a digit is never a keysym (the number row
#      types & é " … on AZERTY); and a punctuation keysym (/, [, ], comma,
#      period) is allowed only with a twin chord for the same action on a
#      layout-safe key, or a stated reason, because German, French, Spanish
#      and Italian keyboards put those symbols behind Shift or AltGr, where
#      Hyprland's first-layout, unshifted match never sees them;
#   5. the login screen's list of layouts that cannot type Latin letters is
#      punar_common::keymap's, so both lead such a layout with US English.
#
# HOW IT READS THE BINDS. It runs the real hyprland.lua, which requires the
# real punar-binds.lua, under a Lua interpreter with a recording stand-in for
# Hyprland's `hl` table, once with the standard clipboard grammar and once
# with the Mac-style one. Loops, the tenth workspace and the conditional
# clipboard binds are therefore counted exactly as the compositor would
# register them. tools/hyprland-verify.sh separately runs the same files
# through the real Hyprland to prove every call is one it accepts.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LUA="$(command -v lua5.4 || command -v lua5.3 || command -v lua || true)"
if [ -z "${LUA}" ]; then
    echo "keybind-contract-test: FAIL: no Lua interpreter (install lua5.4); the test did NOT run" >&2
    exit 1
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/punar-keybinds.XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT INT TERM

cat > "${TMP}/harness.lua" <<'LUA'
local root = arg[1]
local records = {}
local submap = ""

-- Any hl.dsp.<path>(...) builds an opaque dispatcher.
local function recorder(path)
    return setmetatable({}, {
        __index = function(_, key)
            return recorder(path .. "." .. key)
        end,
        __call = function()
            return { dispatcher = path }
        end,
    })
end

-- Every other hl.* call (config, curves, rules, hooks) is accepted and ignored.
hl = setmetatable({}, {
    __index = function()
        return function() end
    end,
})
hl.dsp = recorder("hl.dsp")
hl.bind = function(keys, dispatcher, opts)
    opts = opts or {}
    table.insert(records, {
        submap,
        keys,
        opts.description or "",
        (opts.release and "release" or "") .. (opts.mouse and "mouse" or ""),
    })
    return {}
end
hl.define_submap = function(name, fn)
    local previous = submap
    submap = name
    fn()
    submap = previous
end
-- The configuration requires its modules by their absolute image path.
local real_require = require
require = function(path)
    local file = path:match("^/etc/xdg/hypr/(.+)$")
    if not file then
        return real_require(path)
    end
    local chunk = loadfile(root .. "/os/modules/desktop/hypr/" .. file)
    if not chunk then
        -- punar-session-profile.lua is written at image build time; the
        -- product copy is empty.
        assert(file == "punar-session-profile.lua", "missing module " .. file)
        return nil
    end
    return chunk()
end

local main = assert(loadfile(root .. "/os/modules/desktop/hypr/hyprland.lua"))
main()
for _, r in ipairs(records) do
    io.write(r[1], "\t", r[2], "\t", r[3], "\t", r[4], "\n")
end
LUA

mkdir -p "${TMP}/standard/.config/punar" "${TMP}/mac/.config/punar"
printf '%s\n' '{"version": 1, "clipboardKeys": "mac"}' > "${TMP}/mac/.config/punar/keyboard.json"
for mode in standard mac; do
    env -i PATH="${PATH}" HOME="${TMP}/${mode}" XDG_RUNTIME_DIR="${TMP}/runtime" \
        "${LUA}" "${TMP}/harness.lua" "${REPO_ROOT}" > "${TMP}/binds-${mode}.tsv"
done

python3 - "${TMP}" "${REPO_ROOT}" <<'PY'
import pathlib
import re
import sys

tmp = pathlib.Path(sys.argv[1])
problems = []


def load(mode):
    rows = []
    for line in (tmp / f"binds-{mode}.tsv").read_text().splitlines():
        submap, keys, description, flags = (line.split("\t") + ["", "", "", ""])[:4]
        rows.append({"submap": submap, "keys": keys, "description": description, "flags": flags})
    return rows


def chord(keys):
    parts = [p.strip() for p in keys.split("+") if p.strip()]
    if not parts:
        return ("", frozenset())
    key = parts[-1].lower()
    mods = frozenset(p.upper() for p in parts[:-1])
    return (key, mods)


modes = {mode: load(mode) for mode in ("standard", "mac")}
for mode, rows in modes.items():
    if len(rows) < 60:
        problems.append(f"{mode}: only {len(rows)} binds were recorded; the harness did not see the grammar")
    seen = {}
    for row in rows:
        if row["description"].strip() == "":
            problems.append(f"{mode}: {row['keys']!r} has no description")
        key = (row["submap"], chord(row["keys"]), "release" in row["flags"])
        if key in seen:
            problems.append(
                f"{mode}: {row['keys']!r} is bound twice: {seen[key]!r} and {row['description']!r}"
            )
        seen[key] = row["description"]

standard = {r["description"] for r in modes["standard"]}
mac = {r["description"] for r in modes["mac"]}


def present(prefix, where):
    return any(d.startswith(prefix) for d in where)


# The Mac-style grammar adds copy, paste and cut and MOVES the two floating
# binds rather than dropping them.
for prefix in ("Copy", "Paste", "Cut"):
    if present(prefix, standard):
        problems.append(f"standard grammar binds {prefix!r}; it belongs to the Mac-style keys only")
    if not present(prefix, mac):
        problems.append(f"Mac-style grammar has no {prefix!r}")
for description in ("Toggle floating", "Center floating window"):
    keys = {r["keys"] for r in modes["mac"] if r["description"] == description}
    if not keys or not all("ALT" in k for k in keys):
        problems.append(f"Mac-style grammar did not move {description!r} to PUNAR+ALT: {keys}")

# The number row is bound by key code, 1..9 then 0 (code:10..code:19), in all
# three workspace families: the tenth workspace is on the 0 key.
for family in ("Workspace ", "Move window to workspace ", "Move window quietly to workspace "):
    for number in range(1, 11):
        keys = [r["keys"] for r in modes["standard"] if r["description"] == f"{family}{number}"]
        want = f"code:{number + 9}"
        if not keys or not keys[0].replace(" ", "").endswith("+" + want):
            problems.append(f"{family}{number} is not on the number-row key {want}: {keys}")

# ---------------------------------------------------------------------------
# Rule 4: every chord works under every keyboard layout.
# ---------------------------------------------------------------------------
LAYOUT_SAFE = {
    "return", "space", "tab", "escape", "backspace", "delete", "insert", "home",
    "end", "left", "right", "up", "down", "print", "alt_l", "alt_r",
    "mouse_up", "mouse_down", "mouse:272", "mouse:273",
} | {f"f{n}" for n in range(1, 13)}


def layout_safe(key):
    return (
        (len(key) == 1 and key.isalpha())
        or key in LAYOUT_SAFE
        or key.startswith("xf86")
        or re.fullmatch(r"code:\d{1,3}", key) is not None
    )


# A punctuation keysym, the action it does, and either the twin chord's
# description prefix (which must be live on a layout-safe key) or a reason.
PUNCTUATION = {
    "slash": ("Shortcut help", "twin", "Shortcut help (any layout)"),
    "bracketleft": ("Previous window in group", "twin", "Previous window in group (any layout)"),
    "bracketright": ("Next window in group", "twin", "Next window in group (any layout)"),
    "comma": ("Previous layout preset", "reason",
              "comma is unshifted on every Latin layout the login screen offers, "
              "the previous-preset key alone cycles through all five presets, and "
              "the command center sets any preset by name on every layout"),
    "period": ("Next layout preset", "reason",
               "period is Shift+; on AZERTY only; there PUNAR+comma cycles every "
               "preset and the command center sets any preset by name"),
}
for mode, rows in modes.items():
    for row in rows:
        key, _ = chord(row["keys"])
        if layout_safe(key):
            continue
        if key.isdigit():
            problems.append(
                f"{mode}: {row['keys']!r} binds a digit keysym; bind the number row "
                f"by code (code:10 is the 1 key) so it fires under AZERTY"
            )
            continue
        entry = PUNCTUATION.get(key)
        if entry is None:
            problems.append(
                f"{mode}: {row['keys']!r} ({row['description']!r}) uses a keysym some "
                f"layouts put behind Shift or AltGr; give it a layout-safe twin or a reason"
            )
            continue
        action, kind, detail = entry
        if not row["description"].startswith(action):
            problems.append(f"{mode}: {row['keys']!r} is listed for {action!r} but binds {row['description']!r}")
        if kind == "twin":
            twins = [
                r for r in rows
                if r["description"].startswith(detail) and layout_safe(chord(r["keys"])[0])
            ]
            if not twins:
                problems.append(f"{mode}: {row['keys']!r} has no layout-safe twin described {detail!r}")
        elif len(detail) < 30:
            problems.append(f"{mode}: {row['keys']!r} needs a real reason to stay layout-bound")

# Pointer move and resize are mouse binds (the back-out's missing piece).
for description in ("Move window with the pointer", "Resize window with the pointer"):
    flags = [r["flags"] for r in modes["standard"] if r["description"] == description]
    if not flags or "mouse" not in flags[0]:
        problems.append(f"{description!r} is not registered with mouse = true")

# ---------------------------------------------------------------------------
# Rule 5: the login screen and punar_common::keymap agree on which layouts
# cannot type Latin letters (and so get a US first group). The greeter keeps
# its own copy because it runs before any session exists; a layout missing
# from it would load alone at the login screen and leave a Latin password
# untypeable there.
# ---------------------------------------------------------------------------
root_dir = pathlib.Path(sys.argv[2])
rust = (root_dir / "crates/punar-common/src/keymap.rs").read_text()
greeter = (root_dir / "shell/punar-shell/Greeter/shell.qml").read_text()
rust_list = re.search(r"pub const NON_LATIN: &\[&str\] = &\[(.*?)\];", rust, re.S)
qml_list = re.search(r"readonly property var nonLatin: \[(.*?)\]", greeter, re.S)
if rust_list is None or qml_list is None:
    problems.append("could not find NON_LATIN in keymap.rs or nonLatin in Greeter/shell.qml")
else:
    rust_codes = re.findall(r'"([a-z]+)"', rust_list.group(1))
    qml_codes = re.findall(r'"([a-z]+)"', qml_list.group(1))
    if len(rust_codes) < 30 or sorted(rust_codes) != sorted(qml_codes):
        problems.append(
            f"the greeter's non-Latin layouts differ from punar_common::keymap's: "
            f"only in Rust {sorted(set(rust_codes) - set(qml_codes))}, "
            f"only in the greeter {sorted(set(qml_codes) - set(rust_codes))}"
        )

# ---------------------------------------------------------------------------
# Appendix B, one Omarchy key at a time. BOUND names the live description
# that does the same thing in Punar (a prefix; `mac:` for the Mac-style
# grammar); UNBOUND says why Punar has no chord for it. Every one of K1-K193
# must be in exactly one of the two.
# ---------------------------------------------------------------------------
WP03 = "arrives with WP-03's bar and palette, which gives each panel its own chord"
WP04 = "the capture suite and clipboard history are WP-04"
WP07 = "idle, lid and power keys are WP-07 (suspend that fails closed, power and lid)"
WP11 = ("a dwindle nicety left to WP-11's override format, where a person binds "
        "their own keys as data that cannot run commands")
APPS = ("third-party app and web-app chords: apps open from the command center "
        "(PUNAR+Space), and a person binds their own with WP-11's override format")
BOUND = {
    1: "Close window",
    3: "Toggle split direction", 5: "Toggle floating", 6: "Toggle fullscreen",
    8: "Toggle maximize", 9: "Pop window out", 12: "Next layout preset",
    13: "Focus left", 14: "Focus right", 15: "Focus up", 16: "Focus down",
    17: "Toggle scratchpad terminal",
    19: "Next workspace", 20: "Previous workspace",
    22: "Move workspace to left monitor", 23: "Move workspace to right monitor",
    24: "Move workspace to upper monitor", 25: "Move workspace to lower monitor",
    26: "Swap window left", 27: "Swap window right", 28: "Swap window up", 29: "Swap window down",
    30: "Switch windows", 31: "Switch windows backwards", 32: "Switch windows",
    33: "Switch windows backwards", 34: "Focus next monitor", 35: "Focus previous monitor",
    36: "Resize narrower", 37: "Resize wider", 38: "Resize shorter", 39: "Resize taller",
    48: "Scroll to the next workspace", 49: "Scroll to the previous workspace",
    50: "Move window with the pointer", 51: "Resize window with the pointer",
    52: "Toggle window group", 53: "Move window out of group",
    54: "Move window into group left", 55: "Move window into group right",
    56: "Move window into group above", 57: "Move window into group below",
    58: "Next window in group (any layout)", 59: "Previous window in group (any layout)",
    60: "Previous window in group", 61: "Next window in group",
    66: "Open command center", 67: "Open command center", 71: "System control",
    73: "Session menu", 75: "Shortcut help",
    83: "Toggle window transparency", 84: "Toggle window gaps",
    85: "Toggle square shape for a lone window",
    90: "Notification centre", 97: "Screenshot output to clipboard",
    111: "AI on this device", 121: "Lock session",
    122: "Open terminal", 123: "Open browser", 124: "Open files", 126: "Open browser",
    150: "mac:Copy", 151: "mac:Paste", 152: "mac:Cut",
    154: "Volume up", 155: "Volume down", 156: "Toggle mute", 157: "Toggle microphone mute",
    158: "Brightness up", 159: "Brightness down",
    160: "Brightness to full", 161: "Brightness to lowest",
    162: "Keyboard light up", 163: "Keyboard light down",
    168: "Volume up a little", 169: "Volume down a little",
    170: "Brightness up a little", 171: "Brightness down a little",
    172: "Next track", 173: "Next track (Alt + Play)", 174: "Play or pause (pause key)",
    175: "Play or pause", 176: "Previous track", 177: "Previous track (Alt + Shift + Play)",
    185: "Workspace 1", 186: "Move window to workspace 1", 187: "Move window quietly to workspace 1",
}
UNBOUND = {
    2: "close-all (Ctrl+Alt+Delete): one chord that discards unsaved work in every "
       "application is a hazard; End session and the session menu close apps properly",
    4: "pseudo-tiling is " + WP11,
    7: "tiled fullscreen is " + WP11,
    10: "saving a window's width is " + WP11,
    11: "restoring a window's width is " + WP11,
    18: "Punar's scratchpads are purpose-built (terminal, assistant, notes); a general "
        "move-to-stash chord arrives with WP-11's override format",
    21: "going back to the former workspace: Alt+Tab's quick tap returns to the last "
        "window, wherever it is, and PUNAR+CTRL+Tab is next workspace in Punar's grammar",
    40: "fine resize steps: resize mode (PUNAR+R) repeats one step while held",
    41: "fine resize steps: resize mode (PUNAR+R) repeats one step while held",
    42: "fine resize steps: resize mode (PUNAR+R) repeats one step while held",
    43: "fine resize steps: resize mode (PUNAR+R) repeats one step while held",
    44: "coarse resize steps: resize mode (PUNAR+R) repeats one step while held",
    45: "coarse resize steps: resize mode (PUNAR+R) repeats one step while held",
    46: "coarse resize steps: resize mode (PUNAR+R) repeats one step while held",
    47: "coarse resize steps: resize mode (PUNAR+R) repeats one step while held",
    62: "walking a group with the wheel: Punar's wheel walks workspaces, and the group "
        "is walked with PUNAR+[ ] or PUNAR+ALT+Tab",
    63: "walking a group with the wheel: Punar's wheel walks workspaces, and the group "
        "is walked with PUNAR+[ ] or PUNAR+ALT+Tab",
    64: "display scaling steps belong to WP-11 (scale chosen from the panel's real PPI)",
    65: "display scaling steps belong to WP-11 (scale chosen from the panel's real PPI)",
    68: "the emoji picker " + WP03,
    69: "the capture menu: " + WP04,
    70: "the toggle menu " + WP03,
    72: "the Copilot key (Super+Shift+F23) is left to WP-11's override format; "
        "PUNAR+Space opens the command center",
    74: "the power key: " + WP07,
    76: "a tmux cheat sheet: Punar ships no tmux",
    77: "a herdr cheat sheet: Punar ships no herdr",
    78: "the calculator is inline arithmetic in the command center (WP-03)",
    79: "the calculator is inline arithmetic in the command center (WP-03)",
    80: "hiding the bar " + WP03,
    81: "the background picker is WP-05's wallpaper work",
    82: "the theme menu is WP-05's one theme switch",
    86: "dismissing the last notification is a key inside the notification centre",
    87: "dismissing every notification is a key inside the notification centre",
    88: "silencing notifications is do-not-disturb in the notification centre "
        "(punarctl notifications dnd on)",
    89: "invoking the last notification is a key inside the notification centre",
    91: "the idle-lock toggle: " + WP07,
    92: "night light is WP-11's display work",
    93: "turning the laptop display off is WP-11's display work",
    94: "mirroring the laptop display is WP-11's display work",
    95: "lid close: " + WP07,
    96: "lid open (clamshell): " + WP07,
    98: "screen recording: " + WP04,
    99: "the webcam overlay: " + WP04,
    100: "the webcam overlay: " + WP04,
    101: "the colour picker: " + WP04,
    102: "text from a screenshot (OCR): " + WP04,
    103: "sharing is WP-12's nearby sharing, as an expiring lease",
    104: "transcoding: " + WP04,
    105: "reminders arrive with WP-17's conveniences that do not leak",
    106: "reminders arrive with WP-17's conveniences that do not leak",
    107: "reminders arrive with WP-17's conveniences that do not leak",
    108: "a time notice: the bar's clock is WP-03",
    109: "a battery notice: the bar's battery is WP-03, on hardware WP-23 proves",
    110: "weather is WP-17's opt-in city weather, never located by IP",
    112: "the audio panel " + WP03,
    113: "the Bluetooth panel is WP-13, pairing you confirm",
    114: "a display panel chord arrives with WP-11's displays and input devices",
    115: "the calendar panel " + WP03,
    116: "a network panel chord arrives with WP-06's Wi-Fi, DNS and VPN work",
    117: "a power panel chord arrives with WP-07's power profiles and lid",
    118: "an activity monitor " + WP03,
    119: "screen zoom is an accessibility feature (WP-29)",
    120: "screen zoom is an accessibility feature (WP-29)",
    125: "the file manager in the focused terminal's folder waits for WP-15's shell "
         "integration: every foot window belongs to one server process, so only the "
         "shell reporting its folder (OSC 7) can say which folder a window is in, and "
         "guessing from the process tree, as Omarchy's helper does, opens the newest "
         "shell's folder",
    127: "a private browser window: " + APPS,
    128: "the editor: " + APPS,
    **{k: APPS for k in range(129, 150)},
    153: "the clipboard manager: " + WP04,
    164: "a keyboard-light cycle key: the up and down keys walk the light's levels, and "
         "a keyboard that has a cycle key is proven on WP-23's hardware",
    165: "touchpad on/off needs the per-device enable that WP-11's input-device settings "
         "add; Hyprland names the device, and Punar will not guess one",
    166: "touchpad on needs the per-device enable that WP-11's input-device settings add",
    167: "touchpad off needs the per-device enable that WP-11's input-device settings add",
    178: "eject belongs with WP-19's removable media (notify-then-mount, and unmount "
         "before power-off through udisks)",
    179: "switching the audio output arrives with WP-03's audio panel",
    180: "switching the media source arrives with WP-03's audio panel",
    181: "switching the media source arrives with WP-03's audio panel",
    182: "dictation (speech to text) arrives with WP-26",
    183: "push-to-talk dictation arrives with WP-26",
    184: "push-to-talk dictation arrives with WP-26",
    188: "jumping to the Nth window of a group: groups are walked with PUNAR+[ ] or "
         "PUNAR+ALT+Tab",
    189: "a chord per bar panel " + WP03 + "; PUNAR+SHIFT+B focuses the status cluster today",
    190: "keyboard window picking in the capture picker is WP-04",
    191: "keyboard window picking in the capture picker is WP-04",
    192: "keyboard window picking in the capture picker is WP-04",
    193: "keyboard window picking in the capture picker is WP-04",
}

for number in range(1, 194):
    listed = (number in BOUND) + (number in UNBOUND)
    if listed != 1:
        problems.append(f"K{number} must be bound or unbound exactly once (listed {listed} times)")
for number, bind in BOUND.items():
    where, prefix = (mac, bind[4:]) if bind.startswith("mac:") else (standard, bind)
    if not present(prefix, where):
        problems.append(f"K{number}: no live bind is described {prefix!r}")
for number, reason in UNBOUND.items():
    if len(reason) < 30:
        problems.append(f"K{number}: Punar binds nothing here, so it needs a real reason")

if problems:
    for problem in problems:
        print(f"keybind-contract-test: FAIL: {problem}", file=sys.stderr)
    sys.exit(1)
print(
    f"keybind-contract-test: ok ({len(modes['standard'])} binds standard, "
    f"{len(modes['mac'])} Mac-style; every one described, no chord twice, every "
    f"chord layout-safe; K1-K193: {len(BOUND)} bound, {len(UNBOUND)} unbound with a reason)"
)
PY
