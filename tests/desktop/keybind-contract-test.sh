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
# Appendix B: every Omarchy key family has a Punar row or a stated reason.
# `binds` are description prefixes that must be live (in the standard
# grammar unless marked mac:); `reason` covers what Punar does not bind.
# ---------------------------------------------------------------------------
FAMILIES = [
    ("K1-K2", ["Close window"],
     "close-all (Ctrl+Alt+Delete): one chord that discards unsaved work in every "
     "application is a hazard; End session and the session menu close apps properly"),
    ("K3-K12", ["Toggle split direction", "Toggle floating", "Toggle fullscreen",
                "Toggle maximize", "Pop window out", "Next layout preset"],
     "pseudo-tiling, tiled fullscreen and width save/restore are dwindle niceties "
     "left to WP-11's override format; the per-workspace preset toggle is PUNAR+comma/period"),
    ("K13-K16", ["Focus left", "Focus right"],
     "focus is on H/J/K/L (the Punar grammar); the arrow keys move windows and "
     "workspaces between monitors"),
    ("K17-K18", ["Toggle scratchpad terminal", "Toggle notes scratchpad"],
     "Punar's scratchpads are purpose-built (terminal, assistant, notes); a general "
     "move-to-stash chord arrives with WP-11's override format"),
    ("K19-K25", ["Previous workspace", "Next workspace", "Move workspace to left monitor"], ""),
    ("K26-K29", ["Swap window left", "Swap window right"], ""),
    ("K30-K35", ["Switch windows", "Focus next monitor", "Focus previous monitor"], ""),
    ("K36-K47", ["Enter resize mode", "Resize wider"],
     "one resize step with key repeat, in a mode, instead of three step sizes on nine chords"),
    ("K48-K51", ["Scroll to the next workspace", "Move window with the pointer",
                 "Resize window with the pointer"], ""),
    ("K52-K63", ["Toggle window group", "Next window in group", "Move window into group left"], ""),
    ("K64-K65", [], "display scaling steps belong to WP-11 (scale chosen from the panel's real PPI)"),
    ("K66-K74", ["Open command center", "System control", "Session menu"],
     "emoji, capture and toggle menus arrive with WP-03 and WP-04; the power key is WP-07"),
    ("K75-K77", ["Shortcut help"], "tmux and herdr cheat sheets: neither ships in Punar"),
    ("K78-K79", [], "the calculator is inline arithmetic in the command center (WP-03)"),
    ("K80-K85", ["Toggle window transparency", "Toggle window gaps",
                 "Toggle square shape for a lone window"],
     "hiding the bar is WP-03; background and theme pickers are WP-05"),
    ("K86-K90", ["Notification centre"],
     "dismiss, silence and invoke are keys inside the notification centre"),
    ("K91-K96", [], "idle, night light, laptop display, mirroring and lid are WP-07 and WP-11"),
    ("K97-K104", ["Screenshot output to clipboard", "Screenshot region to clipboard"],
     "recording, colour picker, OCR, share and transcode are WP-04 and WP-12"),
    ("K105-K110", [], "reminders, time, battery and weather notices are WP-03 and WP-17"),
    ("K111", ["AI on this device"], ""),
    ("K112-K118", ["System control"],
     "one System Control opens every panel; per-panel chords follow WP-03"),
    ("K119-K120", [], "screen zoom is an accessibility feature (WP-29)"),
    ("K121", ["Lock session"], ""),
    ("K122-K149", ["Open terminal", "Open browser", "Open files"],
     "third-party app and web-app chords: apps are opened from the command center, "
     "and a person binds their own with WP-11's override format. The file manager "
     "in the focused terminal's folder (K125) waits for WP-15's shell integration: "
     "every foot window belongs to one server process, so only the shell reporting "
     "its folder (OSC 7) can say which folder a window is in, and guessing from the "
     "process tree, as Omarchy's helper does, opens the newest shell's folder"),
    ("K150-K153", ["mac:Copy", "mac:Paste", "mac:Cut"],
     "off by default (punarctl keyboard clipboard-keys on); the clipboard manager is WP-04"),
    ("K154-K156", ["Volume up", "Volume down", "Toggle mute"], ""),
    ("K157", ["Toggle microphone mute"], ""),
    ("K158-K164", ["Brightness up", "Brightness down", "Keyboard light up"],
     "brightness maximum/minimum chords: the verb takes set 100% and set 1%"),
    ("K165-K167", [],
     "touchpad on/off needs the per-device enable that WP-11's input-device settings "
     "add; Hyprland names the device, and Punar will not guess one"),
    ("K168-K171", ["Volume up a little", "Brightness up a little"], ""),
    ("K172-K181", ["Play or pause", "Next track", "Previous track"],
     "output and source switching arrive with WP-03's audio panel"),
    ("K182-K184", [], "dictation (push-to-talk speech to text) arrives with WP-26"),
    ("K185-K187", ["Workspace 1", "Move window to workspace 1", "Move window quietly to workspace 1"], ""),
    ("K188", ["Previous window in group"],
     "jumping to the Nth window of a group: groups are walked with [ and ]"),
    ("K189", ["Focus status cluster"], "per-panel chords follow WP-03"),
    ("K190-K193", [], "keyboard window picking in the capture picker is WP-04"),
]

covered = set()
for family, binds, reason in FAMILIES:
    low, _, high = family.partition("-")
    first = int(low[1:])
    last = int(high[1:]) if high else first
    for number in range(first, last + 1):
        if number in covered:
            problems.append(f"{family}: K{number} is claimed by two families")
        covered.add(number)
    for bind in binds:
        where, prefix = (mac, bind[4:]) if bind.startswith("mac:") else (standard, bind)
        if not present(prefix, where):
            problems.append(f"{family}: no live bind is described {prefix!r}")
    if not binds and len(reason) < 30:
        problems.append(f"{family}: Punar binds nothing here, so it needs a real reason")
missing = sorted(set(range(1, 194)) - covered)
if missing:
    problems.append(f"Omarchy keys with no family row: {missing}")

if problems:
    for problem in problems:
        print(f"keybind-contract-test: FAIL: {problem}", file=sys.stderr)
    sys.exit(1)
print(
    f"keybind-contract-test: ok ({len(modes['standard'])} binds standard, "
    f"{len(modes['mac'])} Mac-style; every one described, no chord twice; "
    f"K1-K193 in {len(FAMILIES)} families)"
)
PY
