# Punar keyboard grammar — Milestones 1–2

Status: **implemented in config** (M1 grammar 2026-08-24, M2 multitasking
grammar 2026-08-25); in-VM behavior unverified until the CI runs (spec
1.22 — labels below; the M2 exercise plan is
[milestone-2.md](milestone-2.md) §7).
Spec basis: [SPEC_v0.2.md](../product/SPEC_v0.2.md) §12 (keyboard-first,
command center, discoverability), §13.2 (window modes: tile, stack/tab,
float), §13.3 (window grammar), §13.5 (layout presets), §13.6
(scratchpads), §14 (project workspaces, overview), §15 (multi-monitor).
M2 chord assignments and the `PUNAR+L` collision resolution follow
[milestone-2.md](milestone-2.md) §3 verbatim.
Source of truth: `os/modules/desktop/hypr/punar-binds.lua` (required by
`hyprland.lua`; input by `punar-input.lua`; layout presets additionally
`os/modules/desktop/hypr/punar-layout.sh`), shipped system-wide at
`/etc/xdg/hypr/` (script at `/usr/lib/punar/punar-layout.sh`) in the
punar-desktop image. The `.conf` files beside them are the superseded
legacy provider and are not staged. This document is the human-readable
mirror; if they disagree, the config is wrong or this page is stale — fix
whichever lies. `tests/desktop/keybind-contract-test.sh` holds the config to
three rules (every bind described, no chord twice, every Omarchy key family
answered), and `punarctl keys list` prints the live table.

The grammar principle (§13.1): the keyboard states intent, the desktop
obeys, motion explains what changed. The **Punar key**, written `PUNAR` in a
chord, is the single leader key: the Windows-logo / Meta key on PC keyboards,
and the guest-Meta position (normally Command) through an Apple VM client.
Hyprland's raw modifier spelling remains confined to the compositor config;
the shell converts modifier bit 64 to `Punar` before a person sees it.
Hovering never steals focus (`input:follow_mouse = 0`); clicking still
focuses, so the mouse remains supported but never required.

## M1 — implemented

### Core window grammar (spec §13.3)

```text
PUNAR + H/J/K/L              Focus left/down/up/right
PUNAR + SHIFT + H/J/K/L      Move window left/down/up/right
PUNAR + R                    Resize mode (submap; below)
PUNAR + F                    Toggle fullscreen
PUNAR + 1..9                 Go to workspace 1..9
PUNAR + SHIFT + 1..9         Move window to workspace 1..9
PUNAR + SHIFT + TAB          Previous open workspace (fast cycle)
PUNAR + Space                Universal command center (punar-shell IPC)
PUNAR + SHIFT + Space        Command center fallback for VM clients that reserve PUNAR + Space
```

(`PUNAR+TAB` was the M1 workspace-cycle placeholder; M2 rebinds it to the
project overview — see below.)

Focus and move in a direction spill across monitor edges to the adjacent
display (`binds:window_direction_monitor_fallback`), so HJKL alone drives a
multi-monitor desk; the arrows below are the explicit form.

### Resize mode (`PUNAR + R`)

Enter the submap, resize with the same HJKL vocabulary (keys repeat while
held, 40 px steps), leave with Escape or Return. `resizeactive` drives
floating windows too, so the same mode resizes floats.

```text
H / L                        Narrower / wider
K / J                        Shorter / taller
Escape · Return              Exit resize mode
```

### Windows and apps

```text
PUNAR + Q                    Close window
PUNAR + SHIFT + Q            Window actions (close normally or confirm a
                             force quit for the exact focused app)
PUNAR + Return               Terminal (a detached footclient; falls back to
                             foot only if the foot server is down)
PUNAR + B                    Browser in the active storage context
```

### Multi-monitor (spec §15)

```text
PUNAR + SHIFT + LEFT/RIGHT/UP/DOWN    Move window to the display in that
                                      direction
```

### Screenshots (spec §12.1)

```text
Print                        Full output → clipboard (pure keyboard path)
PUNAR + SHIFT + S            Region → clipboard (pointer-assisted: slurp
                             region selection needs the mouse)
```

### Session

```text
PUNAR + SHIFT + E            End session — asks first: opens the session
                             menu with End session armed; press it again
                             (or E) to sign out, Esc to stay (greetd falls
                             back to agreety, milestone-1.md §4)
```

## M2 — implemented in config

### Groups — stack/tab windows (spec §13.2)

A group stacks windows behind one frame; the groupbar is its tab strip,
styled to the field-note language in `punar-look.conf` (mono labels at
10 px, no gradients or rounding, a 2 px ink indicator rule for the active
tab — the same selection statement Plate D-007 uses — paper/ink colors,
locked groups marked in ink2, never a status hue).

```text
PUNAR + G                    Toggle group on the active window
PUNAR + SHIFT + G            Move the active window out of its group
PUNAR + [ / ]                Previous / next window in the group
PUNAR + CTRL + H/J/K/L       Move the active window INTO the adjacent
                             group in that direction
```

Group locking (`lockactivegroup`) is a command-center verb, not a chord.

### Floating polish (spec §13.2)

```text
PUNAR + V                    Toggle floating (M1)
PUNAR + SHIFT + V            Pin floating window — visible on every
                             workspace (floating-only by design)
PUNAR + C                    Center floating window (0.56.2
                             `centerwindow`; takes no argument)
```

Window rules float dialog-shaped surfaces as centered cards: portal
implementations by app-id, plus exact-anchored common file-dialog titles
(Open File / Save As / File Upload, …).

### Layout presets (spec §13.5)

```text
PUNAR + comma / period       Previous / next layout preset (< / >)
```

Cycle order: `balanced → columns → rows → focus → stack` (wraps). Both
binds and the command center's chooser exec the same engine —
`/usr/lib/punar/punar-layout.sh <preset|next|prev|restore>`, POSIX sh, one
`hyprctl eval` per invocation, active preset cached at
`$XDG_RUNTIME_DIR/punar/layout-preset`. Presets were **global** in M2
(per-workspace presets were a stretch goal — workspace rules accumulate in
0.56.2, milestone-2.md §1.3). **SMP-1405 WP-02 made the keys per workspace**
(kept across sessions; the accumulation is bounded by a reload or sign-out),
while the command center still sets the session's preset; see the WP-02
section below. At session start `punar-layout.sh restore` re-applies the
preset persisted in `~/.local/state/punar/workspaces.json` (written by
punar-shell, milestone-2.md §6) and every workspace's own.

| Preset | Algorithm | Honest description |
| --- | --- | --- |
| `balanced` | dwindle (even splits, preserve_split) | even BSP splits — the M1 default feel |
| `columns` | scrolling (column_width 0.5, direction right) | every window a column; the viewport scrolls when they overflow |
| `rows` | master (orientation top, mfact 0.5) | hero row on top, the rest share the bottom — a two-row approximation |
| `focus` | master (orientation left, mfact 0.72) | one large focused window, context stack at the side |
| `stack` | monocle | one window at a time; cycle with focus keys |
| `grid` | — | **not shipped**: 0.56.2 has no native grid algorithm (milestone-2.md §2) |

### Scratchpads (spec §13.6)

```text
PUNAR + T                    Scratchpad terminal (special:term; a warm-server
                             footclient is created on first use)
PUNAR + SHIFT + A            Assistant scratchpad (special:assistant)
PUNAR + N                    Notes scratchpad (special:notes)
```

Every scratchpad presents as the same centered card: floating, 60% × 60%
of the monitor (Plate D-007's justified float), parked silently on its
special workspace at spawn. The terminal helper creates a `footclient` only
on first use; assistant and notes likewise have nothing pre-spawned — the
shell/command center launches their clients, and the app-id rules
(`punar-assistant`, `punar-notes`) park them. If a
scratchpad's window is closed its special workspace closes with it;
relaunch via PUNAR+Space or `foot --app-id=punar-scratch`.

### AI panel (spec §25, Plate D-005 · M7)

```text
PUNAR + A                    AI on this device (punar-shell IPC target
                             `aipanel`; ↑/↓ walk the agent rail, Escape
                             closes)
```

`PUNAR+A` is spec §25's own shortcut. M7 takes the chord for the AI panel
and moves the M2 assistant scratchpad to `PUNAR+SHIFT+A` (the pad has no
pre-spawned client; the panel is the milestone's headline surface). Both
binds on one chord is not an option — Hyprland fires every match.

### Privacy panel (Plate D-006 · M12)

```text
PUNAR + P                    Privacy and network activity (punar-shell IPC
                             target `privacypanel`; ↑/↓ walk processes,
                             Enter expands, R refreshes, Escape closes)
```

The panel runs one local, on-demand TCP observation pass and renders the
root-owned result. Policy-denial destinations remain local live-view data;
the persistent audit trail records only the denied zone. Features that are
not enforcement paths yet remain visibly marked as inactive.

### Project overview (spec §14.2, Plate D-007)

```text
PUNAR + TAB                  Project overview (punar-shell IPC)
PUNAR + SHIFT + TAB          Previous open workspace (fast cycle, kept)
```

`PUNAR+TAB` execs the shell contract — exactly
`quickshell ipc call overview toggle` — held in the single `$overview`
variable in `hyprland.conf` (the `$commandCenter` pattern; IpcHandler
target `overview`, functions `toggle`/`open`/`close`/`state`). Inside the
overview the shell owns the keys: arrows move the selection,
type-to-search filters by name, Enter switches workspace, Escape closes.

### Named workspaces (spec §14)

Not chords: rename-workspace and go-to-named-workspace are command-center
actions (validated against the name rules in milestone-2.md §6);
`PUNAR+1..9` stays the fast path, and `hyprctl dispatch workspace
name:<x>` navigation works for scripts. Names show in the bar and the
overview and persist across sessions via the shell's state file.

### `PUNAR+L` collision resolution (spec §13.3)

Spec §13.3's table sketches `PUNAR+L` as both focus-right and the layout
chooser and says bindings may evolve. Resolved (milestone-2.md §3):
**`PUNAR+L` stays focus-right** — directional focus is the
highest-frequency verb and HJKL is its complete vocabulary. The layout
chooser is a command-center action (type "layout"), and
`PUNAR+comma/period` are the direct cycle pair.

## SMP-1405 WP-02 — keys, input and window grammar at Omarchy's level

Implemented in config and in `punarctl`. The in-VM proof is
`os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/keys-check.sh`,
which presses these as real keys through QMP (`tools/qmp-keys.py`). **It has
not run in CI yet.** It has run on real boots: qcow2 overlays of the arm64
release image carrying this branch's binaries, configuration and shell, the
dev profile's account and checks, and the same QMP driver (2026-09-25, HVF).
Its final run was `PUNAR_KEYS_OK`, 55 assertions, and the switcher's
surface-cost budget passed in the same boot. The first runs found two
product faults that no static check could see, both fixed: the Alt-release
bind never fired after a Tab (below), and the overview and the switcher did
not load when opened on their own (`qml-url-surface-import-test.sh` now
holds that). The contract tests (`tests/desktop/keybind-contract-test.sh`,
`layout-script-test.sh`), the pinned Hyprland's `--verify-config`
(`tools/hyprland-verify.sh`) and punarctl's own tests still gate every
change in CI. The desktop gate's first run is what proves it on CI's KVM
lane.

**The login screen's choice, pressed for real.** On a release-image overlay
with no dev fixtures, an account was created through onboarding, and on the
login screen the keyboard picker was clicked and Russian chosen. After
signing in: `/etc/vconsole.conf` held `XKBLAYOUT=ru`, the session's data
file and the live compositor held `us,ru` with `grp:alts_toggle`, and the
change was audited as `allow` under the person's uid. The lock screen named
English (US) with the switch hint. PUNAR+Return opened a terminal. After
both Alt keys, that terminal received `привет` and the lock screen named
Russian. The next login screen showed the device's layout (RU). German
chosen there gave `XKBLAYOUT=de`, a live `kb_layout` of `de`, German
keyboards, and a lock screen reading "Keyboard German". Unlocks were typed
on the lock screen, including one that needed both Alt keys first, because
the active group was Russian when the screen locked.

**Every chord works under every keyboard layout.** Hyprland matches a keysym
bind against the first layout's unshifted symbol, so the number row is bound
by key code (`code:10` is the 1 key … `code:19` the 0 key), as Omarchy's
workspace keys are: on AZERTY the unshifted number row types `& é " …` and a
digit keysym would never fire. Letters are unshifted on every Latin layout
(and a non-Latin layout gets a US first group). The three punctuation chords
that German, French, Spanish and Italian keyboards put behind Shift or AltGr
have a twin on a key every layout names the same: **PUNAR + F1** for the
shortcut help (PUNAR + /), and **PUNAR + ALT + Tab** / **PUNAR + ALT + SHIFT
+ Tab** for the next and previous window in a group (PUNAR + ] and [). The
layout presets need none: comma is unshifted on every Latin layout the login
screen offers, PUNAR + comma alone cycles all five, and the command center
sets any of them by name. The contract test refuses a digit keysym, and any
punctuation keysym without a twin or a stated reason.

### Window grammar

```text
PUNAR + ALT + H/J/K/L        Swap window left/down/up/right
PUNAR + M                    Toggle maximize (keeps the bar and gaps)
PUNAR + O                    Pop window out (float, 60% of the display, centre, pin) / put it back
PUNAR + D                    Toggle split direction (dwindle)
PUNAR + 0                    Workspace 10 (1..9, 0 on the number row)
PUNAR + SHIFT + 0            Move window to workspace 10
PUNAR + ALT + 1..0           Move window quietly (you stay where you are)
PUNAR + CTRL + TAB           Next workspace
PUNAR + wheel                Scroll workspaces
PUNAR + ALT + arrows         Move the workspace to another monitor
PUNAR + drag / right-drag    Move / resize a window with the pointer
PUNAR + comma / period       Previous / next layout preset FOR THIS WORKSPACE (kept across sessions)
PUNAR + E                    Open files (punarctl app open thunar)
ALT + TAB / SHIFT + ALT + TAB  Window switcher (most recent first; release Alt to choose)
CTRL + ALT + TAB             Focus next monitor (SHIFT: previous)
PUNAR + ALT + TAB            Next window in a group (SHIFT: previous); any layout
PUNAR + F1                   Shortcut help, on any layout (as PUNAR + /)
PUNAR + CTRL + T / G / A     Your look: transparency / gaps / square lone window (kept)
```

**Layout presets: the keys are per workspace, the command center is the
session's.** PUNAR + comma/period change the focused workspace's own preset
(Omarchy's Super+L is per workspace too), and it is kept across sessions.
Choosing a preset in the command center sets the **session's** preset, which
every workspace without one of its own follows, and gives the focused
workspace back to it, so the choice is seen where it was made. `punarctl
layout <preset>` is the session's, `--workspace N|active` one workspace's, and
`punarctl layout default --workspace N` gives a workspace back. Hyprland 0.56
cannot delete a live workspace rule, so each per-workspace change adds one
small rule until the next reload or sign-out, which clears them all;
giving back a workspace that never had its own preset adds nothing.

**The look is kept, as data.** PUNAR + CTRL + T/G/A run `punarctl window look
transparency|gaps|square toggle`, which writes three booleans to
`~/.config/punar/look.json` and applies them live; the compositor reads that
file with patterns at every configuration load, so the look survives a reload
and the next session. Omarchy keeps the same toggles by copying Lua files its
configuration then runs; nothing here is run.

**Alt+Tab is decided and drawn by the shell.** The compositor counts the
Tabs of one Alt hold; the shell keeps the most-recent-first list, draws the
strip and focuses the choice through `punarctl window focus`. A quick tap
therefore starts two short `qs ipc` clients and two `punarctl` runs, where
Omarchy's `cycle_next` stays inside the compositor, and if the shell is not
running Alt+Tab does nothing (as the bar, the notifications and the lock
screen do nothing). A compositor-only quick tap (`hl.dsp.focus({ last = true
})`) was considered and not taken: the compositor's "last window" includes
scratchpad windows and hidden group members the switcher leaves out, so a
quick tap and a held Alt could choose different windows. The difference
is measured, not assumed. On an overlay boot a compositor-only
`hl.dsp.focus({ last = true })` bind was added, and both it and Alt+Tab
were pressed as real keys through the same QMP driver path, seven times
each. From the console request to the focus change, the shell's switch had a
median of 341 ms (306-561) and the compositor-only switch 305 ms (219-369).
The driver's own serial polling (up to 250 ms) and pacing are in both
figures. The switcher's most-recent-first order, its previews and its
scratchpad-aware choice cost about 36 ms at the median in that VM, inside
the compositor-only switch's own spread.

**Alt+Tab's release never swallows Alt, and is never lost.** The
Alt-release binds that end a switch are non-consuming, so an application
still sees every Alt release (a bare Alt opens the menu bar in Firefox and
most GTK and Qt apps), and transparent: when ALT + Tab takes the Tab press,
Hyprland shadows every bind on a key that is still held, so without it the
release fired only on a bare Alt tap and never after a Tab. Every Alt+Tab
then ended on the switcher's five-second fallback (5.4 s for a quick switch,
measured in the VM on Hyprland 0.56.2; the same bind with `transparent =
true` fired after Alt+Tab and after Alt+Tab+Tab). `keybind-contract-test.sh`
now refuses a release bind on a modifier key that is not both, and
keys-check.sh fails a quick switch that takes four seconds or more.


Not bound, on purpose: Omarchy's "file manager in the focused terminal's
folder" (K125). Every foot window belongs to one server process, so the
process tree cannot say which shell a window holds; Omarchy's helper takes
the newest shell and opens the wrong folder from any other window. The
precise answer is the shell reporting its folder (OSC 7), which arrives with
WP-15's shell integration; the chord comes with it.

### Media, microphone and brightness (also on the lock screen)

```text
Play/Pause, Next, Previous   punarctl media play-pause|next|previous (MPRIS)
ALT + Play / ALT+SHIFT+Play  Next / previous track, for keyboards with only Play
Mic mute                     punarctl audio mute --input
Brightness up/down           punarctl display brightness +5% / -5% (ALT: 1%)
SHIFT + Brightness up/down   Brightness to full / to lowest (1%, never dark)
Keyboard light up/down       punarctl display brightness --keyboard ±34%
```

Brightness writes only through logind's `SetBrightness` on the session's own
object: no root, no polkit prompt, no video group, no udev rule. A machine
with no backlight (every VM) exits 6 and draws nothing. Every step moves the
device at least one level, taken from the raw value it holds, so a firmware
backlight with eight or ten levels never swallows a key press.

### Keyboard layout

The device's layout is punard's `system.keymap` (`/etc/vconsole.conf`), set by
the person at the machine, **from their own session on it**, with `punarctl
keyboard layout set <layouts>`, System Control's Keyboard view, or a
successful sign-in from the login screen's picker. punard checks the caller's
own logind session (active, local, on seat0), not only its uid, so a user
service, an SSH login or a helper started outside an agent's scope cannot
change it (docs/api/ipc.md section 5.4). Both compositors read it as data from
`$XDG_RUNTIME_DIR/punar/session/input.lua`. A first layout that cannot type
Latin letters is led by US English, and **both Alt keys together** switch
layouts (an XKB option, so it works on the login and lock screens too).

The login screen names the device's whole value, variants and all ("US-DVORAK",
"US RU"), so its label never names a layout it is not typing in, and its plain
US entry means plain US. A choice made there is carried into the device only
by a sign-in within ten minutes of it; after that the login screen goes back
to the device's layout, so the next person does not adopt it unseen. The
installer's layout is the first default only on a device nobody has signed in
to yet; an updated device keeps what it types today, so no existing password
moves under a new layout.

### Clipboard keys (optional)

`punarctl keyboard clipboard-keys on`: PUNAR + C / V / X copy, paste and cut
(Ctrl+Insert / Shift+Insert in a terminal), and floating and centring move to
PUNAR + ALT + V and C. In foot, Ctrl+Insert and Shift+Insert copy and paste.
There is no select-all key: foot has no select-all action, and its only
stand-in (piping the whole scrollback into the clipboard) would copy up to
10,000 lines, secrets included, with nothing shown selected.

## Future — reserved / not in M2

| Binding | Target | Milestone |
| --- | --- | --- |
| `grid` preset | `lua:<name>` custom layout at a future compositor rebase | later |
| Clipboard history (§12.1) | Needs a clipboard manager not in the package set | M2+ |
| `PUNAR` held → shortcut overlay; `?` → help (§12.3) | Shell overlay consuming `hyprctl binds -j` — every bind (M1 and M2) carries a `bindd` description precisely so this needs no second registry | M2+ |
| Wi-Fi/BT/audio/power etc. keyboard flows (§12.1) | Command center capabilities, not compositor binds | M2/M3 |
| Lock / DPMS | With session/idle management work | later |

## Verification status (spec 1.22)

| Claim | Status |
| --- | --- |
| M1 config syntax valid for hyprland 0.56.2-1 (the pinned package) | **verified 2026-08-24** — source-tag check + `Hyprland --verify-config` "config ok" on the exact pinned package (ALA 2026/08/20) in the pinned builder base container, with a non-vacuous negative control |
| M2 grammar (groups, floating, presets, scratchpads, overview binds, groupbar styling, window rules) syntax valid for hyprland 0.56.2-1 | **verified 2026-08-25** — same method: every dispatcher/keyword was pre-verified in milestone-2.md §1, and the full edited config tree passes `Hyprland --verify-config` ("config ok") on hyprland 0.56.2-1 from ALA 2026/08/20 in the pinned builder base container; negative control (`togglegroup` misspelled in `punar-binds.conf`) rejected with a per-file per-line error, so the sourced files are genuinely parsed |
| `punar-layout.sh` lint | **verified 2026-08-25** — shellcheck-clean (koalaman/shellcheck v0.11.0 container, `-s sh`) |
| Binds/presets/overview behave as described in the running VM | **unverified — plan**; the M2 CI exercise phase (milestone-2.md §7, `PUNAR_M2_OK`) is the arbiter. Note `--verify-config` checks `exec` binds only syntactically — the layout script and shell IPC target are proven at runtime, not at parse |
| Overview IPC target `overview` exists in punar-shell | **contract — plan**; the bind carries the agreed string (milestone-2.md §5); the shell workstream implements the handler |
| No-mouse operation of the core desktop | **human-verified walkthrough for M1** (below); M2 additions are walkthrough items, unverified until run |

## No-mouse acceptance walkthrough (human)

Drive the VM with keyboard only; every step must succeed without touching
the pointer:

1. Boot to the desktop (greetd autologin) — `PUNAR_DESKTOP_OK` on serial.
2. `PUNAR+Return` — terminal opens, focused.
3. `PUNAR+Return` again, `PUNAR+H/L` — focus moves between the two tiles.
4. `PUNAR+SHIFT+H/L` — windows swap positions (animated, 300 ms).
5. `PUNAR+R`, resize with HJKL, Escape — sizes change and mode exits.
6. `PUNAR+F` twice — fullscreen in and out.
7. `PUNAR+2`, `PUNAR+Return`; `PUNAR+1` / `PUNAR+2` — workspace switching.
8. `PUNAR+SHIFT+1` on workspace 2 — window moves to workspace 1.
9. `PUNAR+SHIFT+TAB` — cycles back through open workspaces.
10. `PUNAR+T` twice — scratchpad terminal summoned and dismissed.
11. `PUNAR+Space` — command center opens; Escape closes it (shell contract).
12. `PUNAR+B` — Browser launches through the closed Punar argv builder; its
    `--user-data-dir` matches the active context (first paint may be slow
    under llvmpipe).
13. `Print` — screenshot lands in the clipboard (`wl-paste --list-types`
    from the terminal shows `image/png`).
14. `PUNAR+Q` — focused window closes.
15. `PUNAR+SHIFT+E` — session ends to the agreety text greeter.

M2 additions (extends the list; per milestone-2.md §7):

16. Two terminals on one workspace; `PUNAR+G` — they stack behind one
    frame, groupbar tabs appear (mono labels, 2 px ink rule).
17. `PUNAR+[` / `PUNAR+]` — the active tab walks the group;
    `PUNAR+SHIFT+G` — the window leaves the group.
18. `PUNAR+CTRL+L` on an ungrouped window next to a group — it joins that
    group.
19. `PUNAR+V`, `PUNAR+C` — window floats, then centers; `PUNAR+SHIFT+V` —
    it follows across `PUNAR+1/2`; unpin and re-tile.
20. `PUNAR+period` through the full preset cycle — the tiles re-lay-out
    balanced → columns → rows → focus → stack and wrap; `PUNAR+comma`
    steps back.
21. `PUNAR+SHIFT+A`, `PUNAR+N` — assistant and notes scratchpads toggle.
22. `PUNAR+TAB` — overview opens; arrows move the selection,
    typing filters, Enter lands on the chosen workspace, Escape closes.
23. Command center: rename workspace 1 to `atlas`; the name shows in bar
    and overview and survives a shell restart.
