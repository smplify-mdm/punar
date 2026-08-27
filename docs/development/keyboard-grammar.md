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
Source of truth: `os/modules/desktop/hypr/punar-binds.conf` (sourced by
`hyprland.conf`; layout presets additionally
`os/modules/desktop/hypr/punar-layout.sh`), shipped system-wide at
`/etc/xdg/hypr/` (script at `/usr/lib/punar/punar-layout.sh`) in the
punar-desktop image. This document is the human-readable mirror; if they
disagree, the config is wrong or this page is stale — fix whichever lies.

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
PUNAR + Return               Terminal (footclient; falls back to foot if
                             the foot server is down)
PUNAR + B                    Browser (chromium, Wayland ozone)
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
PUNAR + SHIFT + E            End session (greetd falls back to agreety,
                             milestone-1.md §4)
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
`hyprctl --batch` of keywords per invocation, active preset cached at
`$XDG_RUNTIME_DIR/punar/layout-preset`. Presets are **global** in M2
(per-workspace presets are a stretch goal — keyword-added workspace rules
accumulate in 0.56.2, milestone-2.md §1.3). At session start
`punar-layout.sh restore` re-applies the preset persisted in
`~/.local/state/punar/workspaces.json` (written by punar-shell,
milestone-2.md §6).

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
PUNAR + T                    Scratchpad terminal (special:term; foot with
                             app-id punar-scratch pre-spawned at session
                             start)
PUNAR + SHIFT + A            Assistant scratchpad (special:assistant)
PUNAR + N                    Notes scratchpad (special:notes)
```

Every scratchpad presents as the same centered card: floating, 60% × 60%
of the monitor (Plate D-007's justified float), parked silently on its
special workspace at spawn. The assistant and notes pads have nothing
pre-spawned in M2 — the shell/command center launches their clients, and
the app-id rules (`punar-assistant`, `punar-notes`) park them. If a
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

## Future — reserved / not in M2

| Binding | Target | Milestone |
| --- | --- | --- |
| Per-workspace layout presets | Needs a workspace-rule reset mechanism (rules accumulate in 0.56.2) | stretch |
| `grid` preset | `lua:<name>` custom layout at a future compositor rebase | later |
| Clipboard history (§12.1) | Needs a clipboard manager not in the package set | M2+ |
| `PUNAR` held → shortcut overlay; `?` → help (§12.3) | Shell overlay consuming `hyprctl binds -j` — every bind (M1 and M2) carries a `bindd` description precisely so this needs no second registry | M2+ |
| Wi-Fi/BT/audio/power etc. keyboard flows (§12.1) | Command center capabilities, not compositor binds | M2/M3 |
| Media/brightness keys | Real-hardware image (VM dev image has no such keys) | later |
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
12. `PUNAR+B` — chromium launches (first paint may be slow under llvmpipe).
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
