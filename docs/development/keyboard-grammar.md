# Punar keyboard grammar — Milestone 1

Status: **implemented in config** (2026-08-24), in-VM behavior unverified
until the first M1 CI run (spec 1.22 — labels below).
Spec basis: [SPEC_v0.2.md](../product/SPEC_v0.2.md) §12 (keyboard-first,
command center, discoverability), §13.3 (window grammar), §13.6
(scratchpads), §15 (multi-monitor).
Source of truth: `os/modules/desktop/hypr/punar-binds.conf` (sourced by
`hyprland.conf`), shipped system-wide at `/etc/xdg/hypr/` in the
punar-desktop image. This document is the human-readable mirror; if they
disagree, the config is wrong or this page is stale — fix whichever lies.

The grammar principle (§13.1): the keyboard states intent, the desktop
obeys, motion explains what changed. `SUPER` is the single leader key.
Hovering never steals focus (`input:follow_mouse = 0`); clicking still
focuses, so the mouse remains supported but never required.

## M1 — implemented

### Core window grammar (spec §13.3)

```text
SUPER + H/J/K/L              Focus left/down/up/right
SUPER + SHIFT + H/J/K/L      Move window left/down/up/right
SUPER + R                    Resize mode (submap; below)
SUPER + F                    Toggle fullscreen
SUPER + TAB                  Workspace overview — M1 placeholder: next
                             open workspace (see Future)
SUPER + SHIFT + TAB          Previous open workspace (placeholder pair)
SUPER + 1..9                 Go to workspace 1..9
SUPER + SHIFT + 1..9         Move window to workspace 1..9
SUPER + Space                Universal command center (punar-shell IPC)
```

Focus and move in a direction spill across monitor edges to the adjacent
display (`binds:window_direction_monitor_fallback`), so HJKL alone drives a
multi-monitor desk; the arrows below are the explicit form.

### Resize mode (`SUPER + R`)

Enter the submap, resize with the same HJKL vocabulary (keys repeat while
held, 40 px steps), leave with Escape or Return.

```text
H / L                        Narrower / wider
K / J                        Shorter / taller
Escape · Return              Exit resize mode
```

### Windows, apps, scratchpad

```text
SUPER + Q                    Close window
SUPER + Return               Terminal (footclient; falls back to foot if
                             the foot server is down)
SUPER + B                    Browser (chromium, Wayland ozone)
SUPER + V                    Toggle floating (window modes, spec §13.2)
SUPER + T                    Scratchpad terminal (spec §13.6) — toggles
                             special workspace `term`; a foot instance
                             (app-id punar-scratch) is pre-spawned there
                             at session start as a centered 62%×58% card
```

If the scratchpad terminal is exited, its special workspace closes with it;
relaunch with `foot --app-id=punar-scratch` (command center action lands in
M2 alongside the assistant and notes scratchpads).

### Multi-monitor (spec §15)

```text
SUPER + SHIFT + LEFT/RIGHT/UP/DOWN    Move window to the display in that
                                      direction
```

### Screenshots (spec §12.1)

```text
Print                        Full output → clipboard (pure keyboard path)
SUPER + SHIFT + S            Region → clipboard (pointer-assisted: slurp
                             region selection needs the mouse)
```

### Session

```text
SUPER + SHIFT + E            End session (greetd falls back to agreety,
                             milestone-1.md §4)
```

## Future — reserved / not in M1

| Binding | Target | Milestone |
| --- | --- | --- |
| `SUPER + TAB` | Graphical project overview (spec §14.2) replaces the workspace-cycle placeholder; planned as a shell IPC call like the command center | M2 |
| Layout chooser | Spec §13.3 sketches `SUPER + L`, which HJKL focus claims (same table — §13.3 says bindings may evolve). Reassigned in M2, likely a command-center action and/or `SUPER + ,` | M2 |
| Layout presets (balanced/columns/rows/focus/stack/grid, §13.5) | Command center + chooser | M2 |
| Stack / tab groups (`togglegroup`, group navigation) (§13.2) | Dedicated chords, decided with the overview design | M2 |
| Named project workspaces (§14) | Overview + command center; numeric `SUPER+1..9` stays as the fast path | M2 |
| Assistant / notes scratchpads (§13.6) | `special:assistant`, `special:notes` with their own toggles | M2+ |
| Clipboard history (§12.1) | Needs a clipboard manager not in the M1 package set | M2+ |
| `SUPER` held → shortcut overlay; `?` → help (§12.3) | Shell overlay consuming `hyprctl binds -j` — every M1 bind already carries a description (`bindd`) precisely so this needs no second registry | M2 |
| Wi-Fi/BT/audio/power etc. keyboard flows (§12.1) | Command center capabilities, not compositor binds | M2/M3 |
| Media/brightness keys | Real-hardware image (VM dev image has no such keys) | later |
| Lock / DPMS | With session/idle management work | later |

## Verification status (spec 1.22)

| Claim | Status |
| --- | --- |
| Config syntax valid for hyprland 0.56.2-1 (the pinned package) | **verified 2026-08-24** — every keyword, option, dispatcher, and rule field checked against the `v0.56.2` source tag (legacy hyprlang path, `src/config/legacy/`), and `Hyprland --verify-config` reports `config ok` for the full config tree on the exact pinned package (ALA 2026/08/20) in the pinned builder base container; a negative control (invalid dispatcher injected into `punar-binds.conf`) was correctly rejected with a per-file error, proving the check parses the sourced files and is not vacuous |
| Binds behave as described in the running VM | **unverified — plan**; first M1 CI run (desktop-test job) is the arbiter |
| No-mouse operation of the core desktop | **human-verified walkthrough** (below); the presence of this keybind config in the image is the CI-checkable proxy (milestone-1.md §10) |

## No-mouse acceptance walkthrough (human, per M1 acceptance)

Drive the VM with keyboard only; every step must succeed without touching
the pointer:

1. Boot to the desktop (greetd autologin) — `PUNAR_DESKTOP_OK` on serial.
2. `SUPER+Return` — terminal opens, focused.
3. `SUPER+Return` again, `SUPER+H/L` — focus moves between the two tiles.
4. `SUPER+SHIFT+H/L` — windows swap positions (animated, 300 ms).
5. `SUPER+R`, resize with HJKL, Escape — sizes change and mode exits.
6. `SUPER+F` twice — fullscreen in and out.
7. `SUPER+2`, `SUPER+Return`; `SUPER+1` / `SUPER+2` — workspace switching.
8. `SUPER+SHIFT+1` on workspace 2 — window moves to workspace 1.
9. `SUPER+TAB` / `SUPER+SHIFT+TAB` — cycles the open workspaces.
10. `SUPER+T` twice — scratchpad terminal summoned and dismissed.
11. `SUPER+Space` — command center opens; Escape closes it (shell contract).
12. `SUPER+B` — chromium launches (first paint may be slow under llvmpipe).
13. `Print` — screenshot lands in the clipboard (`wl-paste --list-types`
    from the terminal shows `image/png`).
14. `SUPER+Q` — focused window closes.
15. `SUPER+SHIFT+E` — session ends to the agreety text greeter.
