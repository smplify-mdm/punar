# punar-shell

The Punar desktop shell for Milestone 1: a Quickshell (QML) top bar and the
SUPER+Space command center overlay, implementing the field-note design
language.

- Design authority: [`docs/design/DESIGN_LANGUAGE.md`](../../docs/design/DESIGN_LANGUAGE.md)
  (binding) and the mockups — the command-center card is
  [`docs/design/mockups/command-approval.html`](../../docs/design/mockups/command-approval.html)
  Sect I, the M1 acceptance reference.
- Every design value flows through the `Theme` singleton, which loads
  [`shell/theme/punar-tokens.json`](../theme/punar-tokens.json) at runtime.
  No color is hardcoded outside `Theme/Theme.qml` (DESIGN_LANGUAGE.md §8).

## Layout

| File | Role |
| --- | --- |
| `shell.qml` | `ShellRoot` entrypoint; wires the ready marker |
| `Theme/Theme.qml` | Singleton: token loader + typed design properties |
| `Services/Status.qml` | Singleton: compliance/project context — **M1 stub**, M5 wires punard |
| `Bar/Bar.qml` | Top bar (30px paper masthead, hairline rule) |
| `CommandCenter/CommandCenter.qml` | SUPER+Space overlay + `commandcenter` IPC handler |

## Running on a dev machine

Requires Quickshell ≥ 0.3 on a Wayland session (Hyprland for live workspace
data; the bar degrades gracefully without it):

```sh
qs -p shell/punar-shell        # from the repo root; `quickshell -p …` works too
```

The Theme singleton first tries the installed token path and falls back to
the in-repo `shell/theme/punar-tokens.json` (resolved relative to
`Quickshell.shellDir`). Instrument Sans and Geist Mono should be installed
for fidelity; Qt falls back to system fonts otherwise.

Toggle the command center from another terminal:

```sh
qs ipc call commandcenter toggle
```

## Install layout (punar-desktop image)

- Shell QML: `/usr/share/punar/shell/` (this directory's contents;
  `shell.qml` is the entrypoint), launched from Hyprland with
  `exec-once = qs -p /usr/share/punar/shell`.
- Tokens: `/usr/share/punar/theme/punar-tokens.json` (primary path baked
  into `Theme.qml`).

## Keyboard contract (M1 acceptance: no mouse required)

- `SUPER+Space` → Hyprland runs `qs ipc call commandcenter toggle`.
- In the overlay: typing filters, `↑`/`↓` select (animated highlight),
  `Enter` launches, `Esc` closes. A scrim click also dismisses, but nothing
  requires the mouse.

## Command center data sources (M1 scope)

1. Installed applications via Quickshell `DesktopEntries` — launched with
   `DesktopEntry.execute()` (the parsed `Exec`, never a shell string).
2. Static punarctl action stubs (fixed argv table in
   `CommandCenter.qml`): "Open terminal" → `["foot"]` via
   `Quickshell.execDetached`; "System Control" is a labeled placeholder.

**M3 integration point:** the static table is replaced by rows from
punard's capability registry (spec §41) over typed IPC; rows then print the
real typed capability they resolve to. The shell never composes shell
strings — that invariant survives M3.

## Ready marker

Once the bar object tree completes, `shell.qml` runs
`touch /run/punar/shell-ready` (`/run/punar` comes from a root tmpfiles.d
entry, `0755 punar punar` — milestone-1.md §7). `desktop-ready.sh`
(Hyprland `exec-once`, owned by the compositor/image work) waits on that
file — fallback `pgrep quickshell` — then screenshots via grim and touches
`/run/punar/desktop-ready`, which the root marker unit turns into
`PUNAR_DESKTOP_OK` on serial. On dev machines without `/run/punar` the
touch fails harmlessly.

## Linting

All five `.qml` files pass `qmllint` with **zero warnings** (qmllint 6.11.2 /
quickshell 0.3.0-3 from the pinned 2026/08/20 snapshot, run in the pinned
builder base container; default import path — Quickshell ships qmldir +
qmltypes under `/usr/lib/qt6/qml/Quickshell`, so no extra `-I` is needed):

```sh
qmllint shell.qml Bar/Bar.qml CommandCenter/CommandCenter.qml \
        Theme/Theme.qml Services/Status.qml   # run from this directory
```

[`.qmllint.ini`](.qmllint.ini) makes exactly one targeted downgrade —
`UncreatableType=disable` — because Quickshell registers `PanelWindow` with
`isCreatable: false` in its own qmltypes (instances are built by Quickshell's
window-proxy machinery at runtime, so the warning is unresolvable noise for
any Quickshell shell). Every other category stays at its default; new
warnings are fixed in code, never silenced.

## Known deviations from the mockup (deliberate, M1)

- The card's soft drop shadow is omitted: blur effects are costly on the
  llvmpipe VM rendering path (PERFORMANCE_BUDGETS.md); the 22% ink-wash
  scrim plus hairline border carries the separation.
- Mockup fractional font sizes round to whole pixels (8.5→9, 14.5→15,
  16.5→17) — `font.pixelSize` is integral.
- No battery/net widgets in the bar (calm beats complete; the VM target has
  neither) and no execution toast — launching closes the overlay.
- The "Recent / Suggested / Intent / Question" demo states of the mockup
  need punard (M3+); M1 ships the Applications + Punar action groups.
