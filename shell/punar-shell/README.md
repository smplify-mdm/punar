# punar-shell

The Punar desktop shell for Milestones 1–2: a Quickshell (QML) top bar, the
SUPER+Space command center overlay, and the SUPER+TAB project-workspace
overview with named-workspace persistence, implementing the field-note
design language.

- Design authority: [`docs/design/DESIGN_LANGUAGE.md`](../../docs/design/DESIGN_LANGUAGE.md)
  (binding) and the mockups — the command-center card is
  [`docs/design/mockups/command-approval.html`](../../docs/design/mockups/command-approval.html)
  Sect I (M1), and the overview is
  [`docs/design/mockups/desktop-multitasking.html`](../../docs/design/mockups/desktop-multitasking.html)
  state 03 OVERVIEW / Plate D-007 (M2 acceptance reference).
- Every design value flows through the `Theme` singleton, which loads
  [`shell/theme/punar-tokens.json`](../theme/punar-tokens.json) at runtime.
  No color is hardcoded outside `Theme/Theme.qml` (DESIGN_LANGUAGE.md §8).

## Layout

| File | Role |
| --- | --- |
| `shell.qml` | `ShellRoot` entrypoint; wires the ready marker; instantiates `WorkspaceState` |
| `Theme/Theme.qml` | Singleton: token loader + typed design properties |
| `Services/Status.qml` | Singleton: compliance/project context — **M1 stub**, M5 wires punard |
| `Services/WorkspaceState.qml` | Singleton: workspace-name persistence + restore (M2, milestone-2.md §6) |
| `Bar/Bar.qml` | Top bar (30px paper masthead, hairline rule; active workspace NAME) |
| `CommandCenter/CommandCenter.qml` | SUPER+Space overlay + `commandcenter` IPC handler |
| `Overview/Overview.qml` | SUPER+TAB project-workspace overview + `overview` IPC handler (Plate D-007) |

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

Toggle the command center or the overview from another terminal:

```sh
qs ipc call commandcenter toggle
quickshell ipc call overview toggle    # SUPER+TAB binding; `qs` works too
qs ipc call overview state             # prints "open" or "closed" (CI probe)
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

## Overview — SUPER+TAB (M2, Plate D-007)

`SUPER+TAB` → Hyprland runs `quickshell ipc call overview toggle`
(IpcHandler target `overview`, functions `toggle`/`open`/`close` plus the
read-only `state`, which returns `open`/`closed` for the CI check). The
overlay is a paper sheet over the 22% warm ink-wash scrim, holding a
4-column grid of project-workspace cards:

- **Live data, no polling** (milestone-2.md §5): on open the QML calls
  `Hyprland.refreshWorkspaces()` + `Hyprland.refreshToplevels()` once, then
  binds to the `Quickshell.Hyprland` models — socket2 events keep names,
  membership, and titles current between opens; geometry is refreshed on
  each open. No `hyprctl` parsing anywhere.
- **Cards** (workspaces with `id >= 1`; specials hidden, sorted by id) are
  field-note mini plates: a 16:10 wireframe of the workspace's real window
  layout — each client's `at`/`size` normalized by its monitor's logical
  dimensions; floating windows drawn above tiled with the stronger border,
  group slabs carrying a tab notch — then the masthead meta row
  (`N · NAME`, tracked mono, uppercase) and a second line with window
  count · last window title.
- **Empty workspaces render as dashed outlines** — the honesty grammar:
  dashed means nothing is there.
- **Selection** = raise fill + 2 px ink rule + slight scale (150 ms micro
  token). Open/close motion is the 300 ms `cubic-bezier(0.2,0,0,1)` token
  curve. Nothing else animates.
- **Keys**: arrows move the selection (`H/J/K/L` too while the search is
  empty), typing filters cards by name live (the greeter's underline field
  grammar), `Enter` dispatches `workspace <id>` and closes, `R` (search
  empty) begins an inline rename in the card masthead — `Enter` commits
  via `renameworkspace`, `Esc` cancels; an invalid name is refused and the
  underline turns status-bad — and `Esc` closes the overview.

## Named workspaces + state file (M2)

`Services/WorkspaceState.qml` owns `~/.local/state/punar/workspaces.json`
(schema v1, milestone-2.md §6 — the shell is the file's only writer in M2):

```json
{
  "version": 1,
  "updated": "2026-08-25T09:30:00Z",
  "layoutPreset": "balanced",
  "workspaces": [ { "id": 1, "name": "atlas" } ]
}
```

- **Restore on shell start**: stored names are applied via
  `Hyprland.dispatch("renameworkspace <id> <name>")` to workspaces that
  exist and are unnamed (a live name always wins); workspaces created
  later pick their stored names up via `createworkspacev2`. Missing or
  corrupt file → fresh default (workspace 1 = `Punar`). A file with
  `version > 1` is neither restored from nor overwritten.
- **Write triggers**: a `renameworkspace` socket2 event, or a change of
  the layout-preset cache (`$XDG_RUNTIME_DIR/punar/layout-preset`, written
  by `punar-layout.sh` and watched via inotify — event-driven, not
  polling). Writes are debounced 1 s (one-shot timer, never periodic) and
  atomic: `FileView` `atomicWrites` (QSaveFile tmp+rename; parent
  directories created). Entries are sorted by id, only real names persist
  (never specials, never Hyprland's implicit numeric names), names match
  `^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$` (no commas — the socket2 rename
  event frames as `ID,NAME`), and stored names for workspaces not yet
  recreated this session are retained across rewrites.
- **Bar**: the masthead shows the active workspace NAME when one is set,
  falling back to the number — live via the same socket2 events.
- The `layoutPreset` value itself is applied at session start by
  `punar-layout.sh restore` (not by the shell); the shell only records it.

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

All seven `.qml` files pass `qmllint` with **zero warnings** (qmllint 6.11.2 /
quickshell 0.3.0-3 from the pinned 2026/08/20 snapshot, run in the pinned
builder base container; default import path — Quickshell ships qmldir +
qmltypes under `/usr/lib/qt6/qml/Quickshell`, so no extra `-I` is needed):

```sh
qmllint shell.qml Bar/Bar.qml CommandCenter/CommandCenter.qml \
        Overview/Overview.qml Theme/Theme.qml \
        Services/Status.qml Services/WorkspaceState.qml   # from this directory
```

[`.qmllint.ini`](.qmllint.ini) makes exactly one targeted downgrade —
`UncreatableType=disable` — because Quickshell registers `PanelWindow` with
`isCreatable: false` in its own qmltypes (instances are built by Quickshell's
window-proxy machinery at runtime, so the warning is unresolvable noise for
any Quickshell shell). Every other category stays at its default; new
warnings are fixed in code, never silenced.

## Known deviations from the mockups (deliberate)

- The card's soft drop shadow is omitted: blur effects are costly on the
  llvmpipe VM rendering path (PERFORMANCE_BUDGETS.md); the 22% ink-wash
  scrim plus hairline border carries the separation.
- Mockup fractional font sizes round to whole pixels (8.5→9, 14.5→15,
  16.5→17) — `font.pixelSize` is integral.
- No battery/net widgets in the bar (calm beats complete; the VM target has
  neither) and no execution toast — launching closes the overlay.
- The "Recent / Suggested / Intent / Question" demo states of the mockup
  need punard (M3+); M1 ships the Applications + Punar action groups.
- Overview (M2): the sheet omits the drop shadow for the same llvmpipe
  reason; `H/J/K/L` navigate only while the search field is empty — once
  typing has begun, letters belong to the query (D-007 register 02: typing
  searches); the card meta row prints window count · last window title —
  agent presence (`agt_123 · active`) needs the M7 registry and is not
  claimed before it exists; the empty fourth-card "Temporary activity"
  plate (§14.4, drawn dashed in the mockup) is future scope and is not
  rendered.
