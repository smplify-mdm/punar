# punar-shell

The Punar desktop shell: a Quickshell (QML) top bar (M1, with the M5
enrollment chrome), the SUPER+Space command center overlay, the
SUPER+TAB project-workspace overview with named-workspace persistence
(M2), and the SUPER+A AI panel (M7), implementing the field-note design
language.

- Design authority: [`docs/design/DESIGN_LANGUAGE.md`](../../docs/design/DESIGN_LANGUAGE.md)
  (binding) and the mockups — the command-center card is
  [`docs/design/mockups/command-approval.html`](../../docs/design/mockups/command-approval.html)
  Sect I (M1), the overview is
  [`docs/design/mockups/desktop-multitasking.html`](../../docs/design/mockups/desktop-multitasking.html)
  state 03 OVERVIEW / Plate D-007 (M2 acceptance reference), and the AI
  panel is [`docs/design/mockups/ai-panel.html`](../../docs/design/mockups/ai-panel.html)
  / Plate D-005 (M7 acceptance reference).
- Every design value flows through the `Theme` singleton, which loads
  [`shell/theme/punar-tokens.json`](../theme/punar-tokens.json) at runtime.
  No color is hardcoded outside `Theme/Theme.qml` (DESIGN_LANGUAGE.md §8).

## Layout

| File | Role |
| --- | --- |
| `shell.qml` | `ShellRoot` entrypoint; wires the ready marker; instantiates `WorkspaceState` |
| `Theme/Theme.qml` | Singleton: token loader + typed design properties |
| `Services/Status.qml` | Singleton: enrollment/compliance context — watches `/run/punar/status.json` (M5, ipc.md §9) |
| `Services/WorkspaceState.qml` | Singleton: workspace-name persistence + restore (M2, milestone-2.md §6) |
| `Services/Agents.qml` | Singleton: AI-panel display state — watches `/run/punar/agents.json` (M7, ipc.md §11) |
| `Services/Ledger.qml` | Singleton: AI access-ledger display state — watches `/run/punar-agentd/ledger.json` (M8, ipc.md §13.2) |
| `Services/Approvals.qml` | Singleton: approval + grant display state — watches `/run/punard/approvals.json` (M9, ipc.md §15) |
| `Bar/Bar.qml` | Top bar (30px paper masthead, hairline rule; active workspace NAME; org chrome when enrolled) |
| `CommandCenter/CommandCenter.qml` | SUPER+Space overlay + `commandcenter` IPC handler |
| `Overview/Overview.qml` | SUPER+TAB project-workspace overview + `overview` IPC handler (Plate D-007) |
| `AiPanel/AiPanel.qml` | SUPER+A AI panel + `aipanel` IPC handler (Plate D-005) |
| `Approval/ApprovalOverlay.qml` | The M9 approval gate + `approval` IPC handler (Plate D-003 Sect II) |

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
qs ipc call aipanel toggle             # SUPER+A binding
qs ipc call aipanel state              # prints "open" or "closed" (CI probe)
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

- The **approval overlay has no opening keybinding, on purpose**: it opens
  itself whenever punard records something pending, because a gate the
  human has to go looking for is not a gate. In it: `A` approves, `D`
  denies, `↑`/`↓` cycle when more than one is pending, and `Esc` **defers**
  — dismissal is not denial, and the request stays pending in the daemon.

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

## Enrollment chrome (M5)

`Services/Status.qml` (the M1 stub, retired in M5) is the single source of
enrollment/compliance display state, fed by punard's summary file
`/run/punar/status.json` (side contract:
[`docs/api/ipc.md`](../../docs/api/ipc.md) §9; design:
milestone-5.md §8):

```json
{"v": 1, "enrolled": true, "org_name": "Acme Engineering",
 "compliance_overall": "compliant", "ts": "2026-08-26T09:02:00Z"}
```

- **Event-driven, zero polling**: punard rewrites the file atomically
  (tmp+rename) at startup and on every change of the summary tuple; the
  singleton follows it with a `FileView` change watch (inotify — the same
  primitive `WorkspaceState.qml` uses for the layout-preset cache). No
  timers, no socket connection from the shell.
- **Fail closed to personal** (DESIGN_LANGUAGE.md §8, unmanaged-first): a
  missing or unparsable file — personal device, punard not running on a
  dev machine, torn state — reads as `enrolled: false` and the bar is calm
  paper. Org state is additive annotation; its absence is the default.
- **Mapping**: `compliance_overall` → `state` (`compliant`→ok,
  `non_compliant`→bad, anything else — `remediating`/`exception`/
  `unknown`/future — →warn) and the §52 word `label`
  (Compliant / Non-compliant / Remediating / Exception / Unknown). The
  raw value is exposed as `complianceState`; `""` is the personal
  sentinel, under which state/label keep the pre-M5 stub defaults so
  unenrolled surfaces (the command-center masthead) render unchanged. An
  enrolled device with a garbled overall shows UNKNOWN — never silently
  green.
- **Bar grammar when enrolled** (system-control mockup masthead,
  compressed to bar scale): `ACME ENGINEERING · ● COMPLIANT · 14:02` —
  one `MetaLabel` (org name) added before the existing dot + word, all
  gated on `Status.enrolled`. Policy ids stay in `punarctl status`, not
  the 30 px bar. The personal bar renders byte-identical to pre-M5: Row
  positioners skip invisible items.
- The file is **non-authoritative display data** in a user-owned
  directory (ipc.md §9's honest placement note); anything root-trusted
  stays on the punard socket.

## AI panel — SUPER+A (M7, Plate D-005)

`SUPER+A` → Hyprland runs
`qs -p /usr/share/punar/shell ipc call aipanel toggle` (IpcHandler target
`aipanel`, functions `toggle`/`open`/`close` plus the read-only `state`,
which returns `open`/`closed` for the `m7-check` probe). The panel is a
full paper surface over the 22% ink-wash scrim — spec §19 (registry),
§20 (authority) and §21 (the ledger boundary) on one keyboard-first
screen:

- **Masthead**: `PUNAR · AI ON THIS DEVICE`, the mode line, and the
  session counts. Unmanaged-first (DESIGN_LANGUAGE.md §8): the mode line
  reads `PERSONAL` and the counts read `N SESSIONS · M UNKNOWN`; only
  when `Status.enrolled` does the org name replace `PERSONAL` and the
  counts read `N MANAGED`. The unknown count is the one place color
  enters the masthead, and only while it is non-zero.
- **Agent rail** — one row per registry session and per detection, with
  `SESSIONS` / `UNKNOWN` section headers. Managed rows are calm with the
  green presence dot; ended sessions take the grey dot; observed rows
  stay quiet ink; unknown rows are the red voice — the only red on the
  surface. Each row carries the D-005 register-01 fields (name, project,
  session id, classification, status) across two meta lines, because a
  real `agt_` id is twelve hex digits and truncating an identifier is
  worse than a taller row.
- **Detail pane** — the attribution chain as the masthead
  (`AGT_… · USER · ENVIRONMENT · STARTED HH:MM`, spec §22/§47), then
  `AUTHORITY · WHAT IT MAY ACCESS` with the §20 decision words as
  tracked mono in their status colors (`ALLOWED` green, `DENIED` red,
  `APPROVAL REQUIRED` amber, `READ` plain) over the raw policy zone, the
  `POLICY · PERSONAL DEFAULTS` / `POLICY · ENG-AI-V3` citation in the
  section tagline, and **every row's `declared · M9/M12` enforcement
  label**. Nothing here is enforced in M7 and no row is drawn without
  saying so (spec §1.22).
- **Ledger** — `LEDGER · WHAT IT ACCESSED` is a **dashed** card reading
  `NOT YET RECORDED · MILESTONE 8`. The May/Did split (§21) is
  structural: two ruled sections, each with its question in the header.
  Dashed means "not real yet" — the same honesty grammar the overview
  uses for empty workspaces.
- **Unknown detail** — the D-005 unknown card: `UNKNOWN AI ACTIVITY`,
  the `UNMANAGED · SUSPECTED` pill, the executable path (printed in its
  real case — the meta grammar uppercases labels, never evidence), the
  matched signature id, and the §23 honesty card
  (`DETECTION IS HEURISTIC — SUSPECTED, NOT CERTAIN`). No green anywhere
  on this view. The mockup's `Inspect` / `Block network` /
  `Register as managed` buttons are **not rendered**: those capabilities
  arrive with M9/M10, and this release ships no dead buttons.
- **Keys**: `↑`/`↓` (and `K`/`J`) move the rail selection, `Home`/`End`
  jump, `Esc` closes. No mouse is required (spec §12); a scrim click
  still dismisses.

### Data — `/run/punar/agents.json` (M7, ipc.md §11)

`Services/Agents.qml` is the single source of the panel's display state,
fed by `punar-agentd`'s summary file — the AI-panel sibling of
`status.json`:

```json
{"v": 1, "scanned_at": "…", "policy_citation": "personal-defaults",
 "counts": {"managed": 1, "observed": 0, "unknown": 1},
 "sessions": [{"session_id": "agt_…", "agent": "claude-code",
   "project": "atlas", "environment": "punar-env-atlas",
   "classification": "managed", "status": "active", "started_at": "…",
   "authority": {"policy_citation": "…", "rows": [
     {"zone": "filesystem.project", "decision": "read_write",
      "enforcement": "declared · M9"}]}}],
 "detections": [{"session_id": "agt_…", "agent": "foo-agent",
   "classification": "unknown", "suspected": true,
   "executable": "/home/punar/Downloads/foo-agent",
   "signature_id": "downloads-foo-agent", "observed_at": "…"}],
 "ts": "…"}
```

- **Event-driven, zero polling**: agentd rewrites the file atomically
  (tmp+rename) at startup and on every registry change; the singleton
  follows it with a `FileView` change watch (inotify — the `Status.qml`
  pattern). No timers, no socket client in the shell. The masthead's
  `SystemClock` is `enabled` only while the panel is open.
- **Freshness on user action, not on a clock**: opening the panel
  re-reads the file once and `execDetached`s a single
  `punarctl agents list --json` (fixed argv — the shell never composes a
  shell string), whose staleness rule (ipc.md §10.2) triggers agentd's
  scan; the rewrite arrives through the FileView.
- **Fail closed**: a missing or unparsable file renders the calm empty
  panel — `NO AGENT SESSIONS`, `LAST SCAN · NEVER` — never an error
  surface. Absent fields are simply not printed rather than guessed at;
  an unrecognised decision value is printed verbatim.
- The file is **non-authoritative display data** in a user-owned
  directory (the §9 caveat verbatim); anything root-trusted stays on the
  agentd socket. It carries no pids, no cmdlines, no secrets and no
  ledger data.

## Approval gate + elevation chip (M9, Plates D-003 / D-012)

`Approval/ApprovalOverlay.qml` is the local graphical approval of spec §28,
and it is a **gate, not a notification**: the capability behind it has
already been refused and does not execute until a human answers. The
overlay therefore appears **unbidden** whenever `pending > 0`.

The card is Plate D-003 Sect II register by register — masthead
`APPROVAL · apr_…` with a count badge when more than one is waiting, the
risk pill, a live countdown in tabular mono that turns **warn-amber under
a minute**, the identity chain on one line, the request sentence in the
system voice, the requester's own reason **quoted and attributed**, the
contract block between hairlines naming the exact typed call plus the
policy citation and `RECORDED TO LOCAL AUDIT EITHER WAY`, and the action
pair (green filled `APPROVE · A`, red ghost `DENY · D`). Once resolved the
actions give way to the verdict, carrying the audit pointer
(`✓ APPROVED · SETFIREWALL(DISABLED) EXECUTED · AUDIT EVT_501`).

**The reason is shown, and quarantined.** §73 requires *why* and *who
requested it*, and a gate whose justification is hidden is a rubber stamp
— but for an agent-originated approval the reason is text an AI wrote. So
punard validates it at creation (one line, ≤512 bytes, no control
characters) and this surface renders it in a *quoted requester voice*:
plain non-interactive `Text` with `textFormat: Text.PlainText`, italic
sans behind a hairline, never the tracked mono the system speaks in.
System prose and requester prose never share a typeface here, so agent
text can never be read as an OS statement.

**Nothing here decides anything.** `A` and `D` run
`punarctl approvals resolve <id> --decision …` **detached, with fixed
argv**, sending only the `approval_id`; punard re-derives the contract from
its own record and re-checks every authorization rule — including that an
AI agent may resolve nothing, ever (ipc.md §14.5). The overlay never reads
the process result: the next `FileView` change is the truth.

**One timer, with a visible consumer.** A 1 Hz countdown runs only while
the overlay is open with something actionable, and stops otherwise. Past
zero the card reads `EXPIRED · DENIED BY TIMEOUT` immediately whether or
not punard has swept yet (ipc.md §14.4) — the daemon's `expired` answer
then makes it official.

`Bar/Bar.qml` carries Plate D-012 Sect I.03's elevation chip:
`● ELEVATED · 14:32 REMAINING`, green while a just-in-time grant is alive,
amber in its final minute, **gone** the moment it lapses. Its second hand
is a `SystemClock` whose `enabled` is bound to the existence of a grant,
so an unelevated device pays nothing for it and an unelevated bar is
byte-identical to the pre-M9 bar. Privilege is never invisible on this
device, and there is no generic unrestricted root-shell API behind it.

### Data — `/run/punard/approvals.json` (M9, ipc.md §15)

Deliberately **not** in `/run/punar` alongside `status.json` and
`agents.json`. That directory is `0755 punar:punar`, so a local process
could unlink a file there and bind its own. For a counts fingerprint that
is a nuisance; for the file that tells a human *what they are about to
authorize* it is a spoofing primitive — show a benign contract block over
a dangerous `apr_` id and the human presses `A`. So the summary lives at
`0640 root:punar` inside the root-owned `/run/punard`, exactly the
reasoning that put `ledger.json` in `/run/punar-agentd`.

It is still **non-authoritative**: display data, watched with an inotify
`FileView`, with no socket client in the shell. Missing or unparsable
reads as *nothing is pending* — fail closed, never an error surface and
never a spurious gate.

IPC probes (the `aipanel` / `overview` precedent):

```sh
qs -p /usr/share/punar/shell ipc call approval open      # also: close, toggle
qs -p /usr/share/punar/shell ipc call approval state     # open | closed
qs -p /usr/share/punar/shell ipc call approval pending   # count
qs -p /usr/share/punar/shell ipc call approval selected  # the apr_ on screen
```

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

All twelve `.qml` files pass `qmllint` with **zero warnings** (qmllint 6.11.2 /
quickshell 0.3.0-3 from the pinned 2026/08/20 snapshot, run in a container
built on the pinned builder base with `qt6-declarative` + `quickshell`
installed from the same snapshot; default import path — Quickshell ships
qmldir + qmltypes under `/usr/lib/qt6/qml/Quickshell`, so no extra `-I` is
needed; the binary lives at `/usr/lib/qt6/bin/qmllint`):

```sh
qmllint shell.qml AiPanel/AiPanel.qml Approval/ApprovalOverlay.qml \
        Bar/Bar.qml CommandCenter/CommandCenter.qml Overview/Overview.qml \
        Theme/Theme.qml Services/Agents.qml Services/Approvals.qml \
        Services/Ledger.qml Services/Status.qml \
        Services/WorkspaceState.qml                       # from this directory
```

[`.qmllint.ini`](.qmllint.ini) makes exactly one targeted downgrade —
`UncreatableType=disable` — because Quickshell registers `PanelWindow` with
`isCreatable: false` in its own qmltypes (instances are built by Quickshell's
window-proxy machinery at runtime, so the warning is unresolvable noise for
any Quickshell shell). Every other category stays at its default; new
warnings are fixed in code, never silenced.

Beyond linting, the M7 panel was also exercised **headlessly on the
maintainer's machine** as a local pre-flight: the same pinned container
plus `sway` (headless wlroots backend — Quickshell needs wlr-layer-shell,
which weston does not provide), `qs -p shell/punar-shell`, `wtype` for
keys and `grim` for captures. That run is ad-hoc and non-authoritative
per spec 1.22 — the in-VM `m7-check` remains the arbiter — but it did
prove, against a fixture `agents.json`, that the shell loads with **no
QML errors and no binding loops**, that `aipanel state/open/close/toggle`
answer correctly, that `↑`/`↓` move the rail selection and `Esc` closes,
and that deleting `agents.json` fails closed to the empty panel.

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
- AI panel (M7): the same drop-shadow omission. Rail rows print the
  registry's `agent` value verbatim (`claude-code`) rather than the
  mockup's prettified `Claude Code` — the identifier is what
  `punarctl agents inspect` takes and what `registry.jsonl` stores, and
  CLI/UI parity beats typography here. The mockup's live credential
  countdown (`EXPIRES 41:32`) is not rendered: M7 issues no credentials,
  so there is no clock to show; the same goes for the ledger's resource
  summaries, security-event rows and admin-query card (all M8, replaced
  by the one dashed placeholder) and the unknown card's observed-access
  rows (no ledger data exists to fill them). The unknown card's action
  buttons are omitted — those capabilities are M9/M10. The mockup's
  device line (`ThinkPad X1 · dev_123 · Acme Engineering`) shows only the
  mode/org part: the shell has no trustworthy device identity to print
  yet, and inventing one would be the wrong kind of fidelity.
- Approval overlay (M9): the same drop-shadow omission. D-003's identity
  chain ends at a human's email address (`alice@acme.com`); the card
  prints whatever the record actually carries, which on a personal device
  is the local user name — an email the shell has not been given is not
  invented. Plate D-003 Sect III lists the multi-approval queue under
  "states not drawn": M9 ships the count badge and `↑`/`↓` cycling, and
  the fuller queue UI stays future scope.
- Elevation chip (M9): D-012 binds `R` to revoke. The bar is a
  non-focusable layer surface, and making it grab the keyboard to own one
  letter would break every other keystroke on the desktop — so the chip
  revokes on a **two-step click** (the first arms and the chip asks, the
  second acts, the AI panel's `SHIFT+DEL` precedent) and the keystroke
  ships with the graphical elevation dialog (M13). The verb itself is
  already real: `punarctl privilege revoke <gnt_id>`, which is exactly
  what the chip runs. D-012's elevation *dialog* and the graphical broker
  issuance card are not drawn in M9 either; the CLI renders the issuance
  card on stderr, and the dialog is M13.
