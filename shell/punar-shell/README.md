# punar-shell

The Punar desktop shell, in ONE process: the wallpaper, the top bar and
its live status cluster, the SUPER+Space command center, the SUPER+TAB
project overview, SUPER+S system control, the SUPER+A AI panel, the
approval gate, the shadow-AI alert region, the freedesktop notification
daemon with its toasts / centre / OSD, the SUPER+/ shortcut help, the
session lock, and the theme system — all implementing the field-note
design language.

**The composed, human-readable status record — what each surface is, its
IPC target, its chord, its data source, whether it is REAL or honestly
unavailable, and what to press in the VM — lives in
[`docs/development/desktop-surfaces.md`](../../docs/development/desktop-surfaces.md).**
That page, not this one, is the one to hand somebody sitting in front of
the machine.

- Design authority: [`docs/design/DESIGN_LANGUAGE.md`](../../docs/design/DESIGN_LANGUAGE.md)
  (binding) and the mockups — the command-center card is
  [`docs/design/mockups/command-approval.html`](../../docs/design/mockups/command-approval.html)
  Sect I (M1), the overview is
  [`docs/design/mockups/desktop-multitasking.html`](../../docs/design/mockups/desktop-multitasking.html)
  state 03 OVERVIEW / Plate D-007 (M2 acceptance reference), and the AI
  panel is [`docs/design/mockups/ai-panel.html`](../../docs/design/mockups/ai-panel.html)
  / Plate D-005 (M7 acceptance reference), and the shadow-AI alert card is
  [`docs/design/mockups/notifications-osd.html`](../../docs/design/mockups/notifications-osd.html)
  Sect I / Plate D-009 (M10 acceptance reference).
- Every design value flows through the `Theme` singleton, which loads
  [`shell/theme/punar-tokens.json`](../theme/punar-tokens.json) plus the
  active theme document from [`shell/theme/themes/`](../theme/themes) at
  runtime. No color is hardcoded outside `Theme/Theme.qml`
  (DESIGN_LANGUAGE.md §9.1).
- Shell surfaces consume the **mood-aware** token set (`Theme.shellFg`,
  `shellSurface`, `shellInk2/3`, `shellBorder`, `shellStatus*`,
  `shellAction*`, `shellScrim`, …), so a user who selects a panel-mood
  theme gets a dark shell, not a dark desktop with light panels. The
  literal `paperX` / `panelX` accessors still exist and are correct for a
  surface that is pinned to one block by the §6 surface-assignment table —
  which today is exactly one surface, `Notifications/Osd.qml`, because an
  OSD overlay is a plate.

## Layout

| File | Role |
| --- | --- |
| `shell.qml` | `ShellRoot` entrypoint; wires the ready marker; instantiates `WorkspaceState` |
| `Theme/Theme.qml` | Singleton: token loader + typed design properties |
| `Services/Status.qml` | Singleton: enrollment/compliance context — watches `/run/punar/status.json` (M5, ipc.md §9) |
| `Services/WorkspaceState.qml` | Singleton: workspace-name persistence + restore (M2, milestone-2.md §6) |
| `Services/WallpaperState.qml` | Singleton: four-entry wallpaper catalog + atomic user preference + `wallpaper` IPC handler |
| `Services/Agents.qml` | Singleton: AI-panel display state — watches `/run/punar/agents.json` (M7, ipc.md §11) |
| `Services/Ledger.qml` | Singleton: AI access-ledger display state — watches `/run/punar-agentd/ledger.json` (M8, ipc.md §13.2) |
| `Services/Approvals.qml` | Singleton: approval + grant display state — watches `/run/punard/approvals.json` (M9, ipc.md §15) |
| `Services/Alerts.qml` | Singleton: shadow-AI alert display state — watches `/run/punar-agentd/alerts.json` (M10, ipc.md §20) |
| `Bar/Bar.qml` | Top bar (30px paper masthead, hairline rule; active workspace NAME; org chrome when enrolled) |
| `CommandCenter/CommandCenter.qml` | SUPER+Space overlay + `commandcenter` IPC handler |
| `Overview/Overview.qml` | SUPER+TAB project-workspace overview + `overview` IPC handler (Plate D-007) |
| `AiPanel/AiPanel.qml` | SUPER+A AI panel + `aipanel` IPC handler (Plate D-005) |
| `Approval/ApprovalOverlay.qml` | The M9 approval gate + `approval` IPC handler (Plate D-003 Sect II) |
| `Alert/AlertStack.qml` | The M10 shadow-AI alert region + `alerts` IPC handler (Plate D-009 Sect I) |
| `Theme/ThemeContrast.qml` | Singleton: the WCAG contrast gate (R1–R9) that refuses an illegible palette before a human sees it |
| `Services/Apps.qml` | Singleton: desktop-entry lookup + browser-by-role resolution for the command center |
| `Services/Notifications.qml` | Singleton: the freedesktop notification **daemon** (`org.freedesktop.Notifications`) + bus-owner probe |
| `Wallpaper/Wallpaper.qml` | The desktop field, one background layer window per output; one active asset, zero timers |
| `Bar/StatusCluster.qml` · `StatusSlot.qml` · `SlotPopover.qml` | The live right-hand cluster, its slots and their popover (Plate D-016) |
| `CommandCenter/Actions.qml` · `ExplainCard.qml` | The six-kind typed action taxonomy and the §40 policy-explain card (Plate D-003) |
| `SystemControl/SystemControl.qml` | SUPER+S settings surface + `systemcontrol` IPC handler (Plate D-004) — holds every colour, decides nothing |
| `SystemControl/ControlData.qml` | Everything that panel KNOWS: file watches, `punarctl` probes, the view model, the mutations — holds no colour |
| `Notifications/ToastStack.qml` | Transient toasts + `toasts` IPC handler (Plate D-009 Sect II) |
| `Notifications/NotificationCenter.qml` | SUPER+SHIFT+N record + `notifications` IPC handler |
| `Notifications/Osd.qml` | Volume/brightness OSD + `osd` IPC handler — the one PANEL-voice surface |
| `Shortcuts/Shortcuts.qml` · `BindTable.qml` · `BindRow.qml` · `ChordCap.qml` | SUPER+/ help, generated from `hyprctl binds -j` + `shortcuts` IPC handler (Plate D-017) |
| `Lock/Lock.qml` · `LockSurface.qml` | The real `ext-session-lock-v1` lock, authenticated through PAM + `lock` IPC handler (Plates D-002 / D-012) |

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

## Keyboard contract (no mouse required — spec §12)

Every chord below is bound in
[`os/modules/desktop/hypr/punar-binds.conf`](../../os/modules/desktop/hypr/punar-binds.conf)
in the **described** form, so `hyprctl binds -j` carries a human label and
the SUPER+/ help surface renders the live table rather than a written copy
of it. **If this list and the machine disagree, the machine is right.**

| Chord | Surface |
| --- | --- |
| `SUPER + Space` | Command center |
| `SUPER + Tab` | Project overview |
| `SUPER + A` | AI panel |
| `SUPER + S` | System control |
| `SUPER + /` | Shortcut help |
| `SUPER + SHIFT + N` | Notification centre (the plate asks for `SUPER+N`; the notes scratchpad has held it since M2) |
| `SUPER + SHIFT + B` | Focus the bar's status cluster (the plate asks for `SUPER+B`; the browser has held it since M1) |
| `SUPER + Escape` | Lock the session (`SUPER+L` and its SHIFT/CTRL variants are all load-bearing in the §13.3 directional grammar) |
| media keys | Volume up / down / mute — the OSD reads the **sink**, not the keypress |

Two surfaces deliberately have **no chord at all** — see below.

- `SUPER+Space` → Hyprland runs `qs ipc call commandcenter toggle`.
- In the overlay: typing filters, `↑`/`↓` select (animated highlight),
  `Enter` launches, `Esc` closes. A scrim click also dismisses, but nothing
  requires the mouse.

- The **approval overlay has no opening keybinding, on purpose**: it opens
  itself whenever punard records something pending, because a gate the
  human has to go looking for is not a gate. In it: `A` approves, `D`
  denies, `↑`/`↓` cycle when more than one is pending, and `Esc` **defers**
  — dismissal is not denial, and the request stays pending in the daemon.

- The **alert region has no opening keybinding either**, for the same
  reason: punar-agentd raises a card by writing `alerts.json`, and the
  card appears. On it: `I` inspects (the SUPER+A panel, opened on that
  detection), `D` dismisses to the record, `↑`/`↓` walk a multi-card
  stack, and `Esc` **hands the keyboard back without dismissing
  anything** — the card, the record and the alert register all stay.

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

## Shadow-AI alert region (M10, Plate D-009 Sect I)

One layer-shell region at the D-009 toast position (top 13%, right 3.4%,
`min(46%, 340px)` wide), rendering **only** `punar-agentd` detection
alerts. It is the sliver `milestone-10.md` §5.6 names and nothing beside
it: there is still no notification centre, no freedesktop notification
daemon, no OSD, no `Super+N` and no persistent do-not-disturb toggle —
all four are M13.

The card is the D-009 anatomy: **meta row · hairline · one sentence ·
detail · why · policy · actions · footer**.

```
UNKNOWN AI · SUSPECTED                                        14:31
────────────────────────────────────────────────────────────────────
Unknown AI activity suspected · foo-agent

~/Downloads/foo-agent · running as punar since 14:29
Why · an agent-named executable is running from Downloads, outside any
managed Punar session · signature unmanaged-path-agentlike
Policy · Personal defaults

[ INSPECT I ]  SUPER+A   [ DISMISS TO RECORD D ]
────────────────────────────────────────────────────────────────────
Suspected, not certain · nothing was blocked · punarctl agents list
Punar · punar-agentd
```

Voice rules, from `milestone-10.md` §5.1 (spec §73, §23, §1.22):

- **"suspected" appears in the meta row and in the sentence.** Never
  "detected AI", never "malware", never "threat".
- **The subject of every sentence is the process, never the person.**
  This surface passes no verdict on a human.
- **"Nothing was blocked" is mandatory.** M10 detects, records and
  alerts; it blocks, kills and quarantines nothing. There are no
  `BLOCK NETWORK` / `REGISTER AS MANAGED` buttons — those need
  punar-netd (M12) and a policy verb, and no dead button ships.
- **Who requested it: nobody.** The footer names `Punar · punar-agentd`
  as the source group — this is the device's own observation.
- **Unmanaged-first (DESIGN_LANGUAGE §8):** the card renders *fully* on a
  personal device and cites `Personal defaults`; enrollment only adds the
  org citation and a `MANAGED` pill. The shell never upgrades a personal
  citation into an org one.

### Data — `/run/punar-agentd/alerts.json` (M10, ipc.md §20)

`0640 root:punar`, atomic tmp + fsync + rename, written **only when the
alert set changes**. Root-owned for the M9 reason restated: a forged card
reading *"Unknown AI activity suspected · your-bank-helper"* with an
Inspect action is a phishing primitive, and `/run/punar` is
`0755 punar:punar`. `Services/Alerts.qml` follows it with an inotify
`FileView` — event-driven, **zero polling, no socket client, no timers**.

**Fail closed:** a missing or unparsable file renders **no** alert, never
a placeholder alert. Dismissal sends only the `alert_id`
(`punarctl agents alerts dismiss <id>`, detached, fixed argv); the shell
does not read the result — the next `FileView` change is the truth.

**Anti-nag is the daemon's** (§5.2: one alert per `signature_id`, plus a
24 h quiet window). The stack keys every card by `alert_id` and remembers
which ids it has already presented, so no rewrite of the file can
re-toast a card the human has already been shown.

### Do-not-disturb (M10 sliver, §5.5 / §5.6)

DND here is **shell-local state with an IPC setter, no persistence, no
capability and no UI toggle** — the honest minimum that makes decision 8
verifiable. The rule: **the first sighting of a signature breaks through;
nothing else does.** The argument is spec §24.2 — from M10 on an
authorized administrator can query this exact fact, so a quiet-mode
toggle that could hide it would create a state in which the admin knows
about a process on this machine and the user does not.

Under DND the card renders **without sound** (this shell plays none),
**without focus steal** (a quiet raise never takes the keyboard) and
**without auto-dismiss**. There is in fact no auto-dismiss timer at all,
in either mode: M10 ships no notification centre, so a card that vanished
on its own would leave the reader nowhere to find what they were told.

IPC (`alerts` target), driven from CI with
`qs -p /usr/share/punar/shell ipc call alerts …`:

| Call | Behaviour |
| --- | --- |
| `open` | draw what is outstanding and take the keyboard (an explicit open is never quiet) |
| `close` | hide the region; **changes no record** — `punarctl agents alerts` still lists it |
| `state` | `open` / `closed` |
| `dnd on\|off\|toggle` | set shell-local DND; returns the resulting state |
| `cards` | ids currently drawn (read-only probe) |
| `quiet` | of those, the ids raised while DND was on |
| `focused` | the card under the cursor |

`cards` / `quiet` / `focused` exist for the same reason `approval
selected` does — a check must be able to assert what the human was
actually shown without a screenshot being the only evidence. `quiet` also
answers a question **agentd structurally cannot**: whether a raise broke
through quietly is shell-local by §5.6, and the daemon must never be told
to trust the shell about its own root-owned file.

## Command center action taxonomy

The two-entry static stub table is gone. Rows are produced from data in
[`CommandCenter/Actions.qml`](CommandCenter/Actions.qml) in exactly SIX
kinds, each with one execution mechanism and **no seventh "run this string"
escape hatch**. Every row prints its typed action, right-elided so the
action half survives truncation.

| Kind | Mechanism | Printed action |
| --- | --- | --- |
| `app` | `DesktopEntry.execute()` — the argv Quickshell parsed from `Exec`, never a shell string | `Launch(chromium)` |
| `project` | Hyprland `workspace <id>` (+ `renameworkspace <id> <name>` when allocating) | `OpenProject(atlas) · Workspace 2` |
| `surface` | `qs -p <shellDir> ipc call <target> open`, routed by `IpcHandler.target` | `Surface(systemcontrol) · Super S` |
| `layout` | `/usr/lib/punar/punar-layout.sh <preset>` | `SetLayout(columns)` |
| `wallpaper` | `WallpaperState.setWallpaper(<id>)` — finite installed catalog, atomic id preference | `SetWallpaper(stillpoint)` |
| `explain` | `punarctl --json policy explain <path>` | `PolicyExplain(security.firewall)` |

The browser is resolved **by role** — desktop-id list, then
`DesktopEntries.heuristicLookup`, then the freedesktop
`Categories=WebBrowser` sweep — so a machine with only Firefox resolves to
Firefox and a machine with none draws no row. No argv is hardcoded.

Surface availability is a fact rather than an assumption: one `qs ipc show`
on first open lists the targets THIS shell registered, and the parse is
anchored on `commandcenter` — if the surface cannot find its own target the
parse is judged wrong and every row stays solid as "unknown" rather than
falsely dashed. An absent target renders dashed with its milestone, and
Enter on it states the absence instead of doing nothing.

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

All **thirty-four** `.qml` files pass `qmllint` with **zero warnings** (qmllint 6.11.2 /
quickshell 0.3.0-3 from the pinned 2026/08/20 snapshot, run in a container
built on the pinned builder base with `qt6-declarative` + `quickshell`
installed from the same snapshot; default import path — Quickshell ships
qmldir + qmltypes under `/usr/lib/qt6/qml/Quickshell`, so no extra `-I` is
needed; the binary lives at `/usr/lib/qt6/bin/qmllint`):

The file list stopped being worth maintaining by hand once the tree
passed thirty files — enumerate it instead, from this directory, so a
newly added surface can never be quietly left out of the check:

```sh
find . -name '*.qml' -print0 | xargs -0 -n1 /usr/lib/qt6/bin/qmllint
```

`qmllint` 6.11 picks up [`.qmllint.ini`](.qmllint.ini) from the working
directory on its own — there is no `--config` flag to pass, and passing
one fails with `Unknown option 'config'`.

**A trap worth knowing before you write a new `Process` handler:**
`onExited`'s `QProcess::ExitStatus` parameter has no QML registration, so
any `onExited:` handler trips `[signal-handler-parameters]`. Read
completion from the stdout stream, from `onRunningChanged`, or from a
runtime `exited.connect(function (exitCode) { … })` instead — three
surfaces in this tree hit it independently and all three work around it
that way.

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
- Alert card (M10): **the plate's `→ api.foo.ai` is dropped.** D-009's
  subline reads `~/Downloads/foo-agent → api.foo.ai`; nothing on this
  device observes a network destination before M12, and the plate is the
  acceptance reference for *anatomy*, not a licence to print a field no
  code produced (spec §1.22, `milestone-10.md` §5.1). No destination —
  invented, inferred or fixture-borrowed — appears on the card. The same
  drop-shadow omission applies. The path is spelled `~/Downloads/…` when
  the record's own `owner` makes the tilde unambiguous (D-009's and §5.1's
  own spelling); anything outside that owner's home prints verbatim, and
  the untouched path is always in `punarctl agents alerts`. D-009's toast
  stack also carries an approval toast and a calm "screenshot saved"
  toast: neither is drawn here, because M10 ships the detection alert and
  nothing else — the approval surface stays the M9 gate. The `MANAGED`
  pill rides the **meta row** rather than the plate's action row: at
  340 px the action row is already full at `[I] Inspect · Super+A` +
  `[D] Dismiss to record`, and an annotation that overlaps a button is
  worse than one that sits a line higher. Nothing else moves.
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
