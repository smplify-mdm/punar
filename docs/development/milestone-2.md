# Milestone 2 — Native multitasking: capability check + integration plan

Status: **implemented 2026-08-25; runtime acceptance proven the same day
by the first desktop CI run that includes the M2 exercise.** That run
has happened:
[32825539021](https://github.com/smplify-mdm/punar/actions/runs/32825539021)
(2026-08-25, commit `5e1f5cb`, KVM runner, fully green) executed
`punar-m2-check` inside the booted `punar-desktop` VM and delivered
**`PUNAR_M2_OK`** — the §7 assertion list passed at runtime, including
state write/restore across a shell restart and the overview toggling
over IPC. Idle RAM measured **mean 1157 MB / max 1162 MB**: under the
1536 MB hard ceiling, over the 1024 MB target, recorded as a budget
warning, with no new always-on processes. Evidence ships as artifacts —
`punar-desktop-ram-report` (includes `m2-report.txt`) and
`punar-desktop-screenshot` (includes `punar-m2.png`). The desktop gate
itself was already proven infrastructure before that: the M1-scope
`desktop-test` job went green on 2026-08-25 (run
[32804034681](https://github.com/smplify-mdm/punar/actions/runs/32804034681)
— `PUNAR_DESKTOP_OK` after 18 s under KVM, idle RAM 1162 MB mean / 1168
MB max passing the budget gate with an over-target warning), a run that
**predates the M2 wiring**. The M2 workstreams (compositor config,
shell/overview, layout script, state/crate, CI check) have all landed
against the decisions fixed here: Hyprland grammar + `punar-layout.sh`
(verified against the pinned 0.56.2-1 binary via `--verify-config`), the
overview + `WorkspaceState` shell surfaces (qmllint-clean; state
behavior verified headlessly), the `punar-workspace` crate + JSON Schema
(tests + schema validation green), and the in-VM CI exercise wiring (§7
— `/usr/lib/punar/m2-check.sh` + `punar-m2-check.service`, gated by
`tools/boot-test.sh` phase 4 and the `desktop-test` CI job). Per spec
1.22: everything only CI can prove — runtime behavior of
binds/presets/overview in the VM, state write/restore, the §7 assertions
themselves — is now **proven by run 32825539021** (§8). What CI cannot
see stays open: fidelity of the presets and the overview to Plate D-007
(human design review) and the keyboard-only human walkthrough. Spec
basis: [SPEC_v0.2.md](../product/SPEC_v0.2.md) §76 Milestone 2 (tiling,
stacking, floating, overview, layouts, scratchpads, named project
workspaces), with §13 (window management), §14 (project workspaces), §15
(multi-monitor) as the core and §12.2–12.3 (command center,
discoverability) as the delivery surfaces. Design is binding:
[DESIGN_LANGUAGE.md](../design/DESIGN_LANGUAGE.md) (incl. §8
unmanaged-first — the M2 desktop is identical personal vs managed) and
**Plate D-007** `docs/design/mockups/desktop-multitasking.html` (project
grid, wireframe mini layouts, meta rows, type-to-search, arrow nav,
selection = raised fill + 2 px ink rule, 300 ms
`cubic-bezier(0.2,0,0,1)` motion only where it explains state).
[PERFORMANCE_BUDGETS.md](../../PERFORMANCE_BUDGETS.md) still binds: **no
new daemons, no polling loops; the overview renders on demand.**

Honesty (spec 1.22): §1 below is **verified** — method stated per row,
against the exact pinned inputs (hyprland 0.56.2-1 from ALA 2026/08/20,
quickshell 0.3.0-3). Everything after §1 was written as **decided plan**
and is now the **as-built** design; its runtime behavior in the VM was
unverified until the M2 CI check (§7) ran green in run 32825539021, and
what remains unverified is only what CI cannot see — flagged per row in
§8. M1 context (session chain, config paths, vendor-level `.wants/` rule
for any new units) is in [milestone-1.md](milestone-1.md) and is not
relitigated.

---

## 1. Capability check — verified against the pinned versions

Verification method, run 2026-08-25:

- **(a) Source-tag inspection** — Hyprland `v0.56.2` and quickshell
  `v0.3.0` release source trees (the exact upstreams of the pinned Arch
  packages), grepped for dispatcher registrations, config-value
  registrations, JSON emitters, and QML property definitions. File/line
  citations below are into those tags.
- **(b) Pinned-binary check** — hyprland **0.56.2-1** installed from the
  ALA 2026/08/20 snapshot inside the pinned builder base container
  (`snapshot.env` digest, emulated linux/amd64 docker on this host); a
  probe config exercising **every dispatcher and keyword in the tables
  below** passed `Hyprland --verify-config` (“config ok”), and a negative
  control (`togglegroup` misspelled) was rejected with a per-line error —
  the pass is not vacuous. Same method the M1 keyboard-grammar
  verification used.

`--verify-config` proves names/arity/keys parse in the pinned binary; it
cannot prove runtime behavior. Rows marked *(a)* only rest on source
inspection of the same tag the package is built from.

### 1.1 Grouping — stack/tab groups (spec §13.2)

| Item | Verdict | Evidence |
| --- | --- | --- |
| Dispatchers `togglegroup`, `changegroupactive` (`f`/`b`/index), `movegroupwindow` (`f`/`b`), `moveintogroup` (`l`/`r`/`u`/`d`), `moveoutofgroup`, `movewindoworgroup`, `moveintoorcreategroup`, `lockactivegroup` (`lock`/`unlock`/`toggle`), `lockgroups`, `setignoregrouplock`, `denywindowfromgroup` | **valid in 0.56.2** | (a) full dispatcher list `src/managers/KeybindManager.cpp:42-112`; (b) probe binds parsed |
| Group behavior keys: `group:auto_group`, `group:insert_after_current`, `group:focus_removed_window`, `group:group_on_movetoworkspace`, `group:col.border_active/_inactive/_locked_active/_locked_inactive` (gradients) | **valid** | (a) `src/config/values/ConfigValues.cpp:418-430`; (b) probe |
| Groupbar styling: `group:groupbar:` `enabled`, `disable_when_only`, `font_family`, `font_size`, `font_weight_active`, `font_weight_inactive`, `height`, `indicator_height`, `indicator_gap`, `gradients`, `render_titles`, `scrolling`, `middle_click_close`, `rounding`, `text_color`, `text_color_inactive`, `col.active`, `col.inactive`, `col.locked_active`, `col.locked_inactive`, `gaps_in`, `gaps_out`, `text_offset`, `text_padding`, `stacked`, `priority` | **valid** | (a) `ConfigValues.cpp:436-471`; (b) probe styled the groupbar with Instrument Sans / weights per design tokens |
| `hyprctl -j clients` reports `grouped` (array of addresses) per client | **valid** | (a) clients JSON emitter `src/debug/HyprCtl.cpp:385-430` |

### 1.2 Floating (spec §13.2)

| Item | Verdict | Evidence |
| --- | --- | --- |
| `togglefloating`, `setfloating`, `settiled` | **valid** | (a)+(b) |
| `pin` (visible on all workspaces; floating-only by design) | **valid** | (a) `DispatcherTranslator.cpp:849`; (b) |
| `centerwindow` (0.56.2 takes no argument — the older `1`/respect-reserved arg is gone; translator signature ignores args) | **valid** | (a) `DispatcherTranslator.cpp:292`; (b) |
| `resizeactive dx dy` (and `exact w h`) applies to floats and tiles | **valid** | (a)+(b); already used by M1 resize submap |
| clients JSON reports `floating`, `pinned` | **valid** | (a) HyprCtl.cpp clients emitter |

### 1.3 Layouts (spec §13.5 machinery)

| Item | Verdict | Evidence |
| --- | --- | --- |
| 0.56.2 ships **four** tiled algorithms: `dwindle`, `master`, `monocle`, `scrolling` (plus `lua:<name>` custom layouts) | **verified** | (a) `src/layout/algorithm/tiled/{dwindle,master,monocle,scrolling}/`; `general:layout` self-documents “[dwindle/master/scrolling/monocle/lua:<name>]” at `ConfigValues.cpp:179` |
| `hyprctl keyword general:layout <name>` **re-lays-out live** — the keyword trips `REFRESH_LAYOUTS` → `updateWorkspaceLayouts()` + recalculate/damage every monitor | **verified** | (a) `ConfigValues.cpp:179` (`.refresh = REFRESH_LAYOUTS`), `src/config/supplementary/propRefresher/PropRefresher.cpp:131-138`, `src/debug/HyprCtl.cpp:1210-1211` |
| `hyprctl --batch "keyword …; keyword …; dispatch …"` — semicolon-separated batches, server-side `[[BATCH]]` handler | **verified** | (a) `hyprctl/src/main.cpp:339-349,425`, `src/debug/HyprCtl.cpp:2041` |
| `master:orientation` (`left`/`right`/`top`/`bottom`/`center`), `master:mfact` (0–1, live-refresh), `master:slave_count_for_center_master`, `master:center_master_fallback` | **valid** | (a) `ConfigValues.cpp:680-690`; (b) probe |
| `layoutmsg` — master: `swapwithmaster`, `focusmaster`, `cyclenext/cycleprev`, `swapnext/swapprev`, `addmaster/removemaster`, `orientationleft/right/top/bottom/center/next/prev/cycle`, `mfact [exact] <v>`, `rollnext/rollprev` | **verified** | (a) `MasterAlgorithm.cpp` layoutMsg; (b) probe |
| `layoutmsg` — dwindle: `togglesplit`, `swapsplit`, `rotatesplit`, `movetoroot`, `preselect <dir>`, `splitratio` | **verified** | (a) `DwindleAlgorithm.cpp:674-767`; (b) probe |
| Per-workspace layout: workspace rules accept `layout:<name>`; `hyprctl keyword workspace <ws>, layout:<name>` also trips `updateWorkspaceLayouts()`; `hyprctl -j workspaces` reports the active `tiledLayout` per workspace | **verified** | (a) `WorkspaceRule.hpp:43-44`, `HyprCtl.cpp:1210`, workspaces JSON emitter (`tiledLayout` field); (b) probe rule parsed. Caveat: keyword-added rules **append and merge in order** (`WorkspaceRule.cpp:39-44`) — repeated switching leaks rule entries; see §4 |
| `scrolling:` options (`column_width`, `direction`, `fullscreen_on_one_column`, `explicit_column_widths`, …) and layoutmsg (`move ±col`, `colresize`, `fit active/visible/all/…`, `promote/consume/expel`) | **verified** | (a) `ConfigValues.cpp:700-711`, `ScrollingAlgorithm.cpp` |
| A native **grid** algorithm | **does not exist in 0.56.2** | (a) exhaustive: the four algorithms above are all of `src/layout/algorithm/tiled/` |

### 1.4 Named workspaces + overview data (spec §14)

| Item | Verdict | Evidence |
| --- | --- | --- |
| `renameworkspace <id> <name>` dispatcher (id required, name = rest of args; empty name clears) | **valid** | (a) `DispatcherTranslator.cpp:141-158`; (b) probe |
| Rename emits IPC event `renameworkspace>>ID,NAME` on socket2 | **verified** | (a) `src/desktop/Workspace.cpp:543` |
| `workspace name:<name>` / `movetoworkspace name:<name>` selectors | **valid** | (a) selector parsing `src/desktop/Workspace.cpp:134`, `MiscFunctions.cpp:140`; (b) probe |
| `hyprctl -j workspaces` → `id`, `name`, `monitor`, `monitorID`, `windows`, `hasfullscreen`, `lastwindow`, `lastwindowtitle`, `ispersistent`, `tiledLayout` | **verified** | (a) `HyprCtl.cpp getWorkspaceData` |
| `hyprctl -j clients` → `address`, `at [x,y]`, `size [w,h]`, `workspace {id,name}`, `floating`, `pinned`, `fullscreen`, `monitor`, `class`, `title`, `pid`, `grouped [..]`, `focusHistoryID` — everything the D-007 wireframes need | **verified** | (a) `HyprCtl.cpp:385-430` |
| Quickshell 0.3.0 `Quickshell.Hyprland`: `Hyprland.workspaces` / `.toplevels` / `.monitors` models, `focusedWorkspace`, `activeToplevel`, `dispatch()`, `refreshWorkspaces()`, `refreshToplevels()`, `rawEvent` signal | **verified** | (a) quickshell `src/wayland/hyprland/ipc/qml.hpp:22-73` |
| `HyprlandWorkspace` exposes `id`, `name`, `active`, `focused`, `urgent`, `hasFullscreen`, `monitor`, `toplevels`, and `lastIpcObject` (the full `j/workspaces` object incl. `windows`, `lastwindowtitle`) | **verified** | (a) `workspace.hpp:21-42` |
| `HyprlandToplevel` exposes `address`, `title`, `activated`, `urgent`, `workspace`, `monitor`, and `lastIpcObject` — the full `j/clients` object, so **`at`/`size`/`floating`/`class` are available in QML**; `refreshToplevels()` re-queries `j/clients` | **verified** | (a) `hyprland_toplevel.hpp:28-49`, `connection.cpp:710` |
| Quickshell auto-tracks socket2 events incl. `renameworkspace`, `createworkspacev2`, `destroyworkspacev2`, `openwindow`, `closewindow`, `movewindowv2`, `windowtitlev2`, `activewindowv2` — names and membership stay live with **no polling** | **verified** | (a) `connection.cpp:275-569` |
| **Fallback not needed:** parsing `hyprctl -j` via Quickshell `Process` is unnecessary — the typed module carries everything. Kept as the named fallback only if `lastIpcObject.at/size` proves stale in ways `refreshToplevels()` on overview-open cannot fix. | decision | — |

### 1.5 Persistence machinery

| Item | Verdict | Evidence |
| --- | --- | --- |
| Quickshell `FileView`: `atomicWrites` default **true** → writes go through `QSaveFile` (tmp + rename); parent directories created (`mkpath`) before write | **verified** | (a) quickshell `src/io/fileview.hpp:202-207,423`, `fileview.cpp:231,253,288` |
| Quickshell `IpcHandler` (`qs ipc call <target> <fn>`) for the PUNAR+TAB toggle — same mechanism M1 uses for the command center | **verified** | (a) `src/io/ipchandler.hpp`; M1 shell already exercises it |

---

## 2. Scope

| Item | M2 | Reason |
| --- | --- | --- |
| Group grammar (tab/stack groups) + design-language groupbar styling | **in** | §13.2; all machinery verified §1.1 |
| Floating polish: pin, centerwindow, float-aware move/resize | **in** | §13.2 |
| Layout presets **balanced / columns / rows / focus / stack** via `punar-layout.sh` (global) | **in** | §13.5; mapping in §4 |
| Preset **grid** | **out** | no native grid algorithm in 0.56.2 (§1.3); faking it with per-window `resizewindowpixel` breaks on the next open/close reflow. Future path: `lua:<name>` custom layout when the compositor rebase makes Lua layouts worth adopting |
| Per-workspace presets | **out (stretch)** | keyword-added workspace rules accumulate (§1.3 caveat); global presets are honest and sufficient for acceptance. Revisit with a rule-reset mechanism |
| PUNAR+TAB project overview implementing Plate D-007 | **in** | §14.2; data flow §5 |
| Named workspaces: rename via command center, `name:` navigation, names in bar + overview | **in** | §14 |
| Workspace-name persistence: `~/.local/state/punar/workspaces.json` + restore on shell start | **in** | §14.3 first slice (“layout memory ships first” per D-007 register: names + presets, not windows) |
| Scratchpads: assistant + notes special workspaces joining M1's terminal | **in** | §13.6 |
| Command center actions: layout presets, rename workspace, go-to-workspace, group lock, scratchpad relaunch | **in** | §12.2 is the discoverable surface for low-frequency verbs |
| Full §14.3 restoration (app reopening, terminal/browser state, containers) | **out** | future goal per spec; drawn dashed in D-007, never claimed solid |
| §14.4 activities (temporary contexts, credential revocation) | **out** | long-term per spec |
| §15 monitor-layout memory, disconnect collapse | **out** | M1's cross-monitor moves stay; the memory/collapse work needs multi-output test rigs; unchanged from M1 deferral |
| Drag-to-tile with the mouse, workspace-switch spatial slide | **out** | D-007 lists them as specified-in-words; keyboard grammar is the acceptance path |
| `punard`/`punarctl` involvement | **out** | M3; the shell writes state directly (§6) |

## 3. Binding resolution (spec §13.3 “PUNAR+L” collision) and new chords

**Decision: `PUNAR+L` stays focus-right. The layout chooser lives in the
command center; `PUNAR+comma` / `PUNAR+period` cycle presets directly.**

Justification: §13.3's own table assigns `PUNAR+L` to both HJKL focus and
the layout chooser and says “exact bindings may evolve.” Directional focus
is the highest-frequency verb in the grammar and HJKL is its complete
vocabulary — breaking the family for a low-frequency chooser inverts the
frequency ordering. The chooser is a discoverable, typed surface (§12.2:
the command center is *the* universal entry point; type “layout”), and the
fast path is a cycle pair on unclaimed keys: comma/period read as `<` `>`
— previous/next preset. This mirrors how M1 already resolved the same
collision for focus (see keyboard-grammar.md “Future” table).

New M2 chords (M1 grammar untouched; all free keys checked against
`punar-binds.conf`):

```text
PUNAR + G                    Toggle group on active window (togglegroup)
PUNAR + SHIFT + G            Move window out of group (moveoutofgroup)
PUNAR + [ / ]                Previous / next window in group (changegroupactive b / f)
PUNAR + CTRL + H/J/K/L       Move window into adjacent group (moveintogroup l/d/u/r)
PUNAR + SHIFT + V            Pin floating window (pin)
PUNAR + C                    Center floating window (centerwindow)
PUNAR + comma / period       Previous / next layout preset (exec punar-layout.sh prev|next)
PUNAR + A                    Assistant scratchpad (togglespecialworkspace assistant)
PUNAR + N                    Notes scratchpad (togglespecialworkspace notes)
PUNAR + TAB                  Project overview (exec quickshell ipc call overview toggle)
PUNAR + SHIFT + TAB          Previous open workspace (kept — fast cycle stays)
```

`lockactivegroup`, rename-workspace, go-to-named-workspace, and the full
preset chooser are command-center actions, not chords. Every bind uses
`bindd` with a description (no commas) so `hyprctl binds -j` stays the
single discoverability feed.

## 4. Layout presets — mechanism and mapping (spec §13.5)

**Decision: presets are applied by `/usr/lib/punar/punar-layout.sh
<preset|next|prev>`, a POSIX-sh script issuing ONE `hyprctl --batch` of
`keyword` commands. The shell (command center / chooser UI) and the
compositor binds both exec this script; neither applies keywords itself.**

Why a script and not shell IPC: one source of truth callable from binds,
command center, a TTY, and the CI check without the shell running; zero new
daemons or polling (a one-shot process per invocation); trivially
shellcheck-gated. The shell renders the chooser and shows the active
preset, but application is delegated. The script records the active preset
in `/run/user/$UID/punar/layout-preset` (tmpfs, one word) so `next`/`prev`
cycling and the bar chip need no compositor query.

Preset table (all keywords verified §1.3; batches are semicolon-joined):

| Preset | `general:layout` | Extra keywords in the same batch | Honest description |
| --- | --- | --- | --- |
| `balanced` | `dwindle` | `dwindle:default_split_ratio 1.0`, `dwindle:preserve_split 1` | even BSP splits — the M1 default feel |
| `columns` | `scrolling` | `scrolling:column_width 0.5`, `scrolling:direction right`, `scrolling:fullscreen_on_one_column 1` | every window a column; viewport scrolls when they overflow (PaperWM-style — the native columns vocabulary in 0.56) |
| `rows` | `master` | `master:orientation top`, `master:mfact 0.5` | hero row on top, remaining windows share the bottom row — a two-row approximation; 0.56.2 has no n-row stripes layout |
| `focus` | `master` | `master:orientation left`, `master:mfact 0.72` | one large focused window, context stack at the side |
| `stack` | `monocle` | — | one window at a time, the rest stacked behind (cycle with focus keys); per-set-of-windows tab groups (§3 chords) remain orthogonal |
| `grid` | — | — | **not shipped** (§2) |

Cycle order: `balanced → columns → rows → focus → stack`. Presets are
global in M2 (§2). The active preset is also written into the state file
(§6) and re-applied by the same script on session start (`punar-layout.sh
restore`, exec-once after the shell), so the preset survives reboot.

## 5. Overview — PUNAR+TAB, Plate D-007 (spec §14.2)

Data flow (no polling, renders on demand):

1. `PUNAR+TAB` → `quickshell ipc call overview toggle` (IpcHandler target
   `overview`, functions `toggle`/`open`/`close`, plus a read-only `state`
   function returning `open|closed` for the CI check).
2. On open, the overview QML calls `Hyprland.refreshWorkspaces()` and
   `Hyprland.refreshToplevels()` once, then binds to the live models:
   - cards ← `Hyprland.workspaces` (filtered: `id > 0`, i.e. specials
     hidden), title `«id» · «name»` (unnamed → just the number), meta row
     ← `lastIpcObject.windows` + `lastwindowtitle` (agent presence in the
     meta row lands with M7 registry data; M2 renders window count/title);
   - wireframe minis ← each workspace's `toplevels`:
     `lastIpcObject.at/size` normalized by the workspace's
     `monitor.width/height`, floating windows drawn over tiled, grouped
     windows drawn as one slab with a tab notch. Between refreshes the
     socket2 events (§1.4) keep membership/titles current; geometry is
     refreshed on each open, which is exactly the on-demand budget rule.
3. Keyboard per D-007: arrows move the selection (raised fill + 2 px ink
   rule), typing filters by name (the greeter's underline field grammar),
   Enter → `Hyprland.dispatch("workspace " + id)` and close, Escape
   closes. Motion: open/close and selection use 300 ms
   `cubic-bezier(0.2,0,0,1)`; nothing else animates.
4. The M1 placeholder bind (`workspace e+1`) is replaced by the IPC exec;
   `PUNAR+SHIFT+TAB` keeps the quick previous-workspace cycle.

## 6. Persistence — state-file contract

**Path:** `~/.local/state/punar/workspaces.json`
**Writer:** punar-shell only (M2), via `FileView` with `atomicWrites: true`
(QSaveFile tmp+rename, §1.5) — written when a `renameworkspace` event
arrives and when the preset changes, debounced 1 s; never on a timer.
**Reader/restorer:** on shell start, read the file; for each entry with a
non-empty name whose workspace exists (or when it is later created —
`createworkspacev2` handler re-checks), apply
`Hyprland.dispatch("renameworkspace <id> <name>")`. Layout preset is
restored by `punar-layout.sh restore` reading the same file (§4).

**Exact JSON shape (schema version 1):**

```json
{
  "version": 1,
  "updated": "2026-08-25T09:30:00Z",
  "layoutPreset": "balanced",
  "workspaces": [
    { "id": 1, "name": "atlas" },
    { "id": 2, "name": "punar" }
  ]
}
```

Rules: `version` int (readers reject > 1); `updated` UTC ISO-8601;
`layoutPreset` one of §4's five names; `workspaces` sorted by `id`,
entries only for workspaces with non-empty names; `id` int ≥ 1 (specials
never persisted); `name` matches `^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$` — no
commas (the socket2 rename event frames as `ID,NAME`), no leading
`special`. The command center's rename action validates against the same
regex.

**Shared schema:** the `punar-workspace` crate ends its M0 placeholder
state with exactly these serde types — `WorkspaceStateFile { version: u32,
updated: String, layout_preset: String, workspaces: Vec<WorkspaceName> }`,
`WorkspaceName { id: i64, name: String }` (serde rename to the JSON keys
above) — plus the name-regex validator and a round-trip test against a
fixture identical to the example. A JSON Schema for it landed at
`schemas/workspace/workspace-state.json` (a new `workspace` schema domain;
this line originally said `schemas/project/workspace-state.schema.json` —
reconciled to the path the state workstream shipped, following the
existing `schemas/` conventions). The crate does not run at M2 (no daemon); it is
the typed contract M3's `punard` will consume unchanged.

## 7. In-VM exercise plan — what the m2 check asserts

The desktop CI gate grows an M2 exercise phase: a guest-side script
(`/usr/lib/punar/m2-check.sh`, run as the session user by
`punar-m2-check.service`) drives `hyprctl` + `jq` + `qs ipc` inside the
session and writes per-assertion `ok`/`FAIL` lines plus a final
`PUNAR_M2_OK`/`PUNAR_M2_FAIL` verdict into `/run/punar/m2-report.txt`
(also echoed to the serial console); artifacts (overview screenshot
`punar-m2.png`, `hyprctl -j` snapshots, state-file copy) join the §9(M1)
export automatically — the export tars all of `/run/punar`. Ordering (as
wired, refining the original sketch): `idle-ram.sh` starts the service
**synchronously after the canonical sampling window closes** (so the
exercise's windows/overview can never pollute the idle measurement) **and
before the export** (so the report ships in the same tar). The host gate
(`tools/boot-test.sh` phase 4) hard-fails on a delivered `PUNAR_M2_FAIL`
or a truncated report; a missing report is `::warning::` under KVM and
info-only under TCG. Every assertion is a `hyprctl -j` / file read — no
new daemons.

| # | Action | Assertion |
| --- | --- | --- |
| 1 | `hyprctl dispatch renameworkspace "1 atlas"` | `hyprctl -j workspaces` → workspace 1 `name == "atlas"` |
| 2 | open two terminals; `togglegroup`; `changegroupactive f` | clients JSON: both `grouped` arrays length 2; `activewindow` address changed after cycle |
| 3 | `moveoutofgroup` | active client `grouped == []` |
| 4 | `togglefloating` + `centerwindow` + `pin` on active | client `floating == true`, `pinned == true`; after `pin` + `togglefloating` off, restored |
| 5 | `punar-layout.sh focus` then `stack` then `balanced` | after each: `hyprctl -j getoption general:layout` → `master` / `monocle` / `dwindle`, and focused workspace `tiledLayout` matches |
| 6 | `punar-layout.sh next` twice from `balanced` | preset file reads `rows`; `general:layout` is `master` |
| 7 | `hyprctl dispatch togglespecialworkspace assistant` (and `notes`) | workspaces JSON contains `special:assistant` while shown; toggles away clean |
| 8 | `hyprctl dispatch workspace name:atlas` from workspace 2 | `activeworkspace` id 1 |
| 9 | `qs ipc call overview toggle`; `qs ipc call overview state` | state `open`; `grim` screenshot captured for the export; toggle again → `closed` |
| 10 | wait ≥ debounce; read `~/.local/state/punar/workspaces.json` | valid JSON matching §6 (jq: version 1, workspaces contains `{id:1,name:"atlas"}`, layoutPreset `rows`) |
| 11 | kill the quickshell process; relaunch `$shell`; rename ws 1 away beforehand (`renameworkspace 1`) | after shell restart, workspace 1 name is `atlas` again (restoration applied) |
| 12 | budgets | `check-budgets.sh` unchanged and still green — the M2 additions may not move idle RAM past gates; no new always-on processes exist (`pgrep` proves only qs/foot/Hyprland families) |

Human walkthrough additions (keyboard-only, extending the M1 list):
group chords, preset cycle on comma/period, overview arrows +
type-to-search + Enter, assistant/notes scratchpads, command-center
rename.

## 8. Verification status (spec 1.22)

| Claim | Status |
| --- | --- |
| §1 tables (dispatchers, keywords, JSON fields, QML API, FileView atomicity) | **verified 2026-08-25** — method §1 preamble; probe passed `--verify-config` on hyprland 0.56.2-1 with negative control |
| Preset mapping renders the described shapes at runtime | **partly verified 2026-08-25** — run 32825539021: §7 rows 5–6 passed, each preset flipping `general:layout` and the workspace `tiledLayout` in the VM; the *visual* shape fidelity is still unverified and rests on screenshot review + human walkthrough |
| Overview implements D-007 faithfully | **unverified — design review**; run 32825539021 proved the overview toggles over IPC and renders (§7 row 9; `punar-m2.png` in the `punar-desktop-screenshot` artifact), but fidelity to the plate is a human review and is part of shell-workstream acceptance |
| State write/restore behavior in the VM | **verified 2026-08-25** — the arbiter has run: §7 rows 10–11 passed in run 32825539021 (schema-valid `workspaces.json` written; workspace 1 restored to `atlas` after a shell restart) |
| No-polling / no-daemon budget compliance | **by construction** (event-driven shell, one-shot script) **and verified 2026-08-25** — §7 row 12 passed in run 32825539021: no new always-on processes, budgets green at idle RAM mean 1157 MB / max 1162 MB (under the 1536 MB ceiling, over the 1024 MB target — recorded warning) |
| CI wiring (m2-check.sh, punar-m2-check.service, boot-test phase 4, ci.yml uploads) | **statically verified 2026-08-25** — shellcheck v0.11.0 (pinned container) clean on every touched script, actionlint clean on ci.yml, `PUNAR_BUILD_MODE=summary` staging + `mkosi summary` pass in the pinned builder; the exercise's runtime PASS — exactly what the first desktop CI run including it had to prove — was **delivered 2026-08-25** by run 32825539021 (commit `5e1f5cb`, KVM), which ran `punar-m2-check` in-VM and returned `PUNAR_M2_OK` |

Sources: Hyprland `v0.56.2` source tag (files cited inline); quickshell
`v0.3.0` source tag; hyprland 0.56.2-1 binary from ALA 2026/08/20 in the
pinned builder container; Hyprland wiki (Dispatchers, Workspace rules,
Master/Dwindle layouts) consulted as secondary confirmation only — source
and binary win where they disagree.
