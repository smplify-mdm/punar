# Punar desktop surfaces — the status record

**What this document is.** One page that says what the Punar desktop
actually *is* right now: every graphical surface the shell composes, the
chord that opens it, the IPC verb that opens it without a keyboard, the
file or daemon it reads, and — the part that matters most — whether what
it shows is **measured** or **honestly unavailable**. It is written to be
handed to a human sitting in front of the VM.

**Date:** 2026-08-26 · **Shell:** `shell/punar-shell` (Quickshell 0.3.0 /
Qt 6.11.2) · **Compositor:** Hyprland 0.56.2 · **Design authority:**
[`docs/design/DESIGN_LANGUAGE.md`](../design/DESIGN_LANGUAGE.md) (binding).

> **The shell is one process.** Every surface below is a `Scope` inside
> the single `punar-shell` client. One Wayland connection, one D-Bus
> name, one IPC socket, one set of inotify watches. There is no wallpaper
> daemon, no notification daemon, no lock daemon and no settings app —
> adding four processes to draw four surfaces is the arrangement Punar
> exists to avoid.

---

## 1. How to drive any of it

Every surface answers on the same socket. The `-p` is not optional: the
shell's QML lives outside Quickshell's default search path.

```sh
qs -p /usr/share/punar/shell ipc show                # list every target
qs -p /usr/share/punar/shell ipc call <target> <verb>
```

Hyprland reaches the same targets through the `$…` variables in
`/etc/xdg/hypr/hyprland.conf`, so a chord and a script call are the same
call. The help surface (`SUPER + /`) is generated from
`hyprctl binds -j` — the live table, not a written copy — so **if this
document and the machine disagree, the machine is right and the help
surface will say so.**

---

## 2. The surfaces

### 2.1 Wallpaper — the desktop field

| | |
|---|---|
| **Plate** | D-015 · `mockups/wallpaper.html` |
| **Chord** | none — it is the ground, not a control |
| **IPC** | none of its own (follows `theme`) |
| **Files** | `Wallpaper/Wallpaper.qml`, `Wallpaper/punar-wallpaper.svg.in` |
| **Data source** | **none at all.** The only shell surface with zero inputs |
| **Status** | **REAL** |

The boot dial with its progress arc removed, drawn at watermark contrast
on the field colour, one background layer window per output. It reads no
status file and holds no timer, which is why it can never lie: nothing
the machine can observe is allowed to change it. It follows the active
theme's *mood* and nothing else. Marks stay strictly quieter than a
window border in every selectable theme, because the theme contrast gate
(R7) refuses a palette where they would not.

**Try it:** log in. It is the first thing you see. Then run
`qs -p /usr/share/punar/shell ipc call theme set nocturne` and watch the
desktop repaint with no restart.

---

### 2.2 Menubar — identity, modality, live status

| | |
|---|---|
| **Plate** | D-016 · `mockups/menubar.html` (+ D-012 for the elevated chip) |
| **Chord** | `SUPER + SHIFT + B` focuses the status cluster |
| **IPC** | `bar` — `focus` / `release` / `state` |
| **Files** | `Bar/Bar.qml`, `Bar/StatusCluster.qml`, `Bar/StatusSlot.qml`, `Bar/SlotPopover.qml` |
| **Status** | **REAL**, with two slots honestly absent |

Left is identity (`PUNAR · <workspace>`), centre is reserved for modality
and stays empty, right is the live cluster then the org annotation then
the clock. **On a calm personal machine the cluster is zero pixels** —
every slot carries its own `visible:` expression bound to real data, and
a `Row` skips invisible children, so an idle bar is `PUNAR · 1` … `08:26`
exactly as before.

| Slot | Source | Status |
|---|---|---|
| **AI** | `/run/punar/agents.json` (`counts.managed + counts.observed`) | renders |
| **UNKNOWN AI** | `max(agents.json counts.unknown, /run/punar-agentd/alerts.json activeCount)` | renders, never collapsed |
| **APPROVAL** + countdown | `/run/punard/approvals.json` | renders |
| **ELEVATED** chip | `grants[]` in `/run/punard/approvals.json` | renders |
| **ORG** name · dot · compliance word | `/run/punar/status.json` | renders **only when enrolled** (§8) |
| **ENV** | *nothing to read* — `punar-env` writes no state file | **absent** |
| **CRED** | *nothing to read* — `punar-secrets` has no state directory at all | **absent** |
| Battery · network · audio | not wired | **absent** (M11) |

ENV and CRED are absent rather than greyed out on purpose: filling them
would require running `podman` on a timer, which is exactly the polling
loop spec §6.3 prohibits.

**Deviation, stated:** D-016 puts ORG in the cluster with System Control
as its destination. System Control now ships (`SUPER + S`), so the
original reason for keeping ORG an annotation has expired — but design
language §8 says enrollment is additive chrome that "must never
restructure a screen", and promoting ORG to a focusable slot restructures
the right-hand zone the moment a device enrols. It stays an annotation;
the door is reached by its own chord.

**Try it:** `SUPER + SHIFT + B` on a calm machine answers `empty` and does
not take the keyboard. Write a fixture into `/run/punar/agents.json` and
it lands on the highest-severity slot.

---

### 2.3 Command center — SUPER + Space

| | |
|---|---|
| **Plate** | D-003 Sect I · `mockups/command-approval.html` |
| **Chord** | `SUPER + Space` |
| **IPC** | `commandcenter` — `toggle` / `open` / `close` / `state` / `query` / `run` / `explain` |
| **Files** | `CommandCenter/CommandCenter.qml`, `CommandCenter/Actions.qml`, `CommandCenter/ExplainCard.qml` |
| **Status** | **REAL** |

Rows are produced from data in exactly five typed kinds, each with one
execution mechanism and no "run this string" escape hatch:

| Kind | Mechanism | Printed action |
|---|---|---|
| `app` | `DesktopEntry.execute()` | `Launch(chromium)` |
| `project` | `workspace <id>` + `renameworkspace <id> <name>` | `OpenProject(atlas) · Workspace 2` |
| `surface` | `qs ipc call <target> open` | `Surface(systemcontrol) · Super S` |
| `layout` | `/usr/lib/punar/punar-layout.sh <preset>` | `SetLayout(columns)` |
| `explain` | `punarctl --json policy explain <path>` | `PolicyExplain(security.firewall)` |

The browser is resolved **by role**, never by a hardcoded argv: desktop-id
list → `heuristicLookup` → the freedesktop `Categories=WebBrowser` sweep.
A machine with only Firefox resolves to Firefox; a machine with none draws
no row.

A surface whose IPC target is not registered in *this* shell renders
**dashed** with its milestone and says so on Enter. That is now a live
proof rather than a claim: before this pass most targets were dashed;
with the shell composed they resolve and open.

**Try it:** `SUPER + Space`, type `browser` → Enter. Type `Open Atlas` →
Enter, then `hyprctl -j workspaces` and look for the name. Type
`why is the firewall on?` → Enter for the §40 explain card.

---

### 2.4 Project overview — SUPER + Tab

| | |
|---|---|
| **Plate** | D-007 · `mockups/desktop-multitasking.html` |
| **Chord** | `SUPER + Tab` |
| **IPC** | `overview` — `toggle` / `open` / `close` / `state` |
| **Data source** | live Hyprland workspaces (socket2) + `~/.local/state/punar/workspaces.json` |
| **Status** | **REAL** |

---

### 2.5 System Control — SUPER + S

| | |
|---|---|
| **Plate** | D-004 · `mockups/system-control.html` · spec §63 |
| **Chord** | `SUPER + S` |
| **IPC** | `systemcontrol` — `toggle` / `open` / `close` / `state` |
| **Files** | `SystemControl/SystemControl.qml` (all the colour), `SystemControl/ControlData.qml` (all the knowledge) |
| **Status** | **REAL for 15 views, honestly unavailable for 8** |

The settings surface. `↑↓`/`JK` walk the §63 taxonomy rail, `/` searches
it, `PgUp/PgDn` scroll the detail pane, and the letter keys the pane
prints fire that view's actions.

**Measured — nothing invented:**

| View | Source |
|---|---|
| System · Network | `/proc/net/route` → `/sys/class/net/<if>/{operstate,address}` |
| System · Displays | `Hyprland.monitors` (live via socket2) |
| System · Audio | PipeWire default sink/source, live |
| System · Power | `/sys/class/power_supply/BAT0/{capacity,status}` |
| Security · Device | `punarctl status --json` + §40 explain cards |
| Security · Encryption | `/sys/block/dm-0/dm/uuid` (LUKS detection) |
| Security · Secure Boot | the EFI `SecureBoot` efivar + the daemon's attestation word — carries the **dashed SIMULATED · VM** tag |
| **Security · Firewall** | `punarctl capabilities --json` + `punarctl policy effective --json`; live toggle, drift promise, keyed action row |
| AI · Agents / Permissions | `/run/punar/agents.json` |
| Developer · Projects | live Hyprland workspaces |
| Organization · Enrollment / Compliance / Policies / Privilege | `/run/punar/status.json`, `punarctl policy effective --json`, `punarctl privilege status --json` |

**Honestly unavailable — dashed panel, what/why/milestone, never a fake
toggle:** Bluetooth (no stack ships), Wi-Fi list/connect (**M12 ·
punar-netd**), AI Models (no registry), AI MCP (**M9+**), Containers
(punar-env owns environments), Toolchains, Privacy · Connections (**M12**),
Privacy · Relay (**M12**). When punard has not answered at all, every view
becomes the **AWAITING PUNARD** panel and the footer reads *"Awaiting
punard · nothing measured is shown."*

**Mutations all go through `punarctl` with fixed argv** — the exact argv
is printed under the action row, and the daemon's refusal is rendered
verbatim with its exit code:

- `[E]` `punarctl privilege request --capability <path> --reason <typed> --duration 15` — this creates an **approval**, so the M9 gate opens itself.
- `[S]` `punarctl capabilities set <path> <state>` — offered **only** while a live §48 grant covers the capability, because that is the only case a non-root session may write one. No grant → `[E]` is offered instead of a switch that would be refused.
- `[R]` `punarctl privilege revoke <grant_id>`.

**Try it:** `SUPER + S`, `/` then `firewall`, then `E` to request an
exception with a reason — and watch the approval gate open itself.

---

### 2.6 Notifications — toasts, centre, OSD

| | |
|---|---|
| **Plate** | D-009 · `mockups/notifications-osd.html` |
| **Chords** | `SUPER + SHIFT + N` (centre) · `XF86Audio{Raise,Lower}Volume`, `XF86AudioMute` (OSD) |
| **IPC** | `notifications` · `toasts` · `osd` |
| **Files** | `Services/Notifications.qml` (the daemon), `Notifications/{ToastStack,NotificationCenter,Osd}.qml` |
| **Status** | **REAL** — Punar had no notification daemon at all before this |

`Services/Notifications.qml` binds `org.freedesktop.Notifications`.
Declared capabilities are only the ones the surfaces honour: body,
actions and persistence **true**; markup, images, action icons and inline
reply **false**, because the surfaces render plain text and have no image
slot.

**When another daemon owns the bus name, the empty state tells the
truth.** A one-shot `busctl` lookup compares the owning PID to the
shell's own — identity, not a vendor string — giving `punar` | `foreign` |
`unverified`. There is deliberately **no** "nobody owns it" state: a
failed lookup could be an unowned name, an unreachable bus or a missing
tool, and the shell declines to invent a verdict. A **proven** foreign
owner draws a warn-bordered banner naming the process and its pid and
**suppresses the calm empty state**, which would otherwise be the most
comfortable lie the shell could tell.

Other decisions worth knowing before you judge the surface:

- **Dwell time is Punar's, not the sender's:** low 4 s / normal 6 s /
  critical sticky. The protocol's `expire_timeout` unit is a known
  cross-implementation ambiguity, so only its one unambiguous value
  (`0` = never expire) is honoured.
- **No status colour on a toast**, in either voice. §2 binds red/amber/green
  1:1 to *policy decisions*; an app's `Critical` urgency is a self-asserted
  delivery hint, not a judgment Punar made. The loud variant is drawn
  louder and prints the word `CRITICAL`, exactly as the OSD prints `MUTED`.
- **DND applies to every urgency including Critical** — a sender must not
  defeat the user's own switch. The M9 approval gate and the M10 alert are
  separate surfaces this daemon does not route, so quiet cannot reach them
  *by construction*, and that sentence is printed beside the toggle.
- **Toasts never take the keyboard exclusively**, so they can never swallow
  a keystroke while you type. The guaranteed keyboard path is the centre.
- **Dismissing files, it never destroys.** The centre is the record.

The centre reads three registers and owns one: application notifications
are its own; approval rows come from the **same** M9 `Approvals` singleton
the gate uses, and agentd rows from the **same** M10 `Alerts` singleton the
alert region uses. "Approvals and alerts resolve, they don't dismiss" is
therefore unfalsifiable rather than enforced by a check that could rot.

**OSD:** volume is real — it follows the PipeWire sink's own change event
and draws the level the sink *settled on*, whoever moved it, so it cannot
show a level the machine does not hold. With no audio server it reports
`unavailable` and never draws. **Brightness is dashed** with the plate's
`SIM · VM` tag and reachable only by IPC, because no backlight capability
ships — which is also why **no brightness key is bound** (spec §1.22).

**Try it:**
```sh
notify-send "Deploy finished" "atlas · 4m 12s"      # a toast, then SUPER+SHIFT+N
qs -p /usr/share/punar/shell ipc call notifications dnd toggle
qs -p /usr/share/punar/shell ipc call notifications owner   # punar | foreign | unverified
qs -p /usr/share/punar/shell ipc call osd brightness 60      # the dashed row
```

---

### 2.7 Approval gate and shadow-AI alert — no chord, by design

| | |
|---|---|
| **Plates** | D-003 Sect II (gate) · D-009 Sect I (alert) |
| **Chord** | **none** |
| **IPC** | `approval` · `alerts` |
| **Data source** | `/run/punard/approvals.json` · `/run/punar-agentd/alerts.json` |
| **Status** | **REAL** |

Neither has a keybinding, and that is the design: **a gate the human has
to go looking for is not a gate.** punard writes the file, the inotify
watch follows it, the surface appears. On a machine where the daemon never
wrote the file, nothing is ever drawn (fail closed).

The alert's `[I] Inspect` is wired in `shell.qml`, not inside the card —
it *asks*, and the shell root hands the detection to the AI panel.

---

### 2.8 AI panel — SUPER + A

| | |
|---|---|
| **Plate** | D-005 · `mockups/ai-panel.html` · spec §25 |
| **Chord** | `SUPER + A` |
| **IPC** | `aipanel` — `toggle` / `open` / `close` / `state` |
| **Data source** | `/run/punar/agents.json` |
| **Status** | **REAL**, with the §21 ledger's unobserved boundary dashed |

---

### 2.9 Shortcut help — SUPER + /

| | |
|---|---|
| **Plate** | D-017 |
| **Chord** | `SUPER + /` |
| **IPC** | `shortcuts` — `toggle` / `open` / `close` / `state` / `reload` / `rows` / `undescribed` |
| **Data source** | `hyprctl binds -j` — **and nothing else** |
| **Status** | **REAL** (the SUPER-hold overlay is **NOT shipped** — see below) |

Generated from the live bind table, queried once per session on first
open, cached, and invalidated only by Hyprland's `configreloaded` on
socket2. A bind with no description produces **no row**, and the count of
such binds is printed as the alarm — the mistake is loud, not silent.
`/` filters, `↑↓` walks, `Esc` closes, and **`↵` deliberately does nothing
and is never offered**: a help surface that fires a chord for you is a
launcher wearing a help surface's clothes.

**Section mapping reconciled at integration.** The help surface files rows
by a *closed* table keyed on the Hyprland dispatcher (about fifteen verbs,
not seventy bindings), with `exec` disambiguated by the shell IPC target it
calls. Two entries were added so no row lands in the `OTHER` bucket:
`lock` → **SESSION**, and a new **MEDIA** section for the three `wpctl`
media-key binds. `OTHER` is the loud failure for a row nobody classified,
and it should stay empty precisely so it means something when it is not.

**The SUPER-hold overlay of D-017 is not shipped**, and the reason is
written into the file header after reading the Hyprland v0.56.2 tag:
`bindr` on `SUPER_L` is real but `shadowKeybinds()` swallows the release
after a chord (D-017's own stranded-overlay failure); `bindo` long-press
exists but its delay is `input:repeat_delay`, so D-017's argued 400 ms is
unobtainable without changing typing for the whole machine. §7 is explicit
that implementation alone does not earn a solid line, so the overlay stays
a compositor task with the recipe recorded.

---

### 2.10 Lock — SUPER + Escape

| | |
|---|---|
| **Plates** | D-002 (grammar) · D-012 Sect III (surface) |
| **Chord** | `SUPER + Escape` |
| **IPC** | `lock` — `lock` / `state` — and **deliberately no `unlock`** |
| **Files** | `Lock/Lock.qml`, `Lock/LockSurface.qml`, `/etc/pam.d/punar-lock` |
| **Status** | **REAL — it actually locks** |

Not an overlay pretending to be a lock: it drives Wayland
`ext-session-lock-v1` through Quickshell's `WlSessionLock`, so the
*compositor* hides every other surface and refuses to unlock until the
client says so. If the shell dies while locked, a conforming compositor
keeps the session locked rather than exposing the desktop.
`WlSessionLock.secure` is the compositor's own acknowledgement; the footer
prints its absence rather than assuming success.

Authentication is a real PAM conversation. The shell never reads a hash
and never compares a string. The stack is `/etc/pam.d/punar-lock`
(shipped by this pass: `pam_faillock` + `pam_unix`, no session phase, no
`nullok`), falling back to `login` if it is missing.

**There is no IPC `unlock` verb**, and that is the point: an unlock verb
would make the session socket a complete bypass of the passphrase.

**Chord deviation, stated:** every desktop uses `SUPER + L`, and all three
`L` chords are already load-bearing in the §13.3 directional grammar
(focus-right, move-right, move-into-group-right). Taking a working
directional key from every window operation to win a familiar chord is the
worse trade. `SUPER + Escape` is free and carries its own meaning here:
Escape is the key that leaves.

**Try it:** `SUPER + Escape`, then type the dev password (`punar`). A
wrong passphrase leaves it locked and the field clears.

---

### 2.11 Themes — no chord, all IPC

| | |
|---|---|
| **Design** | `docs/design/theme-system.md` |
| **IPC** | `theme` — `status` / `list` / `show` / `validate` / `preview` / `clear` / `set` / `reset` / `reload` |
| **Files** | `Theme/Theme.qml`, `Theme/ThemeContrast.qml`, `shell/theme/themes/*.json` |
| **Status** | **REAL** |

Seven shipped entries over six palettes: `paper`, `panel`, `graphite`,
`oxide`, `nocturne`, `ember`, `contrast`. A theme is **nineteen colours
and four strings** — never the grammar. Unknown keys are *refused*, not
ignored, naming the key. Every other colour on the machine (ANSI slots,
window borders, wallpaper marks) is **derived**.

`ThemeContrast` is a machine-checkable WCAG gate (R1–R9) that runs in full
**before** the pointer is written: a refusal writes nothing. All seven
shipped themes pass; two deliberately illegible fixtures are refused with
rows like `R3 paper · ink3 on raise2 [2.87 < 4.5]`.

**Try it:**
```sh
qs -p /usr/share/punar/shell ipc call theme list
qs -p /usr/share/punar/shell ipc call theme set nocturne
qs -p /usr/share/punar/shell ipc call theme set moss     # applied:false — nothing changes
qs -p /usr/share/punar/shell ipc call theme reset
```

---

### 2.12 Browser and link handling — SUPER + B, and every other path

Chromium 151 from the pinned snapshot. **Not a fork, not an engine** —
spec §30.1's "upstream-current Chromium plus a small, auditable Punar
integration layer". What exists today is the smallest possible layer:
two config files and a package.

| Thing | Where | Note |
|---|---|---|
| Chord | `SUPER + B` → `$browser` | The bind carries **no flags** |
| Launch flags | `/etc/chromium-flags.conf` | Read on **every** launch path |
| Default handler | `/etc/xdg/mimeapps.list` | `http`, `https`, `text/html` |
| `xdg-open` | `xdg-utils` package | Newly present |

**Why the flags moved off the keybind.** `--ozone-platform-hint=auto`
used to live on the `SUPER + B` line. That gave exactly *one* launch path
a native Wayland browser: the chord. The application launcher, `xdg-open`,
and any future web-app launcher all go through the packaged
`chromium.desktop`, which never saw the flag and got **XWayland** — blurry
under fractional scaling, wrong cursor size, no per-monitor DPI. One
source of truth now; the chord is no longer privileged.

**Why `xdg-utils` had to be added at all.** It was absent. `xdg-open` is
the call an application makes to ask the system to open a URL — a
notification action, a terminal URL activation, the command center's
"open" verb. Nothing in the image provided it, and nothing registered a
handler either. A **human** could reach a browser through the chord; the
**system** could not reach one at all, and every such path failed with
command-not-found.

**Override semantics — the opposite of the terminal's.** Both
`/etc/chromium-flags.conf` and `~/.config/chromium-flags.conf` are read,
**in order**, so a user's own file *adds to* Punar's defaults. Compare
`foot.ini`, where the first file found wins outright and a user config
replaces the Punar theme wholesale. The same additive rule holds for
`mimeapps.list`: a user's chosen default browser outranks
`/etc/xdg/mimeapps.list` rather than fighting it.

**A quiet failure mode worth knowing.** The chromium launcher skips any
flags line with unbalanced quotes **silently** — no warning, no error, the
flag simply never applies. This is why `surfaces-check.sh` asserts the
flags on the running browser's own `/proc/<pid>/cmdline` rather than on the
file's text: a present, readable, correct-looking file can apply nothing at
all. A dangling desktop id in `mimeapps.list` fails the same way — `xdg-open`
falls through rather than erroring, which is indistinguishable from having
no default — so the resolved handler is asserted on the running machine too.

**No enterprise policy, on purpose.** Chromium also reads
`/etc/chromium/policies/managed/`. Punar writes nothing there on an
unmanaged device: a managed policy makes the browser's own menu report
*"Managed by your organization"* on a machine that was never enrolled —
false, and the same defect class as the M5 `policy.d/ai` directory that
was created on every device. DESIGN_LANGUAGE.md §8. Managed policy is the
right mechanism once a device **is** enrolled, and Milestone 11 introduces
it as an additive layer.

**Honestly unavailable.** Everything else in §30–32: web-app install, the
`PERSONAL / ACME WORK / ATLAS` context picker, per-project browser
contexts, and browser-update separation from the OS. Milestone 11 is
designed (`docs/development/milestone-11.md`) and unbuilt. The browser
here is a browser, well-integrated at the launch and link layer, and
nothing more is claimed.

---

### 2.13 Networking — not a surface, but the browser is useless without it

The image shipped a browser, a firewall, and **no way to get an IP address**:
no DHCP client was enabled and no `.network` file existed. A machine with a
perfectly good NIC came up with no address, and the browser opened to a network
error.

**CI could not have caught this.** `tools/boot-test.sh` runs the VM with
`-nic none` — the gate has no network by design, so the *absence* of networking
was invisible to every check in the repo. It was found by asking what the
browser would actually do on a real machine.

| Piece | File / unit | Note |
|---|---|---|
| Address | `/usr/lib/systemd/network/50-punar-dhcp.network` | DHCPv4 + IPv6 RA, wired only |
| Client | `systemd-networkd.service` + `.socket` | vendor `.wants`, not `/etc` |
| DNS | `systemd-resolved.service` | `/etc/resolv.conf` → stub, via tmpfiles `L+` |

Three decisions worth stating:

- **`SendHostname=no`** — a deliberate deviation from systemd's default. The
  hostname is device identity, and announcing it to every DHCP server a laptop
  ever touches is a tracking vector across networks. This is the posture the
  privacy panel claims, applied to the one place it silently leaks.
- **`systemd-networkd-wait-online` is NOT enabled.** It blocks boot for up to
  90 s waiting for an interface that may never come up. Punar's boot-time
  budget is a product claim; nothing that can stall it by 90 s gets enabled.
- **Wired only (`Type=ether`).** Wi-Fi needs an association step and a
  credential store, neither of which exists. Matching it here would produce an
  interface that is configured and permanently down — a worse lie than an
  absent one.

**This is not Milestone 12.** It is basic wired connectivity so the browser can
load a page. The private relay (§33–34), network policy, per-project contexts
and Wi-Fi remain unbuilt and unclaimed. The M3 firewall is unchanged and
already permits this: `output accept`, `input drop` with `established,related`
accepted, so replies to outbound connections return and nothing new is exposed.

**Untested in CI, and it must not be read as verified** (spec §1.22). The gate
has no NIC. This was reasoned from the firewall rules and systemd's documented
behaviour, and it is exercised for the first time by a human in the demo VM,
which is launched with user-mode networking precisely so it can be.

---

## 3. IPC targets, all thirteen

Verified unique across the tree; `qs ipc show` is the authority.

| Target | Verbs |
|---|---|
| `bar` | focus · release · state |
| `commandcenter` | toggle · open · close · state · explain · query · run |
| `overview` | toggle · open · close · state |
| `systemcontrol` | toggle · open · close · state |
| `aipanel` | toggle · open · close · state |
| `approval` | toggle · open · close · state · pending · selected |
| `alerts` | open · close · state · dnd · cards · quiet · focused |
| `notifications` | toggle · open · close · state · count · focused · owner · dismiss · clear · dnd |
| `toasts` | state · list · focused · dismiss · dismissAll |
| `osd` | state · volume · ticks · show · brightness · close |
| `shortcuts` | toggle · open · close · state · reload · rows · undescribed |
| `lock` | lock · state |
| `theme` | status · list · show · validate · preview · clear · set · reset · reload |

---

## 4. Chords added by this work

Appended to `os/modules/desktop/hypr/punar-binds.conf`. Every one uses the
**described** form, so `hyprctl binds -j` carries a human label and the
help surface can render it with no second source of truth.

| Chord | Description | Runs |
|---|---|---|
| `SUPER + S` | System control | `$shell ipc call systemcontrol toggle` |
| `SUPER + SHIFT + N` | Notification centre | `$shell ipc call notifications toggle` |
| `SUPER + /` | Shortcut help | `$shell ipc call shortcuts toggle` |
| `SUPER + SHIFT + B` | Focus status cluster | `$shell ipc call bar focus` |
| `SUPER + Escape` | Lock session | `$lock` |
| `XF86AudioRaiseVolume` | Volume up | `wpctl set-volume -l 1.0 @DEFAULT_AUDIO_SINK@ 5%+` |
| `XF86AudioLowerVolume` | Volume down | `wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%-` |
| `XF86AudioMute` | Toggle mute | `wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle` |

**Three chords the plates asked for and did not get, each because the
chord was already load-bearing** (two binds on one chord makes Hyprland
fire *both*, so this is never a free choice):

| Plate wanted | Already bound to | Shipped as |
|---|---|---|
| `SUPER + N` (notification centre) | notes scratchpad, M2 | `SUPER + SHIFT + N` |
| `SUPER + B` (status cluster) | browser, M1 | `SUPER + SHIFT + B` |
| `SUPER + L` (lock) | focus-right, M1 | `SUPER + Escape` |

The M7 precedent (`SUPER + A` taken back from the assistant scratchpad,
which moved to `SUPER + SHIFT + A`) is the way to give a plate its own
chord back; each is a one-line reassignment for whoever owns that call,
not a side effect of adding a surface. Whatever this file carries is what
the help surface prints, so a deviation can never quietly become a lie.

**Volume steps are 5%**, matching the OSD's twenty ticks exactly, so every
press moves the meter by precisely one tick and the reading is never
between two states. `-l 1.0` caps the sink so the meter can never be asked
to draw a twenty-first tick.

---

## 5. What the image gained

**Package delta: one line, zero bytes.**

| Package | Version | Installed size | Why |
|---|---|---|---|
| `qt6-svg` | 6.11.2-1 | 1056 KiB | The wallpaper loads `libqsvg.so` directly |

`qt6-svg` was **already in the image** as a hard dependency of both
`quickshell` and `qt6-wayland` (`pacman -Qi qt6-svg` → *Required By:
qt6-wayland quickshell*, verified against the pinned 2026/08/20 snapshot).
Naming it in `mkosi.conf` costs nothing and removes an unstated
assumption: a package we depend on by name is a package we notice losing.
Nothing else was needed — every surface is QML inside the process that
already runs, and the tools they shell out to (`wpctl`, `hyprctl`,
`punarctl`, `grim`, `slurp`, `jq`) already ship.

**Staging changes** (`os/images/scripts/container-build.sh`):

- `shell/theme/themes/` → `/usr/share/punar/theme/themes/` (**8 files,
  ~7 KB**). Without this the shell resolves no theme document and silently
  renders the built-in fallback palette with nothing selectable.
- The wallpaper template `Wallpaper/punar-wallpaper.svg.in` (5.8 KB) rides
  along in the existing `cp -R shell/punar-shell/.` — no rule change.

**New versioned file:** `mkosi.extra/etc/pam.d/punar-lock`.

---

## 6. Cost, stated honestly

**The daemon RSS gate does not move — at all.** `idle-ram.sh` computes
`PUNAR_SERVICES_RSS_MB` as summed PSS over the cgroups of
`punard.service punar-agentd.service punar-secrets.service`. This work
adds **no daemon**: the notification server, the wallpaper, the lock and
the settings panel are all QML inside `punar-shell`, which is a *user*
process and is not in that sum. That gate is untouched by construction.

**The shell process itself is doing far more, and the shell is in the
idle-RAM number.** `PUNAR_RAM_MEAN_MB` is `MemTotal - MemAvailable` across
the whole VM, so every megabyte the shell gained shows up there. Gates:
**warn above 1024 MB, fail above 1536 MB.**

Expectation, built up from what each surface actually holds:

| Addition | Expected resident cost |
|---|---|
| Wallpaper texture | **the dominant term** — one RGBA8888 texture per output at the fitted size: ~7.5 MB at 1920×1080, ~30 MB at 3840×2160 (D-015 Sect V.03's own budget), plus a full-screen background layer surface |
| System Control | ~4–6 MB; no detail view is instantiated until selected, and the layer surface exists only while open |
| Notifications | low single-digit MB — D-Bus service registration plus the retained records; no image decode path, no cache, no history file |
| Lock | ~0 until locked (it holds a `WlSessionLock` with **zero surfaces** while unlocked) |
| Shortcut help | one `Item` + one idle `Process` until first open; ~55 cached row objects after |
| Bar cluster | no watch, no timer and no window at rest |
| Themes | one parsed palette; the catalog is built on demand |

**We are not quoting a measured figure, because we do not have an honest
one.** The only numbers available locally come from an emulated
`linux/amd64` container under llvmpipe, where a bare `ShellRoot` alone
measures 95 MB and an *empty* full-screen background layer window measures
327 MB — a software-rasteriser artefact, not a VM prediction. Quoting it
would be worse than quoting nothing.

**How the next CI run measures it, with no new instrumentation:** the
desktop boot test already runs `punar-idle-ram.sh` — ten minutes of
stabilisation with no input, then thirty samples at 10 s — and prints
`PUNAR_RAM_MEAN_MB` / `PUNAR_RAM_MAX_MB`, which `tools/boot-test.sh` gates.
The previous run's mean is the baseline; **the delta this pass costs is
exactly the difference, and it either fits under 1024 MB or it does not.**
There is no third answer and no place to hide: the wallpaper is a
full-screen texture that exists from login, so if anything moves the
number, that is what moved it.

**Idle CPU is unchanged (spec §6.3).** No surface polls. The complete list
of timers on a logged-in, idle, personal machine is: **one** `SystemClock`
at minute precision for the bar. Everything else is gated —

| Timer | Runs only while |
|---|---|
| Bar seconds clock | an approval is pending or a grant is live |
| Toast dwell | that toast is on screen |
| Approval countdown (centre) | the centre is open **and** an approval is pending |
| §48 grant countdown (System Control) | the panel is open **and** on the Privilege view **and** a grant is live |
| Lock clock | the screen is locked (one-shot re-armed on the minute boundary) |

Everything else is inotify (`FileView`), Hyprland socket2, PipeWire events
or D-Bus. The wallpaper has no timer at all.

---

## 7. Verification actually run

| Check | Method | Result |
|---|---|---|
| **qmllint** | pinned container (Arch @ `snapshot.env` base, emulated `linux/amd64`; qmllint 6.11.2, quickshell 0.3.0-3, qt6-svg 6.11.2), repo `.qmllint.ini`, every `.qml` in the tree | **34 files, 0 warnings, exit 0** |
| **Hyprland config** | `Hyprland --verify-config` on hyprland 0.56.2-1 in the pinned container, as an unprivileged user | **`config ok`** |
| **— negative control** | injected `thisdispatcherdoesnotexist` | **correctly rejected** (`Invalid dispatcher … at line 321`) — the pass is not vacuous |
| **Chord collisions** | every `bind*` row reduced to `(modmask, key)` and counted | **72 binds, 0 duplicate chords** |
| **IPC target collisions** | every `IpcHandler.target` in the tree | **13 targets, all unique** |
| **Image config** | `PUNAR_BUILD_MODE=summary ./tools/build-image.sh all` | **exit 0**; `qt6-svg` present in the desktop profile's package list; themes staged to `usr/share/punar/theme/themes/` |
| **qmllint, now in CI** | `./tools/qmllint.sh` — pinned container, the image's own Qt 6.11.2 / Quickshell 0.3.0 | **34 files, 0 warnings.** The gate fails on any output, because **qmllint exits 0 while printing warnings** — verified by injecting `Hyprland.thisPropertyDoesNotExist`, which it named while returning 0 |
| **— negative control** | that same injected property | **correctly fails** (exit 1); on the restored tree, exit 0 |
| **Live surfaces exercise** | `surfaces-check.sh` in the CI VM: every surface opened and closed over IPC, each layer confirmed in `hyprctl -j layers`, each frame captured | **found 3 real defects on its first run** (below) |

### What the first live run found

The exercise above is new, and its first execution in the CI VM (run
[32945695360](https://github.com/smplify-mdm/punar/actions/runs/32945695360))
**failed, correctly**, on three things no static check could see. Recorded
here because "the gate found real defects on day one" is the only evidence
that a gate is worth having.

| Found | Where the defect was |
|---|---|
| `theme list` answered `{"ready":true,"themes":[]}` on a machine with **seven** themes installed | **product** — no theme was selectable while the desktop looked perfectly themed |
| `bar app` returned `""` while Hyprland reported `chromium` focused | **product** — the menubar could never have named a window opened after shell start |
| `approval.open` did not open | **the check** — a gate with nothing pending is *correct* to stay closed |

A fourth was caught by the screenshots rather than an assertion: the command
centre photographed as an empty desktop while its own `state()` said `open`.
`state()` reads `root.open`; the window is bound to `root.windowVisible`, a
different property that exists so a surface can stay mapped through its close
animation. Between the flag flipping and the compositor mapping anything there
is a real interval where "open" is true and the screen is bare. Every surface
declares a `WlrLayershell.namespace`, so `hyprctl -j layers` now answers the
question exactly — in both directions, because several of these overlays hold
`WlrKeyboardFocus.Exclusive` and one that reports closed while still mapped is
holding the keyboard.

**What has NOT been verified, and must not be read as verified**
(spec §1.22): the three fixes above are pushed and awaiting their own CI run;
until it is green they are repairs believed correct, not repairs demonstrated
correct. Beyond that: no surface in this composed arrangement had been run in
the real VM before that run. Individual surfaces were exercised headlessly by their authors —
sway/wlroots in a pinned container, driven over IPC, screenshotted with
grim — which found and fixed real defects (a lazily-evaluated `rowCount`
indexing off the end of a list; a 4.4 MB-per-switch leak in Qt's `data:`
URL image path; a `FileView` path-walk stall). Those runs were emulated,
software-rendered and non-authoritative. **The CI VM is the arbiter.**

---

## 8. Follow-ups this pass deliberately did not take

- **`docs/development/keyboard-grammar.md` is now stale** — it predates
  five chords. It is not owned by this pass.
- **`shell/punar-shell/README.md`** describes an older tree.
- **The three chord reassignments** in §4 — each is a one-line edit to an
  existing bind and a design call, not an integration one.
- **Promoting the bar's ORG annotation to a focusable slot** (§2.2).
- **`punarctl theme`** — the shell exposes the whole verb set over IPC, but
  the CLI side is unwritten. The full arithmetic it must reproduce (and
  the reason it, not the shell, must write the SHA-256 receipt half: QML
  offers only `Qt.md5`) is written out at the bottom of
  `Theme/ThemeContrast.qml`.
- **`theme-system.md` §7.3's panel wallpaper row** needs a one-line
  correction — `mix(…, 0.55)` and full-strength `panel.edge` make the
  loudest wallpaper stroke exactly *tie* the window border it must stay
  under, in all seven themes. The shipped code uses 0.42/0.75, which
  reproduces the published SVG byte-for-byte. Changing the doc changes no
  shipped pixel.
- **`theme-system.md` §7.3's `contrast` row** carries two figures
  (1.119/1.271) that measure 1.090/1.203. Non-binding column.
