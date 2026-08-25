# Implementation Status

Tracks progress against the milestone plan in
[`docs/product/SPEC_v0.2.md`](docs/product/SPEC_v0.2.md) section 76. The spec
is authoritative; this file only records status.

Last updated: 2026-08-25.

## M0 — Foundation evaluation: done (acceptance met)

Acceptance criterion — reproducible build and VM boot — is **met**: CI run
[32788238871](https://github.com/smplify-mdm/punar/actions/runs/32788238871)
(2026-08-24) is fully green: `rust`, `contracts`, the containerized mkosi
image build, and the QEMU/OVMF boot test observing the `PUNAR_BOOT_OK`
serial marker.

Deliverables (spec section 76, Milestone 0):

- [x] Substrate ADR — `ADR-001 Distribution Substrate` comparing Arch, NixOS,
  and Fedora Atomic/image-based approaches (spec section 8.4) exists at
  [`docs/architecture/adr/ADR-001-distribution-substrate.md`](docs/architecture/adr/ADR-001-distribution-substrate.md)
  (status: Accepted — ratified 2026-08-24).
- [x] VM build — the containerized mkosi pipeline (`os/images/`,
  `tools/build-image.sh`, `tools/boot-test.sh`; see
  [`docs/development/image-pipeline.md`](docs/development/image-pipeline.md))
  built the minimal `punar-dev` qcow2 and booted it under QEMU/OVMF in CI
  run [32788238871](https://github.com/smplify-mdm/punar/actions/runs/32788238871)
  (`PUNAR_BOOT_OK` on the serial console).
- [x] CI — `.github/workflows/ci.yml`; first fully green run:
  [32788238871](https://github.com/smplify-mdm/punar/actions/runs/32788238871)
  (jobs green in that run: rust, contracts, image, boot-test). The M1
  `desktop-test` job has since had its first green run too:
  [32804034681](https://github.com/smplify-mdm/punar/actions/runs/32804034681)
  (2026-08-25, all five jobs green — see M1 below). The workflow on disk
  has since grown the M2 exercise phase inside `desktop-test`, which has
  **no** recorded run yet (see M2 below).
- [x] Repository — skeleton per spec section 67 (all section 67 directories
  and top-level documents exist; Cargo workspace members match the crates on
  disk).
- [x] Resource-budget baseline — budgets are defined in
  [`PERFORMANCE_BUDGETS.md`](PERFORMANCE_BUDGETS.md) and the first baseline
  measurement is now recorded: CI run
  [32804034681](https://github.com/smplify-mdm/punar/actions/runs/32804034681)
  (2026-08-25) measured `punar-desktop` idle RAM in the VM at
  **mean 1162 MB / max 1168 MB** (`punar-desktop-ram-report` artifact) —
  within the 1536 MB hard ceiling, above the 1024 MB target, recorded as a
  CI warning. Closing the gap to the target is ongoing budget work, not an
  M0 item.

## M1 — Lightweight graphical workstation: CI gate green; one acceptance item open

Detailed plan and per-claim verification:
[`docs/development/milestone-1.md`](docs/development/milestone-1.md) and
[`docs/development/image-pipeline.md`](docs/development/image-pipeline.md)
(their "no desktop-test run recorded" statements are dated 2026-08-24 and
were true when written).

The first green `desktop-test` run —
[32804034681](https://github.com/smplify-mdm/punar/actions/runs/32804034681),
2026-08-25, KVM runner — proved at runtime what was previously only
config-validated: the `punar-desktop` image completes a full mkosi build;
the greetd autologin → Hyprland → punar-shell chain starts under QEMU
virtio-vga with llvmpipe (`PUNAR_DESKTOP_OK` after 18 s); grim captured a
real rendered frame (`punar-desktop-screenshot` artifact); the in-guest
idle-RAM measurement ran and passed the budget gate
(`punar-desktop-ram-report` artifact).

Deliverables (spec section 76, Milestone 1):

- [x] Wayland — Wayland-only session (`XDG_SESSION_TYPE=wayland`; greetd →
  Hyprland chain in the `punar-desktop` mkosi profile,
  `os/images/mkosi.profiles/desktop/`). **Runtime-proven** (run
  32804034681).
- [x] Compositor — hyprland 0.56.2-1 from the pinned snapshot; config at
  `os/modules/desktop/hypr/` (shipped as `/etc/xdg/hypr/`), validated with
  `Hyprland --verify-config` on the exact pinned package. **Runtime-proven**
  (virtio-vga + llvmpipe rendering; real frame in the screenshot artifact).
- [x] Shell — punar-shell Quickshell/QML top bar (`shell/punar-shell/`,
  staged into the image at `/usr/share/punar/shell/`), design tokens from
  `shell/theme/punar-tokens.json`, bound to
  [`docs/design/DESIGN_LANGUAGE.md`](docs/design/DESIGN_LANGUAGE.md).
  **Runtime-proven** (`PUNAR_DESKTOP_OK` requires quickshell up).
- [x] Command center — `CommandCenter/CommandCenter.qml` overlay on
  SUPER+Space (Hyprland → quickshell IPC), implementing the
  `docs/design/mockups/command-approval.html` design. The shell that loads
  it runs in-VM; the overlay's interactive behavior and design fidelity
  remain human-verified (keyboard walkthrough below).
- [x] Terminal — foot 1.27.0-2 + `os/modules/desktop/foot/foot.ini`
  (SUPER+Return; scratchpad on SUPER+T). In-image; interactive use is part
  of the human walkthrough.
- [x] Browser — chromium 151.0.7922.169-1, upstream and unpatched
  (spec section 48), launched via SUPER+B; deeper integration is M11.
- [x] Git — git 2.55.0-1 in the `punar-desktop` package set.
- [x] Editor — neovim 0.12.4-1 in the `punar-desktop` package set.
- [x] Podman — podman 6.1.0-1 + crun, netavark, aardvark-dns; rootless
  setup (subuid/subgid, dev user) in the profile postinst.
- [x] Keyboard navigation — SUPER-leader grammar in
  `os/modules/desktop/hypr/punar-binds.conf`, documented in
  [`docs/development/keyboard-grammar.md`](docs/development/keyboard-grammar.md);
  config verified against the pinned hyprland; the config demonstrably
  loads in-VM (the session came up). Behavior is exercised by the M2 CI
  exercise (pending) and the human walkthrough.

Acceptance (spec section 76, Milestone 1):

- [x] **Idle RAM measured** — run
  [32804034681](https://github.com/smplify-mdm/punar/actions/runs/32804034681):
  mean 1162 MB / max 1168 MB (VM, per PERFORMANCE_BUDGETS.md §2.2 method).
  Verdict from `tests/performance/check-budgets.sh`: **pass with warning**
  — under the 1536 MB hard ceiling, over the 1024 MB (1.0 GB) target. The
  criterion ("idle RAM measured") is met; getting under the target is
  tracked budget work.
- [ ] **No mouse required for core desktop use** — keyboard-only
  walkthrough scripted in
  [`docs/development/keyboard-grammar.md`](docs/development/keyboard-grammar.md);
  it must be executed by a human against a booted desktop image. **Still
  pending** — this is the only open M1 item.

## Current milestone: M2 — Native multitasking (in progress)

Detailed plan, capability verification, and the in-VM exercise contract:
[`docs/development/milestone-2.md`](docs/development/milestone-2.md).
Everything checked below exists **on disk and is statically validated**
(per milestone-2.md §1 and §8: a `Hyprland --verify-config` probe of every
new dispatcher/keyword on the pinned 0.56.2-1 binary with a negative
control; qmllint-clean QML; `punar-workspace` cargo tests; schema +
fixture validation — re-run 2026-08-25, 15 schemas / 123 documents ALL
PASS including the new `schemas/workspace/` domain; shellcheck v0.11.0 and
actionlint clean; `mkosi summary` pass with the M2 staging). **None of it
has executed in a VM**: the green `desktop-test` run above predates the M2
exercise wiring, so no CI run has yet executed `punar-m2-check`. That
first run is the arbiter for every item marked "runtime CI-pending"
(spec 1.22).

Deliverables (spec section 76, Milestone 2) — on disk vs proven:

- [x] Tiling — layout machinery over the M1 dwindle base: four tiled
  algorithms (dwindle/scrolling/master/monocle) driven per preset (see
  Layouts). Keywords/dispatchers config-verified on the pinned binary.
  Runtime CI-pending (exercise rows 5–6).
- [x] Stacking — tab/stack group grammar (SUPER+G toggle, SUPER+SHIFT+G
  out, SUPER+[ / ] cycle, SUPER+CTRL+HJKL move-into) in
  `os/modules/desktop/hypr/punar-binds.conf`; design-language groupbar
  styling in `punar-look.conf`; `stack` preset (monocle) for
  one-window-at-a-time. Config-verified. Runtime CI-pending (rows 2–3).
- [x] Floating — pin (SUPER+SHIFT+V), center (SUPER+C), float-aware
  move/resize on top of M1's togglefloating. Config-verified. Runtime
  CI-pending (row 4).
- [x] Overview — SUPER+TAB project-workspace overview
  (`shell/punar-shell/Overview/Overview.qml`) implementing Plate D-007
  (`docs/design/mockups/desktop-multitasking.html`): project card grid,
  wireframe minis scaled from real client geometry, meta rows,
  type-to-search, arrow navigation, selection as raise fill + 2 px ink
  rule, 300 ms `cubic-bezier(0.2,0,0,1)` motion only where it explains
  state. Event-driven (Quickshell Hyprland models + one refresh on open;
  no polling), toggled via Quickshell IPC. qmllint-clean. Runtime behavior
  CI-pending (row 9); design fidelity human-reviewed against the plate.
- [x] Layouts — five presets (`balanced`, `columns`, `rows`, `focus`,
  `stack`) applied by `/usr/lib/punar/punar-layout.sh` (source
  `os/modules/desktop/hypr/punar-layout.sh`; one `hyprctl --batch` per
  invocation, one-shot, shellcheck-clean), cycled on SUPER+comma/period,
  restored on session start. A `grid` preset is **deliberately not
  shipped** — hyprland 0.56.2 has no native grid algorithm
  (milestone-2.md §1.3/§2). Runtime CI-pending (rows 5–6).
- [x] Scratchpads — assistant (SUPER+A) and notes (SUPER+N) special
  workspaces join M1's terminal (SUPER+T), with silent window rules.
  Config-verified. Runtime CI-pending (row 7).
- [x] Named project workspaces — rename (overview inline + command
  center), `name:` navigation, names in bar and overview; persistence to
  `~/.local/state/punar/workspaces.json` written only by
  `Services/WorkspaceState.qml` (atomic writes, event-driven, 1 s
  debounce, restore on shell start); typed contract in the
  `punar-workspace` crate (serde round-trip + name-regex tests) with JSON
  Schema `schemas/workspace/workspace-state.json` and fixtures. Schema and
  crate validated; in-VM write/restore CI-pending (rows 1, 8, 10–11).
- [x] M2 CI exercise wiring — in-guest `/usr/lib/punar/m2-check.sh` +
  `punar-m2-check.service` (started synchronously after the idle-RAM
  sampling window, before the export), verdict in `m2-report.txt`, hard
  gate in `tools/boot-test.sh` phase 4, `desktop-test` job + artifact
  uploads extended in `ci.yml`. Statically validated (shellcheck,
  actionlint, `mkosi summary`); **no recorded run**.

What only a green `desktop-test` run including the M2 exercise will prove
(all currently unverified; milestone-2.md §7 is the assertion list):
rename lands in `hyprctl -j workspaces` and survives a shell restart via
the state file; group create/cycle/leave behave; float + pin + center
behave; each preset actually flips `general:layout` and the workspace
`tiledLayout`; preset cycling and the preset cache file; the assistant and
notes specials toggle cleanly; `workspace name:` navigation; the overview
opens/closes over IPC and renders (screenshot `punar-m2.png`); the state
file on disk matches the schema; and budgets stay green with no new
always-on processes.

Out of scope for M2 (decided in milestone-2.md §2, not regressions):
`grid` preset, per-workspace presets, full §14.3 restoration (app
reopening), §14.4 activities, §15 monitor-layout memory, mouse
drag-to-tile.

## Milestone table

Deliverables are condensed to one line each; see spec section 76 for the full
lists. The spec states explicit acceptance criteria only for M0 and M1; for
the other milestones the working criterion is that the listed deliverables
exist and function, until sharper criteria are defined.

| Milestone | Deliverables (one line) | Acceptance | Status |
| --- | --- | --- | --- |
| M0 — Foundation evaluation | Substrate ADR; resource-budget baseline; VM build; CI; repository | Reproducible build and VM boot | **Done** — acceptance met, [CI run 32788238871](https://github.com/smplify-mdm/punar/actions/runs/32788238871); budget baseline recorded in [run 32804034681](https://github.com/smplify-mdm/punar/actions/runs/32804034681) |
| M1 — Lightweight graphical workstation | Wayland, compositor, shell, command center, terminal, browser, Git, editor, Podman, keyboard navigation | Idle RAM measured; no mouse required for core desktop use | **CI gate green** — [run 32804034681](https://github.com/smplify-mdm/punar/actions/runs/32804034681) (2026-08-25): build, boot, `PUNAR_DESKTOP_OK`, idle RAM 1162 MB mean (pass w/ over-target warning); human keyboard-only walkthrough pending |
| M2 — Native multitasking | Tiling, stacking, floating, overview, layouts, scratchpads, named project workspaces | Not specified in spec §76 | **In progress** — all deliverables on disk + statically validated (see checklist above); first `desktop-test` run with the M2 exercise pending |
| M3 — `punard` + `punarctl` | Daemon, typed IPC, capability registry, CLI, audit | Not specified in spec §76 | Not started (M2 ships its typed workspace-state contract in `punar-workspace` for M3 to consume) |
| M4 — Declarative desired state | Schemas, preference/policy merge, reconciliation, explain, firewall-drift demo | Not specified in spec §76 | Not started |
| M5 — Mock Smplify enrollment | Mock control plane, device enrollment, policy, compliance, inventory | Not specified in spec §76 | Not started |
| M6 — Developer environment manager | `punar-env`, Podman/devcontainer, Atlas fixture | Not specified in spec §76 | Not started |
| M7 — AI Agent Registry | Managed sessions, Claude adapter, second/generic adapter, agent identity, classification, local UI | Not specified in spec §76 | Not started |
| M8 — AI Access Ledger | Resource summaries, process attribution, security events, local retention, privacy controls | Not specified in spec §76 | Not started |
| M9 — Approval gates + secret broker | Local graphical approval, short-lived mock credentials, redaction tests | Not specified in spec §76 | Not started |
| M10 — Shadow AI detection MVP | Known/observed/unknown classification, fixture unknown agent, local alert, Smplify remote query | Not specified in spec §76 | Not started |
| M11 — Browser/web-app integration | Current Chromium, native launcher integration, project/browser context prototype, web-app install flow | Not specified in spec §76 | Not started |
| M12 — Network privacy prototype | Local network observability, project-route policy, relay abstraction, simulated or prototype private relay | Not specified in spec §76 | Not started |
| M13 — Demo polish | First boot, enrollment, keyboard UX, AI panel, privacy panel, deterministic demo | Not specified in spec §76 | Not started |
