# Implementation Status

Tracks progress against the milestone plan in
[`docs/product/SPEC_v0.2.md`](docs/product/SPEC_v0.2.md) section 76. The spec
is authoritative; this file only records status.

Last updated: 2026-08-24.

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
  (jobs green in that run: rust, contracts, image, boot-test). The workflow
  on disk has since grown the M1 `desktop-test` job, which has **no**
  recorded green run yet (see M1 below).
- [x] Repository — skeleton per spec section 67 (all section 67 directories
  and top-level documents exist; Cargo workspace members match the crates on
  disk).
- [ ] Resource-budget baseline — budgets are defined in
  [`PERFORMANCE_BUDGETS.md`](PERFORMANCE_BUDGETS.md) and the idle-RAM
  measurement harness now exists (`tests/performance/` + the `desktop-test`
  CI job, built as M1 work), but **no measurement has run yet**. The first
  green `desktop-test` run records the baseline. Carried into M1; M0's
  acceptance criterion (reproducible build and VM boot) did not depend on
  it and is met regardless.

## Current milestone: M1 — Lightweight graphical workstation (in progress)

Detailed plan and per-claim verification:
[`docs/development/milestone-1.md`](docs/development/milestone-1.md) (§11)
and [`docs/development/image-pipeline.md`](docs/development/image-pipeline.md).
Everything checked below exists **on disk and is config-validated**
(`mkosi summary` for both images, `Hyprland --verify-config` against the
pinned package, shellcheck-clean scripts); none of it has executed in a VM.
As of 2026-08-24 **no green `desktop-test` CI run is recorded** — that run
is the arbiter for every item marked "runtime CI-pending" (spec 1.22).

Deliverables (spec section 76, Milestone 1) — on disk vs proven:

- [x] Wayland — Wayland-only session (`XDG_SESSION_TYPE=wayland`; greetd →
  Hyprland chain in the `punar-desktop` mkosi profile,
  `os/images/mkosi.profiles/desktop/`). Runtime CI-pending.
- [x] Compositor — hyprland 0.56.2-1 from the pinned snapshot; config at
  `os/modules/desktop/hypr/` (shipped as `/etc/xdg/hypr/`), validated with
  `Hyprland --verify-config` on the exact pinned package. Runtime
  (virtio-vga + llvmpipe rendering) CI-pending.
- [x] Shell — punar-shell Quickshell/QML top bar (`shell/punar-shell/`,
  staged into the image at `/usr/share/punar/shell/`), design tokens from
  `shell/theme/punar-tokens.json`, bound to
  [`docs/design/DESIGN_LANGUAGE.md`](docs/design/DESIGN_LANGUAGE.md).
  Runtime CI-pending (`PUNAR_DESKTOP_OK` requires quickshell up).
- [x] Command center — `CommandCenter/CommandCenter.qml` overlay on
  SUPER+Space (Hyprland → quickshell IPC), implementing the
  `docs/design/mockups/command-approval.html` design. Runtime CI-pending;
  design fidelity is human-reviewed against the mockup.
- [x] Terminal — foot 1.27.0-2 + `os/modules/desktop/foot/foot.ini`
  (SUPER+Return; scratchpad on SUPER+T).
- [x] Browser — chromium 151.0.7922.169-1, upstream and unpatched
  (spec section 48), launched via SUPER+B; deeper integration is M11.
- [x] Git — git 2.55.0-1 in the `punar-desktop` package set.
- [x] Editor — neovim 0.12.4-1 in the `punar-desktop` package set.
- [x] Podman — podman 6.1.0-1 + crun, netavark, aardvark-dns; rootless
  setup (subuid/subgid, dev user) in the profile postinst.
- [x] Keyboard navigation — SUPER-leader grammar in
  `os/modules/desktop/hypr/punar-binds.conf`, documented in
  [`docs/development/keyboard-grammar.md`](docs/development/keyboard-grammar.md);
  config verified against the pinned hyprland. In-VM behavior CI-pending.

Acceptance (spec section 76, Milestone 1):

- [ ] **Idle RAM measured** — mechanism implemented end to end (in-guest
  `punar-idle-ram.service` sampling per PERFORMANCE_BUDGETS.md §2.2 →
  serial `PUNAR_RAM_MEAN_MB`/`PUNAR_RAM_MAX_MB` → `tools/boot-test.sh
  --mode desktop` → `tests/performance/check-budgets.sh` budget gate →
  `punar-desktop-ram-report` CI artifact), but **no measurement exists
  yet**: the first green `desktop-test` run produces it.
- [ ] **No mouse required for core desktop use** — keyboard-only
  walkthrough scripted in
  [`docs/development/keyboard-grammar.md`](docs/development/keyboard-grammar.md);
  it must be executed by a human against a booted desktop image (CI can
  only check the proxy: the keybind config ships in the image). Pending the
  first bootable punar-desktop.

What only a green `desktop-test` CI run will prove (all currently
unverified): the `punar-desktop` image completes a full mkosi build; the
greetd autologin → Hyprland → punar-shell chain starts under QEMU
virtio-vga with llvmpipe; the `PUNAR_DESKTOP_OK` marker fires; grim
captures a real frame (screenshot artifact); the idle-RAM numbers land and
pass the budget gate.

## Milestone table

Deliverables are condensed to one line each; see spec section 76 for the full
lists. The spec states explicit acceptance criteria only for M0 and M1; for
the other milestones the working criterion is that the listed deliverables
exist and function, until sharper criteria are defined.

| Milestone | Deliverables (one line) | Acceptance | Status |
| --- | --- | --- | --- |
| M0 — Foundation evaluation | Substrate ADR; resource-budget baseline; VM build; CI; repository | Reproducible build and VM boot | **Done** — acceptance met, [CI run 32788238871](https://github.com/smplify-mdm/punar/actions/runs/32788238871) (measured budget baseline carried into M1) |
| M1 — Lightweight graphical workstation | Wayland, compositor, shell, command center, terminal, browser, Git, editor, Podman, keyboard navigation | Idle RAM measured; no mouse required for core desktop use | **In progress** — on disk + config-validated; first green `desktop-test` CI run pending |
| M2 — Native multitasking | Tiling, stacking, floating, overview, layouts, scratchpads, named project workspaces | Not specified in spec §76 | Not started |
| M3 — `punard` + `punarctl` | Daemon, typed IPC, capability registry, CLI, audit | Not specified in spec §76 | Not started |
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
