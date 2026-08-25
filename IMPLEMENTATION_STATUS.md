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
  (2026-08-25, all five jobs green — see M1 below). The M2 exercise phase
  inside `desktop-test` has since gone green as well: run
  [32825539021](https://github.com/smplify-mdm/punar/actions/runs/32825539021)
  (2026-08-25, see M2 below). The M3 exercise phase has its green run too:
  [32828986305](https://github.com/smplify-mdm/punar/actions/runs/32828986305)
  (2026-08-25, see M3 below). The workflow in the working tree has since
  grown the M4 exercise phase (uncommitted), which has **no** recorded run
  yet (see M4 below).
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
  exercise (green — run
  [32825539021](https://github.com/smplify-mdm/punar/actions/runs/32825539021))
  and the human walkthrough.

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

## M2 — Native multitasking: done (CI exercise green)

Detailed plan, capability verification, and the in-VM exercise contract:
[`docs/development/milestone-2.md`](docs/development/milestone-2.md) (its
status line "runtime acceptance pending the first desktop CI run that
includes the M2 exercise" is dated 2026-08-25 and predates the green run
recorded here).

The arbiter run has happened: CI run
[32825539021](https://github.com/smplify-mdm/punar/actions/runs/32825539021)
(2026-08-25, KVM runner, all five jobs green) ran the M2 exercise —
`punar-m2-check` executed inside the booted `punar-desktop` VM and
delivered **`PUNAR_M2_OK`**: the milestone-2.md §7 assertion list passed at
runtime (rename lands in `hyprctl` and survives a shell restart via the
schema-valid state file; group create/cycle/leave; float + pin + center;
each preset flips `general:layout` and the workspace `tiledLayout`; preset
cycling + cache; assistant and notes scratchpads; `workspace name:`
navigation; the overview toggles over IPC and rendered — `punar-m2.png` in
the `punar-desktop-screenshot` artifact). Budgets stayed green with no new
always-on processes: idle RAM **mean 1157 MB / max 1162 MB** (under the
1536 MB ceiling, over the 1024 MB target — recorded warning;
`m2-report.txt` ships in the `punar-desktop-ram-report` artifact).

Deliverables (spec section 76, Milestone 2) — all on disk, statically
validated (milestone-2.md §1/§8: `Hyprland --verify-config` probes on the
pinned 0.56.2-1 binary, qmllint-clean QML, `punar-workspace` cargo tests,
schema + fixture validation, shellcheck v0.11.0, actionlint, `mkosi
summary`), and **runtime-proven** by run 32825539021:

- [x] Tiling — four tiled algorithms (dwindle/scrolling/master/monocle)
  driven per preset.
- [x] Stacking — tab/stack group grammar (SUPER+G / SUPER+SHIFT+G /
  SUPER+[ ] / SUPER+CTRL+HJKL) in
  `os/modules/desktop/hypr/punar-binds.conf`; `stack` (monocle) preset.
- [x] Floating — pin (SUPER+SHIFT+V), center (SUPER+C), float-aware
  move/resize.
- [x] Overview — SUPER+TAB project-workspace overview
  (`shell/punar-shell/Overview/Overview.qml`, Plate D-007), event-driven,
  toggled via Quickshell IPC; rendered in-VM (`punar-m2.png`). Design
  fidelity remains human-reviewed against the plate — CI proves behavior,
  not aesthetics.
- [x] Layouts — five presets (`balanced`, `columns`, `rows`, `focus`,
  `stack`) via `/usr/lib/punar/punar-layout.sh`, cycled on
  SUPER+comma/period, restored on session start; `grid` deliberately not
  shipped (no native hyprland algorithm — milestone-2.md §1.3/§2).
- [x] Scratchpads — assistant (SUPER+A) and notes (SUPER+N) specials
  alongside M1's terminal (SUPER+T).
- [x] Named project workspaces — rename, `name:` navigation, names in bar
  and overview; persistence to `~/.local/state/punar/workspaces.json`
  (atomic, event-driven, restored on shell start); typed contract in the
  `punar-workspace` crate + `schemas/workspace/workspace-state.json`; the
  in-VM state file validated against the schema by the exercise.
- [x] M2 CI exercise wiring — `/usr/lib/punar/m2-check.sh` +
  `punar-m2-check.service`, verdict in `m2-report.txt`, hard gate in
  `tools/boot-test.sh` phase 4 — exercised end-to-end in run 32825539021.

Out of scope for M2 (decided in milestone-2.md §2, not regressions):
`grid` preset, per-workspace presets, full §14.3 restoration (app
reopening), §14.4 activities, §15 monitor-layout memory, mouse
drag-to-tile.

## M3 — `punard` + `punarctl`: done (CI exercise green)

Architecture plan, decisions, and as-built list:
[`docs/development/milestone-3.md`](docs/development/milestone-3.md)
(§12 is the implementation status; its "no CI run yet / CI is the arbiter"
statements are dated 2026-08-25 and predate the green run recorded here).
Binding wire contract:
[`docs/api/ipc.md`](docs/api/ipc.md). The build-strategy decision is
recorded as
[ADR-002 Distribution of First-Party Binaries](docs/architecture/adr/ADR-002-first-party-binaries.md).
Everything M3 ships runs in personal mode (design language section 8): no
org anything; policy citations are `personal-defaults` / "os default".

Everything checked below exists **on disk and is statically validated** —
re-verified 2026-08-25 by the M3 status audit against the tree as committed
at f1ff60c (the working tree has since grown the uncommitted M4 changes —
see M4 below): whole workspace
green in the `docker rust:1` container (`cargo test --workspace --locked`:
**200 tests, 0 failed**; fmt/clippy green per milestone-3.md §12);
shellcheck v0.11.0 clean on all five touched scripts (`m3-check.sh`,
`idle-ram.sh`, `boot-test.sh`, `check-budgets.sh`, `container-build.sh`);
actionlint clean on `ci.yml`; contract validation 15 schemas / 123
documents ALL PASS. The `mkosi summary` pass for both images with the M3
staging and the ~50 s in-builder compile probe are recorded in
milestone-3.md §12 (emulated local runs — non-authoritative per spec 1.22).

The arbiter run has happened: CI run
[32828986305](https://github.com/smplify-mdm/punar/actions/runs/32828986305)
(2026-08-25, KVM runner, all five jobs green) built the desktop image with
the hermetically staged binaries and executed `punar-m3-check` inside the
booted VM, delivering **`PUNAR_M3_OK` (27 assertions passed)**. The same
run recorded the first real services-RSS number — `PUNAR_SERVICES_RSS_MB`
= **2 MB** (summed PSS of the `punard.service` cgroup, against the 100 MB
warn / 150 MB fail budget) — and idle RAM mean 1160 MB / max 1167 MB (pass
with the standing over-target warning). Every item marked "runtime-proven"
below cites this run. One dated caveat: the run exercised `m3-check.sh` as
committed at f1ff60c (M3 report-only reconcile); the working tree has since
amended m3-check for M4's remediating reconcile (milestone-4.md §10.4), and
the amended script has no recorded run yet.

Deliverables (spec section 76, Milestone 3) — on disk vs proven:

- [x] Daemon — `punard` (`crates/punard/`): std thread-per-connection UDS
  server at `/run/punard/punard.sock` (**no async runtime** — budgets
  §6.2 frugality; milestone-3.md §3), `SO_PEERCRED` admission via
  `rustix`, root-only mutations (`personal-defaults`), desired-state store
  `/var/lib/punar/desired.json`, boot reconcile (one boot-time apply:
  the firewall os-default). `punard.service` + vendor-level
  `multi-user.target.wants/` symlink + `tmpfiles.d/punard.conf` in the
  desktop extra tree (the M1 preset lesson applied). Unit/integration
  tests green, incl. a socketpair authz matrix. Runtime-proven (run
  32828986305: m3-check rows 1–2, 9; boot reconcile in-image).
- [x] Typed IPC — versioned `{v:1, id, method, params}` NDJSON envelope,
  closed six-method set, **no exec/shell method** (spec sections 10, 60;
  m3-check row 10 probes for it); wire contract in `docs/api/ipc.md`;
  envelope serde round-trip and contract-example tests in `punar-common`.
  Runtime-proven (run 32828986305 — every m3-check RPC ran in-VM).
- [x] Capability registry — three real capabilities behind one
  observe/apply/verify/descriptor trait: `security.firewall` (nftables
  table `inet punar-base`, inbound-drop; ruleset vendored at
  `/usr/share/punar/nftables/punar-base.nft`; `nftables` added to the
  desktop package list), `system.hostname` (`/etc/hostname` +
  `/proc/sys/kernel/hostname`, no D-Bus), `time.timezone`
  (`/etc/localtime` symlink, traversal-guarded). Descriptors conform to
  `schemas/capability/capability-descriptor.json`; `nft` parser tested
  against fixtures captured from the pinned `nftables 1:1.1.6-3`. Real
  in-image apply/verify runtime-proven (run 32828986305, rows 4–7).
- [x] CLI — `punarctl` real `status`, `capabilities [get|set]`,
  `audit tail`, `reconcile`, global `--json`, hidden `debug rpc`; human
  output per Plate D-014 through one formatter module (personal mode — no
  org rows); section-73 denial voice; exit-code contract (0/1/2/3/5, 4
  reserved). 42 punarctl tests green incl. D-014 snapshot tests against a
  mock daemon. Other subcommands keep their milestone stubs.
  Runtime-proven (run 32828986305, rows 3–6, 9).
- [x] Audit — every mutation and every denial appended to
  `/var/log/punar/audit.jsonl` (0640 root:punar, punard-only writes),
  events conform to `schemas/audit/audit-event.json` with documented
  sentinels (`agt_none`, `project_id:"system"`; daemon-initiated events
  use `source:"service"` — milestone-3.md §12 errata). Schema-conformance
  tested host-side; in-VM file modes + emitted-line shape proven (run
  32828986305, rows 5–6, 8).
- [x] Hermetic in-image binary build — ADR-002: snapshot `rust 1:1.97.1-1`
  in the builder container; `stage_punar_binaries()` compiles `--release
  --locked` and stages `usr/bin/{punard,punarctl}` (gitignored) before
  mkosi; summary mode never compiles. Full image build with staged
  binaries proven (run 32828986305).
- [x] M3 CI exercise + budget wiring — `/usr/lib/punar/m3-check.sh` +
  `punar-m3-check.service` (ten assertions: socket perms, typed status,
  group-read authz, allowed mutation + audit, **non-root denial in the
  section-73 voice + deny audit event**, firewall drift/apply/reconcile,
  audit schema shape, unauthorized-socket negative, no-exec probe),
  started after `punar-m2-check` and before export; `boot-test.sh`
  phase-5 M3 verdict gate; `PUNAR_SERVICES_RSS_MB` (summed PSS of the
  `punard.service` cgroup) exported and gated by `check-budgets.sh`
  (fail > 150 MB, warn > 100 MB, dead-daemon `absent` fails even under
  TCG). Exercised end-to-end in run 32828986305: `PUNAR_M3_OK`, and the
  first real `PUNAR_SERVICES_RSS_MB` = 2 MB, within the 100 MB target.

Everything on milestone-3.md §12's "CI is the arbiter" list is now proven
by run 32828986305: the hermetic image build with the staged binaries, the
m3-check assertions (27 passed), the real socket/audit file modes, boot
reconcile applying `punar-base` in the image, and the first real
`PUNAR_SERVICES_RSS_MB` number (2 MB) against the 100/150 MB services
budget.

Out of scope for M3 (decided in milestone-3.md §1, each with its landing
milestone): desired-state schemas/policy merge/drift remediation (M4),
enrollment/compliance (M5), audit rotation (M5 follow-up), agent methods
(M7+), approvals/JIT elevation (M9), `punarctl update status` (stays
stubbed).

## Current milestone: M4 — Declarative desired state (in progress)

Architecture plan, decisions, and as-built status:
[`docs/development/milestone-4.md`](docs/development/milestone-4.md) (§13 is
the implementation status). The wire contract for every M4 method and
result extension is [`docs/api/ipc.md`](docs/api/ipc.md) — all changes are
additive under `v: 1` and marked "M4" there. M4 stays unmanaged-first
personal mode (design language section 8): the merge engine and its tests
know all seven section 39 sources — the org rungs are exercised host-side
against the `fixtures/organizations/acme` fixtures — but the VM renders
only OS defaults and user preferences; nothing org-shaped appears in any
VM output.

Everything below exists **on disk and is statically validated**
(milestone-4.md §13): workspace fmt/clippy/test green in the `docker
rust:1` container; shellcheck v0.11.0 clean on all touched scripts;
actionlint clean; `PUNAR_BUILD_MODE=summary` staging pass for both images
(local emulated runs — non-authoritative per spec 1.22). **The M4 work is
uncommitted and no CI run includes it** — the first M4-inclusive run is
the arbiter for every in-VM claim: each milestone-4.md §10.2 assertion,
the drift demo's 375 s bound, and the merge engine's RSS impact against
the services gate (whose M3-run baseline is 2 MB).

Deliverables (spec section 76, Milestone 4) — on disk vs proven:

- [x] Schemas — shipped early (M3): `schemas/desired-state` (section 38
  `DeviceDesiredState`), `schemas/policy` (ai-policy + policy-source with
  precedence ranks), `schemas/capability`, `schemas/audit`;
  `./tools/validate-schemas.sh` validates them and the Acme fixtures. M4's
  deliberate decision (milestone-4.md §9): **no schema deltas** — the new
  IPC result shapes are contracted by ipc.md; `policy.d` envelopes are
  already covered by `policy-source.json` + `schemas/desired-state`; the
  daemon's private stores (`preferences.json`, `os-defaults.json`,
  `effective.json`) are documented internals, deliberately not public
  schemas.
- [x] Preference/policy merge — layered desired-state store in `punard`
  (`crates/punard/src/policy.rs`, `state.rs`): compiled or
  observation-seeded OS defaults, a `preferences.json` user-preference
  layer written only by `capabilities.set`, and a root-only
  `/var/lib/punar/policy.d/` org drop directory (loader + tests now, files
  arrive with M5 enrollment); the section 39 ladder is encoded in
  `punar-policy` and the spec section 40 org scenario is reproduced from
  the Acme fixtures in host tests. Includes the one-shot migration of the
  M3 `desired.json` (host-test-only by design — a fresh CI image has
  nothing to migrate). Runtime CI-pending.
- [x] Reconciliation — the full section 42 chain (observe → normalize →
  load → diff → policy → plan → apply → verify → audit → compliance) in
  one synchronous `reconcile` pass; section 43 drift classification as
  data (`auto_remediate` in personal mode; `alert_only` /
  `approval_required` representable and org-testable); N=3 loop
  protection; `reconcile` now remediates — the semantic change M3
  pre-announced by making it root-only; drift trigger via the
  low-frequency `punard-reconcile.timer` (120 s cadence, justified against
  spec 6.3 in milestone-4.md §6; vendor-wants enablement per the M1 mkosi
  lesson). Runtime CI-pending.
- [x] Explain — `policy.effective` + `policy.explain` IPC methods;
  `punarctl policy effective` and `punarctl policy explain <path>` render
  the spec section 40 layout verbatim in D-014 grammar; `status` gains the
  section 52 personal-scope compliance block. Personal-mode strings:
  "Personal preference" / "OS default", policy id `personal-defaults`,
  "User override: Permitted". Runtime CI-pending.
- [x] Firewall-drift demo — m4-check phase B: with the timer running,
  `nft destroy table inet punar-base`; the table must be restored within
  three timer periods (375 s poll budget) with a `reconcile.remediate`
  success audit event and a `drift_remediated_total` increment in
  `status`. Wired end-to-end (`m4-check.sh` + `punar-m4-check.service`,
  `idle-ram.sh` chaining after m3-check, `boot-test.sh` phase-6 hard gate
  on `m4-report.txt`, `ci.yml` artifact upload). Runtime CI-pending — this
  is the milestone's headline in-VM assertion.

Honest limits (milestone-4.md §10.3): the migration path, the org-rung
merge scenarios, and loop-protection exhaustion cannot run in the fresh CI
VM — they are covered by host `cargo test` (synthetic M3 stores, Acme
fixtures, a failing mock backend); the VM asserts only that loop
protection does not fire in the happy path.

Out of scope for M4 (milestone-4.md §1, each with its landing milestone):
enrollment and any org source in the VM (M5), policy.d hot-reload (M5),
audit rotation (M5), agent methods (M7+), approvals/JIT elevation (M9 —
`approval_required` degrades to alert-only behavior until then).

## Milestone table

Deliverables are condensed to one line each; see spec section 76 for the full
lists. The spec states explicit acceptance criteria only for M0 and M1; for
the other milestones the working criterion is that the listed deliverables
exist and function, until sharper criteria are defined.

| Milestone | Deliverables (one line) | Acceptance | Status |
| --- | --- | --- | --- |
| M0 — Foundation evaluation | Substrate ADR; resource-budget baseline; VM build; CI; repository | Reproducible build and VM boot | **Done** — acceptance met, [CI run 32788238871](https://github.com/smplify-mdm/punar/actions/runs/32788238871); budget baseline recorded in [run 32804034681](https://github.com/smplify-mdm/punar/actions/runs/32804034681) |
| M1 — Lightweight graphical workstation | Wayland, compositor, shell, command center, terminal, browser, Git, editor, Podman, keyboard navigation | Idle RAM measured; no mouse required for core desktop use | **CI gate green** — [run 32804034681](https://github.com/smplify-mdm/punar/actions/runs/32804034681) (2026-08-25): build, boot, `PUNAR_DESKTOP_OK`, idle RAM 1162 MB mean (pass w/ over-target warning); human keyboard-only walkthrough pending |
| M2 — Native multitasking | Tiling, stacking, floating, overview, layouts, scratchpads, named project workspaces | Not specified in spec §76 | **Done** — [run 32825539021](https://github.com/smplify-mdm/punar/actions/runs/32825539021) (2026-08-25) fully green incl. the in-VM M2 exercise (`PUNAR_M2_OK`); idle RAM 1157 MB mean (pass w/ over-target warning) |
| M3 — `punard` + `punarctl` | Daemon, typed IPC, capability registry, CLI, audit | Not specified in spec §76 | **Done** — [run 32828986305](https://github.com/smplify-mdm/punar/actions/runs/32828986305) (2026-08-25) fully green incl. the in-VM M3 exercise (`PUNAR_M3_OK`, 27 assertions); punard services RSS 2 MB (within the 100 MB target); idle RAM 1160 MB mean (pass w/ over-target warning) |
| M4 — Declarative desired state | Schemas, preference/policy merge, reconciliation, explain, firewall-drift demo | Not specified in spec §76 | **In progress** — implemented on disk + statically validated (checklist above; milestone-4.md §13); uncommitted, no CI run includes the M4 wiring yet — the first such run is the arbiter |
| M5 — Mock Smplify enrollment | Mock control plane, device enrollment, policy, compliance, inventory | Not specified in spec §76 | Not started |
| M6 — Developer environment manager | `punar-env`, Podman/devcontainer, Atlas fixture | Not specified in spec §76 | Not started |
| M7 — AI Agent Registry | Managed sessions, Claude adapter, second/generic adapter, agent identity, classification, local UI | Not specified in spec §76 | Not started |
| M8 — AI Access Ledger | Resource summaries, process attribution, security events, local retention, privacy controls | Not specified in spec §76 | Not started |
| M9 — Approval gates + secret broker | Local graphical approval, short-lived mock credentials, redaction tests | Not specified in spec §76 | Not started |
| M10 — Shadow AI detection MVP | Known/observed/unknown classification, fixture unknown agent, local alert, Smplify remote query | Not specified in spec §76 | Not started |
| M11 — Browser/web-app integration | Current Chromium, native launcher integration, project/browser context prototype, web-app install flow | Not specified in spec §76 | Not started |
| M12 — Network privacy prototype | Local network observability, project-route policy, relay abstraction, simulated or prototype private relay | Not specified in spec §76 | Not started |
| M13 — Demo polish | First boot, enrollment, keyboard UX, AI panel, privacy panel, deterministic demo | Not specified in spec §76 | Not started |
