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
  (2026-08-25, see M3 below). The M4 and M5 exercise phases went green
  together in run
  [32849448721](https://github.com/smplify-mdm/punar/actions/runs/32849448721)
  (2026-08-25, all five jobs green — `PUNAR_M4_OK` + `PUNAR_M5_OK`; see
  M4/M5 below for the red runs on the road there). The M6 exercise phase
  went green in run
  [32857914904](https://github.com/smplify-mdm/punar/actions/runs/32857914904)
  (2026-08-25, all five jobs green — `PUNAR_M6_OK`; see M6 below). The M7
  exercise phase went green in run
  [32868450695](https://github.com/smplify-mdm/punar/actions/runs/32868450695)
  (2026-08-25, all five jobs green — `PUNAR_M7_OK`, 74 assertions; see M7
  below). The M8 and M9 exercise phases then went green **together, and
  for the first time**, in run
  [32899132191](https://github.com/smplify-mdm/punar/actions/runs/32899132191)
  (commit `7943f3c` "Repair M5/M8/M9", 2026-08-25 21:05–21:39 UTC) — the
  **newest run and the newest green one**: all five jobs green,
  `PUNAR_DESKTOP_OK` after 20 s, `PUNAR_M2_OK` (33) + `PUNAR_M3_OK` (28)
  + `PUNAR_M4_OK` (29) + `PUNAR_M5_OK` (63) + `PUNAR_M6_OK` (55) +
  `PUNAR_M7_OK` (74) + **`PUNAR_M8_OK` (123)** + **`PUNAR_M9_OK` (137)**
  = **542 in-VM assertions**, the M9 approval document re-validated
  host-side against the unchanged `schemas/audit/approval.json`
  (boot-test phase 11b), idle RAM mean 1155 MB / max 1160 MB (pass with
  the standing over-target warning), services RSS 6 MB summed over the
  three daemon cgroups. The two red runs on the road there: run
  [32874683680](https://github.com/smplify-mdm/punar/actions/runs/32874683680)
  (commit `9027438`, M8) red in `desktop-test` on one stale **m7**-check
  assertion, and run
  [32891877422](https://github.com/smplify-mdm/punar/actions/runs/32891877422)
  (commit `a53598b`, M9) red on the defects `7943f3c` then repaired.
- **The M8 silent-skip is closed, by evidence.** Run
  [32877949285](https://github.com/smplify-mdm/punar/actions/runs/32877949285)
  went green in the morning **without executing m8-check at all** —
  `m8-check.sh` shipped mode `100644`, `punar-m8-check.service` failed
  its `ExecStart`, and `boot-test` degraded a **missing** verdict to a
  `::warning::`. Commit `dc2dc47` restored the exec bit and made a
  missing M2..M9 verdict a hard failure under KVM; run `32899132191`
  then delivered the first `PUNAR_M8_OK` and the first `PUNAR_M9_OK`
  that have ever existed. **Both milestones are now runtime-proven, not
  merely built.** `origin/main` is `7943f3c`; local `main` is five
  **docs-only** commits ahead of it (`dab66ae`, `8a38c8f`, `e6f20dc`,
  `a273d0d`, `b31a031`), and the M10 tree is working-tree only on top of
  those (see M10 below) — **no CI run contains one byte of M10.**
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
[`docs/development/milestone-2.md`](docs/development/milestone-2.md) — its
status header and §8 verification table now record the green run below,
including the two claims CI cannot settle (fidelity of the presets and
overview to Plate D-007, and the keyboard-only human walkthrough).

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
- [x] Scratchpads — assistant and notes specials alongside M1's terminal
  (SUPER+T). The assistant pad shipped on SUPER+A in M2 and moved to
  SUPER+SHIFT+A in M7, when the AI panel took spec §25's own chord
  (milestone-7.md §8).
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
at f1ff60c (the tree has since grown the committed M4 changes and the
M5 work — see M4/M5 below): whole workspace
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
below cites this run. One dated caveat, since resolved: the run exercised
`m3-check.sh` as committed at f1ff60c (M3 report-only reconcile); the
version amended for M4's remediating reconcile (milestone-4.md §10.4) has
since run in-VM and delivered `PUNAR_M3_OK` inside run
[32837156881](https://github.com/smplify-mdm/punar/actions/runs/32837156881)
(2026-08-25) — a run that failed overall, but on an M4 assertion after the
M3 phase had passed (see M4 below).

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

## M4 — Declarative desired state: done (CI exercise green)

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
(local emulated runs — non-authoritative per spec 1.22). Milestone-4.md
§13's "uncommitted / no CI run" statements are dated: the M4 work was
committed as 5ae79fb and pushed 2026-08-25.

**The gate is green.** Run
[32849448721](https://github.com/smplify-mdm/punar/actions/runs/32849448721)
(2026-08-25, KVM runner, commit 408b51d, all five jobs green) delivered
**`PUNAR_M4_OK` (29 assertions passed)** inside a fully green run —
including the headline timer-driven firewall-drift remediation demo — with
the services-RSS gate reading **2 MB** (the merge engine added nothing
measurable to the M3-run baseline of 2 MB, against the 100 MB warn /
150 MB fail budget) and idle RAM mean 1156 MB / max 1162 MB (pass with the
standing over-target warning).

The road there, for the record. The first M4-inclusive run,
[32837156881](https://github.com/smplify-mdm/punar/actions/runs/32837156881)
(2026-08-25, commit 5ae79fb), **failed narrowly**: four of five jobs green;
`desktop-test` ran the full in-VM chain, delivered `PUNAR_DESKTOP_OK`,
`PUNAR_M2_OK`, and `PUNAR_M3_OK`, then **`PUNAR_M4_FAIL`** with exactly
one failing assertion — `punard-reconcile.timer` `is-enabled` returned
`disabled`. Vendor `/usr/lib` wants symlinks always report `disabled`
(enablement state tracks `/etc` only — the greetd semantics resurfacing in
the *check*, not the wiring; the timer itself was wired and running), and
every other §10.2 assertion, including the drift demo, passed in that run.
The fix — commit 92d5f17: m4-check asserts the wants symlink plus the
`Wants=` relationship instead of `is-enabled` — first failed pre-VM in run
[32839803185](https://github.com/smplify-mdm/punar/actions/runs/32839803185)
(fmt diffs and a compile error from in-progress M5 code bundled into that
commit; the VM jobs never ran). The amended m4-check's first in-VM
execution came inside run
[32846674987](https://github.com/smplify-mdm/punar/actions/runs/32846674987)
(2026-08-25, the M5 push ef66909): `PUNAR_M4_OK` (29 assertions) — a run
red overall, but on an m5-check assertion after the M4 phase had passed
(see M5 below). The fully green run 32849448721 followed the same day.

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
  nothing to migrate). Runtime-proven (green run 32849448721; first passed in-VM inside red run 32837156881).
- [x] Reconciliation — the full section 42 chain (observe → normalize →
  load → diff → policy → plan → apply → verify → audit → compliance) in
  one synchronous `reconcile` pass; section 43 drift classification as
  data (`auto_remediate` in personal mode; `alert_only` /
  `approval_required` representable and org-testable); N=3 loop
  protection; `reconcile` now remediates — the semantic change M3
  pre-announced by making it root-only; drift trigger via the
  low-frequency `punard-reconcile.timer` (120 s cadence, justified against
  spec 6.3 in milestone-4.md §6; vendor-wants enablement per the M1 mkosi
  lesson). Runtime-proven (green run 32849448721; first passed in-VM inside red run 32837156881).
- [x] Explain — `policy.effective` + `policy.explain` IPC methods;
  `punarctl policy effective` and `punarctl policy explain <path>` render
  the spec section 40 layout verbatim in D-014 grammar; `status` gains the
  section 52 personal-scope compliance block. Personal-mode strings:
  "Personal preference" / "OS default", policy id `personal-defaults`,
  "User override: Permitted". Runtime-proven (green run 32849448721; first passed in-VM inside red run 32837156881).
- [x] Firewall-drift demo — m4-check phase B: with the timer running,
  `nft destroy table inet punar-base`; the table must be restored within
  three timer periods (375 s poll budget) with a `reconcile.remediate`
  success audit event and a `drift_remediated_total` increment in
  `status`. Wired end-to-end (`m4-check.sh` + `punar-m4-check.service`,
  `idle-ram.sh` chaining after m3-check, `boot-test.sh` phase-6 hard gate
  on `m4-report.txt`, `ci.yml` artifact upload). The demo itself —
  the milestone's headline in-VM assertion — is **runtime-proven** (green
  run 32849448721; it had already passed inside red run 32837156881, whose
  one failure was the separate timer-enablement assertion).

Honest limits (milestone-4.md §10.3): the migration path, the org-rung
merge scenarios, and loop-protection exhaustion cannot run in the fresh CI
VM — they are covered by host `cargo test` (synthetic M3 stores, Acme
fixtures, a failing mock backend); the VM asserts only that loop
protection does not fire in the happy path.

Out of scope for M4 (milestone-4.md §1, each with its landing milestone):
enrollment and any org source in the VM (M5), policy.d hot-reload (M5),
audit rotation (M5), agent methods (M7+), approvals/JIT elevation (M9 —
`approval_required` degrades to alert-only behavior until then).

## M5 — Mock Smplify enrollment: done (CI exercise green)

Architecture plan, decisions, and the section 49 chain mapped honestly to
the mock: [`docs/development/milestone-5.md`](docs/development/milestone-5.md)
(§13 is the verification/implementation status, including the local
validation record; its "uncommitted and unpushed / the first CI run
containing this tree is the arbiter" statements are dated 2026-08-25 and
predate the push and the green run recorded here). Wire contract:
[`docs/api/ipc.md`](docs/api/ipc.md) — the M5 changes are additive under
`v: 1`, marked "M5" there (`enroll.start`/`enroll.status`/`enroll.stop`
§§5.9–5.11, `conflict`/`upstream_unreachable` error codes, the §9
`/run/punar/status.json` side contract, and the §6 audit-rotation note —
now backed by code). M5 is where unmanaged-first flips to managed and
back, live, in the VM: enroll against an in-VM mock control plane (the CI
VM has no network — `-nic none`), render the spec section 40 managed
explain for real, sync category-level compliance and inventory (spec
54/24: states only, nothing behavioral), survive the control plane dying
(spec 55), and unenroll back to calm paper (design language §8).

**The gate is green.** Run
[32849448721](https://github.com/smplify-mdm/punar/actions/runs/32849448721)
(2026-08-25, KVM runner, commit 408b51d, all five jobs green) delivered
**`PUNAR_M5_OK` (63 assertions passed)**: the full enroll → managed
explain/deny → category-only compliance/inventory (asserted on the mock's
received side) → offline → recovery → offline-unenroll → personal-restore
journey proven in-VM, with both bar screenshots captured, idle RAM mean
1156 MB / max 1162 MB (pass with the standing over-target warning — the
mock stayed structurally invisible to the sampling windows, as designed),
and punard services RSS 2 MB.

The road there, for the record. The finished tree landed as ef66909
(after an earlier mid-integration slice was bundled into 92d5f17, whose
run
[32839803185](https://github.com/smplify-mdm/punar/actions/runs/32839803185)
was red pre-VM — see M4 above), plus one check-string amendment 408b51d.
The finished tree's first run,
[32846674987](https://github.com/smplify-mdm/punar/actions/runs/32846674987)
(2026-08-25, ef66909), came within one assertion of green: rust,
contracts, image, and boot-test all green; `desktop-test` ran the full
in-VM chain — `PUNAR_DESKTOP_OK`, `PUNAR_M2_OK` (33), `PUNAR_M3_OK` (28),
and the first `PUNAR_M4_OK` (29) — then **`PUNAR_M5_FAIL`** with exactly
one failing assertion: the "human overridden-set verdict" grep. m5-check
grepped for the §5.5 verdict line case-sensitively while the D-014
formatter (`fmt::verdict`) renders it uppercase — a check-string bug, not
an enrollment-behavior bug; every other m5-check assertion passed in-VM
on first execution. The amendment (408b51d: case-insensitive verdict
grep) took the gate green in run 32849448721 the same day.

Deliverables (spec section 76, Milestone 5) — on disk vs proven:

- [x] Mock control plane — `crates/punar-mock-smplify` (dev/CI-only bin
  crate: config, verbatim Acme fixture serving, NDJSON/UDS protocol,
  received-state recording; integration-tested), hermetically staged by
  `container-build.sh` as a third in-image binary alongside the Acme
  fixtures (copied to `/usr/share/punar/fixtures/acme`); the
  **never-enabled** `punar-mock-smplify.service` (no `[Install]`, no
  wants symlink — m5-check asserts the discipline; root-only UDS, never
  localhost TCP — the spec 61 trust boundary is documented in the unit
  header; started/stopped only by m5-check, so it is structurally outside
  the `PUNAR_SERVICES_RSS_MB` gate and absent from the idle-RAM window).
  On disk + host-tested; **runtime-proven** (run 32849448721).
- [x] Device enrollment — the section 49 chain against the mock
  (attestation **simulated and labeled**, no IdP — documented gap, per
  spec 49's own "MVP uses a mocked Smplify control plane"):
  `enroll.start`/`enroll.status`/`enroll.stop` in `punard`
  (`crates/punard/src/enroll.rs` + server handlers, `Redacted` device
  token, `/run/punar/status.json` publisher), `punarctl enroll
  start|status|stop` in D-014 grammar, and the shell flip — `Status.qml`
  watches `status.json` (FileView, fail-closed to personal), `Bar.qml`
  org chrome gated on it (design language §8). Enrollment is explicit,
  never automatic (spec 24). On disk + host-tested
  (`crates/punard/tests/enroll.rs`, punarctl `cli.rs`); **runtime-proven**
  (run 32849448721 — live enroll/unenroll with the shell's org chrome
  flipping, both screenshots captured).
- [x] Policy — enrollment writes real `policy-source` envelopes into
  `/var/lib/punar/policy.d/` for the unchanged M4 loader/flattener/merge;
  the spec 40 managed explain renders for real; managed-set behaviors
  (non-root denial citing the org policy — `denied_org_pinned`; root
  recorded-but-overridden with the §5.5 verdict line); `enroll.stop`
  removes the org layers and restores personal state. On disk +
  host-tested; **runtime-proven** (run 32849448721).
- [x] Compliance — category-level states only (spec 52/54/24), sync
  piggybacked on the existing 120 s `punard-reconcile.timer` (no new
  timers); spec 55 offline behavior: cached policy.d keeps enforcing
  without the mock, bounded latest-wins queue, transition-audited
  `unreachable`. On disk + host-tested; **runtime-proven** (run 32849448721).
- [x] Inventory — device info + capability states, nothing behavioral
  (spec 24/54), sent at enroll then on hash change. On disk +
  host-tested; **runtime-proven** (run 32849448721).
- [x] M5 CI exercise wiring — `m5-check.sh` (19 assertion groups:
  mock-discipline check, the full enroll → managed explain/deny →
  compliance/inventory asserted on the mock's RECEIVED side with exact
  category-only key allowlists (the privacy assertion) → offline →
  recovery → offline unenroll → personal restore; two grim screenshots —
  enrolled org chrome and restored personal bar) +
  `punar-m5-check.service`, `idle-ram.sh` chaining after m4-check,
  `boot-test.sh` phase-7 hard gate on `m5-report.txt` + export additions
  and timeout bumps, `ci.yml` artifact wiring + desktop-test 80 min. On
  disk, shellcheck/actionlint clean; **exercised end-to-end** in run
  32849448721 (`PUNAR_M5_OK`, 63 assertions) after the one red first run
  recorded above.
- [x] Audit rotation (the M3 §6 follow-up targeted at M5) —
  `AuditWriter::rotate_if_needed` in `punar-common`: `audit.jsonl` →
  `audit.jsonl.1` at 8 MiB, one rotated file kept, checked at write time,
  unit-tested; the ipc.md §6 "M5: delivered" note is no longer ahead of
  the code. Deliberately not asserted in-VM (M5 event volumes are nowhere
  near the cap).

Static validation for the finished tree — recorded in milestone-5.md §13
(local, non-authoritative per spec 1.22): docker `rust:1`
fmt/clippy/check clean and `cargo test --workspace --locked` green (all
23 suites, including the punard/punarctl/mock M5 suites and the rotation
tests); shellcheck v0.11.0 clean on all ten scripts including
`m5-check.sh`; actionlint clean; `PUNAR_BUILD_MODE=summary` staging pass
with the Acme fixture copy verified; qmllint clean from the shell work
with no QML changed since; `./tools/validate-schemas.sh` re-run at this
audit: 15 schemas / 123 documents ALL PASS (**no M5 schema deltas** —
deliberate, milestone-5.md §11).

Every former "awaits the first CI run" item — the m5-check assertion
groups, the enroll latency bounds, the FileView pickup window, mock RSS
invisibility, the export additions — now rests on run 32849448721.
Deliberately outside the runtime proof, unchanged: audit-rotation volume
(host-unit-tested only — M5 event volumes are nowhere near the cap) and
attestation (simulated and labeled, no IdP — the mock per spec 49).

## M6 — Developer environment manager: done (CI exercise green)

Architecture plan, decisions, and as-built status:
[`docs/development/milestone-6.md`](docs/development/milestone-6.md) (§14 is
the verification status, reconciled to the as-built tree; its "uncommitted
and unpushed / no CI run" statements are dated 2026-08-25 and predate the
push and the green run recorded here). M6 turns the
section 17 environment boundary into a real container: a project directory
with a `ProjectEnvironment` manifest becomes a running rootless Podman
container with the project bind-mounted at `/workspace`, driven by a
user-facing CLI, on a CI VM that has no network (`-nic none`). Everything
the manifest *declares* but the OS does not yet *enforce* — toolchain
provisioning, service containers, network zones, credential grants, AI
agents — is parsed, validated, and **displayed with its enforcement
milestone**, never silently faked (spec 1.22). The wire contract
[`docs/api/ipc.md`](docs/api/ipc.md) is untouched: `punar-env` speaks to no
daemon in M6, and there are no M6 schema deltas (the `ProjectEnvironment`
schema and spec-17 example predate M6 in `schemas/project/`, committed with
the contract layer at 45a6fb0).

**The gate is green.** Run
[32857914904](https://github.com/smplify-mdm/punar/actions/runs/32857914904)
(2026-08-25, KVM runner, commit 0ba4ea6, all five jobs green) delivered
**`PUNAR_M6_OK` (56 assertions passed)** — the run that turned the claims
below from "on disk" into "proven in-VM": the offline `podman load` →
rootless `up` → `shell` → `status` → `destroy` journey, the Atlas
fixture's byte-identity through it, and the M7-stub honesty check, all
executed in the guest. Same run: idle RAM mean 1162 MB / max 1167 MB
(pass with the standing over-target warning) and punard services RSS
2 MB. The in-VM chain stood at **209 assertions** in that run (M2 33,
M3 28, M4 29, M5 63, M6 56); M7 has since taken it to 282 — see M7 below
for the two counts that moved and why.

The road there, for the record. The finished M6 tree landed as 90278f9;
its first run,
[32852810872](https://github.com/smplify-mdm/punar/actions/runs/32852810872)
(2026-08-25), was red inside the VM on m6-check's fixture byte-identity
assertions — the check invoked `diff`, which the `punar-desktop` image
does not ship (no diffutils). A check-tool bug, not an
environment-behavior bug. The amendment 0ba4ea6 (compare with `sha256sum`)
took the gate green the same day.

Deliverables (spec section 76, Milestone 6) — on disk vs proven:

- [x] `punar-env` — new workspace bin crate `crates/punar-env` (user CLI;
  refuses root; drives podman with fixed argv, never a host shell string):
  the full section 17 command set — `init` (idempotent, byte-preserving on
  an existing manifest; scaffolds one otherwise), `up` (loads the offline
  base image at first use, then a rootless container with the project
  bind-mounted at `/workspace`, `--network none`), `shell` (exit-code
  passthrough; `-c` one-shot), `status` (Plate D-014 render; the section 17
  permissions block as a table with per-row `DECLARED · enforcement
  M7/M9/M12` labels — the one grant M6 actually realizes,
  `filesystem.project` via the bind mount, is labeled `applied (bind
  mount)`; `--json`), `destroy` (container gone, project files intact,
  idempotent), and `agent` — the labeled Milestone 7 stub (real
  `ai.agents` membership check, then exits 1 citing M7). The manifest
  parser round-trips the spec-17 Atlas manifest byte-verbatim; toolchains
  and services are declared-and-reported, not installed/started
  (milestone-6.md §5.5–5.6 — provisioning needs network; service
  containers deferred by decision). YAML via `serde_norway`
  (workspace-pinned, advisory-checked, documented `serde_yaml` fallback).
  On disk + host-tested (fmt/clippy/test green in the pinned `rust:1`
  container: argv table tests, verbatim round-trip, the §7 render
  snapshot, engine flows on a scripted podman mock, plus a live non-root
  smoke against a fake podman); **and now proven in-VM** — run
  32857914904, `PUNAR_M6_OK`.
- [x] Podman/devcontainer — `environment.type: devcontainer` realized on
  the podman 6.1.0-1 + crun + netavark stack already in the desktop image
  since M1, rootless via the `punar` `100000:65536` subuid/subgid mapping.
  Because the CI VM has no network, `up` consumes a **deterministic
  offline base image**: `stage_env_base_oci()` in `container-build.sh`
  hand-assembles `localhost/punar-env-base:m6` from the pinned snapshot's
  statically linked busybox (1.36.1-4, sha256-verified against the
  PGP-signed `extra.db`) into a byte-identical 1,320,960-byte OCI archive,
  staged (gitignored) into the desktop image for `podman load -i` at
  first use. Verified at implementation time (milestone-6.md §14):
  byte-identical rebuilds, pinned-podman load with matching digests,
  chroot exec proof; `podman run` itself cannot be exercised under the
  arm64-Mac emulation path — the in-VM m6-check is the authoritative
  proof, **and it has now run**: run 32857914904 exercised the offline
  load and the rootless container journey inside the guest.
- [x] Atlas fixture — `fixtures/projects/atlas/` **predates M6**
  (committed with the contract layer, 45a6fb0; validated by
  `./tools/validate-schemas.sh` in every green CI run): the spec section
  17 `ProjectEnvironment` manifest **verbatim** (byte-identical to the
  spec YAML block below a single provenance comment line) plus the
  section 36 project network policy **declaration** (manifest semantics
  only — network enforcement is FUTURE, M12). M6 adds build-time staging
  of the two contract files to `/usr/share/punar/fixtures/projects/atlas`
  so m6-check can copy them to `~punar/atlas` and assert byte-identity
  through the whole init/up/destroy journey. Fixture: committed +
  CI-validated; the staging and everything consuming it: committed at
  90278f9 and **proven in-VM** in run 32857914904.
- [x] M6 CI exercise wiring — `m6-check.sh` (nine assertion groups, all
  env commands run as the `punar` user via `runuser`: rootless preflight,
  fixture byte-identity, init idempotence + scaffold validity, up with
  `--network none` and the `/workspace` bind, shell exit-code passthrough
  + uid-mapping write proof, status verbatim-render greps + `--json`
  parse, agent-stub honesty, destroy with files intact; verdict
  `PUNAR_M6_OK`/`PUNAR_M6_FAIL` in `m6-report.txt`) + the never-enabled
  root oneshot `punar-m6-check.service`, started synchronously by
  `idle-ram.sh` strictly after the M5 exercise and before export (in-guest
  timeout 100 → 110 min); `boot-test.sh` phase 8 hard-gates the verdict
  and exports `m6-status.txt`/`m6-status.json` + podman snapshots (no
  screenshots — a CLI milestone; `m6-status.txt` is the human evidence);
  `ci.yml` shellchecks `m6-check.sh`, uploads the m6 artifacts, and
  raises desktop-test to 85 min. Shellcheck v0.11.0 + actionlint clean,
  and **executed in-VM twice**: run 32852810872 to `PUNAR_M6_FAIL` (the
  `diff` bug), run 32857914904 to `PUNAR_M6_OK` with all 56 assertions
  passing. (M7 raises the same job to 95 min — see M7 below.)

Static validation for the tree — recorded in milestone-6.md §14 (local,
non-authoritative per spec 1.22): cargo fmt/clippy/`test --workspace`
green in the pinned `rust:1` container; shellcheck v0.11.0 clean on every
touched script including `m6-check.sh`; actionlint clean;
`PUNAR_BUILD_MODE=summary ./tools/build-image.sh all` exit 0 for both
images; `./tools/validate-schemas.sh` green. Budgets are structurally
unaffected by design — `punar-env` is a user CLI, not a service (outside
the `PUNAR_SERVICES_RSS_MB` service-cgroup sample — punard alone at M6;
punard + punar-agentd from M7), and its rootless
containers exist only inside the m6-check window, after idle-RAM sampling
— and run 32857914904 bore that out: idle RAM 1162 MB mean and services
RSS 2 MB, both unmoved by M6. One tracked
deferral: the schemas-side copy of the crate's scaffold example
(`schemas/project/examples/punar-env.scaffold.yaml`) ships with a separate
schemas-owning change and has not landed; until it does, the crate's own
unit test that the embedded scaffold parses cleanly is the guard.

What remains for M6: the one tracked deferral above
(`schemas/project/examples/punar-env.scaffold.yaml`, still not landed as
of this audit) and the by-decision deferrals recorded in milestone-6.md
§13 — service containers and toolchain provisioning, both of which need
network the CI VM does not have. The `punar-env agent` stub that M6
shipped is no longer a stub: M7 implements it (below).

## M7 — AI Agent Registry: done (CI exercise green)

Architecture, decisions, and as-built record:
[`docs/development/milestone-7.md`](docs/development/milestone-7.md) (§14
is the verification status; its "no CI run" / "never executed anywhere"
statements are dated 2026-08-25 and were true when written — the run
below settles them). Wire contract:
[`docs/api/ipc.md`](docs/api/ipc.md) §10–§11 — a **sibling socket**, not
a change to punard's `v: 1` surface: `punar-agentd` serves `agents.list`,
`agents.get`, `agents.register`, `agents.end`, `agents.scan` on
`/run/punar-agentd/agentd.sock`, plus the §11 side contract
`/run/punar/agents.json` for the shell. M7 is where the AI-native thesis
(spec sections 18–27) stops being schemas and becomes a running surface:
an agent session launched *by* the OS gets an identity, a scope cgroup,
a registry record, and a panel row; an agent the OS did not launch gets
found by a heuristic that says **suspected**, never *certain*.

The arbiter run has happened: CI run
[32868450695](https://github.com/smplify-mdm/punar/actions/runs/32868450695)
(2026-08-25, commit `f95c9c4`) is fully green on all five jobs — `rust`,
`contracts`, `image`, `boot-test`, `desktop-test` — and its `desktop-test`
job delivered **`PUNAR_M7_OK` with 74 assertions passed**, all twelve
m7-check groups, in the same boot that produced `PUNAR_DESKTOP_OK`
(20 s to a rendered frame under KVM) and `PUNAR_M2_OK` (33) / `PUNAR_M3_OK`
(28) / `PUNAR_M4_OK` (29) / `PUNAR_M5_OK` (63) / `PUNAR_M6_OK` (55)
before it. The in-VM chain now stands at **282 assertions**. The AI-panel
screenshot `punar-m7.png` (103 KB) landed and rides the
`punar-desktop-screenshot` artifact.

Two earlier counts moved, and the older sections are not wrong — each is
scoped to the run it cites. M3 reads **28** here against the 27 recorded
for run 32828986305 (the M4 commit added an assertion to `m3-check`), and M6
reads **55** against the 56 recorded for run 32857914904: commit
`f95c9c4` **replaced** the stale stub-message assertion described below
with one clean-launch-failure assertion, and the group lost a line in the
trade.

The road there, stated (spec 1.22): the M7 tree's own push, commit
`a2b2ce5`, ran as
[32865062323](https://github.com/smplify-mdm/punar/actions/runs/32865062323)
and was **red** — but not on M7 code. `m6-check` still asserted the
stderr of M6's `punar-env agent` *stub* ("Failed to find executable
claude"), a message M7's real managed launch removed; `PUNAR_M6_FAIL` on
that one stale assertion failed `desktop-test` after M2–M5 had already
passed in the same boot. The M7 exercise itself was **already green in
that red run** — its exported `m7-report.txt` carries `PUNAR_M7_OK` with
the same 74 `ok` lines — but the M6 gate fires first, so no M7 verdict
reached the console and the run is correctly recorded as a failure. The
fix commit `f95c9c4` re-pointed the M6 assertion at the clean launch
failure, and the corrected chain went green end to end on its first run.

Deliverables (spec section 76, Milestone 7) — on disk **and** proven:

- [x] Managed sessions — `punar-env agent <name>` (M6's labeled stub) is
  now the real spec section 27 launch: manifest `ai.agents` membership
  check → adapter resolution → authority summary → `agents.register` on
  the agentd socket → `systemd-run --user --scope` into
  `punar-agent-<id>.scope` → the adapter command in the project directory
  → `agents.end` on exit, with crash-honest reaping (`agents.reap`) for
  sessions whose process died without an end. The session id is the
  registry's, not the caller's claim. **Runtime-proven** in the VM —
  m7-check groups 3, 5 and 10 (launch, scope attribution, end of life)
  are inside the green `PUNAR_M7_OK`.
- [x] Claude adapter — `adapters/claude-code.json`, staged as **data**
  (`/usr/share/punar/agents/adapters/`), not code: launch command,
  `version_command`, and the `comm`/`exe_glob` identity signature for
  `claude`. The CI VM has no network and no real Claude Code binary, so
  the exercise substitutes `/usr/lib/punar/punar-mock-agent` — a
  self-labeling dev/CI stand-in ("PUNAR MOCK AGENT … performs no AI
  work") gated behind `PUNAR_AGENT_MOCK=1`. Adapter definition validated
  against `schemas/ai-agent/agent-definition.json` **in place** (the file
  the image ships is the file the schema checked); the managed launch
  through this adapter path is **runtime-proven** with the mock, and the
  real `claude` binary remains unexercised by design — the VM has no
  network.
- [x] Second/generic adapter — `adapters/generic.json`
  (`generic-shell`, `/bin/sh`, empty signature — a generic adapter
  identifies its sessions by the launch scope, not by what the binary
  looks like), proving spec section 26's "adapters should be modular":
  adding an agent is adding a JSON file, with zero Rust changes.
  Schema-validated in place and present in the booted image
  (m7-check group 2).
- [x] Agent identity + attribution (spec 22) — identity is *checked, not
  claimed*: `SO_PEERCRED` at accept authorizes the register/end caller,
  the registered pid's cgroup is read from the kernel and must name the
  scope, and the executable identity is recorded from `/proc`. Records
  append to `/var/lib/punar/agents/registry.jsonl` (0700 root:root —
  a writable registry *is* attribution authority), conform to
  `schemas/ai-agent/registry-record.json`, and carry one record per
  lifecycle transition. The schema's `status` enum is widened
  `["active"] → ["active", "ended"]` — the additive widening its own
  description pre-authorized. **The kernel-vs-record cgroup agreement is
  now proven in the VM** (m7-check groups 4–5), on top of the 35 host
  assertions in `punar-agentd`. The one honest gap m7-check states in an
  `info` line rather than asserting: cross-user peer-credential denial —
  the image has one interactive user and no tool to forge peer
  credentials; that path is covered by host integration tests.
- [x] Classification (spec 19.1, 23) — the three shipped values
  `managed` / `observed` / `unknown`, with `managed` *proven* by the
  launch scope and `unknown` always rendered **SUSPECTED**. Detection is
  a `/proc` walk against signatures shipped as data
  (`signatures/suspected.json`), run **on demand** (`agents.scan`) — no
  polling loop (spec 6.3), and continuous detection with alerts is M10 by
  spec sectioning. The unknown-agent fixture gets a real, verifiably
  innocuous process to find: `foo-agent-fixture.sh` installed as
  `~punar/Downloads/foo-agent`, which prints what it is and blocks on a
  signal. **Runtime-proven in the VM** (m7-check group 7 — the fixture
  process found and rendered `UNKNOWN · SUSPECTED`).
- [x] Local UI (spec 25, Plate D-005) — `SUPER + A` opens the AI panel
  (`shell/punar-shell/AiPanel/AiPanel.qml`), reading
  `/run/punar/agents.json` through the M6-era `Services/` FileView
  pattern (`Agents.qml` — event-driven, no polling). Unmanaged-first per
  DESIGN_LANGUAGE §8: authority cites `personal-defaults` on an
  unenrolled device and the org policy id only when enrolled; every
  authority row is labeled `declared · M9`/`declared · M12` (display
  only in M7 — enforcement is M9/M12). **Runtime-proven**: m7-check
  group 9 captured `punar-m7.png` with a managed row and an unknown row
  on one screen. The one chord reassignment — the assistant scratchpad
  moves `SUPER+A` → `SUPER+SHIFT+A` — is recorded in
  [`docs/development/keyboard-grammar.md`](docs/development/keyboard-grammar.md).
  What M7 shipped as *labeled absence* — the dashed
  `LEDGER · MILESTONE 8` placeholder and `agents.access` reserved as
  `unknown_method` — is what M8 fills; see the M8 section below.
- [x] M7 CI exercise wiring — `m7-check.sh` (twelve assertion groups:
  daemon/socket/tmpfiles preflight, adapters-and-signatures-as-data,
  the mock managed launch, registry truth, scope attribution, `punarctl
  agents inspect`, shadow-AI detection against the real fixture process,
  `agents.json`, the Plate D-005 panel screenshot, end of life, audit
  lifecycle lines, and negative probes on the new socket; verdict
  `PUNAR_M7_OK`/`PUNAR_M7_FAIL` in `m7-report.txt`) + the never-enabled
  root oneshot `punar-m7-check.service`, started synchronously by
  `idle-ram.sh` strictly after the M6 exercise and before export;
  `boot-test.sh` phase 9 hard-gates the verdict and exports
  `m7-report.txt`, `m7-*.txt/.json/.jsonl` and `punar-m7.png`; `ci.yml`
  shellchecks the three new scripts, uploads the M7 artifacts, and raised
  `desktop-test` to 95 min. **Executed and green**, and
  `desktop-test` finished well inside the 95-minute budget (the whole
  five-job run took 28 m 39 s wall clock under KVM).

Budgets, measured (the M7-specific hard lesson, now with a number):
`punar-agentd` is a **second resident service**, so the services-RSS gate
sums the `punard.service` *and* `punar-agentd.service` cgroups into the
**same single** `PUNAR_SERVICES_RSS_MB` number, with the thresholds
unmoved (target 100 MB, MVP ceiling 150 MB — spec 6.2 budgets the
services total, not each daemon), and a unit whose cgroup is missing or
empty makes the whole value `absent`, which `check-budgets.sh` fails even
under TCG — one live daemon must never mask a dead sibling
(`PERFORMANCE_BUDGETS.md` §2.3, `idle-ram.sh`). The combined number is
now measured: **4 MB** (summed PSS, both cgroups) in run 32868450695,
within the 100 MB target — 2 MB of it the second daemon. Idle RAM in the
same run: **mean 1175 MB / max 1180 MB**, a pass with the standing
over-target warning (target 1024 MB, hard ceiling 1536 MB) and 13 MB
above M6's 1162 MB — the cost of a second resident service, visible where
it should be.

What remains for M7: nothing in M7's own deliverable list. Out of scope
by spec sectioning and tracked in milestone-7.md §13: the **AI Access
Ledger** (spec 21) is M8 — the section below; authority **enforcement**
is M9/M12; continuous shadow-AI detection with local alerts and remote
queries is M10.

## M8 — AI Access Ledger: done (CI exercise green)

> **Superseding update, 2026-08-25 21:39 UTC.** Run
> [32899132191](https://github.com/smplify-mdm/punar/actions/runs/32899132191)
> (commit `7943f3c`) delivered **`PUNAR_M8_OK`, 123 assertions** — the
> first M8 verdict that has ever existed. Every "**no CI run**" and
> "never executed" annotation in the deliverable list below is **dated**:
> it described the state before that run, and is kept as the record of
> how the milestone was validated on the way there. The exercise reached
> green after two repairs, both recorded in `7943f3c`: a **product** fix
> — a pre-registration race dropped an attribution that arrived before
> its session was registered, so the Level-4 denial reference never
> joined the ledger (attributions are now held in a bounded,
> oldest-dropped, tombstone-respecting buffer, with three new tests) —
> and one **check** correction, an over-strict retention clause replaced
> by the invariant it was meant to express. No assertion was weakened to
> obtain green. What M8 still does not claim is unchanged: network
> destinations remain **M12**, MCP servers **M11+**, and both render as
> `NOT YET OBSERVED · MILESTONE n`.

Design plan and as-built record:
[`docs/development/milestone-8.md`](docs/development/milestone-8.md) (§14
is the verification status). Wire contract:
[`docs/api/ipc.md`](docs/api/ipc.md) §12–§13 — **additive** on the M7
agentd socket, with punard's `v: 1` surface again untouched:
`agents.access` (the reserved M7 verb, now real) and `ledger.purge`, plus
the §13 side contract for the panel's runtime view. M8 answers spec
section 21's question — "**what has this agent actually accessed?**" —
kept structurally apart from section 20's "what may it access?", and
gives the user the section 24.2 half: see it all, delete it all, locally.

**The architectural law of this milestone, and the reason to trust the
numbers it prints** (spec 1.14 + 21): every ledger fact is **derived from
a mediation point Punar already owns**. M8 adds **no eBPF, no fanotify,
no ptrace, no `LD_PRELOAD`, no audit-subsystem rules, no filesystem or
network interception** of any kind. Four sources, and only four: (A) the
agent's `punar-agent-<id>.scope` cgroup, read from `/sys/fs/cgroup` at
sampling points → process classes and `pids.peak`; (B) the punard audit
stream filtered by `agent_session_id` → Level-4 security-event
*references*; (C) the `punar-env` workspace grant → directory **zones**
and repository identity; (D) the registry record → identity and
timestamps. A category with no owned producer is **not invented**: it
renders as an explicit `NOT YET OBSERVED · MILESTONE <n>` row in the data
(`not_yet_observed[]`) and on every surface. That is why network
destinations say **Milestone 12** (`punar-netd` does not exist yet), MCP
servers say M9+, and credential classes say M9 — labeled absence, never
an empty array passed off as "nothing happened".

**The privacy model is enforced in types, not in prose** (spec 21.2):
the `ResourceClass` newtype has **no** `From<String>`, and its only
constructors reject `/`, `:`, `\`, any whitespace or non-printable-ASCII
character, a leading `.`, the empty string and anything over the length
cap — then apply the category's shipped-schema pattern on top. A
workspace path, a `host:port`, an argv or a raw `comm` therefore cannot
be *constructed* into a ledger record in the first place, on the wire or
off it (`Deserialize` clears the same floor). No prompts, no
source code, no secrets, no per-read events — aggregate counts plus
first/last seen only (spec 6.4's "do not log every filesystem read by AI
agents" is a type error here, not a code-review note). Retention is 14
days after a session **ends**, pruned event-driven, with **no timers**
(spec 6.3).

**The M8 tree is committed and pushed** (commit `9027438`, 2026-08-25,
plus the m7-check follow-up `f31a8f2`) — the "working-tree only" state
this section described earlier the same day is settled. New in it:
`crates/punar-common/src/ledger.rs`,
`crates/punar-agentd/src/ledger/{mod,store,tail,classes}.rs` +
`tests/ledger.rs` + `data/process-classes.json`,
`shell/punar-shell/Services/Ledger.qml`,
`m8-check.sh` + `punar-m8-check.service`, two `ledger-summary` fixtures
(one valid, one invalid), and `docs/development/milestone-8.md`.
Modified: `ci.yml`, `docs/api/ipc.md`, `AiPanel.qml` (the dashed
placeholder is gone — the D-005 ledger register replaces it),
`Services/qmldir`, `punarctl`, `punard` (`authz.rs`/`server.rs` — the
section-12.5 attribution rule), `punar-agentd`, `punar-common`,
`idle-ram.sh`, `boot-test.sh`, `punar-mock-agent`,
`tmpfiles.d/punar-agentd.conf`, `container-build.sh` and
`validate_schemas.py`.

**What CI has and has not proven about M8.** M8's own push, run
[32874683680](https://github.com/smplify-mdm/punar/actions/runs/32874683680)
(commit `9027438`), was red in `desktop-test` on one stale **m7**-check
assertion — `FAIL inspect: the ledger says it arrives in Milestone 8
(missing: 'MILESTONE 8')`, an assertion M8 itself made obsolete by
replacing the placeholder — with `rust`, `contracts`, `image` and
`boot-test` green. The follow-up, run
[32877949285](https://github.com/smplify-mdm/punar/actions/runs/32877949285)
(commit `f31a8f2`), is **fully green on all five jobs**, so M8's
host-side gates — fmt, clippy, the workspace tests, the schema/fixture
contracts, the containerized mkosi build of both images including every
M8 file, and the `punar-dev` boot — are now CI-proven at HEAD's parent.
**The in-VM M8 exercise ran in neither of those two runs.**
`m8-check.sh` shipped non-executable, its never-enabled oneshot failed
`ExecStart`, and `boot-test` degraded the missing verdict to a
`::warning::` instead of failing — a green run that claimed a milestone
which had not executed. Commit `dc2dc47` restored the exec bit and
turned a missing M2..M9 verdict into a hard failure under KVM; run
[32899132191](https://github.com/smplify-mdm/punar/actions/runs/32899132191)
(commit `7943f3c`) then executed the exercise and delivered
**`PUNAR_M8_OK`, 123 assertions**. The in-VM claims below were unproven
when they were written and are proven now.

Deliverables (spec section 76, Milestone 8) — on disk vs proven:

- [x] Resource summaries (spec 21.1–21.2 Level 3) — the shipped
  `schemas/ai-agent/ledger-summary.json` is the wire contract and **M8
  does not change one byte of it**. `agents.access` returns per-session
  aggregates: directory zones, repositories, process classes, counts and
  first/last seen — never a path, never an event stream. Built, unit and
  integration tested on the host; **no CI run**: the in-VM shape and
  content assertions are m8-check groups 5–6.
- [x] Process attribution (spec 22) — source A: the session's scope
  cgroup is read straight from `/sys/fs/cgroup`, its `cgroup.procs`
  mapped to **classes** through
  `crates/punar-agentd/data/process-classes.json` (staged into the image
  and `sha256sum`-checked byte-identical against the crate file the
  daemon compiles in), with `pids.peak` recorded as **peak concurrent
  pids, never a spawn total** — the honest substitute for the spawn
  history broad tracing would buy. Built and host-tested; **no CI run**
  (m8-check groups 2–4).
- [x] Security events (spec 21.2 Level 4, 53) — one new `punard`
  attribution rule (ipc.md §12.5) tags capability calls with the calling
  session, which is what makes a Level-4 **denial** real rather than
  decorative; the ledger stores an audit **event-id reference**, not a
  payload copy, so the audit log stays the single source of truth.
  Built, unit and integration tested; **no CI run** — the in-VM join of
  a deliberately denied `punarctl capabilities set` back to the ledger
  by event id is m8-check group 7.
- [x] Local retention (spec 76 M8, 24, 6.4) — 14 days after
  `ended_at`, compaction of ended sessions, pruning driven by ledger
  events with **no timer and no polling loop**, bounded on-disk size.
  Built and host-tested; **no CI run** — the in-VM deadline arithmetic
  and the prune against an injected backdated ledger are m8-check
  groups 12 and 15.
- [x] Privacy controls (spec 24.2) — `punarctl privacy ledger [<id>]`
  ("what has this device recorded about me?"), `punarctl privacy purge
  [--session <id> | --all] [--yes]` (unconditional for your own
  sessions, leaving a tombstone and **no resurrection**), `punarctl
  agents access <id>` in D-014 grammar, the panel's privacy line and its
  purge keystroke, and `punarctl privacy connections` reserved
  **honestly** as M12. There is **no upload path in M8** — the
  authorized administrator query is M10 (spec 24.1) and negative probes
  assert its absence. Built and tested; **no CI run** — m8-check groups
  9, 13, 14 and 16.
- [x] Local UI (spec 25, Plate D-005) — `AiPanel.qml`'s dashed
  `LEDGER · MILESTONE 8` placeholder is **replaced** by the real ledger
  register: six category rows, every one present, the unobserved ones
  drawn as labeled `NOT YET OBSERVED` rather than omitted, fed by
  `Services/Ledger.qml` on the M6-era event-driven FileView pattern.
  `qmllint` clean over all 10 `.qml` files; **no CI run** — the
  `punar-m8.png` screenshot is m8-check group 11.
- [x] M8 CI exercise wiring — `m8-check.sh` (17 assertion groups,
  ~111 static assertion sites: preflight, the managed mock session with
  deterministically generated children, the scope cgroup read directly,
  a sampling pass, the `agents.access` shape, Level-3 content **and the
  honest empties**, the Level-4 denial join, the privacy regression that
  greps the on-disk ledger for paths/argv/`comm` and requires zero hits,
  the privacy surface, the counts-only `agents.list` fingerprint, the
  panel screenshot, the retention deadline, an owner purge and its
  tombstone, the no-resurrection drain, a retention prune, negative
  probes proving no export path exists, and three stated-gap `info`
  lines; verdict `PUNAR_M8_OK`/`PUNAR_M8_FAIL` in `m8-report.txt`) + the
  never-enabled root oneshot `punar-m8-check.service`, started
  synchronously by `idle-ram.sh` after the M7 exercise and before
  export; `boot-test.sh` **phase 10** hard-gates the verdict and exports
  the M8 artifacts; `ci.yml` shellchecks the new script, uploads the M8
  reports and screenshot, and raises `desktop-test` from 95 to 105 min.
  Shellcheck and actionlint clean; **never executed anywhere** — the
  exercise only runs in-VM and no VM run contains it.

Static validation for the tree — local and non-authoritative per spec
1.22, measured on 2026-08-25 against the M8 working tree as it stood
before it was committed (the equivalent numbers for today's M9 tree are
in the M9 section below):
`cargo fmt --all --check` and `cargo clippy --workspace --all-targets
--locked -- -D warnings` both exit 0 in the pinned `rust:1` container;
`cargo test --workspace --locked` green — **534 assertions passed, 0
failed** across 27 test binaries (M7's audit measured 458; M8 adds 76);
`./tools/validate-schemas.sh` — 15 schemas metaschema-checked, **127
documents validated, ALL PASS**, including M8's two new
`ledger-summary` fixtures; `shellcheck v0.11.0` (pinned container, the
full CI script list including `m8-check.sh`) exit 0 with zero findings;
`actionlint` clean on `.github/workflows`. Recorded in milestone-8.md
§14.2 and **not** re-run by this audit: `qmllint` 6.11.2 over all ten
`.qml` files, and `PUNAR_BUILD_MODE=summary ./tools/build-image.sh` with
its `sha256sum` equality check on the staged `process-classes.json`.

What remains: **nothing.** Every in-VM claim — all seventeen m8-check
groups, the second mock session and its generated children, the
scope-cgroup read, the schema-exact `agents.access` summary, the Level-4
denial join (the one the attribution race was breaking), the privacy
regression, the panel screenshot, the retention prune, the purge and its
tombstone, and the negative probes — executed in run
[32899132191](https://github.com/smplify-mdm/punar/actions/runs/32899132191)
and passed: **`PUNAR_M8_OK`, 123 assertions**. Out of scope by spec sectioning and
tracked in milestone-8.md §13: network destinations are **M12**
(`punar-netd`), a ledger for unknown/unmanaged agents and the authorized
administrator query **M10**, org-governed retention **M10+**, and the
full graphical privacy panel **M13**. Two of M8's `not_yet_observed`
promises have since been **kept on disk** by the M9 tree below —
`credential_classes` and `credential_request` now have real producers
and left the list, exactly as M8 predicted, with zero ledger-contract
changes — and one was **re-milestoned honestly**: MCP servers and tools
moved M9+ → **M11+**, because M9 shipped the credential broker, not a
tool gateway. `sensitive_resource_access` likewise settled on **M12**.

## M9 — Approval gates + secret broker: done (CI exercise green)

> **Superseding update, 2026-08-25 21:39 UTC.** M9 was committed
> (`a53598b`), pushed, run **red** once
> ([32891877422](https://github.com/smplify-mdm/punar/actions/runs/32891877422)),
> repaired in `7943f3c`, and is now green: run
> [32899132191](https://github.com/smplify-mdm/punar/actions/runs/32899132191)
> delivered **`PUNAR_M9_OK`, 137 assertions** — the first M9 verdict
> that has ever existed — plus the host-side re-validation of the
> exported approval document against the unchanged
> `schemas/audit/approval.json` (boot-test phase 11b, `[PASS]`). Every
> "**no CI run**", "uncommitted" and "never executed" statement in the
> body below is **dated**, and is kept as the record of how M9 was
> validated before it ran. **The repair found no defect in the approval
> gate**: the approve → execute → verify → audit path was read end to
> end and was correct. What was wrong was the *checking*: one assertion
> observed the applied timezone through a stale proxy instead of the
> applied state (replaced by a strictly stronger one), three `jq`
> filters had scoping/precedence errors and were **exiting 5 rather
> than evaluating** — each now evaluates and each was proved to still
> FAIL when the property it guards is removed — and the redaction sweep
> was grepping the mock provider's token *prefix*, a non-secret format
> string, instead of the issued secret. The two assertions that test the
> **actual issued credentials** passed with zero hits across everything
> Punar writes, the journal, and every process `environ`/`cmdline`. No
> assertion was weakened to obtain green.

Design plan and as-built record:
[`docs/development/milestone-9.md`](docs/development/milestone-9.md)
(§15 is the build record, §16 the status). Wire contract:
[`docs/api/ipc.md`](docs/api/ipc.md) §14–§16 — **additive and still
`v: 1`**: `approvals.list/get/create/resolve/consume` and
`privilege.request/status/revoke` on punard's existing socket, the
`/run/punard/approvals.json` side contract for the shell, and a **third
socket** at `/run/punar-secrets/secrets.sock` serving `status`,
`credential.classes`, `credential.request`, `credential.validate` and
`credential.revoke`. M9 is where spec section 28 stops being a schema:
a typed capability call an AI agent is not allowed to make on its own
now **stops**, a card appears on the user's own screen, and the call
executes only if a human answers yes.

**The four laws this milestone is built on**, each enforced in code
rather than asserted in prose: (1) an approval is a **gate**, not a
notification — the gated call returns `approval_required` with **nothing
applied** and `punarctl` exits **4**, the code reserved for exactly this
since M3; (2) **an AI agent may approve nothing** — `approvals.resolve`
is refused for any peer whose kernel-attested cgroup places it inside a
managed agent scope (ipc.md §12.5), and the refusal is itself audited;
(3) **a secret value leaves the broker exactly once**, to the caller, on
a file descriptor — `punar-secrets` keeps only `sha256(token)` after
issuance, so **no method anywhere in Punar can return a token a second
time**, and there is no `credential.show`, `credential.export` or
`credential.list`; (4) **nothing is invented that has no producer** —
M9 ships the producers for M8's `credential_classes`,
`credential_request` and `policy_bypass_attempt` rows and re-milestones
the ones it did not (§9.3 of the plan).

**`schemas/audit/approval.json` and `audit-event.json` are not modified
by one byte.** Everything M9 needs that the approval schema cannot hold
— the originating request, the resolver, the execution result, the
consumption marker — travels as a **sibling field of the envelope**,
never inside the document; `status` never leaves the shipped
`pending|approved|denied|expired` enum. This is M8's Decision-0 law
applied to a second schema, and it is what lets `boot-test` phase 11b
replay an approval document exported from the guest against the shipped
schema on the host.

**The full M9 tree is working-tree only** (audited 2026-08-25 against
local HEAD `dc2dc47`): uncommitted, and sitting on top of **two
unpushed commits** (`f65c7ad` design plates D-015/D-016 and `dc2dc47`
the silent-skip fix), so pushing M9 carries those with it. New:
`crates/punar-secrets/src/{main,server,store,protocol,policy,classes,approvals,attribution,sha256,util,testsupport}.rs`
+ `tests/broker.rs` + `share/classes.yaml` (the M0 placeholder crate,
which said "intentionally empty until Milestone 9", is now the daemon),
`crates/punard/src/{approvals,aipolicy}.rs` + `src/server/m9.rs` +
`tests/approvals.rs`, `crates/punar-common/src/{approval,aipolicy}.rs`,
`crates/punarctl/src/{peer,watch}.rs`,
`shell/punar-shell/Approval/ApprovalOverlay.qml` +
`Services/Approvals.qml`, the `punar-secrets.service` unit with its
vendor `.wants` symlink and `tmpfiles.d/punar-secrets.conf`,
`m9-check.sh` + `in-agent-scope.sh` + `punar-m9-check.service`, four
approval fixtures (three valid, one invalid) and
`fixtures/policies/ai-policy-personal-defaults.yaml`. Modified:
`ci.yml`, `docs/api/ipc.md`, `PERFORMANCE_BUDGETS.md`, `punard`,
`punarctl`, `punar-agentd` (the ledger halves M9 fills),
`punar-common`, `Bar.qml`/`shell.qml`/`Services/qmldir`, `idle-ram.sh`,
`m8-check.sh`, `punar-mock-agent`, `tmpfiles.d/punard.conf`,
`container-build.sh`, `boot-test.sh`, `check-budgets.sh` and
`validate_schemas.py`. The same working tree also carries
`docs/development/milestone-{10,11,12}.md` and
`docs/design/mockups/shortcuts.html` — forward planning, **not** M9
deliverables, and nothing below depends on them.

Deliverables (spec section 76, Milestone 9) — on disk vs proven:

- [x] Local graphical approval (spec 28, Plate D-003) —
  `Approval/ApprovalOverlay.qml` fed by `Services/Approvals.qml` on the
  M6-era event-driven `FileView` pattern from
  `/run/punard/approvals.json` (`0640 root:punar`, summary only — never
  a secret, never a reason the shell must not hold). The overlay is the
  D-003 acceptance reference: identity chain line, live expiry
  countdown that goes amber under a minute, the contract block naming
  the exact typed capability, the policy that gated it and the audit
  promise, green filled **Approve** / red ghost **Deny** on **A**/**D**,
  and **Esc** defers without deciding. It appears **unbidden** when
  something is pending, so no new keyboard chord was added and
  `punar-binds.conf` is unchanged. Resolution runs `punarctl approvals
  resolve` as fixed argv, never a shell string. Built and qmllint-clean;
  **no CI run** — the live card, the countdown and the screenshot are
  m9-check group 5.
- [x] The gate is real, not a notification (spec 28, 60) — an
  agent-originated `capabilities.set` returns error `approval_required`
  with `approval_id` / `expires_at` / `capability` / `resource` /
  `decision` / `policy_ids` in `details`, **nothing applied**, and
  `punarctl` exit **4**; the mutation takes effect only after a human
  resolves, verified against a live `nft` read rather than a cached
  descriptor. `approvals.create` and `approvals.consume` are root-only,
  `approvals.resolve` is human-only, and `approvals.approve` /
  `approvals.deny` / `approvals.delete` / `privilege.grant` /
  `privilege.extend` deliberately **do not exist**. Built, unit and
  integration tested on the host; **no CI run** — m9-check groups 2–5.
- [x] Short-lived mock credentials (spec 29) — `punar-secrets` as a
  third daemon (`Type=simple`, `ProtectSystem=strict`,
  `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, **no**
  `StateDirectory=`), with the class catalog shipped as **data** in
  `share/classes.yaml` → `/usr/share/punar/secrets/classes.yaml`: three
  mock classes (`github` allow, `aws-dev` request, `aws-prod` deny under
  personal defaults), TTLs declared per class, provider `mock` and every
  surface that prints a token saying **SIMULATED**. Issuance is a
  one-way door — the broker retains `sha256(token)` and nothing else.
  Built and host-tested; **no CI run** — m9-check groups 7–8 (allow,
  request-then-approve, deny, single use, real expiry, revoke).
- [x] Redaction tests (spec 29, 53) — the headline assertion. m9-check
  group 9 greps **every file Punar writes**, the journal, the whole
  export tar and every `punar` process's `environ` and `cmdline` for the
  two tokens actually issued and requires **zero** occurrences, with a
  **negative control** proving the grep would have found them, plus a
  second weaker sweep for the identifiable `punar-mock-` prefix that
  would catch a token this script never held. The report records
  **counts and file names, never values**. `punar_common::Redacted`
  carries secret material in the daemons. Host tests exist; **no CI
  run** — the sweep against a real export tar is unobserved.
- [x] Just-in-time privilege (spec 48, Plate D-012) — `punarctl
  privilege request --capability <cap> --reason <text> [--duration
  <min>]`, `privilege status`, `privilege revoke [<id>|--all]`; the
  reason is **required** and travels verbatim into the audit record; a
  grant is a section 39 **Temporary Approved Exception**, so its id is
  cited in `policy_ids` rather than in a `details` object
  `audit-event.json` does not have; the bar carries the ELEVATED
  countdown chip; expiry is lazy, with **no new timer**. `privilege.request`
  is refused for **any** agent-attributed peer, always — an agent gets
  per-request approvals, never a time window (spec 48/60). Built and
  tested; **no CI run** — m9-check group 11.
- [x] The M8 ledger's promise, kept (spec 21) — `credential_request`
  filled with zero code change as M8 predicted; `credential_classes`
  needed real work and got it (`ledger/tail.rs` gains a `classes`
  channel; only an **issued** credential contributes a class — a refused
  one keeps its Level-4 `denied_access` reference, because a credential
  that was not issued is not access), and `classify()` gained rule 0 so
  `approval.resolve` + `decision: deny` becomes a real
  `policy_bypass_attempt`. `not_yet_observed()` went from eight rows to
  **five**. Built, with 2 new unit tests and one integration test that
  drives it through the socket and then asserts no token, hash or
  approval payload reached disk; **no CI run** — m9-check group 10.
- [x] M9 CI exercise wiring — `m9-check.sh` (**13 assertion groups**,
  ~129 static assertion sites plus 10 stated-gap `info` lines: preflight
  and the vendor-symlink assertion, the agent-originated gated mutation,
  the pending approval validated against the shipped schema by `jq`
  in-guest, the agent-may-resolve-nothing refusal, the D-003 screenshot
  and the human resolve with both audit pointer directions, the expiry
  clock, the broker's allow/request/deny paths, real TTL expiry and
  revoke, the redaction sweep, the ledger join, JIT privilege, negative
  probes, and the verdict on the approval nobody answered; verdict
  `PUNAR_M9_OK`/`PUNAR_M9_FAIL` in `m9-report.txt`) + `in-agent-scope.sh`
  (runs one command from **inside** a managed session's real scope
  cgroup, forked by the user manager because cgroup v2 delegation
  permits the migration only from inside the delegated subtree — the M7
  lesson; exits 97/98 on harness failure, deliberately outside
  `punarctl`'s documented 0–5 range) + the never-enabled root oneshot
  `punar-m9-check.service`, started synchronously by `idle-ram.sh` after
  the M8 exercise and before the export; `boot-test.sh` **phase 11**
  hard-gates the verdict and **phase 11b** re-validates the exported
  approval document against `schemas/audit/approval.json` on the host;
  `ci.yml` renames the job to M2..M9, raises `desktop-test` from 105 to
  125 min, shellchecks both new scripts and uploads `punar-m9.png` and
  the M9 reports. Both new scripts ship mode `100755` — the M8 lesson,
  checked. Shellcheck and actionlint clean; **never executed anywhere**.
- [x] Budgets, honestly (spec 6.2) — `punar-secrets.service` joins the
  services-PSS sum in `idle-ram.sh` (`PUNAR_SERVICE_UNITS` is now three
  units), `check-budgets.sh` and `PERFORMANCE_BUDGETS.md` §2.3 name all
  three, and the **thresholds are unchanged** (target 100 MB, MVP
  ceiling 150 MB). Adding a daemon and leaving it out of the sum, or
  raising a threshold to make room for it, would each make the gate say
  something untrue. **The three-daemon number is not yet measured**: the
  last CI-measured value is 4 MB for two daemons (run 32877949285), and
  the first three-daemon value comes from a `punar-desktop-ram-report`
  artifact that does not exist yet.

Static validation for the M9 tree — local and non-authoritative per
spec 1.22, **re-run by this audit on 2026-08-25** against the working
tree: `cargo fmt --all --check` and `cargo clippy --workspace
--all-targets --locked -- -D warnings` both exit 0 in the pinned
`rust:1` container; `cargo test --workspace --locked` green — **719
passed, 0 failed** across **30 test binaries** (M8's audit measured
534 across 27; M9 adds 185 tests and 3 binaries);
`./tools/validate-schemas.sh` — 15 schemas metaschema-checked, **132
documents validated, ALL PASS** (127 at M8; M9's five new fixtures are
the delta); `shellcheck v0.11.0` (pinned container, the full CI script
list, now **17 scripts** including `m9-check.sh` and
`in-agent-scope.sh`) exit 0 with zero findings; `actionlint` clean on
`.github/workflows`. Recorded in milestone-9.md §15.5 and **not** re-run
by this audit: `qmllint` 6.11.2 over all twelve `.qml` files, and
`PUNAR_BUILD_MODE=summary ./tools/build-image.sh` with its check that
both staged M9 data files are present.

What remains: **nothing.** All thirteen m9-check groups executed in run
[32899132191](https://github.com/smplify-mdm/punar/actions/runs/32899132191)
— **`PUNAR_M9_OK`, 137 assertions** — `punar-m9.png` was taken, phases
11 and 11b ran end to end (the exported approval document validates
against the unchanged schema on the host), the redaction sweep ran in
the VM and found **zero** hits for the issued secrets across everything
Punar writes, the journal, and every process `environ`/`cmdline`, and
the three-daemon `PUNAR_SERVICES_RSS_MB` measured **6 MB** against an
unchanged 100 MB target (`boot-test.sh`'s printed label still says
*"punard + punar-agentd"* while `idle-ram.sh` sums three units — the
number covers three daemons, the label under-reports it; tracked in
milestone-10.md §22.5). Known gaps stated rather than
absorbed, per milestone-9.md §15.4 and §13: the expiry group uses the
**shipped 300 s TTL** (`--ttl 15` does not exist and must not), there is
**no graphical path back to a deferred approval card** in M9 (the
multi-approval queue is M13), filesystem **zone grants in the shipped AI
authority document are declared but enforce nothing** in M9 and no
surface may claim otherwise, and the broker is a **mock provider** —
there is no upstream credential authority and the CI VM has no network.
Out of scope by spec sectioning: MCP servers and tools are **M11+**,
network destinations and sensitive-zone observation **M12**, the
unknown-agent ledger and the authorized administrator query **M10**.

## Current milestone: M10 — Shadow AI detection MVP: implemented on disk; statically validated; uncommitted; no CI run

Design plan, build record and status:
[`docs/development/milestone-10.md`](docs/development/milestone-10.md)
(§21 is the build record, **§22 is the status of record**). Wire
contract: [`docs/api/ipc.md`](docs/api/ipc.md) **§17–§20 — additive and
still `v: 1`**: `alerts.list`, `alerts.dismiss`, `query.answer` (root
peer only) and `queries.list` (any admitted peer) on the M7 agentd
socket, amended `agents.scan`/`agents.list` results, punard's courier
behaviour, the control-plane methods the mock now serves, and the
`/run/punar-agentd/alerts.json` side contract. M10 is where spec section
23's promise stops depending on someone looking: **the device notices on
its own, tells the user first, remembers exactly enough, and answers an
administrator only within a scope the user can read back.**

**The four architectural laws** (milestone-10.md §0), each load-bearing
rather than decorative: (1) **Punar is not a server** — M10 opens no
inbound socket, port or listener of any kind; a remote query reaches the
device only because *the device fetched it* on the reconcile-piggybacked
sync M5 already shipped; (2) **the transport is not the authority** —
`punard` carries queries and answers, `punar-agentd` decides what may be
answered, re-evaluating authorization from **local** state
(`enrollment.json`, read by the data owner itself) and never from the
request (spec 59.4, compromised control plane); (3) **the user learns
first and can always read the record** — every query, answered or
refused, lands in `/var/lib/punar/agents/queries.jsonl` and is printed
by an **unprivileged** `punarctl privacy queries`, and the answer's
content is never larger than what the same user can already print about
themselves (spec 24.2); (4) **suspected, never certain, and never
armed** — M10 detects, records and alerts; it blocks nothing, kills
nothing and quarantines nothing, and the alert card says so in words.

Deliverables (spec section 76, Milestone 10) — on disk vs proven:

- [x] Known/observed/unknown classification, now **continuous** — M7
  shipped the vocabulary and an on-demand scan and deferred the trigger
  by name; M10 adds `punar-agentd-scan.timer` (`OnBootSec=240`,
  `OnUnitActiveSec=240`, `AccuracySec=30`, armed by a **vendor**
  `timers.target.wants` symlink, never `/etc`, never `is-enabled`) whose
  oneshot runs `/usr/bin/punarctl agents scan --trigger timer` — the
  timer path is the same socket, authorization and audit path a human
  uses, and the daemon gains no internal clock. 240 s is an exact
  multiple of the shipping 120 s reconcile period so systemd
  **coalesces** the two wakeups. Three event-driven immediate triggers
  (register, session reap, enrollment transition) and **no polling
  loop** (spec 6.3). A scan **diff** is the event: an unchanged pass
  writes zero bytes (spec 6.4). One new detection input, expressed as
  **data** not code — `unmanaged-path-agentlike` in `suspected.json`,
  `require: "both"` (an unmanaged path prefix **and** an agent-like name
  token; either alone is not a signal). Built and tested on the host;
  **no CI run** — that the timer fires, and that a detection appears
  with **no** manual scan in the window, is m10-check group 3 and has
  never been observed.
- [x] Fixture unknown agent, made real — `fixtures/agents/unknown-agent/`
  has described a *persisted, ledgered* unknown agent since M7. M10
  closes M8's open question in the affirmative: detections get a
  schema-exact `registry-record.json` in
  `/var/lib/punar/agents/detections.jsonl` and a
  `ledger-summary.json`-conformant ledger, **strictly smaller than a
  managed one by construction** — a process class, a **zone class** for
  where the executable lives, and the Level-4 `unknown_ai_execution`
  event references, with everything else an explicit
  `not_yet_observed[]` row. **No child-process walk, no `cwd` read, no
  cmdline/argv/environment** — the three refusals are structural, and
  `project` is `"unknown"` rather than inferred. Two identities do two
  jobs: `detection_id` (exe ‖ uid ‖ boot id ‖ pid ‖ start ticks) for the
  set-diff and the record, `signature_id` (exe ‖ uid) for the alert.
  Retention **7 days** after the detection clears, purgeable
  unconditionally by the owning user. Built and tested; **no CI run** —
  m10-check group 6, plus boot-test **phase 12b** which replays the
  exported summary against the unchanged schema on the host (the image
  has no JSON-Schema validator).
- [x] Local alert (Plate D-009) — `/run/punar-agentd/alerts.json`,
  **`0640 root:punar`**, atomic write on change only: the M9
  root-owned-summary lesson applied, because a forged *"Unknown AI
  activity suspected"* card with an `Inspect` action is a phishing
  primitive and `/run/punar` is user-writable. The shell reads it with a
  `FileView` (`Services/Alerts.qml`, the established
  `Status`/`Agents`/`Ledger`/`Approvals` pattern — inotify, no polling,
  no socket client) and draws one layer-shell region
  (`Alert/AlertStack.qml`) with the D-009 anatomy and `I`/`D` keys.
  **One alert per `signature_id`**, not per scan and not per process,
  with a **24 h quiet window** after the last live detection clears, so
  a crash-looping agent yields one card a day. Dismissal **files, never
  destroys**. The first sighting **breaks through do-not-disturb** —
  argued from spec 24.2, not taste: an administrator can query this
  exact fact from this milestone onward, so no quiet toggle may create a
  state where the admin knows and the user does not; under DND it
  renders without sound, without focus steal and without auto-dismiss.
  The card deliberately **drops the plate's `→ api.foo.ai` subline**:
  nothing observes network destinations before M12 (spec 1.22). Built,
  `qmllint` clean per milestone-10.md §21.3; **no CI run** — the card,
  the screenshot `punar-m10.png` and the DND breakthrough are m10-check
  groups 4–5 and have never been rendered in a VM.
- [x] Smplify remote query (spec 51, 24.1, 51.1) — the device **pulls**
  pending queries on the existing sync piggyback when enrolled
  (`queries.pending` → `query.answer` on the agentd socket →
  `queries.answer` back), so there is no listener, no long poll, no new
  timer and no new wakeup; the **administrator's** client is the thing
  that waits, and every surface states the ≤ one-reconcile-period
  latency. Scope is a **closed enum of four** — `inventory`,
  `authority`, `resource_summary`, `security_events`, one per spec 21.2
  observation level — with no wildcard and no free text; an unrecognised
  value is refused `out_of_scope`, never answered best-effort.
  Authorization is a **three-way intersection evaluated by the data
  owner**: `requested ∩ org_granted ∩ device_builtin_max`, where
  `org_granted` is read by agentd **from `enrollment.json` itself**,
  never from the request. **Fail closed**: no file, or no
  `remote_query_scopes` key, means the empty set. The mock enforces RBAC
  too (`fixtures/organizations/acme/admins.json`, three roles) and the
  device does not trust it — two independent checks, and the device's is
  the one that decides. The refusal list is closed and **mostly
  structural**: prompts, source, file paths, cmdlines, secrets, pids and
  cgroup paths, process trees and audit payloads are refused because
  **no field exists to carry them**, not because a filter drops them.
  Every query is recorded with all six spec-51.1 fields; the **answered
  payload is deliberately not stored**. Built, with integration tests in
  three crates; **no CI run** — the enrolled answer, the device-side
  refusal, the unprivileged `privacy queries` read and the personal-mode
  inert path are m10-check groups 7–10.
- [x] Unmanaged-first, structurally (DESIGN_LANGUAGE §8) — three
  independent, each-sufficient gates make the query path inert on a
  personal device: the sync hook that pulls queries runs only when
  enrolled (M5's gate, `m5-check`-proven since); agentd's intersection
  reads `enrollment.json` and no file means the empty set; and no
  inbound path exists at all. Stated with its honest limit: **"inert" is
  not "absent"** — the enterprise query code ships in every binary, and
  a build with it compiled out is the stronger claim M10 does not make.
- [x] M10 CI exercise wiring — `m10-check.sh` (**13 groups, ~113 static
  assertion sites** — 80 helper calls plus 33 hand-written assertion
  blocks — and 10 stated-gap `info` lines), the never-enabled root oneshot
  `punar-m10-check.service` started synchronously by `idle-ram.sh` after
  the M9 exercise and before the export, `boot-test.sh` **phase 12**
  (verdict hard-gated: a `PUNAR_M10_FAIL`, a truncated report **or a
  missing report under KVM** all fail the script) and **phase 12b**
  (host-side schema replay), `ci.yml` job renamed to M2..M10 with
  `desktop-test` raised 125 → 135 min and the M10 artifacts uploaded.
  The check script is mode **0755 on disk** — the M8 trap — but is **not
  yet committed**, so the bit must survive `git add`. Shellcheck clean;
  **never executed anywhere**.
- [x] Budgets (spec 6.2–6.4) — **no new daemon**, so
  `PUNAR_SERVICE_UNITS` is unchanged at three units and the 100 MB
  target / 150 MB ceiling are untouched; the scan is a transient
  `punarctl` every four minutes and is **not** stopped for the idle-RAM
  sampling window, because budgets are measured against the shipping
  configuration. Steady-state disk I/O is **zero writes**. The claim
  that the 240 s timer coalesces with the 120 s reconcile timer is
  arithmetic until a CI run measures it.

Static validation for the M10 tree — local and non-authoritative per
spec 1.22, **re-run by this audit on 2026-08-25** against the working
tree: `cargo fmt --all -- --check` and `cargo clippy --workspace
--all-targets -- -D warnings` both exit 0 in the pinned `rust:1`
container; `cargo test --workspace` green — **840 passed, 0 failed**
across 34 suites (719 at M9); `./tools/validate-schemas.sh` — 15 schemas
metaschema-checked, **132 documents validated, ALL PASS**, and **no
schema was edited by M10** (M8's Decision-0 law holds for a third
milestone: everything the shipped schemas cannot hold travels as a
sibling field of the IPC result or in a separate local record);
`shellcheck v0.11.0` (pinned container) clean on `m10-check.sh`,
`idle-ram.sh` and `boot-test.sh`. Recorded in milestone-10.md §21.3 and
**not** re-run by this audit: `actionlint`, `qmllint` 6.11.2 over all
fourteen `.qml` files, `PUNAR_BUILD_MODE=summary ./tools/build-image.sh`,
and the replay of every `jq` filter in `m10-check.sh` against real
documents (40 filters, none exiting 5 — the M9 failure mode).

What remains: **nothing M10 claims is proven at runtime.** Ten of the
eleven §19 done-conditions are designed and gated, not observed; only
"`ipc.md` §17–§20 landed additively" is verifiable by reading the tree.
`m10-check` has never executed, **no `PUNAR_M10_OK` exists anywhere**,
no `punar-m10.png` has been taken, the timer has never been seen firing,
no query has crossed a real reconcile pass, and the 135-min
`desktop-test` budget is untested. The tree is also **uncommitted** (48
modified files, 21 new paths) on top of five docs-only unpushed commits;
`git status` additionally shows **8.1 GB** of untracked `target-docker*/`
container build cache that `.gitignore` does not cover, so `git add -A`
here would commit it. Two assertions M10 makes stale are left for their
owners and named in milestone-10.md §22.5: `m8-check.sh` line **371**
(the Level-4 `not_yet_observed[]` list — M10 ships
`unknown_ai_execution`'s producer) and line **375** (evidence ⊆ the four
M8 values — M10 adds `detection_scan`); both still pass today because
both read a **managed** session's ledger, and both should be widened to
assert the partition rather than the literal list. Out of scope by spec
sectioning and tracked in milestone-10.md §17–§18: **blocking, killing
or quarantining** an unmanaged agent is M12 plus a policy verb (M10
renders no dead buttons), network destinations and MCP activity as
detection inputs or ledger rows are M12/M11+, the notification centre,
the freedesktop daemon, the OSD and a persistent DND toggle are **M13**,
real cloud/transport/RBAC/IdP and any cross-device fleet **UI** are
Phase 2, behavioural risk scoring is Phase 3, and every tracing
mechanism spec 1.14 forbids — eBPF, fanotify, ptrace, `LD_PRELOAD`,
exec-time notification — is **permanently out**, not deferred.

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
| M4 — Declarative desired state | Schemas, preference/policy merge, reconciliation, explain, firewall-drift demo | Not specified in spec §76 | **Done** — [run 32849448721](https://github.com/smplify-mdm/punar/actions/runs/32849448721) (2026-08-25) fully green incl. the in-VM M4 exercise (`PUNAR_M4_OK`, 29 assertions, timer-driven drift-remediation demo); services RSS still 2 MB; road there: [run 32837156881](https://github.com/smplify-mdm/punar/actions/runs/32837156881) red on one check-wiring assertion, fix's [run 32839803185](https://github.com/smplify-mdm/punar/actions/runs/32839803185) red pre-VM on bundled M5 WIP |
| M5 — Mock Smplify enrollment | Mock control plane, device enrollment, policy, compliance, inventory | Not specified in spec §76 | **Done** — [run 32849448721](https://github.com/smplify-mdm/punar/actions/runs/32849448721) (2026-08-25) fully green incl. the in-VM M5 exercise (`PUNAR_M5_OK`, 63 assertions — enroll → managed → offline → unenroll journey, category-only sync asserted on the mock's received side); idle RAM 1156 MB mean (pass w/ over-target warning); the finished tree's first run [32846674987](https://github.com/smplify-mdm/punar/actions/runs/32846674987) was red on exactly one case-sensitive verdict grep in m5-check |
| M6 — Developer environment manager | `punar-env`, Podman/devcontainer, Atlas fixture | Not specified in spec §76 | **Done** — [run 32857914904](https://github.com/smplify-mdm/punar/actions/runs/32857914904) (2026-08-25) fully green incl. the in-VM M6 exercise (`PUNAR_M6_OK`, 56 assertions — offline `podman load` → rootless `up`/`shell`/`status`/`destroy`, Atlas fixture byte-identical throughout); idle RAM 1162 MB mean (pass w/ over-target warning), services RSS 2 MB; the finished tree's first run [32852810872](https://github.com/smplify-mdm/punar/actions/runs/32852810872) was red on m6-check calling `diff`, which the image does not ship |
| M7 — AI Agent Registry | Managed sessions, Claude adapter, second/generic adapter, agent identity, classification, local UI | Not specified in spec §76 | **Done** — [run 32868450695](https://github.com/smplify-mdm/punar/actions/runs/32868450695) (2026-08-25, commit `f95c9c4`) fully green on all five jobs incl. the in-VM M7 exercise (`PUNAR_M7_OK`, 74 assertions — managed mock session in its own `punar-agent-<id>.scope`, kernel-checked cgroup attribution, schema-exact `registry.jsonl` transitions, adapters-as-data, the `foo-agent` fixture found as `UNKNOWN · SUSPECTED`, the Plate D-005 panel screenshot); services RSS **4 MB combined** (punard + punar-agentd, within the 100 MB target); idle RAM 1175 MB mean (pass w/ over-target warning, +13 MB for the second daemon); the M7 tree's own push [run 32865062323](https://github.com/smplify-mdm/punar/actions/runs/32865062323) was red on one stale **m6**-check assertion expecting the removed `punar-env agent` stub message, not on M7 code |
| M8 — AI Access Ledger | Resource summaries, process attribution, security events, local retention, privacy controls | Not specified in spec §76 | **Done** — [run 32899132191](https://github.com/smplify-mdm/punar/actions/runs/32899132191) (2026-08-25, commit `7943f3c`) fully green on all five jobs incl. the in-VM M8 exercise (**`PUNAR_M8_OK`, 123 assertions** — the first M8 verdict that has ever existed): the scope-cgroup read, the schema-exact `agents.access` summary, the Level-4 denial join, the privacy regression, the panel screenshot, the retention prune, the purge and its tombstone, and the negative probes. The road there is the milestone's own lesson: [run 32874683680](https://github.com/smplify-mdm/punar/actions/runs/32874683680) (`9027438`) was red on a stale **m7**-check assertion, and [run 32877949285](https://github.com/smplify-mdm/punar/actions/runs/32877949285) (`f31a8f2`) went **green without executing m8-check at all** — the script shipped `100644`, its oneshot failed `ExecStart`, and boot-test degraded a missing verdict to a `::warning::`; `dc2dc47` restored the bit and made a missing M2..M9 verdict a hard failure. `7943f3c` then fixed the one real defect the exercise found: a pre-registration race dropped an attribution arriving before its session existed, so the Level-4 denial reference never joined the ledger (attributions are now held in a bounded, oldest-dropped, tombstone-respecting buffer, +3 tests), plus one over-strict retention assertion replaced by the invariant it meant. The ledger derives from four mediation points Punar already owns with **no** eBPF/fanotify/ptrace/LD_PRELOAD anywhere (spec 1.14); `ledger-summary.json` unchanged and privacy enforced in **types**; `agents.access` + `ledger.purge` additive (ipc.md §12–§13); 14-day retention pruned event-driven with no timers. Network destinations stay **M12**, MCP servers **M11+**, both labelled `NOT YET OBSERVED` |
| M9 — Approval gates + secret broker | Local graphical approval, short-lived mock credentials, redaction tests | Not specified in spec §76 | **Done** — [run 32899132191](https://github.com/smplify-mdm/punar/actions/runs/32899132191) (2026-08-25, commit `7943f3c`) fully green on all five jobs incl. the in-VM M9 exercise (**`PUNAR_M9_OK`, 137 assertions** — the first M9 verdict that has ever existed) and boot-test phase 11b, which replays the guest-exported approval document against the unchanged `schemas/audit/approval.json` on the host (`[PASS]`). M9's own push, [run 32891877422](https://github.com/smplify-mdm/punar/actions/runs/32891877422) (`a53598b`), was red — and the repair found **no defect in the approval gate**: the approve → execute → verify → audit path was read end to end and was correct. What was wrong was the checking — one assertion observed the applied timezone through a stale proxy (replaced by a strictly stronger one), three `jq` filters had scoping/precedence errors and were **exiting 5 instead of evaluating** (each now evaluates, and each was proved to still FAIL when its guarded property is removed), and the redaction sweep grepped the mock provider's non-secret token *prefix* rather than the issued secret; the two assertions that test the **actual** issued credentials passed with zero hits across everything Punar writes, the journal, and every process `environ`/`cmdline`. No assertion was weakened to get green. The gate is real: an agent-originated typed call returns `approval_required` with **nothing applied** and `punarctl` exit **4**, a Plate D-003 overlay appears unbidden, and the capability executes only after a human resolves — verified against a live `nft` read. `approvals.*` + `privilege.*` additive on punard's `v: 1` socket; a **third daemon** `punar-secrets` issues mock credentials whose value leaves **once, on a fd**, with only `sha256(token)` retained; an AI agent may resolve **nothing** and may never hold a privilege window; `schemas/audit/approval.json` unchanged by one byte. Three-daemon services RSS measured **6 MB** against an unchanged 100 MB target |
| M10 — Shadow AI detection MVP | Known/observed/unknown classification, fixture unknown agent, local alert, Smplify remote query | Not specified in spec §76 | **Implemented on disk (current); statically validated; uncommitted; no CI run** — classification becomes **continuous**: `punar-agentd-scan.timer` (240 s, `AccuracySec=30`, vendor `.wants` symlink) runs `punarctl agents scan --trigger timer` through the same socket/authz/audit path a human uses, coalescing with the 120 s reconcile timer, with three event-driven immediate triggers and **no polling loop**; an unchanged pass writes **zero bytes**. One new detection input, as **data**: `unmanaged-path-agentlike`, `require: "both"` (unmanaged path **and** agent-like name — either alone is not a signal). M8's open question is closed in the affirmative: a detection gets a schema-exact `registry-record.json` in `detections.jsonl` and a `ledger-summary.json`-valid ledger that is **strictly smaller than a managed one by construction** — a process class, a zone class, the `unknown_ai_execution` references, everything else `not_yet_observed[]`; **no child-process walk, no `cwd`, no cmdline**, `project` is `unknown`, retention 7 days, purgeable. The alert lives in `/run/punar-agentd/alerts.json` (**`0640 root:punar`** — the M9 lesson: a forged card is a phishing primitive), is drawn by a `FileView`-watched layer-shell region with the D-009 anatomy, is raised **once per `signature_id`** with a 24 h quiet window, **files rather than destroys** on dismiss, and **breaks through do-not-disturb on first sighting** — argued from spec 24.2, because an admin can query this fact and the user must never know last. The plate's `→ api.foo.ai` subline is deliberately dropped: nothing observes network destinations before M12. The remote query is a **pull** on the existing sync piggyback — no listener, no long poll, no new timer; four closed scopes; authorization is a three-way intersection evaluated by the **data owner** reading `enrollment.json` itself and failing closed; the mock enforces RBAC too and the device does not trust it; the refusal list is closed and **mostly structural** (no field exists to carry a prompt, a path or a cmdline); every query is recorded with all six spec-51.1 fields and the **payload is not stored**; an **unprivileged** `punarctl privacy queries` shows the user everything that was asked. `ipc.md` §17–§20 landed additively, still `v: 1`, and **no schema was edited**. Host gates re-run green by this audit (fmt, clippy, `cargo test` **840/0** across 34 suites, schemas **15/132 ALL PASS**, shellcheck v0.11.0; actionlint, qmllint and the mkosi summary recorded in milestone-10.md §21.3, not re-run); **`m10-check` (13 groups, ~113 assertion sites) has never executed, no `PUNAR_M10_OK` exists anywhere**, `punar-m10.png` does not exist, and the timer has never been observed firing. Status of record: milestone-10.md **§22** |
| M11 — Browser/web-app integration | Current Chromium, native launcher integration, project/browser context prototype, web-app install flow | Not specified in spec §76 | Not started |
| M12 — Network privacy prototype | Local network observability, project-route policy, relay abstraction, simulated or prototype private relay | Not specified in spec §76 | Not started |
| M13 — Demo polish | First boot, enrollment, keyboard UX, AI panel, privacy panel, deterministic demo | Not specified in spec §76 | Not started |
