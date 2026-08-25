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
  (2026-08-25, all five jobs green — `PUNAR_M6_OK`; see M6 below). **No CI
  run contains any M7 code**: the M7 tree is working-tree only (see M7
  below).
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
2 MB. The in-VM chain now stands at **209 assertions** (M2 33, M3 28,
M4 29, M5 63, M6 56).

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

## Current milestone: M7 — AI Agent Registry: implemented on disk; statically validated; uncommitted; no CI run

Architecture, decisions, and as-built record:
[`docs/development/milestone-7.md`](docs/development/milestone-7.md) (§14 is
the verification status). Wire contract:
[`docs/api/ipc.md`](docs/api/ipc.md) §10–§11 — a **sibling socket**, not a
change to punard's `v: 1` surface: `punar-agentd` serves `agents.list`,
`agents.get`, `agents.register`, `agents.end`, `agents.scan` on
`/run/punar-agentd/agentd.sock`, plus the §11 side contract
`/run/punar/agents.json` for the shell. M7 is where the AI-native thesis
(spec sections 18–27) stops being schemas and becomes a running surface:
an agent session launched *by* the OS gets an identity, a scope cgroup,
a registry record, and a panel row; an agent the OS did not launch gets
found by a heuristic that says **suspected**, never *certain*.

**The full M7 tree is working-tree only** (audited 2026-08-25 against HEAD
0ba4ea6): uncommitted and unpushed. New: `crates/punar-agentd/src/{main,
server,registry,detect,adapters,proc,authz,summary,util,testsupport}.rs` +
`tests/registry.rs`, `crates/punar-common/src/agent.rs`,
`crates/punar-env/src/{session,adapter,authority,agentd}.rs`,
`shell/punar-shell/AiPanel/AiPanel.qml` + `Services/Agents.qml`,
`punar-agentd.service` (+ its vendor `.wants` symlink) and
`tmpfiles.d/punar-agentd.conf`, `m7-check.sh` + `punar-m7-check.service`,
`punar-mock-agent`, `foo-agent-fixture.sh`, the staged
`usr/share/punar/agents/{adapters,signatures}` data, and
`docs/development/milestone-7.md`. Modified: `ci.yml`, `docs/api/ipc.md`,
`schemas/ai-agent/registry-record.json`, `PERFORMANCE_BUDGETS.md`,
`tests/performance/check-budgets.sh`, `idle-ram.sh`, `boot-test.sh`,
`container-build.sh`, the Hyprland bind files, `punarctl`, `punar-env`,
`punar-common`, and the shell entrypoint. **Nothing M7 has ever run in
CI**: the newest run,
[32857914904](https://github.com/smplify-mdm/punar/actions/runs/32857914904),
is M6's green run at commit 0ba4ea6 and contains no M7 code.

Deliverables (spec section 76, Milestone 7) — on disk vs proven:

- [x] Managed sessions — `punar-env agent <name>` (M6's labeled stub) is
  now the real spec section 27 launch: manifest `ai.agents` membership
  check → adapter resolution → authority summary → `agents.register` on
  the agentd socket → `systemd-run --user --scope` into
  `punar-agent-<id>.scope` → the adapter command in the project directory
  → `agents.end` on exit, with crash-honest reaping (`agents.reap`) for
  sessions whose process died without an end. The session id is the
  registry's, not the caller's claim. On disk + host-tested; **no CI
  run** — the in-VM journey is m7-check groups 3, 5 and 10.
- [x] Claude adapter — `adapters/claude-code.json`, staged as **data**
  (`/usr/share/punar/agents/adapters/`), not code: launch command,
  `version_command`, and the `comm`/`exe_glob` identity signature for
  `claude`. The CI VM has no network and no real Claude Code binary, so
  the exercise substitutes `/usr/lib/punar/punar-mock-agent` — a
  self-labeling dev/CI stand-in ("PUNAR MOCK AGENT … performs no AI
  work") gated behind `PUNAR_AGENT_MOCK=1`. Adapter definition validated
  against `schemas/ai-agent/agent-definition.json` **in place** (the file
  the image ships is the file the schema checked); the managed launch
  itself: **no CI run**.
- [x] Second/generic adapter — `adapters/generic.json`
  (`generic-shell`, `/bin/sh`, empty signature — a generic adapter
  identifies its sessions by the launch scope, not by what the binary
  looks like), proving spec section 26's "adapters should be modular":
  adding an agent is adding a JSON file, with zero Rust changes. Schema-
  validated; **no CI run**.
- [x] Agent identity + attribution (spec 22) — identity is *checked, not
  claimed*: `SO_PEERCRED` at accept authorizes the register/end caller,
  the registered pid's cgroup is read from the kernel and must name the
  scope, and the executable identity is recorded from `/proc`. Records
  append to `/var/lib/punar/agents/registry.jsonl` (0700 root:root —
  a writable registry *is* attribution authority), conform to
  `schemas/ai-agent/registry-record.json`, and carry one record per
  lifecycle transition. The schema's `status` enum is widened
  `["active"] → ["active", "ended"]` — the additive widening its own
  description pre-authorized. Host-tested (27 unit + 8 integration
  assertions in `punar-agentd`); the kernel-vs-record cgroup agreement:
  **no CI run**.
- [x] Classification (spec 19.1, 23) — the three shipped values
  `managed` / `observed` / `unknown`, with `managed` *proven* by the
  launch scope and `unknown` always rendered **SUSPECTED**. Detection is
  a `/proc` walk against signatures shipped as data
  (`signatures/suspected.json`), run **on demand** (`agents.scan`) — no
  polling loop (spec 6.3), and continuous detection with alerts is M10 by
  spec sectioning. The unknown-agent fixture gets a real, verifiably
  innocuous process to find: `foo-agent-fixture.sh` installed as
  `~punar/Downloads/foo-agent`, which prints what it is and blocks on a
  signal. Detection was exercised end to end **on the host** (real
  staged adapters + signatures, `UNKNOWN · SUSPECTED`,
  `signature_id: downloads-foo-agent`); in the VM: **no CI run**.
- [x] Local UI (spec 25, Plate D-005) — `SUPER + A` opens the AI panel
  (`shell/punar-shell/AiPanel/AiPanel.qml`), reading
  `/run/punar/agents.json` through the M6-era `Services/` FileView
  pattern (`Agents.qml` — event-driven, no polling). Unmanaged-first per
  DESIGN_LANGUAGE §8: authority cites `personal-defaults` on an
  unenrolled device and the org policy id only when enrolled; every
  authority row is labeled `declared · M9`/`declared · M12` (display
  only in M7 — enforcement is M9/M12); the **ledger section renders as a
  dashed, labeled Milestone-8 placeholder**, and `punarctl agents access`
  is an explicit M8 stub. Terminal equivalent in D-014 grammar:
  `punarctl agents list | inspect <id> | scan`. The one chord
  reassignment — the assistant scratchpad moves `SUPER+A` →
  `SUPER+SHIFT+A` — is recorded in
  [`docs/development/keyboard-grammar.md`](docs/development/keyboard-grammar.md).
  `qmllint` clean and `Hyprland --verify-config` "config ok" (with a
  non-vacuous negative control); the panel rendering with a managed row
  and an unknown row on one screen: **no CI run**.
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
  shellchecks the three new scripts, uploads the M7 artifacts, and raises
  `desktop-test` to 95 min. Shellcheck v0.11.0 + actionlint clean;
  **never executed anywhere** — the exercise only runs in-VM and no VM
  run contains it.

Budgets, honestly (the M7-specific hard lesson): `punar-agentd` is a
**second resident service**, so the services-RSS gate now sums the
`punard.service` *and* `punar-agentd.service` cgroups into the **same
single** `PUNAR_SERVICES_RSS_MB` number, with the thresholds unmoved
(target 100 MB, MVP ceiling 150 MB — spec 6.2 budgets the services
total, not each daemon), and a unit whose cgroup is missing or empty
makes the whole value `absent`, which `check-budgets.sh` fails even
under TCG — one live daemon must never mask a dead sibling
(`PERFORMANCE_BUDGETS.md` §2.3, `idle-ram.sh`). The combined number has
**never been measured**: the last measurement, 2 MB in run 32857914904,
is punard alone.

Static validation for the tree — local and non-authoritative per spec
1.22, re-run by this audit on 2026-08-25 against the working tree:
`cargo test --workspace --locked` green in the pinned `rust:1` container
(**458 assertions passed, 0 failed**, of which `punar-agentd` contributes
36 and the M7 additions to `punar-common`/`punar-env`/`punarctl` the
rest); `./tools/validate-schemas.sh` — 15 schemas metaschema-checked,
125 documents validated, ALL PASS (including both staged adapter
definitions, validated in place); `shellcheck v0.11.0` clean on
`m7-check.sh`, `punar-mock-agent`, `foo-agent-fixture.sh`, `idle-ram.sh`,
`boot-test.sh` and `check-budgets.sh`; `actionlint` clean on `ci.yml`.
Recorded in milestone-7.md §14 and not re-run by this audit:
`cargo fmt`/`clippy` clean, `PUNAR_BUILD_MODE=summary
./tools/build-image.sh`, `qmllint` on all nine `.qml` files,
`Hyprland --verify-config`, `systemd-analyze verify` +
`systemd-tmpfiles --dry-run`, and the host-side detection run.

What remains: **nothing M7 is proven at runtime.** Every in-VM claim
(all twelve m7-check groups, the managed mock session and its scope
cgroup, the registry transitions, the detection pass, the panel
screenshot, the audit lines, the combined services-RSS number, the
95-min job budget) awaits commit, push, and the first CI run containing
the tree. Out of scope by spec sectioning, and tracked in milestone-7.md
§13: the **AI Access Ledger** (spec 21) is M8 — M7 ships the registry
only; authority **enforcement** is M9/M12; continuous shadow-AI
detection with local alerts and remote queries is M10.

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
| M7 — AI Agent Registry | Managed sessions, Claude adapter, second/generic adapter, agent identity, classification, local UI | Not specified in spec §76 | **Implemented on disk (current); uncommitted; no CI run** — `punar-agentd` (sibling socket, `agents.*`, schema-exact `registry.jsonl`), the real `punar-env agent` managed launch into a `punar-agent-<id>.scope`, two adapters shipped as data (claude-code + generic-shell), peer-cred/cgroup-checked identity, on-demand `managed`/`observed`/`unknown` classification, the `SUPER+A` AI panel (Plate D-005, dashed M8 ledger placeholder) and `punarctl agents`, plus m7-check + CI wiring; local static validation green (milestone-7.md §14); every runtime claim awaits the first CI run containing the tree |
| M8 — AI Access Ledger | Resource summaries, process attribution, security events, local retention, privacy controls | Not specified in spec §76 | Not started |
| M9 — Approval gates + secret broker | Local graphical approval, short-lived mock credentials, redaction tests | Not specified in spec §76 | Not started |
| M10 — Shadow AI detection MVP | Known/observed/unknown classification, fixture unknown agent, local alert, Smplify remote query | Not specified in spec §76 | Not started — M7 landed the §19.1 classification vocabulary, the unknown-agent fixture and an **on-demand** scan; M10 owns continuous detection, the local alert, and the Smplify remote query |
| M11 — Browser/web-app integration | Current Chromium, native launcher integration, project/browser context prototype, web-app install flow | Not specified in spec §76 | Not started |
| M12 — Network privacy prototype | Local network observability, project-route policy, relay abstraction, simulated or prototype private relay | Not specified in spec §76 | Not started |
| M13 — Demo polish | First boot, enrollment, keyboard UX, AI panel, privacy panel, deterministic demo | Not specified in spec §76 | Not started |
