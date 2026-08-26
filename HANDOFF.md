# Handoff — Punar, as of 2026-08-26

Written for whoever picks this up next. It assumes no access to the
conversation that produced the current state. Read §2 before touching
anything: several of those rules are non-obvious and were learned expensively.

---

## 1. Where the project actually is

**Green.** Last CI run [33002447374](https://github.com/smplify-mdm/punar/actions/runs/33002447374)
on `4bfc1e9`: all five jobs, **760 assertions** across ten in-VM exercises.

| Exercise | Assertions |
|---|---:|
| M2 multitasking · M3 daemon+CLI · M4 desired state | 33 · 28 · 29 |
| M5 enrollment · M6 dev environments · M7 agent registry | 63 · 56 · 78 |
| M8 access ledger · M9 approvals+secrets · M10 shadow-AI | 136 · 138 · 135 |
| Desktop surfaces (live, 13 surfaces) | 64 |

Measured: idle RAM **1269–1277 MB**, boot **18–20 s**, three daemons **7 MB**
PSS. Per-process attribution: shell 328 MB, Hyprland 163 MB, Xwayland 43 MB;
all processes sum to 671 MB against 1274 MB reported, so **over half the
headline figure is kernel and page cache, not process memory**.

**Surface open latency, first numbers ever recorded** (KVM, upper bound — the
figure includes spawning a `qs` client, which a keypress does not do):

```
overview 112ms   notifications 113ms   aipanel 124ms
commandcenter 125ms   systemcontrol 175ms   shortcuts 240ms
```

**Four commits are local and unpushed** (device classes, lazy-load retraction,
zram, ADR-005). They are committed, gates pass locally, they simply have not
been pushed. Push them first.

## 2. Standing rules from the product owner — read these first

These are not preferences. Several reverse decisions that looked correct.

1. **Always use the least RAM possible.** This overrode an earlier decision to
   keep surfaces eagerly instantiated. See §4.2.
2. **Speed is table stakes.** It is also in tension with (1); the resolution is
   *measure, then decide per surface*, not pick a side. See §4.2.
3. **Unmanaged-first, and stronger than it sounds.** The OS must be excellent,
   secure and private when *not* enrolled, and **nobody may feel they should
   enroll for it to work**. Drift detection and reconciliation are good OS
   primitives and stay — what was wrong was calling them *compliance*, because
   compliance asserts conformance to an authority a personal device does not
   have. Codified as DESIGN_LANGUAGE §8.1 with a single word table.
4. **Punar is opinionated, and adapts to the device.** It measures the machine
   and decides; it never ships a settings panel of knobs, never silently
   degrades, and **never trades a security or privacy guarantee for weaker
   hardware**. `docs/design/device-classes.md` §2 — the right-hand column of
   that table is non-negotiable.
5. **Never claim a simulated thing is real** (spec §1.22), and **never weaken
   an assertion to get green**. Both have been violated and caught; see §5.
6. Targets: developer laptops (x86_64 today) **and a Raspberry Pi**, where the
   Pi is an **appliance / AI-inference device**, not primarily a dev machine.
7. Nothing is published or announced yet. History rewrites and force pushes
   were explicitly sanctioned on that basis — that will stop being true.

## 3. The single open decision

**ADR-005 (Proposed)** — `docs/architecture/adr/ADR-005-arm64-support.md`.

Punar is x86_64 only. ADR-001 never evaluated arm64 — architecture is absent
from its criteria, appearing only as a consequence of choosing x86_64 CI
runners. Arch has **no reproducible package archive on ARM** (verified three
ways, including mkosi's own `die("There is no known public mirror for
snapshots of Arch Linux ARM")`).

**The cost of changing is far lower than it looks and was measured:** 68,614
lines of Rust reference Arch *zero* times; 19,885 lines of QML mention it once,
in a comment. The substrate is ~218 lines of image pipeline plus package names
and the boot chain. **88,499 lines do not care what the substrate is.**

**A second adversarial review was in flight when this was written and had not
returned.** Its run id is `wf_75c2c924-7ca`; results land in
`.claude/projects/*/subagents/workflows/wf_75c2c924-7ca/journal.jsonl` as
`{"type":"result"}` lines. It exists because the first round lost two of three
reviewers to API errors, and the survivor caught the others making a checkably
false claim. **Do not ratify ADR-005 without it.**

One item in ADR-005 is time-sensitive and irreversible: if a Smplify-owned Arch
ARM mirror is ever wanted, it must begin *now* — no date before mirroring starts
is ever pinnable.

## 4. What to do next, in order

### 4.1 Push the four local commits
Gates all pass locally. Run them anyway (§6), then push.

### 4.2 Fix the latency instrument, then use it
`surfaces-check.sh` measures dispatch latency *including a process spawn*, which
a keypress never incurs. Measure the path a person actually takes. Then:
`shortcuts` at 240 ms is the worst surface under KVM and is real — attack it.

Then settle the RAM/speed tension with data: measure what each surface costs to
**construct** (not dispatch) and to hold **resident**. Lazy-load every surface
whose construction is imperceptible; keep eager only what measurement proves
expensive, **with the number in the commit message**. `tests/performance/README.md`
carries the full reasoning and the retraction that preceded it.

### 4.3 Implement device classes
`docs/design/device-classes.md` is designed and unbuilt. Note the shape: every
existing capability is read-write (`observe()` + `apply()`), but **hardware is
read-only** — a device class is an *observed fact* that joins policy resolution
as a source of defaults, outranked by explicit user preference. It must be
**forceable**, or CI's single VM shape means only one class is ever exercised.

### 4.4 Designed and unbuilt, roughly by value
- **Installer and onboarding** — `docs/design/installer.md`, `onboarding.md`
- **`punarctl app` + Chrome install** — `docs/design/third-party-apps.md`.
  Two planning rounds were **rejected by all reviewers** for proposing to ship
  unverifiable facts (hand-transcribed image digests, a `containment: sandboxed`
  safety label nothing could check). Read those objections before re-planning.
- **Execution trust** (Gatekeeper-class exec gate) — `docs/design/execution-trust.md`
- **Slack / local Kubernetes / VMs** — the developer-workstation ask. `kind` on
  rootless podman is the likely stack; `k3d` needs Docker, which Punar lacks.
  Note `punar-env` hardcodes `--network none` and M6 justified it partly by
  "no rootless-net helper in the image", **which is now false** — `passt` ships
  as a podman dependency.
- **M11 browser/web-apps, M12 network/relay**

## 5. Hard-won lessons — these will bite you

- **`qmllint` exits 0 while printing warnings.** `tools/qmllint.sh` therefore
  fails on any output. A gate that reads its exit code is vacuous — that
  happened here and reported "clean" one line below the defect it had named.
- **Verify config option names against the shipped man page.** An invented
  systemd option (`UseprivacyExtensions`) would have shipped silently ignored,
  with the file claiming a privacy property it did not have.
- **`state()` is not pixels.** Shell surfaces bind windows to
  `root.windowVisible`, a *different* property from the `root.open` that
  `state()` reports. Assert `hyprctl -j layers` for the `WlrLayershell.namespace`,
  in both directions — several overlays hold `WlrKeyboardFocus.Exclusive`, so
  one that reports closed while still mapped is holding the keyboard.
- **A mapped layer is still not pixels.** Panels are `color: "transparent"` and
  animate in over 300 ms; capture only after the frame differs from a
  per-surface before-shot.
- **In-VM check scripts must be committed `0755`.** A `100644` check once
  failed `ExecStart`, produced no report, and the gate passed it as a warning.
- **Never `git add -A`.** It swept 27,945 build artifacts (~9 GB) into history;
  removing them needed a filter-repo and a force push.
- **CI runs the VM with `-nic none`.** Anything needing network cannot be gated.
  M6 is the precedent for working around it: preload an OCI archive, `podman load`.
- **The runner has a 14 GB disk and boot-test uses `-snapshot`**, so every guest
  write lands in a host temp file. A ~1 GB kind node image likely will not fit.
- **Prefer relations over constants in assertions.** Several M10 assertions were
  wrong about the product, not the reverse: one called a real security boundary
  a defect (a user may not purge another principal's records), another assumed
  killing a process retires the evidence it ran.

## 6. How to run things

```bash
./tools/qmllint.sh                    # pinned Qt/Quickshell; fails on ANY output
./tools/validate-schemas.sh           # 15 schemas, 132 documents
./tools/punar-up.sh                   # fetch newest CI image + boot it + open viewer
./tools/demo-vm.sh <image.qcow2>      # boot a specific image
```

Rust gates run in a container (the maintainer host is macOS arm64):
`cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test --workspace`.

**On the demo VM:** it is TCG-emulated x86_64 on Apple Silicon and is **~5×
slower than KVM** — measured, 597 ms for an IPC round trip against 112–125 ms
in CI. It feels sluggish and that is mostly the emulator, not the OS. This is
also the most tangible argument for ADR-005.

## 7. Where the truth lives

- `IMPLEMENTATION_STATUS.md` — milestone-by-milestone, with run links
- `docs/development/desktop-surfaces.md` — every surface, its chord, what is
  real vs honestly unavailable
- `docs/development/testing-the-vm.md` — the ten-minute tour
- `docs/development/user-blocked.md` — the nine things needing the owner
  (signing keys, TPM hardware, real control plane, IdP tenants, relay infra,
  legal, security review)
- `tests/performance/README.md` — every measured number and the reasoning
- `docs/design/DESIGN_LANGUAGE.md` — binding; §8 unmanaged-first, §8.1 the word
  table, §8.2 device adaptation
