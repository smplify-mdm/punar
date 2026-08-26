# Performance gate — idle-RAM (Milestone 1)

This directory holds the CI enforcement harness that
[`PERFORMANCE_BUDGETS.md`](../../PERFORMANCE_BUDGETS.md) §5 designed. As of
2026-08-24 the **idle-RAM portion of that design is implemented** (this
README, `check-budgets.sh`, the desktop mode of `tools/boot-test.sh`, and
the `desktop-test` CI job); everything else in §5 (per-service PSS/cgroup
tables, CPU, disk-I/O, boot regression gating, tracked history) **remains
planned** — see "Not yet implemented" below.

Honesty (spec 1.22): until the first green `desktop-test` CI run, the
harness itself is config-validated but **runtime-unverified**; the budgets
doc's §4 baseline table stays "not yet measured" until CI produces real
numbers.

## How the gate works

```
image job                 desktop-test job (CI) / local equivalent
─────────                 ────────────────────────────────────────
build punar-desktop  ──►  tools/boot-test.sh --mode desktop <qcow2>
qcow2 (mkosi)                │  QEMU: -m 8192 -smp 4 -device virtio-vga,
                             │  OVMF, -display none, serial → log, plus a
                             │  virtio-serial channel "punar.export"
                             │  captured to a host file
                             ▼
                          guest boots: greetd → Hyprland (llvmpipe) →
                          punar-shell → desktop-ready.sh
                             │
                             ├─ serial: "PUNAR_DESKTOP_OK"      (gate 1)
                             │
                          punar-idle-ram.service (in guest, canonical
                          method — see "What is measured")
                             │
                             ├─ serial: "PUNAR_RAM_MEAN_MB=<n>
                             │           PUNAR_RAM_MAX_MB=<n>"  (gate 2)
                             │
                             └─ export channel: base64 tar of /run/punar
                                between PUNAR_EXPORT_BEGIN/END sentinels
                                (screenshot.png, meminfo, ram-samples.txt)
                             ▼
                          host files in os/images/out/desktop-proof/
                             ▼
                          tests/performance/check-budgets.sh  (gate 3)
```

1. **Gate 1 — graphical session up.** `boot-test.sh --mode desktop` fails
   unless `PUNAR_DESKTOP_OK` appears on the serial console (compositor
   running, punar-shell constructed, grim capture attempted — the
   `punar-desktop-marker` chain baked into the image).
2. **Gate 2 — idle RAM measured.** The M1 acceptance criterion. The
   in-guest `punar-idle-ram.service` performs the canonical measurement and
   prints mean/max to the serial console; `boot-test.sh` records them into
   `ram-report.txt`. No RAM line, no pass.
3. **Gate 3 — budget verdict.** `check-budgets.sh` reads `ram-report.txt`
   and compares against the budgets (next section).

The artifact **export** (screenshot + raw samples) is collected on a
dedicated virtio-serial channel and is deliberately **non-fatal**: a missing
screenshot or corrupt export produces a `::warning::`, not a failure — the
RAM gate rests on the serial numbers, and the guest likewise continues when
grim fails (its absence is itself a diagnostic signal).

## What is measured

Whole-system idle RAM, by the canonical method fixed in
[`PERFORMANCE_BUDGETS.md`](../../PERFORMANCE_BUDGETS.md) §2.1–2.2 — the
sampling runs **inside the guest** (`punar-idle-ram.service`), not on the
host:

- metric: `MemTotal - MemAvailable` from `/proc/meminfo`;
- stabilization: **10 minutes** after the graphical session is up, no input;
- window: **5 minutes**, sampled every **10 s** (30 samples); report mean
  and max;
- VM shape: 8 GB RAM / 4 vCPU (the spec 5.1 minimum-target machine,
  budgets §5.1).

The host side only waits for the guest's result line and lands the files —
it never shortens or re-implements the stabilization (guest env overrides
for shorter local runs exist but are labeled **non-canonical**, as are the
`PUNAR_RAM_HARD_MB`/`PUNAR_RAM_TARGET_MB` overrides in `check-budgets.sh`).

Known deviation from budgets §2.1 item 5: the VM runs with `-nic none`
(matching the minimal boot test), so idle is currently measured **without**
networking up. Recorded here until guest networking lands; the deviation
makes the measured number, if anything, slightly optimistic.

M2 interplay (milestone-2.md §7): the in-guest M2 multitasking exercise
(`punar-m2-check.service`, started by `idle-ram.sh`) runs **strictly after**
the 5-minute sampling window closes and before the artifact export — it
opens windows and the overview, so ordering it after sampling is what keeps
the canonical idle measurement unpolluted. The RAM numbers and this gate
are therefore unchanged by M2; the M2 verdict is a separate gate applied by
`tools/boot-test.sh` (phase 4) on the exported `m2-report.txt`.

## Budgets applied (`check-budgets.sh`)

Values mirror `PERFORMANCE_BUDGETS.md` §1.1 (which mirrors spec §6) and must
not drift from it:

| Check | Threshold | Result |
|---|---|---|
| mean > hard ceiling | 1536 MB (1.5 GB) | `::error::`, job **fails** (release blocker) |
| mean > target | 1024 MB (1.0 GB) | `::warning::`, job passes |
| max > hard ceiling | 1536 MB | `::warning::` (informational; the gate is on the **mean** — survey decision, milestone-1.md §8 — until a baseline is recorded in budgets §4) |

**TCG caveat:** when the runner has no usable `/dev/kvm`, boot-test degrades
to TCG software emulation. RAM numbers from such runs are labeled
`(VM, emulated)` in `ram-report.txt` (`PUNAR_RAM_ACCEL=tcg`) and are
**indicative only — they never fail the build** (budgets §5.2); a ceiling
breach is downgraded to a warning. Note the desktop test under TCG is also
very slow (the 16-minute measurement is wall-clock on top of an emulated
boot) and may exceed the CI job timeout — that surfaces the broken-KVM
environment problem rather than hiding it.

## Files produced (`os/images/out/desktop-proof/`)

| File | Content |
|---|---|
| `punar-desktop-screenshot.png` | grim capture from inside the session — proof of real (llvmpipe) rendering. Uploaded as the `punar-desktop-screenshot` CI artifact. |
| `ram-report.txt` | key=value: `PUNAR_RAM_MEAN_MB`, `PUNAR_RAM_MAX_MB`, `PUNAR_RAM_ACCEL`, `PUNAR_RAM_ENV_LABEL`, image, timestamp, and `PUNAR_DESKTOP_OK_HOST_SECS` (informational boot-to-desktop proxy, budgets §2.6). Input to `check-budgets.sh`. |
| `ram-samples.txt` | raw per-sample `epoch used-MB` lines from the guest window. |
| `meminfo` | `/proc/meminfo` snapshot taken at desktop-ready. |
| `serial.log` | full serial console log — preserved on failure too. |

## Running locally

```sh
tools/build-image.sh desktop                       # or: all
tools/boot-test.sh --mode desktop \
    os/images/out/punar-desktop-x86_64.qcow2       # mode auto-detected from
                                                   # the filename anyway
tests/performance/check-budgets.sh                 # reads desktop-proof/ram-report.txt
```

On the maintainer's macOS arm64 host there is no x86 KVM: local runs are
TCG, slow, warn-only, labeled `(VM, emulated)`, and never a source of
published baselines. CI (x86_64, KVM) is canonical.

## Not yet implemented (still as designed in PERFORMANCE_BUDGETS.md §5)

- **Per-service RAM table** (budgets §2.3: summed PSS from
  `/proc/<pid>/smaps_rollup` per Punar unit cgroup, cross-checked against
  `systemctl show -p MemoryCurrent`; or a `systemd-cgtop` snapshot). This
  needs an **in-guest** collector — the host reaches the VM only through
  the one-way serial log and the export channel — i.e. an extension of the
  image's `idle-ram.sh` sampler writing a table into `/run/punar` for
  export. The image-side sampler is owned by the image workstream, not this
  directory. Planned; also moot until the Punar first-party services
  (`punard` et al., M3) exist to attribute memory to.
- Idle-CPU and disk-I/O checks (budgets §2.4–2.5), boot-time regression
  gating (§2.6), the single-JSON results file, and the tracked run history
  (§5.1 item 7 — for now, CI artifacts of each run are the history).
- Baseline recording: `PERFORMANCE_BUDGETS.md` §4 must be updated from the
  first stable CI numbers (owned by that file, not this harness).

## Measured idle RAM over time, and what moved it

Recorded because the target is a product claim and the number has drifted
above it. Budget: **fail > 1536 MB, warn > 1024 MB** (`check-budgets.sh`),
whole-system `MemTotal - MemAvailable`, KVM, 10 min stabilize + 5 min window.

| Run | Mean | Boot | What changed |
|---|---|---|---|
| [32804034681](https://github.com/smplify-mdm/punar/actions/runs/32804034681) | 1162 MB | 18 s | M1 baseline — bar + command centre only |
| [32868450695](https://github.com/smplify-mdm/punar/actions/runs/32868450695) | 1175 MB | — | M7 added a second daemon (+13 MB) |
| [32941763915](https://github.com/smplify-mdm/punar/actions/runs/32941763915) | 1265 MB | 22 s | **the thirteen shell surfaces** |
| [32945695360](https://github.com/smplify-mdm/punar/actions/runs/32945695360) | 1277 MB | 20 s | networkd + resolved + xdg-utils |

**Attribution, measured rather than guessed.** The two runs above bracket the
networking change exactly: everything else identical, `1265 → 1277`. Wired
DHCP, systemd-resolved and xdg-utils together cost **12 MB**, and boot got
*faster* (22 s → 20 s) because `systemd-networkd-wait-online` is deliberately
not enabled.

The real regression is the row above it: **the thirteen surfaces cost ~90 MB**
(1175 → 1265). Every surface is a `Scope` instantiated at shell startup
regardless of whether it is ever opened, so a user who never presses
`SUPER + S` still pays for System Control's 1,518 lines of QML and
ControlData's 1,621.

**The obvious diet, not yet taken:** wrap each surface in a `Loader` that stays
inactive until its first `open()`, keeping the `IpcHandler` outside the loader
so `state()` can answer `"closed"` without instantiating anything. That is a
change to all thirteen surfaces and it can break the surfaces exercise in ways
static checks will not catch, so it wants its own pass and its own CI run
rather than being folded into unrelated work. Recorded here so the number has
an owner instead of drifting quietly.

Three daemons still sum to **7 MB** PSS against a 100 MB target — the Rust
side is not the problem and never has been.
