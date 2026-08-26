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

Recorded because the target is a product claim. Budget: **fail > 1536 MB,
warn > 1024 MB** (`check-budgets.sh`), whole-system `MemTotal - MemAvailable`,
KVM, 10 min stabilize + 5 min window.

**Correction to an earlier version of this section**, which said the number had
"drifted above" the target. It has not drifted above it — it has never been
below it. The earliest measurement on record, M1 with a bar and a command
centre and nothing else, is 1162 MB against a 1024 MB target. The 1024 figure
has warned on every run this project has ever made, and describing the current
number as a regression against it was wrong. What *is* a regression is the
90 MB the thirteen surfaces added on top.

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

## Who actually holds it (run 32959913805, per-process PSS at stabilized idle)

| Process | PSS | |
|---|---:|---|
| `qs` — punar-shell | **328.1 MB** | every surface, in one process |
| `Hyprland` | 163.2 MB | compositor, including llvmpipe software rendering |
| `Xwayland` | **42.6 MB** | X11 compatibility — see below |
| `hyprpolkitagent` | 14.9 MB | polkit prompts |
| `foot` | 10.5 MB | the terminal the exercise opened |
| **sum of all processes** | **671 MB** | |
| whole-system used | 1274 MB | |

**Over half of the headline number is not process memory at all.** Per-process
PSS sums to 671 MB against a reported 1274 MB; the remaining ~600 MB is kernel
allocations, tmpfs and page cache that `MemAvailable` declines to count as
available. Any plan to reach 1024 MB by trimming processes is working against
53% of the figure, and that is worth knowing before anyone promises the target.

**Two levers, now measured rather than guessed:**

1. **The shell, 328 MB.** This confirms the lazy-load plan is aimed at the
   right process — it was a hypothesis until this run. Five surfaces are
   genuinely on-demand (command centre, System Control, shortcuts, overview,
   AI panel) and could sit behind inactive `Loader`s. The other eight cannot:
   the bar and wallpaper are always visible; approval and alerts must appear
   *unbidden*; notifications, toasts and the OSD must receive events while
   closed; and putting the lock screen behind a loader would add latency to
   the one surface that must never hesitate.

2. **Xwayland, 42.6 MB, with plausibly zero clients.** Chromium now runs native
   Wayland (`--ozone-platform-hint=auto` in `/etc/chromium-flags.conf`), foot is
   Wayland, and nothing else shipped is an X11 client. Hyprland starts XWayland
   eagerly when `xwayland:enabled` is true.

   **Deliberately not switched off.** It is a one-line config change for a
   measured 3.3% of the total, and the cost is that no X11 application can ever
   run — which contradicts shipping a rich third-party app catalogue, where
   X11-only applications are still common. That is a product decision about
   what Punar supports, not a memory optimisation, and it is recorded here with
   its price rather than taken quietly.

## Interaction latency — measured from 2026-08-26

Idle RAM and boot time were the only performance figures this project had, and
neither is what a person feels minute to minute. **Opening a surface is.** That
number did not exist: the surfaces exercise reported "painted pixels after 1s"
and the 1 was its poll granularity, not a measurement.

The first instrument reported 112–240 ms, but those numbers are not suitable
for a lazy-load decision. It repeatedly spawned `qs ipc call` and `hyprctl -j
layers` while the clock was running, so the checker competed with the surface
and the amount of added work varied by sample.

One premise in the follow-up diagnosis was also wrong: **a physical keypress
does spawn `qs`**. Every relevant Hyprland bind is an `exec` of the same `qs
ipc call <surface> toggle` command the checker uses. The process in that path
is product cost; the repeated polling processes are instrument cost. They must
not be confused.

The replacement re-enters the configured command through Hyprland and writes
three spans to `surfaces-latency.txt`:

| Column | What it is |
|---|---|
| `dispatch_ms` | checker starts `hyprctl dispatch exec` → the surface's `show()` begins |
| `shell_map_ms` | `show()` begins → Quickshell receives Hyprland's `openlayer` event |
| `total_ms` | the two spans above added together |

`shell_map_ms` is the decision-quality number: both endpoints are `Date.now()`
timestamps in the already-running shell. `SurfaceTiming.qml` listens to the
Hyprland socket2 stream Quickshell already consumes, so **no poll, client or
process runs inside that interval**. Its clock quantisation uncertainty is
less than 2 ms (two timestamps with 1 ms resolution).

`dispatch_ms` and `total_ms` intentionally retain one checker-only cost: the
`hyprctl` client used to re-enter Hyprland. The report calibrates it at runtime
with five `hyprctl dispatch exec true` probes and records the largest observed
round trip. A physical chord omits that client, then follows the same Hyprland
`exec` → `qs` → shell path. The report names the boundary instead of subtracting
a noisy estimate.

**No threshold is gated yet, on purpose.** There is no basis for one until the
first numbers exist, and picking a limit before measuring is exactly how idle
RAM ended up with a 1024 MB target that has never once been met.

### The lazy-load plan: withdrawn, then reinstated — and why the withdrawal was wrong

This section previously **withdrew** the `Loader`-per-surface change on the
grounds that 1274 MB is unfelt on a machine idling with 6.7 GB free, so moving
construction cost onto the first keypress traded felt latency for unfelt memory.

**That reasoning optimised for the wrong machine.** It reasoned about the
developer's laptop rather than the product's targets: a Raspberry Pi appliance
where 1274 MB is a majority of RAM, and where every megabyte the shell holds is
a megabyte not holding model weights. The product owner's standing rule is now
explicit — *always optimise for using the least RAM possible* — and the earlier
call is retracted.

**But it is not retracted by simply obeying the newer instruction.** Speed is
also table stakes, and a reversal that makes the desktop feel worse would be
trading one stated requirement for another. The two are only in conflict if
first-open cost is perceptible, and **nobody has measured it**. So the order is:

1. **Measure the construction cost per surface.** `surfaces-check.sh` now times
   `dispatch_ms` and `shell_map_ms` (see above), but every surface is currently
   eager, so
   those numbers are *dispatch* latency, not *construction* latency. The
   measurement that decides this is what a surface costs to build the first
   time — and what it holds resident once built.
2. **Lazy-load every surface whose construction is imperceptible.** If building
   the AI panel on first `SUPER + A` costs 40 ms, there is no trade at all:
   the RAM is recovered and nothing is felt. Both rules are satisfied.
3. **Keep eager only what measurement proves expensive**, and say so in the
   commit with the number. "This surface stays resident because building it
   costs 380 ms" is a defensible sentence; "surfaces are eager for speed" is
   not, because it was never measured.

Where the two rules genuinely collide on a given surface, **RAM wins on
constrained device classes and speed wins on capable ones** — which is exactly
what [`docs/design/device-classes.md`](../../docs/design/device-classes.md)
exists to express, and is a better answer than one global setting.

**The dispatch instrument is implemented; construction and resident-cost
measurement are not.** Do not lazy-load from the historical 112–240 ms figures.
The next CI artifact establishes the corrected eager baseline; then the
measurement in step 1 is the next piece of work.
