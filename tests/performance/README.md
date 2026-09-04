# Performance gate — stabilized idle

This directory holds the CI enforcement harness that
[`PERFORMANCE_BUDGETS.md`](../../PERFORMANCE_BUDGETS.md) §5 designed. The
desktop gate measures whole-system RAM, combined service PSS, each Punar
service's cgroup CPU and writes, whole-guest CPU/block writes for context,
and live zram state over one shared stabilized-idle window. Exact start/end
`meminfo` plus per-process PSS/locked/anonymous/file/shared attribution make
kernel/driver and process movement diagnosable without changing the metric or
threshold. RAM and service PSS, CPU, first-party writes, connected-idle state
and zram are runtime-proven and gated. Boot-regression gating, the cgroup-memory
cross-check, JSON history and bare-metal baselines remain open.

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
                             ├─ serial: RAM + service PSS         (gate 2)
                             ├─ export: CPU/write/zram facts      (gate 3)
                             │
                             └─ export channel: base64 tar of /run/punar
                                between PUNAR_EXPORT_BEGIN/END sentinels
                                (screenshot.png, meminfo, ram-samples.txt)
                             ▼
                          host files in os/images/out/desktop-proof/
                             ▼
                          tests/performance/check-budgets.sh  (gate 4)
```

1. **Gate 1 — graphical session up.** `boot-test.sh --mode desktop` fails
   unless `PUNAR_DESKTOP_OK` appears on the serial console (compositor
   running, punar-shell constructed, grim capture attempted — the
   `punar-desktop-marker` chain baked into the image).
2. **Gate 2 — idle RAM measured.** The M1 acceptance criterion. The
   in-guest `punar-idle-ram.service` performs the canonical measurement and
   prints mean/max to the serial console; `boot-test.sh` records them into
   `ram-report.txt`. No RAM line, no pass.
3. **Gate 3 — runtime evidence complete.** Every Punar service cgroup must
   expose CPU and I/O counters; zram facts must reach the host report. Missing
   evidence is a failure on both native and emulated runs.
4. **Gate 4 — budget verdict.** `check-budgets.sh` reads `ram-report.txt`
   and applies the RAM, service-PSS, per-service CPU and combined first-party
   write ceilings. Whole-guest writes are retained as context and are not
   attributed to Punar.

The artifact **export** (screenshot + raw samples and runtime facts) is
collected on a dedicated virtio-serial channel. A missing screenshot remains
non-fatal because it is visual evidence, not the budget input. A broken export
is allowed to continue long enough to preserve serial diagnostics, but the
later runtime/zram phase fails closed when `runtime-report.txt` is absent.
RAM still has its independent serial marker.

## What is measured

All counters are read **inside the guest** by `punar-idle-ram.service`, over
the canonical window fixed in
[`PERFORMANCE_BUDGETS.md`](../../PERFORMANCE_BUDGETS.md) §2.1–2.5:

- metric: `MemTotal - MemAvailable` from `/proc/meminfo`;
- stabilization: **10 minutes** after the graphical session is up, no input;
- window: **5 minutes**, sampled every **10 s** (30 samples); report mean
  and max;
- per service: `cpu.stat usage_usec` and `io.stat wbytes` deltas from the
  `punard`, `punar-agentd`, `punar-secrets`, and `punar-netd` systemd cgroups;
- periodic work: the persistent, low-priority `punar-background.slice`
  accumulates timer-triggered reconcile and agent-discovery work even though
  their individual oneshot cgroups disappear between samples;
- whole guest, context only: `/proc/stat` busy ratio and physical block-device
  sectors-written delta;
- memory pressure: `/sys/block/zram0` existence, size, active algorithm and
  `/proc/swaps` membership are observed on the live boot, not inferred from
  configuration;
- VM shape: 8 GB RAM / 4 vCPU (the spec 5.1 minimum-target machine,
  budgets §5.1).

The host side only waits for the guest's result line and lands the files —
it never shortens or re-implements the stabilization (guest env overrides
for shorter local runs exist but are labeled **non-canonical**, as are the
`PUNAR_RAM_HARD_MB`/`PUNAR_RAM_TARGET_MB` overrides in `check-budgets.sh`).

The desktop VM uses QEMU's private user-mode network with a virtio NIC. At the
ten-minute boundary the guest emits `PUNAR_NETWORK_ONLINE=yes` only when a
non-loopback link is up and DHCP has installed a default route. Missing or
offline evidence fails the performance gate on every accelerator. The minimal
boot-only smoke test remains intentionally offline.

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
| combined first-party service PSS > ceiling | 150 MB | `::error::`, job **fails** |
| combined first-party service PSS > target | 100 MB | `::warning::`, job passes |
| any first-party cgroup idle CPU ≥ ceiling | 0.50% of one CPU | `::error::`, job **fails** |
| combined first-party writes > ceiling | 98,304 B / 5 min | `::error::`, job **fails** |
| any required runtime fact missing | — | `::error::`, job **fails**, including under TCG |
| whole-guest writes | informational | recorded and uploaded for diagnosis, not attributed to Punar |

**TCG caveat:** when the runner has no usable `/dev/kvm`, boot-test degrades
to TCG software emulation. Numeric performance results from such runs are labeled
`(VM, emulated)` in `ram-report.txt` (`PUNAR_RAM_ACCEL=tcg`) and are
**indicative only — they never fail the build** (budgets §5.2); a ceiling
breach is downgraded to a warning. Missing daemons or facts still fail. Note
the desktop test under TCG is also
very slow (the 16-minute measurement is wall-clock on top of an emulated
boot) and may exceed the CI job timeout — that surfaces the broken-KVM
environment problem rather than hiding it.

Native ARM64 under Apple Hypervisor Framework (`PUNAR_RAM_ACCEL=hvf`) is a
gating run, just like same-architecture KVM. HVF is hardware virtualization,
not the cross-architecture TCG path this caveat describes.

## Files produced (`os/images/out/desktop-proof/`)

| File | Content |
|---|---|
| `punar-desktop-screenshot.png` | grim capture from inside the session — proof of real (llvmpipe) rendering. Uploaded as the `punar-desktop-screenshot` CI artifact. |
| `ram-report.txt` | Typed host budget input: RAM, service PSS, idle CPU/write facts, zram facts, environment, image, timestamp and the informational desktop proxy. |
| `ram-samples.txt` | raw per-sample `epoch used-MB` lines from the guest window. |
| `runtime-report.txt` | Raw guest-emitted per-service/whole-guest CPU and write counters plus live zram facts. |
| `ram-processes.txt` | Per-process PSS ranking at stabilized idle. |
| `ram-process-memory.txt` | Window-end per-process PSS, locked, anonymous, file and shared-memory attribution plus whole-process totals and the non-process accounting remainder. The remainder is diagnostic, not a budget metric. |
| `ram-meminfo-start.txt`, `ram-meminfo-end.txt` | Exact `/proc/meminfo` snapshots bracketing the stabilized five-minute window. |
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

On the maintainer's macOS arm64 host there is no x86 KVM: local **x86** runs
are TCG, slow, warn-only, labeled `(VM, emulated)`, and never a source of
published baselines. Native arm64 images run through Apple HVF and are
release-gating evidence, like same-architecture KVM.

## Not yet implemented (still as designed in PERFORMANCE_BUDGETS.md §5)

- Cgroup `memory.current` cross-check and per-unit PSS table. The combined
  service PSS gate is already real; this is attribution depth, not a missing
  headline number.
- Boot-time regression gating (§2.6), the single-JSON results file, tracked
  history (§5.1 item 7), and physical-device baselines.

## Measured idle RAM over time, and what moved it

Recorded because the target is a product claim. Budget: **fail > 1536 MB,
warn > 1024 MB** (`check-budgets.sh`), whole-system `MemTotal - MemAvailable`,
KVM, 10 min stabilize + 5 min window.

**Correction to an earlier version of this section**, which said the number had
"drifted above" the target. Before 2026-08-31 it had never been below it: the
earliest measurement on record, M1 with a bar and a command centre and nothing
else, was 1162 MB against a 1024 MB target. The first result below that target
is the native ARM64 row added below; describing the preceding history as a
regression against a previously-met target would still be wrong.

| Run | Mean | Boot | What changed |
|---|---|---|---|
| [32804034681](https://github.com/smplify-mdm/punar/actions/runs/32804034681) | 1162 MB | 18 s | M1 baseline — bar + command centre only |
| [32868450695](https://github.com/smplify-mdm/punar/actions/runs/32868450695) | 1175 MB | — | M7 added a second daemon (+13 MB) |
| [32941763915](https://github.com/smplify-mdm/punar/actions/runs/32941763915) | 1265 MB | 22 s | **the thirteen shell surfaces** |
| [32945695360](https://github.com/smplify-mdm/punar/actions/runs/32945695360) | 1277 MB | 20 s | networkd + resolved + xdg-utils |
| [33024091202](https://github.com/smplify-mdm/punar/actions/runs/33024091202) | 1302 MB | 20 s | corrected surface-latency proof; shell PSS remained ~329 MiB |
| [33078009194](https://github.com/smplify-mdm/punar/actions/runs/33078009194) | 1322 MB | 20 s | x86 KVM after all measured surface loaders; 7 MB first-party PSS |
| [33381573989](https://github.com/smplify-mdm/punar/actions/runs/33381573989) | **1116 MB** | 20 s | x86 KVM with the unaccelerated-renderer policy; 10 MB four-service PSS; full gate green |
| local native ARM64, `c2d39a…c1e1` | 1205 / 1210 MB | 18 s | two connected Apple-HVF windows; 18 MB first-party PSS |
| local native ARM64, `cf522b…d19133` | **1004 MB** | 16 s | Qt raster adaptation + two-worker llvmpipe cap on unaccelerated adapters; 24 MB four-service PSS; all runtime suites green |
| local native ARM64, `a21e03a…c960ff` | **933 MB** | 19 s | bounded architecture-aware initrd; full installed firmware/modules retained; 25 MB four-service PSS; all runtime suites green |

**Attribution, measured rather than guessed.** The two runs above bracket the
networking change exactly: everything else identical, `1265 → 1277`. Wired
DHCP, systemd-resolved and xdg-utils together cost **12 MB**, and boot got
*faster* (22 s → 20 s) because `systemd-networkd-wait-online` is deliberately
not enabled.

The historical regression was the row above it: **the thirteen eager surfaces
cost ~90 MB** (1175 → 1265). The measured response is now shipped: command
centre, System Control, shortcuts, overview, AI panel, and the notification
window construct on demand and unload after their close animation. Their small
IPC handlers stay resident so `state()` can answer `"closed"` without loading
the visual tree. Always-visible and unbidden security surfaces remain eager.

The current four daemons sum to **24 MB** PSS on native ARM64, comfortably
below the 100 MB target. The Rust side is not the RAM problem.

**The clean-VM target is now met without weakening the hardware path.** The
Apple-HVF candidate moved from 1210/1213 MB to 1004/1005 MB after the
unaccelerated virtio path selected Qt Quick's built-in software adaptation and
bounded Mesa's llvmpipe pool. AMD, Intel, Raspberry Pi VC4 and other real DRM
drivers explicitly clear both variables and retain their normal hardware
renderer. The reduction therefore closes the clean-VM budget item; it does
not substitute for a physical-device baseline.

## Who actually holds it (run 33024091202, per-process PSS at stabilized idle)

| Process | PSS | |
|---|---:|---|
| `qs` — punar-shell | **329.2 MiB** | every surface, in one process |
| `Hyprland` | 162.8 MiB | compositor, including llvmpipe software rendering |
| `Xwayland` | **42.5 MiB** | X11 compatibility — see below |
| `hyprpolkitagent` | 15.0 MiB | polkit prompts |
| `foot` | 10.4 MiB | the terminal the exercise opened |
| **sum of all processes** | **672.8 MiB** | |
| whole-system used | 1302 MB | |

**Nearly half of the headline number is not process memory at all.** Per-process
PSS sums to 672.8 MiB against 1302 MB whole-system used; the remaining ~629 MB
is kernel allocations, tmpfs and page cache that `MemAvailable` declines to
count as available. Process trimming remains necessary, but cannot explain the
whole gap to 1024 MB.

**Two levers, now measured rather than guessed:**

1. **The shell, 328 MB in the historical eager sample.** This confirmed the
   loader work was aimed at the right process. Five user-invoked surfaces and
   the notification visual now sit behind inactive `Loader`s. The bar and
   wallpaper remain visible; approval and alerts must appear *unbidden*;
   toasts and the OSD must receive events while closed; and the lock screen
   must never pay first-use construction latency.

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

The corrected historical eager baseline is
[run 33024091202](https://github.com/smplify-mdm/punar/actions/runs/33024091202):

| Surface | `dispatch_ms` | `shell_map_ms` | `total_ms` |
|---|---:|---:|---:|
| Overview | 39 | **67** | 106 |
| Notifications | 40 | **69** | 109 |
| AI panel | 41 | **73** | 114 |
| Command centre | 40 | **87** | 127 |
| System Control | 41 | **116** | 157 |
| Shortcuts | 40 | **186** | 226 |

The largest of five checker-only `hyprctl` probes was 12 ms. All six surfaces
also opened, mapped, changed the screen relative to the closed-desktop frame,
closed and unmapped; the exercise ended `PUNAR_SURFACES_OK` with 64 assertions.
`shortcuts` is the first construction-cost suspect, but this eager sample does
not identify its cause.

**No interaction-latency regression threshold is gated yet.** The cost harness
now repeats construction and first-map samples and the resulting 31–59 ms
construction medians justified lazy-loading all measured user-invoked
surfaces. A release threshold still needs a stable multi-run distribution.

### Why the measured lazy-load plan shipped

This section previously **withdrew** the `Loader`-per-surface change on the
grounds that 1274 MB is unfelt on a machine idling with 6.7 GB free, so moving
construction cost onto the first keypress traded felt latency for unfelt memory.

**That reasoning optimised for the wrong machine.** It reasoned about the
developer's laptop rather than the product's targets: a Raspberry Pi appliance
where 1274 MB is a majority of RAM, and where every megabyte the shell holds is
a megabyte not holding model weights. The product owner's standing rule is now
explicit — *always optimise for using the least RAM possible* — and the earlier
call is retracted.

Speed is also table stakes, so the project measured construction time and
resident cost before changing residency. Surfaces with imperceptible measured
construction moved behind loaders; always-visible, event-receiving, and
security-critical surfaces stayed eager for explicit functional reasons.

Where the two rules genuinely collide on a given surface, **RAM wins on
constrained device classes and speed wins on capable ones** — which is exactly
what [`docs/design/device-classes.md`](../../docs/design/device-classes.md)
exists to express, and is a better answer than one global setting.

The construction/resident-cost harness is now implemented and the lazy set is
runtime-proven. Median construction costs were 31–59 ms for command centre,
System Control, shortcuts, AI panel and overview; notifications constructed in
43 ms. These numbers justified the current loader policy. Keep measuring them
when a surface grows, and do not expand the lazy set without the same evidence.
