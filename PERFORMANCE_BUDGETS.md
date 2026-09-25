# Performance Budgets

Status: **RAM, combined service PSS, idle CPU, first-party writes and live
zram are measured and enforced.** The same DHCP-connected 8 GiB / 4-vCPU
stabilized-idle window covers all of those facts. A native Apple-HVF ARM64
window now meets the whole-system 1 GiB target; repeated native ARM64 windows
established the CPU/write baseline and a native KVM result set the
cross-filesystem first-party write ceiling.
A cgroup-memory cross-check, boot-regression gate, physical-device baselines
and tracked JSON history remain open.

Authoritative source: [`docs/product/SPEC_v0.2.md`](docs/product/SPEC_v0.2.md),
sections 6 (Performance Budgets) and 7 (Adaptive Hardware Profiles). Per spec
section 1, performance is an acceptance criterion: RAM, CPU, disk I/O, boot
time, and background activity are first-class engineering budgets, not
nice-to-haves. If a budget and the spec ever disagree, the spec wins and this
file must be corrected.

Scope note on honesty (spec section 1.22): measurements taken inside VMs —
especially emulated x86_64 VMs on the maintainer's arm64 macOS host — must be
labeled with their environment and are not comparable to bare-metal numbers.

---

## 1. Budgets

All numbers below are copied from spec section 6 and must not drift from it.

### 1.1 Idle RAM (whole system)

Measured on a clean graphical desktop after boot and stabilization (see
"stabilized idle", section 2.1).

| Tier         | Budget       |
|--------------|--------------|
| Target       | < 1.0 GB RAM |
| Stretch      | < 750 MB RAM |
| Hard ceiling | 1.5 GB RAM   |

Exceeding the hard ceiling is a **release blocker** unless explicitly waived.
A waiver must be recorded (who, why, for which release) in this file.

### 1.2 Punar / Smplify service RAM (combined)

Combined idle memory for the local control-plane services — the `punard`
daemon and its siblings from spec section 11 (`punar-agentd`, `punar-secrets`,
`punar-workspace`, `punar-env`, `punar-netd`, and the resident parts of
`punar-shell` attributable to control-plane work; `punarctl` is a short-lived
CLI and is excluded while not running).

| Tier        | Budget                                    |
|-------------|-------------------------------------------|
| Target      | < 100 MB total idle RSS/PSS where measurable |
| MVP ceiling | < 150 MB                                  |

The built-in Smplify agent (`punar-smplifyd`) is not part of this idle total
on a device that never enrolled, because it does not run there at all: it is
dormant until enrolled (`docs/development/smplify-enrollment.md` §3.4), and
the gate holds it to never having started this boot (§2.3). Its resident
cost on an enrolled device is **unmeasured** until it is measured on one.

### 1.3 Idle CPU

| Tier   | Budget                          |
|--------|---------------------------------|
| Target | effectively 0% when idle        |

Rules (spec 6.3):

- Continuous high-frequency polling is prohibited.
- Prefer event-driven observation (inotify/fanotify where scoped, netlink,
  D-Bus/varlink signals, eBPF only where aggregation demands it) over timers.

"Effectively 0%" is operationalized in section 2.4 as a concrete threshold so
it can be enforced; the threshold is an engineering interpretation of the
spec, not a spec number, and is marked as such.

### 1.4 Disk I/O

Spec 6.4 defines rules rather than a single number:

- Avoid constant writes for telemetry, AI ledger, inventory, policy, and logs.
- Batch and aggregate writes.
- Do not log every filesystem read performed by AI agents.

Operationalization (engineering interpretation, see section 2.5): at
stabilized idle, Punar first-party services produce no more than **96 KiB
combined over five minutes**. Writes should arrive in infrequent batches, not
a steady trickle. The ceiling covers the three durability-synced reconcile
audit batches observed in a native x86 KVM window (73,728 bytes), reserving
one quarter of the ceiling as headroom; two native ARM HVF windows each
measured only one 8 KiB batch.

### 1.5 Boot

Spec 6.5 mandates tracking, not a fixed number:

- Track boot-to-usable-desktop time.
- Every major release must measure boot performance and regress-test it.

A single-run usable-desktop proxy now exists, but the required median of three
cold boots does not. A regression threshold is set only after that canonical
baseline is collected; one convenient CI observation is not promoted into a
budget.

### 1.6 Memory pressure behavior (companion requirement)

Not a number, but budget-relevant (spec 6.6): use zram, memory-pressure-aware
service behavior, cgroups, and per-project limits where useful. On 8 GB
systems, developer applications take priority over decorative OS effects.

### 1.7 Feature resource contract

Product-owner rule: **user workloads own the machine; the OS earns every
resident process, wake-up and megabyte.** This applies while features are in
use as well as at idle:

- A developer feature is demand-loaded and project-scoped unless it has a
  measured, always-on responsibility. Closing the project must stop its scope
  and leave no child process, listening socket or retained project model.
- Toolchains and SDKs are resolved from the project's pinned inputs and cached
  on demand. They do not enter the base image merely for convenience.
- Before a feature may ship, its evidence records cold activation time, active
  PSS, PSS after teardown, idle wake-ups, idle writes and installed bytes. A
  teardown result that does not return close to the pre-activation baseline is
  a defect, not an allocator footnote.
- Prefer activation and kernel/event signals over resident coordinators and
  polling. Sharing an existing process is not automatically free: its
  attributable retained model still has to be measured.
- Hardware profiles may reduce effects, cache residency and optional local
  compute. They never reduce security, privacy, integrity or audit guarantees.

---

## 2. Measurement methodology

Each budget has exactly one canonical measurement method. Any published number
must state the method, the image version, and the environment (bare metal
model, or hypervisor + host).

### 2.1 Definition: "stabilized idle"

All idle measurements (RAM, CPU, disk I/O) are taken at **stabilized idle**,
defined as all of the following:

1. Boot completed: `systemd-analyze time` returns (no jobs pending) and the
   graphical session is fully started (`graphical.target` active, session
   shell process running).
2. Auto-login into the default graphical session; **no user input** after
   login (no keystrokes, no pointer motion).
3. **10 minutes elapsed** since `graphical.target` became active. This window
   lets one-shot startup units exit, journal/coredump housekeeping finish,
   page cache and service allocator behavior settle, and any first-boot or
   first-login work complete.
4. No foreground applications launched beyond what the default session starts
   itself.
5. Network connected (DHCP complete) but no user-initiated traffic — idle must
   be measured with networking up, since that is the realistic state.
6. Sampling itself must be lightweight: the measurement agent may not cause
   the load it measures. Samplers read `/proc` and cgroup files directly and
   sleep between samples; no `top`-style full-process-table scans at high
   frequency.

Idle metrics are then sampled over a **5-minute measurement window** starting
at the 10-minute mark, and the reported value is the mean over the window
(RAM: mean and max; CPU: mean; disk: total bytes written during the window).

### 2.2 Idle RAM (whole system)

- Canonical metric: `MemTotal - MemAvailable` from `/proc/meminfo`, sampled
  every 10 s across the measurement window; report mean and max.
- Rationale: `MemAvailable` accounts for reclaimable page cache; raw
  `MemFree` would overstate usage and punish healthy caching.
- zram: when zram swap is active (Constrained profile), additionally record
  `swapused` and zram compressed size (`/sys/block/zram0/mm_stat`) so
  compressed memory is visible and cannot silently hide budget breaches.
  The headline budget number remains `MemTotal - MemAvailable`.
- Environment: the budget is defined for the minimum target (8 GB machine,
  spec 5.1) and for the CI VM sized to match (8 GB RAM). Numbers from VMs are
  labeled `(VM)`; numbers from emulated VMs (qemu tcg on arm64 hosts) are
  labeled `(VM, emulated)` and are indicative only.

### 2.3 Punar / Smplify service RAM

- Canonical metric: **PSS**, read from `/proc/<pid>/smaps_rollup` (`Pss:`
  line) for every process belonging to a Punar first-party service, summed.
  PSS is chosen because the services may share libraries; summing RSS would
  double-count shared pages.
- Process attribution: each Punar service runs in its own systemd unit
  (`punard.service`, `punar-agentd.service`, ...). Membership is determined
  from the unit's cgroup (`/sys/fs/cgroup/.../cgroup.procs`), never by
  process-name matching.
- Units summed **as of M12**: `punard.service` (M3), `punar-agentd.service`
  (M7), `punar-secrets.service` (M9 — the credential broker, a separate
  daemon by decision: `docs/development/milestone-9.md` §3.1), and
  `punar-netd.service` (M12 — per-principal nftables policy and on-demand TCP
  observation, target ≤ 6 MB PSS). The in-guest
  sampler (`/usr/lib/punar/idle-ram.sh`) walks that list
  and emits one combined `PUNAR_SERVICES_RSS_MB`; a unit whose cgroup is
  missing or empty makes the whole value `absent`, which
  `tests/performance/check-budgets.sh` fails even on emulated runs — one live
  daemon must never be able to mask a dead sibling. The budget below is the
  **combined** number and does not move as siblings ship: spec section 6.2
  budgets the services total, not each daemon. Adding a daemon and leaving
  it out of the sum, or raising the threshold to make room for one, would
  each make this budget say something untrue; if the total ever crowds the
  target, the honest responses in order are to report the number, trim the
  new daemon, and only then reconsider the topology
  (`docs/development/milestone-9.md` §11,
  `docs/development/milestone-12.md` §12).
- **`punar-smplifyd` is not summed, and its absence is gated instead.** The
  built-in Smplify agent is dormant until enrolled
  (`docs/development/smplify-enrollment.md` §3.4): systemd holds its socket,
  and nothing behind it runs until a call arrives. The measured image never
  enrolls, so summing the agent would make `PUNAR_SERVICES_RSS_MB` `absent`
  rather than say anything true. The sampler instead reports
  `PUNAR_SMPLIFYD_START_MONOTONIC_US` (when systemd last started the agent's
  main process this boot, 0 for never), `PUNAR_SMPLIFYD_PROCS` (the agent's
  cgroup, a missing cgroup counting as none) and `PUNAR_SMPLIFYD_SOCKET`, and
  `tests/performance/check-budgets.sh` fails the image, on every accelerator,
  unless the agent never started, has no process, and the socket is
  `active`. The start time is the one that matters: an agent something
  started during boot exits thirty seconds later and leaves no process to
  count. Leaving the agent out of the sum is honest only together with that
  gate, and the gate proves only the image's side: on the measured image
  punard dials the development mock control plane, not the agent's socket,
  so that an unenrolled punard never connects to the agent is held by
  punard's own test, which counts connections
  (`a_device_that_never_enrolled_never_calls_the_agent`). Its cost on an enrolled
  device is **unmeasured** until it is measured on one: the container figures
  in the activation design (about 1 MiB PSS idle, measured outside socket
  activation and before any TLS or check-in) are not a budget number.
- M11 adds no resident service: Browser and installed web apps run as user
  applications in the session slice. Their one-context PSS and second-context
  delta are recorded separately and do not masquerade as service or idle RAM.
- Cross-check metric: systemd cgroup accounting —
  `systemctl show -p MemoryCurrent <unit>` (i.e. cgroup v2
  `memory.current`), summed across the same units. This includes kernel-side
  memory (sockets, page tables) charged to the cgroup and will normally read
  higher than summed PSS. **The budget (100 MB target / 150 MB MVP ceiling)
  is judged against summed PSS**, per the spec's "RSS/PSS where measurable"
  wording; the cgroup figure is recorded alongside it for drift detection.
- Sampled at stabilized idle, same window and cadence as 2.2.

### 2.4 Idle CPU

- Canonical metric, per service: cgroup v2 `cpu.stat` (`usage_usec`) delta
  across the 5-minute window for each Punar unit, expressed as % of one CPU.
- Whole-system context: `/proc/stat` aggregate non-idle time delta across the
  window. It intentionally includes the small sampler overhead; the enforced
  per-cgroup numbers do not, because the sampler is outside those cgroups.
- Enforcement threshold (engineering interpretation of "effectively 0%", not
  a spec number): each Punar service **< 0.5% of one core averaged over the
  window**, and no periodic wakeup pattern faster than once per 10 s at idle
  (verified ad hoc with `perf`/`timerlat` or wakeup counts when
  investigating, not in the standard harness).
- Implemented by `/usr/lib/punar/idle-ram.sh`: it snapshots every named
  first-party cgroup at both boundaries of the same 300-second RAM window and
  reports integer hundredths of a percentage point (`50` = `0.50%`). Missing
  counters fail on every accelerator. `tests/performance/check-budgets.sh`
  enforces the per-service maximum on native KVM and Apple-HVF runs; TCG
  values are labeled and warn-only because emulation changes CPU cost.
- Periodic reconciliation and agent discovery share
  `punar-background.slice`. The slice persists between their short-lived
  cgroups, so the boundary delta includes every timer firing. Its CPU and I/O
  weights are 10 (default 100): background work may use an idle machine but
  yields under contention to interactive developer workloads.

### 2.5 Disk I/O

- Canonical metric, per service: cgroup v2 `io.stat` (`wbytes`, `wios`)
  delta across the measurement window for each Punar unit.
- Whole-system check: `/proc/diskstats` sectors-written delta for the root
  disk across the window.
- Judged against the rules in 1.4: sustained writers at idle are failures
  regardless of volume; batched, infrequent writes (e.g. a ledger flush once
  per N minutes or on event-count threshold) are acceptable. The combined
  first-party ceiling below is the enforceable volume backstop; a regular
  pattern that stays under it is still a defect when it violates the batching
  rule.
- Enforcement threshold (engineering interpretation, not a spec number):
  combined first-party service writes **≤ 98,304 bytes per five-minute
  window**. Two native Apple-HVF windows each measured exactly 8,192 bytes;
  a native x86 KVM window measured three durability-synced reconcile audit
  batches at 73,728 bytes. The 96 KiB ceiling reserves one quarter for
  cross-filesystem headroom while still turning a sustained writer into a
  release failure. Native KVM/HVF runs gate it; TCG numeric breaches are warn-only.
  Missing facts fail everywhere.
- Whole-guest block writes remain context only. They include the journal,
  filesystem metadata and services outside Punar's ownership, so gating that
  aggregate as though it were first-party would create false attribution.
- **Attributed, never double-counted.** The first-party figure alone left
  most of the guest's writes "unattributed" (98.5% in CI). The sampler now
  splits the device's total over the same window into the journal
  (`systemd-journald.service`, `PUNAR_IDLE_WRITE_JOURNALD_BYTES`), every
  top-level cgroup summed (`PUNAR_IDLE_WRITE_CGROUPS_BYTES`, which includes
  the journal and Punar's services), and the **kernel/filesystem metadata**
  no cgroup was charged for (`PUNAR_IDLE_WRITE_KERNEL_FS_BYTES`): the device
  total minus the cgroups, floored at zero. The device total
  (`PUNAR_IDLE_WRITE_DEVICE_BYTES`) is the root cgroup's `io.stat`, which is
  the whole disk's own counter and not a sum of its children, or diskstats
  when that is unreadable (`PUNAR_IDLE_WRITE_DEVICE_SOURCE`); every figure,
  the first-party services' write counter included, covers the same physical
  disks by `MAJ:MIN`, so zram and loop devices are in none. Adding the root
  to its children would count every charged byte twice, and
  `check-budgets.sh` fails a report whose remainder is not the subtraction,
  whose device total is further from the disks' own diskstats total in the
  same report than writes in flight at the window's edges explain (512 KiB
  plus 1/32 of it; the root's counter is charged at submission, diskstats at
  completion), or whose cgroup sum exceeds the device by more than that. The
  remainder is measured as "bytes no top-level cgroup was charged for"; that
  it is the kernel's and the filesystem's own writes (metadata commits,
  writeback of pages whose writer has gone) is the reading of it, inferred,
  not measured. The figures are context, not a budget. One arm64
  release-image window (2026-09-24, greeter idle, 4 GiB, HVF; not the CI
  lane) split 4,411,392 bytes into 1,134,592 of journal, 73,728 of punard's
  audit, and 3,203,072 no cgroup was charged for; its root `io.stat` and
  diskstats totals were identical (8,616 sectors). The journal and the audit log stay
  persistent: making either volatile would trade audit durability for
  writes, which is not a trade Punar makes.
- **Quieter timers, no record lost.** Much of that journal traffic was
  Punar's own timers: `punard-reconcile.service` printed its whole report
  every two minutes and `punar-agentd-scan.service` its whole registry every
  four, each wrapped in systemd's own start and finish lines. Both now run
  `--quiet` (one line when a pass changed something or failed, nothing
  otherwise) at `SyslogLevel=notice` with `LogLevelMax=notice`, which drops
  systemd's info lines for each run and keeps every failure line (measured
  on systemd 261). Nothing the audit trail needs went with them: every pass
  is a `reconcile` event, each remediation attempt and each capability's
  compliance change is its own event (`reconcile.compliance`, added for the
  drift nothing remediates, which only the old output named), and each
  detection change is `punar-agentd`'s (docs/api/ipc.md section 6). The saving is
  not measured yet.
- **Duplicate kernel audit lines: investigated, kept.** Each timer run's
  `SERVICE_START`/`SERVICE_STOP` records reach the journal twice, as
  `audit[1]: …` and as `kernel: audit: …` (measured in the same window).
  From the kernel source, not measured on the image: with no audit daemon
  registered, the kernel both multicasts every record (journald's audit
  socket receives all of them) and prints it to its log, rate-limited. Each
  way to drop one copy loses records or adds cost: disabling
  `systemd-journald-audit.socket` keeps only the rate-limited kernel copy,
  `audit=0` stops the records altogether, and registering an audit daemon to
  silence the kernel copy adds a resident process with its own log. Both
  copies stay.

### 2.6 Boot

- Canonical tool: `systemd-analyze`.
  - `systemd-analyze time` — firmware/loader/kernel/initrd/userspace split.
  - `systemd-analyze critical-chain` and `systemd-analyze blame` — recorded
    with every measurement for regression diagnosis.
  - `systemd-analyze plot > boot-<image-version>.svg` — archived as a CI
    artifact.
- `systemd-analyze` stops at userspace completion, which is **not**
  "usable desktop". Boot-to-usable-desktop is defined as: time from kernel
  start (as reported by `systemd-analyze`'s zero point) until the session
  shell reports ready — concretely, until a `punar-shell` readiness marker
  (a `systemd-notify`-style READY signal or timestamped journal line emitted
  when the shell has drawn its first frame and accepts keyboard input). Until
  that marker exists in the shell, `graphical.target` activation time is the
  interim proxy, and any number published with the proxy must say so.
- Report the median of 3 consecutive cold boots of the same image.
- VM boots exclude firmware time from cross-environment comparisons (VM
  firmware time is not representative of UEFI on target laptops).

---

## 3. Hardware profiles (spec section 7)

Budgets are defined at the **minimum target** (spec 5.1: 4-core x86_64, 8 GB
RAM, SSD). The adaptive profiles change system behavior, and therefore what a
measurement is expected to show — they do not relax the section 1 budgets.

| Profile | Example hardware | Behavior changes |
|---|---|---|
| **Constrained** | 8 GB RAM, integrated GPU | Aggressive zram; minimal background services; reduced visual effects; conservative local-model defaults; container resource guidance; memory-aware browser behavior; no large local inference stack by default. |
| **Standard** | 16 GB RAM | Full desktop experience; common developer containers; small/medium local AI utilities where appropriate; cloud AI remains primary. |
| **AI workstation** | 32–64+ GB RAM, discrete GPU | Local inference optional; model cache; GPU development stack; larger project/container budgets. |

Budget implications:

- The section 1 idle budgets are enforced on the **Constrained** profile —
  it is the worst case and the spec's minimum target.
- Standard and AI-workstation profiles may legitimately idle higher (more
  services enabled, optional local-AI machinery resident), but the base OS +
  Punar services portion must still meet the section 1 numbers; anything
  above it must be attributable to profile-enabled optional components.
- CI enforcement (section 5) runs the Constrained profile. Per-profile
  measurement is a later addition.

---

## 4. Baseline results

The historical shipping-x86 baseline rows come directly from the green x86 desktop job in
[run 33273700091](https://github.com/smplify-mdm/punar/actions/runs/33273700091),
commit `fe45b9d`, built from the pinned
2026/08/20 Arch snapshot. The desktop job used KVM with the canonical 8 GiB /
4-vCPU shape, ten-minute stabilization and thirty ten-second samples. Image
artifact ZIP digest: `sha256:1961a28daa7af5c06dc6030b4e855f5f85fbe722eef2a9f518f4548eb5a6efc5`.
The usable-desktop value is explicitly a single-run host proxy, not the
three-cold-boot median section 2.6 requires.

The same shipping Arch composition at current commit `f679a26` also passed
[run 33840661515](https://github.com/smplify-mdm/punar/actions/runs/33840661515)
but measured **1373/1376 MB** from exact image
`b601c4d8bee6cea7811d7f5cb2ad04f2c3390e3df178893a7c6b76049b0d06bc`.
That is a 257 MB mean regression from the historical 1116 MB observation,
despite the first-party services remaining 10 MB. It remains below the 1536
MB hard ceiling but is not accepted as a new target baseline. The process
attribution is retained in artifact `9925605057`; the regression requires
attribution and reduction rather than a threshold change.

The regression is now bounded to commit `a8fb51d` (the physical-x86 firmware
floor), not to the resident desktop or Punar services. The last pre-change
window at `0601677` measured 1113 MB with about 375 MiB `Unevictable`; the
first post-change window measured 1359 MB with about 611 MiB `Unevictable`.
The desktop UKI simultaneously grew from 217.3 MiB to 444.3 MiB. In mkosi 26,
leaving `KernelInitrdModules=` unset selects the complete installed module
tree; once firmware exists, its dependency pass also puts firmware for that
tree in the module initrd. The candidate fix explicitly selects mkosi's
architecture-aware `default` boot set on Arch x86_64, Debian x86_64 and generic
Debian ARM64. Full module and firmware trees remain in the installed root for
post-root hardware discovery. This explanation is source/config proven; its
UKI size and stabilized-RAM effect are pending the next canonical runtime run,
so neither result nor the 1024 MB target is predeclared here.

The ARM rows are from the latest local native Apple-HVF run of
`punar-desktop-arm64.qcow2`, SHA-256
`cf522bfff438411c2467a66ce65fc23ff6998ce67ce38798cd88c38b48d19133`,
built from the same immutable 2026-08-20 Debian snapshot and the source
content committed as `e29edbd`. Its 8 GiB / 4-vCPU guest was DHCP-connected
at the ten-minute boundary. It measured **1004/1005 MB**, 24 MB across the
four service cgroups, 0.01% maximum first-party CPU, 73,728 first-party write
bytes and 3,960,832 whole-guest bytes. The immediately preceding exact-method
ARM64 baseline measured 1210/1213 MB; selecting Qt's built-in software
adaptation and capping Mesa's llvmpipe worker pool only on unaccelerated
virtual adapters reduced the mean by 206 MB (17.0%). Hardware sessions
explicitly clear both overrides. Repetition is why the budgets are gates
rather than invented pre-measurement numbers. These are native-virtualization
results, not Raspberry Pi or bare-metal evidence.

The parallel Debian/x86_64 migration candidate is recorded separately rather
than replacing the shipping Arch baseline before substrate cutover. Canonical
KVM [run 33840661515](https://github.com/smplify-mdm/punar/actions/runs/33840661515),
job `100922123462`, measured the exact
`f09141e463ab3254365a30e5dbfa2b6cb27a27980b40df1ee75bb7dba97daf83`
desktop qcow2 from commit `f679a26`. Its artifact bundle is `9925733843`
(`sha256:81c2e780f90e599be1d1d53b0f4f856df96313afb9fdba7fd564341517c08f63`).
The full behavior suite ran after the same stabilization window and before
the report was accepted; this is candidate VM evidence, not a physical-x86
baseline.

| Metric | Method | Budget | Measured value | Environment | Image / date |
|---|---|---|---|---|---|
| Idle RAM (mean) | 2.2 | < 1.0 GB (target) / 1.5 GB (hard ceiling) | **1116 MB** (target missed; ceiling met) | KVM VM, 8 GiB / 4 vCPU | `e29edbd` / 2026-08-31 |
| Idle RAM (mean) | 2.2 | < 1.0 GB (target) / 1.5 GB (hard ceiling) | **1373 MB** (target missed; ceiling met; regression under investigation) | KVM VM, shipping Arch x86_64, 8 GiB / 4 vCPU | `f679a26` / 2026-09-04 |
| Idle RAM (mean) | 2.2 | < 1.0 GB (target) / 1.5 GB (hard ceiling) | **1214 MB** (target missed; ceiling met) | KVM VM, Debian x86_64 candidate, 8 GiB / 4 vCPU | `f679a26` / 2026-09-04 |
| Idle RAM (mean) | 2.2 | < 1.0 GB (target) / 1.5 GB (hard ceiling) | **1004 MB** (target met) | Apple-HVF ARM64 VM, 8 GiB / 4 vCPU, connected | `cf522b…d19133` / 2026-08-31 |
| Idle RAM (mean) | 2.2 | < 1.0 GB (target) / 1.5 GB (hard ceiling) | **933 MB** (target met) | Apple-HVF ARM64 VM, 8 GiB / 4 vCPU, connected; bounded initrd | `762a4a4` / 2026-09-04 |
| Idle RAM (max) | 2.2 | 1.5 GB (hard ceiling) | **1118 MB** | KVM VM, 8 GiB / 4 vCPU | `e29edbd` / 2026-08-31 |
| Idle RAM (max) | 2.2 | 1.5 GB (hard ceiling) | **1376 MB** | KVM VM, shipping Arch x86_64, 8 GiB / 4 vCPU | `f679a26` / 2026-09-04 |
| Idle RAM (max) | 2.2 | 1.5 GB (hard ceiling) | **1220 MB** | KVM VM, Debian x86_64 candidate, 8 GiB / 4 vCPU | `f679a26` / 2026-09-04 |
| Idle RAM (max) | 2.2 | 1.5 GB (hard ceiling) | **1005 MB** | Apple-HVF ARM64 VM, 8 GiB / 4 vCPU, connected | `cf522b…d19133` / 2026-08-31 |
| Idle RAM (max) | 2.2 | 1.5 GB (hard ceiling) | **939 MB** | Apple-HVF ARM64 VM, 8 GiB / 4 vCPU, connected; bounded initrd | `762a4a4` / 2026-09-04 |
| Punar services PSS (sum: punard + punar-agentd + punar-secrets + punar-netd) | 2.3 | < 100 MB (target) / < 150 MB (MVP ceiling) | **10 MB** | KVM VM, 8 GiB / 4 vCPU | `e29edbd` / 2026-08-31 |
| Punar services PSS (sum: punard + punar-agentd + punar-secrets + punar-netd) | 2.3 | < 100 MB (target) / < 150 MB (MVP ceiling) | **10 MB** | KVM VM, shipping Arch x86_64 | `f679a26` / 2026-09-04 |
| Punar services PSS (sum: punard + punar-agentd + punar-secrets + punar-netd) | 2.3 | < 100 MB (target) / < 150 MB (MVP ceiling) | **10 MB** | KVM VM, Debian x86_64 candidate | `f679a26` / 2026-09-04 |
| Punar services PSS (sum: punard + punar-agentd + punar-secrets + punar-netd) | 2.3 | < 100 MB (target) / < 150 MB (MVP ceiling) | **24 MB** | Apple-HVF ARM64 VM, 8 GiB / 4 vCPU, connected | `cf522b…d19133` / 2026-08-31 |
| Punar services PSS (sum: punard + punar-agentd + punar-secrets + punar-netd) | 2.3 | < 100 MB (target) / < 150 MB (MVP ceiling) | **25 MB** | Apple-HVF ARM64 VM, 8 GiB / 4 vCPU, connected; bounded initrd | `762a4a4` / 2026-09-04 |
| Punar services cgroup memory (sum, cross-check) | 2.3 | informational | not yet measured | — | — |
| Idle CPU, max first-party cgroup | 2.4 | < 0.5% of one core | **0.01%** | Apple-HVF ARM64 VM, connected | `cf522b…d19133` / 2026-08-31 |
| Idle CPU, max first-party cgroup | 2.4 | < 0.5% of one core | **0.01%** | Apple-HVF ARM64 VM, connected; bounded initrd | `762a4a4` / 2026-09-04 |
| Idle CPU, max first-party cgroup | 2.4 | < 0.5% of one core | **0.00%** | KVM x86_64 VM, connected | `e29edbd` / 2026-08-31 |
| Idle CPU, max first-party cgroup | 2.4 | < 0.5% of one core | **0.00%** | KVM shipping Arch x86_64, connected | `f679a26` / 2026-09-04 |
| Idle CPU, max first-party cgroup | 2.4 | < 0.5% of one core | **0.00%** | KVM Debian x86_64 candidate, connected | `f679a26` / 2026-09-04 |
| Idle CPU, whole guest | 2.4 | informational | **0.12% across 4 vCPU** | Apple-HVF ARM64 VM, connected | `cf522b…d19133` / 2026-08-31 |
| Idle CPU, whole guest | 2.4 | informational | **0.08% across 4 vCPU** | KVM x86_64 VM, connected | `e29edbd` / 2026-08-31 |
| Idle CPU, whole guest | 2.4 | informational | **0.06% across available CPUs** | KVM shipping Arch x86_64, connected | `f679a26` / 2026-09-04 |
| Idle CPU, whole guest | 2.4 | informational | **0.02% across available CPUs** | KVM Debian x86_64 candidate, connected | `f679a26` / 2026-09-04 |
| Idle writes, first-party services | 2.5 | ≤ 98,304 B / 5 min | **73,728 B** | Apple-HVF ARM64 VM, connected | `cf522b…d19133` / 2026-08-31 |
| Idle writes, first-party services | 2.5 | ≤ 98,304 B / 5 min | **73,728 B** | Apple-HVF ARM64 VM, connected; bounded initrd | `762a4a4` / 2026-09-04 |
| Idle writes, first-party services | 2.5 | ≤ 98,304 B / 5 min | **73,728 B** | KVM x86_64 VM, connected | `e29edbd` / 2026-08-31 |
| Idle writes, first-party services | 2.5 | ≤ 98,304 B / 5 min | **73,728 B** | KVM shipping Arch x86_64, connected | `f679a26` / 2026-09-04 |
| Idle writes, first-party services | 2.5 | ≤ 98,304 B / 5 min | **73,728 B** | KVM Debian x86_64 candidate, connected | `f679a26` / 2026-09-04 |
| Idle writes, whole guest | 2.5 | informational | **3,960,832 B** | Apple-HVF ARM64 VM, connected | `cf522b…d19133` / 2026-08-31 |
| Idle writes, whole guest | 2.5 | informational | **4,722,688 B** | KVM x86_64 VM, connected | `e29edbd` / 2026-08-31 |
| Idle writes, whole guest | 2.5 | informational | **4,456,448 B** | KVM shipping Arch x86_64, connected | `f679a26` / 2026-09-04 |
| Idle writes, whole guest | 2.5 | informational | **4,173,824 B** | KVM Debian x86_64 candidate, connected | `f679a26` / 2026-09-04 |
| Live zram | 2.2 / 1.6 | present and active | **7,923 MB, zstd, active** | Apple-HVF ARM64 VM | `cf522b…d19133` / 2026-08-31 |
| Live zram | 2.2 / 1.6 | present and active | **7,923 MB, zstd, active** | Apple-HVF ARM64 VM, bounded initrd | `762a4a4` / 2026-09-04 |
| Live zram | 2.2 / 1.6 | present and active | **7,925 MB, zstd, active** | KVM shipping Arch x86_64 | `f679a26` / 2026-09-04 |
| Live zram | 2.2 / 1.6 | present and active | **7,934 MB, zstd, active** | KVM Debian x86_64 candidate | `f679a26` / 2026-09-04 |
| Boot to userspace complete | 2.6 | tracked; regression-gated once baselined | not yet measured | — | — |
| Boot to usable desktop | 2.6 | tracked; regression-gated once baselined | **20 s single-run host proxy; not yet a baseline** | KVM VM | `e29edbd` / 2026-08-31 |
| Boot to usable desktop | 2.6 | tracked; regression-gated once baselined | **21 s single-run host proxy; not yet a baseline** | KVM shipping Arch x86_64 | `f679a26` / 2026-09-04 |
| Boot to usable desktop | 2.6 | tracked; regression-gated once baselined | **18 s single-run host proxy; not yet a baseline** | KVM Debian x86_64 candidate | `f679a26` / 2026-09-04 |
| Boot to usable desktop | 2.6 | tracked; regression-gated once baselined | **16 s single-run host proxy; not yet a baseline** | Apple-HVF ARM64 VM | `cf522b…d19133` / 2026-08-31 |
| Boot to usable desktop | 2.6 | tracked; regression-gated once baselined | **19 s single-run host proxy; not yet a baseline** | Apple-HVF ARM64 VM, bounded initrd | `762a4a4` / 2026-09-04 |

Waivers granted: none.

**The desktop gate's VM changed with SMP-1405 WP-02.** From WP-02 on,
`tools/boot-test.sh` gives the desktop VM a `virtio-keyboard-pci` and a
`virtio-tablet-pci` so the keys exercise can press real keys over QMP. Two more
kernel input drivers and their event nodes, and two more libinput devices in
the compositor, now sit in every desktop-gate figure. Figures above this note
were measured without them; the first figure with them is not strictly like
for like with those, and is recorded with that label.

**WP-02's own idle budget (keys, input and window grammar).** Plan rule 3.1-3
makes budgets cumulative, held by `tools/bench/idle-gate.sh` against WP-08's
Punar-only baseline; that gate is not built yet (tools/bench/README.md, "Not
built yet"), so WP-02 states its share here for it to hold: **no new process,
no new unit, no timer, no listening socket, no idle writes**; brightness,
media, microphone and the look toggles run a `punarctl` verb per key press
and exit; the Alt+Tab switcher is a deferred surface, built on the first
Alt+Tab and destroyed after it; the one always-resident addition is the
shell's `ShortcutUsage` singleton (a switch over the socket2 events the shell
already receives, and a few hundred bytes of state), which writes its file
once per account and once per newly tried key family, never per key press.
The switcher's cost is gated relative to the overview's
(`surface-cost-check.sh`). Both draw the same three windows, one per
workspace, so each draws three plates of one window, and the switcher's
median must stay within the overview's highest sample of the same run. On
an arm64 overlay boot (HVF, 2026-09-25, not a CI figure) the switcher was
15.7 MiB resident and 105 ms to first map, against the overview's 18.0 MiB
and 150 ms medians. With all three windows on one workspace, the switcher
drew three plates of three windows against the overview's one, and was
2.3 MiB heavier. That setup measured the wrong thing and was corrected.

### 4.1 Unpacked initramfs

**What it cost (MEASURED).** On the arm64 Debian release image (kernel
`7.1.12+deb14-arm64`, systemd 261), 132.2 MiB of `Unevictable` memory was the
unpacked initrd: the 119.1 MiB main archive plus the 13.2 MiB kernel-module
archive, 33,854 pages carrying the ramfs signature (file-backed, not
swap-backed, mapped by nothing, charged to the root cgroup). It stayed resident
for the whole boot although no mount of it was visible. The kernel's
`Freeing initrd memory` line frees only the compressed image.

**Why (MEASURED, with the systemd part INFER).**

- The `kdevtmpfs` kernel thread has its own mount namespace, copied from the
  initial one early in boot (`ksys_unshare(CLONE_NEWNS)` in
  `drivers/base/devtmpfs.c` before Linux 7.3). Entering that namespace and
  lifting the devtmpfs mounted on top showed the old initramfs intact: 2,851
  files and 254 symlinks. Unlinking them from there freed 135,416 kB of
  `Unevictable`, exactly the initrd's pages. MEASURED.
- systemd's `switch_root()` empties the old root only on its `MS_MOVE`
  fallback. Since Linux 7.0 (the nullfs root) `pivot_root()` from the
  initramfs succeeds, and systemd relies on the old superblock being released,
  which the kdevtmpfs namespace prevents. INFER from systemd v261's source and
  the intact tree. Affected: Linux 7.0 to 7.2 (INFER; only 7.1.12 was
  measured). Earlier kernels take the `MS_MOVE` path, where systemd empties
  the old root itself (INFER).
- **The real fix is Linux 7.3** (INFER from the source; not booted). Commit
  `66d2faeccbff` gives kdevtmpfs an empty namespace (`UNSHARE_EMPTY_MNTNS`). It is not in 7.1.y or 7.2.y and
  carries no stable tag. On 2026-09-25 (MEASURED from the archives): Debian
  unstable 7.2.7, testing 7.2.6, trixie-backports 7.1.x, nothing in
  experimental; Arch `core/linux` 7.2.6; kernel.org mainline 7.3-rc4 and
  stable 7.2.7. The shipped arm64 image runs 7.1.12, on a branch that ended at
  7.1.13, which is a security problem of its own.

**Mitigation (every lane, every profile).** `punar-release-initramfs.service`
(`os/images/initrd-common`, appended to mkosi's default initrd by
`os/images/mkosi.finalize`) runs after `initrd-cleanup.service` and
`initrd-switch-root.target`, immediately before `initrd-switch-root.service`.
It unlinks every file and symlink of the initramfs except what can still run
before PID 1 executes the real init: PID 1, `systemd-executor`,
`systemd-shutdown` (PID 1 reboots by executing it), the commands PID 1 has
loaded for `initrd-switch-root.service` (upstream: `systemctl`), their
libraries as the dynamic loader lists them, the symlinks on those paths, and
the initrd's own `CrashAction=` file. The keep set is computed from the
initramfs at that moment. It acts only:

- in the initrd, on the initramfs, with `/sysroot` mounted and holding an
  executable systemd and an os-release;
- on Linux 7.0 to 7.2 (elsewhere it logs `initramfs release not needed`);
- without `init=`, `systemd.unit=`, `rd.systemd.unit=` or a debug shell on the
  command line;
- after the TPM PCR barrier (`systemd-pcrphase-initrd.service`, whose
  `ExecStop=` extends `leave-initrd` into PCR 11) and the sysext/confext
  initrd services have stopped, since their stop runs a program it deletes;
- once PID 1 has no job left but its own and the switch-root's (it waits up to
  5 s, and keeps everything otherwise).

Anything it cannot resolve keeps everything, and a failure never stops
switch-root. It never deletes on another file system or through a bind mount.
The unit runs with `NoNewPrivileges=`, a capability bounding set of
`CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_OVERRIDE CAP_FOWNER` and
`RestrictAddressFamilies=AF_UNIX`.

The emergency shell's programs (`sulogin`, `bash`, `systemd-sulogin-shell`)
are deleted on purpose. On a release image root is locked, so upstream's
`OnFailure=emergency.target` only ever reached a console nobody could use.
Instead, two initrd-only files make every dead end reboot, so boot counting
can fall back to the other slot with no one at the machine:
`initrd-switch-root.service.d/50-punar-reboot-on-failure.conf`
(`FailureAction=reboot-force`) and
`system.conf.d/50-punar-initrd-crash-action.conf` (`CrashAction=reboot`, for
a PID 1 crash, or a failed `switch_root()` re-executing PID 1 in the emptied
initramfs, or a shutdown binary it cannot execute). The booted system reads
its own configuration after switch-root; neither file reaches it (see
"Failure path" below).

What the stabilized-idle gate requires of the step's line on every desktop
lane is in section 5. Retire the step only once every lane ships Linux 7.3 or
later and a measured boot without it shows no initramfs pages.

**Measured effect.** VM, arm64, release profile, greeter-idle: Apple-HVF
ARM64 VM, 4 GiB / 4 vCPU, headless, release image at the first-boot greeter
with no login, T+3 and T+6 minutes after power-on. Same base image and disk;
only the UKI differs. "After" is a UKI rebuilt with ukify from the shipped
image's own sections plus the member the committed builder makes from commit
`771890d`'s files (a rebuild without the member is byte-identical to the
shipped UKI). The two boots ran one after the other, each alone, on a host
whose load average was 27 to 61 from other work. 2026-09-25.

| Measurement | Before (shipped UKI) | After (with the step) | Change |
|---|---|---|---|
| `Unevictable` at T+3 and T+6 | 162,464 kB | 38,032 kB | −124,432 kB (−121.5 MiB) |
| Initrd page group | 33,854 pages (132.2 MiB) | 2,959 pages (11.6 MiB) | −30,895 pages (−120.7 MiB) |
| `MemAvailable` at T+6 | 3,114,152 kB | 3,245,084 kB | +130,932 kB, of which 123,580 kB is the initrd pages; the other 7,352 kB is not attributed |
| Old initramfs left behind | 2,851 files, 254 symlinks | 13 files, 4 symlinks (12,068,673 bytes) | exactly the 17-path keep set |
| Greeter | up (greetd, greeter Hyprland) | up (greetd, greeter Hyprland) | unchanged |
| Journal warnings at T+3 | 69 | 68 | none new |

The step's line on that boot, in the journal and in `dmesg`: `released the
initramfs: deleted 2843 files (118447151 bytes) and 250 symlinks, kept 17
paths (12068673 bytes); Unevictable 135456 kB -> 25196 kB, Shmem 8316 kB ->
8312 kB; find status 0, 0 errors`. The committed `idle-ram.sh` facts block,
run on that boot, reports `RELEASED=yes`, `FREED_KB=115671`,
`KEPT_KB=11785`, `DROP_KB=110264` and `LATE_WARNINGS=0`, which the section 5
gate passes. Within the step `Unevictable` fell 110,260 kB; the initrd group
fell 123,580 kB in all. The rest is the pages of deleted files that were
still mapped, freed when the step's own shell and `find` exited and PID 1
executed the real init (INFER).

Repeats. Controls: 160,564, 161,212 and 162,464 kB (mean 161,413). Boots with
a working step: 37,600, 36,296, 38,588 and 37,960 kB at commits `06088db` to
`8692aec` (15-path keep set, initrd group 2,941 pages each time) and 38,032
kB at `771890d` (17 paths, 2,959 pages; `systemd-shutdown` and the crash
setting add 18 pages). Mean 37,695 kB, so the saving is about 123,700 kB
(120.8 MiB). The spread is the greeter's locked memory (8.0 to 10.3 MiB
`Mlocked`). The unchanged pre-existing `systemd-userdbd.socket` ordering
cycle is reported from a different starting unit on each boot.

Boot time is within host noise. Initrd phase (`systemd-analyze`): controls
1.790, 1.828 and 2.287 s; boots with the step 1.891, 1.914, 1.939, 1.945,
1.982 and 2.135 s. The 1.790 s control ran at the same time as the 1.945 s
step boot, so that pair is not a clean comparison; the 2.287 s and 2.135 s
pair ran alone, one after the other. The step itself took 72 ms at `8692aec`
and 172 ms at `771890d`, which also lists PID 1's jobs; host load was higher
for the second.

**Failure path (MEASURED on arm64, with a proof-only initrd member).** A UKI
carried the committed member plus a proof-only drop-in making
`initrd-switch-root.service` call `systemctl switch-root` on a path that does
not exist, and one letting the TPM PCR barrier run without a TPM
(`pcrextend --graceful` exits 0), with a verbose serial command line.

- With the step's reboot drop-in: the barrier's stop (`leave-initrd`) ran at
  3.251 s and finished before `initrd-switch-root.target` was reached; the
  release followed at 3.684 s with the same 17-path keep set; switch-root
  failed at 3.703 s. `FailureAction=reboot-force` waits 5 s to show its
  message, then PID 1 executed the kept `systemd-shutdown` ("Shutting down."
  at 8.723 s), which synced and rebooted at 8.847 s. It could not unmount
  `/sysroot` or turn off swap, because `libmount.so.1` had been deleted; the
  root file system's journal covers that on the next boot (INFER; the next
  boot was not observed).
- Without it (the same member, less the drop-in): `emergency.service` could
  not find `systemd-sulogin-shell`, and the machine sat there for the 180 s
  the harness waited. That is the hang review found.
- Not booted: a failed `switch_root()` inside PID 1. PID 1 then re-executes
  the kept systemd in the emptied initramfs, finds no default or rescue
  target, and would freeze; the kept initrd `CrashAction=reboot` turns that
  into a reboot after 10 s (INFER from systemd v261's `main.c` and
  `crash-handler.c`).
- On the boot with the step, the booted system reports `FailureAction=none`
  for `initrd-switch-root.service` (MEASURED): the drop-in stays in the
  initrd.

**Not comparable.** The arm64 figures above are the release profile on 4 GiB
with Linux 7.1.12. The x86 figure below is the Arch desktop CI lane (dev
profile on 8 GiB, Linux 7.2.2). `PUNAR_IDLE_UNEVICTABLE_KB` in CI comes from
dev/desktop images on every lane, the arm64 CI lane included, and cannot be
compared with the 38,032 kB here.

**Still open.**

- The 11.6 MiB keep set stays resident until Linux 7.3.
- x86_64 (Arch 7.2.x and the Debian candidate) and the installer profile are
  not measured locally, and the x86 initrd was never measured. The Arch
  desktop window of CI run 36040855731 (kernel 7.2.2) showed 256.6 MiB
  `Unevictable` with a 109.4 MiB UKI; how much of that is the initramfs is
  not known. After push, the section 5 gate shows on the Arch, Debian x86_64
  and arm64 desktop lanes that the step ran, freed more than it kept, that
  the kernel's `Unevictable` + `Shmem` fell by at least half of what it freed,
  and that nothing warned between the release and the switch. It does not
  show that those kernels would have kept the tree resident without the step,
  or the idle saving there: no lane boots without the step as a control.
- On Linux 7.3 or later, and before 7.0, the step only logs that it is not
  needed. That path is covered by the contract test; no such kernel was
  booted.
- A failed switch-root now reboots, on every profile. On an installer medium
  whose root cannot be reached that is a reboot loop rather than a hang with
  a message.
- Raspberry Pi boots a dracut initramfs with the Pi's 6.18 kernel, not this
  initrd, and does not carry the step. Below Linux 7.0 systemd empties the old
  root itself (INFER).

---

## 5. CI enforcement — stabilized-idle slice implemented

The stabilized-idle slice of this design is implemented:
`tests/performance/check-budgets.sh` (see `tests/performance/README.md`),
fed by `tools/boot-test.sh --mode desktop` and wired as the CI
`desktop-test` job. Whole-system RAM and combined per-service PSS are both
runtime-proven and gated. Per-service CPU, combined first-party writes,
connected-idle facts and live zram are runtime-proven and gated too, and so
is the initrd having freed the unpacked initramfs before switch-root
(section 4.1): the step's line must say it released the initramfs, or that
the kernel does not need it. A release must have freed more than it kept, the
kernel's `Unevictable` + `Shmem` must have fallen by at least half of what it
freed, and no warning-or-worse userspace journal entry may fall between the
release and the switch-root. That shows on every desktop lane that the step
ran and its pages went; it does not measure what the step saves at idle on a
lane (no lane boots without it). The
cgroup-memory cross-check, boot-regression gate, JSON results file and tracked
history remain planned.

### 5.1 Harness shape

A `tests/performance/` harness that:

1. Takes a built Punar x86_64 VM image (the Milestone 0 image artifact) as
   input.
2. Boots it under QEMU/KVM in CI with the minimum-target shape: 4 vCPU, 8 GB
   RAM, virtio disk, Constrained profile, auto-login.
3. Waits for stabilized idle exactly as defined in 2.1 (boot complete,
   10-minute settle).
4. Runs an in-guest sampling script (shipped in the image or injected via
   virtiofs/ssh) implementing sections 2.2–2.6: `/proc/meminfo`,
   `smaps_rollup` sums, cgroup `memory.current` / `cpu.stat` / `io.stat`
   deltas, `systemd-analyze` output.
5. Emits a single JSON results file as a CI artifact, plus the
   `systemd-analyze plot` SVG.
6. Compares results against the budgets in section 1:
   - **Hard failures (build fails):** idle RAM > 1.5 GB hard ceiling;
     Punar service PSS sum > 150 MB MVP ceiling; any first-party cgroup at or
     above 0.50% of one CPU; combined first-party writes above 98,304 bytes
     per five minutes; missing daemon/runtime/network/zram facts; a boot
     whose initrd did not release the unpacked initramfs (or say its kernel
     does not need it), freed no more than it kept, did not lower
     `Unevictable` + `Shmem` by half of what it freed, or was followed by a
     warning before the switch-root.
   - **Warnings (annotated, non-fatal initially):** idle RAM above 1.0 GB
     target; service PSS above 100 MB target; boot-time regression beyond the
     (future) recorded baseline threshold.
7. Appends the run to a tracked history so trends are visible and the
   baseline table in section 4 can be updated from real data.

### 5.2 Environment caveats (must be encoded in the harness)

- CI runners are x86_64 with KVM where available. If a runner offers no KVM,
  the harness runs under TCG emulation: timings (boot, CPU) are then
  **informational only and must not gate the build**. The current harness
  conservatively downgrades every numeric performance breach under TCG;
  missing daemons, counters or live zram facts still fail because emulation
  cannot explain absent evidence.
- The maintainer's local macOS arm64 host cannot natively virtualize the x86_64
  image, so that path remains TCG and non-gating. The native ARM64 image runs
  under Apple HVF and does gate VM budgets. Neither path is a bare-metal
  baseline.
- Budgets gate on VM measurements as a proxy. Bare-metal validation on a
  representative device (spec 5.3) is a separate, later, manual step; VM
  numbers must never be presented as bare-metal results.

### 5.3 Sequencing

- RAM and combined-service PSS passed repeated native KVM/HVF runs before their
  hard ceilings became release gates. The 0.50% CPU interpretation was already
  fixed in section 2.4; deterministic fixtures exercise its pass, native-fail
  and TCG-warn branches before the first image run.
- First-party writes became a native release gate only after two native
  windows repeated the same 8,192-byte batch. Whole-guest writes remain
  context because they include activity outside Punar's ownership.
- Boot regression gating starts only after a baseline boot time is recorded
  in section 4.

---

## 6. Change control

- Budget numbers in section 1 change only via a spec change; edit
  `docs/product/SPEC_v0.2.md` (or its successor) first, then mirror here.
- Interpretation thresholds (CPU 0.5%, settle/measure windows, future disk
  and boot thresholds) are owned by this file and may be tuned with an entry
  in the log below.

| Date | Change |
|---|---|
| 2026-08-24 | Initial version: budgets transcribed from SPEC_v0.2 sections 6–7; methodology defined; all baselines `not yet measured`; CI harness documented as planned. |
| 2026-08-24 | Status wording only, no numbers: M0 CI green (punar-dev builds and boots); section 4 now names the `desktop-test` job's `punar-desktop-ram-report` artifact as the sole source that will fill the baseline table; section 5 marked partially implemented (idle-RAM slice in `tests/performance/`). Everything remains `not yet measured`. |
| 2026-08-25 | Milestone 9: `punar-secrets.service` joins the services-PSS sum (section 2.3) — the third resident daemon, added to the number honestly rather than left out of it. Thresholds unchanged (target < 100 MB, MVP ceiling < 150 MB): spec section 6.2 budgets the services *total*. Still `not yet measured` — the first real value comes from the `punar-desktop-ram-report` artifact of a CI run, and `docs/development/milestone-9.md` records the before/after from that run rather than asserting one here. |
| 2026-08-27 | Updated the canonical KVM RAM row from green run 33078009194: 1322 MB mean / 1329 MB max and 7 MB combined service PSS. The 1024 MB target remains missed and visible; no waiver. |
| 2026-08-27 | Implemented boundary snapshots for per-service cgroup CPU/write bytes and whole-guest context, enforced the existing 0.50% per-service CPU interpretation, required connected runtime facts, corrected the sampling interval from 290 to the full 300 seconds, and carried live zram facts into the host gate. |
| 2026-08-27 | Recorded two native Apple-HVF ARM64 windows: 1205/1210 MB mean, 1213 MB max, 18 MB service PSS, 0.00–0.01% max first-party CPU and exactly 8,192 first-party write bytes in each. Established a 65,536-byte/five-minute combined first-party write ceiling with 8× headroom; whole-guest writes remain context. No waiver. |
| 2026-08-29 | Recorded repeated four-service ARM64 candidates. The final exact-tree gate (`62081fb…12c14c9`) measured 1210/1213 MB RAM, 24 MB combined PSS, 0.00% max first-party CPU, 73,728 first-party write bytes and active 7,923 MB zram; the complete M2–M10, M12 and 122-assertion desktop-surface suites passed. The write ceiling is 98,304 bytes after a native KVM filesystem produced the same 73,728-byte durability batch. No waiver; the 1,024 MB RAM target remains missed. |
| 2026-08-29 | Replaced the older x86 baseline with canonical dual-architecture run 33273700091 at `fe45b9d`: x86_64 KVM measured 1311/1319 MB RAM, 9 MB four-service PSS, 0.00% maximum first-party CPU, 73,728 first-party write bytes and a 20 s single-run desktop marker; both architecture lanes emitted `PUNAR_M12_OK`. The 1,024 MB target remains missed and the 1,536 MB hard ceiling remains met; no waiver. |
| 2026-08-31 | The native Apple-HVF ARM64 candidate with source content committed as `e29edbd` selected Qt's raster adaptation and `LP_NUM_THREADS=2` only for unaccelerated virtual adapters. The exact canonical window (`cf522b…d19133`) improved from 1210/1213 MB to **1004/1005 MB**, meeting the unchanged 1,024 MB target; 24 MB combined service PSS, 0.01% maximum first-party CPU, 73,728 first-party write bytes and active zram also passed. M2–M10/M12, 122 desktop-surface assertions and 15 isolated surface samples all passed. Hardware GPU paths explicitly clear both overrides, so this closes the clean-VM budget item but is not a Raspberry Pi or bare-metal performance claim. No waiver. |
| 2026-08-31 | Canonical x86 KVM [run 33381573989](https://github.com/smplify-mdm/punar/actions/runs/33381573989) at `e29edbd` measured **1116/1118 MB**, down from 1311/1319 MB on the preceding exact method. It also passed 10 MB four-service PSS, 0.00% maximum first-party CPU, 73,728 first-party write bytes, active zram and the complete behavioral export. The x86 VM remains above the 1,024 MB target but below the 1,536 MB ceiling; no waiver. |
| 2026-09-04 | Exact local Apple-HVF ARM64 candidate `a21e03a…c960ff` from `762a4a4` bounded the UKI to mkosi's architecture-aware default early-boot modules while retaining the full installed module and firmware trees. It measured **933/939 MB**, 25 MB combined PSS, 0.01% maximum first-party CPU, 73,728 first-party write bytes and active zram; M2–M10/M12, 129 surface assertions and 15 isolated surface samples all passed. This is a 71 MB (7.1%) mean improvement over the preceding 1004 MB comparable ARM64 result. It is native-virtualization evidence, not physical-Pi or bare-metal evidence; canonical x86/CI confirmation remains pending. No waiver. |
