# Benchmark harness

`tools/bench` measures a desktop Linux system the same way whatever it is: the
same virtual machine, the same in-guest probe, the same host-side clocks,
packet capture and port scan, and one report that applies the owner's rule for
claiming anything (decision D1). It is written for the Punar-versus-Omarchy
head-to-head (WP-08, `punar-vs-omarchy.md` section 2) and runs on Punar alone
first; that run is the baseline the cumulative idle gate reads.

Nothing here makes a claim by itself. Every figure is a **VM measurement with
software rendering** until the physical lane agrees.

## Files

| File | What it does |
|---|---|
| `bench-probe.sh`, `bench-probe.service` | In-guest probe. Its own unit and cgroup; POSIX `sh` and awk (dash + mawk and bash + gawk are both tested); streams JSON Lines to the virtio-serial port `bench.export`. |
| `workload/bench-workload.sh` | Memory-pressure workload, sourced by the probe after the idle window. Experimental. |
| `inject-probe.sh` | Writes the probe into a disposable disk image offline (loop device, or nbd for qcow2), optionally through LUKS and a btrfs subvolume, and records the SHA-256 of every file it wrote. |
| `prepare-punar.sh` | Release image to `prepared.qcow2`: the probe injected, no account, nothing secret, so it can travel as an artifact. |
| `bench_run.py` | Host side: `onboard` (first account through the onboarding screens), `warmup` (one signed-in session on the disk itself), `run` (one measured boot: QEMU with the fixed shape, QMP keystrokes, the probe's stream, host clocks, steal and I/O wait, packet capture with its completeness, port scan, `host.json` and `result.json`), `install-omarchy`. |
| `qmp.py` | QMP client: keys typed from files or stdin only, screen dumps, frame stability, power control. Reuses `tools/framebuffer-probe.py` (screen states) and `tools/vm-type.py` (key map). |
| `bench_parse.py` | Probe stream plus `host.json` to a run result: every derived number, and whether the run is valid for a claim. |
| `pcap_summary.py` | Privacy lane: destinations, bytes, DNS names, TLS SNI, flows whose names it cannot read, identifiers, the guest's own addresses. |
| `portscan.py` | Exposure lane: nmap (SYN, all TCP ports; UDP top 200) or a TCP connect scan without it. |
| `netlane.sh` | The run's own network: tap, DHCP and DNS (dnsmasq), IPv6 router advertisements, NAT, and the guest confined to the internet. |
| `bench_plan.py` | Dispatch plan: cells (shape x run index), exactly balanced lane order, at most 20 cells, validated inputs. |
| `bench_report.py` | Median, min, max and IQR per metric, the D1 rule, families, failures, losses, the baseline file. |
| `source_run.py` | Decides whether a `ci.yml` run may supply the release image (this repository's `main`, a push or a dispatch, installer job green). |
| `scrub.py` | Removes the harness's secrets from every uploaded text file. |
| `omarchy/` | Owner-gated Omarchy lane: pinned ISO (`omarchy.env`), `fetch-iso.sh`, `new-secret.sh`, CIDATA templates and `make-cidata.sh`, `restore-stock.sh`. |

Tests: `tests/performance/bench-probe-test.sh` (the probe against fixture
`/proc`, `/sys` and `/run` trees, plain and dm-crypt layouts, exact expected
figures, the validity gate, the workload's pressure summary) and
`tests/performance/bench-summarize-test.sh` (the D1 rule and the report,
families, like-for-like checks, failed and missing runs, lower bounds, parser
edge cases, a synthetic packet capture, nmap parsing, the plan, the image
source check, the capture check, the scrubber, and the Omarchy lane's secret,
pin check, CIDATA rendering and stock restore). The workflow runs both before
it boots anything.

## Method

### The machine

The same for every system, set in one place (`bench_run.py`, `Machine`):

- q35 with KVM (`virt` with HVF or KVM on ARM64 for local smoke runs), `-cpu host`, 4 vCPU, 8 GiB or 4 GiB (2 GiB allowed);
- UEFI firmware from the distribution's OVMF package, with **no Secure Boot keys enrolled** (both systems need that today); its path is recorded;
- virtio-blk disk: a fresh qcow2 overlay per run over an **uncompressed raw** disk on the runner's own filesystem, the same for both systems, so every run is a cold boot of identical bytes and neither system reads through a compressed image;
- virtio-net with a fixed MAC (`52:54:00:be:0c:01`), on the bench network (below);
- **graphics lane A**: `virtio-vga` at 1920x1080 with no GPU acceleration, so both systems render with llvmpipe (on ARM64: `virtio-gpu-pci`);
- virtio keyboard and tablet (USB on ARM64); QMP on a private unix socket; serial log; the export port.

Before each run the host's page cache is flushed until less than 64 MiB is
dirty or under writeback (a run that follows an install or an image
conversion must not share the disk with gigabytes of writeback); the wait is
recorded, and the host's I/O wait over the window is recorded beside its
steal time.

### The image, the login and the warm-up

Punar is measured as the **release image** (`punar-release-debian-x86_64.qcow2`
from `ci.yml`'s `debian-amd64-installer` job), never the dev image with its
autologin and CI fixtures. It is taken only from a `ci.yml` run of this
repository's `main` branch (a push, or a dispatch on `main`) whose installer
job succeeded: the repository is public, `ci.yml` also runs on fork pull
requests, and a fork can upload an artifact of the same name from a branch it
calls `main`. The `SHA256SUMS` inside the artifact only proves the download is
whole.

`prepare-punar.sh` injects the probe and stops: its `prepared.qcow2` has no
account and no per-machine secret. Each cell then, on its own runner:
converts it to a raw disk; creates the first account once with
`bench_run.py onboard`, typing the same username, password and device name
through the same onboarding screens as `tools/test-release-onboarding.sh` (the
harness reads them from that script, so they cannot drift; the one-time
recovery receipt is recognised but never saved); boots it once more with
`bench_run.py warmup`; and commits the result into the raw disk. That disk
never leaves the runner.

**The warm-up** makes both systems start every measured run from the same
kind of state: after their first signed-in session. It is one boot at the
measured resolution (1920x1080), signed in exactly as a measured run signs in,
held in the session for 600 s (the measured settle), then a clean power-off;
anything short of a clean power-off fails the lane, because every run would
then replay a journal. Without it, each run's throwaway overlay would redo
first-login work (caches, first-run scripts, a wallpaper scaled to a new
screen) and Punar's onboarding boot ran at 1280x800.

A measured run: power on, the password greeter appears (the probe reports
the greeter session, then the harness waits for a stable frame), the password
is typed over QMP, and the session starts. The greeter frame is saved with its
empty password field.

Omarchy is installed unattended from its ISO onto an encrypted disk (its
default) written straight to a sparse raw file; its disk passphrase is typed
at the Plymouth prompt, and SDDM logs in automatically after it, which is
stock. Its warm-up is the first session after the install, held for the same
600 s at 1920x1080 and powered off over SSH (Omarchy binds the power key to a
menu, so an ACPI power-off cannot end it); `restore-stock.sh` then removes SSH
and the harness's key before the probe is injected.

### The probe

`bench-probe.sh` is injected offline into a copy of the disk as
`bench-probe.service`, wanted by `multi-user.target`, in its own cgroup, and
conditioned on running in a VM. `inject-probe.sh --record` lists the SHA-256 of
every file written. (`bench_run.py run --inject credentials` passes the same
unit, a `multi-user.target` drop-in and the scripts as systemd credentials over
SMBIOS type 11 instead, touching no disk. It worked on the ARM64 release image
locally; it is not the default because it depends on the guest's systemd
importing SMBIOS credentials, which the offline copy does not.)

1. **Start condition.** It polls logind's session files every 2 s. It records
   `greeter_ready` when a greeter-class session runs a Quickshell or greeter
   process, and `session_ready` when an active user session's owner runs
   `Hyprland` and a Quickshell process (`qs` on Punar, `quickshell` on
   Omarchy). It gives up after 30 minutes.
2. **Settle** 600 s, then the **idle window**: 30 samples at 10 s, sleeping
   after the last one too, so the window is 300 s (the method of
   `idle-ram.sh`, PERFORMANCE_BUDGETS.md sections 2.1 and 2.2).
3. At the start and end of the window: `/proc/stat` (all CPUs), `/proc/interrupts`,
   `/proc/diskstats`, `/proc/vmstat`, `/proc/pressure/*`, and **every cgroup in
   the tree** (`memory.current`, `memory.peak`, `memory.stat` anon/file/shmem/kernel,
   `cpu.stat`, `io.stat` per device).
4. Every sample: `/proc/meminfo`, a subset of `/proc/vmstat`, `/proc/stat`,
   `/proc/pressure/*`, load, and the probe's own cgroup memory.
5. After the window (so nothing below perturbs it): THP mode and defrag,
   `min_free_kbytes` and the other watermark settings, the zones' watermarks
   and the kernel's reserve from `/proc/zoneinfo`, zram and swap, zswap;
   per-process PSS from `smaps_rollup` for every process; listening sockets from
   `/proc/net/*` with owners joined by socket inode (and `ss -tulpn` when the
   system ships it); setuid and setgid files on the OS filesystems; file
   capabilities; `systemd-analyze time`, `blame`, `critical-chain` and
   `security`; systemd's boot timestamps; enabled units; running services;
   the nftables ruleset; `df`; the apparent size of `/usr` and `/opt`; the
   package manager and its package count; kernel hardening sysctls, lockdown
   and LSMs.
6. Only then, if the run asks for it, the workload.

Per-run settings come over QEMU's `fw_cfg` (`opt/bench/config`), so one
injected image serves every run. A run whose settle, sample count or interval
differs from 600/30/10 is labelled non-canonical and never used for a claim.

### Attribution

- **Memory.** `used = MemTotal - MemAvailable` per sample, mean and max, as in
  `idle-ram.sh`. Beside it, each for a stated reason:
  - `used` with the probe's own anonymous and kernel memory subtracted;
  - the machine's memory minus `MemAvailable`: memory a kernel reserves at
    boot never reaches `MemTotal`, so `used` cannot see it;
  - `used` minus the kernel's **totalreserve** (each zone's high watermark
    plus its largest lowmem reserve, from `/proc/zoneinfo`, as
    `calculate_totalreserve_pages` computes it). This is the part THP raises
    through `min_free_kbytes`, so it is the figure that shows whether a
    system is lighter or only running with lower watermarks;
  - `MemTotal - MemFree - file LRU - KReclaimable`: memory that is neither
    free nor page cache nor reclaimable slab. It differs from `used` by
    exactly the watermark deductions `MemAvailable` applies (totalreserve plus
    up to twice the low watermark kept out of cache and slab), and it is
    labelled as what it is;
  - AnonPages, Unevictable, Mlocked, Shmem, slab, swap in use, and the top 15
    processes by PSS.
- **CPU and wakeups.** Whole-system busy time from `/proc/stat` (steal
  excluded), interrupts and context switches per second, the top interrupts,
  the top five top-level cgroups and top ten leaf cgroups by CPU. The probe's
  cgroup CPU is reported and subtracted.
- **Writes, without double counting.** The device total is the root cgroup's
  `io.stat` for the physical disks (the kernel's own per-disk counter), or
  `/proc/diskstats` when the root has none, and says which. A cgroup is
  charged on the device its write **enters**: the top of each device-mapper or
  md stack (dm-crypt's `dm-0`), and any physical disk no stack sits on. The
  encrypted copy dm-crypt sends to the disk comes from a kernel worker and is
  charged to the root cgroup (or, on newer kernels, to the writer again), so
  counting cgroups on the physical disk under LUKS would give journald nothing
  and the remainder everything. journald is its own figure; every top-level
  cgroup is summed; the kernel/filesystem remainder is the device total minus
  that sum, floored at zero. The root is never added to its children, and no
  cgroup's bytes on a stack are added to its bytes on the disk below it. zram
  is swap and is in neither list. A cgroup's direct writes to a partition of
  a disk that also carries a stack (an ESP beside an encrypted root) land in
  the remainder. A cgroup created inside the window counts from zero; one
  removed inside it falls into the remainder. The probe's own writes are
  reported and subtracted.
- **Pressure.** PSI `some` and `full` stall share over the window, and the
  highest `avg10` seen.

### Boot

From systemd's own monotonic timestamps (firmware excluded from every
figure): kernel, initrd, userspace, kernel start to `graphical.target`,
kernel start to the greeter's shell process, and session start to the user's
shell process. Host clocks (QEMU start to greeter, prompt, typed, session) are
recorded too but never judged, because they include the harness's own polling.
Boot figures are compared only between runs that unlock and log in the same
way; see "Confounders".

### Network, privacy and exposure

`netlane.sh` gives each run a tap device with DHCP from dnsmasq
(192.168.77.0/24), DNS forwarded to the runner's resolver, IPv6 router
advertisements for `fd77:77:77:77::/64` (so there is a link-local and a
routable-looking IPv6 address to scan), and NAT for IPv4. The subnet is in
192.168.0.0/16 on purpose: firewalls that trust "the LAN" usually trust it.

The guest runs third-party code, so it reaches the internet and nothing else
of the runner's. From the tap the host accepts only DHCP, DHCPv6, DNS to
dnsmasq, ICMPv6 and replies to connections the host opened (the scan); any
other service listening on the runner is unreachable. Forwarding drops
link-local and metadata addresses (169.254.0.0/16, Azure's 168.63.129.16),
the private ranges (10/8, 172.16/12, 192.168/16, 100.64/10) and IPv6.

- **Privacy.** `tcpdump` on the tap from before power-on to the end of the idle
  window (on user-mode networking, QEMU's `filter-dump` instead). The capture
  counts only if tcpdump was still running when the harness stopped it and
  reports no packet dropped by the kernel or the interface; otherwise the
  run's privacy figures are not used (a truncated capture would read as a
  quieter system). `pcap_summary.py` reports every remote address with bytes
  each way and the names DNS gave it, which of them are on the internet, DNS
  names, TLS SNI (reassembled across segments), HTTP hosts and user agents,
  NTP servers, and identifiers the guest volunteered: DHCP hostname, FQDN and
  vendor class, DHCPv6 FQDN, mDNS names, names sent to the whole link in LLMNR
  or mDNS questions, and whether the MAC matched the one QEMU gave it. Names
  can only be counted where they are visible, so it also counts the flows that
  may carry a name it cannot read: QUIC, DNS over TLS or QUIC (port 853), DNS
  over HTTPS to the well-known resolvers, and TLS without SNI or with
  Encrypted Client Hello. When there is any, the name count is a lower bound
  and can never win.
- **Exposure.** After the probe is done, nmap scans every guest address it
  learned (DHCP lease, IPv4, IPv6 link-local, IPv6 ULA from duplicate-address
  detection): SYN on all 65,535 TCP ports and UDP on the top 200. Only ports
  that answered count as open; silent UDP ports are reported as
  open|filtered and never counted. `systemd-analyze security` exposure is
  scored as a sum over services (the harness's own probe excluded): a mean
  would fall by adding many small sandboxed units.

### Workload (experimental)

At 4 GiB (configurable), after the idle window and the post-window
collection: 20 local pages in the system's Chromium, left open; a batch-mode
Neovim pass over a 50,000-line file (substitute, sort, delete a tenth, write);
and a container build of a `FROM scratch` fixture of 2,000 files (about
40 MB) with no base image and no network, with rootless `podman` on Punar and
`docker` through one recorded sudo rule on Omarchy. Every process runs as the
signed-in person in their own user slice (`systemd-run --user
--machine=USER@`), each step bounded at 600 s. It records PSI `full` avg10 at
1 s, OOM kills (kernel and systemd-oomd), the lowest MemAvailable, swap in use,
the time of each step and the whole.

The container step cannot be the same program on both systems (root dockerd
does its work in `system.slice`), so the pressure, OOM and lowest-MemAvailable
figures that are compared come from the **browser and editor phase**, recorded
at the moment the container step starts; the whole-workload time and the
container time compare only runs that used the same container tool. How many
of the three steps completed is a metric of its own, so a system whose browser
is killed by oomd in every run loses it, and its pressure figures still count
(a step that was attempted and failed is a result; one that never started
means the systems did different work). Speedometer is not included.

### Runs, validity and the rule

- The workflow plans **cells** (one shape x one run index; five per shape by
  default, at most 20 per dispatch). Each cell is a fresh runner that runs
  every enabled lane once, back to back. The order is **balanced exactly**: on
  each shape every lane runs first in the same number of cells (one lane gets
  the odd one, and which lane alternates between shapes); a seeded shuffle,
  with the workflow run id as the seed, only decides which run index gets which
  order. The report publishes the headline figures split by position.
- A run is **valid for a claim** only if it is canonical, the window is
  complete, it ran under **KVM**, and the guest's steal over the window and
  the host's were both **measured** and both at most 2%. Missing data never
  passes: a run on a Mac (HVF cannot report host steal) or under TCG is
  informational. Invalid runs are listed with the reason and never used.
- **Like with like.** The runs pooled for one lane on one shape must share one
  setup (image, accelerator, architecture, resolution, network, disk format,
  probe version, login, disk encryption); a mixed pool is "not comparable",
  never averaged. The two systems must match on the machine and, for every
  metric, on disk encryption. `--meta` can add facts to a run but cannot
  replace any of these.
- **D1**: a system wins a metric on a shape only with at least 5 valid runs
  on each side, a better median, and min-max ranges that do not overlap.
  The rival winning the same way is a **loss**. Anything else is "no claim"
  with the reason.
- **One difference, one claim.** Figures that read one quantity several ways
  form a family (idle RAM: used, its max, net of the probe, machine minus
  available, minus totalreserve, unreclaimable, MemAvailable; wakeups:
  interrupts and context switches; boot to the desktop: `graphical.target` and
  the greeter; workload pressure: PSI and lowest MemAvailable). A family wins
  once, only when its headline figure wins and none of its figures loses; a
  family whose figures disagree claims nothing and says so.
- **Failures count.** Whether each planned run produced a valid result is a
  metric (a system that fails every run on a shape loses it); planned runs
  that never reported (a cell that timed out or was cancelled) count as
  failed, from the plan; every failed or invalid run of the subject is listed
  in the Losses section; a metric the subject has no usable runs for while the
  rival does is listed there too.
- `bench_report.py` prints the Losses section before the Wins section on every
  report, lists worse medians that are not D1 losses (not-comparable ones
  included), and never uses the word "win" for anything else. Cells show
  median [min-max], IQR and n, with the run ids. The report also writes
  `baseline.json` (the subject's per-shape medians), which the cumulative idle
  gate will read.

## Confounders, pinned or recorded

| Confounder | How it is handled |
|---|---|
| Transparent huge pages | Recorded (`enabled`, `defrag`, `shmem_enabled`, mTHP sizes), never changed: each system is measured as it ships. THP raises `min_free_kbytes` and so the kernel's totalreserve, which `MemAvailable` leaves out, so a THP-off system looks about 130 MiB lighter at 8 GiB without using less. `used` minus totalreserve (from `/proc/zoneinfo`) is in the idle-RAM family; a system can only claim idle RAM if none of the family's figures loses. |
| `min_free_kbytes` and watermarks | Recorded per run (`watermark_scale_factor`, `watermark_boost_factor`, swappiness, each zone's min/low/high, totalreserve). |
| Memory reserved at boot | Different kernels keep different amounts out of `MemTotal`; machine memory minus `MemAvailable` is in the idle-RAM family, and `MemTotal` is in the context. |
| zram, swap, zswap | Recorded (size, algorithm, `mm_stat`, `/proc/swaps`); swap in use is its own metric. Omarchy's zram and oomd stay as shipped. |
| Graphics | Lane A only: `virtio-vga`, no virgl, llvmpipe, 1920x1080 on both. Labelled "software rendering"; says nothing about real GPUs. Lane B (virtio-gpu-gl) needs a GPU host. |
| Firmware | The distribution's OVMF build, path recorded, Secure Boot keys not enrolled on either side. |
| Disk image | Both systems boot a per-run overlay over an uncompressed raw disk on the same host filesystem (the transferred Punar image is compressed qcow2 and is converted first). The format is a pooling key. |
| Host CPU and noise | Host CPU model, `nproc` and kernel recorded; guest and host steal over the window must be measured and at most 2%; paired lanes share a runner. |
| Host I/O | The host's page cache is flushed before every run (the wait is recorded); host I/O wait over the window is recorded. |
| Lane order | Balanced exactly per shape; headline figures published split by position. |
| Accelerator | Only KVM counts; HVF and TCG runs are informational. |
| The probe itself | Its own cgroup; CPU, memory and writes reported and subtracted; it streams everything instead of holding it in tmpfs; its own unit is left out of `systemd-analyze security`. It forks `awk` about once per sample, so it adds a few wakeups the subtraction cannot remove; both systems carry the same probe. |
| Disk unlock, install state and login | Punar's release **qcow2** is a pre-install image with no disk encryption; Omarchy is measured installed and encrypted, paying dm-crypt's CPU, memory and per-write cost. So **every** figure is "not comparable" between them (the report checks `disk_encryption` for every metric, and `login` for boot) until the installed, encrypted Punar lane exists. The medians are still shown side by side, and worse ones are listed. |
| First-run work | Both systems get one signed-in warm-up session of 600 s at the measured resolution, ended by a clean power-off, before any measured run (Omarchy's with SSH running for the harness, removed before measuring). |
| Footprint | `df /` counts a whole btrfs filesystem (home, logs, package cache, snapshots) on one system and one A/B root slot on another, so it is recorded, not scored; the scored figure is the apparent size of `/usr` and `/opt`. Package counts compare only within one package manager (dpkg and pacman split software differently). |
| Container tool | Podman on Punar, root dockerd on Omarchy: whole-workload and container times compare only runs with the same tool; pressure figures come from the browser and editor phase. |
| Network | Connected idle through NAT, like `idle-ram.sh`'s canonical method. Network-driven activity (update checks, weather, time sync) is part of each product and is shown by the privacy lane. |
| Browser | Chromium as each system ships it, with its own flags and policies; versions recorded in the package list. |

## Reproducing

On an x86_64 Linux host with KVM, QEMU, OVMF, `nmap`, `tcpdump` and
`dnsmasq`, from the repository root:

```sh
tools/bench/prepare-punar.sh punar-release-debian-x86_64.qcow2 bench/prepared   # sudo for injection
mkdir -p bench/disks && qemu-img convert -f qcow2 -O raw bench/prepared/prepared.qcow2 bench/disks/punar.raw
python3 tools/bench/bench_run.py onboard --base bench/disks/punar.raw --out bench/disks/onboarded.qcow2 \
    --frames bench/setup
sudo tools/bench/netlane.sh up "$(id -u)"
python3 tools/bench/bench_run.py warmup --disk bench/disks/onboarded.qcow2 --out bench/setup --net tap
qemu-img commit bench/disks/onboarded.qcow2 && rm bench/disks/onboarded.qcow2
python3 tools/bench/bench_run.py run --lane punar --disk bench/disks/punar.raw \
    --shape 8192 --net tap --leases /run/bench-netlane/leases --run-id local-1 --out bench/results/local-1
sudo tools/bench/netlane.sh down
python3 tools/bench/bench_report.py bench/results --md summary.md --json summary.json
```

Five or more runs per shape are needed before the report says anything
comparative. On a Mac (Apple silicon, HVF) the same works for the ARM64
release image with `--arch arm64 --net user` (no scan); such runs are
informational only (no host steal can be measured). Injection runs inside a
privileged Linux container with the image's directory mounted at the same
path, for example `docker run --privileged -v "$D:$D" -w "$PWD" <a Debian
image with qemu-utils> tools/bench/inject-probe.sh --image "$D/prepared.qcow2"
--partlabel PUNAR-ROOT-A --record "$D/injection.json"`. For a quick smoke test
add `--settle 60 --samples 6 --interval 10` to `run` and `--settle 60` to
`warmup`; such a run is labelled non-canonical and never counts.

In CI: **Actions, bench, Run workflow**. Inputs: `lanes` (`punar` or
`punar+omarchy`), `runs` (default 5), `shapes` (default `8192,4096`),
`workload_shapes` (default `4096`), `image_source` (`ci-artifact`: the newest
unexpired release image from a trusted `ci.yml` run on `main`, or the run id
given in `ci_run_id`, which must pass the same checks; `build`: build it in
the job), `omarchy_approved`, and `keep_raw_captures`. The report is on the
run's summary page and in the `bench-report` artifact (`summary.md`,
`summary.json`, `baseline.json`); every cell's probe stream, parsed results,
capture and scan summaries and frames are in `bench-result-<cell>` (90 days).

The repository is public, so its artifacts can be downloaded by anyone signed
in to GitHub. They therefore never include a disk with an account on it (the
first account is created on each cell's runner and discarded with it), the
raw packet captures, the DNS log or the serial consoles; with
`keep_raw_captures` those go to a separate `bench-raw-<cell>` artifact kept 3
days. Every uploaded text file is scrubbed of the Omarchy lane's throwaway
secret and the release image's CI test password first (`scrub.py`).

Budget: a dispatch runs at most 20 cells, and a cell is stopped after 75
minutes (Punar only) or 180 minutes (with Omarchy).

The weekly schedule (Mondays 06:00 UTC, Punar lane only) does nothing until the
repository variable `BENCH_SCHEDULE_ENABLED` is `yes`.

## The Omarchy lane: what the owner approves

The lane is written and tested on canned inputs, but **it has never run**, and
nothing from Omarchy has been downloaded. It runs only when all of these hold:
the dispatch input `lanes` is `punar+omarchy`, the input `omarchy_approved`
is true, and the repository variable `OMARCHY_LANE_APPROVED` is `yes`.
Scheduled runs never include it. Every job that would touch Omarchy checks the
input and the variable again when it starts, so re-running a failed cell after
the variable is cleared does not run it.

That gate is the workflow file's own logic. A dispatch runs the workflow file
of the ref it is dispatched on, so anyone with write access could dispatch an
edited copy from a branch without the checks: the gate prevents accidents, not
a writer who means to run the lane. Keeping writers trusted is what stops that.

Setting the variable approves:

1. **Downloading the Omarchy 4.0.4 ISO in CI** from
   `https://iso.omarchy.org/omarchy-4.0.4.iso` (about 6.19 GB), verified
   against the pinned SHA-256 `ddeded2758c48318d201dfdac905ecb28f570441883f0c052ea3cd5d05acf92d`
   before use. It is downloaded by **each cell** that runs Omarchy (ten per
   default dispatch, about 62 GB from iso.omarchy.org) and deleted after the
   install. It is never put in the Actions cache (the repository's 10 GB is
   already full with PR CI's caches, which the ISO would evict) and never
   uploaded as an artifact (that would re-publish Omarchy's image).
2. **Running Omarchy's installer in a VM on hosted runners**, unattended,
   from a CIDATA drive carrying: a per-cell throwaway secret generated at job
   start and never stored (Omarchy's configurator uses one secret for the disk,
   the user and root; it is in plaintext on that drive, which only the VM sees),
   its SHA-512 crypt hash, and an SSH public key that enables sshd for the
   install and the warm-up session only. The installed system's first session
   is held for 600 s at 1920x1080 and powered off over SSH.
3. **Returning the disk to stock before measuring** (`restore-stock.sh`):
   sshd disabled, the firewall rule for port 22 removed from `user.rules` and
   `user6.rules`, the key deleted; every change recorded.
4. **One recorded deviation**: a sudoers rule letting the person run exactly
   `docker build -t bench-fixture /opt/bench/fixture`, because stock 4.0.4 has
   no docker group and the workload's container step needs it. The
   alternative is dropping the container step on both systems.
5. **Runner time**: up to 180 minutes per cell with both lanes (download,
   install 5 to 15 minutes, both warm-ups, then each lane's boot, settle,
   window, collection, workload and scan); ten cells per default dispatch.
   Results are kept 90 days.
6. **Publishing the results, losses included** (D1 already says yes). Until
   the installed, encrypted Punar lane exists, every figure of this
   head-to-head is reported as "not comparable" (see "Confounders"): the lane
   can show the numbers side by side, but it cannot produce a claim yet.

Before the first run, do one interactive Omarchy install and diff its
`/root/user_configuration.json` and `/root/user_credentials.json` against
`omarchy/cidata/*.tmpl` (archinstall's schema drifts). Still unproven until the
lane runs: finding the Plymouth passphrase prompt by frame stability,
Omarchy's `ufw` rule layout, its Quickshell process name, whether its root
partition is number 2 as the templates lay it out, and whether a hosted
runner's `/` holds the ISO, the installed raw disk and Punar's disk at once
after the disk reclaim (estimated at about 25 GB; not measured).

## What only CI can prove

The fixture tests prove the probe's parsing and arithmetic (including the
dm-crypt attribution) and the report's rules. LUKS2 + btrfs injection with a
newline-terminated key file and the network lane's rules (up and down, leaving
nothing behind) were checked in a privileged Linux container. Local ARM64
smoke runs (HVF, the release image, short non-canonical windows) proved the
whole path on a real Punar image: offline injection and SMBIOS-credential
injection, the first account through onboarding, greeter login over QMP, the
probe's stream, the workload (Chromium with 20 tabs, Neovim, rootless podman),
the capture summary and the parsed result. Only a dispatch proves: KVM on
hosted x86 runners with this shape, the x86 release image's greeter path, the
warm-up's clean ACPI power-off on x86, the tap network with dnsmasq, tcpdump
(and its drop counters) and nmap under `sudo`, that the confined guest still
gets DHCP, DNS and IPv6 router advertisements, the trusted-source lookup and
artifact download from a `ci.yml` run, the workload on x86, five canonical
runs per shape inside the cell time limit, and the baseline.

## Not built yet

- Responsiveness (first changed frame after `Super+Return`, 20 Hz screen
  polling), the soak lane, Speedometer, the physical lane and the Debian/Arch
  lane split (D4).
- `tools/bench/idle-gate.sh`, which will read `baseline.json`.
- An installed, encrypted Punar lane (from the installer ISO with a signed
  answer file), which is what makes any figure comparable with Omarchy.
