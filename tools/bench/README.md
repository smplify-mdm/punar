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
| `prepare-punar.sh` | Release image to `prepared.qcow2` (probe injected) and `onboarded.qcow2` (first account created through the onboarding screens). |
| `bench_run.py` | Host side of one run: QEMU with the fixed shape, QMP keystrokes and screen states, the probe's stream, host clocks and steal, packet capture, port scan, `host.json` and `result.json`. Also `onboard` and `install-omarchy`. |
| `qmp.py` | QMP client: keys typed from files or stdin only, screen dumps, frame stability, power control. Reuses `tools/framebuffer-probe.py` (screen states) and `tools/vm-type.py` (key map). |
| `bench_parse.py` | Probe stream plus `host.json` to a run result: every derived number, and whether the run is valid for a claim. |
| `pcap_summary.py` | Privacy lane: destinations, bytes, DNS names, TLS SNI, identifiers, the guest's own addresses. |
| `portscan.py` | Exposure lane: nmap (SYN, all TCP ports; UDP top 200) or a TCP connect scan without it. |
| `netlane.sh` | The run's own network: tap, DHCP and DNS (dnsmasq), IPv6 router advertisements, NAT. |
| `bench_plan.py` | Dispatch plan: cells (shape x run index), seeded lane order, validated inputs. |
| `bench_report.py` | Median, min, max and IQR per metric, the D1 rule, losses, the baseline file. |
| `omarchy/` | Owner-gated Omarchy lane: pinned ISO (`omarchy.env`), `fetch-iso.sh`, CIDATA templates and `make-cidata.sh`, `restore-stock.sh`. |

Tests: `tests/performance/bench-probe-test.sh` (the probe against fixture
`/proc`, `/sys` and `/run` trees, exact expected figures) and
`tests/performance/bench-summarize-test.sh` (the D1 rule, the report, parser
edge cases, a synthetic packet capture, nmap parsing, the plan, the Omarchy
CIDATA rendering and stock restore). The workflow runs both before it boots
anything.

## Method

### The machine

The same for every system, set in one place (`bench_run.py`, `Machine`):

- q35 with KVM (`virt` with HVF or KVM on ARM64 for local smoke runs), `-cpu host`, 4 vCPU, 8 GiB or 4 GiB (2 GiB allowed);
- UEFI firmware from the distribution's OVMF package, with **no Secure Boot keys enrolled** (both systems need that today); its path is recorded;
- virtio-blk disk, a fresh qcow2 overlay per run over the prepared image, so every run is a cold boot of identical bytes;
- virtio-net with a fixed MAC (`52:54:00:be:0c:01`), on the bench network (below);
- **graphics lane A**: `virtio-vga` at 1920x1080 with no GPU acceleration, so both systems render with llvmpipe (on ARM64: `virtio-gpu-pci`);
- virtio keyboard and tablet (USB on ARM64); QMP on a private unix socket; serial log; the export port.

### The image and the login

Punar is measured as the **release image** (`punar-release-debian-x86_64.qcow2`
from `ci.yml`'s `debian-amd64-installer` job), never the dev image with its
autologin and CI fixtures. `prepare-punar.sh` creates the first account once,
typing the same username, password and device name through the same
onboarding screens as `tools/test-release-onboarding.sh` (the harness reads
them from that script, so they cannot drift). The one-time recovery receipt is
recognised but never saved. That boot is shut down cleanly, and every
measured run starts from the result: power on, the password greeter appears
(the probe reports the greeter session, then the harness waits for a stable
frame), the password is typed over QMP, and the session starts. The greeter
frame is saved with its empty password field.

Omarchy is installed unattended from its ISO onto an encrypted disk (its
default), its disk passphrase is typed at the Plymouth prompt, and SDDM logs
in automatically after it, which is stock.

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
   `min_free_kbytes` and the other watermark settings, zram and swap, zswap;
   per-process PSS from `smaps_rollup` for every process; listening sockets from
   `/proc/net/*` with owners joined by socket inode (and `ss -tulpn` when the
   system ships it); setuid and setgid files on the OS filesystems; file
   capabilities; `systemd-analyze time`, `blame`, `critical-chain` and
   `security`; systemd's boot timestamps; enabled units; running services;
   the nftables ruleset; `df`; kernel hardening sysctls, lockdown and LSMs.
6. Only then, if the run asks for it, the workload.

Per-run settings come over QEMU's `fw_cfg` (`opt/bench/config`), so one
injected image serves every run. A run whose settle, sample count or interval
differs from 600/30/10 is labelled non-canonical and never used for a claim.

### Attribution

- **Memory.** `used = MemTotal - MemAvailable` per sample, mean and max, as in
  `idle-ram.sh`. Also reported: the probe's own anonymous and kernel memory
  (subtracted in `used_net`), the kernel's reserve inside `MemAvailable`
  (`MemFree + file LRU + KReclaimable - MemAvailable`, which THP raises) and
  `used` minus it, AnonPages, Unevictable, Mlocked, Shmem, slab, swap in use,
  and the top 15 processes by PSS.
- **CPU and wakeups.** Whole-system busy time from `/proc/stat` (steal
  excluded), interrupts and context switches per second, the top interrupts,
  the top five top-level cgroups and top ten leaf cgroups by CPU. The probe's
  cgroup CPU is reported and subtracted.
- **Writes, without double counting.** The device total is the root cgroup's
  `io.stat` for the physical disks (the kernel's own per-disk counter), or
  `/proc/diskstats` when the root has none, and says which. journald is its own
  figure. Every top-level cgroup is summed. The kernel/filesystem remainder
  is the device total minus that sum, floored at zero. The root is never added
  to its children. zram, loop and device-mapper devices are in none of these
  (dm-crypt's writes land on the physical disk and are counted there). A
  cgroup created inside the window counts from zero; one removed inside it
  falls into the remainder. The probe's own writes are reported and
  subtracted.
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

- **Privacy.** `tcpdump` on the tap from before power-on to the end of the idle
  window (on user-mode networking, QEMU's `filter-dump` instead).
  `pcap_summary.py` reports every remote address with bytes each way and the
  names DNS gave it, which of them are on the internet, DNS names, TLS SNI
  (reassembled across segments), HTTP hosts and user agents, NTP servers, and
  identifiers the guest volunteered: DHCP hostname, FQDN and vendor class,
  DHCPv6 FQDN, mDNS names, names sent to the whole link in LLMNR or mDNS
  questions, and whether the MAC matched the one QEMU gave it. QUIC's server
  name is encrypted and is not decoded; QUIC flows are listed by address.
- **Exposure.** After the probe is done, nmap scans every guest address it
  learned (DHCP lease, IPv4, IPv6 link-local, IPv6 ULA from duplicate-address
  detection): SYN on all 65,535 TCP ports and UDP on the top 200. Only ports
  that answered count as open; silent UDP ports are reported as
  open|filtered and never counted.

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
the time of each step and the whole. A step that cannot run is recorded as
skipped with the reason, and a run where any step did not run is left out of
the workload metrics. The lane stays labelled experimental until every step
has run on both systems. Speedometer is not included.

### Runs, validity and the rule

- The workflow plans **cells** (one shape x one run index; five per shape by
  default). Each cell is a fresh runner that runs every enabled lane once, back
  to back, in an order drawn from a seeded shuffle (the seed is the workflow
  run id, recorded with each result); the cell list is shuffled too.
- A run is **valid for a claim** only if it is canonical, the window is
  complete, it ran under KVM (or HVF), and both the guest's steal time over the
  window and the host's are at most 2%. Invalid runs are listed with the
  reason and never used.
- **D1**: a system wins a metric on a shape only with at least 5 valid runs
  on each side, a better median, and min-max ranges that do not overlap.
  The rival winning the same way is a **loss**. Anything else is "no claim"
  with the reason. `bench_report.py` prints a Losses section before the Wins
  section on every report, lists worse medians that are not D1 losses, and
  never uses the word "win" for anything else. Cells show median [min-max],
  IQR and n, with the run ids. The report also writes `baseline.json` (the
  subject's per-shape medians), which the cumulative idle gate will read.

## Confounders, pinned or recorded

| Confounder | How it is handled |
|---|---|
| Transparent huge pages | Recorded (`enabled`, `defrag`, `shmem_enabled`, mTHP sizes), never changed. THP raises `min_free_kbytes`, which `MemAvailable` leaves out, so a THP-off system looks about 130 MiB lighter at 8 GiB without using less. `used` minus the reserve is published beside `used`. Punar must not "win" by turning THP off. |
| `min_free_kbytes` and watermarks | Recorded per run (`watermark_scale_factor`, `watermark_boost_factor`, swappiness too). |
| zram, swap, zswap | Recorded (size, algorithm, `mm_stat`, `/proc/swaps`); swap in use is its own metric. Omarchy's zram and oomd stay as shipped. |
| Graphics | Lane A only: `virtio-vga`, no virgl, llvmpipe, 1920x1080 on both. Labelled "software rendering"; says nothing about real GPUs. Lane B (virtio-gpu-gl) needs a GPU host. |
| Firmware | The distribution's OVMF build, path recorded, Secure Boot keys not enrolled on either side. |
| Host CPU and noise | Host CPU model, `nproc` and kernel recorded; guest and host steal over the window recorded; runs above 2% discarded. Paired lanes share a runner. |
| Accelerator | Only KVM (or HVF locally) counts; TCG runs are never valid. |
| The probe itself | Its own cgroup; CPU, memory and writes reported and subtracted; it streams everything instead of holding it in tmpfs. It forks `awk` about once per sample, so it adds a few wakeups the subtraction cannot remove; both systems carry the same probe. |
| Disk unlock and login | Punar's release **qcow2** has no disk encryption until the installer creates it; Omarchy is measured installed and encrypted. Every boot figure is therefore marked "not comparable" between them until the installed-Punar lane exists (`bench_report.py` checks `disk_encryption` and `login` per metric). Idle figures are compared. |
| First-run work | Punar's first account is created once, then every run is a later boot, like a person's second day. |
| Network | Connected idle through NAT, like `idle-ram.sh`'s canonical method. Network-driven activity (update checks, weather, time sync) is part of each product and is shown by the privacy lane. |
| Browser | Chromium as each system ships it, with its own flags and policies; versions recorded in the package list. |

## Reproducing

On an x86_64 Linux host with KVM, QEMU, OVMF, `nmap`, `tcpdump` and
`dnsmasq`, from the repository root:

```sh
tools/bench/prepare-punar.sh punar-release-debian-x86_64.qcow2 bench/prepared   # sudo for injection
sudo tools/bench/netlane.sh up "$(id -u)"
python3 tools/bench/bench_run.py run --lane punar --disk bench/prepared/onboarded.qcow2 \
    --shape 8192 --net tap --leases /run/bench-netlane/leases --run-id local-1 --out bench/results/local-1
sudo tools/bench/netlane.sh down
python3 tools/bench/bench_report.py bench/results --md summary.md --json summary.json
```

Five or more runs per shape are needed before the report says anything
comparative. On a Mac (Apple silicon, HVF) the same works for the ARM64
release image with `--arch arm64 --net user` (no scan), and injection runs
inside a privileged Linux container with the image's directory mounted at the
same path, for example `docker run --privileged -v "$D:$D" -w "$PWD" <a
Debian image with qemu-utils> tools/bench/inject-probe.sh --image
"$D/prepared.qcow2" --partlabel PUNAR-ROOT-A --record "$D/injection.json"`.
For a quick smoke test add `--settle 60 --samples 6 --interval 10`; such a
run is labelled non-canonical and never counts.

In CI: **Actions, bench, Run workflow**. Inputs: `lanes` (`punar` or
`punar+omarchy`), `runs` (default 5), `shapes` (default `8192,4096`),
`workload_shapes` (default `4096`), `image_source` (`ci-artifact`: the newest
unexpired release image from a `ci.yml` run on `main`, or the run id given in
`ci_run_id`; `build`: build it in the job), and `omarchy_approved`. The
report is on the run's summary page and in the `bench-report` artifact
(`summary.md`, `summary.json`, `baseline.json`); every cell's raw stream,
capture, scan and frames are in `bench-result-<cell>`.

The weekly schedule (Mondays 06:00 UTC, Punar lane only) does nothing until the
repository variable `BENCH_SCHEDULE_ENABLED` is `yes`.

## The Omarchy lane: what the owner approves

The lane is written and tested on canned inputs, but **it has never run**, and
nothing from Omarchy has been downloaded. It runs only when all of these hold:
the dispatch input `lanes` is `punar+omarchy`, the input `omarchy_approved`
is true, and the repository variable `OMARCHY_LANE_APPROVED` is `yes`.
Scheduled runs never include it. Setting the variable approves:

1. **Downloading the Omarchy 4.0.4 ISO in CI** from
   `https://iso.omarchy.org/omarchy-4.0.4.iso` (about 6.19 GB), verified
   against the pinned SHA-256 `ddeded2758c48318d201dfdac905ecb28f570441883f0c052ea3cd5d05acf92d`
   before use, and caching it in the repository's Actions cache keyed by that
   hash (it crowds out other caches in the 10 GB budget).
2. **Running Omarchy's installer in a VM on hosted runners**, unattended,
   from a CIDATA drive carrying: a per-run throwaway secret generated at job
   start and never stored (Omarchy's configurator uses one secret for the disk,
   the user and root; it is in plaintext on that drive, which only the VM sees),
   its SHA-512 crypt hash, and an SSH public key that enables sshd for the
   install phase only.
3. **Returning the disk to stock before measuring** (`restore-stock.sh`):
   sshd disabled, the firewall rule for port 22 removed from `user.rules` and
   `user6.rules`, the key deleted; every change recorded.
4. **One recorded deviation**: a sudoers rule letting the person run exactly
   `docker build -t bench-fixture /opt/bench/fixture`, because stock 4.0.4 has
   no docker group and the workload's container step needs it. The
   alternative is dropping the container step on both systems.
5. **Runner time**: about 70 minutes per cell with both lanes (install 5 to 15
   minutes, then each lane's boot, settle, window, collection, workload and
   scan); ten cells per dispatch. Results are kept 90 days.
6. **Publishing the results, losses included** (D1 already says yes).

Before the first run, do one interactive Omarchy install and diff its
`/root/user_configuration.json` and `/root/user_credentials.json` against
`omarchy/cidata/*.tmpl` (archinstall's schema drifts). Still unproven until the
lane runs: finding the Plymouth passphrase prompt by frame stability,
Omarchy's `ufw` rule layout, its Quickshell process name, and whether its
root partition is number 2 as the templates lay it out.

## What only CI can prove

The fixture tests prove the probe's parsing and arithmetic and the report's
rule. Local ARM64 smoke runs (HVF, the release image, short non-canonical
windows) proved the whole path on a real Punar image: offline injection and
SMBIOS-credential injection, the first account through onboarding, greeter
login over QMP, the probe's stream, the workload (Chromium with 20 tabs,
Neovim, rootless podman), the capture summary and the parsed result. Only a
dispatch proves: KVM on hosted x86
runners with this shape, the x86 release image's greeter path, the tap network
with dnsmasq, tcpdump and nmap under `sudo`, the artifact download from a
`ci.yml` run, the workload on x86, five canonical runs per shape inside the
runner time limit, and the baseline.

## Not built yet

- Responsiveness (first changed frame after `Super+Return`, 20 Hz screen
  polling), the soak lane, Speedometer, the physical lane and the Debian/Arch
  lane split (D4).
- `tools/bench/idle-gate.sh`, which will read `baseline.json`.
- An installed, encrypted Punar lane (from the installer ISO with a signed
  answer file), which is what makes boot comparable with Omarchy.
