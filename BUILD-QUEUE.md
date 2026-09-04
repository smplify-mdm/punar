# Punar — Build Queue

**Companion to [`HANDOFF.md`](HANDOFF.md).** That document explains *what Punar
is and how it works*. This one is *what to build next and how*.

**Read `HANDOFF.md` §3 (standing rules) and §11 (failure modes) first.** Several
tasks below exist because an earlier decision was reversed, and §11 lists
mistakes that each cost a full CI cycle.

---

## 0. The finish line

Spec §80 defines done as: a clean VM can do 26 things. **All 26 are now
demonstrated** by the latest native ARM64 candidate's 780 milestone
assertions, 122 desktop-surface assertions, 5 wireless-posture assertions and
15 isolated surface-cost checks. Physical x86/ARM hardware acceptance remains
a separate Phase-2 gate; clean-VM completion must not be restated as a
bare-metal claim. The recently closed gates are recorded here:

| # | DoD item | Status |
|---|---|---|
| 7 | launch browser / **web app** | **CORE DoD VERIFIED IN CANONICAL DUAL-ARCH CI:** [run 33273700091](https://github.com/smplify-mdm/punar/actions/runs/33273700091) passed both 122-assertion desktop-surface suites. Clicking the top-left **PUNAR** launcher, `PUNAR+Space`, or `PUNAR+S` → Applications exposes actionable installed/catalog rows. Spotify → architecture-aware app card → official Spotify web player in Chromium app mode passed by pointer; an installed Chromium row opened directly. The clean ARM64 gate also searched for and opened Geany, Neovim in Foot, and the real Thunar Files window, and represented all 22 signed-catalog products in the live model. The current catalog keeps Claude Web/ChatGPT Web distinct from Claude Desktop beta/ChatGPT Desktop preview. The on-demand vendor-package backend is locally contract-tested: exact origin/architecture/size/digest, no maintainer scripts, setuid/setgid removal, Punar-owned launcher, isolated app home, and reversible removal. Native third-party vendor UIs remain `COMPATIBILITY TESTING` until both architecture lanes install and launch them. Generic user-defined web-app installation, isolated browser contexts and managed Chromium policy are implemented in the current working tree; they remain **LOCAL-ONLY** until the new M11 VM gate passes both architecture lanes. |
| 19 | enforce project network rule | **VERIFIED IN CANONICAL DUAL-ARCH CI:** [run 33273700091](https://github.com/smplify-mdm/punar/actions/runs/33273700091) emitted `PUNAR_M12_OK` with 66 assertions on both x86_64 KVM and ARM64 TCG. A same-user out-of-scope control reached its listener, the managed scope reached the allowed listener, and the managed production probe was denied by the cgroup-v2 nft rule. Policy compilation, attachment, named counters, malformed-policy fail-safe, detach and table self-heal all passed. This proves generic UEFI/QEMU behavior, not internet, VPN, Raspberry Pi or physical-NIC behavior. |
| 20 | display local network activity | **VERIFIED IN CANONICAL DUAL-ARCH CI:** the same run joined a live allowed connection to the cross-user managed cgroup through kernel `NETLINK_SOCK_DIAG` metadata, rendered the bounded local-only Privacy panel, wrote only the reached destination to the purgeable agent ledger, and kept destinations/ports out of immutable audit. Both screenshots and reports exported successfully; the daemon held no `CAP_SYS_PTRACE`. |
| 25 | demonstrate rollback/update mechanism | **VERIFIED IN CANONICAL ARM64 CI:** [run 33273700091](https://github.com/smplify-mdm/punar/actions/runs/33273700091) emitted `PUNAR_UPDATE_AUTO_ROLLBACK_OK attempts=3 fallback_slot=A`. Signed apply had already verified inactive-slot write/readback/hash and health-gated blessing. The four-boot proof exhausted an impossible pending UKI through `+2-1`, `+1-2`, `+0-3`; boot four skipped it and reached `PUNAR_BOOT_OK` from slot A. |
| 3 | remain within idle budget | **MET ON NATIVE ARM64 VM:** exact Apple-HVF candidate `cf522b…d19133` measured **1004 MB mean / 1005 MB max** against the unchanged 1024 MB target, down from the comparable 1210/1213 MB baseline. Four first-party services totaled 24 MB PSS; idle CPU, writes and zram also passed. The unaccelerated-VM renderer policy is runtime-proven and real-GPU paths explicitly clear it. This closes clean-VM DoD item 3, not Raspberry Pi or bare-metal performance acceptance. |
| 10 | report compliance | **VERIFIED:** personal devices render `DRIFT · MATCHES` without organization wording; enrolled wording remains distinct — see §3 |

And spec §81 Test A is the real bar: *"If Smplify management were removed,
would an engineer still choose Punar?"* The answer must be yes. That is why the
unmanaged-first work in `HANDOFF.md` §3.3 is not cosmetic.

The update product is three-channel governed rolling: `stable` (default),
`dev`, and opt-in `edge`. All three deliver complete signed A/B images through
the same verification and rollback path; only promotion cadence and soak
differ. Project toolchain freshness belongs to `punar-env`, never a partial
host upgrade. The core apply, boot-counting, health-gate, blessing, and
automatic-fallback path is implemented and canonical ARM64 CI-proven. Channel
transport/promotion, production key custody, and end-to-end production
repository coverage remain unshipped.

The four typed governed-update methods are implemented in the current tree.
`punarctl update status`
obtains bounded local evidence through the read-only `update.status` IPC method
and reports release identity, actual/desired slot, health signals, rollback
state, channel provenance, and browser-package provenance without inventing
unavailable values. Personal devices can select `stable`, `dev`, or `edge`
through the durable `system.update_channel` capability; enrollment policy
continues to win through the normal effective-policy engine. The current
tree includes root-only, audited `update.check`: it verifies exact-byte
Ed25519 channel metadata against the device image/architecture/platform/channel,
computes rollout eligibility locally, and atomically caches only authenticated
state. A root-owned optional HTTPS origin now resolves the fixed
channel/architecture/platform paths without sending device identity or current
version; HTTPS-only/TLS floor, redirect refusal, response bounds, private
staging, exact signature/target admission, and no downgrade to local media are
unit-proven. The local-media transport remains only when no network origin is
configured. Unit and daemon/CLI integration suites pass locally; canonical CI
and a real production CDN/TLS exercise are still required before calling the
network discovery path shipped. Root-human-only `update.apply` re-authenticates
the exact channel head and release, selects the inactive slot from fixed local
evidence, verifies an independently root-bound A or B payload/UKI pair, writes
and physically re-hashes the inactive root, retains the blessed old UKI, and
installs the counted candidate last. `update.rollback` selects only a retained
local last-known-good release; both methods are audited, reject caller-supplied
paths/origins/slots/digests, and deny agent-attributed peers before uid. The
same public methods dispatch to the existing Raspberry Pi `tryboot` transaction
and its now-explicit durable rollback. Local integration proves A→B, B→A,
post-write verification, selector transition, rollback, non-root denial and
non-overridable agent denial. A real local bundle build from the canonical
ARM64 image produced two distinct 8 GiB root payloads and two distinct
root-bound UKIs for release `2026.09.01.1`; both compressed streams reproduced
their signed uncompressed digests and each UKI exposed exactly one expected
PARTUUID. That artifact proof used an explicitly labelled ephemeral test key,
not production signing custody. Full canonical CI is still required for this
slice. Promotion automation, production key custody, a real production
repository/CDN exercise, bare-metal power-loss testing and physical Raspberry
Pi acceptance remain open.

The primary modifier's product name is the **Punar key** (`PUNAR + …` in
written chords, `Punar` on caps). The raw Hyprland modifier name is internal
configuration syntax and must not leak back into the shell or user guides.

The optional first-desktop activation direction is now explicit in
`docs/design/workstation-activation.md`: keep account creation to its three
values, then offer a dismissible, truthful path to reviewed AI tools,
WireGuard/Tailscale or an actually available Smplify relay, isolated project
environments, and REST API testing. Nothing is installed, registered, or
shown as active until the user takes a real action and the backend verifies it.
These conveniences inherit Punar's non-negotiable security floor: reviewed and
digest-bound supply, sandboxing, secret-broker use, explicit network effects,
least privilege, auditability, and fail-closed negative tests. No developer or
onboarding mode may bypass those controls.

ChatGPT Desktop and Claude Desktop now have official Linux packages for both
x86_64 and ARM64, but neither vendor officially supports Arch/Punar; Anthropic
explicitly directs Arch users to its CLI. Keep the existing official web apps
as universal fallbacks. Native entries now have an on-demand, digest-pinned,
scriptless installation backend and remain a compatibility work item until the
dependency, Wayland, containment, update/rollback, removal, and real
dual-architecture runtime gates in
`docs/design/workstation-activation.md` pass. Never merge web/native/CLI into
one installed state, and never label an extracted vendor package as formally
supported by its vendor.

The profile direction is bounded in `docs/design/profiles.md`. A profile is a
real identity, storage, secret, process, network, peripheral, and policy
boundary—not a theme or a same-user preset. Device encryption, verified boot,
kernel updates, and the hardware trust floor remain device-scoped; separately
keyed profile storage and managed-profile enrollment may narrow that foundation
without acquiring authority over personal profiles. Time and event rules
suggest activation by default, never unlock unattended, and must survive
spoofing, replay, conflict, expiry, recovery, and power-loss tests. Home Hub is
defined as a resource-bounded service profile with no access to human profiles.
Do not publish profile schemas or portal APIs until the encryption, namespace,
seat-isolation, BYOD-disclosure, and Raspberry Pi resource spikes pass.

---

## 1. Immediately

### 1.1 Start from the remote head
`origin/main` is the durable source of truth. Before handing off, require
`git rev-parse HEAD` and `git rev-parse origin/main` to match and leave no
uncommitted source changes. Run `33050021488` is the last historical seven-job
green baseline; newer work adds native onboarding, recovery, the application
catalog, ARM64 A/B update apply, health-gated blessing, and clean-checkout image
fixes. Use the newest run on the current remote head rather than treating that
historical run as current. **Never push while a CI run is in flight** — the
concurrency group cancels it.

---

## 2. Latency and memory — finish what is measured

This is first because the instruments exist, the numbers are recorded, and the
owner's two hardest rules (**least RAM possible**, **speed is table stakes**)
collide here. `tests/performance/README.md` carries the full reasoning.

### 2.1 Corrected latency instrument — complete
The replacement is implemented in this tree. It re-enters each configured
`qs IPC` toggle through Hyprland, timestamps `show()` and the compositor's
`openlayer` event inside the long-lived shell, and exposes the pair on the
surface's existing read-only IPC target. No polling process runs inside
`shell_map_ms`.

**Correction to the old diagnosis:** a keypress does spawn `qs`; every surface
bind is a Hyprland `exec` of that command. The product process belongs in the
path. The defect was the checker's repeated `qs` and `hyprctl` polling, not a
single process that only the checker used.

Completed by
[run 33024091202](https://github.com/smplify-mdm/punar/actions/runs/33024091202):
the surface exercise remained green, clock uncertainty is stated as `<2 ms`,
and the checker-only `hyprctl` calibration was 12 ms. Corrected eager
`shell_map_ms` baseline: overview 67 · notifications 69 · AI panel 73 ·
command centre 87 · System Control 116 · shortcuts 186. Full-path totals were
106–226 ms; the checker-only dispatch span was 39–41 ms.

**File:** `os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/punar/surfaces-check.sh`

### 2.2 Measured lazy-loading — both passes runtime-proven
[Run 33044217553](https://github.com/smplify-mdm/punar/actions/runs/33044217553)
fixed probe identity and measured the real `qs` executable on every sample.
Median isolated cost (`resident delta KiB · construct ms · first map ms`):

```
commandcenter 106982 · 41 · 128    systemcontrol 123032 · 59 · 148
shortcuts     117500 · 31 · 156    aipanel       111801 · 55 · 127
overview      121299 · 35 · 106
```

Those isolated deltas share Qt/Quickshell code and **must not be summed**.
Every construction median is 31–59 ms, so run 33050021488 proved that all five
user-invoked surfaces lazy-load and destroy themselves after their 300 ms close animation.
Their `IpcHandler`s stay resident in `shell.qml`: `state()` answers `closed`
and `residency()` answers `unloaded` without constructing the panel.

The first result was honest but modest: **1333 MB mean / 1337 MB max**, only 12 MB
below the preceding 1345/1348 MB run and still above the 1024 MB target. The
second pass separated the notification daemon from its visual ledger: the
service remains eager, while the PUNAR+SHIFT+N window joins the measured lazy
set. The canonical x86 desktop job in run 33273700091 measured **1311 MB mean /
1319 MB max** and proved the complete 122-assertion shell suite. Notification construction was
43 ms and first map 108 ms. This recovered another 11 MB without making its
first open perceptibly slower.

The third measured pass targeted the unaccelerated VM path identified by the
process attribution rather than removing user-facing compatibility. On
virtual adapters with no real GPU, Qt Quick now uses its built-in software
adaptation and Mesa's remaining llvmpipe pool is capped at two workers. Real
GPUs—including Raspberry Pi VC4—explicitly clear both overrides. The exact
native ARM64 candidate (`cf522b…d19133`) measured **1004/1005 MB**, a 206 MB
(17.0%) mean reduction from the comparable 1210/1213 MB baseline. Canonical
x86 KVM [run 33381573989](https://github.com/smplify-mdm/punar/actions/runs/33381573989)
measured **1116/1118 MB**, 195 MB (14.9%) below its preceding 1311/1319 MB
baseline. Both paths passed the formal budgets and full behavioral gate; all
780 milestone assertions, 122 surface assertions and 15 isolated surface
samples passed locally on ARM64. This meets the clean-VM target without disabling Xwayland,
audio, portals, polkit, alerts, approvals, the lock surface, or security
services. It remains VM-path evidence, not a bare-metal performance result.

The current-commit rerun is intentionally not hidden: shipping Arch image
`b601c4…d06bc` measured **1373/1376 MB** in run 33840661515 while its four
first-party services remained 10 MB. That is a 257 MB mean regression from
the 1116 MB historical result, below the 1536 MB hard ceiling but above the
target. The same-commit Debian/x86_64 candidate measured **1214/1220 MB**,
159 MB lower than the shipping Arch lane but still 190 MB above target. The
process inventories are retained in artifacts `9925605057` and `9925733843`;
the next performance pass must reduce the kernel/non-process remainder rather
than moving either threshold. Bisection now identifies physical-x86 firmware
commit `a8fb51d`: `Unevictable` rose by about 236 MiB while the desktop UKI
grew from 217.3 MiB to 444.3 MiB. The candidate image policy now asks mkosi 26
for its bounded, architecture-aware default boot-module set while retaining
the full module and firmware trees in the installed root. Static policy and
mkosi-summary checks pass. The exact local Apple-HVF ARM64 candidate
`a21e03a…c960ff` from `762a4a4` reduced the UKI to 79.6 MiB and measured
**933/939 MB** after the canonical stabilized window, with 25 MB combined
first-party PSS, 0.01% maximum first-party CPU, 73,728 first-party write bytes,
active zram, all M2–M10/M12 checks, 129 surface assertions and 15 isolated
surface samples passing. This is native-VM proof; canonical x86 CI and
physical-device evidence remain open.

**Never lazy-load:** bar and wallpaper (always visible); approval and alerts
(must appear **unbidden**); toasts and OSD (must receive events while closed);
lock (must never hesitate).

**Trap:** hoist each surface's `IpcHandler` **outside** its `Loader`, or
`state()` cannot answer `"closed"` without instantiating the thing it is
reporting on — which defeats the entire change and breaks 13 assertions.

### 2.3 Preserve the shortcuts cache while unloading its window — implemented
The shortcut visual tree constructs in **31 ms**; its larger 156 ms first-map
path is compositor/render latency, not a reason to hold roughly 115 MiB. The
`hyprctl binds -j` cache is now a tiny singleton, so the window unloads but the
one-query-per-session contract survives every reopen. `configreloaded` and an
explicit `shortcuts reload` remain the only invalidation paths.

### 2.4 Stabilized-idle CPU and writes — runtime-proven and gated

The existing RAM service now snapshots cgroup v2 CPU and write counters at the
boundaries of the same full 300-second window. It covers all four resident
daemons plus the timer-triggered reconcile and agent-scan work accumulated in
a persistent `punar-background.slice`. The slice has CPU/I/O weight 10 against
systemd's default 100, so periodic OS work yields under compiler, editor,
container or test contention without being artificially capped on an idle
machine.

Native runs hard-fail when any first-party cgroup reaches 0.50% of one CPU;
TCG numeric breaches remain labeled/warn-only. The latest DHCP-connected
Apple-HVF ARM64 candidate measured 1004/1005 MB RAM, 24 MB across all four
service cgroups, 0.01% maximum first-party CPU and 73,728 first-party write
bytes. The immediately preceding exact-method image measured 1210/1213 MB,
24 MB service PSS and 0.00% maximum first-party CPU. A native x86 KVM window also measured 73,728 bytes
across three durability-synced reconcile audit batches; the cross-filesystem
ceiling is therefore 98,304 bytes/five minutes, reserving one quarter of the
ceiling without hiding a sustained writer. Whole-guest writes remain context
because they include the journal, filesystem metadata and non-Punar services.
Missing counters, connected-idle facts or live zram fail on every accelerator.

The first x86 KVM run of that gate correctly failed: the then-current three
service cgroups were alive, but `cpu.stat`/`io.stat` were not exposed because
the units had implicitly inherited controller enablement on ARM.
`CPUAccounting=yes` and
`IOAccounting=yes` are now explicit on `punard`, `punar-agentd` and
`punar-secrets`; M12 applies the same accounting contract to `punar-netd`. A
host contract test pins the unit settings, and raw start/end counter snapshots
join the CI evidence. Native ARM64 and x86 confirmation now exist; emulated
TCG measurements remain labelled separately.

---

## 3. Unmanaged-first pass — complete and runtime-proven

`DESIGN_LANGUAGE.md` §8.1's word table is implemented across the CLI, command
center, explain cards and System Control. Run 33050021488 proved on a live
personal session that the Organization/enrollment rail is absent, Drift and
Policy remain findable under Security, and both the summary and capability
card render `DRIFT · MATCHES`. The daemon wire vocabulary deliberately remains
stable; translation happens at render.

**Rule:** personal words never presuppose an authority. `compliant → matches`,
`non_compliant → drifted`, `remediating → restoring`; section key
`COMPLIANCE` → `DRIFT`. Enrolled wording is unchanged.

**Trap:** `""` is *not* a state — it is the absence of a reading. Never let it
share a `case` arm with a real value; that exact bug made the command centre
read `LOCAL · COMPLIANT` on every personal machine.

---

## 4. Device classes — complete and runtime-proven

`docs/design/device-classes.md` is implemented. `punard` reads `MemTotal`, core
count, battery presence and display presence as read-only facts; its closed
classifier produces workstation, laptop or appliance and publishes the result
through typed IPC, CLI status and inventory.

**The shape matters.** Every capability today is read-write (`observe()` +
`apply()`). **Hardware is read-only** — you cannot apply RAM. So a device class
is an **observed fact that joins policy resolution as a source of defaults**,
outranked by explicit user preference and by org policy when enrolled. It is
not a capability with desired state.

**Classify by measurement**, never a model-name table: `MemTotal`, core count,
`/sys/class/power_supply/BAT*`, whether a display is connected. Three classes
only — `workstation`, `laptop`, `appliance`.

The `punard classify-device --force <class>` seam is typed and run for all
three branches by the M3 exercise. The same exercise asserts that none of the
three output documents contains a security/privacy exception. Run 33050021488
proved the complete path on the image.

---

## 5. arm64 / Raspberry Pi — install artifacts proven; physical Pi remains

**ADR-005 is Accepted for implementation: Debian, tracking pinned sid.** Not
testing — testing was measured 36 days behind on Chromium and structurally
blocked by a missing armhf build and an arm64 reproducibility regression.
ADR-006 is also Accepted for implementation: Raspberry Pi uses its native
partition-level `tryboot_a_b`, not third-party UEFI. Real-board reset,
watchdog and power-loss tests remain mandatory before a Pi support claim.

**Do not start an Arch ARM mirror.** That instruction was struck; its urgency
rested on an rsync capability never verified to exist.

**Generic native ARM64 lane now proven locally:** `os/images/arm64/` uses a
digest-pinned `debian:stable-slim` base old enough to be satisfiable, then
upgrades the complete builder and target from the single immutable sid
snapshot `20260820T000000Z`. Two clean minimal builds produced the identical
qcow2 SHA-256
`bab2aba756c8a21d8ddf592fe225aa17d757b0dbed5681f8db4830ceb93802fd`.
The minimal image booted AA64 systemd-boot → Debian kernel
`7.1.8+deb14.1-arm64` → real root → multi-user target in 11 seconds on Apple
HVF.

The same lane now builds a complete ARM64 desktop image: shared shell
and service content, Debian package/account/PAM and Chromium adapters, nine
native AArch64 Rust binaries, and a digest-verified ARM64 offline OCI base.
The latest exact image is
`08ae9697a6d414487b402b1f004d0f9017e627c758484037d6237771c8d7e2f2`.
On its fresh connected 8-GiB / 4-vCPU Apple-HVF proof, the usable desktop marker
arrived in **16 s** and all **713 M2–M10 assertions**, **122 shell-surface
assertions**, **5 wireless-posture assertions**, **15 isolated surface-cost
samples**, the live zram/network checks, and host schema replays passed. This
includes the full app lifecycle, firewall, policy, enrollment, container,
AI/privacy, expiring approval and detection exercises. The M2 graphics policy
also recognizes Debian's live `virtio_pci` spelling and has fake-sysfs
coverage for virtual, AMD, Intel and Raspberry Pi VC4 cases.

The final 2026-08-27 release rebuild adds the signed-catalog application path
without preinstalling third-party payloads and makes every discovery path
pointer-actionable. Its exact qcow2 is 995,295,232 bytes (949 MiB by `ls`,
960 MiB allocated by `du`; 33 GiB virtual) with SHA-256
`f9fe1b26888891cc3432121ed4f7ae1183570f1b9d31fe564ea3e8b8b4d00387`.
A clean Apple-HVF boot proved inline password-context validation, completed
onboarding, reached the desktop, opened Command Center by clicking the
top-left **PUNAR** target, and browsed five installed apps plus Spotify at
`PUNAR+S` → Applications. Pointer tests proved the Spotify row hands off
directly to its inspected card, the card opens `https://open.spotify.com/` in
Chromium app mode, and an installed Chromium row launches directly. The card
disclosed the ARM64 web fallback and community status. The native x86_64
catalog source is a commit- and metadata-digest-pinned Flathub Flatpak;
neither app payload is part of the base image.

The minimal ARM64 image now also carries the real four-partition foundation:
1 GiB ESP, populated 8 GiB slot A, empty 8 GiB slot B and 16 GiB shared btrfs
with isolated `/var`, `/home` and `/var/tmp`. A content-aware gate passed all
five layout groups, and the result reached `PUNAR_BOOT_OK` in about six seconds
under Apple HVF. The exact-head ARM64 release artifact rebuilt on 2026-08-27 is
950 MiB with SHA-256
`faf62850fd12cc476209af3750c86a7e0ec40b4bea2f41743a1a9b2830ef2db1`.
Its provenance records source commit `e03598ec`, Debian snapshot
`20260820T000000Z`, mkosi 26, and generic UEFI/QEMU ARM64 scope. Build outputs
remain intentionally ignored; source, pins, and build recipes are the durable
GitHub inputs.

The current fixture-free product candidate was rebuilt on 2026-08-31 from the
same pinned snapshot. `punar-release-arm64.qcow2` is **0.985 GiB allocated /
33 GiB virtual** with SHA-256
`3c82250e43b3923c40eb2a5165bf54f79af12e886bc3fe534d6db58b2db35bf9`;
its embedded provenance records source commit `e29edbd`.
`tools/test-release-onboarding-arm64.sh` booted that exact hash with a
disposable snapshot disk and emitted `PUNAR_ONBOARDING_OK`: the real keyboard
path created the first account, the one-time recovery receipt appeared, its
focused default action entered through the one-use PAM token, and the actual
desktop bar rendered. The proof retains only the untouched first screen and
post-login desktop; it never persists a password or recovery-code frame. This
closes the clean first-account journey for generic QEMU ARM64, not the
installer, encryption-at-install, x86 release-image parity or physical ARM.

**Common-substrate x86 desktop milestone, canonical CI 2026-09-04:** commit
`f679a26`, [run 33840661515](https://github.com/smplify-mdm/punar/actions/runs/33840661515),
job `100922123462`, moved the generic x86_64 minimal and desktop compositions
through the same pinned Debian sid snapshot as ARM64. The 355,205,120-byte
minimal candidate (`sha256:2085c8dba6a6b7e05ab75a85f5738a9f9f4e367f9fa90b2e76e94402c085345d`)
reached `PUNAR_BOOT_OK` in 10 seconds. The 1,578,369,024-byte desktop candidate
(`sha256:f09141e463ab3254365a30e5dbfa2b6cb27a27980b40df1ee75bb7dba97daf83`)
reached `PUNAR_DESKTOP_OK` in 18 seconds, passed every M2–M10/M12 exercise,
all 129 desktop-surface assertions, 5 wireless-posture assertions and 15
isolated surface-cost samples. Its stabilized KVM window measured **1214 MB
mean / 1220 MB max**, 10 MB combined first-party service PSS, 0.00% maximum
first-party CPU, 73,728 first-party write bytes and active zstd zram. The
surface proof explicitly confirms the user systemd manager sees Punar's
mutable application-handler defaults, closing the D-Bus portal/OAuth startup
race found by the preceding run. Artifact `9925733843` is the seven-day CI
candidate/proof bundle. The same run built and structurally validated a
3,220,754,432-byte Debian hybrid ISO
(`sha256:a239f1240483f327806dfd230b6be285030c328b4dbe123e157d9740f3c930c3`)
plus a 1,576,796,160-byte release qcow2
(`sha256:197d776d3c97312103e8842080bad9b7746208bc6330d4432b0e1f709ceee59e`).
The first downstream runtime attempt did not start QEMU: Docker had left the
clean-checkout output directory owned by root, so the host runner could not
create `installer-boot-proof`. The builder now returns the parent and both
installer proof directories to the host identity, with a static regression
contract. Optical/raw boot, encrypted installation and refusal parity remain
unproven until the corrected canonical rerun passes. Artifact `9926088074`
retains the exact failed-at-the-boundary candidate for diagnosis. The Arch x86
images remain the shipping regression baseline until installer parity
completes and the cutover is recorded.

The hosted `ubuntu-24.04-arm` pool does not consistently expose `/dev/kvm`.
Canonical run 33294648139 proved native image build, checksum, minimal ARM boot,
and automatic rollback, then twice spent one host hour under TCG advancing only
about 202 guest seconds; ordinary guest device deadlines expired before the
shared partition appeared. CI now keeps minimal boot/rollback under TCG, records
an explicit `accelerator-unavailable.txt`, and runs the full ARM desktop and
stabilized-idle gates only when native KVM is actually usable. This is an honest
infrastructure skip, not an ARM desktop pass; the full local Apple-HVF proof
above remains the current graphical runtime evidence.

An unchanged-input comparison found the ESP and root-slot regions stable but
the full qcow2 non-identical because btrfs assigns fresh UUIDs to the three
subvolumes. The filesystem/device identities are fixed; subvolume UUIDs are
not configurable at the pinned toolchain. Promotion therefore signs the exact
artifact and makes no bit-for-bit reproducibility claim.

**Scope boundary:** these results prove QEMU's generic ARM `virt` platform,
the A/B layout, inactive-slot apply, a healthy counted boot being blessed, and
the native Pi install-artifact software path described below. They do not prove
Raspberry Pi firmware/peripherals, a real GPU, Secure Boot, public installer
orchestration, or any physical ARM machine. Automatic fallback is now proven
on a disposable persistent copy by the four-boot ARM64 gate and by canonical
ARM64 CI in [run 33273700091](https://github.com/smplify-mdm/punar/actions/runs/33273700091).

**Next sequence:**

1. **Completed:** the native ARM64 desktop lane builds and the full Apple-HVF
   M2–M10/M12 plus RAM proof is recorded. Hosted ARM CI continues to run the
   graphical gate only when KVM is actually exposed and labels TCG skips.
2. **Desktop/runtime parity completed:** x86_64 now builds and boots the same
   pinned Debian substrate and passed the complete KVM desktop/performance
   gate in run 33840661515. The first downstream encrypted-installer job built
   and validated its final ISO, then exposed a host/container proof-directory
   ownership defect before QEMU launch. That boundary is fixed and
   regression-guarded; the corrected runtime rerun plus physical x86
   acceptance remain mandatory before cutover can become a hardware-support
   claim.
3. **Install-artifact component completed locally 2026-08-30.** The builder
   pins the official firmware commit plus critical and tree digests; stages
   all 1,909 byte-identical loadable modules into release root A; regenerates
   and inspects its dependency indexes; creates the matching dracut initramfs;
   and binds the 8 GiB root-A payload plus a reopened 256 MiB slot-neutral FAT boot image
   into the canonical signed manifest. Version `2026.08.30.4`, built from
   commit `708384d29076a384d7f707803b3a03b55a5f4e32`, independently
   reproduced raw-root SHA-256
   `780d679b4ee241d126a837d489ba94dbea11f69fab0f3ea462fbad731dd09827`,
   compressed-payload SHA-256
   `a77791001fce5cb3fe3e6e62f25e8dfa246b6d768fb2881fd7b894f36467d42b`,
   and bootfs SHA-256
   `5a1cbb4c7dd9bb6836c653617ac5030e355f8bf17791c9ce4bc5427b22d80391`.
   The independent audit mounted both artifacts read-only, counted all 1,909
   loadable modules, proved the root and boot initramfs copies identical, and
   verified the ephemeral Ed25519 signature. The corrected six-partition
   selector layout was rebuilt as `2026.08.30.5`: raw-root SHA-256
   `a976fe4d7d3d74d6b434154cc49a1a537cc578005696497237e762a706eba93e`,
   compressed-payload SHA-256
   `4d1514c8c83c0c9a3db250d9b402b90b92436c56103961deec6f6221b8756c0f`,
   and slot-neutral bootfs SHA-256
   `d1ffe4d8439824b1d0f0101e057babad0c4969c6789e57a65ad098feb549087f`.
   `punard::pi_update` now proves the internal inactive-pair transaction: it
   derives the running slot only from big-endian firmware device-tree facts,
   verifies the signed target-bound bundle before writes, streams only the
   inactive root/boot pair, fsyncs and re-hashes physical reads, validates the
   paired boot filesystem, re-reads the unchanged selector and durably records
   pending state. Candidate commit requires the expected tryboot identity,
   read-only paired root and all four health signals before retaining a
   verified selector backup and swapping ordinary/try partitions. Tests prove
   the known-good pair remains byte-identical. This is verified software-path
   evidence, not a production signature or booted-Pi claim. The typed public
   `update.*` daemon/CLI surface, reboot handoff and image health-unit wiring
   remain before this becomes user-operable.
4. Run ADR-006's reset/watchdog/power-loss matrix on a real supported Pi before
   advertising Raspberry Pi support.

---

## 6. Product gaps, by value

The desktop-field work is implemented: five typed
choices, Stillpoint as the original 3840×2400 default, exact asset hashes,
and no resident wallpaper process. It is not a substitute for the RAM work:
only the active raster is decoded, and Field remains the constrained-machine
vector choice. The new live contract is `docs/design/wallpapers.md`.

### 6.1 Installer and onboarding
`docs/design/installer.md`, `onboarding-flow.md`, and the backend notes in
`onboarding.md`. A real hybrid x86_64 installer ISO now boots its read-only
EROFS/volatile-overlay live root and completes the attended encrypted install in
KVM. This is production-path VM evidence, not a production-qualified
bare-hardware claim: USB-media behavior, physical firmware/storage, Secure
Boot, TPM enrollment, recovery on real hardware and the compatibility matrix
remain open. The prebuilt image is also A/B-shaped.

**Installer-media milestone, canonical CI 2026-08-31:** commit `dda2bb1`,
[run 33442898971](https://github.com/smplify-mdm/punar/actions/runs/33442898971),
built `punar-installer-2026.08.31.1-x86_64.iso` at 4,425,449,472 bytes with
SHA-256 `33f48a6651900651c9e8452c07e15edc6d96253193076be8c5054096b34686d1`.
The final-artifact contract passed, then native KVM/OVMF reached
`PUNAR_INSTALLER_OK` in **7 seconds as optical media** and **6 seconds from the
same bytes as a raw drive**. This closes installer assertions I01–I05 for
generic x86_64 QEMU/OVMF. It does not prove a destructive install, encryption,
installed-system boot, USB media, Secure Boot, or physical firmware/hardware.

**Encrypted installed-system milestone, canonical CI 2026-09-01:** commit
`8a5afbc`, [run 33501585273](https://github.com/smplify-mdm/punar/actions/runs/33501585273),
is fully green across both Rust/contract architectures, ARM64 image and
automatic rollback, x86 image/boot, the graphical desktop and RAM budgets,
and the installer. The same **4,425,838,592-byte** hybrid ISO (SHA-256
`b8ec96a3502ec5968873480ae058998328da5d02adb3083e9ddb304d519929c4`)
booted as optical media in 16 seconds and as a raw drive in 12 seconds. Its
attended KVM install then passed **I08–I13 in 103 seconds** on a disposable
137,438,953,472-byte disk: plan-bound repartition, LUKS2 plus personal recovery
acknowledgement, Btrfs shared state, exact slot-A write/read-back, installed
seed and audit handoff, UEFI boot artifact, installed-system boot and an
independent GPT/LUKS2/Btrfs topology inspection. This closes the privileged
generic-x86 VM proof; it does not close USB/bare-metal qualification, Secure
Boot/TPM key custody, unattended answer media or physical recovery testing.

The first headless installer slice is now implemented and locally verified on
both ARM64 and x86_64: `install.targets` is live-mode-only read discovery, and
`install.plan` is a root-only, audited, non-mutating plan bound to the disk
serial, optional WWN, byte size and SHA-256 of its first/last 34 LBAs. The plan
contains the complete four-partition UEFI or six-partition native Raspberry
Pi layout and signed payload
identity; its recursively canonical JSON token changes when either GPT edge or
any field changes. Tests cover dm-backed boot-media exclusion, the answer-disk
exclusion, the 33 GiB arithmetic, reinstall-on-target versus foreign-Punar
refusal, strict live-mode gating, root authorization and audit outcomes. The
result schema is `schemas/install/plan.json`. The next zero-write boundary is
also implemented and locally green on ARM64 and x86_64: apply parameters are a
strict object with descriptor numbers but no secret bytes; a bounded
current-boot token registry admits only plans returned by explicit
`install.plan`; and preflight re-reads the serial, WWN, size, logical-sector
size, both GPT edges and signed release before a mutating executor may start.
Tests cover a same-sized physical-disk swap, a changed GPT edge and device-node
re-enumeration, each with the target byte-identical across refusal. The public
`install.apply` and `install.recovery_ack` methods are now registered after the
attended personal, organization-escrow and explicit unencrypted branches were
wired to that executor and installed-audit handoff. Agent attribution is
denied before uid, descriptors and disk access; one compare-exchange guard
admits one writer while status and acknowledgement remain responsive on other
connections. `unattended:true` now requires an exact-byte Ed25519 authorization
from the distinct install-answer trust root and binds it to the short-lived
plan, physical serial, release manifest, locale and optional OOBE digest before
transaction start. The live-only
`install.status` read side now exposes the same secret-free fixed nine-phase
state through IPC and an atomically replaced, world-readable
`/run/punar/install.json`; installed mode neither serves the method nor creates
the file. Apply-secret intake is also bounded and zeroizing: `punard` duplicates
the human root peer's passphrase and optional OOBE descriptors with
`pidfd_getfd`, never accepting secret bytes in JSON, argv, environment, status,
errors or audit. Unit and cross-architecture daemon tests are green; the live
installer VM still owes the kernel-privilege proof because ordinary container
seccomp blocks `pidfd_getfd`. Secret input is now restricted further to
anonymous memfds sealed against writes, growth and shrinkage; ordinary files
are refused, and the daemon rewinds the duplicated open description before
its bounded read. The recovery gate and the internal
verify/layout/recovery-enroll/write/re-read/UEFI-boot executor primitives now
exist. The signed plan binds the exact boot artifact as well as the root
payload, and the boot primitive re-verifies and atomically installs the
uncounted first known-good UKI through `bootctl --no-variables`, syncs the ESP,
and refuses to advance until it is unmounted. The seed/final-verification
primitive now unlocks and mounts only the shared `@var` subvolume, writes the
machine/device identities plus exact advisory seed/OOBE seam, reopens shared
data and root A read-only, and refuses digest, plan, owner/mode and unexpected
answer drift before success. Its no-NVRAM/digest/phase, fixed cryptsetup argv,
secret-pipe, encrypted/unencrypted seed and tamper-refusal tests are green; its
privileged real-vfat/LUKS/btrfs mounts still need the live installer VM gate.
The organization receipt gate is connected inside the executor. The native
Raspberry Pi boot-filesystem branch is also connected: its signed raw FAT
image is slot-neutral, bounded, fsynced, physically reread, mounted read-only
and validated for exact boot-A/root-A plus boot-B/root-B pairing before
`seed`. The selector-owned `autoboot.txt` is absent from that artifact and is
written and verified separately, so a future inactive boot-A write cannot
overwrite the last-known-good selector. The plan/schema/repart source now
carries the exact six-partition layout, and the LUKS/seed path derives data as
partition 6 rather than assuming UEFI's partition 4. The build-side raw FAT primitive now pins an official
`raspberrypi/firmware` commit, critical boot-file and complete board/module
tree digests; assembles the exact paired command lines, Pi 4/5 DTBs/overlays,
`kernel8.img` and caller-supplied initramfs; verifies that the root payload
contains identical loadable modules plus regenerated dependency indexes;
reopens the result; and rejects kernel or module drift in the native ARM
builder test. The full local install-bundle proof now stages the pinned tree
into release root A, generates and inspects the matching dracut initramfs,
builds boot A, checks both filesystems, and signs/verifies the canonical
manifest and both artifacts. The internal native Pi updater now verifies the
signed bundle before touching disk, derives the inactive slot from firmware,
writes and physically re-reads only that boot/root pair, keeps the selector
unchanged while staging, and permits a later selector swap only from the
expected tryboot candidate after read-only-root and four-signal health checks.
Its signed regular-file transaction test proves slot A remains byte-identical
while slot B is staged and the durable pending record is then consumed by the
candidate commit. Production key custody, the public `update.*` server/CLI
surface, reboot/health-unit integration, ISO assembly and the unattended Pi
lane remain open. The
hardware-report handoff is now closed in code and contract: PCI, USB and ARM
platform devices are classified from modalias/module binding and fixed-argv
firmware metadata; no serial/MAC/user data is collected; no usable graphics is
a blocker; partial/unsupported devices are warnings; and the fresh report is
durably written, digest-bound and read-only verified beside the seed while
physical qualification remains explicitly false.
The audit handoff is also closed inside the executor: the installed system
inherits the validated live device id, the live JSONL is accepted only when
every record has the exact twelve-field schema and that identity, unknown or
secret-shaped fields and duplicate ids fail closed, and the exact
`install.recovery_key/enrolled` plus `install.apply/success` terminal events
are appended without secret-bearing fields for encrypted installs; the
explicit unencrypted lane must omit, and may not falsely claim, recovery
enrollment. `/var/log/punar/audit.jsonl` is durably written at `0640`, then the
shared volume is unmounted, reopened
read-only and compared byte-for-byte with owner/mode checks before install
success. ARM64 tests prove the required three-event trail, secret-field
refusal and post-write tamper refusal. The public attended orchestration and
privileged generic-x86 installer VM are now runtime-proven through I08–I13.
The unattended signed-answer lane now generates the disk passphrase inside
`punard`, returns it and the recovery key only over the private disclosure
socket, and will not cross the recovery gate until `punarctl` atomically writes,
fsyncs, reopens and byte-verifies `custody.json` on `PUNAR_ANSWR`. The answer
schema, strict parser, no-secret negative fixture, service trigger and dedicated
custody output schema are green. **CANONICAL KVM PROOF:** all nine jobs in
[run 33822526403](https://github.com/smplify-mdm/punar/actions/runs/33822526403)
passed on 2026-09-04. Installer job
[100868070423](https://github.com/smplify-mdm/punar/actions/runs/33822526403/job/100868070423)
built the 4,427,489,280-byte ISO (SHA-256
`3cd4ec6de7372ae3fe0c323edd6c9a425e09e3444837a08ad50d84399d129c32`;
artifact `9919314120`), booted it as both optical and raw hybrid media, and
completed I08–I13 plus every I36 refusal and the unattended custody/secrecy
lane in 104 seconds under KVM. I36a refused the exact 20 GiB disk with the
33 GiB arithmetic; I36b refused a syntactically valid stale plan token as
`invalid_params`; I36c refused a correctly signed answer whose destruction
confirmation named the wrong disk; and I36d refused an agent-attributed apply
through the M9 authority path as `denied`. Guest-side SHA-256 checks immediately
before and after each refusal and host-side first-MiB comparisons around the
whole boot found both target disks byte-identical. The successful lane returned
and byte-verified removable custody, unlocked the installed LUKS2 volume with
the exact generated passphrase, inspected GPT/LUKS2/btrfs and the installed
seed, and found neither generated secret in live or installed logs/state. This
closes I36 in the privileged generic-x86 VM fixture; physical-device and
production key-custody claims remain open.
The origin is fail-closed too: `install.plan` does not return a usable token
unless its success event has been durably appended, so a full/unwritable audit
filesystem is discovered while the target disk is still byte-identical.

The executor's compressed-versus-written identity ambiguity is closed before
its first write: the signed release manifest now binds both the downloaded
`.zst` digest/size and the exact uncompressed root-slot digest/size. The
installer plan carries both identities. Download verification compares the
compressed pair; decompression and the post-`fsync`, device re-read compare the
uncompressed pair. The existing update proof harness enforces the same rule,
so installer and updater cannot accidentally compare compressed bytes with a
raw partition.

The pinned systemd 261.2 transaction probe also closed the 8 GiB temporary
payload problem. `systemd-repart` does not treat `--defer-partitions=root` as
permission to ignore a configured `CopyBlocks=` source, and `--key-file=-` is
not accepted. The fixed shipped `install-streaming/20-root-a.conf` overlay
removes `CopyBlocks=` without changing the partition ABI, and `/dev/stdin`
does accept the passphrase from a pipe. V-REPART now proves the exact merged
production definition set creates four partitions, leaves root A blank,
creates LUKS2+btrfs data, and opens it with the piped key. `punard` can
therefore own a bounded verified slot write without storing either the secret
or an 8 GiB raw payload on the live filesystem.

On 2026-08-30 that exact V-REPART mechanism moved behind `punard`'s internal
plan-bound executor. `prepare_disk_layout` re-reads the physical identity, GPT
edges and signed release at the destructive boundary; refuses a target that is
no longer a block device; merges only the immutable base, encrypted and
streaming definition layers through bounded `O_NOFOLLOW` regular-file reads;
and gives `systemd-repart` the passphrase only through anonymous stdin. It
captures neither output stream and removes the secret-free rendered set after
the fixed operation. A native ARM64 test proves overlay precedence, exact
argv, passphrase absence from argv, byte delivery through the pipe, cleanup
and phase ordering; a separate refusal test changes a GPT edge immediately
before execution and proves the target remains byte-identical. The shipped
definition layers are now staged into the shared desktop tree so a later live
profile inherits the same source of truth as the direct images. The attended
public method and full privileged KVM install proof have now landed. Physical
device qualification remains the boundary before this becomes a bare-hardware
compatibility claim.

The same internal transaction now stops honestly in `encrypt` after the fixed
repart operation and invokes pinned `systemd-cryptenroll --recovery-key` for
encrypted plans. The install passphrase reaches its anonymous stdin through
`--unlock-key-file=/dev/stdin`; the generated 256-bit modhex key is captured
only from bounded anonymous stdout into `SecretRecoveryKey`; and a bounded
`cryptsetup luksDump --dump-json-metadata` identifies exactly one typed
`systemd-recovery` keyslot without carrying key material, and a separate
bounded `cryptsetup luksUUID` read binds escrow to the actual LUKS volume
rather than the deterministic GPT partition UUID. The personal lane
then enters the existing no-timeout two-group acknowledgement gate and cannot
advance to `format` until confirmation succeeds. A native ARM64 test proves
the exact argv, both one-way pipes, secret absence from argv, typed keyslot,
paused status and eventual phase advance. The organization lane is now wired
into the same installer checkpoint: it fetches authenticated tenant material,
constructs the organization/key/device/LUKS/slot binding locally, uploads only
the HPKE envelope, and completes `encrypt` only after the exact signed receipt
verifies. Unavailable escrow, a mismatched token, or any verification failure
leaves status at `awaiting: organization_escrow_receipt`, refuses `format`, and
retains the only key in memory for retry. The real dev/CI control plane and
literal-secret negative assertions pass on native ARM64. Public apply now
supplies the trusted persisted enrollment organization and redacted device
credential before destructive work. The KVM personal-recovery path is now
proven end to end; the production transport/KMS boundary and a real enrolled
organization install remain open.

The personal recovery checkpoint is now a plan-bound in-memory state machine:
the full key and random challenge indices may leave it only through an output
pipe/Unix socket, the two answers return through a sealed memfd, wrong groups
or a different plan token cannot consume the gate, and there is deliberately
no timeout/default-continue. Cancellation drops the only
`PersonalRecoveryView` and zeroizes the key. The state machine, strict wire
types and public two-connection orchestration are unit/integration-proven; the
live installer VM still owes the kernel-level `pidfd_getfd` proof.

The executor-facing status coordinator is now implemented and locally green
on ARM64 Linux across the full workspace. It serializes each transition under
one lock and atomically publishes the same value to IPC and
`/run/punar/install.json`; phases cannot skip or move backward, slot A cannot
advance to re-read until its byte count equals the signed raw size, recovery
is an explicit waiting state, and terminal failures cancel any active recovery-key
checkpoint. Public failures use a fixed secret-free vocabulary and distinguish
pre-write refusal from a disk that may be partially prepared. Tests prove the
complete nine-phase success path, monotonic progress, recovery pause/resume,
secret-free failure, key cancellation and persisted/in-memory agreement. The
seed/final-verify executor half is now closed internally: the platform-bound
data partition (4 on UEFI, 6 on Raspberry Pi) is
unlocked through one fixed `cryptsetup` argv and anonymous passphrase pipe;
only `@var` is mounted; a random machine identity, the validated live device
identity, a private Punar state directory, `seed.json` and an optional
byte-identical OOBE passthrough are durably written; then both shared data and
root slot A are reopened
read-only before success. The verifier binds the exact seed digest in daemon
memory, enforces plan fields, owner/modes and OOBE presence, and refuses
tampering or an unrequested answer file. Native ARM64 unit tests prove the
fixed unlock/close argv, secret absence from argv, exact seed content/modes,
successful closure and both refusal paths. Public organization/enrollment
orchestration, production Raspberry Pi bootfs assembly, live mount proof and
live descriptor-duplication proof still remain before `install.apply` is
registered. Hardware reporting is no longer in that remainder: its bounded
PCI/USB/platform observer, ARM-aware categories, strict schema, plan-time
graphics blocker/warnings, privacy exclusions, installed-state copy and exact
read-only digest verification are locally green on ARM64 and cross-check on
x86_64. Neither is the audit handoff: its identity-bound exact-schema copy,
terminal-event append, durable write and read-only byte verification are
unit-proven; I35 remains open until the public unattended lane exists.

The encryption seam is now materially ahead of the installer. On 2026-08-27
the pinned ARM64 systemd 261.2 spike created a real LUKS2 volume, enrolled a
typed 256-bit `systemd-recovery` keyslot and opened the filesystem with that
key without printing or persisting it. `punar-recovery` implements the
zeroizing personal one-screen display/copy + two-random-group confirmation
and the managed RFC 9180 HPKE envelope. `punard` wraps locally, uploads only
ciphertext and verifies an exact signed receipt; the real dev/CI Smplify mock
proves device-token binding, separate recovery-release RBAC, required reason
code and append-only audit. The installer now holds that verified receipt as
its no-default-continue `encrypt` gate and reads the actual LUKS UUID before
constructing the binding. **This is now an attended generic-x86 VM install
claim, not an enterprise key-custody or bare-hardware claim:** real portal
IdP/step-up, tenant KMS/HSM custody and rotation, TPM sealing, Secure Boot keys
and physical recovery remain open.

The owner has now simplified the interaction contract. The required path is
one account card with exactly three user-provided values: username, password,
and device name; password confirmation is verification, not another value. A
compact recovery receipt follows in the same card. Do not resurrect M13's
seven-stage wizard: network, timezone, organization, privacy, theme, wallpaper,
AI, and updates belong after the usable desktop.

**Current runtime result:** transactional first-account creation, anonymous
stdin password delivery and immediate clearing, the real greeter's one-use PAM
handoff, A/B-shaped release storage, compact responsive focus scrolling and
the no-secret-frame ARM64 release gate are implemented and passed on
2026-08-30. The destructive encrypted installer, recovery acknowledgement and
installed-image proof were closed in canonical KVM CI on 2026-09-01; signed
unattended answer media, removable custody, literal-secret scanning and I36c's
zero-write refusal landed on 2026-09-03. Run 33822526403 closed I36a/b/d and
re-proved I36c plus the full unattended path on 2026-09-04. Still open are the
power-loss matrix, x86 substrate parity, logout/login human acceptance and
physical hardware.

**Closed design defect:** `install.targets` now excludes both the mounted live
medium (including block-device `slaves/` ancestry) and every device carrying
`PUNAR_ANSWR`. The fake-sysfs test exercises both directions; keep it when
the ISO lane adds real media.

### 6.2 `punarctl app`, Flatpak, and the Chrome command
`docs/design/third-party-apps.md`, `app-catalog.md`.

**Two planning rounds were REJECTED by all reviewers.** Read those objections
before re-planning. They proposed shipping hand-transcribed image digests,
sizes, publishers, and a `containment: sandboxed` **safety label** nothing in
the project could verify — a §1.22 violation on the one field that tells a user
an app cannot reach their files.

**Settled and built:** Flatpak is the primary third-party mechanism, because
ADR-003 requires app state to survive an image swap. The generated `fstab`
mounts the encrypted/shared `@var` subvolume at `/var`, so
`/var/lib/flatpak` is outside both immutable root slots. The image-layout gate
reopens that subvolume and verifies that slot A contains none of the mutable
trees. The signed catalog, typed install/remove/update methods, visual
Application Library, installed-state reconciliation, cross-workspace Open
behavior, and generic user-created web apps/browser contexts are implemented.
The remaining application work is the new browser/context VM gate, native
vendor-UI compatibility on both architectures, managed per-app configuration
adapters, and physical-device testing—not the persistence location.

**Also:** the UX reviewer's objection stands — spec §12.2's worked example is
typing `> install Firefox` into the **command centre**, and non-negotiable 17
is *"do not rely on the terminal"*. A CLI-only answer is not the product.

### 6.3 Execution trust
`docs/design/execution-trust.md`. fanotify `FAN_OPEN_EXEC_PERM` inside
`punard`; `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` is verified present.

**This widens `punard` to `CAP_SYS_ADMIN`** — a real privilege increase,
recorded in the design rather than hidden. Two design claims were **falsified
before implementation** and must stay falsified: Chromium on Linux writes **no**
provenance xattr, and IMA/EVM is **not** compiled into Arch's kernel.

### 6.4 Developer workstation: Slack, local Kubernetes, VMs
The owner's ask: *"support slack, support containers to deploy kubernetes apps
locally like our smplify deployment and other VMs."*

- **`kind` on rootless podman** is the likely stack — `k3d` requires Docker,
  which Punar does not ship. `kind` is 10 MiB at the pin; `kubectl` is 85 MiB
  and is the largest single line item.
- **`punar-env` hardcodes `--network none`** (`crates/punar-env/src/podman.rs`),
  justified in M6 partly by *"no rootless-net helper in the image"* — **that is
  now false**, `passt` ships as a podman dependency. So a developer currently
  cannot install a dependency inside the one supported dev environment. Lift it
  deliberately, with policy.
- **`gtk3` already ships** (chromium depends on it), so the portal backend for
  screen-sharing is nearly free — check it, because "can you share your screen
  in a huddle" is a day-one blocker.
- **CI cannot prove most external-network behavior** (QEMU user networking,
  14 GB runner disk with `-snapshot`). M6 is the precedent for deterministic
  coverage: preload an OCI archive, `podman load`. Its project container is
  deliberately launched with `--network none`, so it cannot demonstrate
  "reach a service from the browser". Say so rather than implying otherwise.

### 6.5 M11 browser/web-apps · M12 network + relay
`docs/development/milestone-11.md`, `milestone-12.md`. M11 is now **partially
implemented**: the curated catalog, typed daemon/CLI calls, responsive Command
Center application library, and System Control Applications browse path expose
22 reviewed app identities, including clearly labelled official web entries and
separate native preview/beta entries for Claude and ChatGPT. Flatpak sources
are commit- and metadata-digest-pinned per architecture; unsupported ARM64
publisher clients use labelled Chromium web fallbacks. Vendor Debian sources
are downloaded only on demand, bound to an exact architecture/size/digest,
extracted without control scripts or privileged mode bits, registered through
a Punar-owned desktop entry, and launched with an isolated app home. This
backend is contract-tested; its real native UI remains in compatibility
testing until both architecture gates pass. The catalog now has explicit AI,
Developer, Diagnostics, Writing, Security, Browser, Communication, and Media
categories. Its first developer set includes VSCodium, Dev Toolbox, DBeaver,
HTTPie, Postman, Meld, and Podman Desktop; Logs, Mission Center, Wireshark,
Apostrophe, and KeePassXC cover troubleshooting, Markdown, and credentials.
The base desktop now also carries Geany, Files/Thunar with GVfs SMB, and a
small cross-architecture CLI troubleshooting set. Static/schema/QML gates are
green; the expanded catalog, editor launcher, file-manager behavior and core
Spotify/Chromium app-mode path passed both architecture lanes in canonical
[run 33273700091](https://github.com/smplify-mdm/punar/actions/runs/33273700091).
The card now completes the visual native-app lifecycle: installed applications
show **Uninstall**, the first click/Delete only arms an inline confirmation,
Enter or the second click executes the typed `punarctl --json app remove` call,
Escape cancels, and a failed verification explicitly leaves installed state
unchanged. The section 46 managed-policy bridge is also live: lower-rank policy
wins per application, required apps may install but may not be removed, denied
apps may not install, optional installs obey `allowUserInstall`, optional
removal stays user-controlled, and a missing managed opinion fails closed.
Malformed, duplicate or contradictory application membership refuses the
policy load/enrollment. Unit and real-daemon integration tests cover all four
decisions. The current working tree also implements the already-specified
`apps.update` method and `punarctl app update <id>|--all`: only installed native
catalog apps are eligible, target identities come only from the signed catalog,
managed policy is enforced per id, and the aggregate names updated/current/
failed outcomes. The Application Library checks live state, exposes an
accessible **Update all** control, shows indeterminate activity without
inventing a percentage, and keeps partial failures explicit. Rust integration,
static contract, QML lint, and the UI detector pass locally; a rebuilt image and
canonical VM transaction remain required. Managed per-app settings remain a separate typed-adapter milestone;
Punar does not project undocumented macOS/Windows vendor settings onto Linux.
Connected ARM/HVF testing also proved the corrected Firefox native-detail path,
including its pinned source and verified permissions; third-party native UI
compatibility remains open. Connected ARM/HVF testing later exposed a native
Electron OAuth defect: every callback launch entered a fresh PID namespace, so
the callback process could not join the primary app's `second-instance`
handoff. The current working tree retains PID isolation but gives each app one
private namespace-owning session and a `0600` callback socket; catalog and URI
scheme validation still run for every relay. Static contracts and Rust tests
pass locally. The live ARM VM then exposed a second, independent failure: its
image lacked the GTK portal backend, so `org.freedesktop.portal.OpenURI` was
absent and a later Google sign-in click could not open the browser. Injecting
the exact snapshot backend live restored OpenURI and opened the real Google
authorization page; both architecture profiles now include that backend and a
static gate prevents its removal. A rebuilt image plus a complete callback
round-trip and canonical dual-architecture CI are still required before closing
that compatibility gate.
The current working tree now implements generic web-app creation, persistent
launchers, isolated browser contexts, closed managed Chromium policy,
workspace-aware selection, clean uninstall/purge, and the complete M11 image
exercise. Host Rust, schema, shell, QML parser and static contract suites pass;
the feature remains **LOCAL-ONLY** until a rebuilt image produces the M11
runtime report and screenshot on both architectures. M12's implementation,
daemon/CLI/image integration and event-driven
reconciliation are complete: the same canonical run emitted `PUNAR_M12_OK`
with 66 assertions on x86_64 and ARM64 and closed DoD items 19 and 20 for
generic UEFI/QEMU. Physical NIC, Raspberry Pi and real relay behavior remain
separate production gates.
The private relay is `user-blocked.md` item 6 and is the largest item on that
list.

---

## 7. How to add a new in-VM check

Almost every task above needs one. The full recipe:

1. **Script** at `os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/punar/<name>-check.sh`,
   committed **mode 0755**. Always `exit 0`; the verdict is the last line of
   `/run/punar/<name>-report.txt` as `PUNAR_<NAME>_OK` / `_FAIL`.
2. **Unit** at `.../usr/lib/systemd/system/punar-<name>-check.service`.
   **Not enabled, no `.wants` symlink** — `idle-ram.sh` starts it synchronously.
   Choose `User=punar` for user-session things (shell IPC, the compositor) or
   root for system things (modprobe, D-Bus policy, `/var/lib`).
3. **Hook** it in `idle-ram.sh`, after the RAM sampling window.
4. **Gate** it in `tools/boot-test.sh`: a delivered `_FAIL` **or a missing
   report under KVM** must `exit 1`. A missing verdict once passed as a warning
   and hid a check that never ran.
5. **Export** the report in `boot-test.sh` (tar list **and** the guest-side copy
   loop — they are separate, and missing the second one silently drops the file)
   and in `.github/workflows/ci.yml`.
6. **Lint** it: add the path to the shellcheck list in `ci.yml`.

**Assertion rules** (`docs/development/checks-conventions.md`, binding): assert
the invariant that survives fulfilment, never the placeholder text. Prefer
relations over constants — several M10 assertions turned out to be wrong about
the *product*, not the reverse. Write a vacuity guard where an assertion could
pass against an empty set.

---

## 8. Definition of done for each change

- All gates green: `qmllint` (fails on **any** output), shellcheck, actionlint,
  `cargo fmt/clippy/test`, schemas, and the full CI run.
- New behaviour is **asserted on the running machine**, not on a config file.
- Anything unproven is **labelled** (spec §1.22). Anything simulated says so.
- The commit message explains **why**, and states plainly what was wrong before
  if it corrects something.
- No assertion was weakened to get green.
