# Punar — Build Queue

**Companion to [`HANDOFF.md`](HANDOFF.md).** That document explains *what Punar
is and how it works*. This one is *what to build next and how*.

**Read `HANDOFF.md` §3 (standing rules) and §11 (failure modes) first.** Several
tasks below exist because an earlier decision was reversed, and §11 lists
mistakes that each cost a full CI cycle.

---

## 0. The finish line

Spec §80 defines done as: a clean VM can do 26 things. **20 of the 26 are
already demonstrated** by the latest ARM64 candidate's 713 milestone
assertions, 122 desktop-surface assertions, 5 wireless-posture assertions and
15 isolated surface-cost checks. The genuinely open ones:

| # | DoD item | Status |
|---|---|---|
| 7 | launch browser / **web app** | **EXPANDED ARM64 GATE PROVEN LOCALLY; CANONICAL CI PENDING:** clicking the top-left **PUNAR** launcher, `PUNAR+Space`, or `PUNAR+S` → Applications exposes actionable installed/catalog rows. Spotify → architecture-aware app card → official Spotify web player in Chromium app mode passed by pointer; an installed Chromium row opened directly. The 2026-08-29 clean ARM64 gate also searched for and opened Geany, Neovim in Foot, and the real Thunar Files window, and represented all 22 signed-catalog products in the live model. Commit `2e317c572a8f92dfad1cd157352fdc8dda0eefcf` added the responsive icon-led library plus Telegram, Firefox, Element, Slack, and Discord; its x86 runtime surface passed in run 33146409332. The current catalog keeps Claude Web/ChatGPT Web distinct from Claude Desktop beta/ChatGPT Desktop preview. The on-demand vendor-package backend is locally contract-tested: exact origin/architecture/size/digest, no maintainer scripts, setuid/setgid removal, Punar-owned launcher, isolated app home, and reversible removal. Native third-party vendor UIs remain `COMPATIBILITY TESTING` until both architecture lanes install and launch them. Generic user-defined web-app install/context support remains M11 work. |
| 19 | enforce project network rule | **M12 CORE LOCALLY GREEN; VM GATE PENDING.** Typed zone/policy evaluation, nftables rendering, daemon/CLI/image integration and event-driven managed-session reconciliation are implemented and pass the Linux unit/clippy stage. |
| 20 | display local network activity | **M12 CORE LOCALLY GREEN; VM GATE PENDING.** Privacy-bounded connection observation and truthful CLI projections are implemented; current milestone images still need the complete runtime exercise. |
| 25 | demonstrate rollback/update mechanism | **LOCALLY RUNTIME-PROVEN; CANONICAL CI PENDING.** Signed apply already verified the inactive-slot write/readback/hash and health-gated blessing. On 2026-08-27, `tools/update-rollback-test-arm64.sh` then booted a disposable persistent ARM64 disk four times: an impossible root PARTUUID exhausted the pending UKI through `+2-1`, `+1-2`, `+0-3`; boot four skipped it and reached `PUNAR_BOOT_OK` from slot A. The proof also caught and fixed a real selection bug: counted releases must use systemd 261's assessment-aware `preferred` glob, not `default`. |
| 3 | remain within idle budget | 1322 MB x86 KVM / 1211 MB native ARM64 against a 1024 MB target; hard ceiling met, optimization continues |
| 10 | report compliance | works, but the *word* was wrong on personal devices — see §3 |

And spec §81 Test A is the real bar: *"If Smplify management were removed,
would an engineer still choose Punar?"* The answer must be yes. That is why the
unmanaged-first work in `HANDOFF.md` §3.3 is not cosmetic.

The update product is three-channel governed rolling: `stable` (default),
`dev`, and opt-in `edge`. All three deliver complete signed A/B images through
the same verification and rollback path; only promotion cadence and soak
differ. Project toolchain freshness belongs to `punar-env`, never a partial
host upgrade. The core apply, boot-counting, health-gate, blessing, and
automatic-fallback path is implemented and locally proven. Channel
transport/promotion, production key custody, and canonical CI coverage remain
unshipped.

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

The result was honest but modest: **1333 MB mean / 1337 MB max**, only 12 MB
below the preceding 1345/1348 MB run and still above the 1024 MB target. The
second pass separated the notification daemon from its visual ledger: the
service remains eager, while the PUNAR+SHIFT+N window joins the measured lazy
set. The green x86 desktop job in run 33078009194 measured **1322 MB mean /
1329 MB max** and proved 103 shell assertions. Notification construction was
43 ms and first map 108 ms. This recovered another 11 MB without making its
first open perceptibly slower.

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
Apple-HVF ARM64 candidate measured 1211/1218 MB RAM, 27 MB across all four
service cgroups, 0.00% maximum first-party CPU and 73,728 first-party write
bytes. The immediately preceding image measured 1200/1205 MB, 26 MB service
PSS and 0.01% maximum first-party CPU. A native x86 KVM window also measured 73,728 bytes
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

## 5. arm64 / Raspberry Pi — generic desktop proven locally; CI and Pi remain

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

An unchanged-input comparison found the ESP and root-slot regions stable but
the full qcow2 non-identical because btrfs assigns fresh UUIDs to the three
subvolumes. The filesystem/device identities are fixed; subvolume UUIDs are
not configurable at the pinned toolchain. Promotion therefore signs the exact
artifact and makes no bit-for-bit reproducibility claim.

**Scope boundary:** these results prove QEMU's generic ARM `virt` platform,
the A/B layout, inactive-slot apply, and a healthy counted boot being blessed.
They do not prove Raspberry Pi firmware/peripherals, a real GPU, Secure Boot,
an installer, or any physical ARM machine. Automatic fallback is now proven
on a disposable persistent copy by the four-boot ARM64 gate, but not yet by a
canonical remote run.

**Next sequence:**

1. Land the native ARM64 desktop lane and require its first complete
   `ubuntu-24.04-arm` M2–M10 + RAM gate to pass. Keep the x86_64 desktop gate
   green in the same change.
2. Move x86_64 to the same pinned Debian substrate after the ARM lane is
   canonical. The current Arch image remains the regression baseline until
   that crossing is runtime-proven; two production substrates are not
   accepted.
3. Generate the Pi two-boot/two-root/shared-data layout and software-test the
   state machine, labelled as QEMU evidence.
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
`onboarding.md`. **Nobody can install Punar on a real machine today** — the
only path is booting a prebuilt image. The prebuilt image is now A/B-shaped,
which removes the disk-layout prerequisite but does not make it an installer.
The missing installer blocks hardware testing, which blocks 9 of the
`user-blocked.md` items.

The first headless installer slice is now implemented and locally verified on
both ARM64 and x86_64: `install.targets` is live-mode-only read discovery, and
`install.plan` is a root-only, audited, non-mutating plan bound to the disk
serial, optional WWN, byte size and SHA-256 of its first/last 34 LBAs. The plan
contains the complete four-partition x86_64 or ARM64 layout and signed payload
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
`install.apply` method still remains deliberately unregistered until its
transaction exists, so this slice remains unable to write a byte. The live-only
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
its bounded read. The recovery gate,
partition/encrypt/write/re-read/boot/seed executor, ISO assembly and the
unattended VM lane are still next.

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

The personal recovery checkpoint is now a plan-bound in-memory state machine:
the full key and random challenge indices may leave it only through an output
pipe/Unix socket, the two answers return through a sealed memfd, wrong groups
or a different plan token cannot consume the gate, and there is deliberately
no timeout/default-continue. Cancellation drops the only
`PersonalRecoveryView` and zeroizes the key. The state machine and strict wire
types are unit-proven; executor/status/audit wiring and the live
descriptor-duplication proof remain before the methods are registered.

The executor-facing status coordinator is now implemented and locally green
on ARM64 Linux across the full workspace. It serializes each transition under
one lock and atomically publishes the same value to IPC and
`/run/punar/install.json`; phases cannot skip or move backward, slot A cannot
advance to re-read until its byte count equals the signed raw size, recovery
is an explicit waiting state, and terminal failures cancel any personal-key
checkpoint. Public failures use a fixed secret-free vocabulary and distinguish
pre-write refusal from a disk that may be partially prepared. Tests prove the
complete nine-phase success path, monotonic progress, recovery pause/resume,
secret-free failure, key cancellation and persisted/in-memory agreement. The
destructive executor, audit wiring and live descriptor-duplication proof still
remain before `install.apply` is registered.

The encryption seam is now materially ahead of the installer. On 2026-08-27
the pinned ARM64 systemd 261.2 spike created a real LUKS2 volume, enrolled a
typed 256-bit `systemd-recovery` keyslot and opened the filesystem with that
key without printing or persisting it. `punar-recovery` implements the
zeroizing personal one-screen display/copy + two-random-group confirmation
and the managed RFC 9180 HPKE envelope. `punard` wraps locally, uploads only
ciphertext and verifies an exact signed receipt; the real dev/CI Smplify mock
proves device-token binding, separate recovery-release RBAC, required reason
code and append-only audit. **This is component proof, not a shipping claim:**
installer/UI wiring, installed-image proof, real portal IdP/step-up, tenant
KMS/HSM custody and rotation are still open.

The owner has now simplified the interaction contract. The required path is
one account card with exactly three user-provided values: username, password,
and device name; password confirmation is verification, not another value. A
compact recovery receipt follows in the same card. Do not resurrect M13's
seven-stage wizard: network, timezone, organization, privacy, theme, wallpaper,
AI, and updates belong after the usable desktop. The backend still owes a
transactional account create, password secrecy, a real greeter/logout/login
loop, A/B persistence, negative scans, and rollback-on-failure proof.

**Closed design defect:** `install.targets` now excludes both the mounted live
medium (including block-device `slaves/` ancestry) and every device carrying
`PUNAR_ANSWERS`. The fake-sysfs test exercises both directions; keep it when
the ISO lane adds real media.

### 6.2 `punarctl app`, Flatpak, and the Chrome command
`docs/design/third-party-apps.md`, `app-catalog.md`.

**Two planning rounds were REJECTED by all reviewers.** Read those objections
before re-planning. They proposed shipping hand-transcribed image digests,
sizes, publishers, and a `containment: sandboxed` **safety label** nothing in
the project could verify — a §1.22 violation on the one field that tells a user
an app cannot reach their files.

**Settled:** Flatpak is the mechanism, because ADR-003 forces it —
`/var/lib/flatpak` is the only place a user-installed app survives an image
swap. **Not settled:** whether `/var/lib/flatpak` and `/usr/local` are actually
on shared storage. §1.7 of the design proposes it; **it is not built.**

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
green; the expanded catalog, editor launcher, and file-manager behavior passed
the clean local ARM64 VM gate on 2026-08-29 and remain pending in canonical CI.
Spotify's path is proven on a clean ARM64 release VM and the
expanded library passed its x86 runtime surface in run 33146409332. Connected
ARM/HVF testing then proved the corrected Firefox native-detail path, including
its pinned source and verified permissions; follow-up CI is pending. Generic web-app
creation, persistent launchers, browser contexts and the complete M11 check
remain open. M12's core, daemon/CLI/image integration and event-driven
reconciliation are locally green; its full in-VM enforcement/observation proof
still closes DoD items 19 and 20.
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
