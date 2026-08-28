# Punar — Engineering Handoff

**For:** the agent or engineer taking over. Assumes **no access** to the
conversation that produced this state.
**Written:** 2026-08-26 · **Repo:** `github.com/smplify-mdm/punar` (Apache-2.0)
**Read §3 before changing anything.** Several rules there reverse decisions
that look correct, and §11 lists failures that each cost a full CI cycle.

---

## 1. What Punar is

A lightweight, keyboard-first, **AI-native**, privacy-first, enterprise-ready
Linux distribution. Two brands: **Smplify** is the commercial control plane,
**Punar** is the OS.

The product thesis (spec §81 Test B): *make existing 8–16 GB enterprise laptops
useful again*. Targets are developer laptops (x86_64 today) **and a Raspberry
Pi**, where the Pi is an **appliance / AI-inference device**, not primarily a
developer machine.

The authoritative spec is `docs/product/SPEC_v0.2.md`. Section numbers cited
throughout the codebase (`spec §60`, `§1.22`, `§6.3`) refer to it. It is the
final authority; where this document and the spec disagree, the spec wins.

**What makes it different from another Arch + Hyprland setup:** AI agents are
first-class OS principals with cgroup-attested identity, a local access ledger,
approval gates, and shadow-AI detection — 487 of the 760 green CI assertions
are that machinery.

---

## 2. Current state

**Last fully green canonical baseline:** run
[33050021488](https://github.com/smplify-mdm/punar/actions/runs/33050021488)
on `ba3dc945`, all seven jobs, including x86_64/ARM64 code contracts, the image,
minimal boot, the full graphical desktop, and all ten in-VM exercises. Newer
work on `origin/main` adds native onboarding, recovery, the app catalog, ARM64
A/B apply and health-gated boot blessing. Treat the newest workflow run on the
current remote head as authoritative; do not describe a newer head as green
because this historical baseline passed.

| Exercise | Assertions | What it proves |
|---|---:|---|
| M2 multitasking | 33 | tiling, layouts, scratchpads, named workspaces |
| M3 daemon + CLI | 28 | typed IPC, capability registry, audit |
| M4 desired state | 29 | policy merge, explain, drift remediation |
| M5 enrollment | 63 | mock control plane, enroll → managed → unenroll |
| M6 dev environments | 56 | rootless podman, offline `podman load` |
| M7 agent registry | 78 | cgroup-attested agent identity, classification |
| M8 access ledger | 136 | what an agent touched, schema-exact |
| M9 approvals + secrets | 138 | approval gates, short-lived credentials |
| M10 shadow-AI | 135 | periodic detection, anti-nag alerts, remote query |
| Desktop surfaces (live) | 64 | all 13 shell surfaces open/close/paint |

**Latest measurement:** idle RAM **1333 MB mean / 1337 MB max** (target 1024 —
never once met, not even at M1's 1162 MB), boot **20 s**, three daemons **7 MB**
PSS. Earlier comparable runs measured 1265–1302 MB.

**Latest per-process attribution:** shell 354 MiB · Hyprland 165 MiB ·
Xwayland 43 MiB · hyprpolkitagent 15 MiB · foot server 10 MiB. The shell
remains the largest actionable process cost; the first lazy pass saved only
12 MB whole-system, so a second measured pass is in progress rather than
claiming the target is solved.

**Measured isolated surface cost (KVM).** Run 33044217553 verified the probe
identity as the real `qs` executable on every sample. Medians are resident
delta KiB · construction ms · first map ms:

```
commandcenter 106982 · 41 · 128    systemcontrol 123032 · 59 · 148
shortcuts     117500 · 31 · 156    aipanel       111801 · 55 · 127
overview      121299 · 35 · 106
```

The isolated deltas share Qt/Quickshell code and are not additive. Since every
construction median is 31–59 ms, run 33050021488 proved all five panels unload
after close while their IPC contracts remain available. The shortcuts bind
table remains a tiny singleton, preserving one `hyprctl binds -j` query per
session. The working tree now applies the same split to the visual notification
ledger while leaving the event-receiving notification service resident; local
lint and the live unloaded → resident → unloaded lifecycle are green.

The native ARM64 update lane now has a local four-boot automatic-fallback
proof. A deliberately unbootable counted UKI transitioned through `+2-1`,
`+1-2`, and `+0-3`; boot four reached `PUNAR_BOOT_OK` from the permanently good
slot-A UKI. The proof found a real boot-selection bug: systemd 261's `default`
selector ignores assessment and can keep selecting `+0-N`; counted pending
releases must use the assessment-aware `preferred` selector. The gate is wired
into ARM64 CI but does not become canonical until its exact remote run passes.

---

## 3. Standing rules from the product owner

Not preferences. Several of these **reversed** decisions that had already been
made and defended.

1. **Always use the least RAM possible. User workloads own the machine; the OS
   earns every resident process, wake-up and megabyte.** This overrode a
   decision to keep shell surfaces eagerly instantiated. It also means a
   project-scoped convenience must release its processes and memory when that
   project closes, and an SDK does not belong in the base image merely because
   a developer might use it. See §7.2 and `PERFORMANCE_BUDGETS.md` §1.7.
2. **Speed is table stakes.** In tension with (1). The resolution is *measure,
   then decide per surface* — not pick a side. See §7.2.
3. **Unmanaged-first, and stronger than it sounds.** The OS must be excellent,
   secure and private when **not** enrolled, and **nobody may feel they should
   enroll for it to work**. Reconciliation and drift detection stay — they are
   good OS primitives — but calling them *compliance* was wrong, because
   compliance asserts conformance to an authority a personal device does not
   have. `DESIGN_LANGUAGE.md` §8 and §8.1.
4. **Punar is opinionated and adapts to the device.** It measures the machine
   and decides. No settings panel of knobs. No silent degradation. **It never
   trades a security or privacy guarantee for weaker hardware** —
   `docs/design/device-classes.md` §2, and the right-hand column of that table
   is non-negotiable.
5. **Never claim a simulated thing is real** (spec §1.22). **Never weaken an
   assertion to make it pass.** Both have been violated and caught in this
   repo; see §11.
6. **Governed rolling has two clocks.** The host moves only as a complete,
   signed A/B release on `stable`, `dev`, or opt-in `edge`; compilers, SDKs,
   AI runtimes, and services move per project through `punar-env`. Never use a
   partial host upgrade to satisfy a project toolchain request. See
   `docs/development/update-and-rollback.md` §0 Law 8 and §5.1.
7. **Enrollment must be possible and findable, but never pushed.** Exactly one
   pointer exists, on `punarctl enroll status`'s unenrolled branch — the
   surface a person reaches *by asking about enrollment*. No banners anywhere.
8. Nothing is published or announced. History rewrites and force pushes were
   sanctioned on that basis; that will stop being true.
9. **The primary modifier is the Punar key.** User-facing caps say `Punar` and
   written chords say `PUNAR + …`; the hardware definition is Windows / Meta.
   Hyprland's raw modifier token may exist in config and implementation notes,
   never as product vocabulary.

---

## 4. Repository map

```
crates/                   Rust workspace — 68,614 lines, ZERO reference Arch
  punard          13,472  the daemon: typed capability IPC, policy merge,
                          reconcile loop, audit, M9 approval engine
  punar-agentd    15,713  AI agent registry, access ledger, shadow-AI detection
  punarctl        11,628  the CLI; views.rs is the D-014 render layer
  punar-common    11,667  shared IPC types, descriptors, audit records
  punar-secrets    5,511  short-lived mock credential broker (M9)
  punar-env        4,727  rootless podman dev environments (M6), no daemon
  punar-mock-smplify 4,407 dev/CI stand-in for the Smplify control plane
  punar-policy       689  layered policy resolution
  punar-workspace    786  workspace state
  punar-netd          14  M12 placeholder, unimplemented

shell/punar-shell/        Quickshell/QML — 19,885 lines, ONE Arch mention (a comment)
  SystemControl    3,139  settings-as-capabilities (largest surface)
  Notifications    2,424  centre + toasts + OSD
  AiPanel          2,157  what AI has done on this device
  Theme            1,873  theme system + contrast validator
  Services         1,810  Status, Approvals, Alerts, Apps, WorkspaceState…
  CommandCenter    1,717  PUNAR+Space, natural language → typed capabilities
  Bar              1,380  menubar: identity, status cluster, clock
  Shortcuts        1,313  help overlay, generated from `hyprctl binds -j`
  Approval         1,052  the M9 gate
  Alert            1,006  M10 shadow-AI cards
  Overview           796  workspaces as projects
  Lock               762  session lock
  Wallpaper          262

os/                       image build (THE ONLY substrate-coupled layer)
  images/mkosi.conf              base image, Architecture=x86-64
  images/snapshot.env            ALA date pin (2026/08/20) + builder digest
  images/builder/Containerfile   build container
  images/scripts/container-build.sh  stages os/modules + shell into mkosi.extra
  images/mkosi.profiles/desktop/ the desktop profile + mkosi.extra tree
  modules/desktop/               hypr, foot, chromium, fonts, wallpapers

tools/     build-image.sh boot-test.sh qmllint.sh validate-schemas.sh
           demo-vm.sh punar-up.sh
schemas/   15 JSON Schemas, 132 validated documents
docs/      45 markdown files — see §12
```

---

## 5. Architecture, in the order you need it

**Everything privileged is a typed capability.** `punard` exposes NDJSON over a
Unix socket with `SO_PEERCRED`. **There is never a generic root RPC and never a
method that takes an arbitrary command, path or package name** (spec §60). Add
a method by extending the `Method` enum and `fn dispatch` in
`crates/punard/src/server.rs` (~line 860). The wire contract is
`docs/api/ipc.md`; it is **additive** and still `v: 1`.

**Capabilities are read-write.** Each backend in `crates/punard/src/backends/`
has `observe()` and `apply()` — firewall, hostname, timezone today. The
reconcile loop makes the world match the effective document and audits either
way. **Hardware is read-only** and therefore is *not* a capability; see §7.3.

**Policy is a layered merge.** Ranks include OS defaults, personal defaults,
user preference, temporary approved exception, and org policy when enrolled.
`punarctl policy explain <capability>` shows the whole resolution. An
unenrolled device never has an org layer — creating one is the §8 violation
that was already found and deleted once.

**AI agents are principals.** `punar-agentd` launches managed agents via
`systemd-run --user --scope --unit=punar-agent-<id>` and attributes activity by
**cgroup**, never by process name. Classification is computed by the daemon,
never claimed by the caller. An agent may never approve its own request.

**The shell is ONE process.** All live surfaces are `Scope`s inside a single
`punar-shell` client — one Wayland connection, one IPC socket, one set of
inotify watches. No wallpaper daemon, no notification daemon, no settings app.
State is watched with `FileView` (inotify), never polled — spec §6.3 forbids
polling loops.

**Every surface answers on the same socket:**
```sh
qs -p /usr/share/punar/shell ipc show
qs -p /usr/share/punar/shell ipc call <target> <verb>
```
Fourteen targets: `bar commandcenter systemcontrol notifications toasts osd
overview aipanel approval alerts shortcuts theme lock wallpaper`.

`wallpaper` is a finite five-choice preference. Stillpoint is the shipped
default; only the active 3840×2400 raster is decoded, and Field remains the
theme-derived ultra-lean vector. Source/rights records and exact hashes ship
beside the assets. No wallpaper daemon, scan, download, animation, or timer was
introduced.

**Images are built by mkosi** from a vendor-pinned Arch Linux Archive date
snapshot (`os/images/snapshot.env`). `container-build.sh::stage_desktop_extra`
copies `os/modules/desktop/` and `shell/punar-shell/` into the profile's
**gitignored** `mkosi.extra/` on every build — those trees are the single
source of truth; never edit the staged copy.

**ADR-003** makes an update an **A/B root-slot image swap**: two root
partitions, one UKI per slot on the ESP, `/var` and `/home` shared. **It is
ratified but NOT built** — `mkosi.conf` is a single `Format=disk` with no
repart config. DoD item 25 is honestly recorded as NOT MET.

---

## 6. How to run everything

```bash
# QML — pinned to the image's own Qt/Quickshell. FAILS ON ANY OUTPUT (see §11)
./tools/qmllint.sh

# JSON Schemas + fixtures
./tools/validate-schemas.sh

# Boot the newest CI-built image and open the viewer
./tools/punar-up.sh
./tools/demo-vm.sh <image.qcow2>      # a specific image
./tools/punar-screenshot.sh <shot.png> # exact running-guest framebuffer
./tools/punar-down.sh                 # graceful QMP stop
```

Rust gates run in a container — the maintainer host is macOS arm64 with no
local rust/qemu:

```bash
docker run --rm -v "$PWD:/w" -w /w rust:1 sh -c \
  "rustup component add rustfmt clippy && cargo fmt --all --check && \
   cargo clippy --all-targets -- -D warnings && cargo test --workspace"
```

Shellcheck (pinned v0.11.0) covers `tools/*.sh`, `container-build.sh`,
`punar-layout.sh` and every `usr/lib/punar/*.sh`.

**CI jobs:** `rust` · `contracts` · `image` (builds both qcow2s, runs qmllint) ·
`boot-test` (minimal image smoke) · `desktop-test` (the graphical gate: idle
RAM, per-process PSS, all ten in-VM exercises). A run takes ~45–60 min;
`desktop-test` dominates.

**Never push while a run is in flight** — the concurrency group cancels it.

**On the demo VM:** it is TCG-emulated x86_64 on Apple Silicon and is **~5×
slower than KVM** (measured: 597 ms for an IPC round trip vs 112–125 ms in CI).
It feels sluggish and that is mostly the emulator. This is also the most
tangible argument for ADR-005.

---

## 7. Work queue, in priority order

> **The executable version of this section is [`BUILD-QUEUE.md`](BUILD-QUEUE.md)**
> — every task with its files, the pattern to follow, its acceptance criteria
> and its traps, plus the recipe for adding a new in-VM check. What follows is
> the summary.

### 7.1 Handed-off commits pushed
`origin/main` is the durable source of truth. The handed-off work, device
classes, personal rolling-update controls, latency/memory follow-ups, verified
desktop-field work, native onboarding, recovery, app catalog, and ARM64 A/B
update path are pushed. Before handoff, require local `HEAD` to equal
`origin/main` and consult the newest workflow run for that exact remote commit.

The 2026-08-28 application-library batch is the next durability checkpoint: it
groups Foot's helper desktop entries into one Terminal product, adds local
freedesktop/catalog icons, and exposes six common apps in one responsive
Command Center browse mode. Do not claim this batch as pushed or runtime-proven
until `BUILD-QUEUE.md` records its exact commit and workflow run.

### 7.2 Measured lazy-loading — first pass proven, second pass next
The corrected probe in run 33044217553 identified the real `qs` executable and
measured all five candidate panels. Construction medians are 31–59 ms and
isolated retained deltas are 106982–123032 KiB. Run 33050021488 proved command
center, System Control, shortcuts, AI panel and overview lazy-load in the real
image. The canonical idle result improved from 1345 to 1333 MB — real, but far
short of the target. The next pass lazy-loads only the NotificationCenter
visual tree; the notification daemon, toasts, and event listeners stay eager.

**Do not lazy-load these:** the bar and wallpaper are always visible; approval
and alerts must appear *unbidden*; toasts/OSD must receive events while closed;
the lock screen must never hesitate.

### 7.3 Device classes — complete
`docs/design/device-classes.md` is implemented as read-only observation, not a
mutable capability. `punard` classifies Linux facts into workstation, laptop,
or appliance, publishes the typed result, and provides an enumerated force seam
that the M3 image exercise runs through all three branches. The same check
proves no class carries a weaker security/privacy result.

### 7.4 Designed and unbuilt, roughly by value
- **Installer + onboarding** — `docs/design/installer.md`, `onboarding.md`.
  Nobody can install Punar on a real machine today.
- **Catalog breadth + broad-filesystem consent** — `docs/design/third-party-apps.md`,
  `app-catalog.md`. The typed `punarctl app` path and first curated apps now
  exist. Editors and creative tools that request `home` or `host` filesystem
  access remain deliberately excluded until their card has an explicit consent
  contract; never weaken the daemon's containment check merely to add rows.
- **Execution trust** — `docs/design/execution-trust.md`. fanotify
  `FAN_OPEN_EXEC_PERM` inside `punard`. `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`
  is verified present. This widens `punard` to `CAP_SYS_ADMIN` — a real
  privilege increase, recorded in the design.
- **Developer workstation: Slack, local Kubernetes, VMs.** `kind` on rootless
  podman is the likely stack (`k3d` requires Docker, which Punar lacks).
  **`punar-env` hardcodes `--network none`** and M6 justified it partly by "no
  rootless-net helper in the image" — **that is now false**, `passt` ships as a
  podman dependency. Wi-Fi landed but screen-share portals have not.
- **M11 browser/web-apps · M12 network/relay** — designed, unbuilt.

### 7.5 ARM64 substrate accepted; minimal native lane is build/boot proven
`docs/architecture/adr/ADR-005-arm64-support.md` — **Accepted for
implementation.** The common substrate is Debian pinned sid. The verified
x86_64/Arch desktop remains the regression baseline only during migration;
two production substrates are not the end state.

The owner confirmed on 2026-08-26 that ARM64 and Raspberry Pi are product
requirements. ADR-006 is also Accepted for implementation: Pi uses its native
partition-level `tryboot_a_b` path, not a third-party UEFI layer. No Pi support
claim exists until a physical board passes reset, watchdog and power-loss
fault injection.

At proposal time Punar was x86_64-only and ADR-001 had never evaluated arm64.
The repository now contains a separate minimal migration lane at
`os/images/arm64/`: a digest-pinned native Debian builder and target both use
snapshot `20260820T000000Z`; `tools/build-arm64-image.sh` produced a 335 MiB
qcow2; two clean builds were byte-identical at SHA-256
`bab2aba756c8a21d8ddf592fe225aa17d757b0dbed5681f8db4830ceb93802fd`;
`tools/boot-test-arm64.sh` then reached
`PUNAR_BOOT_OK kernel=7.1.8+deb14.1-arm64` in 11 seconds under Apple HVF.
That is generic UEFI ARM64 proof, not desktop, Pi or bare-metal proof.

**The cost of changing is low and was measured:** 88,499 lines of the product
are substrate-neutral; the substrate is ~218 lines of pipeline plus package
names and the boot chain.

**The second adversarial review has since completed** (7 agents, no failures)
and its findings are folded into **§A of the ADR**. All three attackers returned
**AMEND, then ratify**: Debian is the right destination, the original argument
was not sound. Read §A first — it corrects the ADR's own evidence.

The accepted decision and remaining boundary:

- **Option C (Debian) wins, tracking PINNED SID specifically.** Measured
  chromium age on arm64: sid **6.0 days** (identical version to Arch x86_64),
  testing **36 days** (8 releases behind, ~2.5× worse than the Fedora ADR-001
  rejected), Arch Linux ARM **14.9 days** (also worse than Fedora). Only sid
  passes ADR-001's own 7-day bar. Debian testing is structurally blocked — a
  *missing armhf build* and an *arm64 reproducibility regression* have held
  chromium out for five consecutive uploads and ~5 weeks.
- **All Punar components exist on Debian arm64 at versions identical to amd64**
  — hyprland 0.56.2, quickshell 0.3.0, greetd 0.10.3, foot 1.27.0 — plus every
  ADR-003 boot primitive natively, `debian:sid-slim` for arm64, and
  `snapshot.debian.org` consumed natively by mkosi.
- **Option B (Arch ARM mirror) is STRUCK, and so is the instruction to start it
  immediately.** Its urgency rested on an rsync capability never verified to
  exist. **Do not start a mirror.**
- **Two errors in the original ADR are corrected in §A**, one of them mine: the
  mkosi `die()` I cited as proof mkosi *refuses* snapshot-pinned Arch ARM is
  guarded by `if snapshot and not mirror` — it means "no public mirror exists",
  not "refuses". Supply a mirror and it proceeds.
- **Next:** put the minimal build/boot on `ubuntu-24.04-arm`, port the complete
  desktop and its Debian package/PAM/Chromium/OCI adapters, pass the graphical
  gate natively, then build ADR-006's Pi layout and take it through physical
  fault injection.

**Standing instruction from that amendment:** a fact about a platform is a
citation and an observation, or it is labelled unverified. Two rounds produced
two errors — an invented systemd option name and a misread build gate — and
both survived into documents because they sounded right.

---

## 8. Conventions that are enforced

**Assertions must be biconditional and probed against the running device.**
`docs/development/checks-conventions.md` is binding. The rule: *assert the
invariant that survives fulfilment, never the placeholder text.* Prefer
relations over constants — several M10 assertions turned out to be wrong about
the product, not the reverse.

**Design language is binding.** `docs/design/DESIGN_LANGUAGE.md`. Instrument
Sans + Geist Mono (both OFL, vendored). Paper `#FAF9F6` / panel `#08090A`.
Status colours are the only real colour. **Solid stroke = production claim,
dashed = simulated or unshipped.** §8 unmanaged-first, §8.1 the word table,
§8.2 device adaptation. Tokens: `shell/theme/punar-tokens.{json,css}`.

**Commit messages explain WHY, including what was wrong.** The history is a
design record. Corrections to earlier commits are stated explicitly rather than
quietly overwritten.

**Every new in-VM check needs:** the script (mode **0755**), a systemd unit
(not enabled — `idle-ram.sh` starts it synchronously), a `boot-test.sh` gate
where a missing verdict is a **hard failure** under KVM, and artifact export in
both `boot-test.sh` and `ci.yml`.

---

## 9. Security and privacy invariants

Never violate these; several are asserted in CI:

- Typed capability APIs only — never a generic root RPC (spec §60)
- AI agents may never approve their own requests
- Secrets never logged; the M9 broker retains only `sha256(token)`
- The AI ledger stays local and is never uploaded
- An unenrolled device carries **no** org-layer state, files, or vocabulary
- MAC randomisation per network (`AddressRandomization=network`),
  `SendHostname=no`, `IPv6PrivacyExtensions=yes` — a laptop must not be
  trackable between networks
- No enterprise policy on an unmanaged device — writing Chromium's
  `policies/managed/` would brand a never-enrolled machine "Managed by your
  organization"
- Firewall default-deny inbound; `established,related` accepted
- Never act on `docs/development/user-blocked.md` items: signing keys, TPM
  hardware, real control plane, IdP tenants, relay infra, legal, security review

---

## 10. What is real vs simulated

**Real and CI-exercised:** compositor, shell surfaces, terminal, browser
(native Wayland, flags applied on every launch path), link handling, theme
system, `punard`/`punarctl` and the typed capability API, desired state and
reconciliation, the mock-enrolment journey, dev environments, agent registry,
access ledger, approval gates, secret broker, shadow-AI detection, zram,
native onboarding and recovery, the first signed app-catalog vertical slice,
and generic ARM64 image build/boot. The six-app library expansion is source-
complete but must retain its separate pending CI status until its exact run is
green.

**Real but SIMULATED and labelled everywhere:** Secure Boot, TPM/measured boot,
the Smplify control plane (`punar-mock-smplify`), identity providers, the
private relay. Anything dashed in the design language is here by construction.

**Not built:** bare-metal installer media and install flow, a broad catalog and
broad-filesystem consent path, execution trust, generic user-defined web-app
install and browser contexts (M11), network policy and relay (M12), and physical
Raspberry Pi boot/peripheral/fault-injection proof. Generic QEMU ARM64 and A/B
partition/update primitives are real; they are not Pi support.

**Untested by CI:** networking — the gate runs the VM with `-nic none`, so DHCP
and resolved were reasoned about and first exercised by a human. Wi-Fi *is*
tested, using `mac80211_hwsim` to simulate hardware.

---

## 11. Failure modes that have already cost a cycle

- **Hyprland 0.55+ no longer live-switches `general:layout` through
  `hyprctl keyword`.** The command can return success while every workspace
  remains `dwindle`. Use one native `hyprctl eval 'hl.config({...})'` call and
  assert both `getoption general:layout` and each workspace's `tiledLayout`.
- **`qmllint` exits 0 while printing warnings.** `tools/qmllint.sh` therefore
  fails on any output. The first version of that gate read the exit code and
  reported "clean" one line below the defect it had just named.
- **Verify config option names against the shipped man page.** An invented
  systemd option (`UseprivacyExtensions`) would have shipped silently ignored,
  with the file claiming a privacy property it did not have.
- **`state()` is not pixels.** Surfaces bind windows to `root.windowVisible`, a
  *different* property from the `root.open` that `state()` reports. Assert
  `hyprctl -j layers` for the `WlrLayershell.namespace`, **in both
  directions** — several overlays hold `WlrKeyboardFocus.Exclusive`, so one
  reporting closed while still mapped is holding the keyboard.
- **A mapped layer is still not pixels.** Panels are `color: "transparent"` and
  animate in over 300 ms; capture only after the frame differs from a
  per-surface before-shot.
- **Check scripts must be committed `0755`.** A `100644` script failed
  `ExecStart`, produced no report, and the gate passed it as a *warning*.
  Missing verdicts are now hard failures.
- **Never `git add -A`.** It swept 27,945 build artifacts (~9 GB) into history;
  removal needed `git filter-repo` and a force push. `.gitignore` now globs
  `target-*/`.
- **mkosi applies Arch presets to `/etc` AFTER the extra trees**, wiping
  `systemctl enable` symlinks. Vendor `/usr/lib/systemd/system/*.wants/` only.
- **The image has no diffutils.** `cmp`/`diff` are command-not-found; compare
  with `sha256sum`.
- **CI runs the VM with `-nic none`.** Anything needing network cannot be
  gated. M6 is the precedent for working around it: preload an OCI archive and
  `podman load`.
- **The runner has a 14 GB disk and `boot-test` uses `-snapshot`**, so every
  guest write lands in a host temp file. A ~1 GB kind node image likely will
  not fit.
- **A vacuity guard is worth writing.** An M10 assertion read an ownership
  index *after* the purge that removes those rows; the guard refused to pass
  rather than silently testing nothing.

---

## 12. Where the truth lives

| File | What it is |
|---|---|
| `docs/product/SPEC_v0.2.md` | the authoritative spec; final authority |
| `IMPLEMENTATION_STATUS.md` | milestone status with CI run links |
| `docs/development/desktop-surfaces.md` | every surface, chord, real vs unavailable |
| `docs/development/testing-the-vm.md` | the ten-minute tour |
| `docs/development/user-blocked.md` | the nine items needing the owner |
| `docs/development/checks-conventions.md` | binding assertion rules |
| `tests/performance/README.md` | every measured number, with reasoning |
| `docs/design/DESIGN_LANGUAGE.md` | binding design language |
| `docs/design/wallpapers.md` | owner-approved static desktop-field catalog + resource contract |
| `docs/design/onboarding-flow.md` | binding one-card first-run interaction + acceptance contract |
| `docs/api/ipc.md` | the wire contract (additive, `v: 1`) |
| `docs/architecture/adr/` | ADR-001 substrate · ADR-002 binaries · ADR-003 A/B slots · ADR-005 required arm64 target / proposed substrate |
| `docs/development/milestone-*.md` | per-milestone design + build record |
