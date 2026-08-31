# Image pipeline (Milestones 0–10 + native ARM64 migration lane)

How Punar's VM images are built and boot-tested, locally and in CI. The
pipeline now exposes three compositions from one config tree
([milestone-1.md](milestone-1.md) §3):

- **punar-dev** — the minimal Milestone 0 userspace on the production-shaped
  four-partition foundation (the `PUNAR_BOOT_OK` gate stays cheap and
  regression-isolated even though its disk now exercises A/B boundaries).
- **punar-desktop** — the graphical CI/demo workstation: the safe base plus
  the mkosi `desktop,dev` profiles. The desktop profile adds product content;
  the dev profile alone adds the fixed account, serial access, autologin,
  mocks, fixtures, markers and behavioral proof services. The workstation has
  Hyprland, punar-shell (Quickshell), foot,
  chromium, git/neovim/podman, pipewire, vendored fonts, and the
  `PUNAR_DESKTOP_OK` ready-marker / idle-RAM / artifact-export chain.
  Since Milestone 3 it also carries the Punar control plane —
  `punard`/`punarctl` compiled hermetically inside the builder container
  from the pinned snapshot's own Rust toolchain, plus nftables, the
  punar-base firewall ruleset, and the `punar-m3-check` in-VM exercise
  ([milestone-3.md](milestone-3.md) §7–§9). Milestone 4 adds the
  `punard-reconcile.timer`/`.service` drift trigger (vendor-enabled via a
  `multi-user.target.wants` symlink, 2-minute cadence), the reserved
  `/var/lib/punar/policy.d` tmpfiles entry (empty in the image —
  unmanaged-first), and the `punar-m4-check` in-VM exercise
  ([milestone-4.md](milestone-4.md) §10–§11). Milestone 5 adds the
  `punar-mock-smplify` dev/CI mock control plane (compiled alongside
  `punard`/`punarctl`; its unit is **never enabled** — no `[Install]`, no
  `.wants` symlink — and is started/stopped only by the M5 check), the
  Acme organization fixtures staged verbatim to
  `/usr/share/punar/fixtures/acme/`, and the `punar-m5-check` in-VM
  enrollment exercise ([milestone-5.md](milestone-5.md) §4, §10).
- **punar-release** — the `desktop` profile without `dev`: no fixed human
  account or hostname, locked root, no autologin/serial console, no mocks or
  test services. A finalize-time release policy checks those invariants and an
  architecture-reviewed complete system/user unit enablement manifest before
  UKI generation. Account creation belongs to onboarding.

The shipping x86_64 substrate follows
[ADR-001](../architecture/adr/ADR-001-distribution-substrate.md): minimal Arch
package payload, vendor-pinned snapshot channels and mkosi-built images. The
ADR-003 A/B disk foundation is now present in directly built images; update
write/bless/rollback remains a trajectory. [ADR-005](../architecture/adr/ADR-005-arm64-support.md)
accepts Debian pinned sid as the common destination; the separate native
ARM64 lane now produces both a minimal image and a complete generic-QEMU
desktop. The desktop has crossed the M2–M10 exercises locally; its first
canonical native CI run is still pending. The outputs are unsigned VM-only
qcow2s that
satisfy spec 76 Milestone 0
("reproducible build and VM boot") and spec 66 MVP ("VM image; repeatable
build; development VM"). CI facts and precedents come from
[research/crosscutting.md](../architecture/research/crosscutting.md).

## Initial M0/M1 verification snapshot (spec 1.22)

This table is retained as the dated initial implementation record; the current
ARM64 and CI status appears in the sections below. As of 2026-08-24, the
maintainer's host was an arm64 Mac with no local rust, qemu, or shellcheck:

| Piece | Status |
| --- | --- |
| Docker daemon + `--platform linux/amd64` emulation | verified locally |
| ALA snapshot `2026/08/20` reachable (`core.db` HTTP 200) | verified locally |
| Builder base image digest pull + pacman under Rosetta | verified locally |
| pacman alpm-sandbox failure under Rosetta + `DisableSandbox*` workaround | verified locally (reproduced, then fixed) |
| Builder container build (`builder/Containerfile`) incl. mkosi 26, qemu-img, ukify install from the pinned snapshot | verified locally (emulated) |
| `mkosi.conf` parses; all options land as intended (`mkosi summary` in the builder container) | verified locally (emulated) |
| `bash -n` on all three shell scripts; workflow YAML parses | verified locally |
| Full `mkosi build` producing the qcow2 | **verified in CI only — not yet run** (deliberately not attempted locally; see below) |
| QEMU/OVMF boot smoke test (`tools/boot-test.sh`) | **verified in CI only — not yet run** (no local qemu) |
| `rust` CI job (fmt/clippy/test on ubuntu-24.04) | **verified in CI only — not yet run** (no local rust) |
| shellcheck on all three scripts (`koalaman/shellcheck:stable` via Docker) | verified locally (clean); also enforced by the CI shellcheck step |
| Build-to-build reproducibility comparison | **not yet done** (inputs are pinned; outputs never diffed) |
| **M1** `mkosi summary` for BOTH images (`punar-dev` unchanged: no profile, no postinst, base extra tree only; `punar-desktop`: profile `desktop`, full §2.1 package set, both extra trees, profile postinst picked up, ImageId/Hostname overridden via CLI) | verified locally 2026-08-24 (emulated builder container, `PUNAR_BUILD_MODE=summary` — the same code path CI runs) |
| **M1** desktop staging (font sha256 manifest re-verified, Hyprland/foot/fontconfig configs, vendored fonts, punar-shell QML + tokens copied into the profile extra tree) | verified locally 2026-08-24 (ran inside the builder container; staged tree inspected) |
| **M1** `bash -n`/`sh -n` + shellcheck (`koalaman/shellcheck:v0.11.0`) on all touched/new scripts | verified locally 2026-08-24 (clean) |
| **M1** full `punar-desktop` mkosi build, greetd→Hyprland→quickshell session, `PUNAR_DESKTOP_OK`, screenshot, idle-RAM numbers, virtio-serial export | **unverified — CI (desktop-test job) is the arbiter**; graphics fallback chain documented in milestone-1.md §6 |

"Verified in CI only — not yet run" means: written against documented,
precedent-backed behavior (systemd's mkosi CI, the Android-emulator KVM
recipe), but no run of this repository's workflow has executed yet. The first
CI run is the arbiter.

## Components

| Path | Role |
| --- | --- |
| `os/images/snapshot.env` | The input pins: ALA snapshot date + builder base image digest. Single source of truth. |
| `os/images/builder/Containerfile` | Builder container: pinned Arch + mkosi 26 + UKI/filesystem tools + `rust` (1:1.97.1-1 from the same snapshot — compiles `punard`/`punarctl` for the desktop image; no rustup, single toolchain provenance, milestone-3.md §7). |
| `os/images/mkosi.conf` | Product-safe base image definition: minimal Arch payload (`base`, `linux`), UEFI/systemd-boot, UKI, no credential, hostname, autologin, or serial console. |
| `os/images/repart.d/install/` | Canonical four-partition contract: fixed ESP and root-slot sizes/identities plus shared btrfs state. `install-encrypted/` is the production LUKS2 overlay; direct VM images deliberately use the plaintext base while exercising the same mount boundaries. |
| `os/images/mkosi.extra/` | Base extra tree; intentionally contains no development marker after the profile split. |
| `os/images/mkosi.profiles/desktop/` | Product desktop packages, locked release greeter, session chain, product daemons/data, lean system/user presets, and generated desktop assets/binaries. Its postinstall creates only stable system groups/adapters and warms fonts. |
| `os/images/mkosi.profiles/dev/` | Development-only credentials, fixed `punar` account, serial console, autologin, mocks, fixtures, boot/desktop markers, performance probes, and M2–M10 exercise services. Never compose it into a release payload. |
| `os/images/mkosi.finalize`, `os/images/check-release-image.sh`, `os/images/expected-enabled-units.*.txt` | Release-tree firewall: rejects login credentials/users, autologin, serial/live flags, dev paths, NOPASSWD rules, and any unreviewed system or user unit enablement. `dev` compositions skip it explicitly. |
| `os/modules/desktop/`, `shell/punar-shell/`, `shell/theme/` | Source of truth for Hyprland config (`/etc/xdg/hypr/`), foot config (`/etc/xdg/foot/foot.ini`), fontconfig defaults + vendored fonts (`/usr/share/fonts/punar/`), the punar-shell QML (`/usr/share/punar/shell/`) and design tokens (`/usr/share/punar/theme/punar-tokens.json`). `container-build.sh` re-verifies the font sha256 manifest and stages these into the desktop profile's `mkosi.extra/` on every build — nothing is committed twice. |
| `os/images/scripts/container-build.sh` | Stages product assets/binaries into `desktop`, mocks/fixtures into `dev`, renders the repart set, builds, content-checks the raw A/B layout, converts to qcow2, and writes checksums/metadata. `PUNAR_IMAGES=dev|desktop|release|all`; historical `all` is the CI pair (`dev` + `desktop,dev`), while `release` is explicit. `PUNAR_BUILD_MODE=build|summary`. Crates are lockfile-pinned but fetched at build time. |
| `tools/render-repart-definitions.sh`, `tools/render-mkosi-repart.sh` | Deterministically merge base + overlay definitions and derive mkosi population rules without duplicating partition identity/geometry. The explicit merge is required because pinned systemd 261.2 gives the first repeated `--definitions=` directory priority. |
| `tests/images/repart-spike.sh`, `tests/images/check-repart-layout.sh` | V-REPART toolchain proof plus the raw-image content gate: exact GPT contract, root-A population and mutable-tree exclusion, empty root B, exactly three shared subvolumes, deterministic direct-image btrfs device identity, hardened mount options, and a UKI selecting literal slot A. |
| `tools/build-image.sh` | Host-side wrapper: builds the builder container and runs the containerized path with the repository mounted for desktop staging. `tools/build-image.sh [dev|desktop|release|all]` (default `all`). |
| `tools/boot-test.sh` | QEMU/OVMF headless boot smoke test against the serial console marker. |
| `os/images/arm64/`, `os/images/builder-debian/` | Native ARM64 minimal + desktop lane: digest-pinned Debian base upgraded wholly from one immutable sid snapshot, AA64 systemd-boot disk definitions, Debian desktop/package/PAM adapters, native AArch64 Punar binaries, per-architecture offline OCI fixture, deterministic development credentials and disposable-cache exclusions. This proves generic UEFI/QEMU, not Raspberry Pi hardware. |
| `tools/build-arm64-image.sh`, `tools/boot-test-arm64.sh`, `tools/demo-arm64-vm.sh` | Native ARM64 build wrapper, cheap AArch64 UEFI smoke test, and localhost-only interactive desktop launcher. The boot paths select HVF/KVM when available, otherwise label a TCG fallback, and retain serial proof. The architecture-aware `tools/boot-test.sh` runs the same full desktop gate on ARM64 and x86_64. |
| `.github/workflows/ci.yml` | Native Rust/contracts on pinned x86_64 and ARM64 runners; shipping x86 image/boot/desktop jobs; native ARM64 minimal boot plus full desktop M2–M10/RAM job. |

## How a build works

1. `tools/build-image.sh` sources `snapshot.env` and builds the builder
   container (`--platform linux/amd64` always — a no-op on x86_64 CI, Rosetta
   emulation on the Mac). The builder's own pacman is pointed at the same ALA
   date snapshot, so the toolchain is input-pinned too.
2. It runs `os/images/scripts/container-build.sh` inside that container.
   Before mkosi, the script derives a fresh definition set below `/run` from
   the canonical installer definitions; slot A is populated from the staged
   root and mutable `/var`/`home` content is seeded into shared subvolumes.
3. The container runs privileged because mkosi's sandbox and package manager
   need it in Docker, then executes
   `mkosi --force --mirror https://archive.archlinux.org/repos/<date> build`.
   mkosi installs `base` + `linux` with pacman, builds an initrd, assembles a
   UKI, installs systemd-boot into the ESP, and emits a GPT disk image via
   systemd-repart (offline; no loop devices).
4. Before conversion, `tests/images/check-repart-layout.sh` mounts each raw
   partition read-only and fails the build on a geometry, filesystem, mount,
   subvolume, inactive-slot or UKI-selector mismatch.
5. The raw image is converted to a compressed qcow2
   (`os/images/out/punar-dev-x86_64.qcow2`), plus `SHA256SUMS` and
   `build-info.txt` (snapshot date, mkosi/qemu-img versions, git SHA).
6. With `PUNAR_IMAGES=all` (the default), `desktop`, or `release`, product desktop content is
   staged (font manifest verified first; since M5 the Acme fixtures land in
   `usr/share/punar/fixtures/acme/`), `punard` + `punarctl` +
   `punar-mock-smplify` are compiled `--release --locked` with the builder's
   snapshot-pinned Rust and staged into the profile's `usr/bin/` (build mode
   only — summary mode never compiles), and mkosi runs a second time with
   `--profile desktop,dev --image-id punar-desktop --hostname punar-desktop` —
   scalar overrides on the CLI, so no profile scalar-merge ambiguity — and the
   result is converted to `os/images/out/punar-desktop-x86_64.qcow2`. Both
   builds share `CacheDirectory=cache`, so packages download once; the cargo
   home/target live under the same `os/images/cache` and ride the same CI
   cache entry. `PUNAR_IMAGES=release` instead composes only `desktop`, names
   the output `punar-release`, leaves the hostname/account unset for
   onboarding, and must pass the release finalizer before image generation.

Determinism posture (per ADR-001: input-pinned, not bit-for-bit): base image
by digest, packages from a date snapshot, `SourceDateEpoch` clamped to the
snapshot date, fixed literal partition UUIDs, and a fixed UUIDv5 for the
single direct-image btrfs device. Pinned systemd 261.2 passes the last value
through its documented `SYSTEMD_REPART_MKFS_OPTIONS_BTRFS` hook.

**Two unchanged ARM64 A/B builds were compared on 2026-08-27 and did not
match byte-for-byte.** `qemu-img compare` found the first differing byte
inside `PUNAR-DATA`; the ESP and both root-slot regions before it were
identical. Read-only inspection then isolated the remaining drift to the UUIDs
that btrfs assigns independently to `@var`, `@home` and `@var-tmp`. The btrfs
filesystem UUID and device UUID matched. `mkfs.btrfs` exposes a device-UUID
input but no subvolume-UUID input, so Punar does not patch checksummed btrfs
metadata after creation. The honest claim is **input-pinned with stable OS
payload and partition identities, not bit-for-bit reproducible disk output**.
Release promotion must continue to name and sign the exact built artifact.

Both containerized build lanes keep mkosi's sparse raw output on Docker's
native Linux filesystem and stream only the compressed QCOW2 through the
host-mounted `out/` directory. This is a correctness requirement on Docker
Desktop: handing the raw disk across filesystems can expand its 33 GiB virtual
size into a fully allocated host copy, while building the root tree directly
on VirtioFS fails because that mount cannot preserve the required POSIX ACLs.
Conversion writes a temporary QCOW2 and atomically replaces the prior artifact;
the exit trap truncates any disposable raw output before unlinking it.

The development image itself: UEFI-only, systemd, a 1 GiB ESP, populated 8 GiB root A,
empty 8 GiB root B and a minimum 16 GiB shared btrfs partition whose three
subvolumes mount at `/var`, `/home` and `/var/tmp`. The qcow2 stays sparse, so
that 33 GiB virtual floor does not allocate 33 GiB on the host. The UKI selects
root A by its literal PARTUUID. The image uses a serial console on `ttyS0`
(`console=tty0 console=ttyS0`), root autologin on console gettys, root
password `punar` (dev-image convenience, documented, not a secret),
`punar-boot-marker.service` prints `PUNAR_BOOT_OK` plus
`MemTotal`/`MemAvailable` after `multi-user.target` — the deterministic marker
the boot test waits for, and a coarse first data point for the Milestone 0
RAM baseline (a real measurement harness is future work). `linux-firmware`
is excluded: QEMU/virtio needs none of it and it is the largest single
package. **This image is VM-only; do not expect it to boot on hardware.**

## The punar-desktop image (Milestone 1)

Everything the minimal image has (including `PUNAR_BOOT_OK` — untouched),
plus the graphical workstation. Full decisions in
[milestone-1.md](milestone-1.md); the wiring as built:

- **Session chain** (§4): `greetd.service` enabled, default target
  `graphical.target`. `/etc/greetd/config.toml` autologins the dev user
  `punar` into `/usr/lib/punar/session.sh` once per boot
  (`[default_session]` = agreety fallback after logout). `session.sh`
  exports `XDG_SESSION_TYPE=wayland`, then its DRM policy selects graphics
  before Aquamarine starts: a virtual/fallback-only adapter gets
  `AQ_NO_MODIFIERS=1` + `LIBGL_ALWAYS_SOFTWARE=1`; any real DRM device wins
  and both forcing variables are cleared. The decision and driver names are
  recorded under the private session runtime directory. Software-rendered
  guests also receive a private two-line runtime config which sources the
  product config and disables compositor animations; real GPUs execute the
  product config directly and retain its short spatial motion. This avoids
  queueing transition frames behind QEMU's unaccelerated virtio framebuffer
  without weakening bare-metal rendering. It then executes Hyprland with the
  selected config. The serial getty
  autologin (ttyS0) remains as dev/CI fallback access. User `punar`
  (password `punar` — dev convenience, documented, not a secret) is created
  in the profile postinst with wheel/video/input/uucp groups and
  subuid/subgid ranges for rootless podman.
- **Shell**: Hyprland `exec-once` runs `qs -p /usr/share/punar/shell`
  (quickshell must be pointed at the installed QML — bare `quickshell`
  would find no config), the hyprpolkitagent user unit and a foot server,
  then `/usr/lib/punar/desktop-ready.sh`. The scratchpad window is created
  on its first PUNAR+T and is not part of idle residency.
- **Ready-marker chain** (§7): tmpfiles creates `/run/punar`
  (0755 punar punar) → shell touches `/run/punar/shell-ready` when the bar
  is up → `desktop-ready.sh` (user session) waits on it, captures
  `grim /run/punar/screenshot.png` + `/proc/meminfo`, touches
  `/run/punar/desktop-ready` → `punar-desktop-marker.path` (root) fires
  `punar-desktop-marker.service`, which prints **`PUNAR_DESKTOP_OK`** +
  meminfo to the serial console and starts `punar-idle-ram.service`.
- **Idle-RAM + export** (§8–§9): `idle-ram.sh` runs the canonical
  PERFORMANCE_BUDGETS method (10 min stabilize, then 5 min sampling
  `MemTotal-MemAvailable` every 10 s), prints
  `PUNAR_RAM_MEAN_MB=<n> PUNAR_RAM_MAX_MB=<n>` to the console, then tars
  `/run/punar` base64-encoded onto the `punar.export` virtio-serial port
  between `PUNAR_EXPORT_BEGIN`/`PUNAR_EXPORT_END` sentinels (skipped
  gracefully when the VM lacks the channel).

**Honesty (spec 1.22):** QEMU 11.1.0 on this Apple-Silicon host exposes
`virtio-gpu-pci` but no virgl device or accelerated Cocoa backend. HVF makes
guest CPU execution native-speed; presentation is still a software-rendered
framebuffer, so local VM smoothness is not a bare-metal GPU measurement. The
software path removes compositor transition work for responsiveness. The
virtio-vga + llvmpipe path and full desktop
behavior suite are runtime-gated in CI. Hardware selection has deterministic
fake-sysfs coverage (no device, virtio, AMD, mixed virtio+Intel and
simpledrm+VC4), including the software-only motion overlay, while the VM's M2
exercise proves the live virtio branch.
No real GPU has run Punar yet, and `linux-firmware` remains absent, so this is
not a bare-metal support claim. Config validation still includes `mkosi
summary`, exact-version `Hyprland --verify-config`, foot checks and pinned
shellcheck; milestone-1.md §6 records the rendering fallback chain.

## The M3 control plane in the image (Milestone 3)

Full decisions in [milestone-3.md](milestone-3.md) §7–§9 and
`docs/api/ipc.md`; the wiring as built:

- **Binaries:** `/usr/bin/punard` + `/usr/bin/punarctl`, compiled inside the
  builder container by `stage_punar_binaries()` (hermetic in-container
  build — same pinned snapshot toolchain, `rust 1:1.97.1-1`; crates.io
  pinned by `Cargo.lock`, `--locked`), staged gitignored into the desktop
  extra tree.
- **Service:** `punard.service` (`Type=simple`, `ExecStart=/usr/bin/punard
  run`, `NoNewPrivileges`/`PrivateTmp`/`ProtectHome`; deliberately NOT
  `ProtectSystem` — it writes `/etc/hostname` and `/etc/localtime`),
  enabled by the vendor-level `multi-user.target.wants` symlink in the extra
  tree (the M1 preset lesson — never postinst `systemctl`).
- **Directories:** `tmpfiles.d/punard.conf` — `/run/punard` 0750 root:punar
  (socket dir; deliberately not the punar-writable `/run/punar`),
  `/var/lib/punar` 0700 (desired.json, device-id), `/var/log/punar` 0750
  root:punar (audit.jsonl, written 0640 by punard).
- **Firewall:** package `nftables` (verified absent from base's dependency
  chain), vendored ruleset `/usr/share/punar/nftables/punar-base.nft`
  (inbound drop / outbound accept, idempotent via leading `destroy table`);
  `punard` applies it at boot reconcile — `nftables.service` stays disabled
  so the ruleset has exactly one owner. Netless CI VM unaffected
  (`-nic none`; loopback + established/related accepted).
- **In-VM exercise:** `punar-m3-check.service` (root oneshot, not enabled)
  runs `/usr/lib/punar/m3-check.sh`, started synchronously by `idle-ram.sh`
  after the M2 exercise and before the export: socket perms, typed-IPC
  status/list, root mutation + audit event, non-root denial (exit 3,
  section-73 voice), firewall drift report + real re-apply, audit schema
  shape, `nobody` connect rejection, `system.exec`/`shell.run` →
  `unknown_method`. Verdict `PUNAR_M3_OK`/`PUNAR_M3_FAIL` in
  `/run/punar/m3-report.txt`, gated host-side by `boot-test.sh`.
  Amended under M4 (milestone-4.md §10.4): its reconcile step now expects
  remediation, and it stops `punard-reconcile.timer` at its top for
  determinism.
- **M4 in-VM exercise:** `punar-m4-check.service` (root oneshot, not
  enabled) runs `/usr/lib/punar/m4-check.sh`, started synchronously by
  `idle-ram.sh` after the M3 exercise and before the export: timer
  enablement, layer stores, `policy effective`/`explain` over both personal
  source kinds, preference-layer set cycle, section 52 compliance in
  `status`, the timer-driven firewall-drift demo (`nft destroy` → table
  restored within 375 s + `reconcile.remediate` audit event), loop
  protection untriggered, unknown-path voice, no write-side policy method.
  Verdict `PUNAR_M4_OK`/`PUNAR_M4_FAIL` in `/run/punar/m4-report.txt`,
  gated host-side by `boot-test.sh` (milestone-4.md §10).
- **Services-RSS budget:** `idle-ram.sh` emits `PUNAR_SERVICES_RSS_MB`
  (summed PSS of the `punard.service` cgroup, PERFORMANCE_BUDGETS.md §2.3)
  right after the idle sampling window; `boot-test.sh` records it in
  `ram-report.txt`; `check-budgets.sh` gates it (fail > 150 MB, warn >
  100 MB; `absent` fails even under TCG).

## The M5 enrollment scaffolding in the image (Milestone 5)

Full decisions in [milestone-5.md](milestone-5.md) §4 and §10; the wiring
as built:

- **Mock control plane:** `/usr/bin/punar-mock-smplify` — a dev/CI mock of
  the Smplify control plane, compiled by `stage_punar_binaries()` alongside
  `punard`/`punarctl` and shipped in the image only because the CI VM has
  no network (`-nic none`) and the enrollment exercise needs an in-VM
  counterparty. Its unit `punar-mock-smplify.service` is **never enabled**
  (no `[Install]`, no `.wants` symlink — asserted by m5-check itself);
  only `m5-check.sh` starts and stops it, so it never runs during boot,
  the idle-RAM window, or steady state. Transport is a root-only UDS
  (`/run/punar-mock-smplify/api.sock`, `RuntimeDirectory` 0750 + socket
  0600 — never localhost TCP, spec section 61); the trust-boundary
  statement lives in the unit header and milestone-5.md §4.2. Its
  directories come from `RuntimeDirectory`/`StateDirectory` on the unit,
  deliberately not tmpfiles.d: `/run/punar-mock-smplify` should exist
  exactly while the mock runs (a stale socket path is honest
  "unreachable" for the offline exercise), and
  `/var/lib/punar-mock-smplify` (`StateDirectory`) persists across mock
  restarts, which the recovery and keeps-history assertions rely on.
- **Fixtures:** `fixtures/organizations/acme/*.json` staged verbatim to
  `/usr/share/punar/fixtures/acme/` by `stage_desktop_extra()` (gitignored
  staging, single source of truth in `fixtures/` — the same bytes host
  cargo tests and `./tools/validate-schemas.sh` check).
- **M5 in-VM exercise:** `punar-m5-check.service` (root oneshot, not
  enabled, 15 min bound) runs `/usr/lib/punar/m5-check.sh`, started
  synchronously by `idle-ram.sh` after the M4 exercise and before the
  export. It stops `punard-reconcile.timer` at its top (single-actor sync
  determinism) and restarts it at the end, and walks the full journey:
  mock discipline + personal pre-state → `enroll start acme.com` →
  0600 stores, token grep-absent everywhere → policy.d envelope with the
  embedded payload → spec-40 managed explain → org-pinned set behaviors
  (non-root exit 3 citing the org policy; root recorded-but-overridden)
  → category-only compliance/inventory asserted on the mock's RECEIVED
  files (exact jq key allowlists — spec 24/54) with the inventory hash
  gate → enrolled-bar screenshot `punar-m5.png` (grim under the session
  user, m2-check's session-env pattern) → offline: cached policy still
  enforced, transition-audited `enroll.sync` unreachable → recovery:
  exactly one new compliance line (latest-wins queue) → offline
  `enroll stop` → personal restore + `punar-m5-personal.png` → audit
  lifecycle + timer restored. Verdict `PUNAR_M5_OK`/`PUNAR_M5_FAIL` in
  `/run/punar/m5-report.txt`, gated host-side by `boot-test.sh` phase 7;
  the mock's `received-*.jsonl` are copied into the export as
  `m5-received-*.jsonl` (never `devices.json`, which holds the
  server-side token record).

## The M6 punar-env base image (Milestone 6)

Full decisions in [milestone-6.md](milestone-6.md) §6. `punar-env up`
(the M6 project-environment CLI) needs an OCI image to run, but the CI VM
has no network (`-nic none`), so the image is built **during the OS image
build** — where the pinned snapshot is reachable — and staged into the
desktop image for `podman load -i` at first use. The build step is
`stage_env_base_oci()` in `scripts/container-build.sh`, build mode only
(summary mode skips it, exactly like the binary compile):

- **One provenance.** The only input is the pinned ALA snapshot's
  `busybox` package (`busybox-1.36.1-4-x86_64.pkg.tar.zst`, `extra` repo)
  — filename + sha256 are recorded in the stage function and verified
  against the snapshot's PGP-signed `extra.db` (recorded 2026-08-25); the
  sha256 is re-checked on every build, cache hit or fresh download. The
  download rides `os/images/cache` (the same CI cache entry as the pacman
  and cargo caches). Rejected alternatives (skopeo from docker.io, alpine,
  a pacman-bootstrapped chroot, nested `podman save`) are in
  milestone-6.md §6.3 — each adds a second provenance, tens–hundreds of
  MB, or nested container tooling under the arm64 emulation path.
- **Minimal rootfs.** `/bin/busybox` (statically linked musl — asserted
  at build time with `ldd`, which must report “not a dynamic executable”;
  the documented contingency if a future snapshot changes this is adding
  the snapshot glibc, milestone-6.md §6.2) plus symlinks for the applets
  the M6 contract needs (`sh`, `sleep`, `cat`, `echo`, `ls`, `touch`,
  `env`, `id`, `uname`), `/workspace` and `/tmp` mountpoints, and
  `/etc/punar-env-base-release` (“`punar-env-base m6 <snapshot-date>`”)
  — the marker m6-check reads back from *inside* the running container,
  proving the staged archive is what ran.
- **Hand-assembled, deterministic OCI archive.** No docker/podman nesting
  in the builder: an **uncompressed** layer tar (gzip is avoided entirely
  — it embeds timestamps) built with `--format=posix --sort=name
  --numeric-owner --owner=0 --group=0 --mtime=@<snapshot-epoch>` and
  pinned pax headers (GNU tar's default extended-header name embeds the
  PID), sha256-addressed blobs, config/manifest/`index.json`/`oci-layout`
  emitted via `printf` with fixed key order, config `created` clamped to
  the snapshot date, and the ref annotation
  `org.opencontainers.image.ref.name=localhost/punar-env-base:m6` that
  `podman load` tags from. The result is **byte-identical across rebuilds
  of the same snapshot pin** (verified: two rebuilds, identical sha256);
  the build logs the archive sha256 for exactly that comparison.
- **Staged + digest note.** `usr/share/punar/oci/punar-env-base.tar`
  (mode **0644** — the rootless `punar` user must read it) in the desktop
  extra tree, gitignored like the shell QML and fixtures, alongside
  `punar-env-base.note.txt` recording ref, archive sha256/size, OCI
  manifest/config/layer digests, and the input package pin — itself
  deterministic (no build timestamp by design), and comparable against
  `podman images --digests` in the VM.
- **Size, bounded.** The archive is ~1.3 MB (measured 1,320,960 bytes for
  snapshot 2026/08/20); the build **fails** if it exceeds 16 MiB — a
  tripwire far below the ~80 MB milestone allowance, so accidental fat (a
  glibc contingency, a stray layer) is caught at build time
  (milestone-6.md §6.4).

Verified at implementation (2026-08-25, inside the builder container):
two rebuilds byte-identical; the snapshot's own podman 6.1.0 loads the
archive (`Loaded image: localhost/punar-env-base:m6`) with the loaded
manifest digest matching the staged note; the extracted rootfs executes
under chroot (release marker readable, applets present, `/workspace`
writable, `sh -c 'exit 42'` passes 42 through). `podman run` itself could
not be exercised under the arm64-Mac emulation path (crun's memfd
re-exec fails under Rosetta — a host-environment limit, per spec 1.22);
the in-VM m6-check is the authoritative `podman run` proof.

## The boot smoke test

`tools/boot-test.sh [image.qcow2]` (spec 74.3 "boot"):

- Boots headless: q35 + OVMF firmware (paths probed for Ubuntu, Arch,
  Homebrew, MacPorts), virtio disk, `-snapshot` (the artifact is never
  written), serial console to a log file, no display, no network.
- KVM policy: if `/dev/kvm` exists and is accessible → `accel=kvm`, 300 s
  default timeout. Otherwise → TCG software emulation with a visible warning
  (and a `::warning::` annotation in CI), 1200 s default timeout. Override
  with `PUNAR_BOOT_TIMEOUT` (seconds).
- Pass condition: `PUNAR_BOOT_OK` (primary) or a getty `login:` prompt
  (fallback) appears in the serial log within the timeout. On failure it dumps
  the last 80 serial lines and exits non-zero. It also fails fast if QEMU
  exits before any marker.

## CI (canonical)

`.github/workflows/ci.yml`, six job groups on pinned `ubuntu-24.04` or
`ubuntu-24.04-arm` — not
`ubuntu-latest`, because GitHub is migrating `-latest` labels during 2026 and
an OS pipeline should not float (crosscutting.md §2.1). Public-repo runners:
4 vCPU / 16 GB RAM / 14 GB SSD, with working `/dev/kvm`.

1. **rust** — `cargo fmt --check`, `cargo clippy --workspace --all-targets
   --locked -- -D warnings`, `cargo test --workspace --locked`.
2. **contracts** — `./tools/validate-schemas.sh` (all JSON Schemas + every
   fixture, including the negative fixtures, in a pinned python container).
3. **image** — pinned shellcheck (v0.11.0) on the pipeline and in-VM check
   scripts (including `m5-check.sh`), then `tools/build-image.sh` (the same
   containerized path as local), then uploads both image artifacts
   (qcow2 + SHA256SUMS + build-info.txt, 7-day retention). Docker caching of
   the builder image across runs is future work; the builder rebuild costs a
   few minutes of pacman installs per run.
4. **boot-test** — needs `image`; downloads the artifact, installs
   `qemu-system-x86` + `ovmf`, enables KVM for the runner user via the
   canonical udev rule (crosscutting.md §2.1), runs `tools/boot-test.sh`, and
   re-verifies the artifact checksum. If KVM is unavailable the script warns
   and degrades to TCG rather than failing.
5. **arm64-image** — runs natively on `ubuntu-24.04-arm`, builds the minimal
   and desktop images from digest/timestamp-pinned Debian inputs, verifies both
   checksums, smoke-boots the minimal disk, then runs the same M2–M10 desktop
   and idle-RAM harness through AArch64 UEFI/KVM. It retains both qcow2s and
   exported runtime proof. This is a generic ARM VM gate, not Raspberry Pi or
   bare-metal evidence.
6. **desktop-test** — needs `image`; boots `punar-desktop` through
   `tools/boot-test.sh --mode desktop` (PUNAR_DESKTOP_OK → idle-RAM →
   M2/M3/M4/M5 exercises → export → the four report gates), then the
   PERFORMANCE_BUDGETS.md gates, then uploads the screenshot artifact
   (M1 idle + M2 overview + M5 enrolled/personal) and the report artifact
   (ram-report + m2/m3/m4/m5 reports and snapshots, including the M5
   mock received-state copies + serial.log).

## Local use (arm64 Mac)

```sh
./tools/build-image.sh                    # build both images (slow: emulated)
./tools/build-image.sh dev                # just the minimal M0 image
./tools/build-image.sh desktop            # just the M1 desktop image
PUNAR_BUILD_MODE=summary ./tools/build-image.sh   # cheap: staging + `mkosi summary` only
./tools/boot-test.sh                      # needs qemu (brew install qemu)

# Native ARM64 path (fast on Apple Silicon)
PUNAR_ARM64_IMAGES=all ./tools/build-arm64-image.sh
./tools/boot-test-arm64.sh
./tools/demo-arm64-vm.sh                  # release image, native Cocoa on macOS
PUNAR_VM_DISPLAY=vnc ./tools/demo-arm64-vm.sh  # release image, localhost TigerVNC :5901
PUNAR_BUILD_MODE=summary PUNAR_ARM64_IMAGES=all ./tools/build-arm64-image.sh
```

What to expect, honestly:

- The build runs under Docker Desktop's Rosetta-backed `linux/amd64`
  emulation. It is slow (expect tens of minutes where CI takes minutes) and
  Rosetta has documented failure modes (crosscutting.md §2.3). Local results
  are for iteration only; **CI is canonical** and local emulated results are
  labeled non-authoritative per spec 1.22.
- Since M3 a local `desktop` build also compiles the two release binaries
  under emulation. Measured 2026-08-25 (arm64 Mac, Rosetta, exact pipeline
  commands in the builder container): **~50 s** compile after the crates.io
  fetch — the plan's +10–30 min estimate was far too pessimistic; the
  workspace dependency tree is deliberately small (budgets §6.2). The dev
  loop is unchanged: host-side `docker run rust:1 … cargo test` for code,
  `PUNAR_BUILD_MODE=summary` for image config (it never compiles).
- One Rosetta failure is already known and worked around: pacman 7's alpm
  download sandbox fails to install its seccomp filter under emulation
  (`error restricting syscalls via seccomp: 22`). The builder container
  disables the sandbox (`DisableSandboxFilesystem`/`DisableSandboxSyscalls`
  in the *builder's* pacman.conf only — signature verification is unaffected,
  and nothing of this ships in the image). mkosi generates its own pacman
  config for the target install, which may hit the same failure in a full
  local build — untested, because full local builds are out of scope; if it
  bites you, that is the expected place.
- A local boot test on the Mac runs under TCG only (Apple Silicon cannot
  hardware-virtualize x86); boot takes minutes. Not yet attempted locally
  (no qemu installed on the maintainer host).
- The native ARM64 lane does not use Rosetta. On Apple Silicon it builds in a
  `linux/arm64` container and boots QEMU's generic `virt` machine with HVF.
  Two clean 2026-08-27 **minimal** builds were byte-identical. A fresh native
  desktop run reached `PUNAR_BOOT_OK` in 7.997 seconds and
  `PUNAR_DESKTOP_OK` in 12.091 seconds; its M2–M10 services each passed
  locally. This is generic UEFI/QEMU desktop proof, not Raspberry Pi
  firmware/peripherals or real-GPU evidence; the first canonical ARM desktop
  CI run is pending.
- Cheap config iteration without building:
  `PUNAR_BUILD_MODE=summary ./tools/build-image.sh` — runs the desktop
  staging plus `mkosi summary` for both images inside the builder container
  (the exact code path CI uses), no image build.

## Updating the snapshot pin

Edit `os/images/snapshot.env` (both the date and, when deliberately moving
the builder base, the digest), and update `SourceDateEpoch` in
`os/images/mkosi.conf` to the new snapshot date. Since M6, also re-verify
the `busybox` filename + sha256 pin in `stage_env_base_oci()`
(`os/images/scripts/container-build.sh`) against the new snapshot's
`extra.db` — the punar-env-base archive is built from it. One review-visible commit =
one channel move. This is the manual precursor of ADR-001's promoted channel
snapshots.

## Current limitations / future work

- **Unsigned.** No Secure Boot, no signed UKIs, no sbctl key management yet.
  ADR-001 commits to mkosi v26 `uki-signed` variants + vendor keys; Milestone
  0 output is explicitly unsigned. Any SB/TPM demo in a VM must be labeled
  simulated (spec 1.22).
- **ALA direct, no vendor mirror.** Build inputs come straight from
  archive.archlinux.org. ADR-001 requires a Smplify-owned snapshot mirror and
  a signed vendor repo before anything user-facing; this pipeline pins but
  does not yet own its inputs. No user machine ever points at ALA.
- **No rollback layout.** Plain single-root disk (mkosi default layout), not
  the openSUSE-style btrfs+snapper bootable-snapshot layout ADR-001 specifies
  for MVP, and no A/B partitions. The A/B trajectory only needs this
  pipeline's *output* to become the A/B payload later; nothing here blocks it.
- **Installer media now exists; installation proof does not.** Canonical run
  33442898971 built and verified the 4.12 GiB hybrid x86_64 ISO and booted its
  live root under OVMF as both optical media and a raw drive. The destructive
  install, encrypted installed-system boot, physical USB and bare-hardware
  qualification remain separate work.
- **No budget measurement harness.** The boot marker's meminfo lines are a
  coarse signal, not the Milestone 0 resource baseline; a proper idle-RAM/CPU
  measurement pass against PERFORMANCE_BUDGETS.md is separate work.
- **Reproducibility unproven.** Input-pinned by construction, but no
  build-to-build binary diff has been performed.
- **Builder container not cached in CI.** Rebuilt each run from the pinned
  snapshot (correct, just slower); GHCR caching is an easy later win.
- **ARM64 scope is generic-VM today.** Native minimal and desktop builds,
  package/PAM/Chromium/OCI adapters, generic UEFI boot and local M2–M10
  behavior are proven. The first canonical ARM desktop CI run, Raspberry Pi
  image layout, real-board fault injection, firmware coverage and real GPU
  validation remain open.
