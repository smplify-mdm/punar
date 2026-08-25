# Image pipeline (Milestones 0–3)

How Punar's VM images are built and boot-tested, locally and in CI. The
pipeline now produces two images from one config tree
([milestone-1.md](milestone-1.md) §3):

- **punar-dev** — the minimal Milestone 0 image, unchanged (the
  `PUNAR_BOOT_OK` boot gate stays cheap and regression-isolated).
- **punar-desktop** — the Milestone 1 graphical workstation: the base config
  plus the mkosi `desktop` profile (`os/images/mkosi.profiles/desktop/`)
  adding Hyprland, punar-shell (Quickshell), greetd autologin session, foot,
  chromium, git/neovim/podman, pipewire, vendored fonts, and the
  `PUNAR_DESKTOP_OK` ready-marker / idle-RAM / artifact-export chain.
  Since Milestone 3 it also carries the Punar control plane —
  `punard`/`punarctl` compiled hermetically inside the builder container
  from the pinned snapshot's own Rust toolchain, plus nftables, the
  punar-base firewall ruleset, and the `punar-m3-check` in-VM exercise
  ([milestone-3.md](milestone-3.md) §7–§9).

Substrate per [ADR-001](../architecture/adr/ADR-001-distribution-substrate.md):
minimal Arch package payload, vendor-pinned snapshot channels, mkosi-built
images, with an A/B image trajectory. This pipeline is the Milestone 0 slice
of that: an unsigned, VM-only qcow2 that satisfies spec 76 Milestone 0
("reproducible build and VM boot") and spec 66 MVP ("VM image; repeatable
build; development VM"). CI facts and precedents come from
[research/crosscutting.md](../architecture/research/crosscutting.md).

## Verification status (spec 1.22)

Honesty first: the maintainer's host is an arm64 Mac with no local rust, qemu,
or shellcheck. What each piece has actually been exercised against, as of
2026-08-24:

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
| `os/images/mkosi.conf` | Base image definition: minimal Arch payload (`base`, `linux`), UEFI/systemd-boot, UKI, serial console, root autologin. Shared by both images. |
| `os/images/mkosi.extra/` | Files copied verbatim into every image; currently `punar-boot-marker.service` + its enablement symlink. |
| `os/images/mkosi.profiles/desktop/` | The M1 `punar-desktop` profile: `mkosi.conf` (the verified §2.1 package additions), `mkosi.postinst.chroot` (dev user `punar` + subuid/subgid for rootless podman, `systemctl enable greetd`, `graphical.target`, fc-cache), and `mkosi.extra/` — the versioned parts (greetd `config.toml`, `/usr/lib/punar/{session.sh,desktop-ready.sh,idle-ram.sh}`, `punar-desktop-marker.path/.service`, `punar-idle-ram.service`, tmpfiles `/run/punar`) plus build-time-staged parts (gitignored; see next row). |
| `os/modules/desktop/`, `shell/punar-shell/`, `shell/theme/` | Source of truth for Hyprland config (`/etc/xdg/hypr/`), foot config (`/etc/xdg/foot/foot.ini`), fontconfig defaults + vendored fonts (`/usr/share/fonts/punar/`), the punar-shell QML (`/usr/share/punar/shell/`) and design tokens (`/usr/share/punar/theme/punar-tokens.json`). `container-build.sh` re-verifies the font sha256 manifest and stages these into the desktop profile's `mkosi.extra/` on every build — nothing is committed twice. |
| `os/images/scripts/container-build.sh` | Runs inside the builder container: staging (desktop), since M3 `stage_punar_binaries()` (`cargo build --release --locked -p punard -p punarctl` with CARGO_HOME/target under `os/images/cache`, binaries installed 0755 into the desktop extra tree's `usr/bin/` — gitignored; **skipped entirely in summary mode**), `mkosi build` per selected image, raw→compressed qcow2, checksums, build metadata. `PUNAR_IMAGES=dev|desktop|all`, `PUNAR_BUILD_MODE=build|summary`. Honest hermeticity limit: crates.io is fetched at build time, pinned by the committed `Cargo.lock` (`--locked`); the runtime VM needs no network. |
| `tools/build-image.sh` | Host-side wrapper: builds the builder container, runs the containerized build with the **repo root** mounted (the desktop staging needs `os/modules` + `shell/`). `tools/build-image.sh [dev|desktop|all]` (default `all`). Identical path in CI and locally. |
| `tools/boot-test.sh` | QEMU/OVMF headless boot smoke test against the serial console marker. |
| `.github/workflows/ci.yml` | Jobs `rust`, `image`, `boot-test` on pinned `ubuntu-24.04` runners. |

## How a build works

1. `tools/build-image.sh` sources `snapshot.env` and builds the builder
   container (`--platform linux/amd64` always — a no-op on x86_64 CI, Rosetta
   emulation on the Mac). The builder's own pacman is pointed at the same ALA
   date snapshot, so the toolchain is input-pinned too.
2. It runs `os/images/scripts/container-build.sh` inside that container
   (`--privileged`: mkosi's sandbox and pacman need it in Docker), which runs
   `mkosi --force --mirror https://archive.archlinux.org/repos/<date> build`.
   mkosi installs `base` + `linux` with pacman, builds an initrd, assembles a
   UKI, installs systemd-boot into the ESP, and emits a GPT disk image via
   systemd-repart (offline; no loop devices).
3. The raw image is converted to a compressed qcow2
   (`os/images/out/punar-dev-x86_64.qcow2`), plus `SHA256SUMS` and
   `build-info.txt` (snapshot date, mkosi/qemu-img versions, git SHA).
4. With `PUNAR_IMAGES=all` (the default) or `desktop`, the desktop content is
   staged (font manifest verified first), `punard` + `punarctl` are compiled
   `--release --locked` with the builder's snapshot-pinned Rust and staged
   into the profile's `usr/bin/` (build mode only — summary mode never
   compiles), and mkosi runs a second time with
   `--profile desktop --image-id punar-desktop --hostname punar-desktop` —
   scalar overrides on the CLI, so no profile scalar-merge ambiguity — and the
   result is converted to `os/images/out/punar-desktop-x86_64.qcow2`. Both
   builds share `CacheDirectory=cache`, so packages download once; the cargo
   home/target live under the same `os/images/cache` and ride the same CI
   cache entry.

Determinism posture (per ADR-001: input-pinned, not bit-for-bit): base image
by digest, packages from a date snapshot, `SourceDateEpoch` clamped to the
snapshot date, fixed repart `Seed` for stable partition UUIDs. This should
make builds input-deterministic; **no two builds have been diffed yet**, so no
reproducibility claim beyond input-pinning is made.

The image itself: UEFI-only, systemd, serial console on `ttyS0`
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
  exports the VM graphics env (`AQ_NO_MODIFIERS=1`,
  `LIBGL_ALWAYS_SOFTWARE=1`, `XDG_SESSION_TYPE=wayland`) and
  `exec Hyprland --config /etc/xdg/hypr/hyprland.conf`. The serial getty
  autologin (ttyS0) remains as dev/CI fallback access. User `punar`
  (password `punar` — dev convenience, documented, not a secret) is created
  in the profile postinst with wheel/video/input/uucp groups and
  subuid/subgid ranges for rootless podman.
- **Shell**: Hyprland `exec-once` runs `qs -p /usr/share/punar/shell`
  (quickshell must be pointed at the installed QML — bare `quickshell`
  would find no config), the hyprpolkitagent user unit, a foot server +
  the pre-spawned scratchpad foot, then `/usr/lib/punar/desktop-ready.sh`.
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

**Honesty (spec 1.22):** all of the above is config-validated only
(`mkosi summary`, `Hyprland --verify-config`, `foot --check-config`,
shellcheck — see the verification table). No punar-desktop image has been
built or booted yet; the first CI desktop-test run is the arbiter, and the
virtio-vga + llvmpipe rendering path carries the documented fallback chain
(milestone-1.md §6).

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
- **Services-RSS budget:** `idle-ram.sh` emits `PUNAR_SERVICES_RSS_MB`
  (summed PSS of the `punard.service` cgroup, PERFORMANCE_BUDGETS.md §2.3)
  right after the idle sampling window; `boot-test.sh` records it in
  `ram-report.txt`; `check-budgets.sh` gates it (fail > 150 MB, warn >
  100 MB; `absent` fails even under TCG).

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

`.github/workflows/ci.yml`, three jobs on **pinned `ubuntu-24.04`** — not
`ubuntu-latest`, because GitHub is migrating `-latest` labels during 2026 and
an OS pipeline should not float (crosscutting.md §2.1). Public-repo runners:
4 vCPU / 16 GB RAM / 14 GB SSD, with working `/dev/kvm`.

1. **rust** — `cargo fmt --check`, `cargo clippy --workspace --all-targets
   --locked -- -D warnings`, `cargo test --workspace --locked`, with
   `Swatinem/rust-cache` caching.
2. **image** — shellcheck on the three pipeline scripts, then
   `tools/build-image.sh` (the same containerized path as local), then uploads
   `punar-dev-image` (qcow2 + SHA256SUMS + build-info.txt, 7-day retention).
   Docker caching of the builder image across runs is future work; the
   builder rebuild costs a few minutes of pacman installs per run.
3. **boot-test** — needs `image`; downloads the artifact, installs
   `qemu-system-x86` + `ovmf`, enables KVM for the runner user via the
   canonical udev rule (crosscutting.md §2.1), runs `tools/boot-test.sh`, and
   re-verifies the artifact checksum. If KVM is unavailable the script warns
   and degrades to TCG rather than failing.

## Local use (arm64 Mac)

```sh
./tools/build-image.sh                    # build both images (slow: emulated)
./tools/build-image.sh dev                # just the minimal M0 image
./tools/build-image.sh desktop            # just the M1 desktop image
PUNAR_BUILD_MODE=summary ./tools/build-image.sh   # cheap: staging + `mkosi summary` only
./tools/boot-test.sh                      # needs qemu (brew install qemu)
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
- Cheap config iteration without building:
  `PUNAR_BUILD_MODE=summary ./tools/build-image.sh` — runs the desktop
  staging plus `mkosi summary` for both images inside the builder container
  (the exact code path CI uses), no image build.

## Updating the snapshot pin

Edit `os/images/snapshot.env` (both the date and, when deliberately moving
the builder base, the digest), and update `SourceDateEpoch` in
`os/images/mkosi.conf` to the new snapshot date. One review-visible commit =
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
- **qcow2 only.** No installer ISO yet (spec 66 lists it for MVP; ISO output
  is an mkosi format away once needed).
- **No budget measurement harness.** The boot marker's meminfo lines are a
  coarse signal, not the Milestone 0 resource baseline; a proper idle-RAM/CPU
  measurement pass against PERFORMANCE_BUDGETS.md is separate work.
- **Reproducibility unproven.** Input-pinned by construction, but no
  build-to-build binary diff has been performed.
- **Builder container not cached in CI.** Rebuilt each run from the pinned
  snapshot (correct, just slower); GHCR caching is an easy later win.
- **arm64 runners are not boot-test capacity.** systemd's CI sets `no_kvm: 1`
  on arm — x86_64 runners only for boot tests (crosscutting.md §2.1).
