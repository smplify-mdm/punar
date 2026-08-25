# Image pipeline (Milestones 0–1)

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
| `os/images/builder/Containerfile` | Builder container: pinned Arch + mkosi 26 + UKI/filesystem tools. |
| `os/images/mkosi.conf` | Base image definition: minimal Arch payload (`base`, `linux`), UEFI/systemd-boot, UKI, serial console, root autologin. Shared by both images. |
| `os/images/mkosi.extra/` | Files copied verbatim into every image; currently `punar-boot-marker.service` + its enablement symlink. |
| `os/images/mkosi.profiles/desktop/` | The M1 `punar-desktop` profile: `mkosi.conf` (the verified §2.1 package additions), `mkosi.postinst.chroot` (dev user `punar` + subuid/subgid for rootless podman, `systemctl enable greetd`, `graphical.target`, fc-cache), and `mkosi.extra/` — the versioned parts (greetd `config.toml`, `/usr/lib/punar/{session.sh,desktop-ready.sh,idle-ram.sh}`, `punar-desktop-marker.path/.service`, `punar-idle-ram.service`, tmpfiles `/run/punar`) plus build-time-staged parts (gitignored; see next row). |
| `os/modules/desktop/`, `shell/punar-shell/`, `shell/theme/` | Source of truth for Hyprland config (`/etc/xdg/hypr/`), foot config (`/etc/xdg/foot/foot.ini`), fontconfig defaults + vendored fonts (`/usr/share/fonts/punar/`), the punar-shell QML (`/usr/share/punar/shell/`) and design tokens (`/usr/share/punar/theme/punar-tokens.json`). `container-build.sh` re-verifies the font sha256 manifest and stages these into the desktop profile's `mkosi.extra/` on every build — nothing is committed twice. |
| `os/images/scripts/container-build.sh` | Runs inside the builder container: staging (desktop), `mkosi build` per selected image, raw→compressed qcow2, checksums, build metadata. `PUNAR_IMAGES=dev|desktop|all`, `PUNAR_BUILD_MODE=build|summary`. |
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
   staged (font manifest verified first) and mkosi runs a second time with
   `--profile desktop --image-id punar-desktop --hostname punar-desktop` —
   scalar overrides on the CLI, so no profile scalar-merge ambiguity — and the
   result is converted to `os/images/out/punar-desktop-x86_64.qcow2`. Both
   builds share `CacheDirectory=cache`, so packages download once.

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
