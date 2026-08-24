# Cross-cutting research for ADR-001 and the CI pipeline

Research date: 2026-08-24. Author: automated research agent (workflow for Milestone 0).
Scope: facts that apply to all three substrate candidates (Arch, NixOS, Fedora Atomic) —
CI virtualization, cross-architecture builds from the maintainer's arm64 Mac, mkosi as a
substrate-neutral image builder, Chromium security-shipping latency per substrate,
Hyprland/Quickshell packaging status, idle-RAM data points, and zram policy.
Every load-bearing claim carries a URL in the Citations section. Claims made from general
knowledge without a fetched source are explicitly labeled "unverified".

---

## 1. Overview of findings

1. **GitHub Actions hosted Linux runners expose a working `/dev/kvm`.** Hardware-accelerated
   virtualization has been available on all GitHub-hosted Linux runners (including the
   smallest tier) since 2024; a one-line udev rule opens permissions. Public-repo standard
   runners are 4-vCPU / 16 GB RAM / 14 GB SSD, free and unlimited. This makes real QEMU/KVM
   boot tests of x86_64 images feasible in ordinary CI — the systemd project does exactly
   this with mkosi, including for Arch images.
2. **`ubuntu-latest` is a moving target in 2026.** Ubuntu 26.04 runner images went to public
   preview 2026-06-11 and label migrations were announced 2026-05-14, rolling out gradually.
   CI should pin `ubuntu-24.04` (or `ubuntu-26.04`) explicitly, not `ubuntu-latest`.
   arm64 runners (`ubuntu-24.04-arm`) do **not** provide usable KVM for x86 work; systemd's
   CI sets `no_kvm: 1` on its arm matrix entry.
3. **Building x86_64 images from the arm64 Mac works but belongs in CI.** Docker Desktop's
   Rosetta-backed `--platform linux/amd64` emulation is GA and 2–4x faster than the QEMU
   fallback, but has documented failure modes (exec-format errors, 100 %-CPU hangs on some
   Node/amd64 workloads, stack-smashing aborts). Rosetta accelerates *user-mode* code only;
   full-system x86_64 boots on the Mac fall back to QEMU TCG software emulation with no KVM
   (architectural fact: Apple Silicon cannot hardware-virtualize x86). Local amd64 container
   builds are acceptable for iteration; authoritative image builds and boot tests must run on
   x86_64 CI runners.
4. **mkosi is a credible substrate-neutral image builder — for two of the three candidates.**
   Latest release is v26 (tagged 2025-12-17; Arch ships `26-5`, updated 2026-05-12). It
   builds Fedora, CentOS/RHEL/UBI, Debian, Ubuntu, Kali, **Arch**, openSUSE and Azure Linux
   images from any host distro, outputs disk images and signed UKIs (`uki-signed`,
   `systemd-boot-signed`, `grub-signed` variants in v26), and is exercised in GitHub Actions
   by systemd's own CI with QEMU/KVM boot tests. **NixOS is not an mkosi target** — a Nix
   substrate means a Nix-native image pipeline, which is the main pipeline asymmetry ADR-001
   must weigh.
5. **Chromium security latency (sampled 2026-08): Arch ≈ nixpkgs-unstable ≈ 1–3 days;
   Fedora ≈ 1–2 weekly refreshes behind.** Upstream shipped 151.0.7922.173 for Linux around
   2026-08-18/20; Arch packaged it 2026-08-21 and nixpkgs `nixos-unstable` pins exactly
   151.0.7922.173 as of 2026-08-24, while Fedora 44 stable carried .169 and most other Fedora
   releases .137. Chrome moves to a two-week stable milestone cadence with Chrome 153 on
   2026-09-08, with weekly security refreshes continuing — substrate patch-lag will matter
   *more* over time.
6. **Hyprland/Quickshell freshness strongly favors Arch, then nixpkgs; Fedora's official
   packaging has stalled.** Hyprland 0.56.2 (2026-08-05) is in Arch extra same-day and in
   nixpkgs-unstable; Fedora's official package is frozen at 0.45.2 and F43/F44 users depend
   on COPRs. Quickshell 0.3.1 (2026-08-20) is in Arch extra; nixpkgs has 0.3.0; Fedora's
   official package is a 0.2.1 git snapshot.
7. **Idle RAM: the compositor is not the dominant term.** Omarchy (full Arch+Hyprland stack)
   measured 1.3 GB on boot per DHH (2025-08); compositor-only figures are ~40–60 MB (Sway)
   and ~80–120 MB (Hyprland), 150–250 MB with bar/notification/wallpaper daemons. Punar's
   < 1.0 GB target (spec 6.1) is beatable on any substrate, but it is won or lost in
   services and shell components, not in the substrate choice.
8. **zram: defaults differ from best practice.** Upstream zram-generator defaults to
   `min(ram/2, 4096)` MB; Fedora has shipped `zram-size = min(ram, 8192)` (fraction 1.0
   capped at 8 GiB) since F34. For 8 GB machines the practical consensus (Pop!_OS values,
   mirrored on the Arch wiki) is device size = RAM, zstd, `vm.swappiness=180`,
   `vm.watermark_boost_factor=0`, `vm.watermark_scale_factor=125`, `vm.page-cluster=0`.

---

## 2. Detailed findings

### 2.1 GitHub Actions: KVM availability and runner facts (as of 2026-08)

- GitHub extended hardware-accelerated virtualization to its smallest (2-vCPU) hosted Linux
  runners; announcement content dated 2024-04-02. Larger runners had it earlier (2023).
  KVM is present but the runner user lacks permission by default; the canonical setup step
  (used by the android-emulator-runner ecosystem and systemd's setup-mkosi) installs a udev
  rule making `/dev/kvm` mode 0666, then re-triggers udev:

  ```yaml
  - name: Enable KVM
    run: |
      echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
        | sudo tee /etc/udev/rules.d/99-kvm4all.rules
      sudo udevadm control --reload-rules
      sudo udevadm trigger --name-match=kvm
  ```

- Standard runner hardware for **public** repositories: 4-vCPU, 16 GB RAM, 14 GB SSD, x64;
  free and unlimited for public repos. (Private-repo standard Linux runners are smaller.)
- Image labels in flux during 2026: Ubuntu 26.04 x64 and arm images available to all users
  since 2026-06-11 (`ubuntu-26.04`); GitHub announced gradual `-latest` migrations
  (2026-05-14 changelog), spanning 1–2 months. **Recommendation: pin `ubuntu-24.04` now,
  move to `ubuntu-26.04` deliberately.**
- arm64 hosted runners exist (`ubuntu-24.04-arm`, `ubuntu-26.04-arm` preview) but systemd's
  CI disables KVM and QEMU boot tests on them (`no_kvm: 1`, `no_qemu: 1`) — treat arm
  runners as build/lint capacity only, not boot-test capacity, for an x86_64-first distro.
- Nested-virtualization support on hosted runners has a messy documentation history (older
  community threads say "unsupported"); the empirically settled state since 2023–2024 is
  that KVM on Linux runners works and whole ecosystems (Android emulator, mkosi, cloud-image
  boot tests) rely on it.

### 2.2 Established QEMU boot-test CI patterns for OS projects

- **systemd (`.github/workflows/mkosi.yml`)** — the closest precedent to what Punar needs.
  Matrix of ~8 distro configurations (Arch rolling, Debian stable/testing, Ubuntu
  noble/resolute, Fedora 44/rawhide, openSUSE Tumbleweed, CentOS 9/10, postmarketOS edge)
  built with mkosi on `ubuntu-24.04` runners; boot tests run in VMs (Arch entry sets
  `vm: 1`), with `TEST_NO_KVM` / `TEST_PREFER_QEMU` toggles. mkosi's own integration tests
  "build and boot full images" and "require KVM (skipped or very slow without /dev/kvm)".
- **Cloud-image boot + SSH probe** — a documented pattern boots an Ubuntu minimal cloud
  image under qemu-kvm inside a GitHub Actions job and drives it over SSH; directly
  adaptable to "boot the Punar image, wait for a login prompt / ssh, assert budgets".
- **Omarchy** — builds its ISO with archiso inside an `archlinux/archlinux:latest` Docker
  container via `omarchy-iso-make` (repo `omacom-io/omarchy-iso`); a marketplace "Mkarchiso"
  action does the same on Actions and requires a `--privileged` Arch container. Precedent
  that Arch image production containerizes cleanly.
- **NixOS** — nixpkgs carries qemu-based NixOS VM tests (e.g. `nixos/tests/chromium.nix`);
  the NixOS test framework is the most mature declarative VM-test system of the three
  ecosystems, but it is Nix-only. (Fedora's openQA and Universal Blue's OCI/bootc pipelines
  are further precedents; noted from general knowledge, unverified in this pass.)
- **Commercial escape hatch** — actuated and similar services sell KVM-capable runners if
  hosted-runner limits ever bind.

### 2.3 x86_64 image building from an arm64 Mac

- Docker Desktop's "Use Rosetta for x86_64/amd64 emulation" is GA since Docker Desktop 4.25
  (2023-11) and enabled by default on macOS 14.1+. Benchmarks put Rosetta at roughly 2–4x
  the speed of the QEMU user-mode fallback.
- Documented pitfalls, all still open or recent as of 2025–2026:
  - some `--platform linux/amd64` containers fail with exec-format errors when Rosetta is
    enabled (sickcodes/Docker-OSX #883);
  - certain Node.js/amd64 workloads spin at 100 % CPU and hang (docker/for-mac #6998) —
    teams work around it by disabling Rosetta (falling back to slow QEMU);
  - stack-smashing aborts in amd64 binaries under Rosetta-for-Linux (Apple dev forums).
- Architectural limits (well-established; stated without a single citation): Rosetta
  translates user-space only — the Linux VM kernel is arm64, so amd64 kernel modules,
  `qemu-system-x86_64` with KVM, and x86 nested virt are impossible on Apple Silicon.
  Full-system x86_64 boot tests on the Mac run under TCG software emulation (minutes, not
  seconds). Lima has the same ceiling.
- Practical consequence for Punar: `--platform linux/amd64` Arch/Fedora containers on the
  Mac are fine for iterating on package lists and scripts; **authoritative image builds,
  UKI signing, and boot tests belong on x86_64 CI runners with KVM.** CI is the arbiter;
  local emulated results should be labeled as such per spec 1.22.

### 2.4 mkosi as a substrate-neutral image builder

- Version: **v26**, tagged 2025-12-17 (newest tag as of 2026-08-24; prior: v25.3 on
  2025-01-31). Arch extra ships `mkosi 26-5`, last updated 2026-05-12.
- Distribution targets: Fedora, CentOS Stream / RHEL / RHEL UBI, Debian, Ubuntu, Kali,
  **Arch Linux**, openSUSE, Azure Linux — i.e. anything driven by dnf/apt/pacman/zypper.
  systemd's CI additionally builds postmarketOS (apk) images with it. It cross-builds any
  supported target from any host distro (package managers run in a sandbox/container), so
  one config repo can emit both Arch-based and Fedora-based Punar images.
- Boot/security features relevant to spec 8 criteria: UKI/USI output formats; v26 adds
  `systemd-boot-signed`, `uki-signed`, `grub-signed` bootloader variants for Secure Boot
  signing inside the build; verity partition signing; kernel-install plugin mode;
  `mkosi vm` boots the produced image under qemu (KVM-accelerated where available).
- CI story: proven at scale in systemd's own GitHub Actions; a setup action configures
  /dev/kvm, /dev/vhost-vsock and /dev/vhost-net permissions for unprivileged image testing.
- **The gap: NixOS.** mkosi cannot produce NixOS images; a NixOS substrate replaces the
  whole image pipeline with Nix-native tooling (and Secure Boot via lanzaboote — general
  knowledge, unverified here). Choosing mkosi keeps Arch-vs-Fedora reversible cheaply;
  it does not keep NixOS reversible.

### 2.5 Chromium security cadence and substrate latency

- Upstream: stable milestone every 4 weeks with **weekly** security "stable refreshes"
  in between (weekly cadence since Chrome 116, 2023). Announced 2026-03-03: from Chrome 153
  (stable 2026-09-08) the milestone cadence halves to **two weeks**, weekly security
  refreshes continuing.
- August 2026 sample (Linux versions): upstream stable refreshes 151.0.7922.75 (~Aug 3),
  .137 (~Aug 10), .173 (~Aug 18–20).
  - **Arch**: `chromium 151.0.7922.173-1` in extra, last updated 2026-08-21 00:25 UTC →
    ~1–3 days behind upstream.
  - **nixpkgs (nixos-unstable)**: `info.json` pins chromium and ungoogled-chromium at
    151.0.7922.173 as of 2026-08-24 → current at the pin level. Caveats: channel/Hydra
    rebuild latency adds time before binaries reach users, and history shows variance —
    a chronic maintainer-shortage issue (nixpkgs #78450) and update-request issues left
    open 10+ days (#407502). NixOS *stable* releases lag further.
  - **Fedora**: F44 stable at 151.0.7922.169, F43/F45/rawhide at .137 → one to two weekly
    refreshes (≈7–14 days) behind; Bodhi's updates-testing flow adds inherent latency.
- Reading for ADR-001: Arch and nixpkgs-unstable both meet a "days" SLO for browser CVEs
  today; Fedora's official chromium runs about a week or two behind. Punar's spec 30.2
  browser-cadence requirement effectively demands Arch-like or self-built browser delivery
  on any substrate.

### 2.6 Hyprland and Quickshell versions and packaging (as of 2026-08-24)

| Component | Upstream | Arch | nixpkgs | Fedora official |
|---|---|---|---|---|
| Hyprland | 0.56.2 (2026-08-05; 0.56.1 2026-07-27, 0.56.0 ~2026-07-20) | extra `0.56.2-1`, updated 2026-08-05 (same day) | nixos-unstable `0.56.2` | stalled at `0.45.2` (F42/rawhide); **no official F43/F44 package** — users rely on COPRs carrying 0.51–0.55 |
| Quickshell | 0.3.1 (2026-08-20) | extra `0.3.1-1` | `0.3.0` (upstream also ships a nix flake) | `0.2.1^git20260209` (F44 updates) |

- The Fedora Hyprland situation is the sharpest packaging signal in this research: community
  posts document F43→F44 upgrades breaking Hyprland setups and the official package being
  months out of date, with per-user COPRs filling the gap. For a Hyprland-based product,
  Fedora means carrying own compositor packaging.
- Arch tracks both components at release speed; nixpkgs-unstable tracks Hyprland at release
  speed and Quickshell within one point release.

### 2.7 Idle RAM data points

- **Omarchy** (Arch + Hyprland + full DHH stack): "A fresh Omarchy installation uses just
  1.3 GB RAM on boot" — DHH, 2025-08. Omarchy's stated minimum is 4 GB RAM. A tracked issue
  shows the Walker launcher growing past 1.2 GB over time — shell component quality
  dominates long-run RSS.
- **Compositor-only figures** (secondary source, 2026 comparison article; treat as rough):
  Sway ~40–60 MB; Hyprland ~80–120 MB; Hyprland + Waybar + dunst + hyprpaper ~150–250 MB.
- Interpretation against spec 6.1 (< 1.0 GB target / 750 MB stretch / 1.5 GB ceiling):
  Omarchy at 1.3 GB sits between Punar's target and hard ceiling, so "Omarchy-like" is not
  automatically within budget. The delta between a 250 MB desktop stack and a 1.3 GB booted
  system is services, portals, pipewire, and app preloading — substrate-neutral engineering.
  No published NixOS/Fedora-Hyprland idle figures were found in this pass (absence noted,
  not evidence).

### 2.8 zram policy for 8 GB machines

- Upstream `zram-generator` defaults: `zram-size = min(ram / 2, 4096)` MB;
  `compression-algorithm` unset → kernel default (lzo-rle).
- Fedora (since F34, change accepted 2021-01-27): `zram-size = min(ram, 8192)` — fraction
  1.0 of RAM capped at 8 GiB, justified by typical 2:1–3:1 compression ratios. On an 8 GB
  machine this yields an 8 GB (uncompressed) zram device.
- Community tuning consensus for zram-heavy systems (Pop!_OS values, reproduced on the Arch
  wiki zram page and Arch forums): `vm.swappiness=180`, `vm.watermark_boost_factor=0`,
  `vm.watermark_scale_factor=125`, `vm.page-cluster=0`; zstd as compression algorithm.
  A middle-ground sizing seen in the field is `zram-fraction=0.75`.
- Recommended Punar default for the Constrained profile (spec 7.1, "aggressive zram"):
  Fedora-style `zram-size = min(ram, 8192)` + zstd + the four sysctls above; ship via
  zram-generator (available on all three substrates). Verify on real 8 GB hardware —
  the sysctl set is workload-tested by Pop!_OS but not by us (unverified for Punar).

---

## 3. Assessment against spec section 8 criteria (cross-cutting lens)

- **Resource efficiency.** Substrate-neutral in the kernel/compositor; decided by service
  set and shell components (2.7). zram policy identical everywhere (2.8). No criterion
  winner; Punar-owned engineering either way.
- **Developer familiarity.** The CI toolchain (GitHub Actions, Docker, QEMU/KVM, mkosi) is
  mainstream for Arch/Fedora pipelines; a Nix pipeline demands Nix expertise for every
  contributor touching images.
- **Reproducibility.** mkosi gives config-as-code image builds with pinned package sets but
  inherits pacman/dnf repo drift unless snapshots/lockfiles are added; Nix is categorically
  stronger here. CI facts (2.1) are neutral.
- **Package availability.** For Punar's actual desktop stack: Arch first-class and same-day;
  nixpkgs-unstable near-same-day; Fedora official repos have dropped the ball on Hyprland
  and lag on Quickshell (2.6). Any Fedora choice implies self-packaging the desktop.
- **Security.** Browser CVE latency: Arch ≈ nixpkgs-unstable (days) < Fedora (1–2 weeks)
  (2.5). Chrome's 2-week milestone cadence from 2026-09 raises the bar. Fedora counters
  with SELinux-by-default (out of scope for this note).
- **Secure Boot.** mkosi v26 signs UKIs in-build for Arch and Fedora targets (2.4); NixOS
  requires the separate lanzaboote path (unverified here). CI can only *simulate* SB/TPM in
  VMs — label per spec 1.22.
- **Transactional updates / rollback.** An image-based pipeline (mkosi + systemd-sysupdate
  style A/B or snapshots) is substrate-portable across Arch/Fedora; Nix generations and
  Fedora Atomic's ostree/bootc are native but lock the pipeline to their tooling. The
  cross-cutting point: choosing mkosi keeps Arch↔Fedora reversible; NixOS is a one-way door
  for the pipeline.
- **Hardware compatibility.** Kernel freshness driven: Arch and Fedora both ship recent
  kernels; substrate-neutral for target hardware in spec 5. (Not deeply researched here.)
- **Ease of enterprise governance.** Controlled channels, signed artifacts and update
  assignments (spec 8.1) are properties of the image pipeline and release process, which CI
  facts here show are buildable on hosted runners for any substrate; none of the three
  provides them out of the box for a derivative distro.
- **Maintenance burden.** Fedora path: carry compositor packaging (COPR-grade) yourself.
  Arch path: carry snapshot/rollback and channel infrastructure yourself. Nix path: carry
  a parallel image/CI toolchain and contributor onboarding. The Chromium sample suggests
  Arch minimizes *security-update* toil for the browser.
- **Upstream velocity.** Measured: Hyprland 3 releases in ~3 weeks (Jul–Aug 2026); Chrome
  weekly refreshes moving to 2-week milestones; Quickshell 0.3.1 in Aug 2026. Arch and
  nixpkgs-unstable absorb this velocity automatically; Fedora's 6-month cadence (plus
  updates) structurally trails for desktop-stack components.

---

## 4. Precedent projects

| Project | Pattern | Relevance |
|---|---|---|
| systemd | mkosi-built images for 8+ distros incl. Arch, booted under QEMU/KVM on `ubuntu-24.04` hosted runners | Direct template for Punar's build+boot-test CI |
| Omarchy | archiso inside `archlinux/archlinux` Docker container (`omarchy-iso-make`); 1.3 GB idle measurement; 4 GB minimum | Closest product-shape precedent; also a cautionary RAM data point |
| Android emulator CI ecosystem | udev-rule KVM enablement on standard hosted runners | The canonical `/dev/kvm` permission recipe |
| Ubuntu-cloud-image boot tests | qemu-kvm + SSH probe of a booted image inside a GH Actions job | Boot-to-login smoke-test recipe |
| NixOS / nixpkgs | Declarative qemu-based VM tests (`nixos/tests/*.nix`), Hydra channels | Reference standard for reproducibility and VM testing; Nix-only |
| Fedora openQA, Universal Blue (bootc/OCI) | Distro-scale automated image QA; OCI-delivered atomic desktops | Noted from general knowledge; unverified in this pass |
| actuated | Paid KVM-capable microVM runners | Escape hatch if hosted-runner capacity binds |

---

## 5. Citations

CI / KVM / runners:
- https://github.blog/changelog/2023-06-27-github-actions-hardware-accelerated-android-virtualization-now-available/ (fetched; content dated 2024-04-02: KVM on 2-vCPU hosted Linux runners; udev permission step required)
- https://github.com/marketplace/actions/android-emulator-runner (KVM enablement pattern)
- https://github.blog/news-insights/product-news/github-hosted-runners-double-the-power-for-open-source/ (4-vCPU standard runners for public repos)
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners (runner hardware: 4-core / 16 GB / 14 GB SSD)
- https://github.blog/changelog/2026-05-14-github-actions-upcoming-image-migrations/ (label migrations, 2026-05-14)
- https://github.blog/changelog/2026-06-11-new-runner-images-in-public-preview/ (Ubuntu 26.04 x64 + arm images, 2026-06-11)
- https://github.com/actions/runner-images/issues/14226 (Ubuntu 26.04 public preview tracking)
- https://github.com/orgs/community/discussions/8305 (historical nested-virt ambiguity)
- https://actuated.com/blog/kvm-in-github-actions (KVM-in-Actions background; commercial runners)
- https://dev.to/vast-cow/running-ubuntu-minimal-cloud-image-with-qemu-kvm-and-ssh-in-github-actions-3lnk (cloud-image boot+SSH pattern)
- https://github.com/systemd/systemd/blob/main/.github/workflows/mkosi.yml (fetched: distro matrix, `vm: 1` for Arch, `no_kvm: 1` on arm)

arm64 Mac / Rosetta:
- https://www.docker.com/blog/docker-desktop-4-25/ (Rosetta for Linux GA)
- https://ddev.com/blog/amd64-with-rosetta-on-macos/ (practical Rosetta guidance)
- https://patrickwthomas.net/macos-docker/ (Rosetta ~2–4x faster than QEMU mode)
- https://github.com/docker/for-mac/issues/6998 (Node/amd64 100 % CPU hangs)
- https://github.com/sickcodes/Docker-OSX/issues/883 (exec-format failures with Rosetta)
- https://developer.apple.com/forums/thread/731620 (stack smashing under Rosetta-for-Linux)

mkosi:
- https://github.com/systemd/mkosi/tags (fetched: v26 tagged 2025-12-17; v25.3 2025-01-31)
- https://github.com/systemd/mkosi/releases (v26 features: signed bootloader variants, verity, KernelModules=)
- https://github.com/systemd/mkosi/blob/main/README.md (supported package managers/distros; UKI; KVM-dependent integration tests)
- https://archlinux.org/packages/extra/any/mkosi/ (fetched: `26-5`, updated 2026-05-12)
- https://wiki.archlinux.org/title/Mkosi (Arch UKI/Secure Boot usage)

Chromium cadence and substrate latency:
- https://chromium.googlesource.com/chromium/src/+/master/docs/process/release_cycle.md (4-week milestones, weekly stable refreshes)
- https://developer.chrome.com/blog/chrome-two-week-release (two-week cycle from Chrome 153)
- https://9to5google.com/2026/03/03/chrome-two-week-updates/ (Chrome 153 stable 2026-09-08)
- https://chromereleases.googleblog.com/2026/08/stable-channel-update-for-desktop_0404570826.html (151.0.7922.173 for Linux, mid-Aug 2026)
- https://archlinux.org/packages/extra/x86_64/chromium/ (fetched: 151.0.7922.173-1, updated 2026-08-21)
- https://raw.githubusercontent.com/NixOS/nixpkgs/nixos-unstable/pkgs/applications/networking/browsers/chromium/info.json (fetched 2026-08-24: pins 151.0.7922.173)
- https://packages.fedoraproject.org/pkgs/chromium/chromium/ (fetched: F44 at .169; F43/F45/rawhide at .137)
- https://github.com/NixOS/nixpkgs/issues/78450 (chromium maintainer shortage, historical)
- https://github.com/NixOS/nixpkgs/issues/407502 (10+ days out-of-date update request, historical)

Hyprland / Quickshell:
- https://hypr.land/news/ and https://www.warp2search.net/story/hyprland-0562-released-16-backported-fixes-stabilize-the-056-series (0.56.2, 2026-08-05)
- https://www.linuxcompatible.org/story/hyprland-0561-releases-one-week-after-0560-with-14-regression-fixes (0.56.1, 2026-07-27)
- https://archlinux.org/packages/extra/x86_64/hyprland/ (fetched: 0.56.2-1, updated 2026-08-05)
- https://raw.githubusercontent.com/NixOS/nixpkgs/nixos-unstable/pkgs/by-name/hy/hyprland/package.nix (fetched: version 0.56.2)
- https://packages.fedoraproject.org/pkgs/hyprland/hyprland/ (fetched: 0.45.2-1.fc42 latest official)
- https://www.verona.se/post/hyprland-after-f44-upgrade/ (F44 upgrade breakage; COPR reliance)
- https://github.com/AshBuk/Hyprland-Fedora (Fedora COPR at 0.55.1)
- https://outfoxxed.me/blog/quickshell-0-3 and https://github.com/quickshell-mirror/quickshell/releases (Quickshell 0.3.x; 0.3.1 announced 2026-08-20)
- https://archlinux.org/packages/extra/x86_64/quickshell/ (0.3.1-1)
- https://packages.fedoraproject.org/pkgs/quickshell/quickshell/fedora-44-updates.html (0.2.1^git20260209.fc44)
- https://mynixos.com/nixpkgs/package/quickshell (nixpkgs 0.3.0)

Idle RAM:
- https://x.com/dhh/status/1952346236557603261 (Omarchy 1.3 GB on boot, 2025-08)
- https://omarchy.net/omarchy-system-requirements-explained/ (4 GB minimum)
- https://github.com/basecamp/omarchy/issues/2435 (Walker memory growth past 1.2 GB)
- https://botmonster.com/self-hosting/hyprland-vs-sway-vs-cosmic-wayland-compositors/ (compositor RSS ranges; secondary source)

zram:
- https://github.com/systemd/zram-generator/blob/main/man/zram-generator.conf.md (fetched: default `min(ram/2, 4096)`; kernel-default compression when unset)
- https://fedoraproject.org/wiki/Changes/Scale_ZRAM_to_full_memory_size (fetched: accepted for F34, 2021-01-27; fraction 1.0 capped 8 GiB; 2:1–3:1 compression rationale)
- https://bbs.archlinux.org/viewtopic.php?id=293444 (Pop!_OS sysctl set: swappiness 180, watermark_boost_factor 0, watermark_scale_factor 125, page-cluster 0)
- https://wiki.archlinux.org/title/Zram (recommended tuning; page fetch blocked by anti-bot on 2026-08-24 — values cross-checked via the forum thread above)
- https://www.ctrl.blog/entry/how-to-systemd-zram-generator.html (zram-generator resizing practice)

Omarchy ISO build:
- https://github.com/omacom-io/omarchy-iso (archiso submodule; Docker build in `archlinux/archlinux:latest`)
- https://github.com/marketplace/actions/mkarchiso (archiso on Actions; requires privileged Arch container)
