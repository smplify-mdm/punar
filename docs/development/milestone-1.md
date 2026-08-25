# Milestone 1 — Lightweight graphical workstation: integration plan

Status: **implemented in the image pipeline, config-validated; first
green `desktop-test` CI run still pending.** Plan written 2026-08-24; the
same day the decisions below were wired into `os/images/` (desktop profile,
session chain, marker/RAM/export units — see
[image-pipeline.md](image-pipeline.md) for the as-built wiring and its
verification table). As built, the §9–§10 desktop gate lives in
`tools/boot-test.sh --mode desktop` plus
`tests/performance/check-budgets.sh`; this plan's provisional name
`tools/desktop-test.sh` was not used. The substrate underneath is proven:
Milestone 0 acceptance is met — CI run
[32788238871](https://github.com/smplify-mdm/punar/actions/runs/32788238871)
(2026-08-24) is fully green (rust, contracts, mkosi image build, QEMU boot
test with `PUNAR_BOOT_OK`). No punar-desktop image has been **built or
booted** yet; as of 2026-08-24 no `desktop-test` run is recorded.
Spec basis: [SPEC_v0.2.md](../product/SPEC_v0.2.md) §76 Milestone 1 (deliver
Wayland, compositor, shell, command center, terminal, browser, Git, editor,
Podman, keyboard navigation; acceptance: idle RAM measured and no mouse
required for core desktop use), §57 (stack: Wayland, Hyprland, Quickshell),
§53 (Quickshell/QML shell implementation), §48 (upstream Chromium, no fork).
Substrate and pipeline facts come from
[ADR-001](../architecture/adr/ADR-001-distribution-substrate.md) and
[image-pipeline.md](image-pipeline.md); budgets from
[PERFORMANCE_BUDGETS.md](../../PERFORMANCE_BUDGETS.md); visual design is
bound by [DESIGN_LANGUAGE.md](../design/DESIGN_LANGUAGE.md) and the mockups
`docs/design/mockups/boot-greeter.html` and
`docs/design/mockups/command-approval.html`.

Honesty (spec 1.22): §2's package versions are **verified** against the
pinned snapshot (method stated there). Everything else in this document is a
**plan** — labeled unverified until the first CI run of the M1 image proves
it. Where a step rests on documented-but-unexercised behavior, the fallback
is named inline.

---

## 1. Scope

| Item | M1 | Reason |
| --- | --- | --- |
| Hyprland compositor (Wayland) | **in** | spec §57 committed stack; tiling + keyboard-first |
| punar-shell bar + command center (Quickshell/QML) | **in** | spec §53; must implement `command-approval.html` design, not approximate it |
| Terminal: foot | **in** | lightweight native Wayland terminal; keyboard-first |
| Browser: chromium (upstream, unpatched) | **in** | spec §48: upstream Chromium + thin integration; launch/window integration only in M1 |
| Git, Neovim, Podman (+crun, netavark, aardvark-dns) | **in** | spec §76 M1 deliverables; CLI tools, no UI work needed |
| Keyboard grammar (SUPER-based binds, no-mouse operation) | **in** | M1 acceptance criterion |
| pipewire + wireplumber + pipewire-pulse (socket-activated) | **in** | minimal audio so chromium doesn't stall; no pulseaudio per budgets |
| Fonts: Instrument Sans + Geist Mono (vendored) + Noto fallback | **in** | design language is binding; see §5 |
| `punar-desktop` mkosi profile | **in** | see §3 |
| `PUNAR_DESKTOP_OK` graphical ready marker | **in** | CI gate for "graphical session up"; see §7 |
| Idle-RAM measurement + CI gate, screenshot export | **in** | M1 acceptance: "idle RAM measured"; see §8–§9 |
| QML greetd greeter (`boot-greeter.html`) | **deferred** | M1 dev image autologins via greetd `initial_session`; the greeter is polish that should land after the Quickshell stack is proven in-VM |
| Named project workspaces, layouts, scratchpads, overview | **deferred → M2** | spec §76 assigns multitasking depth to Milestone 2 |
| `punard` + `punarctl` + typed IPC + audit | **deferred → M3** | spec §76; M1 shell may stub, not implement |
| Secure Boot / signed UKIs, vendor mirror, ISO | **deferred** | carried M0 pipeline limitations, unchanged by M1 |
| Real-hardware boot (linux-firmware) | **deferred** | VM-only dev image remains VM-only; firmware is the largest single package |
| Web-app install flow | **deferred → M11** | spec §76 |

## 2. Verified package manifest

Verification method: `docker run --platform linux/amd64` on the pinned
builder base (`snapshot.env` digest), pacman pointed at the pinned Arch Linux
Archive snapshot **2026/08/20**, then `pacman -Sy` + `pacman -Si` per
package. Run locally (emulated) on 2026-08-24. This is repository-metadata
inspection only — authoritative for existence/version, since it reads the
exact snapshot the image build will use. Nothing was installed.

### 2.1 To be added to the punar-desktop profile

| Package | Version (extra) | Role |
| --- | --- | --- |
| hyprland | 0.56.2-1 | compositor (deps pull aquamarine, hyprland-guiutils 0.2.2-2, xorg-xwayland 24.1.13-1) |
| xdg-desktop-portal-hyprland | 1.4.1-1 | portal backend (screencopy for grim) |
| xdg-desktop-portal | 1.22.1-2 | portal frontend |
| quickshell | 0.3.0-3 | punar-shell runtime (deps pull qt6-base 6.11.2-2, qt6-declarative 6.11.2-1, qt6-svg 6.11.2-1, qt6-wayland 6.11.2-1, polkit 127-3) |
| greetd | 0.10.3-2 | session manager; deps pull greetd-agreety (text fallback greeter) |
| foot | 1.27.0-2 | terminal |
| chromium | 151.0.7922.169-1 | browser |
| git | 2.55.0-1 | tooling |
| neovim | 0.12.4-1 | editor |
| podman | 6.1.0-1 | containers (rootless; newuidmap ships in base's shadow) |
| crun | 1.29.1-1 | OCI runtime |
| netavark | 2.1.0-3 | podman networking |
| aardvark-dns | 2.1.0-3 | podman DNS |
| pipewire | 1:1.6.8-1 | audio (socket-activated user service) |
| pipewire-pulse | 1:1.6.8-1 | pulse shim for chromium |
| wireplumber | 0.5.15-1 | session manager for pipewire |
| mesa | 1:26.1.7-1 | GL/EGL incl. llvmpipe + kms_swrast software rasterizers (VM rendering path, §6) |
| polkit | 127-3 | authorization |
| hyprpolkitagent | 0.1.3-9 | polkit agent for the session |
| noto-fonts | 1:2026.08.01-1 | glyph-coverage fallback |
| noto-fonts-emoji | 1:2.051-1 | emoji fallback |
| grim | 1.5.0-2 | screenshot (CI proof of rendering + spec deliverable) |
| slurp | 1.5.0-2 | region select for grim |
| wl-clipboard | 1:2.3.0-1 | keyboard-first clipboard |
| jq | 1.8.2-1 | shell/CI scripting inside guest |

Also verified present but **deliberately not shipped**: vulkan-swrast
1:26.1.7-1 (llvmpipe GL suffices; Vulkan adds RAM/disk for nothing at M1),
seatd 0.9.3-1 (the libseat *library* arrives as a hyprland dep; the seatd
*daemon* stays disabled — logind is the seat provider, §4),
greetd-tuigreet 0.11.0-3 and uwsm 0.26.6-1 (not needed by the chosen session
chain), qemu-guest-agent 11.1.0-1 (kept in reserve as the fallback export
path, §8), otf-geist-mono-nerd 3.5.0-1 (rejected: patched fork with renamed
family; design language names Geist Mono proper). Kernel at the pin:
linux 7.1.8.arch1-3.

### 2.2 Absent from the snapshot (verified missing)

`ttf-geist`, `ttf-geist-mono`, and any Instrument Sans package do **not**
exist in the 2026/08/20 snapshot (`pacman -Ss geist` / `-Ss instrument`
checked). Both design-language typefaces are therefore vendored — §5.

## 3. Decision: mkosi profiles, not a single evolved image

**Decision: keep `punar-dev` minimal and add a `punar-desktop` profile via
mkosi profiles (mkosi v26 `mkosi.profiles/`).**

- The M0 boot gate stays cheap and regression-isolated: a broken desktop
  stack must not take down the "does the substrate boot" signal.
- One config tree, one snapshot pin, shared `[Distribution]`/determinism
  settings; the profile adds only packages + desktop config.
- Cost: CI builds two images per run. Accepted — the minimal build is small,
  and pacman package cache (`CacheDirectory=`) is shared.

Mechanics: `os/images/mkosi.profiles/desktop/mkosi.conf` carries the package
additions and desktop `mkosi.extra`/postinst pieces.
`container-build.sh` invokes mkosi twice, passing `--profile desktop
--image-id punar-desktop` explicitly on the CLI for the desktop build —
CLI settings override all config files, which sidesteps any ambiguity in
profile scalar-merge semantics rather than relying on them. Outputs:
`punar-dev-x86_64.qcow2` (unchanged name — boot-test defaults keep working)
and `punar-desktop-x86_64.qcow2`. Note: the compressed desktop qcow2 will be
substantially larger (chromium + qt6 + mesa; estimate 1.5–2.5 GB — estimate,
not measured); CI artifact upload time grows accordingly.

## 4. Decision: session start chain (dev image)

**greetd autologin → Hyprland → punar-shell via exec-once.** No display
manager beyond greetd; no uwsm; the real QML greeter is deferred (§1).

1. `greetd.service` enabled (its packaged unit conflicts `getty@tty1`; the
   serial getty autologin on ttyS0 from `Autologin=yes` remains as dev/CI
   fallback access).
2. `/etc/greetd/config.toml`: `[initial_session]` runs
   `/usr/lib/punar/session.sh` as user `punar` (autologin once per boot);
   `[default_session]` is `agreety --cmd /usr/lib/punar/session.sh` as the
   manual fallback after logout.
3. User `punar` is created by an `mkosi.postinst` chroot script
   (`useradd -m -G wheel,video,input,uucp punar`; `/etc/subuid`+`/etc/subgid`
   ranges for rootless podman). Dev-image convenience account, documented,
   like root/`punar` in M0.
4. `/usr/lib/punar/session.sh`: exports the VM graphics env (§6) and
   `XDG_SESSION_TYPE=wayland`, then `exec Hyprland` with the shipped config.
5. Shipped Hyprland config: `exec-once = qs -p /usr/share/punar/shell`
   (as built — the shell QML installs to `/usr/share/punar/shell/` with
   tokens at `/usr/share/punar/theme/punar-tokens.json`, outside
   Quickshell's default XDG search, so `-p` is load-bearing),
   `exec-once = hyprpolkitagent`,
   `exec-once = /usr/lib/punar/desktop-ready.sh` (§7), plus the keyboard
   grammar binds (SUPER+Return foot, SUPER+Space command center, SUPER+B
   chromium, SUPER+arrows/HJKL focus, etc. — exact grammar owned by the
   shell workstream, but it lives in this config).
6. Seat/session management: systemd-logind via greetd's PAM session;
   Hyprland's libseat uses the logind backend. The seatd daemon is never
   enabled.

## 5. Decision: fonts are vendored, with OFL license files

Neither typeface exists in the snapshot (§2.2), so both are vendored as
static TTFs into the image tree (proposed:
`os/images/mkosi.profiles/desktop/mkosi.extra/usr/share/fonts/punar/`):

- **Instrument Sans** — from Google Fonts' GitHub
  (`google/fonts` `ofl/instrumentsans`, upstream
  Instrument-Sans repo), OFL-1.1. Vendor the TTFs + the upstream `OFL.txt`.
- **Geist Mono** — from Vercel's `vercel/geist-font` GitHub releases,
  OFL-1.1. Vendor TTFs + `OFL.txt`.

Rules: pin the exact upstream release tag/commit and record per-file sha256
in a small manifest next to the fonts; update the repo `NOTICE` with both
OFL attributions; `noto-fonts` + `noto-fonts-emoji` (packaged, verified)
provide glyph fallback; fontconfig defaults set Instrument Sans /
Geist Mono per the design language tokens
(`shell/theme/punar-tokens.json`). The nerd-font Geist Mono package is
explicitly rejected (patched metrics, renamed family).

## 6. Decision: Hyprland under QEMU — virtio-vga + guest-side llvmpipe

**QEMU device: `-device virtio-vga` (guest KMS via the in-kernel virtio_gpu
driver), no virgl/host-GL. Rendering: mesa software GL (llvmpipe /
kms_swrast) inside the guest.** `-display none` still instantiates the
device and its connector, so this works headless in CI; grim proves real
frames.

Environment set by `session.sh` (dev image; revisited for real hardware
later):

- `AQ_NO_MODIFIERS=1` — disable DRM buffer modifiers; the aquamarine flag
  the Hyprland wiki recommends for VMs/limited devices.
- `LIBGL_ALWAYS_SOFTWARE=1` — force mesa's software rasterizer for EGL/GLES.
- Hyprland config: `cursor { no_hardware_cursors = true }`.
- Documented fallback only (not set by default): `AQ_NO_KMS_REQUIREMENT=1`,
  which lets Hyprland start on a card with no output — not needed with
  virtio-vga's connector present.

Basis (as of 2026): Hyprland wiki
[Virtual-GPU](https://wiki.hypr.land/Configuring/Advanced-and-Cool/Virtual-GPU/)
and [aquamarine env flags](https://wiki.hypr.land/Hypr-Ecosystem/aquamarine/);
[QEMU virtio-gpu docs](https://www.qemu.org/docs/master/system/devices/virtio/virtio-gpu.html)
(without virgl "the guest needs to employ a software renderer for 3D
graphics", which mesa llvmpipe provides out of the box);
[Hyprland FAQ](https://wiki.hypr.land/FAQ/).

**Honesty label:** the Hyprland FAQ's older guidance says VMs need 3D
acceleration enabled; the software-GL path above is current community
practice but **unverified in this repo until the first CI run**. If Hyprland
refuses the llvmpipe path in CI, the named fallback is
`-device virtio-vga-gl -display egl-headless` on the KVM runner
(host-side GL via the runner's mesa), and after that, sway as the spec §57
fallback compositor evaluation trigger.

## 7. Decision: graphical ready marker — `PUNAR_DESKTOP_OK`

Mirrors the proven `punar-boot-marker` pattern (flag file + root unit
writing to the console) instead of letting the user session write to
`/dev/ttyS0` directly:

1. tmpfiles.d: `d /run/punar 0755 punar punar`.
2. `desktop-ready.sh` (user session, Hyprland exec-once): waits until the
   Wayland socket answers and the quickshell process is up (`hyprctl`
   + pgrep), captures `grim /run/punar/screenshot.png`, snapshots
   `/proc/meminfo`, then creates `/run/punar/desktop-ready`.
3. `punar-desktop-marker.path` (system): `PathExists=/run/punar/desktop-ready`
   triggers `punar-desktop-marker.service` (root, oneshot,
   `StandardOutput=journal+console`): prints
   `PUNAR_DESKTOP_OK` + MemTotal/MemAvailable to the serial console, then
   runs the idle-RAM sampler (§8) and the artifact export (§9).

`PUNAR_BOOT_OK` (multi-user) stays untouched in both profiles; the desktop
test greps for `PUNAR_DESKTOP_OK`.

## 8. Decision: idle-RAM measurement (the M1 acceptance number)

Canonical method is fixed by PERFORMANCE_BUDGETS.md §2.1–2.2 and is not
renegotiated here: VM sized **8 GB** (`-m 8192`), stabilized idle = 10
minutes after graphical session up with no input, then a 5-minute window
sampling `MemTotal - MemAvailable` every 10 s; report mean and max.

- Guest side: `punar-idle-ram.service` (started by the marker service)
  sleeps/samples per the methodology reading `/proc/meminfo` only, then
  emits `PUNAR_RAM_MEAN_MB=<n> PUNAR_RAM_MAX_MB=<n>` to the console and
  writes the raw samples to `/run/punar/ram-samples.txt` for export.
- CI gate: **fail** if mean > 1536 MB (hard ceiling, release blocker),
  `::warning::` if mean > 1024 MB (target). Numbers are labeled `(VM)`;
  if the runner degraded to TCG the run labels them `(VM, emulated)`,
  gates warn-only, and the result is indicative per the budgets doc.
- Cost: ~15 minutes wall time added to the desktop test job under KVM.
  Accepted — this *is* the M1 acceptance criterion.

## 9. Decision: artifact export from the VM — second virtio-serial port + base64

**Chosen: a dedicated virtio-serial channel carrying a base64-encoded tar
between sentinel lines, captured by QEMU to a host file.** Rejected:
9p/virtiofs shares.

- QEMU side (new `tools/desktop-test.sh`): `-device virtio-serial-pci`
  `-chardev file,id=exp,path=<workdir>/export.b64`
  `-device virtserialport,chardev=exp,name=punar.export`.
- Guest side: after the RAM sampler finishes, the marker service runs
  `tar -C /run/punar -cf - . | base64` to
  `/dev/virtio-ports/punar.export`, framed by
  `PUNAR_EXPORT_BEGIN` / `PUNAR_EXPORT_END` lines.
- CI decodes between sentinels, untars screenshot.png + meminfo +
  ram-samples.txt, and uploads them as workflow artifacts.

Justification: zero new host requirements (the boot-test host already needs
only qemu — virtiofs would add a virtiofsd process + shared-memory machine
setup, 9p needs `-virtfs` support plus guest mount units and has
security-model/permission quirks); it works identically under KVM and TCG;
the capture is a plain append-only file, trivially robust; and the payload
is small (an llvmpipe PNG plus text — well under a few MB, where base64's
33% overhead is irrelevant). Fallback if the channel misbehaves:
qemu-guest-agent (verified in the snapshot) with `guest-file-read` over its
own virtio-serial channel.

## 10. CI changes (all GitHub-owned actions, ubuntu-24.04 pinned — unchanged policy)

- `image` job: `container-build.sh` builds both profiles (§3); uploads both
  qcow2s + checksums. Timeout raised to accommodate the chromium/qt6
  download (still bounded by the shared pacman cache; exact new timeout set
  from the first real run).
- `boot-test` job: unchanged, still gates `punar-dev`.
- New `desktop-test` job (needs `image`): installs qemu+ovmf, enables KVM via
  the existing udev rule, runs `tools/desktop-test.sh
  os/images/out/punar-desktop-x86_64.qcow2` — boots with `-m 8192 -smp 4
  -device virtio-vga` + export channel, waits for `PUNAR_DESKTOP_OK`
  (then the RAM lines), applies the §8 gate, decodes the §9 export, uploads
  `punar-desktop-proof` (screenshot + RAM data). Timeout ~45 min (boot +
  15 min measurement under KVM; TCG degradation keeps the boot-test
  warning pattern).
- "No mouse required" acceptance: not CI-provable at M1; verified by a human
  driving the VM per a scripted keyboard-only walkthrough (documented with
  the shell work), with the keybind config's presence as the CI-checkable
  proxy.

## 11. Verification status (spec 1.22)

| Claim | Status |
| --- | --- |
| All §2.1 packages exist at the pinned versions in ALA 2026/08/20 | **verified locally 2026-08-24** (snapshot metadata via pinned builder base; emulated docker, but metadata is environment-independent) |
| ttf-geist / ttf-geist-mono / Instrument Sans absent from snapshot | **verified locally 2026-08-24** (same method) |
| greetd pulls agreety; hyprland pulls xwayland, guiutils, seatd(lib) | **verified locally 2026-08-24** (`pacman -Si` dependency lists) |
| Hyprland runs on virtio-vga + llvmpipe with §6 env | **unverified — plan**, precedent-backed (wiki links in §6); fallback named |
| §3 profile mechanics (`mkosi.profiles/desktop/`, CLI `--profile/--image-id/--hostname`, both images from one tree, punar-dev unchanged) | **implemented + verified locally 2026-08-24** via `mkosi summary` for both images in the pinned builder container (emulated; the same code path CI runs) — package set, both extra trees, profile postinst pickup, and CLI scalar overrides all confirmed in the summary output |
| §4/§5/§7–§9 wiring (greetd config, session.sh, dev user postinst, desktop-ready/marker/idle-RAM/export units, fonts + configs staged into the image) | **implemented, config-validated** (shellcheck v0.11.0 clean, font manifest re-verified at stage time); **runtime unverified** — first CI desktop-test run is the arbiter |
| Session chain, marker, export, RAM gate **at runtime** | **unverified**; first CI run of the M1 branch is the arbiter |
| Desktop image size / CI timings | **estimates, not measurements** |

Sources for §6:
[Hyprland Virtual-GPU wiki](https://wiki.hypr.land/Configuring/Advanced-and-Cool/Virtual-GPU/) ·
[aquamarine wiki](https://wiki.hypr.land/Hypr-Ecosystem/aquamarine/) ·
[Hyprland FAQ](https://wiki.hypr.land/FAQ/) ·
[QEMU virtio-gpu documentation](https://www.qemu.org/docs/master/system/devices/virtio/virtio-gpu.html)
