# Omarchy — Research Notes

**Research date:** 2026-08-25
**Subject:** Omarchy, an Arch Linux + Hyprland + Quickshell desktop distribution by David Heinemeier Hansson (DHH), incubated at 37signals.
**Purpose:** Evidence file for competitive analysis. No comparison, no recommendations — findings only.

**Evidence convention used throughout:**

- **[V]** = VERIFIED — read directly from a primary source (omarchy.org, the manual, the GitHub repo/API, release notes) or from a named person's own public statement.
- **[V-SELF]** = VERIFIED that the claim was made, but the claim is a **self-report by the project or its author**, not an independent measurement.
- **[I]** = INFERRED — my reasoning from verified facts, not stated anywhere.
- **[U]** = UNVERIFIED — a third-party or secondary claim I could not confirm against a primary source.
- **[NOT FOUND]** = I looked and could not establish it.

---

## 1. Overview

| Fact | Value | Marker | Source |
|---|---|---|---|
| Current version | **4.0.1**, released 2026-08-25 (same day as this research) | [V] | [omarchy.org](https://omarchy.org/), [GitHub release v4.0.1](https://github.com/basecamp/omarchy/releases) (GitHub API, `published_at: 2026-08-25T11:24:30Z`) |
| Previous major | **4.0.0 "Quattro"**, 2026-08-14 | [V] | [GitHub release v4.0.0](https://github.com/basecamp/omarchy/releases), API `published_at: 2026-08-14T16:35:40Z` |
| Project start | Repo created 2025-06-01; public launch 26 June 2025 | [V] repo date / [U] launch date | GitHub API `created_at`; launch date from secondary sources |
| Tagline | "Beautiful, Modern & Opinionated Linux by DHH" | [V] | [omarchy.org](https://omarchy.org/) |
| Base | Arch Linux, rolling | [V] | [Manual ch.1](https://github.com/basecamp/omarchy/blob/quattro/manual/01-welcome-to-omarchy.md) |
| Compositor | Hyprland (Wayland tiling WM) | [V] | ibid. |
| Shell toolkit | Quickshell (QML) | [V] | ibid. + v4.0.0 release notes |
| License | MIT | [V] | GitHub API |
| Governance | **Omacom Foundation**, non-profit, launched 2026-08-21 | [V] | [omarchy.org/news](https://omarchy.org/news/2026/08/omacom-foundation-launches-with-8-million/) |
| Corporate home | Incubated at 37signals (Basecamp, HEY); hosting sponsored by Cloudflare | [V] | [omarchy.org](https://omarchy.org/) |

**Self-description, verbatim [V]** ([manual ch.1](https://github.com/basecamp/omarchy/blob/quattro/manual/01-welcome-to-omarchy.md)):

> "Omarchy is an omakase Linux distribution based on Arch, the tiling window manager Hyprland, and the desktop construction-kit Quickshell. It ships with everything a modern, savvy computer user needs to be productive immediately."

> "There's zero bloat here: Just everything I use."

---

## 2. What Omarchy Actually Ships Today

### 2.1 Install method

- **ISO only. [V]** The ISO repo README states flatly: *"The Omarchy ISO is the only supported way to install Omarchy."* ([omacom-io/omarchy-iso README, quattro branch](https://github.com/omacom-io/omarchy-iso/blob/quattro/README.md)). This is a change from the project's origin, which was a curl-to-bash script over an existing Arch install; ISO became the path at 2.0 (Aug 2025). [V] for current state, [U] for the 2.0 transition detail.
- **ISO URL pattern:** `https://iso.omarchy.org/omarchy-4.0.1.iso`, with `.sha256` and `.sig` beside it. [V] (release notes + ISO README)
- **Under the hood the installer drives `archinstall`** with a JSON config (`user_configuration.json`), plus a bundled offline pacman mirror inside the ISO. [V] (ISO README)
- **Unattended / autoinstall:** supported by attaching a second drive labelled `cidata` (cloud-init NoCloud convention) carrying `user_configuration.json` + `user_credentials.json`. Works with Proxmox, libvirt, Packer. [V] (ISO README; manual ch. "Unattended Installs")
- **Dual boot:** new in 4.0 — installs into unallocated free space alongside Windows, keeps LUKS. Requires BitLocker off first. [V] (v4.0.0 release notes; [manual: Getting Started](https://omarchy.org/manual/getting-started/))
- **OEM / gifting mode:** 4.0 adds "set up a machine for a new owner during install" and `Setup > Reset Computer` factory reset. [V] (v4.0.0 release notes)

### 2.2 Install duration

- **[V-SELF]** [Manual: Getting Started](https://omarchy.org/manual/getting-started/): *"It can be done in under a minute on the fastest modern machines, but it shouldn't take more than 5 minutes even on an older computer."*
- **[V-SELF]** v4.0.0 release notes: *"Speed-up installation by +30% (sub-minute installs now possible!)"*
- No independent timing measurement found. **[NOT FOUND]**

### 2.3 Hardware support

Support is expressed as **shipped driver/firmware packages in the ISO**, which is stronger evidence than marketing copy. From `install/omarchy-other.packages` on the `quattro` branch [V]:

- **NVIDIA:** `nvidia-dkms`, `nvidia-open-dkms`, `nvidia-580xx-dkms`, `nvidia-utils`, `lib32-nvidia-utils`, `libva-nvidia-driver`, `egl-wayland`
- **Intel:** `intel-media-driver`, `intel-ipu7-camera` (modern laptop webcams), `intel-lpmd`, `libvpl`/`vpl-gpu-rt`, `vulkan-intel`
- **AMD / Apple Silicon:** `vulkan-radeon`, `vulkan-asahi`
- **Apple T2 MacBooks:** `linux-t2`, `linux-t2-headers`, `apple-bcm-firmware`, `apple-t2-audio-config`, `t2fanrd`, `macbook12-spi-driver-dkms`. There is a dedicated **"Mac support"** manual chapter.
- **Dell XPS:** `dell-xps-touchpad-haptics`, `dell-xps13-sidecar-amps`; v4.0.0 adds *"speaker tunings for 2026 XPS 14/16 laptops for dramatically better sound"*
- **Framework 16:** `qmk-hid`
- **Microsoft Surface:** `linux-firmware-marvell`
- **ASUS:** `asusctl`; **Tuxedo:** `tuxedo-drivers-nocompatcheck-dkms`
- **Kernel choice:** ships both `linux` and `linux-ptl` (+ headers) — [I] `linux-ptl` appears to be an Omarchy-built kernel variant; its exact patch set is **[NOT FOUND]**.

**Hard hardware constraints stated by the project [V]** ([Getting Started](https://omarchy.org/manual/getting-started/)):
- You must **turn off Secure Boot and/or TPM in the BIOS.**
- You need **a wired or 2.4 GHz keyboard** — *"full-disk encryption won't allow you to enter the password from a Bluetooth keyboard at startup."*
- Full-disk install **wipes the selected drive.**

**Stated minimum RAM/disk:** No official minimum requirements page found on omarchy.org. **[NOT FOUND]** Third-party sites (omarchy.net, docuwriter.ai) quote "4 GB minimum / 8 GB recommended / 10–60 GB disk" — **[U]**, not from the project.

### 2.4 Default application set

Definitive list: `install/omarchy-base.packages` on the `quattro` branch — **148 packages** ("Omarchy core package list pacstrapped by the ISO"). [V] Full list read directly from the repo. Grouped:

| Category | Packages |
|---|---|
| **Compositor / shell** | `hyprland`, `quickshell`, `hyprland-guiutils`, `hyprland-preview-share-picker`, `hyprpicker`, `hyprsunset`, `sddm` (display manager), `uwsm`, `plymouth`, `xdg-desktop-portal-hyprland`, `xdg-desktop-portal-gtk` |
| **Terminal / shell tooling** | `foot` (default terminal), `ttfx`, `tmux`, `herdr` (new agent-aware multiplexer), `starship`, `fzf`, `zoxide`, `eza`, `bat`, `fd`, `ripgrep`, `jq`, `gum`, `tldr`, `plocate`, `dua-cli`, `btop`, `fastfetch`, `inxi` |
| **Editor** | `nvim` + `omarchy-nvim` (LazyVim-style preconfigured Neovim) |
| **Browser** | `chromium` |
| **Notes / office / docs** | `obsidian` (proprietary), `libreoffice-fresh`, `evince`, `xournalpp` (PDF forms), `omawrite` (own Markdown editor, replaced Typora in 4.0) |
| **Media / creative** | `mpv`, `imv`, `kdenlive`, `obs-studio`, `pinta`, `cliamp` (retro Winamp-style player), `omacut` (own ffmpeg video trimmer), `gpu-screen-recorder`, `yt-dlp`, `imagemagick` |
| **Files** | `nautilus`, `sushi`, `gnome-disk-utility`, `udiskie`, `gvfs-*` |
| **Dev / containers** | `docker`, `docker-compose`, `docker-buildx`, `lazydocker`, `lazygit`, `git`, `mise-bin`, `ruby`, `clang`, `llvm`, `luarocks`, `qemu-user-static-binfmt`, `tree-sitter-cli` |
| **Networking / sharing** | `networkmanager`, `localsend`, `avahi`, `nss-mdns`, `whois`, `inetutils` |
| **Printing** | `cups`, `cups-browsed`, `cups-filters`, `cups-pdf`, `system-config-printer` |
| **Security** | `ufw`, `ufw-docker`, `gnome-keyring`, `libsecret` |
| **OCR / capture** | `tesseract` + `tesseract-data-eng`, `grim`, `slurp`, `zbar`, `qrencode`, `wl-clipboard`, `wtype` |
| **Gaming/streaming** | `moonlight-qt` (GameStream client) |
| **Own apps (new in 4.0)** | `omawrite`, `omacut`, `omacalc` |
| **Unclear / Omarchy-specific** | `aether`, `tensaku`, `tobi-try`, `usage` — **[NOT FOUND]** what these do |

Notably **absent from the base set**: Steam, Signal, Spotify, 1Password, HEY. Those are **menu-installable extras** (the manual has Gaming, Commercial apps/services, and Web Apps chapters), not preinstalls. This matters because a common criticism (§8) is that Omarchy "ships bloatware / DHH's own products" — as of 4.x that is **partly out of date**; the shortcuts exist as launch bindings, but the apps are not in the base pacstrap. [V] on package list, [I] on the reconciliation.

### 2.5 Compositor / shell stack (the 4.0 headline change)

**[V]** from the v4.0.0 release notes, verbatim:

> "The entire desktop shell has been reimagined in Quickshell: the bar, launcher, menus, notifications, on-screen displays, control panels, lock screen, and polkit agent now all live inside a single long-running shell process with a plugin architecture. That means **Waybar, Walker, Mako, SwayOSD, hyprlock, hypridle, swaybg, and polkit-gnome are all gone**, replaced by one coherent, fully-themed, IPC-scriptable shell."

Other verified 4.0 stack facts:
- **Hyprland configs converted from `.conf` to Lua** for Hyprland 0.56 compatibility — enables loops/conditionals in config. [V]
- **Omarchy internals moved from a git checkout to pacman-owned system packages** in `/etc` and `/usr/share/omarchy`. [V]
- Shell made **event-driven rather than polled** — *"an idle desktop stops burning CPU."* [V-SELF]
- Bar is **draggable to any screen edge**, transparency toggled by double-click, widgets reorderable without editing config. [V]
- Notification daemon has **replayable history** (`Super+Shift+Alt+,` replays last ten, including DND-silenced ones) and popups **survive shell restarts**. [V]
- Native launcher (fuzzy + acronym matching) **merged into the Omarchy menu** — one surface on `Super+Space`. [V]
- `hyprlock` replaced by **shell-powered PAM password + fingerprint flows**, with fingerprint enrollment offered on first run when a reader is present. [V]
- **Plugin system:** third-party bar widgets, panels, overlays, menus, services — or entire replacement bars — installed from git via `omarchy plugin add <git-url>`. QML + `manifest.json`. [V] ([manual: Shell Plugins](https://omarchy.org/manual/shell-plugins/))

### 2.6 Theming system

- **22 built-in themes** [V] ([manual: Themes](https://omarchy.org/manual/themes/)). Named: Tokyo Night, Catppuccin, Catppuccin Latte, Lumon, Ethereal, Everforest, Gruvbox, Miasma, Hackerman, Osaka Jade, Kanagawa, Nord, Matte Black, Vantablack, Ristretto, Retro 82, Flexoki Light, Rose Pine, White, plus 4.0 additions **Solitude, Last Horizon, Lupine**.
- **Switching:** `Super + Ctrl + Shift + Space` opens a **filterable carousel of live theme previews** (new in 4.0); or `Super + Space` → Style > Theme. Backgrounds switch on `Super + Ctrl + Space` with a matching visual picker. [V]
- **Scope of theming, verbatim [V]:** *"Each theme styles the desktop, terminal, neovim, activity screen (btop), Chromium, and the entire Omarchy shell: top bar, menu, notifications, OSD, and the lock screen."* Obsidian must be themed by hand.
- **Palette expanded from 8 to 24 colors in 4.0**, so btop/nvim/VS Code themes can be **auto-generated** from the theme rather than hand-maintained. Plus a "semantic theme color system with normalized color names". [V]
- **Machine-level override:** `~/.config/omarchy/shell.toml` is merged over the active theme and is **file-watched** — personal font/spacing tweaks survive theme switching and re-flow live. [V]
- **Extra themes** installable from a separate extras list; a "Making your own theme" manual chapter exists. [V]
- **Security note:** v4.0.1 shipped a fix titled *"Stop an installed theme from running code"* (PR #7884) — i.e. themes were a code-execution vector until 2026-08-25. [V] (release notes)

### 2.7 Keybinding grammar

The grammar is consistent and is arguably a signature feature. [V] ([manual: Hotkeys](https://omarchy.org/manual/hotkeys/)):

| Modifier | Role |
|---|---|
| `Super` alone | Window + workspace management |
| `Super + Shift` | Launch applications |
| `Super + Shift + Alt` | Launch the *alternate* variant of an app (e.g. private browsing) |
| `Super + Ctrl` | System control panels (Audio/Bluetooth/Wifi/Display/Power/Calendar/Activity) |
| `Super + Alt` | Secondary window functions |

Anchor bindings [V]:
- `Super + Space` — Omarchy menu (unified command palette + app launcher, nested search)
- `Super + Alt + Space` — apps-only menu
- `Super + Escape` — system menu (suspend/restart)
- `Super + K` — **show all keybindings** (the manual tells new users this is the one hotkey they must memorise)
- `Super + Return` terminal; `Super + Shift + Return` browser; `Super + Shift + N` Neovim
- `Super + W`/`Q` close, `Super + T` toggle tiling/float, `Super + F` fullscreen, `Super + G` group, arrows to move/swap, `Super + -/=` resize
- `Super + 1..4` workspaces; `Super + Tab` next
- `Super + Ctrl + 1..9` open the bar's right-side panels **counted left to right**, so rearranging widgets renumbers them with no binding to rewrite — a small but distinctive design decision [V]
- `Super + Ctrl + V` clipboard, `Super + Ctrl + E` emoji, `Super + Ctrl + Q` calculator
- `Super + Shift + Ctrl + A` launch the configured coding agent

### 2.8 Signature features (what a user would name as distinctive)

Ranked by how frequently they appear in project material and coverage. All [V] from release notes / manual unless noted.

1. **Unified single-process Quickshell desktop** — bar, launcher, menu, notifications, OSDs, panels, lock screen and polkit agent in one themed, IPC-scriptable process.
2. **The Omarchy menu** (`Super+Space`) as a nested, filterable command palette defined in JSONC and user-extensible via `~/.config/omarchy/extensions/omarchy-menu.jsonc` — it is the install/remove/setup/update surface for the whole system, not just an app launcher.
3. **First-class coding-agent integration.** Nine agents selectable as the system default (Claude Code, Codex, OpenCode, Pi, Oh My Pi, Gemini, Grok, Copilot, Crush), lazy-installed on first use, launched as their own `org.omarchy.agent` app. Plus: a **bar widget showing model-usage stats** (Claude Code/Codex/Fireworks plan burn), aggregated across machines via synced JSON in `~/.local/state/omarchy/agents/usage/`; **crash diagnosis** wired to `systemd-coredump` that hands the crash to an agent via a shipped `diagnose-crash` skill; an **"Omarchy skill"** that teaches agents the boundary between read-only `/usr/share/omarchy/` and user-editable `~/.config/`; and **Herdr**, a new agent-state-aware terminal multiplexer (idle/working/blocked/done).
4. **Live-preview theme carousel** + 24-color palettes that auto-generate downstream app themes.
5. **Drag-to-reposition bar** and drag-to-reorder widgets — GUI customisation without config editing, unusual for a tiling-WM setup.
6. **Snapshot-on-every-update with boot-menu rollback.**
7. **`omarchy` CLI** — the repo `bin/` directory contains **hundreds** of `omarchy-*` scripts (audio, bluetooth, brightness, capture, clipboard, agent, channel, branding, crash-watch, debug, defaults…), unified behind a single `omarchy` command as of 3.7. [V]
8. **Text extraction (OCR) and dictation** as first-class system features with their own manual chapter and hotkeys — `tesseract` is a base package. [V]

---

## 3. Update / Rollback / Packaging Model

### 3.1 Packaging — three tiers [V] ([manual: Updates](https://omarchy.org/manual/updates/))

1. **Omarchy Package Repository** (`pkgs.omarchy.org`) — Omarchy itself, shipped as normal pacman packages.
2. **Omarchy Arch Mirror** — base Arch packages held **one month behind upstream**, so compatibility breakage surfaces before it reaches users.
3. **AUR** — via `yay` (in the base package set), optional.

### 3.2 Release channels [V]

| Channel | Behaviour |
|---|---|
| **Stable** (default) | Official releases, **running one month behind latest Arch** |
| **RC** | Pre-release validation of upcoming major versions |
| **Edge** | Current Arch packages + latest dev builds; project says it "requires Linux experience" |
| **Dev** | Direct git; expect instability |

Switch via `Update > Channel` or `omarchy-channel-set`. [V]

**This is the core answer to "how does it handle Arch's rolling nature": a curated one-month-delayed Arch mirror plus a migration system, not immutability.** [V]

### 3.3 Update mechanism [V]

- Update via `Update > Omarchy` in the menu, or `omarchy update`. A circular-arrow badge appears next to the clock when updates exist.
- One update = install newest Omarchy release + **run system migrations** + refresh packages from all three sources.
- **`pacman -Syu` is deliberately blocked** ("migration guard") so users can't bypass config migrations. [V]
- `omarchy reinstall` resets configuration and downgrades oversized packages. [V]
- Firmware updates via `Update > Firmware` using LVFS/fwupd. [V]

### 3.4 Rollback [V] ([manual: System snapshots](https://omarchy.org/manual/system-snapshots/))

- **Automatic snapshot before every update**; manual snapshots via `omarchy-snapshot create`.
- Snapshots are selectable **from the Limine bootloader** by date and version. Booting into one offers a restore prompt; or `omarchy-snapshot restore`.
- **Backed by btrfs + snapper** — `btrfs-progs`, `snapper`, `limine`, `limine-mkinitcpio-hook`, `limine-snapper-sync` are all in the ISO package set. [V] via package list; the manual itself does *not* name the filesystem — [I] that btrfs+snapper is the mechanism, though the package evidence is strong.
- **Limits, stated [V]:**
  - Restores **root only, never `/home`** — "suitable for reverting broken updates but not recovering lost personal files."
  - `~/.config` is untouched, so **rolling back can leave newer config formats against older binaries.**
  - **Requires Limine** (default since 2.0). **Not available on GRUB or systemd-boot installs.**
  - No documented retention policy or storage cap. **[NOT FOUND]**

**[I]** Net: the rollback story is real but shallower than an image-based/immutable OS — it is a filesystem snapshot of `/`, with an explicitly acknowledged config-skew hazard, and it does not cover user data.

---

## 4. Documentation & Onboarding

- **The Manual** ([omarchy.org/manual](https://omarchy.org/manual/)) — **51 chapters** for v4, written in Markdown in the main repo under `manual/` and rendered on the site. [V] Chapters run from Welcome / Getting Started / Coming From Mac or Windows / Navigation / The Top Bar / Themes / Hotkeys through Terminal, Neovim, AI, Development Tools, Gaming, Windows VM, Updates, Dotfiles, Shell Plugins, Monitors, Networking, System Sleep, Hardware Authentication, Troubleshooting, FAQ, System Snapshots, Security, Dual Boot Install, Unattended Installs.
- **A separate legacy v3 manual** is preserved at [learn.omacom.io](https://learn.omacom.io/2/the-omarchy-manual) (49 chapters), explicitly marked "preserved for legacy installations." [V]
- **Video:** an official full introduction video accompanied 4.0 — [youtube.com/watch?v=F7fe9pa8OeE](https://www.youtube.com/watch?v=F7fe9pa8OeE). [V] (linked from v4.0.0 release notes)
- **Community:** an official **Discord** is linked from omarchy.org's top nav, and 4.0 added *"the Discord community and Herdr's keybindings viewer to the Learn menu"* — i.e. community is reachable from inside the OS. [V] Discord member count **[NOT FOUND]**.
- **Other site sections [V]:** News, Teams (including a named **Security team**), Patrons, Sponsorships, **Meetups**, **Workstations**, **Merch**, Plugins.
- **Onboarding path [V]:**
  1. ISO → configurator wizard → answer a handful of questions → automated install (<1–5 min).
  2. First boot: fingerprint enrollment offered if a reader is present.
  3. "Coming From Mac or Windows" chapter sets expectations: *"you don't drag windows around or snap them to screen halves"*; *"The instincts transfer faster than you'd think"*; *"Give it two weeks."*
  4. The taught primitive is **one hotkey — `Super + K`** — which shows the complete binding reference.
  5. `Super + Space` menu is the discovery surface for installing/removing/configuring everything else.

**[I]** The onboarding design bet is: teach two keys (`Super+Space`, `Super+K`), let everything else be discovered from a searchable menu, and set a two-week expectation rather than promising familiarity.

---

## 5. Footprint

**No independent benchmark of Omarchy 4 was found.** Every number below is a project/author self-report unless marked otherwise.

| Metric | Value | Marker | Source & date |
|---|---|---|---|
| **ISO size** | "under 6 GB", down "over a gigabyte" from 3.x | [V-SELF] | [v4.0.0 release notes](https://github.com/basecamp/omarchy/releases), 2026-08-14 |
| **ISO size (3.x era, third-party)** | ~6.8 GB | [U] | third-party install guides; not primary |
| **Install duration** | <1 min on fast hardware; ≤5 min on older machines; "+30% faster" in 4.0 | [V-SELF] | [Getting Started](https://omarchy.org/manual/getting-started/); v4.0.0 notes |
| **Shell process runtime memory (4.0)** | "**Less than 300mb of runtime memory load** once you account for the shared library usage" | [V-SELF] | DHH, [x.com/dhh/status/2087441252182548857](https://x.com/dhh/status/2087441252182548857), Aug 2026. **This is the Quickshell shell process only, not whole-system idle RAM.** |
| **Whole-system idle RAM (v2 era)** | "A fresh Omarchy installation uses just **1.3GB RAM on boot**. No wonder folks are making this work on machines with as little as 4GB!" | [V-SELF] | DHH, [x.com/dhh/status/1952346236557603261](https://x.com/dhh/status/1952346236557603261), Aug 2025. **Pre-Quattro. No 4.x equivalent figure found.** |
| **Idle CPU** | "an idle desktop stops burning CPU" (event-driven, not polled) | [V-SELF] | v4.0.0 release notes. No watt or percentage figure published. |
| **Boot time** | — | **[NOT FOUND]** | No published figure from the project or any reviewer. |
| **Installed disk footprint** | — | **[NOT FOUND]** | Third-party guides quote 10–60 GB free-space needs [U]; the project publishes no installed-size figure. |
| **Minimum RAM** | — | **[NOT FOUND]** officially; DHH's tweet implies 4 GB is workable [V-SELF] |

**Counter-evidence on memory, worth noting [V]:** GitHub issue [#2435](https://github.com/basecamp/omarchy/issues/2435) documented Walker (the pre-4.0 launcher) leaking — *"memory usage grows each time launching an app with walker"*, exceeding 1.2 GB. That component **no longer exists in 4.0**, so the specific leak is moot, but it shows self-reported idle figures did not reflect steady-state usage in practice. Issue [#3338](https://github.com/basecamp/omarchy/issues/3338) is a user reporting high RAM attributed to a background Windows VM.

**[I]** Bottom line on footprint: the *shell* is genuinely light by desktop-environment standards and the project has one credible architectural reason for it (eight daemons collapsed into one process). But there is **no independent, current, whole-system measurement of Omarchy 4** in the public record — anyone citing "1.3 GB" is citing a 12-month-old tweet about a different shell stack.

---

## 6. Security Posture

### 6.1 What is claimed and shipped [V] ([manual: Security](https://omarchy.org/manual/security/))

| Area | Position |
|---|---|
| **Disk encryption** | **LUKS full-disk encryption is the install default.** Two passwords (drive unlock + login/sudo), both changeable from the Omarchy menu. [V] |
| **Secure Boot** | **Explicitly NOT supported — you must disable Secure Boot and/or TPM in BIOS to install.** [V] This is the single largest security gap. |
| **Firewall** | `ufw` on by default. *"All incoming traffic is blocked by default except for port 53317 for LocalSend."* SSH off until enabled via `Setup > Security > SSHD`, with brute-force rate limiting. `ufw-docker` used so containers can't punch through. [V] |
| **Hardware auth** | Fingerprint PAM flows for lock screen, polkit and sudo (gated on lid state); FIDO2 setup supported; dedicated "Hardware authentication" manual chapter. [V] |
| **ISO signing** | ISOs signed with GPG key `40DFB630FF42BCFFB047046CF0134EE680CAC571`; `.sig` and `.sha256` published beside each ISO. [V] |
| **Patch velocity** | Relies on Arch's rolling model for upstream CVE patches — but **Stable channel deliberately runs one month behind Arch.** [V] |
| **Disclosure process** | `security@omarchy.org`; named Security team at [omarchy.org/teams](https://omarchy.org/teams/#security); responsible-disclosure policy; security credits page. In-scope: vulnerabilities. Out-of-scope: regular bugs. [V] ([omarchy.org/security](https://omarchy.org/security/)) |
| **Sandboxing** | **None claimed.** No Flatpak/bubblewrap/AppArmor/SELinux posture stated anywhere in the manual. [V] absence |

### 6.2 Package signing — a material discrepancy [V, primary evidence]

The manual says packages are GPG-signed. **The shipped pacman config does not enforce that for Omarchy's own repository.** Read directly from `default/pacman/pacman-stable.conf` on the `quattro` branch:

```
SigLevel = Required DatabaseOptional     # global default (Arch repos)
LocalFileSigLevel = Optional

[omarchy]
SigLevel = Optional TrustAll
Server = https://pkgs.omarchy.org/stable/$arch
```

`pacman-edge.conf` and `pacman-rc.conf` carry the **identical `SigLevel = Optional TrustAll`** for `[omarchy]`. [V]

**What this means [I]:** Arch's own `core`/`extra`/`multilib` packages are signature-verified (`Required`). Omarchy's own packages — which include the shell, the CLI, the installer glue, themes, and the Neovim config — are **not** signature-verified by pacman; `TrustAll` accepts any signature and `Optional` accepts none at all. Integrity rests on TLS to `pkgs.omarchy.org` (Cloudflare-fronted) rather than on package signatures. This was flagged independently by a third-party reviewer ([codetocloud.io, 2026-08-14](https://codetocloud.io/blog/omarchy-4-quattro-whats-new/)) and I confirmed it against the repo. It is a real gap between documented and implemented posture.

### 6.3 Plugins run unsandboxed [V]

[Manual: Shell Plugins](https://omarchy.org/manual/shell-plugins/), verbatim: *"Plugins run as arbitrary, unsandboxed code inside your long-lived shell process"* with full user-account permissions. The install flow shows the repo URL and requires confirmation; the manual's advice is "only add repositories from trusted sources and review code before enabling." Validation (`omarchy plugin validate`) checks schema and paths — **not** behaviour.

### 6.4 The 4.0.1 security fix list — an unusually candid signal [V]

v4.0.1 (2026-08-25, eleven days after 4.0.0) is described as *"mostly for a collection of security fixes that was validated and examined by the new Omarchy Security team."* The fixes name the vulnerability classes:

- *"Launch claude and codex agents with **auto-review instead of full bypass**"* (#7001, by @dhh) — **[I] 4.0.0 shipped coding agents in full-permission-bypass mode by default.**
- *"Stop an installed theme from running code"* (#7884)
- *"Stop USB device names from being executed as Hyprland Lua"* (#8129) — [I] a malicious USB device name was a code-execution vector.
- *"Stop a video title from becoming the Download Video play command"* (#7847)
- *"Don't put the user in the docker group; make it opt-in"* (#8056) — [I] 4.0.0 gave the default user passwordless-root-equivalent docker access.
- *"Stop the FIDO2 setup staging its authfile at a predictable /tmp path"* (#7904)
- *"Run notification click actions as safe argv"* (#7926)
- *"Remove the sudo lockout reset command"* (#8046)
- *"Guard plugin-add against git transport-helper URLs"* / *"Refuse the git transports Omarchy does not clone from"* (#8067, #8174)
- *"Pin trusted PATH in privileged DNS helper"* (#8172)

**[I]** Two readings, both fair: (a) the project now has a real security team doing real work with public credit and fast turnaround; (b) a rewrite that touched the whole shell shipped with at least eleven exploitable paths, several of them classic shell-injection through untrusted input (theme files, USB names, video titles, notification actions), which suggests the codebase moves faster than it is reviewed.

**Also relevant [V]:** the codetocloud review notes 4.0.0 itself *"closed three code execution paths exploitable by malicious themes."*

---

## 7. Community & Momentum

| Signal | Value | Marker | Source (measured 2026-08-25) |
|---|---|---|---|
| GitHub stars | **31,171** | [V] | GitHub API `repos/basecamp/omarchy` |
| Forks | **3,171** | [V] | GitHub API |
| Watchers | 161 | [V] | GitHub API |
| **Contributors** | **~450** (non-anonymous) | [V] | GitHub API contributors pagination, `page=450` as last |
| **Open issues** | **703** | [V] | GitHub search API, `is:issue is:open` |
| **Closed issues** | **2,394** | [V] | GitHub search API |
| **Open PRs** | **878** | [V] | GitHub search API |
| **Issues opened in last 30 days** | **629** | [V] | GitHub search API, `created:>2026-07-26` |
| **Commits in last 30 days** | **448** | [V] | GitHub search API |
| Default branch | `quattro` | [V] | GitHub API |
| Last push | 2026-08-25 | [V] | GitHub API |
| **Releases** | **63** since v1.1.1 (2025-07-05) | [V] | GitHub API |

**Release cadence [V]** (releases per month, from GitHub API):

```
2025-07: 15   2025-08: 13   2025-09: 4   2025-10: 5   2025-11: 6   2025-12: 1
2026-01:  4   2026-02:  2   2026-03: 1   2026-04: 3   2026-05: 5   2026-07: 2   2026-08: 2
```

**[I]** Cadence peaked at ~15/month in the first two months and settled to ~2–5/month through 2026 — i.e. it matured from frantic to a normal minor-release rhythm, with 4.0 as the big-bang event.

**Notable:** `@omarchybot` appears as a PR author on multiple merged security fixes in v4.0.1. [V] **[I]** The project is landing AI-authored patches into the security path under a bot identity.

### 7.1 Funding and institutional backing [V]

- **Omacom Foundation** launched **2026-08-21** as a non-profit to *"hold the trademarks, fund the infrastructure, promote the work, and support the open-source projects"* Omarchy depends on. ([omarchy.org/news](https://omarchy.org/news/2026/08/omacom-foundation-launches-with-8-million/))
- **$8M** from eight founding patrons at $1M each: **Michael Dell** (Dell), **Patrick Collison** (Stripe), **Tobi Lütke** (Shopify), **Jack Dorsey** (Block), **Matthew Prince** (Cloudflare), **Brendan Iribe** (Sesame, ex-Oculus), **Jason Fried** (37signals), **DHH**.
- Within days, **funding rose to $10M** with **Drew Houston** (Dropbox) and **Peter Steinberger** (OpenClaw) added. ([omarchy.org/news](https://omarchy.org/news/2026/08/omacom-foundation-funding-hits-10m/))
- **First external grant: Hyprland** — an exclusive sponsorship for Vaxry, the compositor's developer. [U] (reported in coverage; not confirmed against a primary page)
- **[I]** This is an extraordinary momentum signal — a desktop Linux project with $10M and Michael Dell's name on it has no recent precedent. It also creates the governance concentration risk raised in §8.

### 7.2 Adoption

- **[V-SELF]** DHH, Nov 2025: *"We've distributed over a petabyte worth of ISOs in the last thirty days alone, which is enough for 150,000+ new installs. In total, we're well into the hundreds of thousands of ISO downloads."* ([x.com/dhh/status/1985619573056352742](https://x.com/dhh/status/1985619573056352742))
- **[I]** This is a bandwidth-derived estimate, not telemetry. ISO bytes ÷ ISO size ≠ installs — it counts re-downloads, mirrors, CI, and abandoned downloads. Treat as an order-of-magnitude ceiling.
- No 2026 adoption figure found. **[NOT FOUND]**

### 7.3 Ecosystem

- **Plugin marketplace** at [omarchyplugins.com](https://omarchyplugins.com/) — but it is an **"Independent community project. Not affiliated with, sponsored by, or endorsed by Omarchy or 37signals."** [V] When I fetched it on 2026-08-25 it rendered **"0 community plugins / No plugins found"** [V] — likely a client-side rendering issue rather than a true empty registry, since secondary sources claim 44 plugins at Quattro beta and "over 500" more recently [U]. **Treat any plugin-count number as unverified.**
- A **"first plugin competition"** was run in Aug 2026. [V] ([omarchy.org/news](https://omarchy.org/news/))
- **Downstream/derivative projects exist** — e.g. "Omarchy on CachyOS" was a Show HN. [V]
- Official **Meetups** and **Workstations** (hardware) pages exist on omarchy.org. [V]

---

## 8. Explicit Non-Goals & Scope Limits

Stated by the project itself:

1. **Not aiming for Mac/Windows familiarity. [V]** Manual ch.1, verbatim: *"Omarchy isn't like Windows and it's not like macOS either. It's not trying to be as familiar as possible. It's trying to be beautiful and better. Embrace the Linux-ness of it all. Manually editing some config files, sure. Heavy on the terminal, definitely."*
2. **Not a configuration framework — an "omakase" (chef's choice) system. [V]** Manual ch.1: *"There's zero bloat here: Just everything I use."* The package selection is explicitly one person's taste, not a survey of user needs.
3. **Not tiling-optional. [V]** "Coming From Mac or Windows" warns *"you don't drag windows around or snap them to screen halves"* and asks users to *"give the tiling a real chance first."*
4. **Secure Boot / TPM are out of scope. [V]** Required to be disabled to install.
5. **Only the ISO is supported. [V]** ISO README: *"The Omarchy ISO is the only supported way to install Omarchy."* Manual installation over an existing Arch install is documented in v3 but is not the supported path in v4.
6. **`pacman -Syu` is not a supported update path. [V]** Deliberately blocked.
7. **Snapshots do not protect user data. [V]** Explicitly: root only, not `/home`.
8. **Snapshots are Limine-only. [V]** GRUB and systemd-boot installs get no rollback.
9. **Plugins are not sandboxed and that is by design. [V]** The manual states it as a property to be managed by user trust, not a bug.
10. **Bluetooth keyboards are out of scope at boot. [V]** Because of LUKS.

---

## 9. Criticisms — What Real Users Say

Ordered roughly by how well-evidenced and how current each criticism is. Dated criticisms are marked as such.

### 9.1 "It's not a distro, it's dotfiles" — the definitional critique

- **HN: "Omarchy Is Not A Distro"** — 186 points, 168 comments, ~May 2026. ([news.ycombinator.com/item?id=48257612](https://news.ycombinator.com/item?id=48257612)) The article argues *"the entire 'omarchy distribution' amounts to little more than Arch linux"* with default configs; commenters call it *"just ricing"* rather than packaging or infrastructure work. [V]
- **HN: "I cannot for the life of me understand the Omarchy hype"** — ~Sep 2025. ([news.ycombinator.com/item?id=45334309](https://news.ycombinator.com/item?id=45334309)) Xerox9213: *"Does Omarchy offer anything other than opinionated dotfiles? These have always existed."* nickjj: *"I think it's popular because DHH turned dotfiles into a product and it's being marketed as a distro."* [V]
- Also on [Lobsters](https://lobste.rs/s/t1spjc/omarchy_is_not_distro), where commenters split on the definition and noted the piece would be stronger *"with less nitpicking and sass."* [V]
- **Currency note [I]:** this critique is **materially weaker against 4.x than it was against 2.x/3.x.** Omarchy 4 ships its own ISO, its own pacman repository, its own **delayed Arch mirror**, its own kernel package (`linux-ptl`), its own applications (Omawrite/Omacut/Omacalc), its own multiplexer (Herdr), migrations, and a snapshot/rollback integration. Whatever it was in 2025, in Aug 2026 it does most of what "distro" normally means. The critique survives mainly as "it does no upstream packaging or maintenance work of its own."

### 9.2 Shell-rewrite instability — the strongest *current* criticism

This is the most concrete and most current body of evidence. **629 issues opened in the 30 days around the 4.0 release [V].** The most-discussed open issues created since 2026-08-01 (GitHub search API, sorted by comments, measured 2026-08-25) cluster hard into a few failure modes:

**Lock screen / session strandings — the single worst cluster (20 open issues with "lock screen" in the title [V]):**
- [#7106](https://github.com/basecamp/omarchy/issues/7106) (17 comments) — *"Saving a file under `~/.config/omarchy/plugins/` while locked strands the session"*
- [#6628](https://github.com/basecamp/omarchy/issues/6628) (16 comments) — *"Lock shell dies during normal idle→lock; session permanently locked, **reboot required**"*
- [#6888](https://github.com/basecamp/omarchy/issues/6888) (12) — *"Stranded-lock recovery never completes"*
- [#6995](https://github.com/basecamp/omarchy/issues/6995), [#7145](https://github.com/basecamp/omarchy/issues/7145) — idle/lock races, lock screen flashing blank
- **[I]** Replacing `hyprlock`/`hypridle` with in-house Quickshell code moved the lock screen into the same process as everything else — so a shell crash is now a lockout requiring a hard reboot. That is a structural consequence of the single-process design, not a one-off bug.

**Quickshell crashes [V]:**
- [#6952](https://github.com/basecamp/omarchy/issues/6952) — *"Quickshell SIGSEGV in QQuickRepeater when PipeWire removes USB audio nodes"*
- [#6805](https://github.com/basecamp/omarchy/issues/6805) — *"Quickshell segfaults in QQuickItem::mapToScene during context-menu delivery"*

**NVIDIA — 32 open issues with "nvidia" in the title [V]:**
- [#7045](https://github.com/basecamp/omarchy/issues/7045) — *"NVIDIA 50xx Users - Can't Install - Boots to black screen"*
- [#7755](https://github.com/basecamp/omarchy/issues/7755) — *"NVIDIA env vars (NVD_BACKEND, LIBVA_DRIVER_NAME, __GLX_VENDOR_LIBRARY_NAME) never set: `os.execute()` broken"* — [I] a regression introduced by the `.conf`→Lua config migration
- [#4200](https://github.com/basecamp/omarchy/issues/4200) — black screen after wake on NVIDIA
- [#1776](https://github.com/basecamp/omarchy/issues/1776) — hybrid iGPU+dGPU power management; dGPU never enters d3cold, drains battery

**Sleep/suspend — 28 open "suspend" + 13 "sleep" issues [V]:** [#4740](https://github.com/basecamp/omarchy/issues/4740) suspend/hibernate not working; [#4184](https://github.com/basecamp/omarchy/issues/4184) suspend broken in 3.3; reports of 72%→18% battery over 8h of "suspend".

**Post-Quattro regressions [V]:**
- [#7549](https://github.com/basecamp/omarchy/issues/7549) — *"Frequent kernel panics after upgrade to Quattro"*
- [#6768](https://github.com/basecamp/omarchy/issues/6768) — Quattro causes **sluggish behaviour on Dell XPS 16 (Panther Lake)**; reverting to the prior release restored performance
- [#6637](https://github.com/basecamp/omarchy/issues/6637) — system freezes on Framework 13 after screen upgrade
- [#7019](https://github.com/basecamp/omarchy/issues/7019) — migration refuses to run because *"a browser window is open"*
- [#7565](https://github.com/basecamp/omarchy/issues/7565) — calculator keybindings survive `omarchy-remove-preinstalls` and point at a removed binary
- [#6976](https://github.com/basecamp/omarchy/issues/6976) — user ran out of disk space upgrading to Quattro

**Peripherals [V]:** [#6956](https://github.com/basecamp/omarchy/issues/6956) Bluetooth widget vanishes when Bluetooth is off; [#7776](https://github.com/basecamp/omarchy/issues/7776) built-in camera dead on fresh install; [#7199](https://github.com/basecamp/omarchy/issues/7199) screensaver fires during fullscreen video in Zen Browser (works in Chromium — [I] the idle inhibitor only recognises some browsers); [#6947](https://github.com/basecamp/omarchy/issues/6947) Steam idle-inhibit matches the client but not games.

**VMs [V]:** [#7835](https://github.com/basecamp/omarchy/issues/7835) black screen in VMware after entering the LUKS password. HN, Sep 2025 (sonar_un): *"I spent 2 days trying to get it to run in a VM and it was not playing well."*

**The project's own advice corroborates this [V]:** third-party review of 4.0 ([codetocloud.io](https://codetocloud.io/blog/omarchy-4-quattro-whats-new/), 2026-08-14) recommends *"if it's your only work machine, you should wait a few days since early point releases will fix real bugs."*

### 9.3 Breaking changes punish customisers

- **[V]** Quattro *"breaks every hook the repository has into Omarchy: the git checkout becomes a pacman-owned symlink, Hyprland config converts from `.conf` to Lua, Waybar is replaced by a Quickshell shell configured through `shell.json`, and generated theme state moves locations."* ([codetocloud.io](https://codetocloud.io/blog/omarchy-4-quattro-whats-new/))
- Custom edits under `~/.local/share/omarchy` are now pacman-owned and **must be migrated to `~/.config/` before updating.** [V]
- **HN, "Omarchy 4 concerns, am I the only one?"** ([news.ycombinator.com/item?id=48893609](https://news.ycombinator.com/item?id=48893609), ~Jul 2026, 4 points, 3 comments — a small thread, weight accordingly). OP: *"from thousands of ai written lines of code to some system specific moves that might break tons of installs where people have customized things quite a bit."* [V]
- **HN (nickjj):** *"I don't want to ask for permission or maintain a fork to deviate from the Omarchy defaults."* [V] — the omakase model means deviation is unsupported by construction.
- **HN (dinkleberg):** *"why not just use arch directly? You set it up once and it is yours forever."* [V]

### 9.4 Architectural / dependency risk

- **Single point of failure [I, well-supported]:** bar + launcher + menu + notifications + OSD + panels + **lock screen** + **polkit agent** in one process means one crash takes the whole desktop, including authentication. §9.2's lock-strand issues are this risk realised.
- **Moving dependency [U, from secondary review]:** the desktop reportedly builds on `quickshell-git`, tracking upstream git rather than a tagged release. *"Basing your entire shell on a moving dependency could become problematic."* I did **not** confirm the `-git` package against the repo — the base package list names plain `quickshell`. **Treat as unverified.**
- **Unsandboxed plugins in the shell process [V]** — §6.3. A third-party plugin crashing or misbehaving takes the lock screen with it.

### 9.5 Security-posture criticisms

- **Secure Boot must be disabled. [V]** Named as a gap by an independent reviewer: *"gap with mainstream"* distributions ([dashen-tech.com](https://dashen-tech.com/en/dev-tools/omarchy-4-quattro-review/), 2026-08-19).
- **Omarchy's own repo is `SigLevel = Optional TrustAll`. [V — confirmed by me against the repo]** See §6.2.
- **v4.0.0 shipped agents in full-permission bypass and put the user in the docker group. [V]** Both reversed in 4.0.1 eleven days later.
- **Original install method was `curl | bash` as root** with limited warning — resolved by the move to an ISO at 2.0. [U] on the detail, but the ISO-only present state is [V]. **Dated criticism.**
- **AUR exposure [V-third-party]:** community packages of *"varying quality requiring manual PKGBUILD review"* ([dashen-tech.com](https://dashen-tech.com/en/dev-tools/omarchy-4-quattro-review/)).

### 9.6 Defaults and bundling

- **HiDPI assumption [V, though possibly dated].** The "Omarchy Is Not A Distro" piece: *"Omarchy assumes you're running on a 2x-capable retina-class display by default"*, with PPI requirements matching <2% of monitors — read as targeting Apple hardware. Omarchy 4 added `omarchy display text size` (a 9–20px knob moving shell font, GTK text-scaling-factor and terminal point size together) and per-display auto-scaling [V], which **partially answers** this. Whether the 2x default remains is **[NOT FOUND]**.
- **Bundling DHH's own products [V].** HN (danpalmer): *"Sounds like Omarchy also ships with a bunch of bloatware. Why would I need the Hey or Basecamp apps"*; the "not a distro" piece objects to 1Password, Hey.com and Grok/X shortcuts *"benefiting DHH's business interests."* **Currency correction [V]:** as of 4.x these are **not in the 148-package base pacstrap** — they exist as keybindings and menu-installable web apps. The criticism now applies to *default keybindings and menu prominence*, not to preinstalled packages.
- **Proprietary software in a Linux distro [V].** Obsidian is a base package [V, confirmed in package list]; Typora was until 4.0 replaced it with Omawrite [V]. Called out by [tedium.co](https://tedium.co/2025/10/13/omarchy-linux-distro-commentary/) (2025-10-13) as contradicting distro norms.
- **Caps Lock is remapped to compose by default** [V-third-party, codetocloud] — deliberate, and a reliable source of surprise.

### 9.7 Learning curve

- **[V-third-party]** [dashen-tech.com](https://dashen-tech.com/en/dev-tools/omarchy-4-quattro-review/) (2026-08-19) rates stability **7.5/10**, learning curve *"steep"*, requiring *"a week of learning"*; gaming support *"average"* vs Ubuntu's *"excellent"*; notes localisation gaps (*"interface defaults to English, and some documentation hasn't been localized yet"*). Explicitly **not recommended for enterprise users, gamers, non-technical users, or general office workers.**
- **[V]** [tedium.co](https://tedium.co/2025/10/13/omarchy-linux-distro-commentary/): the distro *"doesn't hold your hand"*; defaulting to Neovim carries *"a significant learning curve"*; keyboard-first design is alien to Mac/Windows users.
- The project agrees — see §8. This is a scope choice, not a defect, but it bounds the addressable audience.

### 9.8 Distribution and infrastructure

- **[V]** [tedium.co](https://tedium.co/2025/10/13/omarchy-linux-distro-commentary/): no torrent; ISO offered *"only ... as a single download from a Cloudflare server"* — hard on weak connections, and at ~6 GB that is a real barrier.
- **Dated criticism [V]:** the same review complains the installer *"insisted on deleting my entire drive"* with no partition-preserving option. **Fixed in 4.0** by free-space dual-boot installs.

### 9.9 Governance, funding, and the founder

This is a substantial and recurring strand. Reporting it factually because it demonstrably affects adoption decisions.

- **Foundation independence [V].** Lobsters on the $8M launch ([lobste.rs/s/svrhsc](https://lobste.rs/s/svrhsc/omacom_foundation_launches_with_8), 2026-08-21). thomas0 noted the foundation **did not donate to SPI**, Arch's non-profit sponsor, and wrote: *"they also have $8,000,000 reasons to just take all the work and do a hard fork."* [V]
- **Upstream relations [V].** Foxboron (an Arch Linux developer) — highest-scored comment in that thread (17): *"I personally hope Arch is principled enough to stay far away from Mr.Fash and his friends."* [V] **[I]** Friction with Arch's own maintainers is a live risk for a distro whose entire package base is Arch's.
- **Founder politics [V].** Recurs across HN, Lobsters, Reddit and blogs. [tedium.co](https://tedium.co/2025/10/13/omarchy-linux-distro-commentary/) (2025-10-13) quotes criticism that DHH is *"desperately trying to convince you that he is not 'far right'"* and references a post *"many saw as deeply xenophobic, bordering on eugenicist"*, concluding *"no matter its technical benefits, the 'opinionated' Omarchy fails the test."* HN commenter klaxzygen said they would reconsider using products from someone with those stated positions. Lunduke has framed Omarchy as *"the non-woke distro"* — i.e. the political framing runs in both directions.
- **Bus factor / cult-of-personality [V].** nickjj on HN: *"it's popular because DHH turned dotfiles into a product."* **[I]** The commit and release-note evidence shows @dhh personally authoring a large share of headline features, which concentrates key-person risk even with $10M behind the foundation.
- **Community-support gap [U].** Secondary summary of a Lobsters thread: *"the best product in open source means nothing without community support."* Could not attribute to a specific comment. **Low confidence.**

### 9.10 Fair counterweight — what critics concede

Recorded so the criticism section is not one-sided. All [V] from the same threads.

- HN: *"I tried to setup Arch with Hyprland like 3 times... Omarchy fixed that."*
- HN: the out-of-box experience is *"highly functional, aesthetically pleasing and challenges users to lean more on keyboard shortcuts."*
- HN: *"config file structure and hotkeys are well designed and useful out of the box"*; all scripts are plain bash and editable; PWAs are *"first class citizens"*; Hyprland is made *"usable out of the box."*
- Defenders consistently frame the value as **time-to-working-desktop**: manual Arch+Hyprland is *"a weekend of tweaking"*; Omarchy is minutes.
- Some ex-macOS users report it solved workflow problems macOS did not.

---

## 10. Open Questions / Gaps in This Research

| Question | Status |
|---|---|
| Boot time (any measurement) | **[NOT FOUND]** — no figure from project or reviewers |
| Installed disk footprint after a default install | **[NOT FOUND]** |
| Whole-system idle RAM on 4.x | **[NOT FOUND]** — only the 12-month-old 1.3 GB v2 tweet and the shell-only <300 MB claim |
| Official minimum hardware requirements | **[NOT FOUND]** on omarchy.org |
| Actual plugin ecosystem size | **[U]** — marketplace is unaffiliated and rendered empty when fetched; counts of 44 and 500+ appear in secondary sources only |
| Whether `quickshell` or `quickshell-git` is actually shipped | **[U]** — base package list says `quickshell`; a reviewer says `-git` |
| What `aether`, `tensaku`, `tobi-try`, `linux-ptl`, `ttfx`, `usage` are | **[NOT FOUND]** |
| Discord member count | **[NOT FOUND]** |
| Omacom Foundation governance structure (board, bylaws, voting) | **[NOT FOUND]** — announcement names patrons but not governance |
| Whether the Hyprland/Vaxry sponsorship is confirmed by a primary source | **[U]** |
| Whether the 2x-HiDPI default persists in 4.x | **[NOT FOUND]** |

---

## Source Index

**Primary — project:**
- https://omarchy.org/
- https://omarchy.org/manual/ (and chapters: getting-started, themes, hotkeys, the-top-bar, updates, system-snapshots, security, shell-plugins, coming-from-mac-or-windows, faq)
- https://omarchy.org/security/
- https://omarchy.org/news/2026/08/omacom-foundation-launches-with-8-million/
- https://omarchy.org/news/2026/08/omacom-foundation-funding-hits-10m/
- https://github.com/basecamp/omarchy (README, releases v4.0.0 / v4.0.1, `manual/01-welcome-to-omarchy.md`, `install/omarchy-base.packages`, `install/omarchy-other.packages`, `default/pacman/pacman-{stable,edge,rc}.conf`, `bin/`)
- https://github.com/omacom-io/omarchy-iso/blob/quattro/README.md
- GitHub REST + search API, queried 2026-08-25
- https://learn.omacom.io/2/the-omarchy-manual (legacy v3 manual)

**Primary — author statements:**
- https://x.com/dhh/status/2087441252182548857 (<300 MB shell memory, Aug 2026)
- https://x.com/dhh/status/1952346236557603261 (1.3 GB boot RAM, Aug 2025)
- https://x.com/dhh/status/1985619573056352742 (petabyte of ISOs / 150k installs, Nov 2025)

**Third-party coverage & criticism:**
- https://news.ycombinator.com/item?id=48257612 ("Omarchy Is Not A Distro", 186 pts)
- https://news.ycombinator.com/item?id=45334309 ("cannot understand the hype")
- https://news.ycombinator.com/item?id=48893609 ("Omarchy 4 concerns")
- https://news.ycombinator.com/item?id=46923469 ("Omarchy First Impressions")
- https://lobste.rs/s/svrhsc/omacom_foundation_launches_with_8
- https://lobste.rs/s/t1spjc/omarchy_is_not_distro
- https://tedium.co/2025/10/13/omarchy-linux-distro-commentary/
- https://codetocloud.io/blog/omarchy-4-quattro-whats-new/ (2026-08-14)
- https://dashen-tech.com/en/dev-tools/omarchy-4-quattro-review/ (2026-08-19)
- https://www.phoronix.com/news/Omarchy-4.0-Released (2026-08-14)
- https://www.phoronix.com/news/Omarchy-3.7-Released
- GitHub issues cited inline throughout §9.2
