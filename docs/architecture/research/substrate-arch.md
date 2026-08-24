# Substrate research: minimal Arch-based system

**ADR-001 input — spec section 8.1.**
Research date: 2026-08-24. All versions, dates, and numbers below were checked against live sources on this date unless labeled otherwise. Claims sourced from third-party summaries rather than primary documents are labeled. Nothing here has been locally benchmarked yet; footprint numbers are from published sources, not our own measurements.

---

## 1. Overview

Arch Linux is a rolling-release, binary x86_64 distribution with a deliberately small base system, a very large official repository plus the AUR, and packaging that tracks upstream within days. The proposition for Punar is: start from `pacstrap`-installed minimal Arch, ship it as a vendor-built image with a **date-pinned, vendor-controlled package channel**, add btrfs+snapper (or an A/B image scheme) for rollback, sbctl-signed UKIs for Secure Boot, and a first-party control plane on top.

This is no longer a speculative architecture. Omarchy (DHH / omacom-io, sponsored by 37signals) has been shipping exactly this stack — Arch + Hyprland, own curated pacman repo, own delayed Arch mirror, offline-mirror ISO built with mkarchiso in a container, Limine + UKI + btrfs/snapper rollback, LUKS by default — at consumer scale since 2025, and as of Omarchy 4 (2026-08-14) it runs a Quickshell-based desktop shell, the same shell toolkit Punar's spec targets. SteamOS 3 demonstrates the heavier-weight variant: immutable A/B-imaged Arch derivative updated with RAUC/casync.

The core trade: Arch gives the smallest, freshest, most familiar substrate with the exact desktop components Punar needs already packaged in the *official* repos — at the cost of vendor-built controls for everything enterprise-shaped (update channels, reproducibility discipline, security advisory triage, Secure Boot chain, rollback), because upstream Arch provides mechanisms but no product-level guarantees.

---

## 2. Criteria-by-criteria assessment (spec section 8 list)

### 2.1 Resource efficiency

- **Base disk footprint.** The official Arch OCI/Docker `base` image is ~150 MiB (compressed layer; `base-devel` ~260 MiB) ([archlinux/archlinux-docker](https://gitlab.archlinux.org/archlinux/archlinux-docker)). The official `arch-boxes` VM images are 516 MB (basic qcow2) and 556 MB (cloudimg qcow2) as of build 20260815 ([mirror listing](https://geo.mirror.pkgbuild.com/images/latest/)). A bootable on-disk install (base + linux + linux-firmware + bootloader) lands around 2 GiB; the installation guide's stated floor is "less than 2 GiB" ([ArchWiki install guide](https://wiki.archlinux.org/title/Installation_guide)). linux-firmware is the dominant single cost.
- **Idle RAM.** A console-only base system idles in the tens of MB (forum reports; anecdotal). The most relevant published graphical figure: DHH reports **a fresh Omarchy install uses ~1.3 GB RAM on boot** ([DHH, X, 2025-08-04](https://x.com/dhh/status/1952346236557603261)). Note: that is *above* Punar's 1.0 GB idle target and below the 1.5 GB hard ceiling (spec 6.1) — but Omarchy ships far more userland than Punar's minimal profile would (Waybar-era stack, background services, Dropbox-class extras). A stripped Arch + Hyprland + greetd + Quickshell composition should land meaningfully lower; this is an expectation, not a measurement — Milestone 0 should measure it in a VM and record it in `PERFORMANCE_BUDGETS.md`.
- No mandatory heavyweight daemons: systemd + dbus is essentially the floor. No snapd/packagekit-style agents unless we add them.

**Verdict: strong.** Best-in-class among the three candidates for both disk and RAM floor; the spec's budgets are plausible but must be verified by measurement, not assumed from Omarchy's number.

### 2.2 Developer familiarity

- Arch + AUR is the default enthusiast/developer distro family; pacman and PKGBUILD are widely known. Omarchy's traction is direct evidence that the target audience (developers) accepts and likes this base.
- Hiring/contribution surface: PKGBUILD is drastically simpler than Nix expressions or rpm-ostree/Containerfile layering; a small team can be productive immediately.

**Verdict: strong.** This is Arch's clearest win over NixOS (steep language learning curve) and Fedora Atomic (less mindshare among the target demographic).

### 2.3 Reproducibility

- Arch runs an official rebuilderd instance. As of 2026-08-24 it reports **13,534 reproducible / 2,037 bad / 3 unknown ≈ 86.9% bit-for-bit reproducible** ([reproducible.archlinux.org dashboard API](https://reproducible.archlinux.org/api/v0/dashboard)). So: majority reproducible, not complete, and no *guarantee* for any given package.
- Official Docker and WSL **images** are verified bit-for-bit reproducible by a third-party weekly rebuilder (both GOOD as of 2026-08-19; ISO/cloud images not yet covered) ([archimgrepro.antiz.fr](https://archimgrepro.antiz.fr/)).
- Practical vendor path: **input-pinning, not bit-for-bit.** A date-pinned snapshot repo (see 2.10) plus a locked package list makes image builds *deterministic in inputs*; `mkosi` supports Arch/pacman and has explicit reproducibility options (SOURCE_DATE_EPOCH clamping, fixed repart seeds) ([mkosi man page](https://man.archlinux.org/man/mkosi.1.en), [J. van der Waa: reproducible Arch images with mkosi](https://vdwaa.nl/mkosi-reproducible-arch-images.html)).

**Verdict: adequate with vendor discipline; weaker than NixOS.** Honest framing for the ADR: Arch gives ~87% package-level bit-reproducibility and fully pinnable inputs; it does not give NixOS-grade closure over the whole system definition.

### 2.4 Package availability

Everything Punar's MVP needs is in **official repos** (not AUR), current as of 2026-08-24:

| Package | Repo | Version | Last update |
|---|---|---|---|
| hyprland | extra | 0.56.2-1 | 2026-08-05 ([pkg page](https://archlinux.org/packages/extra/x86_64/hyprland/)) |
| quickshell | extra | 0.3.1-1 | 2026-08-21 ([pkg page](https://archlinux.org/packages/extra/x86_64/quickshell/)) |
| greetd | extra | 0.10.3-2 | 2026-03-27 ([pkg page](https://archlinux.org/packages/extra/x86_64/greetd/)) |
| chromium | extra | 151.0.7922.173-1 | 2026-08-21 ([pkg page](https://archlinux.org/packages/extra/x86_64/chromium/)) |

- Quickshell graduated from AUR-only to official `extra` (release builds official; `quickshell-git` remains in AUR) ([quickshell install docs](https://quickshell.org/docs/v0.3.0/guide/install-setup/)). Omarchy 4's shell rewrite onto Quickshell means the exact Hyprland+Quickshell pairing Punar wants is being exercised at scale by another distro ([Omarchy 4 coverage](https://codetocloud.io/blog/omarchy-4-quattro-whats-new/)).
- Chromium is packaged by Arch within days of upstream releases (last rebuild 3 days before research date), which matters for spec section 30's browser cadence requirement.
- AUR covers the long tail but is unsigned, unreviewed user content — for a product, anything from AUR must be rebuilt into the vendor repo, never consumed live on user machines (Omarchy pulls AUR at update time; Punar should not copy that part).

**Verdict: excellent — the best of the three candidates for Punar's specific component list.**

### 2.5 Security

- Arch has a volunteer Security Team and a public tracker (AVGs mapped to CVEs) at [security.archlinux.org](https://security.archlinux.org/); ~90+ packages listed as currently vulnerable at any time (11 high-severity at research date). Fix latency is usually good *because* packaging tracks upstream fast.
- However: the ASA advisory *publication* pipeline has been intermittent — the arch-security mailing list went quiet for extended periods (nothing sent Dec 2021→Apr 2022; sporadic ASAs since, e.g. ASA-202403-1 for the xz backdoor) ([Arch Security Team wiki](https://wiki.archlinux.org/title/Arch_Security_Team), [arch-general thread, 2022-04](https://lists.archlinux.org/archives/list/arch-general@lists.archlinux.org/2022/4/)). A vendor cannot rely on Arch to *notify*; we must run our own CVE watch against the tracker's data and gate our channel promotion on it.
- No SELinux by default; AppArmor and SELinux are installable but not distro-integrated the way Fedora's SELinux policy is. Punar would rely on systemd sandboxing + landlock/seccomp + its own policy layer.
- Packages and databases are signed (pacman key infrastructure); repo metadata signing exists.

**Verdict: adequate, with the advisory/notification gap explicitly owned by us.** Weaker than Fedora (SELinux + formal advisories), comparable-to-better than NixOS on fix latency.

### 2.6 Secure Boot

- Upstream Arch ships **nothing signed by Microsoft** — no shim in official repos, kernels unsigned. Secure Boot on Arch means either (a) enrolling machine-owner keys with **sbctl** and signing UKIs, or (b) shipping a Fedora-style signed shim + MOK enrollment (Archboot does this) ([ArchWiki Secure Boot talk](https://wiki.archlinux.org/title/Talk:Unified_Extensible_Firmware_Interface/Secure_Boot), [Archboot](https://archboot.com/)).
- The tooling is now genuinely mature: mkinitcpio/dracut grew first-class UKI modes (calling `ukify`), and sbctl automates key creation, enrollment, and re-signing via pacman hooks ([s3lph writeup](https://s3lph.me/unified-kernel-images-and-secure-boot-using-arch-linux.html), [MichaelEischer gist](https://gist.github.com/MichaelEischer/806a50a6bb44e08550de4a0c0329498f)).
- Precedent gap: **Omarchy does not ship Secure Boot enabled out of the box** — it is a documented manual/community-tooling flow (sign the Limine EFI binary; Limine verifies UKIs via embedded BLAKE2B hashes) ([omarchy-secure-boot-manager](https://github.com/peregrinus879/omarchy-secure-boot-manager), [Omarchy discussion #2296](https://github.com/basecamp/omarchy/discussions/2296)). CachyOS likewise documents a manual sbctl flow ([CachyOS wiki](https://wiki.cachyos.org/configuration/secure_boot_setup/)).
- For Punar the realistic production path is vendor-signed UKIs + our own KEK/db enrollment during install (fine for self-setup and managed fleets), or licensing a Microsoft-signed shim (a real cost/effort item no Arch derivative has fully productized). Firmware setup-mode enrollment fails on some quirky OEM firmware; enterprise fleets with custom PK/KEK provisioning are actually the *easy* case.
- Spec 1.22 note: any Secure Boot/TPM demo in QEMU/OVMF for Milestone 0 is simulated and must be labeled as such.

**Verdict: workable but vendor-owned; the least-finished area of the Arch story.** Fedora Atomic wins this criterion outright (signed shim end-to-end).

### 2.7 Transactional updates

- Stock pacman is **not transactional**: an interrupted `-Syu` can leave a partially-updated system. Mitigations in practice:
  - **snapshot-bracketed updates**: snap-pac takes pre/post btrfs snapshots around every pacman transaction — rollback-able, but not atomic (2.8).
  - **A/B images**: SteamOS 3 ships complete images to an inactive partition with RAUC + casync; failed boot falls back to the previous slot ([Collabora on SteamOS 3.6 atomic updates](https://www.collabora.com/news-and-blog/news-and-events/steamos-3-6-how-the-steam-deck-atomic-updates-are-improving.html), [iliana.fyi SteamOS fork writeup](https://iliana.fyi/blog/build-your-own-steamos-updates/)). Arkane Linux does atomic deployments of prebuilt btrfs subvolume images via its `arkdep` tool ([arkanelinux.org](https://www.arkanelinux.org/), [docs](https://docs.arkanelinux.org/)).
- So: Arch does not give transactional updates; an Arch *derivative* can build them, and two working open-source precedents exist for the image-deployment route. The package-channel route (Omarchy-style) accepts non-atomicity and compensates with snapshots.

**Verdict: buildable, not inherited.** NixOS (atomic activation) and Fedora Atomic (ostree) inherit this for free — this is the biggest structural gap to weigh in the ADR.

### 2.8 Rollback

- **btrfs + snapper + snap-pac + bootable snapshots** is the proven package-channel pattern; Omarchy ships it by default (Limine boot menu exposes snapshots of `/` and `/home`; automatic snapshot before every Omarchy update, one-keypress boot into the prior state) ([Omarchy manual — updates](https://omarchy.org/manual/updates/), [DeepWiki: boot management and snapshots](https://deepwiki.com/basecamp/omarchy/2.2-boot-management-and-snapshots)).
- Known sharp edges (must be engineered around, not discovered in the field): booting a read-only snapshot from GRUB can land in an overlayfs that silently isn't a real rollback; a rollback isn't durable unless the default subvolume is switched; some subvolume layouts require chroot surgery for openSUSE-style single-command rollback ([Arch forum thread](https://bbs.archlinux.org/viewtopic.php?pid=2254950), [dwarmstrong guide](https://www.dwarmstrong.org/btrfs-snapshots-rollbacks/)). openSUSE solved this with `snapper rollback` + proper layout; a derivative must copy that design deliberately.
- A/B image schemes give coarser but bulletproof rollback (previous slot always intact) at 2× root-partition disk cost — SteamOS and Arkane precedents above.
- Kernel/initramfs live on the ESP outside btrfs; snapshot rollback must be paired with UKI retention per snapshot (Omarchy's Limine integration handles UKI discovery for snapshots).

**Verdict: good, with known engineering traps; both viable patterns have shipping Arch-based precedents.**

### 2.9 Hardware compatibility

- Mainline kernel days-fresh, plus `linux-lts` as a fallback pairing; current linux-firmware; NVIDIA proprietary drivers packaged and (in derivative land) heavily exercised. New laptop enablement generally reaches Arch first among the candidates. Rolling firmware/kernel occasionally *causes* regressions — the linux-firmware 2025-06 package split required manual intervention ([Arch news](https://archlinux.org/news/linux-firmware-2025061312fe085f-5-upgrade-requires-manual-intervention/)); a delayed vendor channel absorbs this class of event.
- **Official Arch is x86_64-only.** Arch Linux ARM is a separate, unofficial project. Practical consequence for this team: on the maintainer's Apple Silicon host, "native" Arch containers are emulated x86_64 (slow) — image builds belong in x86_64 CI, with Lima/UTM VMs for boot testing. This is a development-workflow cost, not a product cost (Punar targets x86_64 hardware per spec section 5).

**Verdict: strong for target hardware; note the x86_64-only official scope and the dev-machine friction.**

### 2.10 Ease of enterprise governance / controlled package channels

What Arch provides that a vendor can build on:

- **Arch Linux Archive (ALA)**: official daily snapshots of the whole mirror at `archive.archlinux.org/repos/YYYY/MM/DD/`; any system can be pinned to a date by pointing the mirrorlist at a snapshot URL ([ArchWiki: Arch Linux Archive](https://wiki.archlinux.org/title/Arch_Linux_Archive), [worked example](https://theorangeone.net/posts/arch-revert-to-date/)). Caveats: ALA is shared community infrastructure, not a product CDN — a vendor must run **its own snapshot mirror** (rsync a chosen date, test, publish), not point customers at ALA; and mixing ALA with live mirrors is unsafe (partial-epoch systems) ([ArchWiki, same page](https://wiki.archlinux.org/title/Arch_Linux_Archive)).
- **The Omarchy channel model is the working template**: an *Omarchy Arch Mirror* (curated snapshot of Arch running ~one month behind latest on the stable channel, so incompatibilities are caught before users see them), an *Omarchy Package Repository* (vendor's own pacman packages, including the OS's own code shipped *as packages* with migrations run on update), and four channels — stable / RC / edge / dev ([Omarchy manual — updates](https://omarchy.org/manual/updates/), [omacom-io/omarchy-pkgs](https://github.com/omacom-io/omarchy-pkgs)). This maps directly onto Punar's enterprise update assignments (spec 8.1): per-ring mirror snapshots promoted after test gates.
- What Arch does **not** provide: any of the compliance surface. No vendor SLAs, no certified builds, no FIPS mode, no CIS benchmark or STIG for Arch, no ISO 27001/PCI-attestable vendor behind it; formal advisories intermittent (2.5) ([Arch Security Team wiki](https://wiki.archlinux.org/title/Arch_Security_Team)). Enterprise credibility must come from **Smplify's** signing, testing, advisory, and support story on top — the substrate contributes nothing here, and procurement/security teams at conservative organizations will read "Arch-based" as a yellow flag that our own attestations have to overcome. This is a real go-to-market cost, not just an engineering one.
- Config-management ecosystems (Ansible etc.) support Arch fine; fleet products (Landscape, Satellite) do not — irrelevant since Punar ships its own control plane, but it means no fallback tooling exists.

**Verdict: mechanisms excellent (ALA + pacman repos are simple, boring technology); institutional/compliance surface absent — wholly vendor-supplied.**

### 2.11 Maintenance burden (small team)

- **Image building is cheap and containerizable.** Omarchy's entire ISO is built by a script running mkarchiso inside an `archlinux:latest` container with a bundled offline package mirror; installs complete in under a minute from a <6 GB ISO ([omacom-io/omarchy-iso](https://github.com/omacom-io/omarchy-iso), [DeepWiki build process](https://deepwiki.com/omacom-io/omarchy-iso/2.3-docker-build-process), [Omarchy 4 coverage](https://codetocloud.io/blog/omarchy-4-quattro-whats-new/)). archiso itself ships `releng`/`baseline` profiles ([ArchWiki: archiso](https://wiki.archlinux.org/title/Archiso)); `mkosi` is the cleaner alternative for disk/UKI images (2.3); official `arch-boxes` qcow2s serve as CI base images ([archlinux/arch-boxes](https://github.com/archlinux/arch-boxes)).
- **The recurring cost is channel curation**: someone must watch Arch news and test each snapshot before promotion. Measured rate of "manual intervention required" news events: roughly 6–7 in the last ~14 months (linux-firmware 2025-06, zabbix 2025-08, dovecot 2025-10, waydroid 2025-11, .NET and NVIDIA-Pascal 2025-12, iptables→nft 2026-04) ([Arch news](https://archlinux.org/news/)). Each of these is a migration Punar must automate in its update tool (Omarchy ships migrations in its packages for exactly this reason). That is a tractable, bounded stream for a small team — EndeavourOS maintains a thin overlay repo over stock Arch with a handful of people ([endeavouros-team/repo](https://github.com/endeavouros-team/repo)) — but it is *permanent* work with no upstream to lean on when it's late or wrong.
- Risk pattern to avoid: Manjaro-style *partial* divergence (own delayed repos while consuming live AUR) produces AUR/library mismatches. Mitigation: never consume AUR live; rebuild needed AUR packages into the vendor repo against the pinned snapshot.
- Team-scale precedents, honestly stated: Omarchy is a well-funded personal project with heavy community energy, not an enterprise vendor; EndeavourOS deliberately avoids owning package QA; CachyOS shows a mid-size volunteer team *can* run full rebuild infrastructure (v3/v4/znver4 tiers, Docker-containerized builds, PGO/LTO kernels) ([CachyOS wiki: optimized repos](https://wiki.cachyos.org/features/optimized_repos/)) — more than Punar needs, and more headcount than Punar has.

**Verdict: moderate and predictable; the burden is curation-and-migration ops, not packaging-from-scratch. Higher than Fedora Atomic (where Red Hat does curation), lower than NixOS module upkeep for a team without Nix expertise.**

### 2.12 Upstream velocity

- Arch tracks upstream within days: chromium rebuilt 2026-08-21, hyprland 0.56.2 on 2026-08-05, quickshell 0.3.1 on 2026-08-21 (package pages, 2.4). For Punar this is the direct feed for spec section 30's Chromium cadence and for fast Hyprland/Quickshell iteration.
- A delayed vendor channel converts raw velocity into controlled velocity: the vendor chooses the lag (Omarchy's stable: ~1 month) and can fast-track security rebuilds ahead of the snapshot date — that selective-fast-track machinery is on us to build.

**Verdict: best-in-class raw velocity; the vendor channel is what makes it consumable.**

---

## 3. Precedent projects

### 3.1 Omarchy (omacom-io / DHH, sponsored by 37signals) — the closest prior art

- **What it ships**: Arch + Hyprland desktop, opinionated dev tooling; Limine bootloader with UKIs; btrfs + snapper snapshots of `/` and `/home` surfaced in the boot menu; LUKS full-disk encryption preconfigured by the ISO ([AkitaOnRails install writeup](https://akitaonrails.com/en/2025/09/12/omarchy-2-0-install-with-the-omarchy-iso/), [DeepWiki boot management](https://deepwiki.com/basecamp/omarchy/2.2-boot-management-and-snapshots)). Omarchy 4 "Quattro" (2026-08-14) rewrote the shell on **Quickshell** (dropping Waybar/Walker/Mako for one themeable process with a plugin system) ([Omarchy 4 coverage](https://codetocloud.io/blog/omarchy-4-quattro-whats-new/), [review](https://dashen-tech.com/en/dev-tools/omarchy-4-quattro-review/)).
- **How it is built**: `build-iso.sh` runs mkarchiso inside an `archlinux:latest` container; the ISO embeds a self-contained offline package mirror, installs Arch + Omarchy packages, runs chroot setup, reboots into the installed system; ISO <6 GB, install <1 minute ([omacom-io/omarchy-iso](https://github.com/omacom-io/omarchy-iso), [DeepWiki](https://deepwiki.com/omacom-io/omarchy-iso)).
- **How it updates**: Omarchy code ships as pacman packages with migrations; four channels (stable/RC/edge/dev); stable tracks a vendor Arch mirror ~1 month behind; pre-update snapshot enables boot-menu rollback ([Omarchy manual — updates](https://omarchy.org/manual/updates/)).
- **Published footprint**: ~1.3 GB RAM on boot for a fresh install (DHH, 2025-08; single self-reported datapoint, not an audited benchmark) ([X post](https://x.com/dhh/status/1952346236557603261)).
- **Gaps relative to Punar's needs**: no out-of-box Secure Boot; live AUR consumption on user machines; no enterprise management, attestation, or advisory process; single-maintainer governance.

### 3.2 SteamOS 3 (Valve) — the A/B image precedent

Arch-derived, immutable read-only root, A/B partitions, complete image updates via RAUC + casync, `/etc` handled with overlayfs, automatic fallback to the previous slot on failed boot ([Collabora](https://www.collabora.com/news-and-blog/news-and-events/steamos-3-6-how-the-steam-deck-atomic-updates-are-improving.html), [iliana.fyi](https://iliana.fyi/blog/build-your-own-steamos-updates/)). Proves Arch works as an *image-based* product at tens-of-millions scale; also proves it takes Valve-level engineering to run that pipeline.

### 3.3 CachyOS — full-rebuild derivative

Rebuilds effectively the whole Arch repo in tiers (x86-64-v3/v4/znver4, LTO/PGO, custom kernels) with containerized build infrastructure ([wiki](https://wiki.cachyos.org/features/optimized_repos/)). Demonstrates the *upper bound* of derivative maintenance a volunteer team can sustain; Punar should stay far below this (curate, don't rebuild the world). Secure Boot: documented manual sbctl flow only ([wiki](https://wiki.cachyos.org/configuration/secure_boot_setup/)).

### 3.4 EndeavourOS — thin-overlay derivative

Small overlay repo (installer, tools, theming); everything else is stock live Arch, keeping AUR compatibility perfect and team burden minimal ([dev site](https://endeavouros-team.github.io/EndeavourOS-Development/), [repo](https://github.com/endeavouros-team/repo)). Demonstrates the *lower bound*: minimal burden but zero update control — no delayed channel, no curation, users ride raw Arch. Punar cannot be this thin (spec 8.1 explicitly forbids "raw rolling Arch with enterprise controls bolted on"... and equally forbids no controls at all).

### 3.5 Arkane Linux / arkdep — atomic btrfs-image deployments

Immutable, atomic Arch-based distro; `arkdep` builds and atomically deploys prebuilt btrfs subvolume images, keeping prior deployments for rollback; failed updates leave no permanent changes ([arkanelinux.org](https://www.arkanelinux.org/), [docs.arkanelinux.org](https://docs.arkanelinux.org/), [LinuxLinks](https://www.linuxlinks.com/arkane-linux-immutable-atomic-arch-based-distribution/)). Small project (assess bus-factor before depending on it), but a directly reusable design sketch for an A/B-lite scheme on plain btrfs without RAUC.

---

## 4. Summary judgment for ADR-001

Arch is the strongest candidate on resource efficiency, package availability (every Punar desktop component is in official `extra`, days-fresh), developer familiarity, and upstream velocity — and Omarchy has de-risked the exact product shape (curated repo + delayed vendor mirror + snapshot rollback + containerized mkarchiso ISO + Hyprland/Quickshell). The honest costs: transactional updates and full-system reproducibility are *built, not inherited* (NixOS/Fedora Atomic get them for free); Secure Boot is mature at the tooling level but unproductized in every Arch derivative surveyed; and the enterprise trust surface (advisories, compliance posture, support) is 100% Smplify's to construct and defend, with "Arch-based" itself a perception hurdle in conservative procurement. The maintenance burden is a bounded, permanent curation-and-migration stream (~6–7 upstream manual-intervention events observed in the last 14 months) that a small team can carry if — and only if — channel promotion, migrations, and AUR-rebuild policy are automated from day one.

---

## 5. Citations

Live-checked 2026-08-24 unless noted:

- Spec: `/Users/spurtipreetham/Documents/smplify-punarOS/docs/product/SPEC_v0.2.md` sections 5, 6, 8, 30.
- Arch install footprint: https://wiki.archlinux.org/title/Installation_guide
- Arch Docker images and sizes: https://gitlab.archlinux.org/archlinux/archlinux-docker ; https://hub.docker.com/_/archlinux
- arch-boxes images and sizes: https://github.com/archlinux/arch-boxes ; https://geo.mirror.pkgbuild.com/images/latest/ (basic 516 MB / cloudimg 556 MB, build 20260815)
- Reproducible packages dashboard: https://reproducible.archlinux.org/api/v0/dashboard (13,534 good / 2,037 bad / 3 unknown ≈ 86.9%)
- Reproducible official images (third-party rebuilder): https://archimgrepro.antiz.fr/ (Docker + WSL GOOD, 2026-08-19)
- mkosi: https://man.archlinux.org/man/mkosi.1.en ; https://vdwaa.nl/mkosi-reproducible-arch-images.html ; https://wiki.archlinux.org/title/Mkosi
- archiso: https://wiki.archlinux.org/title/Archiso
- Arch Linux Archive: https://wiki.archlinux.org/title/Arch_Linux_Archive ; https://theorangeone.net/posts/arch-revert-to-date/
- Package pages: https://archlinux.org/packages/extra/x86_64/hyprland/ ; https://archlinux.org/packages/extra/x86_64/quickshell/ ; https://archlinux.org/packages/extra/x86_64/greetd/ ; https://archlinux.org/packages/extra/x86_64/chromium/
- Quickshell packaging status: https://quickshell.org/docs/v0.3.0/guide/install-setup/
- Security team and tracker: https://wiki.archlinux.org/title/Arch_Security_Team ; https://security.archlinux.org/ ; https://lists.archlinux.org/archives/list/arch-general@lists.archlinux.org/2022/4/
- Secure Boot / UKI / sbctl: https://wiki.archlinux.org/title/Talk:Unified_Extensible_Firmware_Interface/Secure_Boot ; https://s3lph.me/unified-kernel-images-and-secure-boot-using-arch-linux.html ; https://gist.github.com/MichaelEischer/806a50a6bb44e08550de4a0c0329498f ; https://archboot.com/
- Omarchy Secure Boot (community tooling, not out-of-box): https://github.com/peregrinus879/omarchy-secure-boot-manager ; https://github.com/basecamp/omarchy/discussions/2296 ; CachyOS: https://wiki.cachyos.org/configuration/secure_boot_setup/
- Snapper/btrfs rollback and pitfalls: https://bbs.archlinux.org/viewtopic.php?pid=2254950 ; https://www.dwarmstrong.org/btrfs-snapshots-rollbacks/
- SteamOS A/B updates: https://www.collabora.com/news-and-blog/news-and-events/steamos-3-6-how-the-steam-deck-atomic-updates-are-improving.html ; https://iliana.fyi/blog/build-your-own-steamos-updates/
- Arkane Linux / arkdep: https://www.arkanelinux.org/ ; https://docs.arkanelinux.org/ ; https://www.linuxlinks.com/arkane-linux-immutable-atomic-arch-based-distribution/
- Omarchy: https://omarchy.org/manual/updates/ ; https://github.com/omacom-io/omarchy-iso ; https://github.com/omacom-io/omarchy-pkgs ; https://deepwiki.com/omacom-io/omarchy-iso/2.3-docker-build-process ; https://deepwiki.com/basecamp/omarchy/2.2-boot-management-and-snapshots ; https://codetocloud.io/blog/omarchy-4-quattro-whats-new/ (4.0.0 released 2026-08-14) ; https://akitaonrails.com/en/2025/09/12/omarchy-2-0-install-with-the-omarchy-iso/ ; https://x.com/dhh/status/1952346236557603261 (1.3 GB RAM on boot, 2025-08)
- CachyOS build/repos: https://wiki.cachyos.org/features/optimized_repos/
- EndeavourOS: https://endeavouros-team.github.io/EndeavourOS-Development/ ; https://github.com/endeavouros-team/repo
- Manual-intervention cadence: https://archlinux.org/news/ ; https://archlinux.org/news/linux-firmware-2025061312fe085f-5-upgrade-requires-manual-intervention/

Known gaps in this research (flag for follow-up): no local measurement of minimal Arch+Hyprland+Quickshell idle RAM (planned as a Milestone 0 VM benchmark); Omarchy's 1.3 GB figure is self-reported by its author; ALA usage/bandwidth policy for derivatives was not found in primary sources (the own-mirror recommendation is inferred from mirror-etiquette norms and Omarchy's practice); Chromium/Hyprland upstream-to-Arch packaging lag asserted from observed package dates, not a longitudinal study.
