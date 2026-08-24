# Substrate research: Fedora Atomic / image-based via bootc

**Input for:** ADR-001 Distribution Substrate (SPEC_v0.2 section 8, 8.3, 8.4)
**Researched:** 2026-08-24, via web search/fetch. Every load-bearing claim carries a citation in section 8. Claims that could not be independently verified are labeled as such (spec 1.22).

---

## 1. Overview

The "Fedora Atomic" option is no longer just "use Silverblue." As of August 2026 the center of gravity is **bootc**: the OS is defined as an OCI container image (a plain `Containerfile` on top of `quay.io/fedora/fedora-bootc`), built with podman/docker, pushed to any OCI registry, and booted on hardware with transactional A/B updates and bootloader-level rollback, backed by ostree/composefs storage. Fedora is mid-way through formally converging CoreOS, IoT, and the Atomic Desktops onto this model (Fedora "Image Mode Phase 2 (2026)" initiative, production target Fedora 45, scheduled 2026-10-20). Red Hat ships the same stack commercially as "image mode for RHEL," GA and supported on RHEL 9.6/10 — meaningful de-risking for an enterprise-oriented product like Punar.

For Punar specifically, the proposition is: **Punar = a Containerfile**. The entire OS — kernel, compositor stack, punard/punarctl, policies, branding — is one signed image in a registry. Updates are `bootc upgrade`; channels are registry tags; staged rollout is progressive re-tagging of digests; health-gated automatic rollback is greenboot; fleet state is `bootc status --json`. Universal Blue (Bluefin/Bazzite/Aurora) has operated exactly this model at >50k-user scale on nothing but GitHub Actions + GHCR, and secureblue shows deep security hardening is possible purely as an image layer.

The main costs: Fedora's 6-month cadence and conservative packaging fight Punar's need for a tip-of-tree Wayland stack (Hyprland was *orphaned out of official Fedora repos*; Quickshell's official package is a stale 0.2.1 git snapshot), builds are not hermetically reproducible (unlike Nix), local package layering on clients remains the ecosystem's acknowledged weak spot, and bootc itself is young (CNCF Sandbox, weekly releases, desktop-specific gaps still open).

---

## 2. State of the toolchain (as of 2026-08)

### 2.1 bootc

- Current release **v1.16.9 (2026-08-21)**; the project moved to a **weekly release cadence** in June 2026 (v1.16.1, 2026-06-17). Repo is `bootc-dev/bootc` (moved out of `containers/`).
- 2026 feature themes visible in the release stream: **composefs "unified storage"** backend (manifest GC roots, composefs repository handling), **UKI + systemd-boot support** (BLSConfig UKI in v1.16.3, bootloader chroot integration for composefs installs in v1.16.6), transient `/etc` and volatile `/var` (v1.16.0), read-only `/sysroot` on live ISOs.
- Governance: **CNCF Sandbox project, accepted 2025-01-21**. The v1.16.9 release notes mention "incubation docs," which suggests an incubation application is in progress; *incubating status could not be verified as of 2026-08-24 — the CNCF project page still lists Sandbox*.
- Update model: `bootc upgrade` stages the new image as an A/B deployment for next boot; `bootc switch` retargets the tracked image (channel moves); `bootc rollback` swaps bootloader order back; an upstream `bootc-fetch-apply-updates.timer` exists for opinionated auto-updates. Signature verification uses the containers-policy.json / sigstore machinery; Universal Blue documents `bootc switch --enforce-container-sigpolicy` and signature checks before staging.

### 2.2 ostree

- libostree remains the storage/deployment substrate and is mature (Silverblue since 2018). Release train is active: **ostree 2026.4** packaged downstream; 2026.1–2026.4 all shipped during 2026. Development emphasis has shifted to the bootc/composefs layer above it.
- rpm-ostree is in **maintenance mode for new features**: "widely in use … will continue to be supported with an emphasis on fixing important bugs," with client-side feature work explicitly deprioritized in favor of bootc + dnf5.

### 2.3 Fedora integration

- Base images: `quay.io/fedora/fedora-bootc` (tags per release: 42/43/44, latest), built from `gitlab.com/fedora/bootc/base-images`. The standard image is ~**1.88 GB / 523 packages**; documented smaller tiers exist (minimal ≈ kernel + systemd + bootc + dnf + SELinux; minimal-plus adds podman/openssh/sudo etc.), and community from-scratch builds have hit ~255 packages.
- **Fedora Image Mode Phase 2 (2026) initiative**: bootc OCI artifacts become first-class Fedora deliverables; dev pipeline + beta/nightlies in F44 (released 2026-04-28), full production pipeline with shared base images in **F45 (target 2026-10-20)**. Atomic Desktops, CoreOS and IoT converge on shared base images and become "use-case-specific layering."
- **Sealed images**: test images of sealed Atomic Desktop bootable containers published **2026-04-28** — systemd-boot + signed UKI + composefs with fs-verity, enabling a fully verified boot chain and reasonable TPM-based passwordless disk unlock. Test-only, signed with non-official keys; explicitly not production-ready.
- Release cadence context: **F43 released 2025-10-28; F44 released 2026-04-28; F45 targeted 2026-10-20** (beta 2026-09-15). Each Fedora release is supported ~13 months.
- Ecosystem breadth: image mode for **RHEL is GA** (RHEL 9.6/10, `registry.redhat.io/rhel10/rhel-bootc`), RHEL 10 added soft-reboot image updates (2025-11); CIQ ships **Rocky Linux bootc images** (2026). A CentOS Stream bootc base also exists (`fedora/centos-bootc` docs) for a slower-moving track.

---

## 3. Criteria-by-criteria assessment (spec section 8)

### 3.1 Resource efficiency

- The substrate itself is close to free at runtime: ostree/composefs are inert after boot (hardlinked/EROFS-backed read-only /usr), and update daemons are socket/dbus-activated rather than resident. Idle RAM is determined by the desktop stack Punar chooses, not by bootc. *(Engineering assessment, not a measurement — must be validated against the section 6 budgets on the M0 image.)*
- Disk: the standard fedora-bootc image is ~1.88 GB with 523 packages; Punar would build from the minimal tier and add only its stack. A/B deployments roughly double the OS footprint on disk (two deployments retained), plus registry-side storage. OCI-based updates re-download changed layers; careful layer design and "rechunking" (as Universal Blue does) keeps deltas reasonable, and bootc's composefs/zstd:chunked work targets this.
- Fedora's generic kernel carries broad module coverage — no penalty at runtime, some on disk.
- Verdict: **compatible with the <1.0 GB idle-RAM target only because Punar controls the payload**; the substrate adds disk overhead, not RAM/CPU overhead.

### 3.2 Developer familiarity

- The build interface is a **Containerfile** — the single most familiar artifact format in the industry. Anyone who can write a Dockerfile can read, review, and diff the entire Punar OS definition. This is the strongest familiarity story of the three ADR-001 candidates (vs Nix language; vs bespoke Arch image tooling).
- Client-side concepts (deployments, `bootc status`, three-way /etc merge, immutable /usr) are a real but modest learning curve; Universal Blue's user base demonstrates ordinary users absorb it.
- Caveat (LWN, 2025-11-07): read-only /usr pushes ad-hoc software installation toward Flatpak/Toolbx/Distrobox or image rebuilds — a workflow shift for developers used to `pacman -S`. Punar's project-container model (spec 17) aligns with rather than fights this.

### 3.3 Reproducibility

- **Deployment reproducibility is excellent**: every device boots an exact content-addressed image digest; fleet convergence is verifiable by digest; `bootc switch` to a pinned digest is deterministic.
- **Build reproducibility is weaker than Nix**: `dnf install` in a Containerfile resolves whatever the repos hold at build time. Mitigations exist — pin RPM NEVRAs, snapshot/mirror repos, build from a lockfile, keep the SBOM from each build — but they are Punar's responsibility, not the toolchain's default. Not bit-for-bit hermetic.
- Net: better than mutable Arch (image is the unit of truth), worse than Nix (no hermetic evaluation).

### 3.4 Package availability

- Fedora repos are large and well-maintained, plus COPR (community), RPM Fusion (codecs/NVIDIA), and Flatpak. But Fedora's update policy is conservative inside a release, and the packages Punar's UX depends on are precisely the fast-moving ones:
  - **Hyprland was orphaned out of official Fedora repos** (orphaning email 2024-11-10, maintainer Pavel Solovev: config refactors made updates incompatible with Fedora's update policy; he preferred a rolling model). Fedora 43/44 do not ship Hyprland; the last official build was 0.45.2 (F42). The community standard is the `solopasha/hyprland` COPR, which has itself lagged (community reports of F44 stuck on 0.51 for months while upstream moved on; upstream Hyprland is at **0.56.2, released 2026-08-05**, with 0.55.0 on 2026-05-09). Alternative COPRs (ashbuk) have appeared. *(COPR version-lag specifics are community-reported; treat exact lag figures as approximate.)*
  - **Quickshell** *is* in official Fedora (correction 2026-08-24: earlier draft said COPR-only), but as a stale git snapshot: `quickshell 0.2.1^git20260209.dacfa9d` in F44/F45/rawhide (maintainers ngompa, errornointernet), versus upstream 0.3.1 released 2026-08-21 — i.e. roughly two point-releases and six months behind. An `errornointernet/quickshell` COPR also exists. Official-but-stale changes the packaging-obligation argument in degree, not kind: Punar still cannot ship current Quickshell from Fedora's repos.
  - **Chromium**: Fedora maintains a chromium RPM and does track upstream security releases (149.0.7827.53 in June 2026; 149.0.7827.196 June 2026; 150.0.7871.124 for F43/F44 in July 2026), but latency of days-to-weeks per milestone is normal, and it is a volunteer-maintained package. Punar's spec (30.1, 58) demands upstream-current Chromium shipped independently of OS releases — on this substrate that means **Punar builds/ships its own Chromium channel** (own RPM repo layered into the image, a separately-updated sub-image, or Flatpak), regardless. secureblue's Trivalent (hardened Chromium derived from Fedora's package, shipped from a COPR) proves an independent Chromium channel on this substrate is tractable for a small team.
- Practical conclusion: **Punar must expect to own RPM packaging for its compositor/shell stack** (Hyprland/Quickshell or equivalents) on Fedora — COPRs are single-maintainer infrastructure with no SLA. This is real, recurring work that Arch would mostly give for free from its repos.

### 3.5 Security

- **SELinux enforcing is the default** across Fedora Atomic and survives the bootc model. Files in derived image layers are labeled using the image's file contexts; since bootc 1.1.0, `semanage fcontext` works inside a Containerfile, and custom policy modules can be built/installed (`semodule`) at image build time — so Punar's daemons can ship confined, with policy versioned in the same repo as the OS.
- Cost of keeping enforcing: (a) authoring and maintaining policy modules for punard/punar-agentd/punar-secrets etc. (audit2allow iteration, per-release policy rebases); (b) build hosts running bootc-image-builder need osbuild-selinux; (c) occasional relabel friction in derived images. Upstream desktop sessions run largely unconfined_t, so enforcing costs little for user applications while still confining system services — a reasonable default posture for Punar; secureblue demonstrates much stricter confinement is achievable as a layer if wanted later.
- Update integrity: images signed with sigstore/cosign; bootc verifies signatures per containers-policy.json before staging (Universal Blue does keyless cosign on every image).
- Trajectory: sealed images (signed UKI + fs-verity composefs) point at a fully measured/verified boot chain with TPM-bound disk unlock — aligned with Punar's attestation ambitions, but test-only today.

### 3.6 Secure Boot

- Works **out of the box** when Punar ships Fedora's signed shim + signed kernel unmodified — the cheapest credible Secure Boot story of the candidate substrates.
- The moment Punar ships out-of-tree kernel modules or a custom kernel, it must sign them and get its **MOK certificate enrolled on each device** — Universal Blue's precedent: kernels/akmods signed with the ublue key, users enroll it via mokutil (password "universalblue") at first boot. Acceptable for community mode; for managed fleets, MOK enrollment can be part of provisioning.
- The sealed-image/UKI path would eventually let Punar sign its own UKI (enterprise-enrolled keys), but that is not production today (non-official keys, test images).
- Anything demonstrated in VMs without real SB keys must be labeled simulated per spec 1.22.

### 3.7 Transactional updates

- This is the substrate's core competency: updates are staged as a complete A/B deployment while the system runs, applied atomically at reboot, interruption-safe (a pulled power cord mid-update leaves the running deployment untouched). `bootc upgrade --check/--download-only/--apply` gives the exact control points spec 57 needs. RHEL 10 added soft-reboot apply (seconds-scale) showing headroom in the model.

### 3.8 Rollback

- First-class and layered:
  - bootloader menu retains previous deployment; if a staged update fails to boot, the previous entry still boots (Universal Blue documents the fallback behavior);
  - `bootc rollback` programmatically swaps boot order;
  - `ostree admin pin` preserves known-good deployments beyond the default two;
  - **greenboot** (and its Rust rewrite greenboot-rs, approved for Fedora 43) runs required health checks each boot and, on repeated failure, automatically reboots into / rolls back to the previous deployment — a direct implementation of spec 57's "Health" gate, already shipped with every Fedora IoT install.
- Caveat: rollback covers the OS image; /etc is three-way merged and /var is untouched, so state migrations still need discipline (same as every substrate).

### 3.9 Hardware compatibility

- Fedora ships near-latest stable kernels with broad hardware enablement, firmware, and fwupd; this is as good as Arch in practice and better than any LTS base for the 2–5-year-old developer laptops in spec 5.
- x86_64 and aarch64 base images are published (base-images CI also builds other arches). NVIDIA and other out-of-tree modules follow the Universal Blue akmods pattern (prebuilt, signed, baked into the image) rather than client-side DKMS — a better fleet story, but module builds become Punar CI's problem (LWN flags kernel modules as a live pain point).
- UEFI is required for the sealed/UKI path; legacy BIOS remains supported via grub for ordinary (non-sealed) images.

### 3.10 Ease of enterprise governance

- Strongest of the three candidates:
  - the fleet converges on **one signed artifact per channel**, identified by digest; drift in /usr is structurally impossible on clients;
  - channels/rings are registry tags; assignment is `bootc switch` (spec 57 stages map 1:1 — see section 5);
  - `bootc status --json` exposes booted/staged/rollback image + digest for the compliance endpoint;
  - commercial validation: image mode for RHEL is GA and included in RHEL subscriptions — auditors and enterprise buyers can be pointed at a supported analog of Punar's architecture.
- Gap: nothing off-the-shelf does per-device update *assignment* (that's Smplify's control plane to build), and client-side layered packages (if allowed) reintroduce drift — Punar policy should forbid or tightly scope layering on managed devices.

### 3.11 Maintenance burden

- Punar inherits kernel, toolchain, security updates, and the entire base OS from Fedora, and the update/rollback machinery from bootc upstream. Punar maintains: a Containerfile tree, its own RPMs for the desktop stack (see 3.4), CI, and a registry.
- Precedent: Universal Blue maintains Bazzite + Bluefin + Aurora + uCore — dozens of image variants — with a small volunteer team entirely on GitHub Actions + GHCR, at 50k+ measured users. This is strong evidence the steady-state burden is manageable for a small company.
- Recurring costs: ~6-month Fedora rebase (F44→F45 etc., with 13-month support windows limiting how long a rebase can be deferred); tracking the still-moving bootc ecosystem (rpm-ostree→bootc/dnf5 transition is in flight — churn risk is real: the local-layering design is explicitly unsettled upstream).

### 3.12 Upstream velocity

- Very high, and pointed in Punar's direction: weekly bootc releases; a formal Fedora initiative making bootc images first-class by F45; Red Hat, Fedora, CIQ/Rocky and CNCF all invested; active conference track (DevConf.CZ/Flock 2026).
- Risk framing: velocity == churn. bootc is CNCF **Sandbox** (not incubating as of 2026-08), several desktop workflows (kernel modules, disk re-encryption tooling, offline layering) are acknowledged gaps, and Fedora's own pipeline for this lands fully in F45. Punar M0 would ride a wave that is cresting, not settled.

---

## 4. Precedent projects

### 4.1 Fedora Atomic Desktops (first-party)

Silverblue (GNOME), Kinoite (KDE), **Sway Atomic** (née Sericea — closest to Punar's keyboard-first shape: a wlroots/Sway ostree desktop with official F44 images), Budgie Atomic, and a COSMIC Atomic in rawhide. All are ostree/rpm-ostree today, transitioning to bootc-native under the Phase 2 initiative; dnf5 has been available on image-mode variants since F41. They prove the atomic desktop model at distro scale, and Sway Atomic specifically proves a tiling-WM atomic desktop is a supportable first-party product.

### 4.2 Universal Blue (Bluefin, Bazzite, Aurora) — the operating model Punar would copy

- **What it is**: custom OSes defined as Containerfiles over Fedora Atomic base images; `ublue-os/image-template` is the documented starting point ("Build your own custom Universal Blue Image").
- **Pipeline**: GitHub Actions builds (daily + on-change), pushed to GHCR, **cosign keyless signing on all images**, bootc/rpm-ostree client verifies signature before staging.
- **Channels/staged rollout**: registry tags as release streams — historically `gts` / `stable` / `latest` / `beta`; gts and latest were merged into `stable` on 2026-03-01 (channel consolidation is itself an instructive lesson: too many rings fragment QA). The stable stream trailed Fedora's default kernel by ~2 weeks via the FCOS stable kernel — i.e., a soak-time ring implemented purely with tags.
- **Updates**: `uupd` daemon + systemd timer (default: check ~every 6 h, apply on reboot) coordinating OS image + Flatpak updates.
- **Rollback**: bootloader fallback if a staged deployment fails to boot; previous deployment selectable in the boot menu; imageless recovery by rebasing to any older tagged image.
- **Secure Boot**: kernels/akmods signed with the ublue MOK key; guided enrollment at first boot.
- **Scale**: Bazzite alone surpassed ~50k active users by the 2025 holiday season per Fedora countme-based counting (community-reported; countme systematically undercounts). Aurora/Bluefin add more.
- **Relevance**: this is an existence proof for nearly everything spec 57 wants — signed registry updates, ring-based rollout via tags, automatic fallback — run by a small team with zero bespoke server infrastructure.

### 4.3 secureblue

Hardened images layered on Fedora Atomic: GrapheneOS `hardened_malloc` system-wide (ld.so.preload), kernel/network hardening flags, module blacklisting, and **Trivalent**, a Vanadium-inspired hardened Chromium built from Fedora's Chromium and shipped from a COPR. Demonstrates (a) deep security posture changes need no fork — only image layers; (b) an independently-updated hardened Chromium on Fedora is sustainable for a small project (directly relevant to spec 30/58).

### 4.4 Image mode for RHEL / Rocky bootc

GA, subscription-supported bootc on RHEL 9.6/10; RHEL 10 soft-reboot updates; CIQ ships Rocky bootc images. Matters less as tech input than as an enterprise-credibility and longevity signal: the substrate Punar would build on is a supported Red Hat product line, not a Fedora experiment.

---

## 5. Mapping the OCI update model to spec section 57

Spec 57 requires: controlled, signed, reversible, measurable updates with stages Candidate → Canary → Health → 10% → 50% → 100%, and an endpoint reporting current/desired version, channel, health, rollback state.

| Spec 57 requirement | bootc/OCI mechanism |
|---|---|
| Signed | cosign/sigstore signatures; containers-policy.json enforced by bootc before staging (`--enforce-container-sigpolicy`) |
| Channels | registry tags (`punar:candidate`, `punar:canary`, `punar:stable` …); device assignment = `bootc switch` from the control plane |
| Staged % rollout | progressive re-tagging of an immutable digest to ring tags, or control-plane hands each cohort a digest directly (digest-pinned = deterministic; Universal Blue precedent for tag-ring operation) |
| Health gate | greenboot/greenboot-rs required health checks; failed boots → automatic rollback to previous deployment |
| Reversible | A/B deployments, `bootc rollback`, `ostree admin pin` for known-good retention |
| Measurable / endpoint state | `bootc status --json`: booted image+digest, staged image, rollback target; punard wraps this for the compliance endpoint |
| Browser decoupling (spec 58) | Chromium as an independently-updated unit (own repo/sub-image/Flatpak), not tied to OS image cadence — required regardless of substrate; proven feasible on Fedora by secureblue/Trivalent |

Assessment: **this substrate is the only ADR-001 candidate whose native update primitive already matches spec 57's shape**; the deltas Punar must build are the assignment control plane and the reporting glue, not the transport, signing, or rollback machinery.

---

## 6. Building and boot-testing in CI, and local dev on macOS

- **Build**: `podman build` of a Containerfile on any GitHub Actions Linux runner; disk artifacts (qcow2/AMI/ISO/raw) via `osbuild/bootc-image-builder` and its first-party GHA action `osbuild/bootc-image-builder-action` (Universal Blue's own action is deprecated in its favor). Community actions also handle rechunk+push (jharmison-redhat/action-bootc-build).
- **Boot test**: GitHub-hosted **x86_64 Linux runners expose KVM** (hardware-accelerated virtualization enabled on larger runners 2023-02-23, extended to standard runners 2024-04-02), so real boot tests of the built image run at native speed in CI. `bootc-dev/bcvk` ("bootc virt kit") launches ephemeral VMs from a bootc image rootless via qemu/virtiofsd and creates disk images (`bcvk to-disk`); bootc's own projects use it in their GHA CI (active through 2026). This directly satisfies "keep every milestone bootable" as an automated check.
- **aarch64 caveat**: GH-hosted arm64 runners are GA for public repos (2025-08-07) but **do not support KVM/nested virt**, so aarch64 boot tests need emulation (slow), self-hosted arm64, or third-party runners. Cross-arch *builds* work via `podman build --platform`.
- **Maintainer's macOS arm64 host**: podman machine (Apple Virtualization framework) builds images; `podman-bootc run` boots a bootc image in a VM from macOS, with a known Rosetta-related limitation for cross-arch (x86_64-on-arm) bootc image builds — plan on native aarch64 images locally and x86_64 in CI. Fits the stated Lima/Docker Desktop environment.

---

## 7. Risks and open questions

1. **Ecosystem mid-transition**: rpm-ostree (maintenance mode) → bootc+dnf5 convergence completes around F45 (2026-10-20 target); the client-side package-layering story for a bootc-only world is explicitly undesigned (fedora bootc tracker issue #4). M0 built today straddles the seam.
2. **bootc maturity**: CNCF Sandbox; weekly releases; desktop gaps on record (out-of-tree kernel modules, encryption tooling integration, offline/local layering — LWN 2025-11-07). Mitigated by RHEL GA support of the same stack.
3. **Fast-moving Wayland stack vs Fedora policy**: Hyprland's orphaning from official repos is a documented, structural incompatibility between tip-of-tree compositors and Fedora's update policy. Punar must budget for owning these RPMs (build in CI, ship in image — the image model actually makes this easy, but it is permanent work).
4. **Reproducibility ceiling**: without repo snapshotting/lockfiles, two builds of the same Containerfile differ. Decide early: mirrored+snapshotted RPM repos, NEVRA lockfile, SBOM per image.
5. **Update download size**: OCI layer granularity can make small OS changes cost large downloads; requires deliberate layer ordering/rechunking; composefs/chunking improvements are active upstream but not free.
6. **Trademark/branding**: shipping a derivative requires Fedora remix branding hygiene (unverified detail — check Fedora trademark guidelines before naming/positioning; Universal Blue navigates this successfully).
7. **Unverified/approximate items in this document**: bootc CNCF incubation status (application appears in progress; Sandbox is the confirmed status); exact COPR Hyprland version lags (community-reported); Bazzite user counts (countme-based, undercounted); idle-RAM claims are architectural reasoning, not measurements — must be validated on the M0 image against section 6 budgets.

---

## 8. Citations

State of bootc / ostree / Fedora:

- bootc releases (v1.16.x, dates, features): https://github.com/bootc-dev/bootc/releases
- bootc project / CNCF Sandbox (accepted 2025-01-21): https://www.cncf.io/projects/bootc/ and https://bootc.dev/
- bootc update/rollback commands and auto-update timer: https://bootc.dev/bootc/upgrades.html
- bootc image layout / SELinux labeling in derived layers: https://bootc.dev/bootc/bootc-images.html
- Fedora Image Mode Phase 2 (2026) initiative (F44/F45 milestones): https://fedoraproject.org/wiki/Initiatives/Fedora_bootc
- Sealed Atomic Desktop test images (2026-04-28; systemd-boot+UKI+composefs/fs-verity): https://fedoramagazine.org/sealed-atomic-desktops-test-images/
- Fedora bootc base images (quay.io/fedora/fedora-bootc, tiers): https://gitlab.com/fedora/bootc/base-images and https://fedora.gitlab.io/bootc/docs/bootc/building-from-scratch/
- fedora-bootc image size/package count; minimal builds: https://gursmangat.medium.com/exploring-bootc-base-images-my-initial-take-0e3128c318a6 and https://andrew.dunn.dev/writing/building-bootc-from-scratch/
- ostree 2026.x releases: https://github.com/ostreedev/ostree/releases (downstream: https://archlinux.org/packages/extra/x86_64/ostree/ , https://git.almalinux.org/rpms/ostree/commit/b87acf403a3aeb278e34948396dd859c81f38ce6 )
- rpm-ostree maintenance-mode emphasis, dnf5 on image mode (F41): https://fedoraproject.org/wiki/Changes/DNFAndBootcInImageModeFedora
- Local layering in a bootc world (open design): https://gitlab.com/fedora/bootc/tracker/-/issues/4
- LWN, "Bootc for workstation use" (2025-11-07; desktop gaps): https://lwn.net/Articles/1042708/
- Fedora 43 release (2025-10-28): https://fedoramagazine.org/announcing-fedora-linux-43/
- Fedora 44 release (2026-04-28): https://fedoramagazine.org/announcing-fedora-linux-44/ and https://ostechnix.com/fedora-44-release-date-confirmed/
- Fedora 45 schedule (beta 2026-09-15, final target 2026-10-20): https://fedoraproject.org/wiki/Releases/45/ChangeSet and https://endoflife.date/fedora
- Image mode for RHEL GA (9.6/10): https://www.redhat.com/en/blog/image-mode-for-red-hat-enterprise-linux-generally-available and https://developers.redhat.com/products/rhel-image-mode/faq
- RHEL 10 soft-reboot image updates (2025-11-17): https://developers.redhat.com/articles/2025/11/17/image-mode-rhel-10-updates-seconds-soft-reboot
- Rocky Linux bootc images (CIQ): https://ciq.com/blog/rocky-linux-from-ciq-bootable-container-images-bootc

Atomic desktops / precedents:

- Fedora Atomic Desktops overview: https://fedoraproject.org/atomic-desktops/ ; Sway Atomic: https://fedoraproject.org/atomic-desktops/sway/
- Atomic Desktops in F42: https://fedoramagazine.org/whats-new-for-fedora-atomic-desktops-in-fedora-42/
- Universal Blue org / image-template: https://universal-blue.org/ and https://github.com/ublue-os/image-template
- Bluefin admin docs (cosign signing, sigpolicy, bootloader fallback, streams): https://docs.projectbluefin.io/administration/
- GTS→stable channel merge (2026-03-01): https://github.com/ublue-os/bluefin/commit/49d0f118bd1021844d72d71b8992c286ab64d6cc
- uupd update daemon/timer behavior: https://universal-blue.discourse.group/t/automatic-updates-both-disabled-and-enabled/12127
- Universal Blue Secure Boot / MOK enrollment: https://universal-blue.discourse.group/t/secure-boot-notice/405 and https://docs.projectbluefin.io/installation/
- Bazzite ~50k active users (countme-based, community-reported): https://lemmy.ml/post/40932805 ; https://bazzite.gg/
- secureblue features (hardened_malloc, kernel hardening, Trivalent): https://secureblue.dev/features and https://secureblue.dev/faq
- Trivalent COPR: https://copr.fedorainfracloud.org/coprs/secureblue/trivalent/

SELinux:

- Custom SELinux policy module in bootc images: https://discussion.fedoraproject.org/t/custom-selinux-policy-module-in-bootc-container/158340
- bootc-image-builder SELinux requirement on enforcing hosts: https://github.com/osbuild/bootc-image-builder/issues/6
- RHEL guide, writing custom policy: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/using_selinux/writing-a-custom-selinux-policy

Package freshness:

- Hyprland orphaning email (2024-11-10, reason): https://www.mail-archive.com/devel@lists.fedoraproject.org/msg203424.html
- Hyprland missing from F43 repos: https://discussion.fedoraproject.org/t/hyprland-package-seems-to-be-missing-from-fedora-43-repositories/172183
- Last official Fedora hyprland build (0.45.2-1.fc42): https://packages.fedoraproject.org/pkgs/hyprland/hyprland/
- solopasha COPR: https://copr.fedorainfracloud.org/coprs/solopasha/hyprland ; COPR lag reports: https://www.verona.se/post/hyprland-after-f44-upgrade/ and https://dev.to/ashbuk/hyprland-0522-for-fedora-clean-copr-build-24hm
- Hyprland upstream releases (0.55.0 2026-05-09 … 0.56.2 2026-08-05): https://github.com/hyprwm/Hyprland/releases
- Quickshell official Fedora package (0.2.1^git20260209.dacfa9d, F44/F45/rawhide; verified 2026-08-24): https://packages.fedoraproject.org/pkgs/quickshell/quickshell/ ; COPR also exists: https://copr.fedorainfracloud.org/coprs/errornointernet/quickshell/
- Fedora Chromium security updates mid-2026 (149.x June, 150.0.7871.124 July): https://www.linuxcompatible.org/story/chromium-net-pie-and-more-updates-for-fedora-44 and https://www.linuxcompatible.org/story/linux-security-roundup-thunderbird-chromium-and-nvidia-patches

Rollback / health:

- greenboot (health checks, auto rollback): https://github.com/fedora-iot/greenboot
- greenboot-rs approved for Fedora 43: https://www.phoronix.com/news/Greenboot-Rust-Fedora-43 and https://fedoraproject.org/wiki/Changes/Greenboot_RS_Change_Proposal
- Red Hat article on greenboot rollbacks (2024-08-12): https://developers.redhat.com/articles/2024/08/12/greenboot-automate-rollbacks-atomically-updated-systems

CI / local dev:

- bootc-image-builder + GHA action: https://github.com/osbuild/bootc-image-builder and https://github.com/osbuild/bootc-image-builder-action (ublue action deprecated in its favor: https://github.com/ublue-os/bootc-image-builder-action )
- bcvk ephemeral VM testing: https://github.com/bootc-dev/bcvk
- KVM on GH-hosted Linux runners (2023-02-23 larger, 2024-04-02 standard): https://github.blog/changelog/2023-02-23-hardware-accelerated-android-virtualization-on-actions-windows-and-linux-larger-hosted-runners/ and https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/
- arm64 hosted runners GA for public repos (2025-08-07), no nested virt: https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/ and https://github.com/orgs/community/discussions/160591
- podman-bootc (macOS caveats): https://github.com/containers/podman-bootc
