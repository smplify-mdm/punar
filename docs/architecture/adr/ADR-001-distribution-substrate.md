# ADR-001: Distribution Substrate

- Status: **Accepted** — ratified by Smplify (Spurti Preetham Gurram), 2026-08-24
- Date: 2026-08-24
- Spec references: `docs/product/SPEC_v0.2.md` sections 5, 6, 7, 8 (8.1–8.4), 30, 38–43, 44, 57, 58, 66, 75, 76, 80
- Research inputs (read these for evidence and citations; this ADR does not duplicate their detail):
  - [`docs/architecture/research/substrate-arch.md`](../research/substrate-arch.md)
  - [`docs/architecture/research/substrate-nixos.md`](../research/substrate-nixos.md)
  - [`docs/architecture/research/substrate-fedora-bootc.md`](../research/substrate-fedora-bootc.md)
  - [`docs/architecture/research/crosscutting.md`](../research/crosscutting.md)

## Context

Punar needs a base Linux substrate before Milestone 0 can produce a bootable,
budget-measured VM image (spec 76). Spec 8 names three candidates — a minimal
Arch-based system, NixOS, and Fedora Atomic/image-based — and twelve evaluation
criteria, and states the substrate "must not be permanently finalized until the
MVP architecture evaluation is complete." This ADR therefore makes a **scoped
decision: the substrate for the MVP (Milestones 0–10)**, with explicit revisit
triggers, not a permanent commitment.

Forces that bind the choice:

- **Performance budgets are acceptance criteria** (spec 6): < 1.0 GB idle RAM
  target, 1.5 GB hard ceiling as release blocker; < 100 MB control-plane idle;
  effectively 0% idle CPU; 8 GB constrained profile (spec 7.1) is a first-class
  target.
- **The desktop stack is tip-of-tree**: Hyprland, Quickshell, greetd, and an
  upstream-current Chromium (spec 30, 69). Hyprland shipped three releases in
  ~3 weeks in Jul–Aug 2026; Chrome moves to two-week stable milestones on
  2026-09-08 (crosscutting.md §2.5–2.6). The substrate must absorb this
  velocity or Punar must self-package it.
- **Enterprise requirements are real but MVP-mocked**: spec 44 (Secure Boot,
  LUKS2, MAC, firewall) and spec 57 (signed, channelized, staged
  Candidate→Canary→Health→10%→50%→100% rollout with rollback) must have a
  credible engineering path, but the MVP demo (spec 75, 80) requires enrollment
  into a *mocked* Smplify and "rollback/update mechanism appropriate to chosen
  substrate" — not a production update fleet.
- **Team and environment**: a small Rust-focused team; maintainer's host is
  macOS arm64 (Docker Desktop + Lima, no local rust/qemu/nix); authoritative
  x86_64 builds and boot tests must run in CI. GitHub-hosted x86_64 runners
  expose working KVM; systemd's mkosi CI is a directly copyable pattern
  (crosscutting.md §2.1–2.2).
- **punard is itself a declarative reconciler** (spec 38–43): the substrate
  either stays out of its way or becomes a second source of truth.

Evidence quality note (spec 1.22): no local measurements exist yet. All
footprint and latency figures below come from published sources dated
2026-08-24 in the research files. The only published graphical idle-RAM figure
on any candidate (Omarchy, 1.3 GB, self-reported) is *between* our target and
hard ceiling. Milestone 0 must produce first-party measurements; anything
demonstrated in VMs (Secure Boot, TPM) is simulated until run on hardware.

## Options considered

### Option A — Minimal Arch-based system, vendor-pinned channels, mkosi-built signed images

Start from a pacstrap-minimal Arch package set. Build bootable images in CI
with mkosi (which supports Arch, emits signed UKIs, and boot-tests under
QEMU/KVM on free GitHub runners). Package inputs are pinned to a vendor-owned
snapshot mirror seeded from Arch Linux Archive date snapshots; Punar's own code
ships as pacman packages in a vendor repo; channels (dev/edge/rc/stable →
enterprise rings) are per-ring snapshot promotions. Rollback for MVP is
btrfs + snapper with bootable snapshots (openSUSE-style layout, deliberately
engineered around the documented sharp edges); the A/B image path (SteamOS via
RAUC/casync, arkdep via btrfs subvolume deployments) is the charted production
upgrade. Secure Boot via sbctl-managed keys and signed UKIs (mkosi v26
`uki-signed` variants), vendor key enrollment owned by the installer.

- For: smallest base footprint of the three (~150 MiB container base, ~2 GiB
  bootable install); every MVP desktop component in official `extra`, days-fresh
  (Chromium rebuilt 3 days before research date; Hyprland/Quickshell same-day to
  days); best developer familiarity; the exact product shape — curated repo +
  delayed vendor mirror + channels + snapshot rollback + containerized ISO,
  including the Hyprland+Quickshell pairing — is de-risked by Omarchy at
  consumer scale (substrate-arch.md §3.1).
- Against: transactional updates and full-system reproducibility are **built,
  not inherited** — pacman is non-atomic, and package-level bit-reproducibility
  is ~86.9%, with only input-pinning determinism achievable for images. No Arch
  derivative surveyed ships Secure Boot out of the box; no Microsoft shim.
  Enterprise trust surface (advisories, compliance content, SLAs) is 100%
  Smplify-supplied, and Arch's own advisory publication has been intermittent.
  Permanent curation/migration workload (~6–7 manual-intervention events in the
  last 14 months, each needing an automated migration). "Arch-based" is a
  procurement-perception hurdle. Official Arch is x86_64-only; local work on
  the arm64 Mac is emulated and second-class (substrate-arch.md §2, §4).

### Option B — NixOS

Punar as a module set + overlay on pinned nixpkgs; images via
`nixos-rebuild build-image`; Secure Boot via lanzaboote (v1.1.0, self-enrolled
keys); punard renders desired state into a generated Nix module and drives
`nixos-rebuild`.

- For: best-in-class reproducibility (closure hash doubles as a compliance
  attestation); native atomic activation, generations, and instant rollback —
  spec 42's safe failure implemented at substrate level, with every generation
  signed under lanzaboote; largest package collection with current
  Hyprland/Quickshell and a Chromium security update that landed on the stable
  branch one day after upstream; strong fleet prior art (comin, NixFleet,
  Anduril) and an official Framework hardware partnership
  (substrate-nixos.md §1–4).
- Against: steepest learning curve for a small Rust team with no Nix
  background, in a fragmented ecosystem (flakes still formally experimental;
  CppNix/Determinate/Lix split). The **double-declarative problem** is the
  structural cost: Nix's module priorities are a second precedence system that
  must be kept faithful to spec 39 forever; no partial application (a
  one-capability change is a whole-system eval+switch); eval bursts of ~1–2 GiB
  RAM and tens of seconds are hostile to the reconcile loop on 8 GB devices;
  opaque Nix eval errors clash with spec 40/42 typed explainability; and a
  hybrid nix-owned/runtime-owned state split creates a silent-revert failure
  class (substrate-nixos.md §2). No SELinux, no CIS/SCAP content, auditor
  unfamiliarity. NixOS is not an mkosi target, so choosing it replaces the
  entire image/CI pipeline with Nix-native tooling — the one candidate that is
  a one-way door for the pipeline (crosscutting.md §2.4). No known
  consumer-desktop product OS ships on a NixOS substrate.

### Option C — Fedora Atomic via bootc (OS-as-OCI-image)

Punar is a Containerfile over `quay.io/fedora/fedora-bootc`, built with podman
in CI, pushed to a registry, booted with A/B transactional updates,
health-gated rollback (greenboot), and cosign-signed images; channels are
registry tags.

- For: the native update primitive is a near 1:1 match for spec 57 — signed,
  channelized, digest-pinned staged rollout, health-gated auto-rollback,
  `bootc status --json` for fleet reporting; only the assignment control plane
  is Punar-built (substrate-fedora-bootc.md §5). Secure Boot works out of the
  box with Fedora's Microsoft-signed shim — the cheapest credible SB story.
  SELinux enforcing by default with policy shippable in the image. Best
  enterprise credibility (image mode for RHEL is GA). Universal Blue proves a
  small team can operate the whole model on GitHub Actions + GHCR at 50k+
  users; secureblue proves deep hardening and an independent hardened Chromium
  channel as pure image layers.
- Against: Fedora's update policy is structurally hostile to Punar's desktop
  stack — **Hyprland was orphaned from official Fedora repos** (2024-11) and is
  absent from F43/F44; Quickshell's official Fedora package is a stale 0.2.1
  git snapshot (2026-02) while upstream is at 0.3.1; Fedora
  Chromium lags upstream by one to two weekly refreshes. Punar would
  permanently own RPM packaging for its compositor/shell/browser stack —
  precisely the components that move fastest — on top of a ~6-month Fedora
  rebase treadmill. The ecosystem is mid-transition (rpm-ostree feature-frozen;
  dnf5/bootc convergence completes only around F45, target 2026-10-20; local
  layering explicitly undesigned; bootc is CNCF Sandbox with weekly-release
  churn and documented desktop gaps). Builds are digest-deterministic but not
  hermetic; repo snapshotting/lockfiles/SBOMs are Punar's to add
  (substrate-fedora-bootc.md §3.4, §7).

### Option D — Hybrid strategies (evaluated, partially adopted)

1. **mkosi as substrate-neutral image builder.** mkosi v26 builds both Arch and
   Fedora images (signed UKIs, in-CI KVM boot tests) from one config tree. This
   does not decide the substrate, but choosing it *keeps Arch↔Fedora reversible
   cheaply* while NixOS remains the only irreversible pipeline choice
   (crosscutting.md §2.4). **Adopted as part of Option A.**
2. **Arch package payload delivered via image-based A/B updates.** SteamOS and
   arkdep prove Arch works as an image-deployed atomic OS. This is the
   production-hardening path *for* Option A, not a separate substrate: MVP
   ships snapshot-bracketed pacman updates from pinned channels; the update
   architecture (spec 57) is specified so the transport can move to
   A/B images (mkosi-built, systemd-sysupdate or RAUC-style) without changing
   the channel/signing/health model. **Adopted as the stated trajectory,
   deferred past MVP.**
3. **Nix as CI build system only, punard-native runtime** (substrate-nixos.md
   §2.4). Banks reproducibility without the runtime costs, but imports the Nix
   learning curve into every image-touching contribution while still leaving
   rollback/atomicity to us — the cost profile of Option B with the benefit
   profile of Option A. **Rejected for MVP**; date-pinned snapshot mirrors +
   locked package lists + mkosi's reproducibility options give
   input-deterministic builds at a fraction of the ramp-up.
4. **bootc's OCI update model versus spec 57.** The honest reading: bootc is
   the best off-the-shelf implementation of spec 57's shape, and this ADR
   treats it as the reference model. But spec 57's stages are a *control-plane*
   contract — signing, channels, promotion gates, health checks, percentage
   cohorts — which Smplify must build in punard regardless of substrate
   (bootc supplies transport and apply, not assignment). On Arch, the same
   contract is met with per-ring snapshot repos + signed images/packages +
   punard health gates; what Arch loses is atomic apply, which the A/B
   trajectory (D.2) restores. **Used as the design benchmark for spec 57
   work.**

### Criteria summary (spec 8, twelve criteria)

Grades are relative to the other two candidates: ✓✓ strongest, ✓ adequate,
✗ weakest / highest-cost. Evidence: the per-criterion sections of the three
research files.

| Criterion | Arch (A) | NixOS (B) | Fedora bootc (C) |
| --- | --- | --- | --- |
| Resource efficiency | ✓✓ smallest base; budgets plausible, unmeasured | ✓ runtime par; 1–2 GiB eval bursts on-device | ✓ runtime par; larger disk (A/B + generic kernel) |
| Developer familiarity | ✓✓ pacman/PKGBUILD, target-audience mindshare | ✗ steep niche language, small hiring pool | ✓✓ Containerfile — most familiar artifact |
| Reproducibility | ✓ ~86.9% pkg bit-repro + input pinning | ✓✓ hermetic closures, best by far | ✓ digest-deterministic deploys; non-hermetic builds |
| Package availability | ✓✓ whole MVP stack in official extra, days-fresh | ✓ current in nixpkgs-unstable; channel-lag caveat | ✗ Hyprland orphaned, Quickshell a stale git snapshot — self-packaging forever |
| Security | ✓ fast fixes; advisory pipeline intermittent; no default MAC | ✓ best supply chain; no SELinux, no CIS/SCAP | ✓✓ SELinux enforcing, formal advisories; slower browser fixes |
| Secure Boot | ✗ mature tooling (sbctl/UKI), unproductized, vendor-owned keys | ✗ lanzaboote works, self-enrolled keys only | ✓✓ Microsoft-signed shim out of the box |
| Transactional updates | ✗ built, not inherited (snapshots ≠ atomic; A/B is real work) | ✓✓ atomic activation native | ✓✓ A/B staging native, interruption-safe |
| Rollback | ✓ btrfs+snapper proven (Omarchy), sharp edges; A/B path exists | ✓✓ generations, instant, signed | ✓✓ bootloader fallback + greenboot auto-rollback |
| Hardware compatibility | ✓✓ days-fresh kernel/firmware; x86_64-only official | ✓ par; Framework partnership | ✓ near-latest kernel; akmods pattern for OOT modules |
| Enterprise governance | ✗ mechanisms fine; trust surface 100% vendor-supplied | ✗ best mechanism, worst auditor/ecosystem acceptance | ✓✓ one signed digest per channel; RHEL-GA analog |
| Maintenance burden | ✓ bounded curation+migration stream, automatable | ✗ lowest steady-state *if* team clears ramp — it hasn't | ✓ base inherited, but compositor/browser packaging + rebases owned |
| Upstream velocity | ✓✓ days-level tracking of exactly our stack | ✓ near-par at pin level; Hydra/channel lag | ✗ structurally trails on desktop stack; high bootc churn |

Prose only where the table is not self-evident:

- **Resource efficiency** is *not* decided by the substrate at idle: kernel,
  systemd, compositor, and Punar's own services dominate RAM on all three
  (crosscutting.md §2.7). It is decided by the substrate in two second-order
  ways: NixOS's 1–2 GiB on-device eval bursts conflict with the spirit of
  spec 6 on the 8 GB constrained profile, and Arch's smaller base/disk
  footprint is a real but minor edge. Omarchy's 1.3 GB shows "Omarchy-like" is
  not automatically within budget; Punar's minimal composition must be measured
  in Milestone 0.
- **Package availability** is the sharpest discriminator for *this* product.
  Punar's differentiating UX sits on Hyprland + Quickshell + current Chromium.
  Arch carries all three in official repos at days-level freshness; Fedora
  carries none of the three at acceptable freshness, converting the substrate's
  other wins into a permanent self-packaging obligation for the fastest-moving
  code we depend on; nixpkgs is close behind Arch at the pin level with
  binary-delivery lag unmeasured.
- **Transactional updates / rollback** is the sharpest discriminator *against*
  Arch. We weigh it as: mandatory for production (spec 57), demonstrable for
  MVP via snapshot rollback (spec 80 item 25 asks for a mechanism "appropriate
  to chosen substrate"), and recoverable via the A/B trajectory with two
  shipping Arch precedents. This is the criterion we are consciously buying
  with engineering effort rather than inheriting.
- **Spec 58 (browser decoupling) is substrate-neutral in the end**: an
  upstream-current, independently-updated Chromium channel is Punar-built on
  every candidate. Arch minimizes that toil today (rebuild/curate from a
  days-fresh package); Fedora maximizes it; secureblue proves it is tractable
  even there.

## Decision

**Punar's MVP substrate is Option A: a minimal Arch-based package payload with
vendor-pinned snapshot channels, built into signed images by a mkosi-based
x86_64 CI pipeline, with btrfs+snapper bootable-snapshot rollback for the MVP
and a declared trajectory to image-based A/B updates for production
(Option D.2), using bootc's OCI model as the design benchmark for the spec 57
control plane (Option D.4).** This decision covers Milestones 0–10; the
substrate is re-decidable at the revisit triggers below, and the mkosi pipeline
is chosen specifically to keep the Fedora alternative cheap to reach.

Deciding factors, in order:

1. **MVP hero-demo speed.** The demo (spec 75) is won by the desktop: boot, low
   idle RAM, keyboard-first Hyprland/Quickshell shell, current Chromium,
   enrollment into a *mocked* control plane. Arch is the only candidate where
   every component of that story is in official repos, days-fresh, with a
   shipping consumer product (Omarchy) already proving the exact composition —
   including the ISO build running inside a container, which matches our
   CI-only x86_64 constraint. Fedora would spend pre-demo weeks standing up
   compositor/shell packaging; NixOS would spend them on team ramp-up and
   punard/Nix integration design. Neither expenditure moves the demo.
2. **Section 6 budgets.** Idle budgets are decided by what we ship, not the
   substrate — but Arch has the smallest floor to build up from, no mandatory
   agents, and no on-device evaluation engine. NixOS is the one candidate that
   adds a material RAM/CPU cost (eval bursts) to the reconcile loop on 8 GB
   devices.
3. **Small-team maintenance burden.** Arch's burden — channel curation and
   ~6–7 automated migrations per year, with promotion automated from day one —
   is bounded, boring, and provably carried by teams our size (Omarchy,
   EndeavourOS). Fedora's burden looks smaller until the desktop stack is
   priced in: permanently maintaining Hyprland/Quickshell/Chromium RPMs against
   a 6-month rebase treadmill, on a bootc layer that is itself mid-transition
   until ~F45. NixOS's steady-state burden is lowest but gated on a learning
   curve this team has not paid, plus a permanent two-precedence-system
   mapping inside punard.
4. **Credible path to spec 44 and 57.** Not hand-waved, and not free:
   spec 57's channel/signing/promotion/health control plane is Smplify-built on
   *every* substrate; on Arch the transport is per-ring snapshot mirrors +
   signed vendor repo + snapper-bracketed apply with punard health gates (all
   boring, shipped technology), hardening to A/B images per the SteamOS/arkdep
   precedents when fleet scale demands atomicity. Spec 44: sbctl-managed
   vendor-signed UKIs (emitted by mkosi's signed variants), installer-owned key
   enrollment for self-setup and managed fleets — the same self-enrollment
   posture NixOS has; only Fedora's shim is genuinely cheaper, and shim
   licensing remains an open option for Punar later. LUKS2, nftables, and
   systemd sandboxing/Landlock are substrate-neutral; the MAC ADR (spec 44.3)
   stays open and is *not* prejudged Fedora-style SELinux.

Why not the others, in one line each: **NixOS** solves problems punard must
solve anyway (declarative state, drift, rollback) at the cost of a second
source of truth inside our core product loop, an unpaid team learning curve,
and the only irreversible CI pipeline — the reproducibility win is real but
partially bankable with pinned snapshots. **Fedora bootc** has the best
update/enterprise story, but it structurally cannot keep up with the desktop
stack that *is* the product's differentiation, and its own foundation does not
settle until ~F45; we adopt its update model as the target shape rather than
its substrate.

This is a considered confirmation of the spec 8.1 lean, reached by weighing
the criteria — the strongest counter-candidate (Fedora bootc) loses on the
product's core differentiator, not on ideology.

## Consequences

What we commit to (the "built, not inherited" bill):

- **Vendor infrastructure from day one**: our own rsync'd snapshot mirror
  seeded from Arch Linux Archive dates (never pointing users at ALA or live
  mirrors), a signed vendor pacman repo for Punar's own packages, and automated
  channel promotion with test gates. AUR is never consumed live; anything
  needed from AUR is rebuilt into the vendor repo against the pinned snapshot.
- **Migration automation**: every upstream manual-intervention event becomes a
  shipped migration in Punar's update tooling (Omarchy's migrations-as-packages
  pattern). We watch Arch news and the security tracker ourselves; we do not
  rely on Arch advisories to notify us.
- **Rollback engineering**: openSUSE-style snapper layout with default-subvolume
  switching, per-snapshot UKI retention on the ESP, and explicit avoidance of
  the overlayfs pseudo-rollback trap — designed, not discovered.
- **Secure Boot ownership**: vendor key management, UKI signing in CI, installer
  enrollment flow; evaluate Microsoft shim licensing before enterprise GA. All
  VM-based SB/TPM demos are labeled simulated (spec 1.22).
- **Enterprise trust surface**: advisories, compliance evidence, hardening
  guides, and support posture are entirely Smplify-authored; "Arch-based" will
  cost us procurement conversations and our attestation story must carry that
  weight.
- **CI as the arbiter**: authoritative image builds, UKI signing, and KVM boot
  tests on x86_64 GitHub runners (pinned `ubuntu-24.04`, systemd's mkosi
  workflow as template); the arm64 Mac is for emulated iteration only.

What we give up:

- Inherited atomic updates and hermetic reproducibility (NixOS) — we get
  input-pinned determinism and ~87% package bit-reproducibility instead, and
  must build atomicity ourselves on the A/B trajectory.
- Out-of-the-box Microsoft-shim Secure Boot and distro-integrated SELinux
  (Fedora) — our MAC posture will be assembled from systemd
  sandboxing/Landlock/seccomp unless the spec 44.3 ADR concludes otherwise.
- The RHEL-adjacent enterprise-credibility halo of the bootc ecosystem.

Migration cost if reversed later (kept deliberately low where possible):

- **To Fedora bootc — moderate.** The mkosi pipeline builds Fedora targets from
  the same config tree; punard's capability handlers, the spec 57 control
  plane (designed against bootc's model), CI boot tests, and all Rust services
  carry over. The real costs are self-packaging the compositor/shell/browser
  stack as RPMs and rewriting the update transport onto bootc — weeks-scale,
  not a rewrite.
- **To NixOS — high.** The entire image/CI pipeline is replaced with Nix-native
  tooling, punard grows a Nix rendering/ownership layer, and the team pays the
  full learning curve. Nothing in this decision reduces that cost; it was
  already the price of Option B.
- **Within Option A (channel→A/B transport) — planned, not a reversal.** The
  spec 57 interfaces (channels, signing, health, reporting) are defined
  transport-agnostically so snapshot-apply can be swapped for image-apply.

## Revisit triggers

A trigger firing means opening a new ADR, not editing this one.

1. **Budget miss attributable to the substrate**: the Milestone 0/1 measured
   idle RAM of the minimal Punar composition exceeds the 1.5 GB hard ceiling
   (spec 6.1), or the 1.0 GB target is missed by more than 20% after service
   tuning, with profiling showing substrate-mandated components (not Punar
   services or shell) as the dominant term.
2. **Curation burden exceeds capacity**: Arch upstream requires more than 2
   manual-intervention migrations per month sustained over a quarter, or a
   channel promotion is blocked more than 14 days by upstream breakage we
   cannot patch locally.
3. **Security-response failure**: we are unable to ship a critical
   (CVSS ≥ 9 or actively exploited) kernel/browser fix to the stable channel
   within 7 days on two occasions in any 6-month window, for reasons rooted in
   the substrate or our channel machinery.
4. **Secure Boot becomes a sales blocker**: enterprise deals concretely require
   shim-signed out-of-the-box Secure Boot and shim licensing for Punar is
   refused or exceeds one quarter of effort — re-weigh Fedora bootc.
5. **The A/B trajectory fails**: by the time fleet updates go to real
   enterprise rings (post-MVP), snapshot-bracketed updates demonstrably cannot
   meet spec 57's reliability bar and the A/B image build (mkosi +
   sysupdate/RAUC-style) is estimated at more than one quarter of dedicated
   effort — at that price, bootc's inherited transport re-enters.
6. **Upstream ground shifts**: Fedora ships (or credibly re-adopts) official,
   current Hyprland/Quickshell packaging and the F45 bootc convergence lands
   settled; or Arch's package signing/advisory infrastructure degrades
   materially; or Punar pivots off Hyprland/Quickshell (spec 69's noted
   Hyprland governance risk) — the package-availability discriminator that
   decided this ADR would then need re-scoring.
7. **Enterprise reproducibility demand**: a paying enterprise requires
   bit-for-bit reproducible full-system attestation (beyond input-pinned
   digests and SBOMs) as a contractual condition — re-evaluate the Nix-as-CI
   hybrid (Option D.3) or NixOS proper.
