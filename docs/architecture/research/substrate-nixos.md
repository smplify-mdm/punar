# Substrate research: NixOS

Input to ADR-001 Distribution Substrate (spec section 8.4). Evaluates NixOS per spec section 8.2 against the section 8 criteria, with specific attention to the interaction between NixOS's declarative model and Punar's own reconciliation engine `punard` (spec sections 38-43).

Research date: 2026-08-24. All versions and dates verified against primary sources on this date unless labeled otherwise. Claims labeled *anecdotal* or *inference* are not independently verified (spec section 1.22).

---

## 1. Overview

### 1.1 Current release and cadence

- Current stable: **NixOS 26.05 "Yarara"**, released **2026-05-30**. Supported with bugfixes and security updates for seven months, until **2026-12-31**. ([nixos.org announcement][1])
- Previous stable 25.11 "Xantusia" reached EOL **2026-06-30** — i.e. roughly one month of overlap between releases. ([nixos.org announcement][1])
- Cadence: two releases per year (May and November), each supported ~7 months. A product tracking stable must rebase twice a year; the alternative is the `nixos-unstable` rolling channel.
- 26.05 scale: 20,442 new packages, 20,641 updated, 17,532 removed; 85 new NixOS modules and 1,547 new options. Notable: stage-1 initrd is now **systemd-based by default** (scripted initrd deprecated, removal planned for 26.11); GNOME 50; GCC 15. ([Phoronix][2], [nixos.org announcement][1])

### 1.2 Generations, atomic activation, rollback

Mechanics (from the NixOS manual, [Upgrading][3] / [Rollback][4]):

- `nixos-rebuild` evaluates the system configuration to a complete immutable **system closure** in `/nix/store`, then runs `switch-to-configuration switch`, which (a) registers the closure as a new **generation** of the system profile, (b) updates the bootloader default, and (c) activates the new system in place — restarting only changed systemd units.
- Every rebuild produces a generation; the bootloader menu lists all retained generations, so a machine that fails to boot the new generation can be booted into any previous one from the boot menu. `nixos-rebuild switch --rollback` flips the profile pointer back without rebuilding.
- Nothing is modified in place: old and new systems coexist in the store until garbage collection. Rollback is a pointer flip, effectively instant.

Caveats relevant to Punar:

- Activation is atomic with respect to store contents, but **service restarts are not transactional** — a switch that half-fails can leave a mix of old and new units running (the generation pointer still lets you retry or roll back cleanly).
- Rollback does not revert mutable state (databases, user home, `/var`) — same limitation as every image-based system.
- Kernel/initrd changes require reboot to take full effect; `switch` activates userspace only.
- Generations consume disk until GC'd; a fleet product must ship a retention policy (e.g. keep last N + last-known-good).

This is the strongest transactional-update/rollback story of the three ADR-001 candidates, and it comes for free rather than being a subsystem Punar must build (as it would be on Arch with snapshots, or partially inherit on Fedora Atomic).

### 1.3 Flakes: maturity and fragmentation

- Flakes (hermetic, lock-file-pinned project entry points) remain **formally experimental in upstream Nix as of August 2026**, behind `experimental-features = nix-command flakes`. ([nix.dev][5], [NixOS Discourse][6])
- In practice they are the dominant workflow: the 2025 NixOS Community Survey (3,399 complete responses, fielded Sep-Dec 2025) reports **78.9% of respondents use flakes** and 66.7% use the new `nix` CLI. Flakes are simultaneously the most-requested area for improvement (50.3%). ([2025 survey report][7])
- A stabilization path exists — RFC 0136 "A plan to stabilize flakes and the new CLI incrementally" is merged — but stabilization is incremental and unfinished. ([RFC 0136][8])
- The ecosystem has partially routed around upstream: **Determinate Nix 3.0** (a downstream distribution, not a fork) ships flakes enabled by default with a commercial stability guarantee, and the community fork **Lix** maintains its own consolidated feature set. ([Determinate blog][9])

Assessment: flakes are safe to build on for pinning and CI (lock files are exactly what Punar's reproducible-build requirement wants), but there are now effectively three Nix implementations (CppNix upstream, Determinate, Lix). A substrate decision must pin one and treat the flag as permanent configuration, and accept small residual risk of breaking changes during stabilization.

### 1.4 Image building

- **nixos-generators is retired**: the repo was archived 2026-01-30 after most of its functionality was upstreamed into nixpkgs; since NixOS 25.05 the supported path is **`nixos-rebuild build-image`**, which builds platform-specific disk images (qcow2, ISO, raw, amazon, etc.) directly from a NixOS configuration via `system.build.images`. ([nixos-generators README][10], [nixpkgs PR #371142][11])
- **nixos-anywhere** (install NixOS on any reachable Linux machine over SSH via kexec, with disko-managed partitioning) is actively maintained; latest release 1.13.0, 2025-11-13. ([nixos-anywhere releases][12])
- CI story: an image build is an ordinary `nix build` derivation — deterministic, cacheable, no root or loop-device tricks required for most formats. It runs on any x86_64-linux GitHub Actions runner; `cache.nixos.org` means CI mostly downloads pre-built binaries rather than compiling. For the maintainer's macOS arm64 host, local builds require a Linux builder (nix-darwin's `linux-builder` VM, or nix inside Lima/Docker); x86_64 images from an arm64 host additionally need emulation or remote builders — consistent with the plan to do x86_64 work in CI.
- Closure minimization is a known, documented practice: a NixOS system importing the `minimal`, `perlless`, and image-based appliance profiles reaches a ~467-500 MiB closure; an example appliance image shrank from 1.5 GB to ~360 MB. ([nixcademy][13], [Discourse: how minimal can a NixOS image get][14])

### 1.5 Secure Boot: lanzaboote

- **Lanzaboote reached v1.0.0 on 2025-12-10; v1.1.0 followed 2026-06-22** (verified via GitHub API). After three years of 0.x releases this is the project's own signal of production readiness. ([lanzaboote releases][15])
- The official NixOS wiki lists two supported Secure Boot routes: **Lanzaboote** and the **Limine** bootloader's signing support. ([NixOS wiki: Secure Boot][16])
- Lanzaboote requires UEFI + systemd-boot and builds on the bootspec format (default since NixOS 23.05). It signs a UKI-style stub per generation so *every generation in the boot menu* is signed — Secure Boot and rollback compose correctly. ([lanzaboote docs][17])
- Key model: **self-enrolled platform keys** created with `sbctl`; the machine must be put into firmware Setup Mode to enroll them. There is no Microsoft-signed shim for NixOS, so Secure Boot on unmodified OEM key databases is not available (*inference from lanzaboote quick-start docs and wiki; no shim-signing effort found as of 2026-08*). Planned but not shipped: remote-signing and PKCS#11/HSM signature backends. ([lanzaboote docs][17])
- Still-open gaps: measured boot / TPM PCR handling has an open tracking issue (#636, opened 2026-07-07). ([lanzaboote issues][18])

Assessment for Punar: for a controlled installer flow (Punar owns key enrollment at install time, spec section 66) lanzaboote is viable today and uniquely gives signed rollback targets. For "enable Secure Boot on an arbitrary consumer laptop without touching firmware settings," NixOS is behind Fedora (which has a Microsoft-signed shim). Note that a custom Arch-based substrate would face the same self-enrollment requirement, so this criterion mainly differentiates Fedora Atomic.

### 1.6 Size and RAM data points

- Runtime RAM: NixOS adds no unusual overhead versus other systemd distros — the same kernel, systemd, and chosen services dominate. `nix-daemon` is idle unless building. One community datapoint: NixOS + Hyprland on a 4 GB machine left ~2.7 GB free after boot (~1.3 GB used including caches) — *anecdotal, unverified, methodology unknown*. ([Discourse][19]) A Punar-built minimal Hyprland/Quickshell configuration would need first-party measurement against the spec section 6.1 budget (<1.0 GB target); nothing in NixOS architecturally prevents meeting it.
- Disk: minimal server-style closure ~500 MiB (section 1.4); the official desktop guidance recommends ~30 GiB free for a full DE + browser setup, 15 GiB for bare-bones. ([NixOS wiki: NixOS as a desktop][20]) Generations add retained-closure overhead (deduplicated at the store-path level, so deltas are usually small).
- The real resource-efficiency concern is **evaluation cost**, not runtime cost: evaluating even a fairly simple NixOS system configuration allocates roughly **1-2 GiB of RAM** and takes tens of seconds on modest hardware (minutes on very low-end); this is a long-standing tracked issue. ([nix issue #12153][21], [nixpkgs issue #57477][22]) This directly matters for the punard integration (section 2).

---

## 2. The double-declarative problem: punard on NixOS

Punar's `punard` (spec sections 11.1, 38-43) is itself a declarative reconciliation engine: typed capabilities, desired-state documents, observe→diff→plan→apply→verify→audit, precedence rules (spec 39), explainability (spec 40). NixOS is *also* a declarative reconciliation engine whose apply step is `nixos-rebuild switch`. Running one on top of the other is the central architectural question for this substrate.

### 2.1 How punard would drive NixOS

The workable pattern, with direct prior art:

1. punard renders the effective desired state (after spec-39 precedence resolution) into a **generated Nix module** — e.g. `/etc/punar/generated.nix` or a locked flake input — covering the capabilities that are configuration-shaped (packages, services, firewall ruleset, disk-encryption requirements, update channel).
2. punard invokes `nixos-rebuild switch` (or, for tighter control, `nix build` of the system closure followed by `switch-to-configuration switch` — the same two primitives, callable separately so plan and apply are distinct phases, which maps cleanly onto spec 42's Plan/Apply split).
3. The resulting generation is recorded in the audit log; the **system closure's store path hash is a precise, cheap compliance attestation** — "device is running exactly closure X" is a stronger statement than any package-list inventory on Arch or Fedora.
4. Verification still runs punard's own capability probes (spec 41 `verification` field, e.g. nftables state), because Nix guarantees what activation *wrote*, not what is *currently true* at runtime.

Prior art that this pattern works: **comin** (a systemd daemon that pull-deploys NixOS configurations from git, i.e. a GitOps agent invoking nixos-rebuild) ([comin][23]); **NixFleet** (declarative NixOS fleet management with signed GitOps and a **Rust control plane** — almost exactly punard's shape) ([NixFleet announcement][24]); colmena/deploy-rs for push-based fleets; Anduril's embedded fleet (section 3).

### 2.2 Costs of two sources of truth

1. **Ownership of the configuration.** Either punard owns the entire system configuration (users lose the native NixOS workflow — at which point NixOS's community familiarity benefit largely evaporates and it is functioning as an internal image/config compiler), or the config is split between user-authored and punard-generated modules. The split model surfaces conflicts as Nix module-system merge errors and `mkForce`/`mkOverride` priority fights. Critically, **Nix's option-priority system is a second precedence mechanism that does not match spec 39's semantics** (Hard OS Constraint > Org Mandatory > Role > Exception > User Pref > Default). punard would have to compile spec-39 precedence *into* mkOverride priority numbers and guarantee no user module can out-prioritize an org-mandatory value — possible, but it means maintaining a faithful mapping between two precedence systems forever.
2. **Error surface and explainability.** Spec 42 requires typed, testable reconciliation; spec 40 requires explainability. `nixos-rebuild`'s failure mode is a Nix evaluation error — the single most complained-about UX in the ecosystem (47.6% of survey respondents want better error messages ([survey][7])). punard would need to translate eval failures into typed capability-level errors, which in the general case means parsing Nix stderr. This is the weakest link in the chain.
3. **Reconcile-loop resource cost.** Each apply is a full system evaluation: ~1-2 GiB transient RAM and tens of seconds to minutes ([nix #12153][21], [nixpkgs #57477][22]). Spec 6.2 budgets <100 MB *idle* for control-plane services — bursts are technically outside the idle budget, but on the 8 GB constrained profile (spec 7.1) a 1-2 GiB eval burst during memory pressure is hostile. Mitigations: strictly event-driven reconciliation (no periodic re-eval; consistent with spec 6.3), eval caching, minimal module imports. It cannot be reduced to the cost of a typed nftables API call.
4. **No partial application.** NixOS switches whole systems. A single-capability change (toggle firewall) costs a full eval+switch; a direct typed API call costs milliseconds. The tempting hybrid — Nix owns install/update-shaped state, punard mutates runtime-mutable capabilities directly — creates a *third* failure class: state changed by punard at runtime is silently reverted at the next switch unless the generated config was updated first. Every capability must be classified as exactly one of nix-owned or runtime-owned, and the capability registry (spec 41) must encode that.
5. **Verification/audit granularity.** `nixos-rebuild` reports success/failure for the whole switch. Per-capability audit events (spec 42/53) require punard to diff generations and attribute unit restarts itself.
6. **Secrets.** The Nix store is world-readable; secrets must never enter it. Standard workarounds (sops-nix/agenix) deliver secrets at activation time outside the store. Punar already plans a runtime secret broker (`punar-secrets`, spec 29), which sidesteps this cleanly — but it forbids ever templating a secret into generated config.

### 2.3 What NixOS gives back

- Atomic apply + per-reconcile rollback for free; a failed remediation is a pointer flip away from last-known-good — this is spec 42's "safe failure" implemented at the substrate level.
- Config-owned drift largely *cannot happen*: `/etc` entries are symlinks into the read-only store; a class of drift (config file tampering) is structurally prevented rather than detected. Runtime drift (e.g. `nft flush ruleset`) still exists and still needs punard — NixOS narrows drift, it does not eliminate it.
- One code path from CI image build (`nixos-rebuild build-image`) to fleet update to local reconcile — the update architecture (spec 57) and the reconcile engine share a substrate primitive.
- Closure hash as compliance evidence (section 2.1).
- "Temporary approved exception" (spec 39) maps naturally onto NixOS **specialisations** (variant generations sharing a base config).

### 2.4 The hybrid worth naming in ADR-001

There is a middle option: **Nix as build system, not as runtime substrate** — use Nix/nixpkgs in CI to build reproducible Punar images and update payloads (over any base, including an Arch-derived rootfs or an image-based scheme), while runtime reconciliation stays fully punard-native with typed capability handlers. This captures most of the reproducibility win and none of the double-declarative runtime costs, at the price of building rollback/atomicity ourselves. ADR-001 should evaluate this explicitly rather than treating "NixOS everywhere" and "no Nix at all" as the only options.

---

## 3. Criteria-by-criteria assessment (spec section 8)

| Criterion | Assessment | Grade vs. other candidates |
|---|---|---|
| **Resource efficiency** | Runtime overhead equal to any systemd distro; minimal closures ~500 MiB proven; idle-RAM budget (spec 6.1) achievable but unmeasured for our stack (*first-party measurement required*). Weak spot: 1-2 GiB / tens-of-seconds evaluation cost per reconcile or update on-device. ([13], [14], [21]) | Runtime: par. Reconcile cost: worst of the three. |
| **Developer familiarity** | Nix language is a genuinely steep, niche skill. Community itself is young: 82.5% of survey respondents have under four years' experience, 28.9% under one. Hiring pool small; ramp time for the existing Rust-focused team is a real cost. ([7]) | Worst of the three for a small team; Arch best. |
| **Reproducibility** | Best-in-class. Pinned nixpkgs + flake lock yields the same closure everywhere; images, updates, and dev shells share one mechanism; store-path hash doubles as attestation. | Best of the three, by a wide margin. |
| **Package availability** | nixpkgs is the largest active package collection (20k+ new packages in 26.05 alone). Everything Punar needs is present with current versions: Hyprland 0.55.4 in 26.05 stable / 0.56.2 in unstable, Quickshell 0.3.0 in both (verified in nixpkgs branches 2026-08-24); Hyprland upstream officially supports NixOS. ([1], [25], [26]) | Par with Arch+AUR; better vetting, slightly more packaging friction for out-of-tree binaries (FHS assumptions). |
| **Security** | Strong supply chain (reproducibility, signed cache, read-only store — spec 59.6). Weak MAC story: **no SELinux support**, AppArmor partial — spec 44.3 would lean on other primitives (namespaces, systemd hardening, spec 45). No CIS/SCAP/STIG content exists for NixOS. World-readable store forbids secrets in config (aligns with spec 29 anyway). ([27], [28]) | Supply chain: best. MAC/compliance content: worst (Fedora best). |
| **Secure Boot** | lanzaboote v1.1.0 (2026-06-22); v1.0 milestone 2025-12-10. Works with self-enrolled keys; signs every generation; no Microsoft shim; measured-boot gaps open. Viable when the installer owns key enrollment; label VM demos as simulated per spec 1.22. ([15], [16], [17], [18]) | Behind Fedora (shim); roughly par with a custom Arch build (sbctl). |
| **Transactional updates** | Native and mature: atomic closure build + generation registration; `nixos-rebuild test/boot/switch` modes; staged enterprise rollout (spec 57) still Punar-built on top, with comin's testing-branch model as prior art. ([3], [23]) | Best of the three (Fedora Atomic close second). |
| **Rollback** | Generations + bootloader menu + `--rollback`; signed under lanzaboote; instant pointer flip. ([4]) | Best of the three. |
| **Hardware compatibility** | Mainline kernel; nixos-hardware quirk library; official NixOS Foundation-Framework partnership (community since April 2025, formalized January 2026) — direct fit for spec 5.3's Framework 13 target. Unfree firmware/NVIDIA require explicit config flags. ([29]) | Par; Framework partnership is a concrete plus. |
| **Ease of enterprise governance** | Two-sided. The module system *is* a declarative control surface, and fleet prior art exists (comin, NixFleet, colmena, Anduril). But zero MDM-vendor support, no CIS/SCAP content, auditor unfamiliarity — all compliance evidence formats would be Smplify-built (which is, admittedly, the product). ([23], [24], [28]) | Mechanism: best. Ecosystem/auditor acceptance: worst. |
| **Maintenance burden** | Punar as overlay + module set on pinned nixpkgs: no self-maintained package repo, twice-yearly stable rebases (7-month support window forces discipline), occasional unstable backports for the fresh desktop stack. Must run a binary cache for own packages. Nix-expression upkeep is real but far below maintaining an Arch derivative's repo/ISO infrastructure. ([1]) | Lowest ongoing burden of the three *if* the team clears the learning curve. |
| **Upstream velocity** | Very high: 26.05 added/updated ~41k packages; Chromium 151.0.7922.173 landed on nixpkgs master *and* the release-26.05 branch on 2026-08-21, one day after Google's 2026-08-20 Linux stable release (verified via nixpkgs commit history + Chrome releases blog). Caveats: commit ≠ channel — Hydra build + channel advance adds hours-to-days for a source-built Chromium; and freshness is maintainer-dependent (chromium has needed maintainers before; a google-chrome staleness incident left it 10+ days outdated with known CVEs). Governance noise (Lix/Determinate forks, sponsor controversies) is real but has not slowed nixpkgs. Spec 58's rapid-browser-patching requirement argues for Punar shipping its own Chromium channel regardless of substrate. ([30], [31], [32], [33]) | Par with Arch on freshness; better on stable-branch security backports; channel-lag caveat unique to Nix. |

---

## 4. Precedent projects

- **Anduril Industries** — the flagship industrial NixOS deployment: NixOS across embedded products ("fleet of robots"), virtualized test assets, and developer infrastructure; continuously hiring NixOS engineers; 5+ year community member and sponsor (CUDA support, docs funding). Demonstrates NixOS fleet operation at scale in a security-sensitive company. ([34], [35])
- **TII Ghaf** — an open-source, NixOS-based secure edge/virtualization platform from the Technology Innovation Institute; uses lanzaboote for Secure Boot. Precedent for building a hardened product OS on NixOS. ([36])
- **NixOS Foundation - Framework partnership** — official hardware-vendor partnership (announced January 2026, building on community collaboration since April 2025). Precedent for first-party laptop support on Punar's reference hardware. ([29])
- **Determinate Systems** — "Nix for the enterprise": commercial downstream distribution with flake stability guarantees; evidence of a commercial support ecosystem existing (relevant to spec's enterprise posture). ([9], [37])
- **comin / NixFleet / colmena / nixos-anywhere** — the fleet-tooling ecosystem punard would either reuse patterns from or compete with; NixFleet in particular (Rust control plane + Nix module system + signed GitOps) validates the punard-on-NixOS architecture. ([23], [24], [12])
- Counter-signal: no known consumer-desktop product OS ships on NixOS; deployments are embedded, server, and enthusiast-desktop. Punar would be first-mover in the "polished consumer-grade desktop on NixOS substrate" category (*assessment, not a verified absence*).

---

## 5. Bottom line for ADR-001

NixOS is the strongest candidate on exactly the axes Punar's spec is most demanding about — reproducibility, transactional updates, rollback, declarative control — and the weakest on team ramp-up, MAC/compliance ecosystem, Microsoft-shim Secure Boot, and the resource cost of its evaluation engine. The double-declarative tension is manageable with a strict ownership split (every capability is either nix-owned or runtime-owned, never both) and event-driven reconciliation, and it has direct prior art (comin, NixFleet); its worst costs are the opaque eval-error surface versus spec 40/42's typed explainability requirements, and the 1-2 GiB eval bursts on 8 GB devices. The "Nix as build system only" hybrid (section 2.4) deserves explicit evaluation in ADR-001 as a way to bank the reproducibility win without adopting the runtime.

---

## 6. Citations

[1]: https://nixos.org/blog/announcements/2026/nixos-2605/ "NixOS 26.05 'Yarara' released 2026-05-30; support to 2026-12-31; 25.11 EOL 2026-06-30; systemd stage-1 default"
[2]: https://www.phoronix.com/news/NixOS-26.05-Released "NixOS 26.05 release coverage: 20,442 new packages, systemd stage-1"
[3]: https://nixos.org/manual/nixos/stable/#sec-upgrading "NixOS manual: upgrading and channels"
[4]: https://nixos.org/manual/nixos/stable/#sec-rollback "NixOS manual: rolling back configuration changes"
[5]: https://nix.dev/concepts/flakes.html "nix.dev: flakes concept page (experimental status)"
[6]: https://discourse.nixos.org/t/is-nix-flakes-really-out-of-experimentation/62529 "Discourse: flakes experimental status discussion"
[7]: https://discourse.nixos.org/t/2025-nixos-community-survey-report/78812 "2025 NixOS Community Survey: 3,399 responses; 78.9% flakes; 82.5% under 4 years experience; error messages 47.6%"
[8]: https://github.com/NixOS/rfcs/blob/master/rfcs/0136-stabilize-incrementally.md "RFC 0136: stabilize flakes and new CLI incrementally"
[9]: https://determinate.systems/blog/determinate-nix-30/ "Determinate Nix 3.0: flakes default with stability guarantee"
[10]: https://github.com/nix-community/nixos-generators "nixos-generators: archived 2026-01-30 (verified via GitHub API); superseded by nixos-rebuild build-image"
[11]: https://github.com/NixOS/nixpkgs/pull/371142 "nixpkgs PR: nixos-rebuild build-image implementation (NixOS 25.05)"
[12]: https://github.com/nix-community/nixos-anywhere/releases "nixos-anywhere releases: 1.13.0 on 2025-11-13 (verified via GitHub API)"
[13]: https://nixcademy.com/posts/minimizing-nixos-images/ "Minimizing NixOS images: 1.5 GB to ~360 MB; perlless ~491 MB"
[14]: https://discourse.nixos.org/t/how-minimal-can-a-nixos-image-get/45268 "Discourse: minimal NixOS closure ~467.7 MiB with minimal+appliance+perlless profiles"
[15]: https://github.com/nix-community/lanzaboote/releases "lanzaboote v1.0.0 2025-12-10; v1.1.0 2026-06-22 (verified via GitHub API)"
[16]: https://wiki.nixos.org/wiki/Secure_Boot "NixOS wiki: Secure Boot via Lanzaboote or Limine"
[17]: https://nix-community.github.io/lanzaboote/ "lanzaboote docs: bootspec basis, sbctl key enrollment, planned remote/PKCS#11 signing"
[18]: https://github.com/nix-community/lanzaboote/issues "lanzaboote issue tracker incl. measured boot #636 (2026-07-07)"
[19]: https://discourse.nixos.org/t/my-progress-with-nixos-hyprland/37585 "Discourse anecdote: NixOS+Hyprland on 4 GB machine, ~2.7 GB free (unverified)"
[20]: https://wiki.nixos.org/wiki/NixOS_as_a_desktop "NixOS wiki: ~30 GiB recommended for desktop install, 15 GiB bare-bones"
[21]: https://github.com/NixOS/nix/issues/12153 "nix: ~1.8-2 GiB RAM allocated evaluating a fairly simple NixOS system"
[22]: https://github.com/NixOS/nixpkgs/issues/57477 "nixpkgs tracking issue: nixos-rebuild switch too slow"
[23]: https://github.com/nlewo/comin "comin: pull-mode GitOps daemon deploying NixOS configurations"
[24]: https://discourse.nixos.org/t/nixfleet-declarative-nixos-fleet-management-with-signed-gitops/77195 "NixFleet: NixOS fleet management, Rust control plane, signed GitOps"
[25]: https://wiki.nixos.org/wiki/Hyprland "NixOS wiki: Hyprland officially supports NixOS; versions verified in nixpkgs branches 2026-08-24 (0.55.4 stable / 0.56.2 unstable)"
[26]: https://quickshell.org/docs/v0.1.0/guide/install-setup/ "Quickshell install docs: release versions available from nixpkgs (0.3.0 in both branches, verified 2026-08-24)"
[27]: https://github.com/NixOS/nixpkgs/issues/11790 "nixpkgs issue: benchmark NixOS against CIS guidelines (no official content; SELinux not workable)"
[28]: https://discourse.nixos.org/t/nixos-in-cis-benchmark-level-1/2189 "Discourse: CIS benchmarks are distro-specific and do not cover NixOS"
[29]: https://nixos.org/blog/announcements/2026/framework-partnership-announcement/ "NixOS Foundation-Framework official partnership (announced 2026-01; community collaboration since 2025-04)"
[30]: https://chromereleases.googleblog.com/2026/08/stable-channel-update-for-desktop_0404570826.html "Chrome stable 151.0.7922.173 for Linux, ~2026-08-20"
[31]: https://github.com/NixOS/nixpkgs/commits/release-26.05/pkgs/applications/networking/browsers/chromium "nixpkgs release-26.05: chromium 151.0.7922.173 committed 2026-08-21 (verified via GitHub API)"
[32]: https://github.com/NixOS/nixpkgs/issues/78450 "nixpkgs: Chromium/Chrome need new maintainers (historic maintainer-capacity risk)"
[33]: https://github.com/NixOS/nixpkgs/issues/407502 "nixpkgs: google-chrome 10+ days outdated with known CVEs (2025 incident)"
[34]: https://discourse.nixos.org/t/anduril-is-hiring-nixos-and-embedded-linux-engineers/42862 "Anduril: NixOS at scale, embedded fleet, 5+ years in community"
[35]: https://startup.jobs/nixos-developer-anduril-industries-3928249 "Anduril NixOS Developer role: embedded NixOS fleet, overlays/flakes, virtualized NixOS test assets"
[36]: https://github.com/tiiuae/ghaf "TII Ghaf: NixOS-based secure edge platform using lanzaboote"
[37]: https://github.com/determinateSystems/determinate "Determinate: Nix for the enterprise"
