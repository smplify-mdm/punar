# Competitive position — Punar vs Omarchy

**Status:** historical baseline · frozen 2026-08-25 · owner: product
**Brief received, verbatim:** *"We need to be better than omarchy.org in every way."*
**Evidence base:** [`docs/product/research/omarchy.md`](research/omarchy.md) (verified
2026-08-25, marker-tagged) for Omarchy; [`IMPLEMENTATION_STATUS.md`](../../IMPLEMENTATION_STATUS.md),
[`docs/development/milestone-13.md`](../development/milestone-13.md) §3 (the DoD
traceability matrix), [`docs/development/user-blocked.md`](../development/user-blocked.md),
[`PERFORMANCE_BUDGETS.md`](../../PERFORMANCE_BUDGETS.md),
[`docs/design/DESIGN_LANGUAGE.md`](../design/DESIGN_LANGUAGE.md), ADR-001/002/003, and the
image definition at `os/images/mkosi.profiles/desktop/mkosi.conf` for Punar.

> **Do not use this frozen snapshot as Punar's current readiness report.** It
> intentionally preserves the evidence available on 2026-08-25; later work has
> closed its installer, onboarding, application, update/rollback and desktop
> claims. Current implementation and canonical-run evidence live in
> [`BUILD-QUEUE.md`](../../BUILD-QUEUE.md). Refreshing the full comparison
> requires a new same-date Omarchy research pass rather than silently mixing
> old competitor evidence with new Punar evidence.

This document is written to be useful to a founder deciding where the next month goes.
It is therefore honest in both directions. Where Punar's status is
**IMPLEMENTED — NOT YET RUN** or **SIMULATED**, it says so rather than counting it as
shipped. Where Omarchy is simply better today, it says that too.

Two standing evidence rules, used literally throughout:

- Omarchy markers follow the research file: **[V]** verified primary source,
  **[V-SELF]** verified self-report by the project or DHH (not independent),
  **[I]** inferred, **[U]** unverified secondary, **[NF]** not found.
- Punar statuses follow milestone-13.md §3.1: **PROVEN IN CI**, **IMPLEMENTED — NOT YET
  RUN**, **PLANNED**, **HUMAN-VERIFIED ONLY**, **NOT MET**. A status describes the
  *weakest* link in the evidence chain, never the strongest.

---

## 0. The one-paragraph situation

Omarchy is a shipped product with roughly six-figure install volume [V-SELF,
bandwidth-derived], 31,171 GitHub stars, a $10M foundation, 148 curated packages, driver
and firmware coverage for nine hardware families, LUKS by default, a 51-chapter manual,
22 themes, and a snapshot-rollback story — and it is currently unstable, having shipped a
whole-shell rewrite eleven days ago that produced 629 issues in 30 days including 20 open
lock-screen strandings [V]. Punar is a pre-alpha repository with no installer, no ISO, no
bare-metal boot ever performed, 33 packages, no firmware, no networking stack, no
Bluetooth, no printing, no lock screen and no notification daemon — and it has a
control-plane architecture, an agent-governance model and a verification discipline that
Omarchy does not have and would not find cheap to acquire. Eleven of Punar's 26
Definition-of-Done items are true today without a caveat or a pending run
(milestone-13.md §3.3). The gap is not close, and it is not in the direction the brief
assumes.

---

## 1. Axis-by-axis

Sixteen axes a user or buyer would actually care about. "Gap size" is the honest distance,
expressed as the engineering it would take to close, not as a feeling.

| # | Axis | Omarchy's position (evidenced) | Punar's position (evidenced) | Verdict | Honest gap |
|---|---|---|---|---|---|
| 1 | **Install experience** | ISO-only and it works: `omarchy-iso` drives archinstall against a bundled offline pacman mirror; LUKS full-disk encryption is the install default; free-space dual-boot added in 4.0; unattended install via a cloud-init `cidata` drive (Proxmox/libvirt/Packer); OEM/gifting setup and factory reset in 4.0. Self-reported "<1 min on fastest machines, ≤5 min on older", "+30% faster" in 4.0 [V-SELF, no independent timing]. | **No installer exists.** `os/images/mkosi.conf` emits `Format=disk` dev images only; ISO output is listed under "not yet done". The dev image ships `Autologin=yes` and `RootPassword=punar` — documented conveniences, never a production default. Nobody outside this repository has ever installed Punar. | **OMARCHY LEADS** | Enormous. 6–10 weeks of work, and it must land *after* the ADR-003 A/B slot layout because the installer partitions for it. This is the axis on which Punar is not a product. |
| 2 | **Hardware support** | Shipped as driver/firmware packages, which is stronger evidence than marketing: `nvidia-dkms`/`nvidia-open-dkms`/`nvidia-580xx-dkms`, `intel-media-driver`, `intel-ipu7-camera`, `vulkan-radeon`, `vulkan-asahi`, `linux-t2` + `apple-bcm-firmware` + `t2fanrd` for T2 MacBooks, `dell-xps-touchpad-haptics`, `qmk-hid` (Framework 16), `linux-firmware-marvell` (Surface), `asusctl`, `tuxedo-drivers` [V]. Also 32 open NVIDIA-titled issues and #7045 "NVIDIA 50xx — can't install, black screen" [V] — which is itself proof that thousands of people run it on metal. | `linux-firmware` is **deliberately excluded** from both images (`os/images/mkosi.conf:7`, desktop profile line 19). Every measurement and every assertion in this repository comes from an emulated x86_64 QEMU VM on an arm64 macOS host, virtio-vga with llvmpipe. **No bare-metal boot has ever happened.** Hardware is user-blocked item 3 — the machines do not exist yet. | **OMARCHY LEADS** | Decisive, and calendar-blocked rather than effort-blocked. Firmware packaging is ~1–2 weeks; *validation* is 2–3 months and cannot start until physical §5.3-class machines are on a desk. |
| 3 | **Daily-driver completeness** (audio, Bluetooth, printing, suspend/resume, external displays, screen share) | All present and in daily use, with known and public defect clusters: 28+13 open suspend/sleep issues, #4740, reports of 72%→18% battery over 8 h "suspended"; #7776 built-in camera dead on fresh install; #6956 Bluetooth widget vanishes when BT is off [V]. Speaker tunings shipped for 2026 XPS 14/16. Broken in places, but present everywhere. | The desktop profile is **33 packages**. `pipewire`/`pipewire-pulse`/`wireplumber` are installed but the CI VM has no audio device, so audio has never made a sound. **No `bluez`. No `cups`. No `NetworkManager` or `iwd`. No `cryptsetup`. No `fprintd`.** `xdg-desktop-portal-hyprland` is installed and has never been exercised — no screen share has ever occurred. Suspend/resume has never been attempted. External displays have never been attached. | **OMARCHY LEADS** | Enormous. This is the table-stakes bill in §3: roughly 12–16 weeks of surface work, of which the majority is gated on axis 2's hardware. |
| 4 | **Desktop polish and theming** | 22 built-in themes with a live-preview carousel; the 4.0 palette expanded 8→24 colours so nvim/VS Code/btop themes **auto-generate**; theming covers desktop, terminal, nvim, btop, Chromium *and* the whole shell including the lock screen; drag-to-reposition bar and drag-to-reorder widgets — GUI customisation, rare in tiling WMs [V]. | One design language ("Field Note"), one token set (`shell/theme/punar-tokens.{json,css}`), documented with type roles, a WCAG-AA contrast rule and five numbered non-negotiables; 16 design plates D-001…D-016. **No theme switching. No wallpaper** — milestone-13.md §7.1 rank 10 notes the desktop is currently "a flat token color". **No lock screen at all. No notification daemon** — the image contains no `org.freedesktop.Notifications` implementation (milestone-13.md §6.1 gap 7). Plate fidelity of the shipped panels is an unexecuted human review. | **OMARCHY LEADS** on shipped polish. **PUNAR LEADS** on design-system rigour (token discipline, contrast rules, a written editorial voice) — but rigour nobody has seen is not polish. | Large on shipped surface (~6–8 weeks for lock screen + notifications + wallpaper + a second theme). Near-zero on design *coherence*, where Punar is arguably already ahead and should stop there — see §5. |
| 5 | **Application curation** | Exactly 148 packages in `install/omarchy-base.packages` [V]: foot, chromium, nvim+omarchy-nvim, obsidian, libreoffice-fresh, kdenlive, obs-studio, mpv, nautilus, docker+lazydocker, lazygit, mise, btop, tmux, herdr, starship, tesseract, ufw+ufw-docker, localsend, sddm, plymouth, cliamp, plus first-party omawrite/omacut/omacalc. Steam/Signal/Spotify/1Password/HEY are *menu-installable extras*, not base — the "ships DHH's bloatware" criticism is largely stale for 4.x [V]. | 33 packages: hyprland, quickshell, greetd, foot, chromium, git, neovim, podman+crun+netavark+aardvark-dns, pipewire trio, mesa, polkit, hyprpolkitagent, noto fonts, grim/slurp/wl-clipboard, jq, nftables, portals. No office suite, no media tooling, no file manager, no package-install surface. | **OMARCHY LEADS** | Large in count, small in effort (~1 week of packaging). The real question is curation *policy*, not effort — and §5 argues Punar should deliberately not match this. |
| 6 | **Documentation and onboarding** | 51-chapter manual at omarchy.org/manual written as Markdown in-repo, v3's 49-chapter manual preserved separately; official 4.0 YouTube intro; Discord linked from site nav *and* from inside the OS Learn menu; a "Coming From Mac or Windows" chapter that sets expectations honestly ("you don't drag windows around… give it two weeks"); onboarding teaches exactly two keys — Punar+Space and Punar+K [V]. | **Zero user-facing documentation.** What exists is engineering documentation of unusual quality: an authoritative spec, three ADRs, twelve milestone design documents, a DoD traceability matrix that grades its own project NOT MET on three items, and a `user-blocked.md` that lists what cannot be honestly claimed. First boot (spec §65, Plate D-008) has **no implementation** — milestone-13.md §5.1 calls this out. | **OMARCHY LEADS** on user docs, decisively. **PUNAR LEADS** on internal traceability — genuinely, and it is not close in that direction either. Two different documents; only one of them a user reads. | Large. 3–4 weeks of writing, but correctly *blocked* on the product settling: a manual written now would describe something that will not exist in three months. |
| 7 | **Performance and footprint** | ISO "under 6 GB" [V-SELF]. Shell process "less than 300mb… once you account for shared library usage" — DHH tweet Aug 2026, **shell process only** [V-SELF]. Whole-system idle "1.3GB RAM on boot" — DHH tweet **Aug 2025, v2 era, a different shell stack**; no 4.x equivalent [V-SELF, stale]. Boot time [NF]. Installed disk size [NF]. Minimum requirements [NF]. **No independent benchmark of Omarchy 4 exists anywhere.** Counter-evidence: issue #2435, the old Walker launcher leaking past 1.2 GB. | Idle RAM **1004 MB mean / 1005 MB max** on the exact native Apple-HVF ARM64 candidate `cf522b…d19133`, measured in-guest over five minutes after ten minutes of stabilization by the published canonical method. This meets Punar's unchanged 1024 MB clean-VM target, down from the comparable 1210/1213 MB ARM64 baseline. Four services total **24 MB PSS** against a 100 MB target; maximum first-party CPU **0.01%** and first-party writes **73,728 B / 5 min** are enforced; desktop marker **16 s**. The renderer reduction is explicitly VM-only and real-GPU paths clear it. No Raspberry Pi or bare-metal performance baseline exists. | **PUNAR LEADS on the measured VM number and evidence quality.** Omarchy's only whole-system number is self-reported and stale, so this is not an independent same-hardware benchmark. **PUNAR LEADS on measured control-plane footprint.** | Clean-VM target closed. The remaining gap is physical evidence: repeat the canonical method on representative x86 hardware and Raspberry Pi/ARM hardware, then compare on the same machine. |
| 8 | **Update and rollback** | Three-tier packaging: own pacman repo, an "Omarchy Arch Mirror" held **one month behind** upstream Arch to catch breakage, optional AUR. Four channels (Stable/RC/Edge/Dev). `pacman -Syu` is **deliberately blocked** so users cannot bypass config migrations; updates run through `omarchy update`. Automatic snapshot before every update, selectable from the Limine bootloader by date/version [V]. Stated limits: **root only, never /home**; `~/.config` untouched, so a rollback can leave new config formats against old binaries; **Limine-only** (no GRUB/systemd-boot); no documented retention policy [V]. | **NOT MET, and unowned for the entire project.** `punarctl update status` is a stub whose text says so out loud, and a unit test pins the sentence. No snapshot has ever been taken; no rollback has ever been performed. ADR-003 (accepted 2026-08-25) chose **A/B root slots with per-slot UKIs**, superseding ADR-001's btrfs+snapper — a design that is strictly better than Omarchy's on the two failure modes that matter (it can restore the ESP, and it works when userspace never comes up, because the firmware selects the slot). **No code exists.** Note a live doc defect: milestone-13.md §8 still designs the superseded snapper mechanism. | **OMARCHY LEADS** today, decisively — a shallow rollback that exists beats a deep one that does not. Punar's *design* is better on the merits. | Real: 4–6 weeks for the A/B mechanism, plus a human second-boot runbook step that `tools/boot-test.sh` structurally cannot perform (it boots the VM once). The signing half is user-blocked item 7. |
| 9 | **Security posture** | Shipped defaults are strong: LUKS FDE is the install default, ufw on with all inbound blocked except 53317, SSH off until enabled with rate limiting, ufw-docker so containers can't punch through, fingerprint PAM for lock/polkit/sudo, FIDO2, GPG-signed ISOs, a named security team, security@ address and disclosure policy [V]. Three material weaknesses, all primary-sourced: **Secure Boot is explicitly unsupported** — you must disable it to install; **`SigLevel = Optional TrustAll` on Omarchy's own repo** while Arch's repos get `Required` — so the shell, installer glue, themes and CLI are not signature-verified, with integrity resting on TLS; and **plugins run as arbitrary unsandboxed code inside the long-lived shell process**, stated as a property to manage by trust. v4.0.1, eleven days after 4.0.0, fixed ~11 named injection classes including agents launched in **full permission bypass** and users placed in the **docker group** by default [V]. | Structural posture is the strongest thing in the repository. **No generic privileged root-shell RPC** — `system.exec` and `shell.run` are rejected `unknown_method` against punard's closed typed method table, proven as a negative assertion in CI (DoD 26, PROVEN IN CI). `SO_PEERCRED` peer admission; root-only mutations; every mutation and every denial appended to a schema-conformant audit log. M9's approval gate: an agent-originated typed call returns `approval_required` with **nothing applied**; an AI agent may resolve **nothing**, refused by kernel-attested cgroup placement and audited; a credential leaves the broker **once, on a file descriptor**, and only `sha256(token)` is retained so no method can return it twice. **But:** Secure Boot and TPM are **SIMULATED** (user-blocked 1 and 2); there is **no release signing at all** (user-blocked 7); no LUKS in any image because there is no installer; M9's entire in-VM proof — including the headline redaction sweep — has **never executed**; and there has been **no independent security review** (user-blocked 9). | **OMARCHY LEADS today**, because a shipped LUKS default and a real disclosure process beat an unshipped architecture. **PUNAR LEADS structurally**, and by a wide margin. | Moderate and mostly gated: LUKS ships with the installer (axis 1); Secure Boot needs a key decision with weeks-to-months lead time (start now); the M9 proof needs one CI run. |
| 10 | **Privacy posture** | Not an axis Omarchy competes on and not a criticism of it: Omarchy collects nothing because Omarchy manages nothing. Its adoption figures are explicitly **bandwidth-derived, not telemetry** [V-SELF], which is itself a privacy posture. There is no ledger, no compliance sync, no fleet view — nothing to leak. | The only axis where Punar's lead is both real and already proven. M5's compliance sync is asserted **on the mock's received side** with exact category-only key allowlists — the org's own copy is checked to contain nothing more; milestone-13.md calls this the single strongest privacy assertion in the repository. M8 enforces privacy **in types**: `ResourceClass` has no `From<String>` and rejects `/`, `:`, `\`, whitespace, non-printable ASCII and a leading `.`, so a path or an argv cannot be *constructed* into a ledger record. **No eBPF, fanotify, ptrace or `LD_PRELOAD` anywhere in the tree.** No upload path in M8; user purge with a tombstone and no resurrection. Unmanaged-first is a written design law (DESIGN_LANGUAGE §8). Caveat: M8's in-VM proof has never run, and the whole managed half is asserted against `punar-mock-smplify`. | **NOT COMPARABLE in the unmanaged case** (neither phones home). **PUNAR LEADS decisively in the managed case** — which is the only case where the axis exists. | None to close. This is a lead to protect, not to build. |
| 11 | **AI capability** | Deep and shipped: 9 selectable default agents (Claude Code, Codex, OpenCode, Gemini, Copilot, Crush, Grok, Pi, Oh My Pi); a bar widget showing model plan-usage/token burn aggregated across machines via synced JSON; systemd-coredump crash handoff to an agent via a `diagnose-crash` skill; an "Omarchy skill" teaching agents the read-only vs user-editable boundary; and **Herdr**, an agent-state-aware terminal multiplexer (idle/working/blocked/done) [V]. Governance: none. Agents ran in **full permission bypass** until 4.0.1 [V]. | Governance, not ergonomics. An agent session launched by the OS gets an identity, a `punar-agent-<id>.scope` cgroup, a registry record and a panel row; attribution is **kernel-checked**, not claimed. Adapters ship as **data**, not code. An agent the OS did not launch is found and labelled `UNKNOWN · SUSPECTED` — never *certain*. All of that is **PROVEN IN CI** (74 assertions, run 32868450695). The AI Access Ledger (M8) and the approval gate + credential broker (M9) are **IMPLEMENTED — NOT YET RUN**. And the honest one: **the real `claude` binary has never run under Punar anywhere** — what is proven is the claude-code *adapter* driving `punar-mock-agent` (milestone-13.md §3.4 item 12). | **OMARCHY LEADS on shipped AI ergonomics**, and it is not close — nine agents, a usage widget and a state-aware multiplexer are real daily value. **PUNAR LEADS on AI governance architecture**, and that is not close either. | The governance lead is Punar's thesis and needs protecting (§4). The ergonomics gap is ~4–6 weeks of unglamorous surface work — and §5 argues to do two agents well, not nine. |
| 12 | **Enterprise management** | Explicit non-goal. Independent review does not recommend it for enterprise; the project agrees, and the manual sets the expectation that this is a personal machine [V]. Secure Boot must be off, which alone disqualifies it from most managed fleets. | Enroll → managed policy → category-only compliance → inventory → offline survival → unenroll → personal restore is **PROVEN IN CI**, 63 assertions, against `punar-mock-smplify` in a VM with no network. Layered policy precedence, drift classification, timer-driven auto-remediation and `policy explain` are all proven. The control plane it enrolls into **does not exist** (user-blocked 4); there is no identity provider, so enrollment binds a device, not a person (user-blocked 5). | **NOT COMPARABLE.** Omarchy is not playing. Punar is playing against a mock. | None against Omarchy. The gap is against Jamf/Intune, which is the competitor this axis actually has — see §7. |
| 13 | **Verification rigour** | 703 open / 2,394 closed issues; **629 issues opened in the last 30 days**; 878 open PRs; 448 commits in 30 days; `@omarchybot` authors merged PRs **including security fixes** — AI-authored patches landing in the security path [V]. No public test harness or CI gate documented in the research. A friendly reviewer's own advice: "if it's your only work machine, you should wait a few days" [V]. | **All 542 in-VM assertions execute and pass** (M2 33, M3 28, M4 29, M5 63, M6 55, M7 74, M8 123, M9 137), verified in run 32899132191 (commit 7943f3c, 2026-08-25) — `PUNAR_M8_OK` and `PUNAR_M9_OK` both exist. *(Corrected 2026-08-25: an earlier draft of this document, written from a stale IMPLEMENTATION_STATUS.md, claimed M8 and M9 had never run.)* Five CI jobs gate every push; a missing milestone verdict is being made a hard failure by an unpushed commit (`dc2dc47`) after a green run once claimed a milestone that had not executed — and the repository **wrote that failure down**. The DoD matrix grades its own project: 14 PROVEN (3 daggered), 4 IMPLEMENTED-NOT-RUN, 4 PLANNED, 1 HUMAN-VERIFIED-never-executed, 3 NOT MET. **Eleven of 26 items are true today without a caveat or a pending run.** | **PUNAR LEADS**, decisively, and this is the single most defensible axis in the comparison. | None to close — this is a moat to keep. But read §7.3: field evidence from 10⁵ installs is a form of testing 282 assertions cannot substitute for, and Punar has none of it. |
| 14 | **Community and momentum** | 31,171 stars, 3,171 forks, ~450 non-anonymous contributors, 63 releases since 2025-07, settled cadence 2–5/month. **Omacom Foundation launched 2026-08-21 with $8M from 8 patrons at $1M each** (Michael Dell, Patrick Collison, Tobi Lütke, Jack Dorsey, Matthew Prince, Brendan Iribe, Jason Fried, DHH), risen to $10M within days. Incubated at 37signals. Discord, meetups, patrons, merch, a named security team [V]. Governance structure [NF]. Adoption "well into the hundreds of thousands of ISO downloads" [V-SELF, bandwidth-derived — an order-of-magnitude ceiling, not telemetry]. | One private repository. One maintainer signature on all three ADRs. Zero public users. Zero external contributors. No public download. Not announced. | **OMARCHY LEADS** by three or four orders of magnitude. | **Unclosable, and should not be attempted** — see §5.1. |
| 15 | **Keyboard-first UX** | A genuine signature and consistently designed: Punar = windows/workspaces, Punar+Shift = launch, Punar+Shift+Alt = alternate variant, Punar+Ctrl = system panels, Punar+Alt = secondary; Punar+Space is a unified menu/launcher/command palette; Punar+K shows all bindings — the one key onboarding teaches. Punar+Ctrl+1..9 opens bar panels counted left-to-right, so reordering widgets renumbers with no binding rewrite [V]. And it is used daily by six figures of people. | A documented PUNAR-leader grammar that parses under the pinned Hyprland 0.56.2-1 with a non-vacuous negative control, and an in-VM exercise that drives every window operation through `hyprctl dispatch` and asserts the resulting state. And then the sentence from milestone-13.md §3.4: **"No keystroke has ever been injected anywhere in this project."** `hyprctl dispatch` proves the dispatcher; it does not traverse the bind table. The 23-step walkthrough has been the only open M1 acceptance item since 2026-08-25 and is **HUMAN-VERIFIED ONLY — never executed**. The command center is worse: its action table is two static entries, **no check script has ever opened it**, and spec §75 step 3 ("type *Open Atlas*") has no owner and no implementation (DoD item 4, **NOT MET**). | **OMARCHY LEADS** | Small in effort, large in embarrassment. A bind-table assertion against `hyprctl binds -j` plus one human hour closes DoD item 5; command-center verbs are 1–2 weeks. This is the cheapest credibility in the repository and it is unspent. |
| 16 | **Browser / web-app integration** | PWAs are conceded by critics to be "first class citizens"; Chromium is themed along with everything else by the 24-colour palette; web apps are menu-installable [V]. | M11 is now **implemented locally but not yet proven in the canonical VM gate**: upstream unpatched Chromium behind a closed launcher, root-owned typed install/uninstall records, generated and manifest icons, isolated named contexts, workspace routing, a System Control surface, and a never-enabled in-VM exercise that launches a real web-app window and inspects Chromium's live sandbox. The gate still lacks the managed enrollment/drift groups and has not produced a green x86_64 or ARM64 run, so DoD item 7 remains open. | **OMARCHY LEADS today** | The core flow exists. Remaining work is runtime stabilization, completion of managed-policy assertions, human UX review, and release-channel evidence—not another 3–5 weeks merely to create an install path. |

### 1.1 Verdict tally

| Verdict | Count | Axes |
|---|---|---|
| **OMARCHY LEADS** | 9 | 1 install, 2 hardware, 3 daily-driver, 4 polish, 5 apps, 6 docs, 8 update/rollback, 15 keyboard, 16 browser |
| **OMARCHY LEADS today / Punar leads structurally** | 1 | 9 security |
| **SPLIT** | 1 | 11 AI (ergonomics vs governance) |
| **PUNAR LEADS** | 3 | 7 performance *evidence* (parity on the number), 10 privacy, 13 verification |
| **NOT COMPARABLE** | 2 | 12 enterprise management, 10 privacy in the unmanaged case |

Read plainly: **Omarchy is better today on nine of sixteen axes, most of them by a lot,
and on every axis a user touches in the first hour.** Punar leads on three, all of which
are invisible until something goes wrong or until an organisation is attached.

---

## 2. The category argument

### 2.1 The collision is real and should not be waved away

Both products are **Arch + Hyprland + Wayland keyboard-first developer workstations with
an AI story, built by an opinionated small team, distributed as an image**. That is not a
coincidental overlap; it is the same substrate, the same compositor, the same target user's
machine, and — increasingly — the same headline feature. A person installs *one* operating
system. On axes 1–8 and 15–16 there is no category defence available: if Punar's suspend
does not work and Omarchy's mostly does, "different category" is not an answer a user will
accept.

ADR-001 records this explicitly: it evaluated Omarchy's published idle-RAM figure as the
only comparable data point on any candidate substrate. The two projects are, at the
substrate layer, siblings.

### 2.2 Where the categories genuinely diverge

Omarchy's category is **omakase** — the project says so in its own words: *"There's zero
bloat here: Just everything I use"*, package selection is explicitly one person's taste,
and it is *"not trying to be as familiar as possible… it's trying to be beautiful and
better"* [V]. Its ten stated non-goals include: not tiling-optional, Secure Boot and TPM
out of scope, ISO the only supported install path, snapshots do not protect user data,
plugins unsandboxed by design [V]. Those are not oversights; they are the shape of the
product.

Punar's category is **the governed workstation** — an OS with a control plane, where
policy has a named source, every restriction explains itself, an AI agent is a first-class
OS entity with an identity and a scope, and enrollment is additive chrome on the same
surface rather than a different product.

The axes that belong to that category and to nobody else: enterprise management (12),
privacy under management (10), approval gates and credential brokerage (9 structurally),
verification rigour as a shipped property (13), and signed staged rollout (8, once built).
Omarchy has stated non-goals on four of those five.

### 2.3 So: is "better in every way" the right goal?

**No, and stating it as the mandate is itself a risk.** Three findings:

1. **On axes 14 (community) it is arithmetically unachievable.** $10M, eight named
   patrons, 31k stars, ~450 contributors, six-figure installs. No amount of engineering
   closes that, and money spent trying is money not spent on the product.
2. **On axes 5 (apps) and 4 (theme count) it is achievable and wrong.** Both are taste
   competitions against a famous person's taste, on a thesis ("instrument, not ornament")
   that says taste-maximising is the wrong objective function. See §5.
3. **On axes 1, 2, 3, 8, 15, 16 it is not only right but mandatory** — not because Omarchy
   sets the bar, but because these are the conditions of being an operating system at all.
   Punar would need every one of them if Omarchy did not exist. The brief and the
   engineering plan happen to agree here, which is the useful part of the brief.

The reframe worth adopting: **match Omarchy where it defines table stakes, beat it where
the categories collide and we have an architectural edge (7, 9, 11-governance, 13),
concede where it is a different game (14, 5, plugin ecosystem), and never claim a lead we
have not run in a VM.** That last clause is the one thing this project already does better
than almost anyone, and it is worth more than any of the sixteen axes.

---

## 3. The table-stakes gap

Everything a person would need before they could daily-drive Punar the way people daily-drive
Omarchy. Sizing is engineering effort at current team size; "blocked on" names the real
dependency, not a nice-to-have.

| # | Item | Today | Size | Blocked on |
|---|---|---|---|---|
| 1 | **Installer + ISO output** | Does not exist. `Format=disk` dev images only. | **6–10 weeks** | Must land *after* the ADR-003 A/B slot layout — the installer partitions ESP + slot A + slot B + shared `/var`,`/home` + LUKS. Not otherwise blocked. |
| 2 | **A/B slot image layout (ADR-003)** | Accepted 2026-08-25; **zero code**. milestone-13.md §8 still designs the superseded snapper mechanism — fix that doc first. | **4–6 weeks** | Nothing. Do it **first**: it changes the root filesystem and therefore risks all 542 existing assertions, so it must be discovered early. Signing is user-blocked 7 but CI can prove the verification path with ephemeral keys. |
| 3 | **`linux-firmware` + GPU stacks** | Deliberately excluded from both images. | **1–2 weeks** to package | Validation is meaningless without user-blocked 3 (hardware). |
| 4 | **Bare-metal bring-up + hardware matrix** | Never booted on metal. Every number is emulated x86_64-on-arm64 with llvmpipe. | **8–12 weeks** elapsed, and expect worse — Omarchy has 32 open NVIDIA issues and 41 open suspend/sleep issues *with 450 contributors* | **user-blocked 3.** Buy three §5.3-class machines (2019–2022 ThinkPad / Latitude / EliteBook) **this week**. This single purchase gates six of sixteen axes. |
| 5 | **Networking (Wi-Fi + wired + a surface)** | No `NetworkManager`, no `iwd`. The CI VM runs `-nic none` by design. | **2–3 weeks** | Item 4 for real radios. The surface (bar widget + System Control page) is unblocked. |
| 6 | **Bluetooth** | No `bluez`. | **1–2 weeks** | Item 4. |
| 7 | **Audio, actually making sound** | pipewire trio installed, no audio device has ever existed. | **1 week + hardware** | Item 4. |
| 8 | **Printing** | No `cups`, no `avahi`. | **1 week** | Nothing. Unglamorous, and "daily driver" is false without it. |
| 9 | **Suspend / resume / lid / power** | Never attempted. | **3–4 weeks**, high variance | Item 4, completely. This is where hardware programmes go over. |
| 10 | **External displays, hotplug, HiDPI scaling** | Never attached. Omarchy's HiDPI 2× default drew real criticism; 4.0 answered with a unified 9–20px text-size knob — learn from that, don't repeat it. | **2–3 weeks** | Item 4. |
| 11 | **Screen share / portals** | `xdg-desktop-portal-hyprland` installed, **never exercised**. Also a RAM-diet candidate — resolve that tension before cutting it. | **1–2 weeks** | Nothing. A check script that actually opens a portal is one afternoon. |
| 12 | **Lock screen + idle + session security** | **Absent entirely.** No hyprlock, no hypridle, nothing. | **2–3 weeks** | Nothing — and see §4.6: build it **out of process**, and that decision is worth publishing. |
| 13 | **Notification daemon** | No `org.freedesktop.Notifications` implementation. milestone-13.md decision 10 **refuses** one and ships a single denial toast. | **1–2 weeks** | Nothing. **That refusal should be reversed** — it was scoped for a demo, not a daily driver. |
| 14 | **Disk encryption (LUKS2) for real** | No `cryptsetup` in any image. Omarchy has LUKS as the *install default*. | **2 weeks** | Item 1 (installer). TPM-assisted unlock is user-blocked 2. |
| 15 | **Secure Boot** | **SIMULATED.** Everything that mentions it renders `SIMULATED` in VM builds. | **2–4 weeks** of work; **weeks-to-months** of lead time | **user-blocked 1** — MOK vs Microsoft third-party CA shim. The shim path has a review process measured in months. If enterprise deployment on unmodified firmware matters, **this is the long pole and must start in month 1.** Note this is also Omarchy's largest posture gap — an axis Punar can win outright. |
| 16 | **Theming story** | One token set, no switcher, no wallpaper. | **3–4 weeks** for a switcher + a second theme | Nothing. §5.3 argues for a *bounded* version of this. |
| 17 | **Application set + an install surface** | 33 packages, no way to add more from the UI. | **1 week** packaging + **2 weeks** surface | Nothing. The surface matters more than the count. |
| 18 | **User manual** | Zero user-facing docs. Omarchy has 51 chapters. | **3–4 weeks** of writing | Correctly blocked on items 1–13 settling. Writing it now documents a product that will not exist. |
| 19 | **First boot (spec §65, Plate D-008)** | No implementation. | **2–3 weeks** | Nothing. |
| 20 | **Keyboard proof + command-center verbs** | No keystroke ever injected; command center has two static actions and no check has ever opened it. | **1 week + 1 human hour** | Nothing. **The cheapest credibility in the repository.** |
| 21 | **Idle CPU + idle disk-write gates** | Never measured. Two of four defined budgets have no measurement. | **~3 days** — both ride the existing idle window at zero extra cost | Nothing. |
| 22 | **RAM breakdown, then the diet** | 130–150 MB over target in every run; **the repository has never enumerated where the gigabyte goes.** | **1 week** to publish the breakdown; the diet is measurement-led after | Nothing. Publish the breakdown before cutting anything. |
| 23 | **Release signing + a public download** | No key, no custody decision, no host. | **2–3 weeks** once decided | **user-blocked 7 and 8** (key custody, trademark clearance, export-control read). |
| 24 | **Independent security review** | Never done. Per-milestone adversarial audit agents have found real defects (a path reaching ledger storage in M8, a hostname validation bypass in M3) — not a substitute. | External, **4–8 weeks** elapsed | **user-blocked 9.** Required before any security claim to an enterprise buyer. |

**Honest total: roughly 6–9 months of engineering to daily-driver parity**, of which about
three months is hardware-gated and cannot start until laptops exist. That number assumes
nothing goes wrong on axis 4, which it will.

---

## 4. The defensible lead

What Punar has that Omarchy could not add quickly *even if it wanted to* — and, rigorously,
what is quickly copyable and should not be counted as a moat.

### 4.1 The closed typed method table with no generic execution — **deeply defensible**

`punarctl debug rpc system.exec` and `shell.run` are both rejected `unknown_method` against
punard's closed method table, proven as a negative CI assertion (DoD 26, PROVEN IN CI).
Every administrative action is a named, typed, audited capability with an observe / apply /
verify / descriptor contract.

Omarchy's administration model is the opposite by construction: hundreds of `omarchy-*`
bash scripts unified behind one `omarchy` command [V]. The entire surface *is* generic
execution. To acquire this property they would have to replace their administration model
wholesale — and 4.0.1's fix list shows what the current model costs: USB device names
executed as Hyprland Lua, a video title becoming a Download Video play command, notification
click actions not run as safe argv [V]. **This is a multi-year architectural difference, not
a feature.**

### 4.2 Kernel-attested agent identity — **hard, and contradicts their stated model**

A managed session runs in its own `punar-agent-<id>.scope`; attribution is read from the
cgroup, not claimed by the caller; the session id is the registry's, not the caller's
claim. The rule "an AI agent may approve nothing" is enforced by cgroup placement and the
refusal is itself audited. `privilege.request` is refused for **any** agent-attributed
peer, always — an agent gets per-request approvals, never a time window.

Omarchy launches agents as ordinary user processes with the user's full privileges — and
until 4.0.1, in full permission bypass by default [V]. Retrofitting identity requires
changing every launch path *and* having a control plane to check against. **Estimate: two
to three quarters if they decided to, and it fights a stated non-goal (unsandboxed by
design).**

### 4.3 The reconciler — **very hard, and of narrow value alone**

Layered desired state with seven precedence-ranked sources, drift classification as data,
timer-driven auto-remediation proven end-to-end (destroy the nftables table, watch it come
back, with an audit event and a counter increment), and `policy explain` rendering the
precedence ladder for any path. Omarchy has **migrations**, not reconciliation — a
one-directional upgrade script, not a converging loop.

Be honest about this one: it is a genuinely different machine and would take them six-plus
months, **but most single users do not want it.** Its value is realised under management,
which means its defensibility is real and its addressable value is contingent on
user-blocked item 4 (the real Smplify control plane) existing.

### 4.4 Privacy-by-construction — **the trick is cheap, the stack is not**

`ResourceClass` with no `From<String>` is a hundred lines. Anyone could copy it in an
afternoon. **Say so plainly.** What is not copyable is the reason it matters: a privacy-safe
ledger is only meaningful if you have per-agent identity (4.2), which is only meaningful if
you have a control plane to attribute against (4.1). The moat is the stack, not the newtype.

Similarly defensible and worth stating: **no eBPF, fanotify, ptrace or `LD_PRELOAD`
anywhere in the tree.** Every ledger fact derives from a mediation point the OS already
owns. A category with no owned producer renders as `NOT YET OBSERVED · MILESTONE <n>` rather
than an empty array. Competitors reach for tracing because they lack the mediation points;
having them is architecture.

### 4.5 A/B UKI slots — **better design, and not yet a lead**

ADR-003's mechanism beats Omarchy's snapshots on the two failure modes that matter: it can
restore the ESP (Omarchy's snapshots structurally cannot — the UKI lives outside any btrfs
subvolume) and it works when userspace never comes up (snapper is a userspace tool). It
also gives health-gated blessing via systemd-boot's boot counting.

**But it does not exist.** This is a lead Punar has *decided*, not a lead Punar *has*. Do
not put it in a deck until DoD 25 says PROVEN IN CI.

### 4.6 Out-of-process lock screen — **a free, targeted, publishable win**

Omarchy's single worst live defect class is structural: bar + launcher + menu +
notifications + OSD + panels + **lock screen** + polkit agent in one long-running process
means a shell crash is a hard lockout. 20 open lock-screen issues; #6628 "session
permanently locked, reboot required"; #7106 saving a plugin file while locked strands the
session; and third-party plugins run unsandboxed *inside that same process* [V].

Punar has **no lock screen yet**, which means the architectural decision is still free.
Building it as a separate process with its own failure domain costs nothing extra now and
is a directly demonstrable superiority on the axis where Omarchy is currently hurting its
own users. Take it, and write down why.

### 4.7 Verification rigour — **culturally defensible, technically not**

542 executed in-VM assertions per push, five gating jobs, hard verdict gates, a DoD matrix
with a fixed status vocabulary and a rule that status describes the *weakest* link. Any
project could adopt this. Omarchy structurally will not: 878 open PRs, ~450 contributors,
`@omarchybot` merging security fixes, and a release cadence that peaked at 15 releases in a
month. **The moat is organisational shape, not technology** — which makes it durable for as
long as they stay that shape, and worthless the day they change it.

### 4.8 Quickly copyable — count none of these as a moat

The Field Note design language and token system (a competent designer, one to two weeks).
The keyboard grammar (Omarchy's is already better proven). The AI panel visuals. The boot
splash and greeter plates. Adapters-as-data. The unmanaged-first chrome rule. Most of
milestone-13's polish list. All good work; none of it defensible.

---

## 5. Where we should deliberately not compete

### 5.1 Community, momentum, foundation, stars

$10M and 31,171 stars against a private repository with zero public users. Every dollar
and hour spent on evangelism, meetups, merch, Discord growth or a plugin marketplace is a
dollar not spent on the six-to-nine-month engineering bill in §3. **Punar's distribution
channel is Smplify's existing enterprise relationships, not developer mindshare** — and
that channel does not require winning a popularity contest against a famous founder.
Revisit after the alpha exists, never before.

### 5.2 Application breadth

148 packages versus 33, including LibreOffice, kdenlive and OBS. Matching the count is
about a week of packaging and it is still the wrong move: Omarchy's bundle is *explicitly
one person's taste* [V], and competing on taste against a famous person's taste is
unwinnable and off-thesis. Ship a minimum coherent set plus an **install surface** (§3 item
17) and let users choose. The surface is the product; the list is not.

### 5.3 Theme count

22 themes and a live carousel is a rice competition. Punar's design language says
"**instrument, not ornament**" and lists five non-negotiables including "no colour without
meaning". Shipping 22 themes would falsify the thesis. Ship **one excellent, coherent design
language plus a documented token contract** so third parties can theme without the project
curating. If a light/dark pair and a high-contrast accessibility variant emerge, good —
that is three, and three is the ceiling.

### 5.4 A plugin ecosystem

Omarchy's plugins run unsandboxed inside the shell process, by design and by their own
documentation [V], and the actual plugin count is **[U]** — the marketplace is unaffiliated
and rendered "0 community plugins" when fetched. A plugin system directly contradicts
Punar's closed-method-table thesis until there is a sandbox story. **Defer to Phase 2, and
say why** — the reason is a differentiator, not an excuse.

### 5.5 Founder-brand marketing

Punar has no DHH, and DHH's politics are documented in the research as an adoption blocker
running in both directions across HN, Lobsters and blogs. Trying to substitute a
personality is a category error; the substitute asset is institutional trust through
Smplify. Do not build a persona.

### 5.6 Nine AI agent adapters, usage widgets, crash handoff, a multiplexer

Adapters ship as data, so adding agents is cheap and should be done as needed — but Herdr,
the token-burn widget and the crash-handoff skill are product surface that is cheaply
copyable in *both* directions and defensible in neither. **Do two agents excellently
(Claude Code plus one generic) and spend the remainder on governance**, which is the half
Omarchy structurally cannot follow into.

### 5.7 Being an omakase

Do not fight to have better default taste. Fight to have better default **guarantees**.
That is a sentence worth putting on the homepage when there is a homepage.

---

## 6. The programme

Sequenced workstreams. Each names entry criteria, evidence-of-done, and whether it is
blocked on `user-blocked.md`. The ordering rule is: **retire the risks that gate the most
other work first, and buy the long-lead items before they are needed.**

### W0 — This week. Days of work that gate months.

| Item | Entry | Evidence of done | Blocked? |
|---|---|---|---|
| **W0.1 — Push `f65c7ad` + `dc2dc47`; run M8 and M9 in-VM** | Nothing | A green run carrying `PUNAR_M8_OK` (123) and `PUNAR_M9_OK` (137) → **542 executed assertions**; the three-daemon `PUNAR_SERVICES_RSS_MB` measured for the first time; a missing verdict is a hard failure. **Until this happens, half the repository's claims are IMPLEMENTED — NOT YET RUN and cannot be said out loud.** | No |
| **W0.2 — Order three §5.3-class machines** | Money | Hardware on a desk | **user-blocked 3.** Lead time is weeks; it gates six of sixteen axes. Order before reading the rest of this document. |
| **W0.3 — Open the Secure Boot signing decision** | A decision-maker | A written MOK-vs-shim decision with an owner and a date | **user-blocked 1.** Microsoft third-party CA review runs weeks-to-months. Starting this in month 3 costs a quarter. |
| **W0.4 — Fix the two doc defects this analysis found** | Nothing | `PERFORMANCE_BUDGETS.md` §4 stops saying "not yet measured" for every row when nine CI runs have measured RAM; milestone-13.md §8 stops designing the snapper mechanism ADR-003 superseded | No. Half a day. This repository's honesty is its brand asset; stale honesty documents corrode it faster than anything else. |

### W1 — Month 1. Close the cheap proof gaps. (~20 working days, unblocked)

Entry: W0.1 green. Everything here is unblocked, small, and moves the DoD matrix from
**11 clean to ~17**.

- Bind-table assertion (`hyprctl binds -j` vs `keyboard-grammar.md`) **plus** a human who
  executes the 23-step walkthrough, dates and signs it. → DoD 5 stops saying "pending".
- Command-center real verbs (`Open Atlas`, workspace rename/go-to, layout presets) and a
  check script that actually opens the overlay. → DoD 4 leaves NOT MET.
- Land and stabilize the M11 in-VM Chromium/web-app gate on both x86_64 and ARM64, then add
  its remaining managed-policy/drift assertions. → DoD 7 stops resting on implementation
  evidence alone.
- `PUNAR_IDLE_CPU_PCT` + `PUNAR_IDLE_WRITE_KB` gates riding the existing idle window. →
  closes half of DoD 3's hole. ~3 days.
- Publish the per-process, per-cgroup PSS breakdown **before cutting anything**. The
  repository has never enumerated where the gigabyte goes; every diet candidate is
  currently a hypothesis.
- Exercise a portal (screen share) once, in CI. → resolves the tension between "portal is
  a RAM-diet candidate" and "screen share is table stakes".

Evidence of done: a DoD matrix regenerated from the run that proves it, with the counts
updated in place.

### W2 — Months 1–4. Install and update. (mostly unblocked; do the risky part first)

Entry: W1 in flight. **Order matters and is not negotiable:** the A/B layout changes the
root filesystem and therefore risks all 542 existing assertions, so it goes first, with
time left to discover a failure.

1. ADR-003 A/B slot layout in mkosi (ESP + slot A + slot B + shared `/var`,`/home`).
2. `update.status` and `update.rollback` as typed, root-only, audited methods on punard's
   closed table — the operator never types a filesystem tool (spec §1.17).
3. The in-VM demonstration: snapshot → mutate → rollback → assert the default slot changed
   and content is restored → assert the audit event carries all twelve required keys.
4. The installer, then ISO output.

Evidence of done: **DoD 25 reads PROVEN IN CI** for the mechanism, plus a dated human
runbook step for the second boot that `boot-test.sh` structurally cannot perform. Then: a
machine installed from an ISO by somebody who did not write the installer.

Blocked component: release signing (user-blocked 7). CI proves the verification path with
per-run ephemeral keys and labels custody SIMULATED; the device fails closed with an empty
trusted-key set. **That is honest and shippable to an alpha; it is not shippable to a
buyer.**

### W3 — Months 2–5. Metal. (hard-blocked on W0.2)

Entry: hardware physically present. `linux-firmware` + GPU stacks → boot on metal →
networking → Bluetooth → audio → suspend/resume → external displays → lid/power.

Evidence of done: **the per-model results table user-blocked 3 already specifies** — boot
time, idle RAM, suspend/resume, external display, Wi-Fi, audio — *published including the
models that do not work*. And the number that matters most in the whole programme: **a
bare-metal idle-RAM and boot figure that replaces every emulated number in
`PERFORMANCE_BUDGETS.md`.**

Plan for this to overrun. Omarchy, with ~450 contributors and six-figure installs, has 32
open NVIDIA issues, 41 open suspend/sleep issues, and post-Quattro reports of kernel
panics, a sluggish Panther Lake XPS 16, and Framework 13 freezes [V]. Punar will find the
same class of problems with a fraction of the eyes.

### W4 — Months 3–6. Daily-driver surfaces. (partly parallel to W3)

Lock screen **as a separate process with its own failure domain** (§4.6 — do this one
first, it is free and it is a publishable superiority). Then: a notification daemon
(reversing milestone-13 decision 10 — that refusal was scoped for a demo, not a daily
driver), System Control (Plate D-004), network / Bluetooth / audio / display surfaces,
printing, first boot (Plate D-008), a wallpaper.

Evidence of done: in-VM assertions where the VM can hold them, plus rows in the W3 hardware
matrix where it cannot.

### W5 — Months 4–7. Governance depth — the actual differentiator.

Complete M11's managed-policy/drift and browser-equivalence proof, then continue M13
(demo polish, first boot, the deterministic demo). M10 (continuous shadow-AI detection +
local alert + the authorized Smplify query) and M12 (network privacy prototype) already
have canonical in-VM evidence. Plus the one item that has been outstanding since M7: **run
the real `claude` binary under Punar** on a networked machine with a licence, and record
the result. Today what is proven is an adapter driving `punar-mock-agent`, and every
surface says so.

Evidence of done: the M13 DoD matrix regenerated with the run ids that prove it, and the
fourteen-beat deterministic demo driven both scripted and by a human.

### W6 — Ongoing, blocked on Smplify. Name an owner and a date, or these become the launch delay.

| user-blocked | What it gates | Do now |
|---|---|---|
| 1 Secure Boot keys | Any claim of booting a locked-down enterprise laptop; **and an outright win over Omarchy, whose largest posture gap this is** | Decide MOK vs shim in month 1 |
| 2 TPM / physical hardware | Removing `SIMULATED` from boot-integrity and disk-encryption rows | Ships with W0.2 |
| 3 Hardware matrix | Six of sixteen axes | **W0.2, this week** |
| 4 Real Smplify control plane | Everything in the PUNAR-LEADS column of axes 10 and 12 | Get a date from Smplify |
| 5 IdP tenants | Enrollment binding a *person*, not just a device | Month 3 |
| 6 Private relay | §33–34 dual-hop privacy — the largest item on the list; §34 forbids the one-VPN shortcut | Decide build-vs-partner in month 4 |
| 7 Release signing + hosting | Any public download at all | Month 3, alongside W2 |
| 8 Legal / trademark / export | Public release under the name "Punar" | Start month 2; trademark searches are slow |
| 9 Independent security review | Any security claim to an enterprise buyer | Book for month 6 |

### 6.1 Honest calendar shape

- **Month 1** — M8/M9 actually run; DoD 11 clean → ~17; A/B layout underway; hardware
  arrives; signing decision open. *Nothing a user could touch.*
- **Months 2–3** — metal bring-up. **Expect this to take 1.5–2× the estimate.** This is
  where the programme's variance lives.
- **Months 4–5** — installer, update/rollback, daily-driver surfaces. **First install by
  someone who is not the author.**
- **Month 6** — an alpha a Smplify engineer can daily-drive on one supported model. **Not
  a public launch.** No manual yet, one hardware model, signing possibly still SIMULATED.
- **Months 7–12** — manual, governance depth, second and third hardware models, security
  review, real signing, public availability.
- **"Better than Omarchy on the axes that are ours"** — end of Q2 next year at the very
  earliest, and **never on axis 14.**

---

## 7. The uncomfortable section

The strongest argument that this is the wrong goal, stated without softening.

### 7.1 Omarchy is not the competitor, and measuring against it optimises the wrong scoreboard

Punar's buyer is an enterprise IT or security organisation. Omarchy's user is an individual
who chose their own operating system and is explicitly told the product is not for
enterprise, not for non-technical users, and requires Secure Boot to be **off** [V]. These
two populations barely intersect. Punar's real competitors are the incumbent stack it wants
to delete — Jamf, CrowdStrike, Zscaler layered on a Mac — and Ubuntu-or-Fedora plus Intune
or Workspace ONE. **Beating Omarchy on theme count wins zero deals and costs a quarter.**
The brief's framing is a distraction dressed as a mandate, and the honest response to a
founder is to say so.

### 7.2 "Better in every way" is a specification for arriving second on everything

Sixteen axes, one team, zero users. Omarchy wins by being one person's taste executed
fast, with $10M and 450 contributors behind it. Punar cannot win a taste race or a momentum
race. Attempting both means underinvesting in the two or three axes it could actually own —
governance, verification, privacy under management — and arriving second on all sixteen
instead of first on three. A mandate that admits no concessions produces no priorities.

### 7.3 The evidence asymmetry cuts both ways, and the direction it cuts against us is worse

Punar's verification rigour is real and Omarchy's is thin — merged AI-authored security
patches, 878 open PRs, a rewrite that shipped eleven exploitable input paths. But **629
issues in 30 days is the signature of a product being used**, not only of one being broken.
Omarchy has hundreds of thousands of installs' worth of field evidence: firmware quirks,
docking behaviour, GPU regressions, battery drain on real silicon. That is a form of testing
542 in-VM assertions cannot substitute for, and every one of those assertions runs on
emulated x86_64 with llvmpipe on an arm64 host.

Stated plainly: **Omarchy is over-shipped and under-verified. Punar is over-verified and
un-shipped.** Both are failure modes. Only one of them kills companies.

The sharpest version of the same point: this repository contains twelve milestone design
documents averaging around a thousand lines each, a Definition-of-Done matrix with a fixed
status vocabulary, three ADRs, and 542 written assertions — and **no installer, and no
machine outside CI has ever booted it.** Extraordinary discipline is also an extraordinarily
comfortable way to be busy.

### 7.4 What would have to be true for Punar to lose

1. **Hardware bring-up takes twice the estimate.** It usually does. If W3 slips two months,
   the alpha misses whatever demo window Smplify actually needs, and the programme loses its
   internal sponsor before it has an external user.
2. **The 1.0 GB result is not yet proved on real metal.** "Make existing 8–16 GB enterprise
   laptops useful again" is the product thesis and 1024 MB is its headline number. The
   clean ARM64 VM now measures 1004 MB, but its renderer optimization is deliberately
   VM-specific; the bare-metal figure could land better or worse and **nobody in this
   repository knows which.** milestone-13.md §7.3 therefore keeps physical-device
   measurement separate from the closed clean-VM item.
3. **Someone adds governance before Punar adds a product.** It is not architecturally cheap
   for Omarchy — §4.1 and §4.2 argue quarters, not weeks, and it fights two of their stated
   non-goals. But a $10M foundation, a security team hiring in public, and obvious
   commercial interest in agent governance can buy a lot of quarters. If Punar's 18-month
   architectural lead compresses to six months while Punar is still doing suspend/resume,
   the differentiator evaporates and what remains is a less mature Omarchy.
4. **Smplify's control plane never ships.** Every entry in Punar's PUNAR-LEADS column on
   axes 10 and 12 is asserted against `punar-mock-smplify` in a VM with no network. The
   protocol is the deliverable and the service is Smplify's product — which means the
   single largest source of Punar's differentiation is **outside this project's control**.
5. **Nobody actually wants a governed developer workstation.** Spec §81 Test A —
   *"if Smplify management were removed, would an engineer still choose Punar?"* — has never
   been asked of a human being, and milestone-13.md §9 states outright that it **cannot be
   settled by this milestone, by CI, or by any artifact in this repository.** If the answer
   is no, then Punar is an MDM agent with an operating system attached, Omarchy's thesis
   (make the developer love it first, everything else second) was correct, and six months of
   governance engineering was spent on the wrong half of the product. **The smallest honest
   test is five engineers, two weeks on their real work, one instrumented question — and it
   is not scheduled.** It should be, the week the alpha boots on metal.
6. **The discipline becomes the deliverable.** The most likely way this project fails is not
   a bad architectural decision. It is another six months of excellent, honest, well-gated
   milestone documents, and still no installer.

### 7.5 The one-sentence version

**Omarchy's risk is that it breaks. Punar's risk is that it never arrives — and of the two,
only one is recoverable by shipping a patch.**
