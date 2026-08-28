# Update, staged rollout and rollback: design plan

Spec authority: section 57 (update architecture — *"controlled, signed,
reversible, and measurable"*, the `Candidate → Canary → Health → 10% → 50%
→ 100%` stage ladder, and the endpoint that *"exposes current version,
desired version, channel, health, and rollback state"*), 58 (browser
emergency security updates must not wait for a full OS release), 55
(offline behavior: cached policy, queued audit, credentials still expire),
8.1 (*"controlled package/update channels; reproducible build/image
strategy; rollback/snapshot strategy; signed release artifacts; enterprise
update assignments; declarative control surface"*), 38 (`DeviceDesiredState`
carries `spec.update.channel`), 39 (state sources and precedence), 42
(reconciliation), 44.1 (UEFI, Secure Boot, signed boot artifacts, TPM),
45 (security through native OS primitives), 5.1 (minimum target hardware:
8 GB RAM, **128 GB SSD**), 6 (performance budgets are acceptance criteria),
59.6 (supply chain: pinned dependencies, signed artifacts, reproducible
builds where possible, SBOM and provenance *future*), 60 (hard safety
constraints — no generic privileged execution), 66 (installation MVP),
73 (the explainability voice), 74.3/74.4 (VM and security tests),
**80 item 25** (*"demonstrate rollback/update mechanism appropriate to
chosen substrate"*), 1.22 (treat unsupported claims honestly), 1.17 (do not
rely on the terminal for ordinary OS administration).

Binding prior contracts, not relitigated here:

- [`ADR-001`](../architecture/adr/ADR-001-distribution-substrate.md) —
  accepted: minimal Arch payload, vendor-pinned ALA snapshot channels,
  mkosi-built images in CI, signed release artifacts, enterprise update
  assignments, **btrfs + snapper for the MVP** with an **A/B image
  trajectory** (Option D.2) and bootc's OCI model as the design benchmark
  for the spec 57 control plane (Option D.4).
- [`docs/api/ipc.md`](../api/ipc.md) §1–§16 — transport, framing, envelope,
  the closed method table, the nine-plus error codes, and the twelve-key
  audit contract. **This document changes none of it**; every addition below
  is a *proposal* in §8, for the owner of `ipc.md` to land.
- [`milestone-3.md`](milestone-3.md) / [`milestone-4.md`](milestone-4.md) —
  the typed capability registry, the layered state store
  (OS defaults → `policy.d` org layers → `preferences.json`), the section 42
  reconcile chain (observe → normalize → load → diff → policy → plan →
  apply → verify → audit → compliance), and the
  `punard-reconcile.timer` drift trigger.
- [`milestone-9.md`](milestone-9.md) §5 — the AI authority path that runs
  **before** the uid check for agent-attributed peers, and fails closed when
  no policy rule names the capability.
- [`milestone-11.md`](milestone-11.md) §7 — the spec 58 tension, the
  `punar-security` narrow pinned-package exception channel (**DESIGN-ONLY**),
  and the one implemented sliver: the `BROWSER` block of
  `punarctl update status`.
- [`milestone-13.md`](milestone-13.md) §3 row 25 and §8 — the Definition-of-Done
  audit that records item 25 **NOT MET**, and M13's proposed remedy.
- [`image-pipeline.md`](image-pipeline.md) — how images are actually built
  today, and its own limitation list: *"Unsigned"*, *"No rollback layout.
  Plain single-root disk (mkosi default layout)"*, *"qcow2 only"*,
  *"Reproducibility unproven"*.

**Ownership note.** This document is a design plan, not an implementation.
It writes only itself. Milestone 10 is being implemented concurrently in
`crates/`, `shell/` and `os/images`; nothing here touches those files, and
every contract addition is staged as a **proposal** (§8) for its owner to
accept, amend or reject.

---

## 0. The architectural law of this document

Eight rules. Every decision below is downstream of them.

**Law 1 — Rollback is only trustworthy if it works when userspace does
not.** The failure that actually strands a laptop is a kernel that panics,
an initrd that cannot find root, or a graphical session that never comes
up. Any rollback mechanism that requires a shell on the broken system to
run a command is a mechanism for the failures you did not need help with.
This law alone decides §3, and it is the reason this document departs from
ADR-001's MVP choice.

**Law 2 — The update unit and the reproducibility unit must be the same
object.** ADR-001's entire determinism story is *one snapshot date = one
promotable channel object*. A device-side package transaction reintroduces
per-device dependency resolution, and destroys the one question spec 57's
endpoint must answer: *what version is this machine running?* The answer
has to be a single identifier, not a package-set fingerprint.

**Law 3 — Nothing is trusted before it is verified, and verification
happens before the first byte is written to a bootable location.** Signature
first, digest second, write third, re-read fourth, make bootable last. The
ordering is the design.

**Law 4 — The unmanaged device is the default, and its update experience is
the product.** Design language §8: most devices will never enroll. A
personal Punar laptop must get staged, signed, reversible updates *with no
control plane, no account, and no telemetry*. §5.3 is not a fallback
section; it is the main case.

**Law 5 — The device never decides a rollout percentage, and it never
uploads one either.** Staging is a property of *published, signed metadata*
evaluated locally. That makes staged rollout work for unmanaged devices and
makes the check a plain fetch of a static file with no device identity in
it.

**Law 6 — Every claim in this document is labeled with what proves it.**
Signing infrastructure that does not exist is named **USER-BLOCKED**, not
assumed. Anything a VM demonstrates about Secure Boot or TPM is
**SIMULATED** (ADR-001's own consequence bullet; spec 1.22). §12 is the
table and §14 is the limits list.

**Law 7 — An update must not violate the budgets it ships.** Spec 6.3
prohibits continuous polling; 6.4 prohibits constant writes. An update
system is the single largest disk-write event the OS performs, so §10
prices it explicitly and makes it idle-scheduled, timer-driven with jitter,
and structurally absent from the measurement window.

**Law 8 — Governed rolling has two clocks.** The OS clock promotes one
complete, signed, health-gated image through a chosen channel. The developer
clock selects compilers, SDKs, AI runtimes, and services per project through
`punar-env`. A request for a newer Rust, Node, CUDA, or model runtime must not
turn into a partial base-system upgrade. This is how Punar keeps upstream
velocity without letting two machines accidentally resolve two different
operating systems under the same release name.

---

## 1. Scope

| Area | In this design | Out — and where it goes |
|---|---|---|
| The update unit | A/B root slots, per-slot UKI, shared `/var` + `/home`; the update unit is a signed root-slot image (§3) | ostree, bootc, RAUC, casync, delta transports — §13 |
| Release identity | `release.json` manifest + detached signature + per-artifact digests; `channel.json` for staging (§4) | SBOM and provenance attestation — spec 59.6 calls them future; §13 |
| Signing | The verification code path on the device, exercised with **ephemeral CI keys** (§4.4) | Real key generation and custody — **USER-BLOCKED** (§12.2) |
| Staged rollout | Locally-evaluated cohort buckets from signed channel metadata (unmanaged); control-plane assignment (managed) (§5) | The control plane that computes cohorts and gates promotion — Phase 2, mock only (§13) |
| Health | Four concrete signals reusing `PUNAR_BOOT_OK`, the punard socket, `PUNAR_DESKTOP_OK`, and the section 42 verify step (§6.2) | Fleet health aggregation, telemetry-driven promotion — Phase 2 |
| Automatic rollback | systemd-boot boot counting + `systemd-bless-boot`, gated on health (§6.3–§6.5) | A punar-owned counter (rejected, §6.3); recovery media (§13) |
| Typed surface | `update.check` / `update.apply` / `update.rollback` methods + `system.update_channel` **capability** (§7, §8) | Any generic execution method — permanently out (spec 60) |
| Browser fast lane | M11's `punar-security` overlay resolved as a *build input* producing an ordinary signed release (§9) | A runtime package updater — refused by name (§9.3) |
| Offline / failure | Interrupted download, power loss mid-apply, months offline, dead channel (§11) | Real network transport, TLS, CDN behavior — not proven (§12) |
| CI proof | A three-to-five boot in-VM exercise against a **local fixture repository on a second virtio disk** (§12) | Anything requiring network, real keys, real fleets — §12.2 |
| Sequencing | The MVP-completing slice vs. the hardening program, with a named owner each (§13) | — |

---

## 2. Decision summary

| # | Decision |
|---|---|
| 1 | **A Punar update is an A/B root-slot image swap, not a package transaction and not a filesystem snapshot.** Two root partitions with fixed, distinct PARTUUIDs; one UKI per slot on the ESP; `/var` and `/home` shared and never rolled back. §3.1–§3.3. |
| 2 | **The UKI *is* the slot selector.** Each slot's UKI embeds `root=PARTUUID=<its own slot>` in its cmdline. There is no bootloader variable, no shared pointer file, and no state that can disagree with the thing that booted. §3.3. |
| 3 | **btrfs + snapper is demoted from *the* rollback mechanism to an optional data-side convenience, and DoD item 25 does not depend on it.** On systemd-boot + UKI (what we ship) snapper cannot restore the ESP, cannot be reached when userspace does not come up, and has no boot-menu enumeration of snapshots. This is a departure from ADR-001's MVP choice and requires **ADR-003**, not an edit to ADR-001. §3.4, §12.2 item 5. |
| 4 | **This pulls ADR-001's declared A/B trajectory (Option D.2) forward into the MVP instead of building the snapper interim first.** Argued on cost, not preference: the interim is not cheaper here, it is differently shaped work that ends in the same place minus the trustworthiness. §3.4. |
| 5 | **The disk arithmetic is stated, not waved at: a second 8 GiB slot costs 6.25% of the spec 5.1 minimum 128 GB disk, and 3.1% of the 256 GB recommended target.** The full table, its inputs, and the fact that the input is an *estimate* nobody has measured, are in §3.5. |
| 6 | **Punar-owned mutable `/etc` state is a capability output, never a file the update must preserve.** A new slot boots vendor `/etc`; punard's boot reconcile makes it match the effective document. Any Punar-owned `/etc` file that is not produced by a capability is a rollback hazard and is asserted absent. §3.6. |
| 7 | **`machine-id`, the device id, users, and all Punar state live on the shared partition.** Otherwise every update silently re-identifies the device. §3.6. |
| 8 | **A release artifact is a compressed root-slot payload + its UKI + a signed `release.json` manifest.** The manifest carries version, channel, snapshot pin, overlay pin, both digests, size, build provenance, and `min_from`. §4.1. |
| 9 | **Two independent signatures, two independent purposes.** The UKI is signed with the Secure Boot vendor key and verified by *firmware*; the manifest is signed with the Punar release key and verified by *punard* before a byte is written. Neither substitutes for the other. §4.2. |
| 10 | **Verification order is fixed and is the security design: manifest signature → channel/version admissibility → streamed payload digest → post-write re-read digest → UKI install last.** §4.3. |
| 11 | **Key custody is USER-BLOCKED and is named as such.** No release key, no Secure Boot vendor key, no HSM/KMS decision, no signed UKI in the pipeline today (`image-pipeline.md`: *"Unsigned"*). CI proves the *verification path* with per-run ephemeral keys and labels custody **SIMULATED**. §4.4, §12.2. |
| 12 | **A channel is a monotonic sequence of releases and is declarative state, so it becomes a capability — `system.update_channel` — not a bespoke setting.** Org channel pinning then flows through the existing M4 merge and M5 `policy.d` envelope with zero new policy machinery, and `punarctl policy explain system.update_channel` works for free. §5.1, §8.3. |
| 13 | **Staged rollout is evaluated on the device from signed metadata, with a locally-computed cohort bucket: `bucket = SHA256(device_id ‖ version) mod 10000`, accept iff `bucket < rollout_bps`.** No enrollment, no per-device server state, nothing uploaded. §5.2. |
| 14 | **The published `channel.json` carries a `halted` flag — a kill switch that stops a bad rollout for every device, managed or not, without contacting any of them.** §5.2. |
| 15 | **For unmanaged devices, staged rollout is *exposure limiting*, not *health-gated promotion*, and the difference is stated out loud.** Without telemetry the vendor learns nothing from personal devices; the stage ladder's `Health` gate is real only for managed fleets and opt-in reporters. §5.3.3. |
| 16 | **A personal device downloads and stages automatically, and then waits.** Nothing reboots the machine, ever, without the human. Because the write lands in the *inactive* slot, "installing" is a reboot and nothing more — no progress bar between a person and their laptop. §5.3. |
| 17 | **The update check sends no device identifier.** It is a plain GET of a static, signed file; the cohort is computed locally. This is the privacy-preserving consequence of decision 13 and it belongs to the unmanaged case first. §5.3.4. |
| 18 | **Health is four concrete signals, all of which already exist:** `PUNAR_BOOT_OK` (boot completed), punard + punar-agentd answering on their sockets, `PUNAR_DESKTOP_OK` (the session came up), and a clean section-42 verify pass across the capability registry. §6.2. |
| 19 | **Boot counting is systemd-boot's own (`name+tries-left-tries-done.efi` + `systemd-bless-boot`), not a punar-owned counter.** A punar counter cannot be decremented by a kernel that panics before userspace; the bootloader's can. §6.3. |
| 20 | **The exact automatic-rollback rule: blessing is gated on health.** `punar-update-health.service` is ordered before `systemd-bless-boot.service` in the `boot-complete.target` chain. Health fails ⇒ no blessing ⇒ tries-left stays decremented ⇒ after three unblessed boots systemd-boot selects the previous slot's permanently-blessed UKI. §6.4. |
| 21 | **The last-known-good UKI is never removed by an update, and the ESP is sized for three.** The "both slots bad" case is therefore reachable only by ESP corruption or deletion — for which the answer is recovery media, which **does not exist** and is named as unowned work. §6.5. |
| 22 | **Four typed methods, one new capability, no reboot method.** `update.status` (read, any peer), `update.check` / `update.apply` / `update.rollback` (root-only, audited). Rebooting is the *caller's* act (`punarctl update apply --reboot` runs `systemctl reboot` itself); punard does not grow a side-effect verb it does not need. §7.1. |
| 23 | **`update.apply` is NOT approval-gated for a human at the keyboard, and IS denied for agent-attributed peers by M9's AI authority path.** Gating your own laptop behind an approval you also grant is theatre; an agent updating or rolling back the OS unattended is exactly what M9 exists to stop. The denial cites a *named* rule (`host.system_update: deny`), not the generic no-rule text. §7.3. |
| 24 | **Rollback is never blocked on a managed device in this slice.** It is audited, and reported on the next sync. A device that cannot be recovered is worse than a device that reports a recovery. An org-side `rollbackPermitted` field is *proposed*, not implemented. §7.3. |
| 25 | **The browser fast lane is a build input, not a second transport.** M11's `punar-security` overlay produces an ordinary signed release delivered by the ordinary mechanism — same manifest, same key, same slot, same health gate, same rollback. There is no second unsigned path because there is no second path. §9.1. |
| 26 | **The honest price of decision 25 is stated: a browser-only update is still a full slot download** (~1.5–2.5 GB for a ~120 MB delta), and the vendor builds an OS-channel × security-channel matrix. Delta transport is the top hardening item. §9.2, §13.2. |
| 27 | **Offline rules follow spec 55 exactly, plus one addition: staleness is displayed, never hidden.** `update status` prints the age of the channel metadata in days. §11.3. |
| 28 | **A channel that no longer exists fails visible and changes nothing.** Never silently fall back to another channel — that is a policy change made by an error path. One transition-only audit event, the M5 `enroll.sync` precedent. §11.4. |
| 29 | **CI proves the transport against a local fixture repository on a second virtio disk, not a network and not an image-in-an-image.** The CI VM has `-nic none`; the fixture disk is the `punar-mock-smplify` precedent applied to bytes instead of a socket. §12.1. |
| 30 | **The CI exercise is a multi-boot test on a writable disk copy, which means `boot-test.sh` must drop `-snapshot` for this mode.** Today it boots once with `-snapshot` and the artifact is never written; an update that does not survive a reboot has not been demonstrated. §12.1. |
| 31 | **The forced failure is a kernel-level failure, on purpose.** The fixture release `N+2` names a root PARTUUID that does not exist, so userspace never starts and only the bootloader can save the machine. That is the strongest available proof of Law 1, and it is cheap to construct. §12.1 phase 3. |
| 32 | **The MVP-completing slice and the hardening program are separated by one question: does the assertion require infrastructure that does not exist?** The slice is layout + manifest + fixture transport + boot counting + health gate + four methods + the multi-boot proof. Everything requiring real keys, a real CDN, a real fleet, or real hardware is hardening. §13. |
| 33 | **This work is recommended as a dedicated workstream sequenced *before* M13's demo polish, not inside it** — for M13's own stated reason (its decision 9: the layout change can break every existing check, so it must land where there is time to discover that). M13's §8.4 fallback text is preserved verbatim: if it destabilizes the image, item 25 is recorded **NOT MET** and is never relabeled. §13.1. |

---

## 3. Decision 1 — what a Punar update *is*

### 3.1 The four candidates, against the substrate we actually have

The substrate is not hypothetical. `os/images/mkosi.conf` today produces a
single GPT disk image, `Format=disk`, `Bootable=yes`,
`Bootloader=systemd-boot`, a UKI, one root partition, packages from
`PUNAR_SNAPSHOT_DATE="2026/08/20"`. `image-pipeline.md` lists under
*Current limitations*: **"No rollback layout. Plain single-root disk (mkosi
default layout), not the openSUSE-style btrfs+snapper bootable-snapshot
layout ADR-001 specifies for MVP, and no A/B partitions."**

| Candidate | What it would mean here | Verdict |
|---|---|---|
| **A/B partition swap of a whole image** | A second root partition; the mkosi output *is* the payload; a UKI per slot; systemd-boot picks. Uses only primitives already in the image (spec 45). | **Chosen** (§3.2) |
| **ostree-style deployment** | A content-addressed store of many deployments on one filesystem, hardlink-shared, with `/etc` three-way merged. Atomic, space-efficient, proven. | **Rejected** — imports a whole second package/deployment model (ostree, its repo format, its `/etc` merge semantics) onto an Arch payload that has none of it, and makes the update unit a commit rather than the mkosi artifact CI already builds and signs. Violates Law 2 by inserting a second reproducibility unit. Its space efficiency is the one thing worth stealing, and delta transport (§13.2) gets most of it without the model. |
| **btrfs snapshot + package transaction** | ADR-001's stated MVP. Snapper snapshots `/` around a `pacman -Syu` from a pinned channel; rollback switches the default subvolume. | **Rejected as the rollback mechanism** (§3.4) — fails Law 1 and Law 2. Retained as an optional data-side convenience with no acceptance weight. |
| **Hybrid** | A/B for the OS; shared, non-rolled-back `/var` + `/home`; snapshots available inside `/var` for user data if the user wants them. | **This is what "A/B" means below.** The hybrid is in *what is shared*, not in *how the OS is applied* (§3.3). |

### 3.2 The decision

**A Punar update is the replacement of the inactive root slot with a
signed, versioned root-filesystem image, followed by a reboot into it.**

- Two root partitions, **slot A** and **slot B**, with fixed, literal,
  distinct PARTUUIDs defined in the repart configuration (not seed-derived —
  `mkosi.conf`'s fixed `Seed=7ad2f9bf-…` exists to make partition UUIDs
  *stable across builds*, which would make two slots built from the same
  config identical twins; the slot UUIDs must be authored, not derived).
- The populated filesystems also have distinct UUIDs and labels. Rebinding a
  release from slot A to B means changing `/etc/fstab`, the ext4 UUID, and the
  label to `PUNAR-ROOT-B`; changing only the UKI's PARTUUID leaves ambiguous
  filesystem identities for fsck and recovery tooling.
- One partition is active (mounted `/`), the other is the staging target.
- `/var` (holding `/var/lib/punar`, the audit log, the ledger, containers,
  and `/home`) is a third, shared partition. It is **not** rolled back.
- The ESP holds systemd-boot plus one UKI per *retained* release.

### 3.3 Why the UKI is the slot selector

Each slot's UKI embeds its own kernel command line, including
`root=PARTUUID=<that slot's UUID>`. Consequences, all of them good:

1. **There is no shared pointer.** No `bootloader` EFI variable, no
   `/boot/active-slot` file, nothing that can disagree with the thing that
   actually booted. The question "which slot am I on?" is answered by "which
   UKI ran", which is the same fact.
2. **Selection and rollback are the same operation.** Choosing an entry
   *is* choosing a root. systemd-boot's counting therefore counts *slots*
   without knowing what a slot is.
3. **A signed UKI covers the cmdline.** Because the cmdline is inside the
   PE image that Secure Boot verifies (spec 44.1 "signed boot artifacts"),
   an attacker cannot repoint a signed kernel at an attacker-controlled root
   by editing a loader config. This is a real security property that the
   GRUB-plus-config approach does not have, and it is one more reason the
   boot chain we already ship (systemd-boot + UKI) prefers A/B.
4. **The bootloader needs no filesystem knowledge.** systemd-boot reads the
   ESP (vfat) and nothing else. It does not need to understand btrfs
   subvolumes, which is precisely what the snapper approach would require of
   it and which it does not implement.

### 3.4 Why btrfs + snapper is demoted, argued honestly

ADR-001 chose snapper for the MVP and cited spec 80 item 25 by name while
doing so. This document disagrees with that half of ADR-001. The argument:

1. **Snapper cannot restore the ESP.** The kernel, the initrd and the
   cmdline live in the UKI on a vfat ESP, outside any btrfs subvolume. A
   root snapshot rolls back `/usr` and `/etc` but pairs them with whatever
   kernel the ESP happens to hold. The failure mode this creates —
   old userland, new kernel, or vice versa — is exactly the class of failure
   an update system exists to prevent. ADR-001's own consequence bullet
   anticipates this and commits to *"per-snapshot UKI retention on the
   ESP"*, which is A/B's ESP management arriving through the back door with
   an unbounded number of slots instead of two.
2. **Snapper needs a working userspace to roll back.** `snapper rollback`
   is a command. If the machine reaches a shell, you did not need automatic
   rollback. Law 1.
3. **systemd-boot does not enumerate btrfs snapshots.** openSUSE's
   snapshot-boot experience is a GRUB feature (`grub-btrfs`). We ship
   systemd-boot. Building snapshot enumeration for systemd-boot is *more*
   work than A/B, not less.
4. **A package transaction is not a version.** Spec 57's endpoint must
   report *current version* and *desired version*. After a
   partially-applied `pacman -Syu`, the honest answer is a package-set
   fingerprint, not a version. Law 2.
5. **The interim is not cheaper.** ADR-001 priced snapper as the cheap MVP
   step toward A/B. Concretely, the snapper path costs: a btrfs root layout
   change (the same disruptive change A/B needs), snapper config and
   cleanup policy, ESP UKI retention (A/B has this too), a device-side
   package transaction engine with a pinned mirror (A/B needs none), quota
   and space management for an unbounded snapshot set (A/B is two fixed
   slots), and a rollback path that still fails Law 1. The delta in favor of
   A/B is *one extra partition* against *an entire runtime package-updater
   plus a rollback that does not cover the boot chain*.

**What snapper is still good for, and keeps:** user data. Snapshots of
`/home` and `/var` protect against *user* mistakes, which A/B deliberately
does not (§3.3 shares those partitions on purpose — nobody wants an OS
rollback to eat three days of work). That is a genuinely useful, entirely
optional feature with **no acceptance weight in this design** and no
dependency from DoD item 25.

**Process consequence, stated plainly.** ADR-001 is Accepted and ratified.
Its own rule is *"A trigger firing means opening a new ADR, not editing this
one."* This design therefore requires **ADR-003 — Update unit and rollback
mechanism**, superseding ADR-001's MVP rollback choice while remaining
inside its declared trajectory (Option D.2) and its design benchmark
(Option D.4, bootc's model). Ratifying or rejecting that ADR is
**USER-BLOCKED** (§12.2 item 5): it is a substrate-level decision with the
same standing as ADR-001 itself, and no implementation should start until
it is decided.

### 3.5 The disk arithmetic, explicitly

**Inputs, with their evidence quality (spec 1.22):**

| Input | Value | Evidence |
|---|---|---|
| Minimum target storage | 128 GB SSD | spec 5.1 — *normative* |
| Recommended target storage | 256 GB SSD | spec 5.2 — *normative* |
| `punar-desktop` compressed qcow2 | 1.5–2.5 GB | [`milestone-1.md`](milestone-1.md) §3 — **an estimate, explicitly labeled *"estimate, not measurement"*, and never measured since** |
| Uncompressed desktop root content | ~3–5 GB (inferred) | **Inference** from the above at ~2× compression on a package-dense root. No measurement exists. |
| UKI size (kernel + initrd + cmdline) | ~60–120 MB | Typical for an Arch `linux` UKI without `linux-firmware`; **not measured in this repo** |

**The rule, so the arithmetic survives a real measurement:**

```text
slot_size = roundup_GiB( 1.5 × R_max )
```

where `R_max` is the largest uncompressed root any release on the channel is
expected to produce within one channel generation. The 1.5× headroom is for
package growth (Chromium and Mesa dominate and both grow); the roundup keeps
the partition table boring. Taking `R_max = 5 GB` from the inference above:

```text
slot_size = 8 GiB
```

**Layout on the spec 5.1 minimum (128 GB SSD):**

| Partition | Size | Rolled back? | Note |
|---|---|---|---|
| ESP (vfat) | 1 GiB | n/a | systemd-boot + **three** UKI slots (~360 MB used, sized for growth) |
| root A | 8 GiB | yes (by swapping) | |
| root B | 8 GiB | yes (by swapping) | |
| `/var` (incl. `/home`) | remainder ≈ 110 GiB | **no** | punard state, audit, ledger, containers, user data |

```text
fixed OS cost      = 1 + 8 + 8            = 17 GiB
cost of A/B itself = one extra 8 GiB slot =  8 GiB

as a fraction of the 128 GB minimum (119.2 GiB):
    fixed OS cost   17.0 / 119.2 = 14.3 %
    A/B surcharge    8.0 / 119.2 =  6.7 %

as a fraction of the 256 GB recommended target (238.4 GiB):
    A/B surcharge    8.0 / 238.4 =  3.4 %
```

**Verdict: 6.7% of the smallest disk we promise to support, in exchange for
a rollback that works with no userspace.** That is a good trade, and it is
the whole trade — there is no RAM cost (apply is streaming I/O with a
bounded buffer, §10) and no idle-CPU cost (§10).

**What the snapshot alternative costs instead:** 0 GiB at snapshot creation,
then unbounded growth proportional to divergence × retained snapshots, plus
a cleanup policy, plus btrfs quota management, plus the risk profile of a
full root filesystem on a device that cannot then be updated. A fixed 8 GiB
that can never surprise anyone is worth more than a variable 0-to-many GiB
that can.

**The download cost is the real recurring price, and it is not small:**
every update is a full compressed slot image, 1.5–2.5 GB. At a monthly
cadence that is ~2 GB/month per device. On a metered connection that is a
genuine imposition, which is why the metered-link rule (§5.3.2) and delta
transport (§13.2) are both first-class rather than nice-to-haves.

### 3.6 The consequence nobody enjoys: `/etc`, identity, and shared state

A/B means the new slot arrives with **vendor `/etc`**, not the running
system's `/etc`. There are exactly two ways to handle that, and the wrong
one is seductive.

- **Rejected: copy `/etc` from the old slot to the new one.** Non-atomic,
  order-dependent, and it silently carries forward files the new release
  intended to change. It is the mechanism that makes long-lived systems
  diverge from their own image, which is the disease the substrate decision
  was taken to avoid.
- **Chosen: Punar-owned mutable config is a capability output, and punard's
  boot reconcile reproduces it.** This is not new machinery — it is
  [`milestone-4.md`](milestone-4.md) decision 4's section-42 chain, already
  running at boot, already applying `security.firewall` from the effective
  document, already writing `/etc/hostname` and `/etc/localtime`. This
  design simply makes that property **load-bearing** and asserts it.

**The rule:** *every* file under `/etc` that Punar mutates at runtime must
be the verified output of a registry capability whose desired value lives in
`/var/lib/punar/`. A Punar-owned `/etc` file with no capability behind it is
an update-and-rollback hazard, and §12.1 asserts the set is empty (assertion
A4). M11's `/etc/chromium/policies/managed/punar-managed.json` already
satisfies this — punard writes it from effective policy — and this rule is
why that was the right shape.

**Identity and accounts must live on the shared partition, or every update
re-identifies the device:**

| Thing | Must live | Why |
|---|---|---|
| `machine-id` | provisioned to `/var`, bound into `/etc/machine-id` | Otherwise journald continuity and any machine-id-derived key breaks on every update |
| punard device id (`/var/lib/punar/device-id`) | already on `/var` | Enrollment identity survives — spec 55 *"enrollment does not silently downgrade"* |
| Enrollment token, `policy.d`, `preferences.json` | already on `/var/lib/punar` | Cached policy survives an update *and* a rollback |
| Audit log, ledger | already on `/var` | An audit trail that a rollback erases is not an audit trail |
| User accounts and home directories | `/var` (with `/home` a bind or subdirectory) | The dev image bakes user `punar` into both slots identically and therefore works *by accident*; a real device must not |

**And the hazard this creates, stated before anyone discovers it:** because
`/var` is shared and never rolled back, **rolling the OS back does not roll
punard's state back.** If release N+1 writes a state file that release N
cannot parse, a rollback produces a booting system with a daemon that cannot
read its own store. The rule that closes this:

> **N-1 compatibility rule.** Every on-disk state file punard owns carries a
> schema version. A release must read the state written by the immediately
> preceding release on its channel. A migration that cannot satisfy this
> sets `min_from` in its manifest (§4.1), which makes the update refuse to
> apply from too old a version rather than trap the device.

Assertion D6 in §12.1 proves the N→N+1 direction; the N+1→N direction is
proven by the rollback phase (group E) reading the same store.

---

## 4. Decision 2 — release identity and signing

### 4.1 What a release artifact is

Three files per release, per channel:

```text
punar-<image_id>-<version>.slot.raw.zst     the root-slot payload
punar-<image_id>-<version>.uki.efi          the UKI for that slot payload
release.json                                the manifest — the only thing signed directly
release.json.sig                            detached signature over release.json
```

`release.json` (proposed schema `schemas/update/release-manifest.json`, §8.4):

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | int | Manifest format version |
| `release_id` | string | `punar-<image_id>-<channel>-<version>` — globally unique |
| `image_id` | string | `punar-dev` / `punar-desktop` — must match the device |
| `version` | string | `YYYY.MM.DD.N`, compared component-wise as integers |
| `channel` | string | The channel this release was published to. A device refuses a manifest whose channel is not its own — a release cannot be smuggled across channels |
| `snapshot_pin` | string | The ALA date this was built from (`2026/08/20`) — ADR-001's channel object, made visible on the device |
| `overlay_pin` | object \| null | The `punar-security` overlay pin set, when present (§9) |
| `payload` | object | `{ digest_sha256, size_bytes, compression }` |
| `uki` | object | `{ digest_sha256, size_bytes }` |
| `min_from` | string \| null | Lowest version that may update *to* this release directly (§3.6, §11.3) |
| `security` | object | `{ severity: "none"\|"important"\|"critical", advisory_ids: [...] }` — drives the §5.3 tone, never an action |
| `provenance` | object | `{ git_commit, ci_run_id, builder_base_digest, source_date_epoch, built_at }` — spec 59.6 "pinned dependencies", made auditable |
| `sbom` | string \| null | Reserved. **Always `null` in this slice** — spec 59.6 calls SBOM and provenance attestation *future*, and a field that is never populated is more honest than one that is quietly omitted |

And per channel, one small file fetched far more often:

```text
channel.json        { schema_version, channel, current: <version>,
                      rollout_bps: 0..10000, halted: bool,
                      published_at, min_supported_version }
channel.json.sig
```

`channel.json` is signed by the same key and is the *only* thing a routine
check fetches. It is a few hundred bytes; the manifest and payload are
fetched only when the device has decided it wants the release.

### 4.2 Two signatures, two purposes, neither optional

| Artifact | Key | Verified by | Protects against |
|---|---|---|---|
| `release.json`, `channel.json` | **Punar release key** (ed25519, detached signature) | `punard`, before any write | A hostile or compromised distribution host serving a payload the vendor never built |
| The UKI | **Secure Boot vendor key** (`db`), PE-signed | UEFI firmware at boot (spec 44.1) | A local attacker with disk access replacing a kernel on a device that never comes back online |

They are not redundant. The manifest signature protects the *transport*; the
UKI signature protects the *device at rest*. A device that only checks the
manifest is safe from a bad mirror but not from someone with a screwdriver;
a device that only relies on Secure Boot has no idea whether the payload it
just wrote is the one the vendor published.

**Key hygiene rules, specified now so implementation has no design left:**

- The image ships a **set** of trusted release public keys at
  `/usr/share/punar/keys/release/*.pub`, not one. Rotation is: publish the
  new key in a release signed by the old key, wait one channel generation,
  then start signing with the new key. Because the key set lives *in the
  image*, a rollback also rolls back the key set — which is correct, and is
  why the overlap window must be at least one generation.
- The `punar-security` overlay key (M11 §7.2 property 3) is **a different
  key with a different holder**, and it signs *package pins consumed at
  build time*, not releases. §9.1 keeps M11's asymmetry intact.
- No key material is ever on a device. Devices hold public keys only.

### 4.3 How a device verifies, before trusting anything

The order is the design (Law 3):

```text
1. fetch channel.json + .sig        → verify signature against the pinned key set
                                      (fail ⇒ untrusted_artifact, nothing changes)
2. admissibility, all local:
     channel matches this device's system.update_channel
     halted == false
     version > current  (or explicit rollback / allow_downgrade)
     current >= min_supported_version
     cohort bucket < rollout_bps               (§5.2)
3. fetch release.json + .sig        → verify signature
     image_id matches this device
     channel matches
     current >= min_from
4. stream payload → inactive slot, hashing as it goes
     abort on digest mismatch; slot is not bootable regardless (§11.2)
5. fsync, then RE-READ the written slot from disk and hash it again
     (proves what landed, not what was sent — catches a lying storage stack)
6. verify the UKI's digest, then install it to the ESP under a temp name,
     fsync, rename into place as `punar_<version>+3-0.efi`
7. set `punar_<version>*.efi` as the default selector, so boot-counter
   decrements and the final blessing rename cannot make the default stale
```

Steps 1–5 are reversible by deleting a file. The device becomes committed at
step 6, and step 6 is the *last* step — which is what makes §11.2's
power-loss analysis short.

**Post-write verification is a re-read, not a checksum of the buffer.** This
is the same instinct as the section 42 verify step: *observe the world
again, do not trust the plan.*

### 4.4 What is real, what is simulated, what is blocked

| Piece | Status | Note |
|---|---|---|
| Manifest schema, signature verification code, digest streaming, re-read verification, key-set loading, rotation logic | **REAL** — implementable and CI-provable today | §12.1 group B |
| The release signing key used in CI | **SIMULATED** — an ephemeral ed25519 keypair generated per CI run, used to sign the fixtures, discarded | The *code path* is real; the *custody* is not |
| The production release signing key and its custody model | **USER-BLOCKED** | §12.2 item 1 |
| Secure Boot vendor keys (PK/KEK/db), `sbctl` enrollment, mkosi `uki-signed` output | **USER-BLOCKED** | `image-pipeline.md` states the pipeline is *"Unsigned. No Secure Boot, no signed UKIs, no sbctl key management yet."* §12.2 item 2 |
| Firmware actually rejecting an unsigned UKI | **NOT PROVEN** | CI's OVMF is not in Secure Boot mode with enrolled vendor keys. ADR-001: *"All VM-based SB/TPM demos are labeled simulated."* |
| Microsoft shim licensing | **USER-BLOCKED** — a business decision | ADR-001 revisit trigger 4 |

**Nothing in this document assumes a key exists.** The device-side code is
written to fail closed when the key set is empty: `update.check` returns
`untrusted_artifact` with the section-73 text *"This release could not be
verified. Punar will not install software it cannot check."* — which is the
correct behavior for an unsigned build, and is what an honest MVP ships
until §12.2 item 1 is unblocked.

---

## 5. Decision 3 — channels and staged rollout (spec 57)

### 5.1 A channel is declarative state, so it is a capability

Spec 38 already puts `spec.update.channel` in `DeviceDesiredState`, and
`schemas/desired-state/desired-state.json` already makes it **required**,
typed as an open non-empty string with a comment explaining that narrowing
it would be speculative. Nothing consumes it today.

**Proposal: add `system.update_channel` to the capability registry** (§8.3).
The observed state is read from `/var/lib/punar/update/channel`, the apply
step writes it, the verify step re-reads it. That single move buys:

- Org channel pinning through the **existing** M4 layered merge and M5
  `policy.d` envelope — no new policy code, no new precedence rules.
- `punarctl policy explain system.update_channel` for free, in the spec 40
  layout, in the section 73 voice.
- The M5 org-pinned denial text for free: a non-root `capabilities.set` on a
  channel the org pinned cites *the pinning source*, not "personal
  defaults".
- Drift detection for free: an out-of-band channel change is remediated by
  the existing `punard-reconcile.timer`.

Punar exposes three channels. They differ in **promotion evidence and
cadence**, never in integrity, atomicity, or rollback:

| Channel | Promise | Intended use |
|---|---|---|
| `stable` (default) | Longest soak; fully promoted only after the complete gate and available health evidence | Personal machines and enterprise fleets that value predictability |
| `dev` | Faster promotion after the complete gate and an initial canary window | Engineers who want current platform packages without being first |
| `edge` | Earliest promotable Punar image after the complete gate; least soak, explicitly opt-in | Contributors and engineers validating the newest base stack |

`candidate` / release-candidate is an internal promotion state, not a fourth
channel a person must choose. Even `edge` is a whole Punar release: signed
manifest, exact package set, inactive-slot write, health check, and bootloader
rollback. Punar never offers an *unsafe* channel and never performs a partial
base-system upgrade.

On a personal device, these are **the user's options**. `stable` is the
factory OS default, not a remote assignment. The user may select `dev` or
`edge`, return to `stable`, disable automatic checks, or keep checks while
disabling automatic staging. `punarctl policy explain system.update_channel`
must cite `Personal preference` after a user choice and `OS default` before
one. An organization can become the winning source only after enrollment;
there is no implicit Smplify layer on a personal machine.

The other half of freshness is deliberately outside this table. A project can
select `rust: nightly`, a newer Node line, or an AI runtime in its
`ProjectEnvironment` manifest while the host stays on `stable`. Closing or
destroying that environment releases its processes and storage under the M6
lifecycle. The OS channel is therefore not a proxy for the age of every tool
an engineer can use.

### 5.2 Staged rollout, evaluated locally (Law 5)

Spec 57's ladder is `Candidate → Canary → Health → 10% → 50% → 100%`. Read
carefully, four of those six are **control-plane states** and only one is a
device behavior:

| Stage | Who owns it | What the device does |
|---|---|---|
| Candidate | Vendor build/CI | Nothing. The release is not published to a channel yet |
| Canary | Vendor | Publishes with `rollout_bps` small (e.g. 100 = 1%) |
| Health | Vendor + managed fleet | Watches. Managed devices report; unmanaged do not (§5.3.3) |
| 10 / 50 / 100 % | Vendor | Raises `rollout_bps` in `channel.json` |
| *(halt)* | Vendor | Sets `halted: true` — decision 14 |

The device's entire contribution is one deterministic function:

```text
bucket(device_id, version) = SHA256(device_id ‖ ":" ‖ version) interpreted
                             as a big-endian u32 of the first 4 bytes,
                             mod 10000
accept iff  bucket < channel.rollout_bps  and  not channel.halted
```

Properties that make this the right choice:

- **Deterministic per device and per version.** A device does not flip in
  and out of a cohort as it re-checks.
- **Uncorrelated between versions.** Because `version` is in the hash, the
  same devices are not the canaries every single time — which is the bug in
  the naive `hash(device_id) % 100` design.
- **Requires no server state and no upload.** The vendor never learns which
  devices are in the cohort. It does not need to.
- **Works identically for managed and unmanaged devices**, which means the
  managed path is the unmanaged path plus an assignment, not a separate
  system.

Assertion B3 (§12.1) proves the distribution and the determinism on the host
with 10,000 synthetic device ids — the one part of "staged rollout" that is
genuinely, mechanically provable without a fleet.

### 5.3 The unmanaged device — the default case (Law 4)

Design language §8: *"Most devices will never enroll... the personal,
unmanaged device as the default state of every surface."* So this section
describes the product, and §5.4 describes the variant.

#### 5.3.1 The experience

The factory personal-device settings are `stable`, automatic checks on,
automatic staging on, payload downloads deferred on metered links, and
automatic reboot permanently off. They are shown and editable after login in
**System Control › System › Updates** and through the command center.
They are not another page in the account-first onboarding card. The surface
explains the three channels in the §5.1 language and shows the effective
source (`OS default`, `Personal preference`, or—only after enrollment—the
organization policy).

1. When automatic checking is enabled, a timer fires (§10:
   `OnBootSec=15min`, `OnUnitActiveSec=6h`,
   `RandomizedDelaySec=1h`). punard fetches `channel.json`, verifies it,
   evaluates the bucket. Cost: a few hundred bytes.
2. If a release is admissible, punard fetches the manifest and **streams the
   payload into the inactive slot** at idle I/O priority, resumable,
   deferring on a metered link (§5.3.2).
3. When the slot is written, verified and the UKI is installed, the device
   is *ready*. Nothing has been disrupted. The running system is untouched.
4. One calm line appears — in `punarctl update status`, in the shell
   masthead via the proposed `/run/punar/status.json` block (§8.5), and in
   System Control's SECURITY section:

   ```text
   Punar 2026.09.02.1 is ready. It applies the next time you restart.
   ```

5. That is all. **The device never reboots itself.** Ever. Not on a
   deadline, not for a critical CVE, not at 3 a.m.

Changing channel never resolves packages on the device. It invalidates cached
metadata and selects the next admissible whole release from that channel. The
currently blessed slot remains bootable throughout, including when moving
from `edge` back to `stable`.

**Why this is good rather than merely safe:** because the write landed in
the *inactive* slot, there is no install step to interrupt anyone. The
thing every desktop OS gets wrong — a progress bar between a person and
their laptop — is structurally impossible here. A/B does not just make
rollback trustworthy; it makes the update invisible until the user chooses
otherwise. This is the strongest user-facing argument for decision 1 and it
lands hardest on the unmanaged device.

#### 5.3.2 Rules that keep it calm

- **Metered links**: if NetworkManager reports the connection metered, the
  payload download defers; the metadata check (a few hundred bytes) still
  runs. `update status` says so in words.
- **Severity changes tone, never behavior.** A `critical` release renders
  the line in the alert token and names the advisory:
  *"Punar 2026.09.02.1 fixes a critical browser security issue. It applies
  the next time you restart."* It still does not act. Personal devices are
  not coerced (design language §8: absence of chrome is calm, never an
  upsell — the same discipline applies to urgency).
- **No nagging.** The line appears; it does not repeat, escalate, badge or
  modal. Discoverability is spec 12.3's job, not anxiety's.
- **The user can turn automatic checks or automatic staging off.** Turning
  checks off causes no network contact and `update status` states when the
  last signed metadata was seen. Turning only staging off still checks and
  reports availability but writes no slot until the human acts. Spec 73:
  every restriction — including a self-imposed one — states what happens,
  why, and the next step.

#### 5.3.3 The honest limit of unmanaged staging

**For an unmanaged device, staged rollout is *exposure limiting*, not
*health-gated promotion*.** The `Health` box in spec 57's ladder is a gate
that requires *signal coming back*. Unmanaged devices send nothing (§5.3.4),
so the vendor's information about a bad release on personal devices comes
from managed fleets, opt-in reporters, and people complaining — not from a
metric. What `rollout_bps` genuinely buys the unmanaged population is that a
bad release reaches 1% before 100%, and `halted` stops the rest. That is
worth a great deal. It is not the same as a health gate, and this document
does not call it one.

#### 5.3.4 What the check discloses (spec 54, 64)

The routine check is an unauthenticated GET of a static, signed file. It
carries **no device identifier, no version, no channel in a query string, no
telemetry**. The cohort is computed locally (decision 13), which is the
entire reason it can be. What is observable to the vendor or a network
observer is: an IP address fetched a file, and the URL path names a channel.

Consequences that must be stated on the privacy surface (spec 64) and in
first-boot consent (spec 65):

- This is, for a never-enrolled device, likely **the only outbound contact
  Punar makes on its own**. M12's zero-connection posture must account for
  it explicitly rather than be quietly contradicted.
- Whether an unmanaged device performs this check by default at all is a
  **product/consent decision, not an engineering one** (§12.2 item 4). The
  mechanism supports either answer; the default text is not this document's
  to write.

### 5.4 The managed device — assignment (spec 38, 49)

Everything above still runs. Two things are added:

1. **The channel is assigned**, through `spec.update.channel` in the
   `DeviceDesiredState` the org already ships (M5's `policy.d` envelope),
   landing on the `system.update_channel` capability (§5.1). A user
   preference is *recorded and overridden* per section 39, and `punarctl`
   renders M4/M5's existing "Recorded, not applied" verdict line. No new
   code path.
2. **A desired version may be pinned.** For a fleet, the vendor's
   `rollout_bps` is the wrong lever — the *org* wants to control its own
   ring. Proposed (`§8.4`, not implemented): `spec.update.pinnedVersion` and
   `spec.update.rollbackPermitted`. When `pinnedVersion` is set, the org's
   value replaces the channel's `current`, and the cohort bucket is not
   consulted — the org has taken the decision.

**Health reporting for managed devices** rides the existing M5 sync, and
inherits its privacy posture exactly: the payload is the **five fields spec
57 names and nothing else** —

```json
{"current_version": "...", "desired_version": "...", "channel": "...",
 "health": "pass|fail|unknown", "rollback_state": "..."}
```

M5's strongest privacy assertion is that the mock's *received* files are
checked against an exact key allowlist. §12.1 assertion F5 applies the same
technique here: the update report is asserted **on the received side** to
contain those five keys and no others. Spec 57's "endpoint" is thereby the
same five fields locally and remotely, which is the only way the two can be
kept honest with each other.

### 5.5 What the control plane owes, and does not exist

The stage ladder's promotion logic — cohort assignment, health aggregation,
automatic halt on a health regression, the 10/50/100 schedule — is
**Smplify-side software that does not exist** (ADR-001 said this plainly:
*"spec 57's stages are a control-plane contract... which Smplify must build
in punard regardless of substrate"*, and spec 50/77 place the real control
plane in Phase 2). `punar-mock-smplify` can serve a `channel.json` and
record a health report, which is enough to prove the *device* side of the
contract and nothing more. §12.2 marks it SIMULATED.

---

## 6. Decision 4 — health and automatic rollback

### 6.1 Rollback state, named

Five values, and `update.status` reports exactly one:

| `rollback_state` | Meaning |
|---|---|
| `none` | Only one release has ever been on this device; there is nothing to go back to |
| `available` | The other slot holds a release that previously booted and blessed |
| `pending_reboot` | A rollback has been requested and the entry re-pointed; it takes effect on reboot |
| `auto_rolled_back` | The running release is here *because* the bootloader gave up on the other slot |
| `unavailable` | A rollback target should exist but cannot be used; **`rollback_unavailable_reason` is then required** |

That last row deliberately reuses [`milestone-13.md`](milestone-13.md) §11's
contract decision: `rollback_unavailable_reason` is a **required** field
whenever rollback is not available, so an absence always carries a reason.
Continuity with the doc that owns DoD item 25 is worth more than a
prettier field name.

### 6.2 What "health" means concretely — four signals that already exist

| # | Signal | Mechanism (already shipping) | Failure means |
|---|---|---|---|
| 1 | **Boot completed** | `multi-user.target` reached; `punar-boot-marker.service` emits `PUNAR_BOOT_OK` | The system did not finish starting |
| 2 | **The control plane answers** | `punard` responds to `status` on `/run/punard/punard.sock`; `punar-agentd` responds on its sibling socket (ipc.md §1, §10.1) | Punar itself is broken on this release |
| 3 | **The graphical session came up** | the authenticated shell creates `$XDG_RUNTIME_DIR/punar/shell-ready`; the health gate verifies that `/run/user/<uid>` and the marker belong to that regular user | The user would face a black screen — the single worst update outcome |
| 4 | **Capabilities verify** | one section-42 `reconcile` pass with **no** `verify_failed` across the registry (M4 decision 4) | The new release cannot enforce the state the device is supposed to be in |

Notes that keep this honest:

- Signal 3 is **not applicable to `punar-dev`** (no graphical target). The
  health unit reads the image profile and skips inapplicable signals rather
  than failing them — and `update status` prints which signals were
  evaluated, so "PASS" never hides a skip. (`FULL` / `PARTIAL` coverage
  voice, design language §7.)
- Signal 4 is a *verify*, not a *remediate*. A health check that fixes the
  system it is judging cannot judge it.
- These four are **the same four facts the existing CI gate already waits
  for**. The health check is not new instrumentation; it is the boot gate,
  moved on-device and given an opinion.

### 6.3 Boot counting: systemd-boot's, not ours

**Decision: use systemd-boot's automatic boot assessment.** UKIs are named

```text
punar_2026.09.02.1+3-0.efi      3 tries left, 0 done
punar_2026.09.02.1+2-1.efi      after one failed attempt
punar_2026.08.25.1.efi          blessed — counter removed, permanent
```

systemd-boot decrements the counter at boot; `systemd-bless-boot.service`
removes the counter once `boot-complete.target` is reached; an entry that
reaches `+0-3` is no longer offered. This follows the Boot Loader
Specification's boot-counting contract: the absence of a counter means
"good", while zero tries left means "bad". See
<https://uapi-group.org/specifications/specs/boot_loader_specification/#boot-counting>.

`loader.conf` uses `default punar_<version>*.efi`, not the literal counted
filename. systemd-boot's `default` value is a glob; the stable selector keeps
matching the same entry as `+3-0` becomes `+2-1` and finally `.efi`.

**Why not a punar-owned counter, argued:** a counter maintained by punard
requires punard to run to be decremented. The failures that need automatic
rollback are precisely the ones where punard never runs — a panicking
kernel, an initrd that cannot find root, a corrupted `/usr`. A userspace
counter is a counter that only counts the failures you would have survived
anyway. Law 1. Additionally, spec 45 asks for security and reliability
*through native OS primitives* rather than resident agents, and this is a
textbook case: the primitive is in the bootloader we already ship.

**Tries = 3.** Two is too few (one spurious failure — a flaky disk, a
transient firmware hiccup — should not roll back a good release); five wastes
minutes of a user's life watching a machine fail to boot. Three is the
systemd default and the greenboot convention.

**Availability caveat (spec 1.22):** `systemd-bless-boot.service`,
`boot-complete.target` and `bootctl`'s counting support all ship with
systemd, but their presence and behavior in the pinned ALA snapshot
(`2026/08/20`) has **not been verified by this document** — no build has been
run. Implementation must verify it in the builder container before anything
depends on it, and the fallback (a `bootctl`-driven equivalent implemented
in the health unit) must be priced then, not assumed now.

### 6.4 The exact rule that triggers an automatic rollback

**Blessing is gated on health.** That single sentence is the mechanism.

```text
boot
 └─ systemd-boot decrements tries-left on the entry it selects
     └─ kernel + initrd + root mount           ── fails here ⇒ path A
         └─ multi-user.target                  ── fails here ⇒ path A
             └─ punar-update-health.service    ── the four §6.2 signals
                 │   Before=systemd-bless-boot.service
                 │   Requires ordering into boot-complete.target
                 │   TimeoutStartSec=180
                 ├─ PASS ⇒ boot-complete.target reached
                 │          ⇒ systemd-bless-boot strips the counter entirely
                 │          ⇒ release is permanent; the OTHER slot becomes
                 │            the rollback target; audit update.health success
                 └─ FAIL ⇒ boot-complete.target NOT reached
                            ⇒ NO blessing; tries-left stays decremented
                            ⇒ audit update.health failure (12 keys)
                            ⇒ punard emits the §73 notice and schedules a
                              reboot after a 60 s grace window
```

**Path A** (nothing reaches userspace): the counter decrements with no
userspace involvement at all. After three attempts systemd-boot stops
offering the entry and selects the previous slot's **blessed, permanently
uncounted** UKI. The machine comes back. Nobody typed anything.

**Path B** (booted, but unhealthy): punard is running, so the system can be
honest about it. The grace window exists so a person watching the screen can
cancel (`punarctl update rollback --cancel`); after three unhealthy boots
path A's counter has run out anyway and the bootloader takes over. The
symmetry is deliberate: **the userspace path is a convenience that makes the
failure faster and better-explained; the bootloader path is the guarantee.**

**One rule that prevents a nasty loop:** punard **never** auto-reboots a
system whose health failed *only* on signal 4 (capabilities verify) when
signals 1–3 passed. A machine that boots to a working desktop but cannot
apply one capability is a machine a person can use to fix the problem;
rebooting it out from under them is worse than the fault. In that case the
release is left unblessed, `update status` reports
`health: PARTIAL`, and the *next* natural reboot resolves it. This is the
one place the automatic path defers to the human, and it defers in the
direction of not destroying work.

### 6.5 When rollback itself fails

Enumerated, because "rollback failed" is not one failure:

| Failure | What happens | Mitigation |
|---|---|---|
| New slot never boots | Bootloader counts down, falls back | The design (path A) |
| New slot boots unhealthy | No blessing, counts down over subsequent boots | The design (path B) |
| **Old slot's UKI missing** | Nothing to fall back to | **An update never deletes the last-known-good UKI.** Retention is exactly two release UKIs (current + last-good); the ESP is sized for three so a write never has to delete before it succeeds. Asserted (§12.1 C3) |
| **Old slot's payload overwritten** | Fallback boots into a half-written root | Staging **always** targets the slot that is *not* last-known-good. A device with `rollback_state: none` (one release only) writes the empty slot; a device with a good pair overwrites the older of the two. Never the running one, never the blessed one |
| **ESP corrupt / vfat damage** | No entries at all | **No software answer.** The device needs recovery media, which **does not exist** — spec 66 lists a bootable ISO for the MVP and `image-pipeline.md` records *"qcow2 only. No installer ISO yet."* Named as unowned work in §13.2, not glossed |
| **Both slots exhausted** | Unreachable by construction: a blessed entry has no counter and cannot be exhausted. Reachable only via the two rows above | Same as above |
| `/var` corrupt | The OS boots; punard cannot read its store | Out of scope for OS rollback by design (§3.6). punard must start with an unreadable store and say so in the section 73 voice rather than crash-looping — an existing robustness requirement this document does not extend |

**The honest summary:** this design guarantees recovery from *a bad
release*. It does not guarantee recovery from *a damaged ESP*, and until
recovery media exists, that gap is real and named.

---

## 7. Decision 5 — the typed surface

### 7.1 Methods (proposed; the contract text is §8.1)

| Method | AuthZ | Mutating | Audited |
|---|---|---|---|
| `update.status` | any connected peer | no | no |
| `update.check` | **root only** | yes (writes cached metadata) | always |
| `update.apply` | **root only**, and agent-attributed peers take the M9 AI path first | yes | always |
| `update.rollback` | **root only**, same M9 rule | yes | always |

**There is no `update.reboot`, and that is deliberate.** `punarctl update
apply --reboot` runs `systemctl reboot` *as the caller*, after punard
returns `requires_reboot: true`. punard does not need a verb whose entire
effect is a side effect it cannot audit the completion of, and spec 60's
posture is that the method table stays as small as the job allows.
`system.exec`, `shell.run`, `update.exec` and every other generic-execution
probe continue to return `unknown_method` (§12.1 C8).

**`update.check` is mutating and audited even though it "only reads",**
because it writes verified metadata into `/var/lib/punar/update/` that later
decisions depend on, and because a check is the first observable step of an
update — an audit trail that starts at `apply` cannot explain why the device
wanted that version.

### 7.2 What `punarctl update status` prints (spec 57's five fields)

Spec 57 requires current version, desired version, channel, health, and
rollback state. All five are here, in the field-note grammar M11 §7.5
established, with M11's `BROWSER` block **preserved verbatim** — this
extends that surface, it does not replace it.

```text
PUNAR · UPDATE                                  punar-desktop · dev_9f3k2v8q1x

SYSTEM
  Current         2026.08.25.1 · slot A · blessed · booted 3 days ago
  Desired         2026.09.02.1 · staged in slot B · ready
  Channel         stable · metadata 2 h old · rollout 10% · this device is in
  Health          PASS · boot ok · services ok · session ok · capabilities verified
  Rollback        available → 2026.08.19.2 (slot B, blessed 2026-08-25)
  Next step       Restart to apply, or: sudo punarctl update apply --reboot

BROWSER
  Engine          chromium 151.0.7922.169-1
  Channel         snapshot (2026/08/20)
  Pin source      release 2026.08.25.1 · snapshot_pin
  Pin age         5 days
  Security channel  not configured — browser updates currently ride the OS
                    snapshot pin (SPEC 58 · design: this document section 9)
```

Three states worth drawing, because they are where honesty lives:

```text
  Rollback        unavailable — no previous release has booted on this device
```
```text
  Health          PARTIAL · boot ok · services ok · session ok
                  capabilities: security.firewall did not verify
                  This release has not been marked good. It will be
                  reconsidered on the next restart.
                  Next step: sudo punarctl reconcile
```
```text
  Channel         stable · metadata 94 days old · this device has been offline
  Desired         unknown — the update source has not been reachable since
                  2026-05-23. Your current release is unaffected.
```

Every one of those follows spec 73: what happened, why, which policy, whether
the user can change it, what the next step is. No `EPERM`.

### 7.3 Approval, and who is the authority

**Decision 23, argued.**

- **Human at the keyboard, root, unmanaged device: not gated.** M9's own
  rule (§5.1) is that *the agent raises an approval, the human does not*.
  An approval gate on a personal device is a dialog the user grants to
  themselves — it teaches people to click through gates, which is the
  opposite of what M9 is for. `sudo punarctl update apply` runs.
- **Agent-attributed peer: denied, fail closed, by the existing M9 path.**
  M9 §5.1 step 2 runs the AI authority path *before* the uid check
  precisely so root-ness cannot bypass AI policy (spec 60). Today no
  capability maps to an update token, so the generic *"No AI authority rule
  covers …"* denial fires. **Proposal:** add `host.system_update: deny` to
  `usr/share/punar/policy/ai-defaults.yaml` so the denial cites a named
  rule. An explicit `deny` is more honest than a fail-closed silence: it
  says *someone decided this*, which is exactly what spec 73 asks a
  restriction to answer. This is a policy-document proposal; it changes no
  M9 code.
- **Managed device, off-channel version:** `update.apply --version X` where
  X is not on the org's channel is a **policy** denial, not an authz one,
  and it uses M5's org-pinned denial text citing the pinning source.
- **Rollback on a managed device: allowed** (decision 24). Audited, and
  carried in the M5 audit queue to the next sync. The org can *see* it. The
  org cannot, in this slice, *prevent* it — because a device an
  administrator has locked out of its own recovery path is a device that
  becomes a support ticket and a landfill entry. `rollbackPermitted` is
  proposed (§8.4) so the decision can be made deliberately later, by a
  person, rather than defaulted into now.
- **The section 60 line:** none of these methods can disable Secure Boot,
  disable encryption, disable audit, or change trusted control-plane keys.
  Notably, **the release key set is inside the image**, so changing trusted
  keys requires shipping a release signed by the current key — the one thing
  spec 60 names that this design touches, and it is closed by construction.

### 7.4 Audit events

All events carry the twelve required keys of
`schemas/audit/audit-event.json`; **no schema change is required** — the
`action` pattern is dotted lowercase and `result` is an open string by
design (ipc.md §6).

| `action` | `resource` | `source` / `user_id` | `result` values |
|---|---|---|---|
| `update.check` | `update_channel` | human/root, or service/punard for the timer | `success`, `noop`, `unreachable`, `failure` |
| `update.apply` | `system_image` | human/root | `success`, `denied`, `failure`, `noop` |
| `update.rollback` | `system_image` | human/root | `success`, `denied`, `failure` |
| `update.health` | `system_image` | **service / punard** | `success`, `failure`, `partial` |
| `update.auto_rollback` | `system_image` | **service / punard** | `success` |
| `capabilities.set` | `system.update_channel` | existing path, unchanged | existing values |

`update.auto_rollback` is emitted by the *recovered* system on its first
boot after the bootloader gave up on the other slot, reconstructed from the
ESP counter state — because the system that failed could not write an audit
event about its own failure. That reconstruction is a *fact about the ESP*,
not an inference, and the event records which slot and which version. The
inherited limit from ipc.md §6 applies: punard sees peer credentials, so a
timer-driven check arrives as `user_id: "root"`, `source: "human"`, and no
spoofable "I am the timer" flag is added.

`update.status` is a read method and is **not** audited, consistent with
every other read on the table.

---

## 8. Proposed contract additions

Everything in this section is a **proposal** for the owners of `ipc.md`,
`schemas/`, and the capability registry. Nothing here is written by this
document into their files.

### 8.1 Method table additions (proposed for `ipc.md` §5)

```text
update.status    any connected peer   no   no
update.check     root only            yes  always
update.apply     root only (+M9)      yes  always
update.rollback  root only (+M9)      yes  always
```

**`update.status`** — params `{}`. Result:

```json
{
  "v": 1,
  "image_id": "punar-desktop",
  "current": { "version": "2026.08.25.1", "slot": "a", "blessed": true,
               "booted_at": "2026-08-22T09:14:03Z", "snapshot_pin": "2026/08/20" },
  "desired": { "version": "2026.09.02.1", "slot": "b", "state": "staged" },
  "channel": { "name": "stable", "source": "personal-preference",
               "policy_ids": ["personal-defaults"],
               "metadata_age_seconds": 7200, "rollout_bps": 1000,
               "in_cohort": true, "halted": false, "reachable": true },
  "health":  { "state": "pass",
               "signals": { "boot": "pass", "services": "pass",
                            "session": "pass", "capabilities": "pass" },
               "evaluated_at": "2026-08-22T09:15:41Z" },
  "rollback": { "state": "available", "target_version": "2026.08.19.2",
                "target_slot": "b", "rollback_unavailable_reason": null },
  "browser": { "...": "M11 section 7.5 block, unchanged" }
}
```

**`update.check`** — params `{ "force": bool }`. Result
`{ v, channel, current, available: <version|null>, in_cohort, halted,
   admissible: bool, reason: <string|null> }`. Errors:
`upstream_unreachable` (reused from M5), `untrusted_artifact` (new, §8.2).

**`update.apply`** — params
`{ "version": "2026.09.02.1", "allow_downgrade": false }`. Result
`{ v, staged_version, staged_slot, requires_reboot: true,
   bytes_written, verified: true }`. Errors: `denied`, `invalid_params`,
`untrusted_artifact`, `insufficient_space`, `apply_failed`,
`verify_failed`, `upstream_unreachable`, `approval_required` (only on the
M9 agent path, if a future policy sets the token to `approval_required`
rather than `deny`).

**`update.rollback`** — params `{ "to_version": "<v>" | null }` (null =
last-known-good). Result
`{ v, previous_default, new_default, requires_reboot: true }`.
Errors: `denied`, `not_found`, `conflict` (nothing to roll back to).

### 8.2 Error-code additions (proposed for `ipc.md` §4)

| `code` | Meaning | `details` |
|---|---|---|
| `untrusted_artifact` | A signature did not verify, a digest did not match, the channel or `image_id` did not match, or the key set is empty. **Never retried automatically.** Message is the section-73 text | `stage` (`manifest_signature`, `payload_digest`, `post_write_digest`, `channel_mismatch`, `no_trusted_keys`), `release_id` |
| `insufficient_space` | The inactive slot cannot hold the payload | `required_bytes`, `available_bytes` |

`untrusted_artifact` is deliberately distinct from `verify_failed` (which
means "apply succeeded but the world did not change") and from
`apply_failed` (which means "a backend step exited nonzero"). Conflating a
*trust* failure with a *mechanical* failure would make the one error a
security operator cares about invisible in the audit log.

### 8.3 Capability registry addition (proposed)

| Capability | Observed from | Applied by | Allowed states |
|---|---|---|---|
| `system.update_channel` | `/var/lib/punar/update/channel` | writing that file (and invalidating cached metadata) | `stable`, `dev`, `edge` |

Descriptor conforms to the shipped `schemas/capability/capability-descriptor.json`
unchanged. It joins `security.firewall`, `system.hostname`,
`time.timezone`; the M9 token map gains `system.update_channel →
host.system_update` alongside the action-level rule in §7.3.

### 8.4 Schema proposals

| Schema | Change | Status |
|---|---|---|
| `schemas/update/release-manifest.json` | **new** — §4.1 | Proposed |
| `schemas/update/channel-metadata.json` | **new** — §4.1 | Proposed |
| `schemas/desired-state/desired-state.json` | `spec.update.pinnedVersion` (string, optional), `spec.update.rollbackPermitted` (bool, optional) | Proposed, **not implemented in the MVP slice** (§5.4, §7.3) |
| `schemas/audit/audit-event.json` | **none** — new actions and results fit the existing patterns (ipc.md §6) | No change |
| `schemas/capability/capability-descriptor.json` | **none** — `system.update_channel` is an ordinary descriptor | No change |

Both new schemas ship with positive **and negative** fixtures, validated by
`./tools/validate-schemas.sh` in the existing `contracts` CI job — the
negatives are the point (§12.1 group B).

### 8.5 Side-contract addition (proposed for `ipc.md` §9)

`/run/punar/status.json` gains an `update` block carrying the five spec-57
fields plus `severity`, so the shell masthead and System Control can render
the §5.3.1 line **without a socket client** — M13 decision 5's pattern (the
shell performs no privileged work and gains no socket client) applied here.

---

## 9. Decision 6 — the browser fast lane (spec 58), reconciled with M11

### 9.1 The resolution: a build input, not a second transport

M11 §7.1 states the tension without softening it, and §7.2 designs the
`punar-security` overlay: a closed package allowlist committed in *this*
repo, exact `name = version = sha256` pins, **its own signing key with its
own holder**, and the asymmetry that *the overlay says which version while
the image build config says which packages*, so two independent keys must
fall for arbitrary code to ship. M11 §7.3 then names the target explicitly:
*"Under ADR-001's declared trajectory (image-based A/B), a browser-only
update is a new image whose only delta is the overlay packages — small, fast
to build, atomically activated, health-gated, and rolled back by the
bootloader. That is the target and it needs no new mechanism."*

**Decision 1 makes that target the present tense.** Therefore:

- The `punar-security` overlay stays exactly as M11 designed it — a
  **build-time** input, its own key, its own holder, its own allowlist,
  its asymmetry fully intact.
- What it produces is an **ordinary release**: same `release.json`, same
  release signing key, same payload+UKI, same slot, same health gate, same
  bootloader rollback.
- The manifest's `overlay_pin` field (§4.1) records the overlay pin set, so
  `punarctl update status` can state that a release differs from its base
  only in Chromium — the provenance M11 §7.5 already reports, now sourced
  from a signed manifest instead of a local package database.
- Speed comes from **build and validation scope**, not from a shortcut in
  trust. A browser-only release rebuilds one slot image and runs the same
  gates. Nothing about its delivery is faster or looser than a full release;
  what is faster is producing it.

**There is no second unsigned path because there is no second path.** That
was the requirement, and it is met by refusing to add a mechanism rather
than by hardening one.

### 9.2 The two honest costs

1. **A browser-only update is still a full slot download.** ~1.5–2.5 GB
   moves to change ~120 MB of Chromium. This is the single worst property of
   image-based updates and it is the strongest argument for delta transport
   (§13.2 item 1). It is not hidden behind "atomic updates are better".
2. **The vendor builds a matrix.** A device runs one image, so an org that
   wants OS ring `stable` with browser ring `canary` (M11 §7.2's example)
   needs a published cross product: `os_channels × security_channels`
   images. Keep `security_channels` at **two** (`none`, `current`) and the
   matrix stays 4×2 = 8 builds. Let it grow and the build farm becomes the
   constraint. This bound is a design rule, not an observation.

### 9.3 The alternative, named and refused

A device-side pacman transaction for Chromium only, bracketed by a snapshot,
would download 120 MB instead of 2 GB. It is refused because it creates a
second delivery path with different trust properties, different rollback
semantics, and per-device package resolution (Law 2), for the one package
most likely to be attacked. M11 §7.3 already declined to build it —
*"a runtime package updater is an update architecture, not a browser
feature"* — and this document, which **is** the update architecture,
declines it too.

---

## 10. Budgets (spec 6)

| Budget | Rule |
|---|---|
| **6.3 Idle CPU** — *"effectively 0%"*, continuous polling prohibited | The check is a systemd **timer**, `OnBootSec=15min`, `OnUnitActiveSec=6h`, `RandomizedDelaySec=1h`, `AccuracySec=15min`. No thread, no loop, no watcher. The jitter serves three purposes: idle-CPU manners, thundering-herd avoidance, and a small privacy benefit (fetch times do not fingerprint a device) |
| **6.4 Disk I/O** — *"avoid constant writes"* | The download is the largest write the OS performs, so it is `IOSchedulingClass=idle`, `IOSchedulingPriority=7`, `Nice=19`, `CPUWeight=20`, resumable, and rate-limited. It is a rare burst, never a steady state. The *metadata* check writes a few hundred bytes at most every 6 h |
| **6.2 Services RAM** — <100 MB target, 150 MB ceiling | **No new daemon.** `punard` gains a capability backend and a timer-triggered path; `PUNAR_SERVICE_UNITS` does not grow (the M11 decision-2 discipline). Apply streams with a bounded buffer (4 MiB) — an 8 GiB slot never enters RAM. A non-gating `PUNAR_UPDATE_RSS_MB` is recorded so the number exists in the record before anyone guesses it (M11 decision 24's idiom) |
| **6.1 Idle RAM** | Untouched. The update path is not resident |
| **6.5 Boot** | The health unit adds one oneshot to the boot path with `TimeoutStartSec=180`. In the healthy case it completes in milliseconds (three file/socket probes and one reconcile); it must be **ordered after** the desktop marker so it never delays first light, and it must not be a `Before=` dependency of anything the user waits for |
| **Measurement-window discipline** | The update timer is **stopped at the top of every in-VM `mN-check` and restarted at the end** — the M4/M5 precedent for `punard-reconcile.timer`, for exactly the same single-actor determinism reason. Assertion G3 proves no `update.*` audit event lands inside the idle-RAM sampling window |

---

## 11. Decision 7 — offline and failure (spec 55)

### 11.1 Interrupted download

Staging state lives in `/var/lib/punar/update/staging.json`:
`{ release_id, target_slot, expected_digest, bytes_written, started_at }`.
Resume is by offset. The whole-artifact digest is verified at the end
regardless of how many resumptions occurred — a partial is never trusted,
and a digest mismatch discards the staging state and starts over rather
than attempting a repair.

**The slot is not bootable at any point during this.** The UKI is installed
last (§4.3 step 6), so an interrupted download cannot produce a bootable
half-image. This is why the ordering is the design.

### 11.2 Power loss mid-apply

| Loss occurs at | Result |
|---|---|
| Steps 1–5 (streaming, verifying) | The old slot is untouched and still default. The device boots normally. Staging state is stale and is discarded on the next check |
| Step 6, before the UKI rename completes | The temp-named UKI is not an entry systemd-boot offers. The device boots the old slot |
| Step 6, **during** the rename | vfat is not journaled and rename atomicity is **not guaranteed**. Mitigation is retention plus counting, not atomicity: the old UKI is still present, and a UKI that fails to load causes systemd-boot to try the next entry. Stated as a real, unclosed gap rather than asserted away |
| Step 7 (setting default) | Worst case the old entry stays default; the update applies on a later reboot. Nothing is broken |

### 11.3 A device offline for months

Spec 55's rules hold unchanged: cached policy is still enforced, enrollment
does not silently downgrade, audit queues, temporary credentials still
expire. Three additions specific to updates:

- **Staleness is displayed, never hidden.** `update status` prints the age
  of the channel metadata in days and says the source has not been reachable
  since a date (§7.2's third example).
- **There is no update chain to climb.** Each release is a complete image,
  so a device six releases behind applies the *current* one directly. This
  is a real advantage of decision 1 over package-transaction updating, where
  a long-offline device faces a migration ladder.
- **`min_from` is the only thing that can require an intermediate step**,
  and it exists for the §3.6 N-1 state-compatibility rule. It is `null` for
  every release in this slice; the field exists so a future migration can
  gate honestly instead of trapping a device.

Nothing is forced. A device offline for a year comes back, checks, stages,
and shows one calm line.

### 11.4 A channel that no longer exists

**Fail visible, change nothing** (decision 28).

- `channel.json` absent or unreadable ⇒ `upstream_unreachable`; the device
  stays on its current release; **one** transition-only audit event, exactly
  the M5 `enroll.sync` precedent (a per-retry event encodes no new fact).
- `channel.json` present but signed for a different channel, or its
  `min_supported_version` exceeds the device's current version ⇒
  `untrusted_artifact` / `admissible: false` with a reason, and `update
  status` prints `CHANNEL · UNAVAILABLE`.
- **Never silently fall back to another channel.** A channel change is a
  policy change, and a policy change made by an error path is the kind of
  thing that ends up in an incident report. If the device is managed and the
  org pinned a channel that no longer exists, the message cites the org
  source and names the next step as the org's — spec 73, and M5's org-pinned
  denial voice.

---

## 12. Decision 8 — what CI can actually prove

### 12.1 The in-VM exercise

**The constraint:** the CI VM has **no network** (`-nic none`), and
`tools/boot-test.sh` today boots **once**, with `-snapshot`, so *"the
artifact is never written"*. Both facts must change for this test, and
changing them is part of the work.

**The transport fixture.** Two rejected options first: (a) embedding image
N+1 inside image N — a 2 GB payload inside a 2 GB image, not viable; (b) a
localhost HTTP server — needless, since the transport abstraction is one
trait and the fixture can be a directory. **Chosen:** the fixture repository
is a **second virtio disk** attached at boot, containing `channel.json`,
`channel.json.sig`, the manifests, the signatures and the payloads. punard's
transport uses a `file://` base URL pointing at its mount. This is the
`punar-mock-smplify` precedent — an in-VM counterparty because the VM cannot
reach a real one — applied to bytes instead of a socket, and it adds **no
new binary and no new daemon**.

**The images under test are `punar-dev`, not `punar-desktop`.** The minimal
image is small enough that N and N+1 both fit on a fixture disk, and the
first four assertions of the desktop image's health (signal 3) do not apply
to it. The desktop image's update path is proven by construction (same code,
same layout) and its multi-boot proof is named as follow-up (§13.2) — the
same honest split M13 §8.3 made about its own second boot.

**Phases:**

```text
setup   build punar-dev at version N and N+1 (N+1 = N with one marker file
        changed and a bumped version); build a deliberately broken N+2 whose
        UKI cmdline names a root PARTUUID that does not exist; generate an
        ephemeral ed25519 keypair; sign all manifests; assemble the fixture
        disk; copy image N to a WRITABLE scratch qcow2 (no -snapshot)

boot 1  N running. update status → N. update check → sees N+1. update apply
        → stages slot B, installs UKI +3-0, keeps N's blessed UKI.
        Negative cases (unsigned, tampered, wrong channel, non-root, agent).
        Guest reboots itself.

boot 2  N+1 running, blessed, healthy. Full status assertions. State written
        under N is readable. Then arm the failure: apply the broken N+2 and
        reboot.

boots   N+2 fails to mount root. Three attempts, counter 3→2→1→0, no
3–5     userspace involved at any point. systemd-boot falls back to N+1's
        blessed UKI.

boot 6  N+1 running again. update.auto_rollback in the audit log. Failed slot
        marked bad. Offline and dead-channel cases run here with the fixture
        disk detached.
```

### The assertion list

**Group A — layout and identity**

| # | Assertion |
|---|---|
| A1 | The repart configuration defines exactly two root partitions with **distinct, literal** PARTUUIDs, an ESP ≥ 1 GiB, and `/var` as the remainder — checked with `mkosi summary` on the config and `sfdisk --json` on the built image; once populated, the two roots also have distinct filesystem UUIDs and labels |
| A2 | Each slot's UKI embeds `root=PARTUUID=<its own slot>` — extracted from both UKIs' `.cmdline` sections and compared; the two must differ |
| A3 | In-VM `findmnt --json`: `/`, `/var`, `/home`, `/var/lib/punar` resolve as designed; `/var/lib/punar` is **not** on the root slot |
| A4 | **No Punar-owned mutable file under `/etc` lacks a capability behind it** — a host test over a committed list, failing on any addition (§3.6) |
| A5 | `machine-id` is stable across the N → N+1 → rollback sequence |

**Group B — release identity (host unit tests, no VM)**

| # | Assertion |
|---|---|
| B1 | A valid manifest and a valid `channel.json` validate; every negative fixture fails, in `./tools/validate-schemas.sh` |
| B2 | Signature verification **rejects**: wrong key, truncated signature, altered digest field, payload bytes not matching the digest, a manifest for a different channel, a different `image_id`, a version ≤ current without `allow_downgrade`, and an **empty key set** |
| B3 | Cohort bucket over 10,000 synthetic device ids: selection is within ±1% of `rollout_bps`; deterministic for a fixed (device_id, version); and the selected set for version X is uncorrelated with the set for version Y (so the same devices are not always canaries) |
| B4 | Version comparison is component-wise integer on `YYYY.MM.DD.N`, with fuzz cases (`2026.09.02.10 > 2026.09.02.9`) |

**Group C — apply (boot 1)**

| # | Assertion |
|---|---|
| C1 | `update status` on a fresh device: `current = N`, `rollback.state = "none"`, `rollback_unavailable_reason` **non-empty** |
| C2 | `update check` returns N+1, records `metadata_age_seconds = 0`, emits an `update.check` audit event with 12 keys |
| C3 | `update apply` writes slot B, re-reads and re-hashes it, installs `punar_<N+1>+3-0.efi`, **leaves N's UKI present**, sets the new default, returns `requires_reboot: true`; `update.apply` audited `result: "success"` |
| C4 | `update apply` from a non-root peer → `denied`, `punarctl` exit **3**, section-73 text |
| C5 | `update apply` from an **agent-attributed** peer → denied by the M9 AI authority path, citing the named `host.system_update` rule, **regardless of uid** |
| C6 | A tampered payload → `untrusted_artifact` with `stage: "payload_digest"`; slot B is **byte-identical to before** the attempt; audited `result: "failure"` |
| C7 | A truncated payload → staging discarded, no UKI installed, slot B not bootable |
| C8 | `system.exec`, `shell.run`, `update.exec` → `unknown_method` (spec 60 regression, the existing 74.4 probe extended) |

**Group D — health and success (boot 2)**

| # | Assertion |
|---|---|
| D1 | Running version is N+1; the release marker on disk agrees with `update.status.current.version` |
| D2 | `boot-complete.target` reached; the UKI on the ESP has **no** remaining tries counter (blessed) |
| D3 | `punar-update-health.service` succeeded, and its record names each of the four signals with an individual verdict (including any `skipped`) |
| D4 | `update status`: `current = N+1`, `rollback.state = "available"`, `target_version = N`, `health.state = "pass"` |
| D5 | Audit contains `update.health` `result: "success"`, `source: "service"`, `user_id: "punard"`, 12 keys |
| D6 | **State written under N is readable under N+1** — `preferences.json`, `policy.d` and the audit log survive, and `policy.effective` returns the same document as before the update |

**Group E — forced failure and automatic rollback (boots 3–6)**

| # | Assertion |
|---|---|
| E1 | Broken release N+2 stages and installs normally (the failure is at boot, not at apply — this is what makes it a *boot-chain* test) |
| E2 | The ESP's UKI filename counter decrements 3 → 2 → 1 → 0 across three attempts, with **no userspace reached** on any of them |
| E3 | On the fourth attempt the machine boots N+1 — the previously blessed entry — unattended |
| E4 | `update status` reports `rollback.state = "auto_rolled_back"` and names the version it came from |
| E5 | Audit contains `update.auto_rollback`, `source: "service"`, `user_id: "punard"`, `resource: "system_image"`, 12 keys |
| E6 | The failed release is marked bad and is **not re-offered** by `update check` until the channel publishes a different version |
| E7 | `update rollback` (the explicit method) from root on a healthy device re-points the default, returns `requires_reboot: true`, and is audited; from a non-root peer it is `denied` with exit 3 |

**Group F — offline and channel failure (boot 6, fixture disk detached)**

| # | Assertion |
|---|---|
| F1 | `update check` → `upstream_unreachable`; local state byte-unchanged; **exactly one** transition audit event across repeated attempts |
| F2 | `update status` prints metadata staleness in days and does not hide it |
| F3 | A `channel.json` naming an absent channel → `CHANNEL · UNAVAILABLE`, no version change, no silent fallback |
| F4 | Cached policy is still enforced while the update source is unreachable (spec 55 continuity, re-asserted here rather than assumed from M5) |
| F5 | **Received-side privacy:** the health report the mock control plane receives contains exactly the five spec-57 keys and nothing else — an exact `jq` key allowlist, the M5 technique |

**Group G — budgets**

| # | Assertion |
|---|---|
| G1 | `PUNAR_UPDATE_RSS_MB` is recorded (non-gating in this slice), proving the apply buffer is bounded |
| G2 | The update timer is stopped at the top of each `mN-check` and restarted at the end |
| G3 | **No `update.*` audit event falls inside the idle-RAM sampling window** |
| G4 | `PUNAR_SERVICE_UNITS` is unchanged — no new resident daemon |

### 12.2 What CI cannot prove — SIMULATED and USER-BLOCKED

| Piece | Status | Why |
|---|---|---|
| Signature **verification** code path | **PROVEN** with per-run ephemeral keys | Group B |
| Real release signing key and its **custody** | **USER-BLOCKED** | §12.2 item 1 below |
| Secure Boot chain: firmware rejecting an unsigned or wrongly-signed UKI | **NOT PROVEN / SIMULATED** | CI's OVMF is not in Secure Boot mode with enrolled vendor keys. ADR-001: *"All VM-based SB/TPM demos are labeled simulated"* |
| HTTPS transport, TLS, CDN behavior, resumption over a real link | **NOT PROVEN** | `file://` fixture only; the VM has `-nic none` |
| Staged rollout across a **real fleet** | **SIMULATED** — one device plus the group-B bucket unit tests | There is no fleet and no control plane (spec 50/77 → Phase 2) |
| Health-gated **promotion** (the vendor halting a bad rollout on evidence) | **NOT BUILT** | Control-plane software; mock can serve `halted: true`, which proves the device honors it, not that anyone decided it |
| Real hardware boot, TPM, measured boot | **NOT PROVEN** | Every number and boot this project has produced is an emulated x86_64 VM on an arm64 host |
| Delta downloads / bandwidth behavior / metered links | **NOT BUILT** | §13.2 item 1 |
| Recovery from a corrupted ESP | **NOT PROVEN — no recovery media exists** | §6.5, §13.2 item 4 |
| Desktop-image multi-boot update proof | **FOLLOW-UP** | The mechanism is proven on `punar-dev`; the desktop variant is named, not claimed (M13 §8.3's precedent) |

**The USER-BLOCKED list — decisions and assets only the user can supply.**
Items 1–3 are already carried in the project registry
[`user-blocked.md`](user-blocked.md) (its items 7, 1, and 7 respectively);
they are restated here with the update-specific detail, and the registry
remains the single index. Item 4 is specific to this design.

1. **Generate and hold the Punar release signing key** (ed25519) and decide
   custody: offline HSM, hardware token, or cloud KMS, plus rotation and
   leak response. Until this exists, every release is unsigned and the
   device correctly refuses it. → registry item 7.
2. **Generate and hold Secure Boot vendor keys** (PK/KEK/db), decide the
   enrollment story for self-install and managed fleets, and decide whether
   to pursue **Microsoft shim licensing** (ADR-001 revisit trigger 4; the
   registry notes its lead time is *"weeks-to-months"* and that it is the
   long pole). → registry item 1.
3. **Stand up the Smplify-owned snapshot mirror and the release artifact
   host.** ADR-001 already committed to both (*"Vendor infrastructure from
   day one"*); neither exists, and `snapshot.env` says so: *"until that
   mirror exists, CI pulls the ALA snapshot directly."* → registry item 7.
4. **Decide the managed reboot-deadline policy** — whether Smplify may ever
   force a reboot — *before* the desired-state schema is widened to express
   it (§5.4, §8.4).

Two former blockers are resolved: ADR-003 is Accepted (2026-08-25), and the
personal update policy is `stable` by default with user-owned `stable` /
`dev` / `edge`, checking, and staging controls. Automatic checking is an
explicitly documented outbound contact and can be disabled; automatic reboot
does not exist.

---

## 13. Decision 9 — sequencing and ownership

### 13.1 The MVP-completing slice

**The test for inclusion:** does the assertion require infrastructure that
does not exist? If no, it is in the slice. If yes, it is hardening.

DoD item 25 asks a device to *"demonstrate rollback/update mechanism
appropriate to chosen substrate."* The smallest honest demonstration is a
real update applied and a real rollback performed **automatically**, with an
audit trail that matches. That is exactly §12.1.

**In the slice:**

1. The A/B repart layout, fixed slot PARTUUIDs, shared `/var` + `/home`, and
   the `/etc`-is-a-capability-output rule with its assertion (§3).
2. `release.json` + `channel.json` schemas, fixtures (positive and
   negative), signature verification, digest streaming, post-write re-read
   (§4) — signed in CI with **ephemeral keys**.
3. The `file://` fixture transport and the fixture disk (§12.1).
4. systemd-boot boot counting, `punar-update-health.service` ordered before
   `systemd-bless-boot.service`, the four health signals (§6).
5. Four typed methods, the `system.update_channel` capability, the five
   audit actions, and `punarctl update status` printing spec 57's five
   fields while preserving M11's `BROWSER` block (§7, §8).
6. The local cohort-bucket evaluation and `halted` (§5.2) — the device half
   of staged rollout, which is the half a device can have.
7. `boot-test.sh --mode update`: writable copy, fixture disk, multi-boot,
   the assertion list.

**Ownership recommendation.** M13 currently claims DoD item 25 (its decision
8, scoped to btrfs+snapper plus two methods). This work is larger than that
and changes the disk layout every existing check runs on. M13's **own**
decision 9 gives the right rule for this situation: *"The btrfs change lands
first in the milestone order, because it is the one change that can break
every existing check."* Applying that rule honestly, the recommendation is:

> **A dedicated workstream — call it M13-U — sequenced *before* M13's demo
> polish, owning §13.1 items 1–7.** M13 then keeps the DoD row, the
> traceability matrix, and the honest `update status` fallback, and inherits
> a working mechanism instead of building a root-filesystem change during
> demo week.

M13's §8.4 fallback text carries over **verbatim and unamended**: if the
layout destabilizes the image, the honest `update status` ships, item 25 is
recorded **NOT MET** with the reason, and it is *"not relabeled, softened,
or moved to a phase that does not exist in the milestone plan."*

This is a recommendation to M13's owner. This document does not modify
`milestone-13.md`.

### 13.2 The production-hardening program

| # | Item | Owner | Why it is not in the slice |
|---|---|---|---|
| 1 | **Delta transport** (casync/desync-style, or systemd-sysupdate's future) | Phase 2 | The single largest UX and bandwidth win; needs a real artifact host to matter (§9.2) |
| 2 | **Real keys, signed UKIs, Secure Boot enrollment, shim evaluation** | Phase 2 + USER-BLOCKED | §12.2 items 1, 2 |
| 3 | **The control plane**: cohort assignment, health aggregation, automatic halt, the promotion schedule | Phase 2 (spec 50/77) | Smplify-side software; no amount of device work substitutes |
| 4 | **Recovery media** (the spec 66 bootable ISO) | Unowned — named here | The last line of defense against §6.5's ESP row; `image-pipeline.md` records *"No installer ISO yet"* |
| 5 | **dm-verity on the root slot**, and measured boot | Phase 2 (spec 44.1) | Turns "we verified it once at write time" into "the kernel verifies every block forever" |
| 6 | **Desktop-image multi-boot proof** and a second boot in the existing `desktop-test` | Follow-up | M13 §8.3's precedent: name the follow-up, do not attempt it alongside a layout change |
| 7 | **Managed reboot deadlines**, `pinnedVersion`, `rollbackPermitted` | Phase 2 + USER-BLOCKED item 7 | Schema widening should follow a product decision, not precede it |
| 8 | **SBOM and provenance attestation** | Phase 2 | Spec 59.6 calls them future; the manifest reserves the field and always sets it `null` |
| 9 | **State-migration framework** for the §3.6 N-1 rule beyond `min_from` | Phase 2 | Not needed until a release actually breaks state compatibility |
| 10 | **Evaluate `systemd-sysupdate`** as the transport | Phase 2 | See §14 item 9 — a real alternative, not used here for control-surface reasons, and worth re-pricing once the artifact host exists |

---

## 14. Honest limits

Everything this design does not do, and every place a claim would outrun the
evidence.

1. **No image has ever been built with this layout, and no boot has ever
   been performed against it.** This document is a plan. `mkosi`'s repart
   handling for a two-root layout, and the presence and behavior of
   `systemd-bless-boot` / `boot-complete.target` in ALA snapshot
   `2026/08/20`, are **stated as requirements to verify at implementation
   time**, not as verified facts (§6.3).
2. **The disk arithmetic rests on an estimate nobody has measured.** The
   1.5–2.5 GB desktop image figure is labeled *"estimate, not measurement"*
   in `milestone-1.md` and has not been measured since. §3.5 gives a *rule*
   (`1.5 × R_max`, rounded up) precisely so the arithmetic survives the first
   real number, but the 8 GiB slot size is provisional.
3. **This design contradicts an Accepted ADR.** ADR-001 chose btrfs+snapper
   for the MVP. §3.4 argues the case; it does not settle it. Until ADR-003
   is ratified, this is a proposal against a ratified decision, and the
   implementation should not start.
4. **An OS rollback does not roll back user data or Punar state**, by
   design (§3.6). The N-1 compatibility rule and `min_from` reduce the
   hazard; they do not eliminate it. A release that writes a state format
   its predecessor cannot read, and then needs to be rolled back, will land
   a working system on an unreadable store.
5. **Secure Boot is not proven and will not be proven in a VM.** ADR-001
   already committed to this labeling; nothing here improves it.
6. **Signing custody is entirely absent.** The verification path is real; a
   real key is not. A CI run signing fixtures with an ephemeral key proves
   the code, and proves nothing about whether the vendor can keep a key
   safe.
7. **Staged rollout is half-proven at best.** The bucket function is
   provable and will be proven; the stage ladder above it is control-plane
   software that does not exist. Calling the device half "staged rollout" is
   a stretch, and §5.3.3 says why.
8. **Unmanaged health is exposure limiting, not health gating** (§5.3.3).
   Without telemetry there is no signal to gate on, and this document does
   not pretend that `rollout_bps` is a substitute for one.
9. **`systemd-sysupdate` is a real alternative that is not being used, and
   the reason is control-surface ownership, not capability.** It implements
   A/B partition updating with versioned artifact naming and works with
   systemd-boot's counting. It is not adopted because spec 57 requires a
   *typed*, audited, policy-aware control surface, and driving `updatectl`
   from punard is a generic-execution shape (spec 60's neighborhood) with a
   policy model that is not ours. Its **on-disk naming conventions are
   deliberately adopted** so a future migration is cheap. This is a
   defensible call, not an obvious one, and it should be re-priced (§13.2
   item 10).
10. **vfat rename atomicity is not guaranteed** (§11.2). The mitigation is
    retention plus boot counting. There is a residual window, and it is
    named rather than closed.
11. **A corrupted ESP strands the device**, and there is no recovery media
    (§6.5, §13.2 item 4).
12. **A browser-only update still costs a full image download** (§9.2). The
    fast lane is fast to *produce*, not cheap to *deliver*.
13. **The build matrix grows multiplicatively** with OS channels × security
    channels, and the bound of two security channels is a design rule that
    nothing enforces yet.
14. **The check is an outbound connection on an otherwise silent personal
    device** (§5.3.4), which must be reconciled with M12's zero-connection
    claims and with first-boot consent, and is not this document's to
    decide.
15. **The CI proof runs on `punar-dev`, not `punar-desktop`.** Health
    signal 3 (the graphical session) is therefore exercised only by the
    existing desktop gate, not by an update. That split is the same one
    M13 §8.3 made about its second boot, and it is named for the same
    reason.
16. **`update.auto_rollback` is reconstructed after the fact** from ESP
    counter state by the recovered system, because the system that failed
    could not write its own audit event. The event is accurate about what
    the ESP says; it cannot describe *why* the boot failed.
17. **The five-field health report to a managed control plane is asserted
    against a mock**, not a cloud. M5's received-side technique is the
    strongest available form of that assertion, and it is still an
    assertion about a mock.
18. **No claim is made about update reliability at fleet scale**, because
    there is no fleet. ADR-001's revisit trigger 5 explicitly contemplates
    the A/B trajectory failing to meet spec 57's reliability bar in
    production; that trigger remains live, and this design does not retire
    it.

---

## 15. Scope-out table

| Refused / deferred | Where it goes | Why |
|---|---|---|
| ostree / bootc as the substrate transport | Not adopted | §3.1 — a second reproducibility unit on an Arch payload; ADR-001 keeps bootc as the *design benchmark*, which this design honors |
| RAUC, casync as the MVP mechanism | §13.2 item 1 | New dependencies for a job systemd primitives already do; casync's value is delta, which is a later win |
| btrfs+snapper as *the* rollback mechanism | §3.4 | Fails Law 1 and Law 2; retained as optional user-data protection with no acceptance weight |
| A runtime pacman transaction for browser-only updates | §9.3 | A second delivery path with different trust properties for the most-attacked package |
| A punar-owned boot counter | §6.3 | Cannot count the failures that need counting |
| `update.reboot` as a method | §7.1 | An unauditable side effect; the caller reboots |
| A generic `update.exec` or any privileged execution verb | Permanently out | Spec 10, 60, 82; asserted by C8 |
| Forced reboots on unmanaged devices | Permanently out | Design language §8; Law 4 |
| Uploading device identity with the update check | Permanently out | §5.3.4; decision 17 |
| Delta / bandwidth-efficient transport | §13.2 item 1 | Needs a real artifact host to be meaningful |
| dm-verity, measured boot | §13.2 item 5 | Spec 44.1 production goals |
| SBOM / provenance attestation | §13.2 item 8 | Spec 59.6 names both as future |
| A graphical update panel | Not proposed | M13 §7 already refused D-010 (*"a panel over a mechanism that is one milestone old is premature"*); this design supplies the mechanism and one calm status line, not a panel |
| A notification for a ready update | Not proposed | M13 decision 10 declines to build a notification daemon; the line lives in the masthead, System Control, and `punarctl` |

---

## 16. Definition of done for this design

This document is done when a reader can answer, with a citation, each of:

1. What is a Punar update, physically? → §3.2
2. What does it cost on the smallest disk we support? → §3.5
3. What is signed, by whom, and verified when? → §4
4. What happens on a personal laptop that has never enrolled? → §5.3
5. What exactly triggers an automatic rollback? → §6.4
6. What happens when the rollback also fails? → §6.5
7. What does `punarctl update status` print? → §7.2
8. Who has to approve an update, and who is refused? → §7.3
9. How does a browser CVE ship faster than an OS release without a second
   trust path? → §9
10. What does CI prove, and what is it forbidden from claiming? → §12
11. What is the smallest thing that honestly closes DoD item 25? → §13.1
12. What does this design *not* do? → §14

If any of those twelve has no answer, the design is incomplete — not the
implementation.
