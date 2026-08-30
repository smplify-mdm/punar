# The Punar Installer — design

**Status:** design plan · partition-layout foundation implemented 2026-08-27
**Spec authority:** §66 (installation), §65 (first-boot UX), §44.2 (disk
encryption), §44.1 (boot), §49 (enrollment chain), §48 (JIT privilege),
§5.1/§5.3 (target hardware), §12 (keyboard-first), §60 (hard safety
constraints), §61 (local IPC security), §73 (security/privacy UX voice),
§1.22 (honesty).
**Design authority:** [ADR-003](../architecture/adr/ADR-003-ab-slots-over-snapper.md)
(A/B root slots — **Accepted**), [`update-and-rollback.md`](../development/update-and-rollback.md)
(the update mechanism this installer lays the ground for),
[`execution-trust.md`](execution-trust.md) §3.3/V3 (the mount-mark
prerequisite), [`DESIGN_LANGUAGE.md`](DESIGN_LANGUAGE.md) §7/§8,
Plate **D-008** [`mockups/first-boot.html`](mockups/first-boot.html).

> **Punar has never booted on hardware, and nobody outside this repository
> has ever installed it.** The four-partition A/B layout below now builds and
> boots in a generic ARM64 VM; the installer, encryption-on-the-built-image,
> update swap and physical-device claims remain designs. The purpose here is
> still to make the first real install possible without inventing a second
> privileged path around the one this project spent thirteen milestones
> building.

---

## 0. Claim register (spec §1.22 · design language §7)

Solid lines are operating production paths. Dashed lines are mechanisms
outside the current production claim. The layout foundation is implemented;
the installer is not. The register therefore distinguishes VM image evidence
from an installation or production claim, and every row says what would make
it solid.

| # | Mechanism | Line | Standing |
|---|---|---|---|
| 01 | ISO built by the pinned mkosi pipeline, offline install, no network | *dashed* | Designed here. Solid when the `install-test` CI lane is green (§10). |
| 02 | ADR-003 partition layout created on a device | *dashed* | **Implemented and content-checked in the directly built ARM64 VM image**: I08–I11/I13's unencrypted-layout equivalents pass and the image boots. It is not an installed device and not encrypted. Solid only when the real installer lane passes I08–I13. This gives execution-trust V3 an artefact to target without claiming the installer exists. |
| 03 | LUKS2 by default, passphrase unlock | *dashed* | Designed here (§5). Solid when I12 and I19 pass. |
| 04 | **TPM-assisted unlock** | *dashed* | **SIMULATED and deliberately not enrolled.** User-blocked item 2. §5.4 argues why enrolling against a software TPM would be worse than not enrolling at all. |
| 05 | **Secure Boot / signed UKI** | *dashed* | **SIMULATED.** User-blocked item 1. The installer's live-mode gate (§7.1) is only as strong as the signature over the UKI that carries it — stated, not hidden. |
| 06 | **Release-manifest signature verification at install** | *dashed* | Mechanism designed and exercised with per-run ephemeral keys; **custody is user-blocked item 7**. Device fails closed on an empty trusted-key set. |
| 07 | Recovery key generated, shown once, never logged | *dashed* | Designed here (§5.3). Solid when I36's secrecy half passes. |
| 08 | Typed install surface, no generic root shell | *dashed* | Designed here (§7). Solid when I33–I35 pass. The *existing* negative assertion (`system.exec` → `unknown_method`) is already **PROVEN IN CI** and is extended, not replaced. |
| 09 | Dev conveniences absent from a release image | *dashed* | Designed here (§8) as **both** a profile split and a build-time assertion. Solid when the build fails on violation *and* I22–I28 pass. |
| 10 | **Hardware coverage** | *dashed* | The *report mechanism* (§9.3) is provable in QEMU. **Coverage itself is unknowable until user-blocked item 3.** No row in this document claims a machine works. |
| 11 | The installer→first-boot seam (`seed.json`, the accountless image) | *dashed* | Designed against `onboarding.md` §4.2–4.4 (§6.4). Solid when I29–I32 pass — and it is the one row whose failure mode is *silence on both sides*, which is why it gets four assertions. |
| 12 | **`onboarding.md` §1.8 Layer 2 recovery** (a fourth UKI, `punar-recover`) | *dashed* | **Does not exist.** ESP room is reserved and the artefact is not built. Recorded here because onboarding §4.4 requirement 5 asked this document to decide, and this is the decision. |
| 13 | **Bare-metal boot, USB boot, real firmware** | *dashed* | **NOT PROVEN AND NOT PROVABLE HERE.** QEMU + OVMF + virtio proves the software stack and nothing about hardware. |
| 14 | **The ISO build steps against the pinned toolchain** (comma-composed profiles, `Format=uki`, the `xorriso` hybrid idiom, `libisoburn` in the snapshot) | *dashed* | **TO VERIFY, F1–F4 in §3.6.** The builder installs `mkosi` by name, not by version, so these are properties of the snapshot and not of this document. Each has a build-script fallback. |
| 15 | **A recovery path when the freshly installed system does not come up** | *dashed*, **and absent** | §12.1. I17 requires slot B zero-filled, `punar-recover` is not built, and `onboarding.md` §1.6.2 shows that a locked root makes `punard` the only privilege path. This is the sharpest gap the three designs have between them, and §12.1 recommends the cheap half of the fix. |

---

## 1. Today's truth, stated before anything is designed on top of it

`os/images/mkosi.conf` still emits a directly bootable `Format=disk`, not an
installer ISO. Its raw disk now uses the canonical four-partition definition
set from §4.7: ESP, populated 8 GiB slot A, empty 8 GiB slot B and an
unencrypted btrfs `PUNAR-DATA` partition with separate `/var`, `/home` and
`/var/tmp` subvolume mounts. A content-aware build gate checks the GPT,
filesystems, mounts, mutable-tree separation, empty slot B and the UKI's
literal slot-A selector before conversion to qcow2. The ARM64 image has booted
this layout under Apple HVF. This is layout evidence, not update/rollback or
installer evidence.

The dev image still sets
`RootPassword=punar` and `Autologin=yes`; the desktop profile's
`mkosi.postinst.chroot` creates a `punar` user with the password `punar`
and puts it in `wheel`; `etc/greetd/config.toml` autologins that user into
Hyprland. `linux-firmware` is deliberately excluded from both images.
`cryptsetup` is not installed in the target. The directly built VM layout is
deliberately plaintext; the production encrypted overlay has been validated
only by V-REPART. `image-pipeline.md` still correctly records *"qcow2 only.
No installer ISO yet."*

Two accepted designs are blocked on that:

- **ADR-003** ratified A/B root slots. Its partition table now exists in the
  directly built VM image, but no update has written the inactive slot, no
  health gate has blessed it, and no installer has created it on a device.
- **`execution-trust.md` §3.3** places `FAN_MARK_MOUNT` marks on
  user-writable mounts and states the prerequisite in its own words: on a
  single root filesystem, *"marking `/home` would mark `/`"*, which
  destroys the entire cost argument. Its verification item **V3** —
  *"ADR-003's separate `/home` and `/var` exist"* — is the thing this
  document makes true.

So the installer is not the last feature. It is the load-bearing member
under two designs that are already accepted.

---

## 2. Decision summary

| # | Decision |
|---|---|
| 1 | **The artefact is a UEFI-bootable hybrid ISO built by the same pinned mkosi pipeline**, from a third profile, assembled by one pinned `xorriso` invocation. It is dd-able to USB and mountable as BMC virtual media. §3. |
| 2 | **The install is an update apply.** The ISO carries a complete release triple (`release.json`, `.sig`, payload, UKI) exactly as `update-and-rollback.md` §4.1 defines it, and the install streams that payload into slot A through the same verify → write → re-read → bless order. There is no `pacstrap`, no package transaction, no network. §3.2. |
| 3 | **The live environment and the thing it installs are the same tree in two containers** — an erofs for booting read-only, an ext4 slot payload for writing. CI asserts the two trees are identical file-for-file. What you tried is what you get. §3.1. |
| 4 | **The device layout is ADR-003's, literally**: ESP 1 GiB (three UKIs), root A 8 GiB, root B 8 GiB, shared remainder. Created by `systemd-repart` from a definition set that is the single source of truth for both the build and the install. §4. |
| 5 | **`/var`, `/home` and `/var/tmp` are three btrfs subvolumes of the shared partition, mounted separately.** This satisfies execution-trust's separate-mount requirement *and* resolves its `/var/tmp` dilemma at zero cost, without imposing a fixed size split that a 128 GB disk cannot afford to get wrong. §4.3. |
| 6 | **Every partition UUID is a fixed literal**, shared by every Punar device. That makes `/etc/fstab` and `/etc/crypttab` vendor files identical on every install — which is what ADR-003's "Punar-owned `/etc` is a rollback hazard" rule requires. §4.2. Its one real cost (two Punar disks in one machine) is named. |
| 7 | **LUKS2 is the default for every device, not only managed ones.** Argued against §44.2's narrower wording in §5.1. An opt-out exists, is never the default, and is permanently visible afterwards as a named compliance state. |
| 8 | **The root slots are not encrypted; the shared partition is.** Everything about the user is encrypted; the OS image — identical on every device and publicly downloadable — is not. The OS integrity boundary is Secure Boot, which is SIMULATED. §5.5. |
| 9 | **TPM unlock is designed for and not enrolled.** Enrolling against a software TPM would produce a device that unlocks without a passphrase on the strength of measurements nobody has validated — a weaker device carrying a stronger claim. §5.4. |
| 10 | **The installer asks exactly two things: keyboard and disk** — plus the two secrets that belong to the disk (passphrase, recovery key). **It creates no user account at all.** Language, network, the account, the fork and privacy defaults are first boot's, per `onboarding.md` §4.2, which this design accepts without reopening. §6.2, §6.4. |
| 11 | **The seam is one advisory file.** The installer writes `/var/lib/punar/install/seed.json` and, when given one, passes an `oobe-answers.json` through untouched. First boot reads both as hints and works if they are missing. `onboarding.md` §4.3. §6.4. |
| 12 | **The installer offers no theme and no app selection.** Argued in §6.6. Whether *first boot* offers one is onboarding's decision, and it made it (`onboarding.md` §3.1: two moods at the end, contrast at the beginning). |
| 13 | **The live environment runs the same `punard` binary from the same image.** No second daemon, no second policy engine, no second audit writer. `install.*` exists only when the kernel cmdline says `punar.live=1`, which only the installer UKI carries. §7.1. |
| 14 | **Every privileged install step is a typed method with a validated parameter object.** `install.plan` returns a plan and a `plan_token`; `install.apply` refuses any token that does not match the plan the user confirmed. The screen you agreed to and the bytes written are the same object. §7.2. |
| 15 | **Dev conveniences move to a `dev` profile and a release build asserts their absence at build time.** A profile split alone is a convention; a build that fails is a mechanism. Both, plus a post-install check. §8. |
| 16 | **`linux-firmware` and both microcode sets ship in the image.** On an A/B system, *"install the driver afterwards"* does not exist — a consequence of ADR-003 that no other document has stated. §9.2. |
| 17 | **MVP graphics support is integrated Intel/AMD only** — exactly what §5.1 says. No out-of-tree modules, no NVIDIA. Named, costed, deferred. §9.2. |
| 18 | **A pre-flight hardware report classifies every device `FULL` / `PARTIAL` / `UNSUPPORTED` before commit** and travels to the installed system. Design language §7's coverage vocabulary, applied where it matters most: *silence is not support.* §9.3. |
| 19 | **CI proves the install offline, end to end, with 40 named assertions** — including the two that unblock other designs: the ADR-003 layout (I08–I13) and five distinct mounts (I15). §10. |

---

## 3. Decision 1 — the artefact

> **The ISO is not a new build system. It is the existing pipeline emitting
> one more shape of the same bytes.**

### 3.1 What is on the ISO

`punar-installer-<version>-x86_64.iso`, an ISO 9660 (level 3, Rock Ridge)
image with a GPT-appended ESP partition, so the same file boots from a
DVD/virtual-media path *and* from a USB stick written with `dd`.

| Path on the ISO | What it is | Approx. |
|---|---|---|
| *appended partition 2* (type GUID `C12A7328-…`) | The ESP: `EFI/BOOT/BOOTX64.EFI` (systemd-boot) + `EFI/Linux/punar-installer.efi` (the live UKI) | ~120 MB |
| `punar/live.erofs` | The live environment — the desktop tree as a read-only erofs, loop-mounted with a tmpfs overlay | ≈ 1.2–2 GB |
| `punar/punar-desktop-<version>.slot.raw.zst` | **The release payload**, byte-identical to what the update channel publishes | ≈ 1.2–2 GB |
| `punar/punar-desktop-<version>.uki.efi` | The slot-A UKI (cmdline: `root=PARTUUID=<slot A>`) | ~60 MB |
| `punar/release.json`, `release.json.sig` | The signed manifest, `schemas/update/release-manifest.json` | ~2 KB |
| `punar/tree-manifest.json` | Per-file sha256 of the tree, emitted once and true of both containers (used by I04) | ~2 MB |

**The live root and the installed root are the same tree in two
containers.** The erofs is what you boot to run the installer; the
`slot.raw.zst` is what gets written to slot A. They are produced from one
mkosi build. CI asserts (I04) that their file lists, modes and per-file
digests are equal. That gives the claim every installer wants and almost
none can make: *the system you just used to install is the system you
installed.*

**Why two containers and not one file used twice.** A slot payload must be
a writable ext4 that `systemd-repart --copy-blocks` can lay down and that
the update path can digest as an opaque blob; a live root wants to be
compressed and read-only so it fits on a stick and mounts without a key.
Storing one uncompressed ext4 and loop-mounting it for live use would work
and would make the ISO ≈ 5 GB. The chosen shape costs one duplicated tree
in the build and saves ~2 GB on every download. The tradeoff is recorded
rather than assumed; the alternative is a two-line change if the assertion
in I04 ever proves awkward to keep true.

### 3.2 The install *is* an update apply, and that is the whole design

`update-and-rollback.md` §4.1 already defines a release as three files plus
a UKI, and §3 already defines applying one as: verify manifest signature →
check admissibility → stream the payload into the inactive slot with a
bounded buffer → re-read and digest what was written → install the UKI →
make it default.

An install is that sequence with two additions on the front (create the
partition table; create the LUKS container and filesystems) and one on the
back (seed the shared partition with `machine-id`, the device id and the
hardware report, but no account). **It reuses the code path, the digest discipline, the failure
ordering and the audit events that the update design already owns.**

Consequences worth naming:

- **The offline package set question dissolves.** Omarchy bundles an
  offline pacman mirror because `omarchy-iso` drives `archinstall`, which
  resolves and installs packages at install time. Punar installs an image.
  There is no dependency resolution on the device, no mirror, no `pacman`
  transaction, no ordering that can differ between two machines. The
  install is a block write and a digest comparison. This is strictly
  stronger than an offline mirror on reproducibility (every device gets
  bytes CI verified) and on speed (no resolver, no scriptlets), and it is
  the direct payoff of ADR-003.
- **It costs the thing package installers are good at**: a device cannot
  choose a different kernel, add a driver, or omit an application at
  install time. §9.2 takes that consequence seriously; §6.6 takes the
  application half of it.
- **The first update on a new device is not a special case.** Slot B is
  empty and blessed-nothing; the first `update.apply` is the second write
  the machine has ever seen, and it is shaped exactly like the first.

### 3.3 What changes in `os/images/`

```text
os/images/
  mkosi.conf                       MODIFIED — remove RootPassword=, Autologin=,
                                   console=ttyS0 and the punar-dev Hostname/ImageId
                                   defaults; these move to the dev profile (§8.2)
  mkosi.repart/                    NEW — the build-time partition definitions,
                                   generated from repart.d/install (§4.7) minus
                                   Encrypt=, so the dev qcow2 is already A/B-shaped
                                   and update-and-rollback's A1–A3 have something
                                   to assert against
  repart.d/install/*.conf          NEW — THE DEVICE LAYOUT. Single source of truth.
                                   Staged into the image at
                                   /usr/share/punar/repart.d/install/
  repart.d/install-encrypted/      NEW — fixed LUKS2 overlay for shared data
  repart.d/install-streaming/      NEW — fixed root-A overlay without CopyBlocks=;
                                   punard owns the bounded verified write
  mkosi.profiles/dev/              NEW — every CI and development convenience (§8.2)
  mkosi.profiles/desktop/          MODIFIED — product content only; postinst loses
                                   the punar user; greetd loses [initial_session]
  mkosi.profiles/installer/        NEW — layered on desktop; adds cryptsetup,
                                   btrfs-progs, gptfdisk; sets the live UKI cmdline
                                   (punar.live=1, no root=PARTUUID=); ships the
                                   installer's QML layer and the answer-file reader
  mkosi.finalize                   NEW — the build-time release assertion (§8.3);
                                   fails the build when `dev` is not among $PROFILES
                                   and a dev artefact is present
  scripts/container-build.sh       MODIFIED — stage_installer(), build_release_triple(),
                                   assemble_iso()
  builder/Containerfile            MODIFIED — add libisoburn (xorriso).
                                   erofs-utils, dosfstools, mtools, zstd, cpio
                                   are already pinned in the builder.
```

Outside `os/images/`:

```text
tools/build-image.sh               PUNAR_IMAGES gains `iso`
tools/install-test.sh              NEW, 0755 — the unattended-install QEMU lane (§10)
schemas/install/answers.json       NEW — the unattended answer file
schemas/install/plan.json          NEW — what install.plan returns
schemas/install/hardware-report.json  NEW — §9.3
```

**Three build steps, all in the pinned builder container:**

1. `mkosi --profile desktop,installer` → the live tree. `mkfs.erofs -zlz4hc`
   → `live.erofs`. `Format=uki` for that profile → `punar-installer.efi`.
2. `mkosi --profile desktop` → the release tree → the `slot.raw.zst` payload
   and the slot UKI, i.e. **the ordinary release build**, unchanged. The ISO
   consumes its output; it does not fork it.
3. `xorriso -as mkisofs` assembles both plus the manifest into the hybrid ISO:

   ```text
   xorriso -as mkisofs \
     -iso-level 3 -rational-rock -volid PUNAR_INSTALL \
     -eltorito-alt-boot -e --interval:appended_partition_2:all:: -no-emul-boot \
     -append_partition 2 C12A7328-F81F-11D2-BA4B-00A0C93EC93B esp.img \
     -o punar-installer-<version>-x86_64.iso iso_root/
   ```

**Honest note on mkosi's own formats.** The pinned mkosi's `Format=` set
covers `disk`, `directory`, `tar`, `cpio`, `uki`, `esp` and friends; it is
*not* an ISO authoring tool, and this design does not pretend it is. What
"the same pinned mkosi pipeline" means precisely is: **every byte inside
the ISO is a mkosi output from the pinned ALA snapshot, and the only
non-mkosi step is one deterministic `xorriso` invocation over those
outputs.** The container gains one package; the snapshot pin, the builder
base digest and `SourceDateEpoch` are unchanged, so the ISO stays as
input-deterministic as the qcow2 is today. If a later mkosi gains a native
ISO output, step 3 collapses into step 1 and nothing else in this document
changes.

### 3.4 How the live environment boots

The live UKI's initrd does one thing the ordinary initrd does not: find the
medium and pivot into it. No dracut module, no custom C, no shell script —
three generated systemd units, which is the §45 "native OS primitives"
rule applied:

1. `punar-live-medium.mount` — mounts the partition/filesystem labelled
   `PUNAR_INSTALL` at `/run/punar/medium` (read-only).
2. `punar-live-root.mount` — loop-mounts `medium/punar/live.erofs`.
3. An overlay mount with a tmpfs upper, then `switch-root`.

RAM cost: the tmpfs upper only. The erofs stays on the medium. A 4 GB
machine can run this installer; the 8 GB §5.1 minimum has room to spare.

### 3.5 ISO size, said out loud

≈ **2.5–4 GB**, dominated by the tree shipping twice. The lower bound
assumes the unmeasured desktop image sits near ADR-003's `R_max` inference
floor; the upper assumes it does not. **The image size is still
unmeasured** — ADR-003 says so, and this document does not launder its
estimate into a number. Measuring it is the first task of the milestone
that builds this, because it is simultaneously the ISO size, the slot
sizing input, and the download every user pays for.

For reference, Omarchy's ISO is self-reported "under 6 GB".

---

### 3.6 What is unverified at the pin, named before it reads as settled

Everything in §3 is designed against `os/images/snapshot.env`
(`PUNAR_SNAPSHOT_DATE=2026/08/20`, builder base pinned by digest). The builder
installs `mkosi` **by name, not by version**, so the toolchain's exact
behaviour is a property of the snapshot rather than of this document. Four
things are asserted above that a spike must confirm before the milestone is
scheduled — they are cheap, and each one changes a build step if it is false:

| # | Claim | Status |
|---|---|---|
| F1 | `mkosi --profile desktop,installer` composes **two** profiles. The repository passes a single profile today (`container-build.sh` line 452). mkosi renamed the option to a list form at some point in its 25.x line; the pinned version is whatever `pacman -S mkosi` resolved to in the 2026/08/20 snapshot | **VERIFIED 2026-08-27.** Pinned mkosi 26 parses `Profiles=`/`--profile=` with a comma-delimited list and loads each matching `mkosi.profiles/` directory in order. Its scripts receive `$PROFILES` as a **space-delimited** string despite the same pinned manual still saying comma-delimited; the policy gate normalizes both and fixture-tests the distinction. |
| F2 | `Format=uki` emits the installer UKI, and a second `mkosi` invocation emits the slot payload, from the same config tree | **TO VERIFY.** `Format=uki` is a documented mkosi output; that it composes with the profile split here is not |
| F3 | The `xorriso -as mkisofs … -append_partition 2 … -e --interval:appended_partition_2:all::` idiom produces an image that boots as `-cdrom` **and** as a raw drive on OVMF | **TO VERIFY** — this is the exact form assertion I05 exists to prove, and it is the step with the least margin for a typo. The idiom is the one Arch's own `archiso` uses; that it is correct *here*, at this xorriso version, over these inputs, is what I05 asserts |
| F4 | `libisoburn` is present in the 2026/08/20 snapshot and installs into the builder cleanly | **TO VERIFY.** Low risk; named because the builder's package list is a pin |

None of these is load-bearing on the *design*: each has a fallback that is a
build-script change. They are listed because "the same pinned mkosi pipeline"
is a claim about a toolchain nobody in this repository has yet run in this
shape, and §1.22 does not distinguish between overclaiming a security property
and overclaiming a build step.

---

## 4. Decision 2 — the partition layout

> **This section is the reason the document exists. It implements ADR-003
> exactly, and it answers the one question ADR-003 left open: how `/home`
> and `/var` become separate mounts.**

### 4.1 The table

Four GPT partitions. Nothing else. No BIOS boot partition (UEFI is required
per §44.1 and §5.1), no swap partition (§4.6), no recovery partition
(§4.5's honest limit).

| # | Name | GPT type | PARTUUID | Size | Filesystem | Rolled back? |
|---|---|---|---|---|---|---|
| 1 | `PUNAR-ESP` | `c12a7328-…` (ESP) | fixed literal | **1 GiB** | vfat, mounted `/efi` | n/a — holds *all* retained UKIs |
| 2 | `PUNAR-ROOT-A` | `4f68bce3-…` (root-x86-64) | fixed literal **A** | **8 GiB** | ext4 | yes, by swapping |
| 3 | `PUNAR-ROOT-B` | `4f68bce3-…` (root-x86-64) | fixed literal **B** | **8 GiB** | ext4 | yes, by swapping |
| 4 | `PUNAR-DATA` | `0fc63daf-…` (linux-generic) | fixed literal | **remainder** | **LUKS2 → btrfs** | **never** |

Inside partition 4, three subvolumes, mounted as three separate mounts:

| Subvolume | Mount | Why it is its own mount |
|---|---|---|
| `@var` | `/var` | ADR-003: punard state, audit log, ledger, containers, `machine-id`, device id — all survive updates and rollbacks |
| `@home` | `/home` | **execution-trust §3.3**: `FAN_MARK_MOUNT` on `/home` must not mark `/usr` |
| `@var-tmp` | `/var/tmp` | execution-trust §3.3's second consequence, resolved — see §4.3 |

`/tmp` and `/run/user/<uid>` are tmpfs and are already distinct mounts;
nothing here changes them. `/efi` is a fifth mount. That makes **five
non-tmpfs mounts** for assertion I15, and it makes execution-trust's V3
true.

**Why `linux-generic` and not the discoverable `var` type for partition 4.**
systemd's `gpt-auto-generator` will only auto-mount a partition of type
`var` whose partition UUID equals an HMAC of the machine-id — a rule this
layout cannot satisfy, because the partition UUID is a fixed literal (§4.2)
and the machine-id is per device and lives *inside* that partition. The
layout therefore mounts explicitly from a vendor `/etc/fstab`, and marks the
data partition `linux-generic` so nothing tries to be clever about it. The
root slots keep the discoverable `root-x86-64` type because it costs
nothing and is informative to other tools; auto-discovery of root never
fires because every UKI passes `root=` explicitly, which is ADR-003's whole
point.

### 4.2 Fixed PARTUUIDs, and what they buy

ADR-003 already requires *"fixed, literal, distinct PARTUUIDs"* for the two
root slots. This design extends that to all four partitions, and the reason
is a rule ADR-003 itself imposes:

> *Punar-owned mutable `/etc` state becomes a capability output, never a
> file an update must preserve. Any Punar-owned `/etc` file not produced by
> a capability is a rollback hazard and is asserted absent.*

`/etc/fstab` and `/etc/crypttab` are exactly such files, and neither is a
capability. With fixed literals they do not have to be: **they are identical
on every Punar device, so they ship as vendor files inside the image**, are
rebuilt with every slot, and are asserted byte-identical to the vendor copy
after install (I20).

```text
# /etc/crypttab  (vendor, identical on every device)
punar-data  PARTUUID=<data literal>  none  luks,discard

# /etc/fstab  (vendor, identical on every device)
PARTUUID=<esp literal>   /efi       vfat   umask=0077,noexec,nosuid,nodev  0 2
/dev/mapper/punar-data   /var       btrfs  subvol=@var,compress=zstd:1     0 0
/dev/mapper/punar-data   /home      btrfs  subvol=@home,compress=zstd:1    0 0
/dev/mapper/punar-data   /var/tmp   btrfs  subvol=@var-tmp,nosuid,nodev    0 0
```

`/dev/shm` is mounted `noexec` in the same vendor tree — one line,
kernel-enforced, and the thing execution-trust §3.3 asks for and records as
missing today.

**The cost, named.** Two Punar disks attached to one machine have colliding
PARTUUIDs and the boot resolves whichever the kernel enumerates first. The
mitigations are: (a) the installer refuses to write a Punar layout to a disk
while another Punar GPT is attached, and says why in the §73 voice; (b) the
recovery answer, when it exists, is to detach one. This is a real limit of a
fixed-UUID design, it is the price of vendor `/etc`, and it is cheaper than
the alternative — per-device `/etc` files that ADR-003 classifies as
rollback hazards. Recorded in §12.

The **LUKS2 header UUID is random per device** and so is `/etc/machine-id`
(provisioned into `/var` per ADR-003 and bound into `/etc`). Fixed
partition UUIDs are not a fingerprint of *you*; they are a fingerprint of
*Punar*, which is public information.

### 4.3 Why subvolumes and not two more partitions

execution-trust needs `/home` to be a different *mount object* from `/`.
Two ways to get there:

| | Two partitions (`/var`, `/home`) | **One partition, btrfs subvolumes** |
|---|---|---|
| Separate mounts? | yes | **yes** — a subvolume mount is its own `vfsmount` with its own `st_dev`; a `FAN_MARK_MOUNT` on `/home` does not match opens reached through `/var` |
| Free space | **Fixed split, decided at install, wrong forever.** On a 102 GiB budget, a full `/var` beside 60 GiB of idle `/home` is the single most common Linux install regret | Shared. No decision is made, so no decision is made badly |
| `/var/tmp` dilemma | Needs a *third* partition to solve, or is dropped from the mark set | **Solved for free** — one more subvolume |
| ADR-003 conformance | "remainder ≈ shared" — conforming | conforming; ADR-003 explicitly leaves btrfs available as *"an optional data-side convenience"* |
| Snapshots of user data | none | available, unused by the update path by design |
| Cost | none | btrfs on the data path; `btrfs-progs` already in the builder |

**Chosen: one partition, three subvolumes.** It satisfies the constraint
that motivated the question, and it declines to make a sizing decision that
a 128 GB disk cannot afford to have made wrongly.

**The rule that makes the subvolume answer *sound*, and that two partitions
would not have needed:** a btrfs filesystem's **top level (subvolid 5) is
never mounted**, by anything, ever. Every subvolume is reachable from the top
level, so a single `mount /dev/mapper/punar-data /mnt` exposes `@home`,
`@var` and `@var-tmp` under paths that a `FAN_MARK_MOUNT` on `/home` does not
cover — which would quietly reintroduce the exact bypass this layout exists to
close. Concretely: the vendor `/etc/fstab` above contains no subvol-less entry
for the mapper device, no unit mounts one, and `install.apply`'s `format`
phase mounts the top level only transiently to create the three subvolumes and
unmounts it before the `write-slot-a` phase begins. Asserted by **I39**, and it
is a constraint execution-trust's adopting milestone inherits rather than one
it can choose. *(Two separate partitions would have had this property for
free; it is the one real cost of the subvolume answer, and it is one line of
`fstab` and one assertion.)*

This also resolves, in the installer rather than in the adopting milestone,
the open choice execution-trust §3.3 left:

> *The adopting milestone chooses one of: mark `/var` and accept the events;
> give `/var/tmp` its own mount; or drop `/var/tmp` from the mark set.*

Option two is now free. The layout makes `/var/tmp` its own mount, so
marking it does **not** mark `/var/lib/flatpak`, and every Flatpak launch
stays on the no-event fast path. Option three (drop it entirely) remains
available and remains cheaper still; the layout no longer forces the
choice. This is a genuine improvement over what execution-trust could
assume, and it is a decision the installer is the right place to make,
because the installer is what creates the mounts.

### 4.4 The arithmetic

ADR-003 fixes the OS cost at 17 GiB and states the percentages. Restated
here against both targets, with the shared remainder computed rather than
quoted:

| | §5.1 minimum **128 GB** | §5.2 target **256 GB** |
|---|---|---|
| Usable (GiB, 1 GB = 10⁹) | 119.2 | 238.4 |
| ESP | 1.0 | 1.0 |
| root A | 8.0 | 8.0 |
| root B | 8.0 | 8.0 |
| **Fixed OS cost** | **17.0 GiB — 14.3 %** | **17.0 GiB — 7.1 %** |
| Cost of A/B *itself* (the second slot) | 8.0 GiB — **6.7 %** | 8.0 GiB — **3.4 %** |
| **`PUNAR-DATA` (shared)** | **≈ 102.2 GiB** | **≈ 221.4 GiB** |

**A correction, made rather than inherited.** `update-and-rollback.md`
§3.5's table reads *"`/var` (incl. `/home`) — remainder ≈ 110 GiB"*. On the
119.2 GiB usable figure the remainder is **102.2 GiB**, which is what
`execution-trust.md` §13 already uses. ADR-003's percentages (6.7 % / 3.4 %
/ 14.3 %) are the corrected ones and are the numbers this document uses;
the 110 GiB row is stale and wants a corrigendum in the update document.

Slot size does **not** scale with the disk. ADR-003's rule is
`slot = roundup_GiB(1.5 × R_max)` — a property of the image, not of the
device. A 2 TB disk gets the same 8 GiB slots and 1.9 TB of `PUNAR-DATA`.
That is correct and should not be "improved".

### 4.5 Smaller disks — three bands, and a refusal that shows its working

The shared partition needs a floor. It holds `/home`, `/var/lib/containers`,
`/var/lib/flatpak` (≈ 90 MB of preinstalls plus runtimes at ≈ 3 GB per
app-catalog §2.3/§13), the audit log and the ledger. The update path
streams into the inactive slot with a bounded buffer, so **no full copy of a
release ever lands on `PUNAR-DATA`** — the floor is about the user, not
about updates. Set it at 16 GiB.

| Disk | Verdict | What the installer does |
|---|---|---|
| **< 33 GiB** (17 fixed + 16 floor) | **Refuse** | Names the arithmetic: *"Punar needs 33 GiB and this disk has 20. 17 GiB is the operating system and its second copy — the second copy is how Punar rolls back a bad update, and it is not optional. The remaining 16 GiB is the floor for your files."* Disk untouched (I36a). |
| **33 GiB – 119.2 GiB** | **Install, with a standing warning** | Proceeds. Records `disk_below_minimum_target: true` in the hardware report; System Control shows it permanently. Copy: *"This disk is below Punar's minimum target of 128 GB. Punar will install and has never been tested here."* |
| **≥ 119.2 GiB** | **Install** | Normal path. |

The refusal is a refusal, not a hidden "advanced" override. A user who
wants Punar on a 24 GiB disk is asking for a device that cannot roll back,
and ADR-003 made that non-negotiable.

**There is no recovery partition, and that is a gap, not a decision.**
`update-and-rollback.md` §6.5 names a corrupt ESP as having *"no software
answer"* and recovery media as unowned work. This ISO **is** that recovery
media in the "reinstall" sense and is **not** it in the "repair without
losing `/home`" sense. A repair mode that re-writes the ESP and slot A
while leaving `PUNAR-DATA` alone is the obvious next thing to build; it is
out of scope here and listed in §13.

### 4.6 No swap partition

Spec §6.6 asks for zram, not swap. A swap partition on the data disk would
have to be either inside the LUKS container (fine, but then it is a swapfile
and can be added later without a layout change) or outside it (a plaintext
copy of the memory of an encrypted system — unacceptable on a privacy-first
OS). **Consequence, stated: hibernation is unavailable.** Suspend-to-RAM is
unaffected. If hibernation is ever wanted, the answer is a swapfile inside
the encrypted btrfs, which needs no repartition — which is itself an
argument for this layout.

### 4.7 The definitions, and the one source of truth

`os/images/repart.d/install/` is now committed with these literal identities:

```text
10-esp.conf        Type=esp        SizeMinBytes=1G  SizeMaxBytes=1G
                   UUID=8bb56554-b5f1-4058-90ac-8dc91a8e2bd4
                   Label=PUNAR-ESP   Format=vfat
20-root-a.conf     Type=root       SizeMinBytes=8G SizeMaxBytes=8G
                   UUID=1beabfe0-9cb8-4b49-91ef-d372b845e7ea
                   Label=PUNAR-ROOT-A
                   CopyBlocks=/run/punar/install/payload.raw
30-root-b.conf     Type=root       SizeMinBytes=8G SizeMaxBytes=8G
                   UUID=2b1b91a9-cf2c-4e9c-a723-5ec997971662
                   Label=PUNAR-ROOT-B   NoAuto=yes
50-data.conf       Type=linux-generic  SizeMinBytes=16G  Weight=1000
                   UUID=21d4af4f-a19c-4c6a-b4e8-dd50e9f7ecb9
                   Label=PUNAR-DATA   Format=btrfs
                   MakeDirectories=/@var /@home /@var-tmp
                   Subvolumes=/@var /@home /@var-tmp
```

and two fixed overlay directories. `repart.d/install-encrypted/` contains a
complete `50-data.conf` with `Encrypt=key-file`. It intentionally does not set
`EncryptKDF=minimal`; that shortcut belongs only to V-REPART's random
disposable test key, never to a person's passphrase.
`repart.d/install-streaming/` contains a complete `20-root-a.conf` without
`CopyBlocks=`. The production installer renders both overlays after the base,
so repart creates and formats the fixed layout while `punard` decompresses and
writes slot A with a bounded 4 MiB buffer. This avoids materializing an 8 GiB
`payload.raw` in `/run`; no caller chooses either definitions directory.

**V-REPART falsified the original merge assumption.** Pinned systemd 261.2
accepts repeated `--definitions=`, but the **first** directory wins for a
duplicate filename. `tools/render-repart-definitions.sh` therefore copies the
base and overlays into a fresh directory below `/run` with explicit
later-directory-wins semantics, and repart receives that one rendered set.
The spike also found that `Subvolumes=` alone does not materialize the three
subvolumes at this pin; their names must also appear in `MakeDirectories=`.
Both corrections are now in the committed source rather than left as
toolchain folklore.

`tools/render-mkosi-repart.sh` derives the build-time definition set from the
same files: it removes `CopyBlocks=`, populates slot A from mkosi's staged
tree, seeds the shared subvolumes, and keeps mutable `/var` and `/home` out of
the root slot. So **the dev qcow2 is built with the ADR-003 layout too**. That
is worth more than it looks: it means
`update-and-rollback.md`'s assertions A1–A3 have an artefact to run against
before any installer exists, and it means every existing boot test starts
exercising A/B mounts immediately.

---

## 5. Decision 3 — LUKS2 by default, for everyone

> **A privacy-first operating system does not make its personal users the
> unencrypted tier.**

### 5.1 The argument, against the spec's own wording

§44.2 reads *"encrypted install by default for managed devices"*. Read
narrowly, that makes encryption an enterprise feature and leaves the
personal default plaintext. This design encrypts by default for every
device, and the argument is made from the rest of the spec rather than
against §44.2:

1. **§3.6 is "Private by default", not "private when your employer asks".**
   The design language's own unmanaged-first law (§8) says *"privacy
   statements strengthen, never weaken, in personal mode."* An
   encryption default that exists only under management is the exact
   inversion of that sentence.
2. **§59.5 "Lost device" is a threat-model entry, not an enterprise
   feature.** The personal laptop is the one that gets left in a taxi. It
   is also the one with no remote wipe, no fleet console and no
   administrator to notice.
3. **The AI Access Ledger, the audit log, the policy store and the device
   identity all live on `/var`.** Punar generates a detailed local record of
   what ran on the machine. Shipping that record unencrypted by default
   would mean Punar's own observability is a liability it created for the
   user. Encryption is not a feature we add to that; it is the condition of
   being allowed to keep it.
4. **§60 forbids AI from disabling encryption.** A constraint written to
   protect something that most devices would not have is a constraint about
   nothing.
5. **The competitor already does this.** Omarchy ships LUKS full-disk
   encryption as the install default, for personal machines, today. Being
   the privacy-positioned OS with the *weaker* default is not a position.

**Default is not mandatory.** The opt-out is one keystroke away, is never
pre-selected, requires typing the word `unencrypted` (§6.3's confirmation
grammar), and is remembered honestly: the device reports
`encryption: disabled · chosen at install · <date>` in System Control →
SECURITY → Encryption, forever, and enrolling later into an organisation
whose baseline requires encryption produces a **named non-compliance**
citing the policy, not a silent pass. That is §52's explicit-coverage rule
applied to the one decision a user can make that they cannot undo without
reinstalling.

**The honest cost of this decision, stated in full.** With TPM unlock not
enrolled (§5.4), encryption by default means **every Punar user types a
passphrase at every boot**. That is the strongest argument the
"managed-only" reading has, and it is real: it is a daily tax on people who
did not ask for it. Three things make it acceptable and none of them is
"users will not mind":

- it is one prompt, before the graphical stack, on a keyboard layout the
  person chose two minutes earlier (§6.2 — this is precisely why keyboard is
  the one question the installer asks before the passphrase);
- the opt-out exists and is not buried;
- TPM unlock is designed for and blocked on a laptop being on a desk, not
  on a design decision. When user-blocked item 2 lands, the tax goes to
  zero for TPM-equipped machines, which is most of §5.3's target classes.

### 5.2 Passphrase entry

- LUKS2, argon2id, default systemd/cryptsetup parameters at the pin. No
  hand-tuned KDF costs: a number chosen today against QEMU is a number
  wrong on every real machine.
- The passphrase is entered **twice** and never echoed; a strength meter is
  shown as *information* and never blocks (blocking on an entropy heuristic
  teaches people to append `!1` and nothing else).
- It is **separate from the account password**, necessarily and not merely
  by preference: at this point in the machine's life **no account exists**
  (§6.4), so there is nothing to share it with. `onboarding.md` §4.5 refuses
  the merge from the other side too, and for the better reasons — a password
  change that re-keys a LUKS volume can fail halfway and leave a disk that
  will not unlock, and a forgotten password would become an unbootable disk
  rather than a Layer-1 recovery. Two secrets, every boot, until TPM unlock
  exists. Both documents say so; neither hides it.
- The passphrase reaches `punard` **on a file descriptor, never in the JSON
  request** — the M9 credential-broker rule (*"a credential leaves the
  broker once, on a file descriptor"*), applied in the other direction. It
  is never a process argument, never an environment variable, never written
  to disk.
- At boot, unlock is systemd's console prompt (`systemd-cryptsetup`). **A
  graphical unlock surface is Phase 2** and is honestly out of scope: it
  needs a plymouth-class early graphical stack that the image does not have
  and that Plate D-002's greeter does not cover.

### 5.3 The recovery key

Generated by `systemd-cryptenroll --recovery-key` — systemd's modhex
format: **256 bits**, rendered as 64 modhex characters in eight
dash-separated groups of eight, designed to be read off a screen and typed
back. *(Corrected 2026-08-26: an earlier draft said "64 bits of entropy",
conflating the rendering with the key length and understating it by a factor
of four. Verified 2026-08-27 against pinned ARM64 systemd 261.2: the key has
exactly this shape, is enrolled as a typed `systemd-recovery` token, and
independently opens the loopback LUKS2 filesystem.)*

**Personal display and enterprise escrow are mutually exclusive lanes.**

| | |
|---|---|
| Personal display | **On screen, once, at the recovery-key gate inside stage 07 — immediately after the `encrypt` phase enrolls it, and not before, because before that it does not exist (§6.5.2).** Large, monospace, in eight groups, with a QR rendering beside it. Stage 05 announces that this is coming; it does not show a key. |
| Personal confirmation | The user must type back **two randomly chosen groups** before `Continue` enables. Not the whole key — that trains transcription errors into muscle memory rather than catching them. Two groups catches the "I did not save it at all" failure, which is the failure that matters. |
| Enterprise display | **Never.** When organization policy requires escrow, the key travels from the `cryptenroll` pipe directly into the in-memory tenant-key wrapper. The installer displays only the organization, key id, verified receipt state and audit reference. |
| Not shown again | In the personal lane there is no retrieve-plaintext action. The authenticated recovery-key action rotates: add a new key, prove it, show it once, then remove the old slot. In the enterprise lane Smplify's audited recovery workflow may release the wrapped key to an authorized operator. |
| Not logged | **The file descriptor *is* stdout, and this needs saying precisely, because the obvious phrasing is self-defeating.** `systemd-cryptenroll --recovery-key` writes the key to its own stdout; a unit with `StandardOutput=null` would therefore discard the very thing the installer needs. So `punard` spawns `systemd-cryptenroll` directly with **stdout connected to a pipe it holds** — never a journal stream, never a terminal, never a file — reads the key, renders the personal QR or feeds the enterprise wrapper in memory, and closes the pipe. `StandardError` is discarded. It is never in a `punard` result object, audit event, state file, process argument, environment variable, or journal field. §44.2's *"no recovery material in logs"* is enforced by the key never entering a log-bound stream, not by after-the-fact redaction. |
| Proven | **I36** — after a full unattended install, the literal key string appears zero times in the live journal, the installed journal, `/var/log`, and the audit log. A grep-for-the-known-secret assertion, which is the only kind that proves this. |
| Personal device | Uses the personal display and confirmation lane. Punar persists no revealable copy. |
| Enrolled device with `security.diskEncryption.recoveryKeyEscrow.enabled: true` | Generated on the device and never displayed. The key is wrapped immediately to the organization’s pinned tenant-recovery public key, then the wrapped envelope is uploaded to Smplify. The UI says `RECOVERY · ESCROWED TO <ORG>` without showing material. Automatic means no extra human step; it does not mean invisible or unaudited. |
| Enrolled device without an escrow requirement | The personal one-time display lane remains in force. Enrollment alone does not silently grant the vendor or organization a decryption key. |
| Portal custody | Smplify stores the tenant-wrapped envelope, never a globally vendor-decryptable key. Recovery access is tenant-RBAC protected and every view or release is append-only audited with operator, device, reason, time and outcome. Portal recovery provides the key to an authorized operator; it is not a network backdoor in the pre-boot unlock path. |
| Enterprise receipt gate | The device verifies a Smplify receipt bound to the device id, LUKS UUID, recovery keyslot, tenant key id and wrapped-envelope digest before reporting `escrowed`. A required-but-unacknowledged escrow is `pending`/non-compliant and never a green check. Rotation is add → test while held in memory → escrow → verify receipt → remove old slot; failures retain the old working slot. |

The wrapping key is not accepted from an unauthenticated network response. Its
key id and public key arrive through the same enrollment trust chain that pins
the organization and policy. The envelope uses a reviewed standard
public-key wrapping construction (HPKE, RFC 9180) and carries algorithm and key
ids for rotation; no first-party encryption primitive is invented here.

**Implemented seam (2026-08-27; not yet the installer):** `punar-recovery`
normalizes the systemd key into a zeroizing, non-cloneable, non-serializable
owner; provides the personal one-screen disclosure/Copy gate with two random
group confirmations; and fixes the managed suite to RFC 9180
DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305. Organization,
tenant key id, device id, LUKS UUID and keyslot are authenticated as HPKE
associated data. `punard` fetches tenant public material through the enrolled
device channel, wraps locally, uploads only the envelope, and accepts
`escrowed` only after an Ed25519 receipt verifies over the exact envelope
digest and bindings. The real dev/CI mock proves token-to-device binding,
ciphertext-only server custody, a separately permissioned recovery release,
mandatory structured reason and append-only release audit. Its complete HPKE
keypair and asserted admin identities are public test fixtures; **production
portal identity, step-up authorization and tenant KMS/HSM key custody remain
unimplemented here.** The install service/UI still has to connect the proven
LUKS pipe to these state machines.

**Late enrollment of an unencrypted device.** Cryptsetup supports in-place
LUKS2 encryption, but its own contract requires a reliable backup and warns
that plaintext remains exposed during conversion. Smplify may schedule and
orchestrate a guided, resumable encryption migration with a reboot and backup
gate; it may not start one invisibly on a populated workstation. Until that
workflow is implemented and completed, organization policy reports the device
as named non-compliant. A newly installed enrolled device takes the encrypted
and escrowed lane automatically.

Losing both the passphrase and the recovery key means the data is gone.
The surface says exactly that, once, in plain words, at the moment it
matters — not in a manual nobody has written yet.

### 5.4 TPM: designed for, deliberately not enrolled

The mechanism is a one-line addition to the crypttab this design already
ships (`tpm2-device=auto`) plus one `systemd-cryptenroll --tpm2-device=auto
--tpm2-pcrs=...` call at the `encrypt` phase. It is designed for and the
layout accommodates it. **It is not enrolled in the MVP, and the reason is
not laziness.**

QEMU with `swtpm` can present a real TPM 2.0 interface, and enrolling
against it would make a green check appear. What it would prove is that the
plumbing calls the right function. What it would *claim* is that the disk
unlocks only when the boot chain measures as expected — and that claim
requires PCR values produced by real firmware, sealed against a boot chain
that is actually signed. Neither exists: Secure Boot is user-blocked item 1
and the measurement hardware is user-blocked item 2, whose own proof
criteria are *"unlock without a passphrase on real hardware after a measured
boot, plus a deliberate PCR mismatch refusing to unlock."*

**Enrolling a TPM key now would produce a device that unlocks without a
passphrase on the strength of measurements nobody has validated.** That is
strictly weaker than a passphrase and strictly stronger-sounding. §1.22
exists for exactly this shape of decision.

So: the stage exists, is drawn dashed, and reads
`TPM-ASSISTED UNLOCK · SIMULATED · NOT ENROLLED`, with the reason and the
unblock condition on the stage. When item 2 lands, enrolling is a phase
addition and a crypttab line, and the dashed line becomes solid by a
measurement rather than by an edit.

### 5.5 What LUKS here does and does not protect

| | |
|---|---|
| **Encrypted** | `/home`, `/var` — user files, the audit log, the AI Access Ledger, cached policy, enrollment token, device identity, `machine-id`, container images, browser profiles. Everything about the person and the device. |
| **Not encrypted** | The ESP and both root slots — systemd-boot, the UKIs, and the OS image. |
| **Why** | Those bytes are identical on every Punar device and are published for download. Encrypting them protects nothing and costs the two properties the update design depends on: digesting a slot at rest, and writing a slot without holding a user secret. |
| **What defends them instead** | Secure Boot and a signed UKI — **user-blocked item 1, SIMULATED today.** |
| **The gap, plainly** | An attacker with physical access and time can modify the operating system on a Punar disk today. They cannot read the user's data. Until item 1 lands, "full disk encryption" would be the wrong phrase for what this ships, and the surfaces say **"Your files are encrypted"**, which is what is true. |

Revisit trigger: if Secure Boot remains unavailable long enough that
evil-maid resistance has to come from somewhere else, the alternative is
moving the slots inside the LUKS container and unlocking in the initrd —
which changes ADR-003's `root=PARTUUID=` selector and therefore needs a new
ADR, not a paragraph.

---

## 6. Decision 4 — the install flow

> **§65 forbids shell commands during first boot. This design reads that as
> forbidding them during install too, and it reads "keyboard-first" as the
> constraint that makes the flow good, not the constraint that makes it
> austere.**

### 6.1 Where it runs

**The installer is a full-surface layer in `punar-shell`**, in the
`punar-installer` layershell namespace — architecturally the same choice
M13 made for first boot (`FirstBoot/FirstBoot.qml`), for the same reasons,
plus one more:

- It reuses the compositor, the shell, the theme tokens and the
  `Quickshell.execDetached`/`FileView` patterns that already boot and are
  already exercised in CI.
- It means the installer *looks exactly like the system it installs*,
  which is the visual half of decision 3's "what you tried is what you get".
- It means the QML surface has **no privileged socket client** — the same
  M13 decision 5 rule. Every side effect is a fixed `punarctl` argv against
  the typed methods in §7.2.

Progress is read the way M5's status is read: `punard` writes
`/run/punar/install.json` atomically and the shell watches it with
`FileView`. **No polling** — §6.3's rule holds inside the installer.

### 6.2 The stages — two questions, and no more

| # | Stage | What it asks | What it writes |
|---|---|---|---|
| 01 | **Keyboard** | Layout, from the closed set the image ships. A test field below it says *"type here to check"*. | Nothing on the device — it sets the layout **for this session**, so the passphrase can be typed safely, and is later recorded as a *hint* in `seed.json` (§6.4). |
| 02 | **Hardware** | Nothing. It **reports** (§9.3): every device classified `FULL` / `PARTIAL` / `UNSUPPORTED`, before commit. | Nothing yet; the report travels to the installed system. |
| 03 | **Disk** | Which disk. Model, serial, size, and — loudly — what is currently on it. | Nothing. Selecting is not committing. |
| 04 | **Encryption** | Passphrase ×2, or the explicit opt-out. | Nothing yet. |
| 05 | **Recovery key** | **Nothing yet — it explains what is coming.** A recovery key cannot exist before the LUKS volume does, so this stage states that one will be generated during the install and shown once, and that the install will pause until it has been written down. Skipped entirely if 04 opted out. | Nothing. |
| 06 | **Confirm** | The whole plan, and the destructive confirmation (§6.3). | **Everything, from here.** |
| 07 | **Install** | **One thing, once:** the install pauses immediately after the `encrypt` phase to show the recovery key and take two groups typed back (§6.5.2). Otherwise nothing — nine named phases with honest progress (§6.5). | The device. |
| 08 | **Done** | *"Remove the medium and restart."* One line pointing forward: *"When it starts, your machine will ask who you are."* | The install record and `seed.json`. |

**Why only two questions.** Language, network, timezone, **the account**,
the personal/organisation fork and the privacy defaults are D-008's stages
and first boot's job. `onboarding.md` §4.2 decided that seam and this
document accepts it wholesale rather than relitigating it; its three
arguments are better than any this document would have made, and one of
them is decisive:

- **§65's list is a first-boot list**, and it orders **network (3) before
  account (4)** — an ordering an installer structurally cannot honour,
  because an offline installer has no network and does not need one.
- **The imaged-fleet case.** An organisation images 200 machines from one
  artefact. Under a split seam every machine arrives at a clean first boot
  and the person who opens it owns the account; under the Ubuntu model the
  fleet arrives pre-populated with the technician who ran the installer.
- **The two secrets belong to two people at two moments.** The LUKS
  passphrase and the disk recovery key are *disk* secrets, set by whoever
  owns the disk. The account password and the account recovery code are
  *personal* secrets. On a fleet those are different humans.

And the constraint that settles the other direction, in onboarding's own
words: **disk encryption cannot move to first boot, because you cannot
encrypt the volume you are running from.** Physics decides that half; the
account half is decided above.

**Keyboard is the one exception, and it is not negotiable.** You cannot
safely set a passphrase on a layout you have not chosen — a passphrase typed
on the wrong layout is an unbootable disk, and it is the most common
catastrophic install failure in the Linux ecosystem. So the installer asks,
uses the answer for its own session, and hands it forward as a hint that
first boot pre-selects and the person can change.

### 6.3 The destructive confirmation

The one screen that must not be smooth.

```text
PUNAR · INSTALL                                          Stage 06 of 08

  This erases Samsung SSD 980 · 500 GB · S64ANS0T123456

  Everything on that disk is destroyed and cannot be recovered.
  Punar found: 1 NTFS partition (465 GB, "Windows"), 1 EFI partition.

  What Punar will create
    /efi          1 GiB     boot
    root A        8 GiB     the operating system
    root B        8 GiB     the operating system's second copy — this is
                            how Punar rolls back a bad update
    your data   446 GiB     encrypted · your files, everything Punar records

  Type the disk's serial to continue        S64ANS0T______

                                                       ESC cancels · ↵ install
```

Rules:

- **The confirmation token is the disk serial**, not the word "yes" and not
  a checkbox. It is device-specific, it is on the screen above, and it is
  impossible to type by accident or muscle memory. When there is no serial,
  it is the model plus size string.
- **What is being destroyed is enumerated**, by reading the existing
  partition table and filesystem labels. "All data will be lost" is a
  sentence people have learned to scroll past; *"1 NTFS partition, 465 GB,
  labelled Windows"* is not.
- **Slot B is explained where it costs disk**, not in a manual. A user who
  sees 8 GiB spent twice deserves the sentence that justifies it.
- The confirmation produces the `plan_token` of §7.2. **The screen the user
  agreed to and the bytes written are the same object** — a mismatched
  token is refused (I36b).
- No `--force`, no expert mode, no hidden override. The one escape hatch is
  the unattended answer file (§10.1), which carries the same serial and is
  recorded as `initiated: unattended` in the install record.

Dual-boot and free-space installs are **out of scope** and said so on the
stage rather than half-built: *"Punar installs to a whole disk. Installing
beside another operating system is not supported yet."* Omarchy added
free-space dual-boot in 4.0; this is a real gap and it is in §13.

### 6.4 The account: there is no account stage

**`docs/design/onboarding.md` §4.2 decided this seam, and this document
honours it rather than restating it: the installer creates no user account
whatsoever.** No `punar`, no first administrator, no service account, no
placeholder. The image it writes contains **no login-capable user**, and
root is locked with no password.

That is a stronger statement than "the account is somebody else's stage",
and it has a mechanical consequence the installer owns: the payload it
writes must itself be accountless, which is what §8's build-time assertion
A1 enforces on the release image. The Ubuntu model — an installer that
creates an account — is not merely declined here; the image makes it
impossible.

**The six requirements `onboarding.md` §4.4 places on this document, and
where each is answered:**

| # | Requirement from `onboarding.md` §4.4 | Answered |
|---|---|---|
| 1 | Ship an image with **no login-capable user account** — no `punar`, no autologin, root locked | **§8.** Enumerated (items 1, 2, 4, 6), removed by profile split, enforced by build-time assertions A1–A4, proven by I22–I24 and I29. |
| 2 | Create `/var` and `/home` per ADR-003, with `/var/lib/punar` present and `0700 root:root` before first boot | **§4.1, §4.3, §7.3** (`seed` phase). Proven by I15, I16, I30. |
| 3 | Write `seed.json`, or write nothing | **Below.** Written at the `seed` phase; absent on a failed install, which is the "write nothing" case and is exactly why onboarding treats it as advisory. |
| 4 | Own the disk secret and the disk recovery key entirely; display them at install time; first boot never shows, stores or asks for them | **§5.2, §5.3.** The recovery key never reaches a stream that a log or a state file can see, so first boot could not read it even if it tried. |
| 5 | Reserve ESP room for the §1.8 **Layer-2 recovery entry** as a fourth UKI, or record that Layer 2 does not exist | **Both halves answered.** The room exists: the ESP is 1 GiB, ADR-003 sizes it for three UKIs at ≈ 360 MB used, and a fourth at ≈ 120 MB brings it to ≈ 480 MB — under half. **The artefact does not exist**: `punar-recover` is not built, no fourth UKI is produced, and this design does not build one. So `onboarding.md` §1.8 **Layer 2 is dashed**, and this document carries the matching line in §12. *(Revisited 2026-08-26 against `onboarding.md` §1.6.2, which shows the consequence is larger than "one recovery layer is missing": with root locked and nobody in `wheel`, a `punard` that will not start on a fresh install is unrecoverable. **§12.1 is this document's answer**, and it recommends blessing slot B as the cheap interim.)* |
| 6 | Accept `oobe-answers.json` as a passthrough artefact it writes and never interprets | **Below.** Copied byte-for-byte; never parsed beyond a size cap. |

**The seam, and what the installer writes.**

`/var/lib/punar/install/seed.json`, `0644 root:root`, written at the `seed`
phase, in the shape `onboarding.md` §4.3 defines:

```json
{ "v": 1, "locale": "C.UTF-8", "keymap": "us",
  "installedAt": "2026-08-26T09:14:03Z",
  "imageVersion": "punar-desktop-2026.08.26.1",
  "diskEncrypted": true,
  "diskRecovery": { "mode": "personal_copy" } }
```

Two rules govern it, and both are onboarding's:

1. **It is a hint, never authority.** Missing, truncated or malformed, first
   boot falls back to its own defaults and shows the user nothing. So the
   installer writes it last, after every phase that can fail — a half-written
   seed is worse than no seed.
2. **`diskEncrypted` is load-bearing for honesty, not for behaviour.** It is
   how first boot knows whether the sentence *"nothing on this disk can be
   recovered"* is true on the device printing it. An installer that opted
   out of encryption (§5.1) must say so here, or first boot prints a false
   sentence — which is §1.22 failing across a seam rather than inside a
   file.

`/var/lib/punar/install/oobe-answers.json`, when the answer file supplied
one: **copied verbatim, never parsed.** The installer applies a size cap and
a "is it valid UTF-8" check and nothing else. It does not validate it
against onboarding's schema, does not normalise it, and does not act on any
field — including `account`, which it must not read and has no use for. An
installer that understood the account fields would be an installer that
could create an account, which is the thing this section refuses.

**What the installer emphatically does not decide**, and where it lives
instead: username rules, password policy, the account recovery code,
group membership and the bootstrap rule, the device name, whether accounts
live in `/etc` or in `userdb` records — all `onboarding.md` §1. The
installer's only interaction with any of it is negative: it ships an image
where none of it has happened yet.

### 6.5 Progress that tells the truth

Nine phases, named, in order, each either done, running or waiting. The
rule that keeps it honest:

> **A progress bar exists only where a denominator exists.** Everything
> else is a checklist.

Exactly one phase has a real denominator — `write-slot-a`, whose total is
`release.json`'s `payload.uncompressed_size_bytes`. It gets a bar and a byte count.
The other eight get a state and, where they have one, a real number.

```text
PUNAR · INSTALL                                          Stage 07 of 08

  ✓ verify        release 2026.08.26.1 · manifest signature ok
                  SIGNING KEY · SIMULATED · per-build key, custody unresolved
  ✓ partition     4 partitions · ADR-003 layout
  ✓ encrypt       LUKS2 · argon2id · recovery key enrolled
                  TPM-ASSISTED UNLOCK · SIMULATED · NOT ENROLLED
  ✓ write it down the recovery key was shown and acknowledged (§6.5.2)
  ✓ format        btrfs · @var @home @var-tmp · vfat /efi
  ▸ write slot A  ███████████████░░░░░░░░  1.9 / 3.1 GB
                  reading from the medium, writing to root A, hashing as it goes
    re-read       waiting — Punar reads slot A back and compares the digest
                  before it will boot from it
    boot          waiting
    seed          waiting
    verify        waiting

                                                      Do not remove the medium
```

Three rules behind that screen:

1. **No phase claims more than it did.** `verify` says the signing key is
   simulated because it is (user-blocked 7). A green tick beside a
   simulated claim, with no tag, is the failure mode §1.22 was written
   about.
2. **`re-read` is shown as a step, not hidden as an implementation
   detail.** It is the step that makes the install trustworthy —
   `update-and-rollback.md`'s verification order — and a user watching an
   installer spend thirty seconds "doing nothing" deserves to know it is
   reading back what it wrote.
3. **Failure names the phase and the disk state.** Before `partition` the
   disk is untouched and the message says so. From `partition` onward it is
   not, and the message says *that*: *"The install stopped at write slot A.
   The disk has been partitioned and is not bootable. Nothing was written to
   your old data — it was erased when partitioning began. Next step: restart
   the installer."* §73's five questions, answered, including the one nobody
   answers: what state am I in now.

### 6.5.1 Interruption, and what the disk is when the lights come back

> **The install is not resumable, it is restartable, and the design's job is
> to make restarting always safe rather than to make resuming possible.**

Nothing in §6.5 survives a power cut, and a partial `install.apply` leaves no
journal to replay. That is a deliberate simplification and it is only
defensible because of where the disk can be when it happens:

| Interrupted during | Disk state | Is restarting safe? | What the next boot shows |
|---|---|---|---|
| `verify` | **Untouched.** Not one byte written. | yes | The old system still boots |
| `partition` | A new GPT, possibly half-written; the old table is gone | **yes** — there is no user data on this layout yet | Firmware finds nothing bootable; boot the medium again |
| `encrypt`, `format` | Punar layout present, LUKS header possibly incomplete | **yes**, same reason | as above |
| `write-slot-a`, `re-read` | Slot A partial; digest will not match | **yes** | as above |
| `boot`, `seed` | Slot A complete; ESP or `/var` seeding incomplete | **yes** | Possibly boots to a system with no `seed.json`, which first boot treats as the advisory-missing case (§6.4) |

**The one row that is not in that table, and is the dangerous one:** a
**reinstall over a disk that already carries `PUNAR-DATA`**. From `partition`
onward that partition's contents are gone, and unlike every other row above
there *was* something there. So:

- `install.plan` reads the target's existing table. If it finds a partition
  labelled `PUNAR-DATA` **or** a LUKS2 header, stage 06 enumerates it as its
  own line — *"1 Punar data partition, 446 GB, encrypted · Punar cannot see
  what is inside it and cannot recover it"* — and the destructive
  confirmation is unchanged in mechanism and louder in wording. Punar does not
  offer to preserve it, because preserving it is repair mode (§13) and half a
  repair mode is worse than none.
- **There is no "resume the previous install" offer.** An interrupted install
  and a deliberate reinstall are indistinguishable from the disk, and an
  installer that guesses which one it is guessing about a person's data.

**A GPT is not written atomically, and the design does not pretend otherwise.**
`systemd-repart` writes the primary header, the entries and the backup header
in that order; a cut between them yields a table one tool calls valid and
another calls repairable. The mitigation is the row above — *restarting is
always safe* — not a claim of atomicity. Recorded in §12.

**Two Punar disks, scoped correctly.** §4.2's fixed-PARTUUID refusal is a
refusal about *other* disks: `install.plan` fails when a **non-target** block
device carries any of the four literal PARTUUIDs, and it names that device.
The target itself carrying them is the ordinary reinstall case and must not be
refused — a rule worth writing down because the naive implementation of §4.2's
sentence bricks reinstallation. Assertion I38.

### 6.5.2 The recovery-key gate — an ordering correction

*(Corrected 2026-08-26. An earlier draft of §6.2 displayed the disk recovery
key at stage **05**, before the destructive confirmation at stage 06. That is
not implementable: `systemd-cryptenroll --recovery-key` generates and enrolls
a key **into an existing LUKS2 header**, and no LUKS2 header exists until the
`encrypt` phase of stage 07. The draft screen showed a secret that had not
been created. This subsection is the fix.)*

Three ways out of the contradiction were available. The one chosen is the one
that keeps systemd's primitive:

| Option | Verdict |
|---|---|
| Generate 256 bits in `punard`, render modhex ourselves, enroll it as an ordinary keyslot passphrase | **Rejected.** It moves key generation and encoding into first-party code for a cosmetic ordering benefit, and it silently drops `cryptenroll`'s own recovery-key keyslot type — which is the thing that makes `cryptsetup luksDump` say *recovery* rather than *passphrase*, and the thing a future `systemd-cryptenroll --wipe-slot=recovery` would act on |
| Show the key at the **Done** stage (08) | **Rejected.** By then the install has succeeded and the machine is finished; a person is already reaching for the power button. The moment a secret must be written down is not the moment the flow is over |
| **Pause stage 07 immediately after `encrypt`** | **Chosen.** |

**The gate.** When the `encrypt` phase completes, `install.apply` **blocks**
before `format` and `/run/punar/install.json` gains
`phase: "encrypt", awaiting: "recovery_key_ack"`. The surface renders the key —
large, monospace, eight groups, QR beside it — and enables `Continue` only
when two randomly chosen groups have been typed back. Acknowledgement is a
second typed call, `install.recovery_ack {plan_token, groups_fd}`; the two
groups live in a sealed anonymous memfd, never in JSON. The same `plan_token`
binds the acknowledgement to the same object as the confirmation. The full
key and challenge indices travel only over the one-way pipe/Unix socket named
by `install.apply.recovery_output_fd`; neither can appear in a result or status
document. Nothing before this point is destructive-in-the-new-sense
(§6.5.1's table: at `encrypt` the old data is already gone, so the gate is not
a last chance to back out — it is a last chance to *keep the key*), and
nothing after it proceeds without it.

**What the gate does when nobody answers.** It waits. There is no timeout and
no default-continue: an installer that proceeds past an unacknowledged
recovery key has produced a device whose owner cannot recover it, which is the
exact outcome the key exists to prevent. `Esc` at this gate does not cancel
the install — the disk is already repartitioned — it re-renders the key. The
one escape is the unattended path, where `answers.json` carries
`recovery_key_ack: "unattended"`, the key is written to the answer disk's own
filesystem and **not** to the installed system, and the install record says
`recovery_key_ack: unattended` so that a device provisioned this way is
distinguishable forever from one a human acknowledged.

**Consequence for §6.5's phase list:** `encrypt` is followed by a named
waiting state rather than immediately by `format`, and the screen says so:

```text
  ✓ encrypt       LUKS2 · argon2id · recovery key enrolled
  ▸ write it down  the install is paused here until you have

    format        waiting
```

The **opt-out lane skips the gate entirely**, because there is no key. That is
the second place `diskEncrypted` is load-bearing (§6.4), and it is asserted in
both directions by I30.

### 6.6 No theme picker, and no app picker — in the installer

**Decided: the installer offers neither. Whether *first boot* offers a theme
is `onboarding.md`'s question, and it answered it** — two moods at stage 07,
`contrast` as an accessibility row at stage 01 (`onboarding.md` §3.1). This
document does not reopen that; it decides only its own surface, and it
decides against.

Against a genuinely good competitor feature (Omarchy's 22-theme live-preview
carousel):

1. `theme-system.md` §6.1 decided that theme selection is **a user
   preference file**, written to `~/.config/punar/theme.json`. **The
   installer has no user and no home directory to write it into** (§6.4).
   This is not a preference, it is an impossibility.
2. `theme-system.md` §5.5 argues the default *"should assert the least"*.
   A picker on the install medium is the most-assertive possible moment: it
   demands an aesthetic decision from someone who has not seen a single
   Punar surface in use and does not yet own the machine.
3. **D-008 has seven stages and no theme stage on the install side.** The
   plate is the acceptance reference.
4. The person running the installer may not be the person who uses the
   machine — the imaged-fleet case of §6.2. A technician choosing the
   theme for 200 strangers is the same error as a technician creating their
   accounts.

`onboarding.md` §3.1 makes the accessibility half of this work anyway, and
better than an installer could: it puts `contrast` on stage **01**, on the
argument that *the person who needs high contrast cannot read stage 07*.
The installer inherits nothing from that except the obligation not to
contradict it — so the **Done** stage says nothing about themes at all, and
the discoverability line belongs to first boot's Ready stage where a user
exists to receive it.

On applications, the same answer with a stronger reason: `app-catalog.md`
§2.5 establishes that **a preinstall cannot be permanently removed** on an
A/B system, so an install-time application picker would offer choices it
cannot honour. And installing anything not in the image requires a network
the install deliberately does not need.

### 6.7 Keyboard grammar

Inherited wholesale from D-008 §IV and `keyboard-grammar.md`; the installer
introduces no new grammar:

`←` `→` move between stages · `↵` acts on the current stage · `Tab` /
`Shift+Tab` move within a stage · `Esc` cancels the current stage's edit and,
on stage 06, cancels the install · single letters make binary choices.
Bindings are printed in the frame footer, never hidden. **The pointer works
and is never required.** No stage shows, requires or suggests a shell
command, and there is no terminal in the live environment's session — the
`PUNAR+RETURN` bind is absent from the installer profile's Hyprland config,
because "no shell commands" is a property of the surface, not a request to
the user.

---

## 7. Decision 5 — what the installer is not allowed to do

> **The installer is the single most privileged thing Punar will ever run,
> and it is the last place to invent a shortcut around the typed-capability
> architecture.**

### 7.1 It runs `punard` — the same binary, from the same image

**Decision: the live environment starts the ordinary `punard.service` from
the ordinary image, and the installer is a client of it.**

Alternatives considered and rejected:

| Option | Verdict |
|---|---|
| A dedicated `punar-installd` | **Rejected.** A second daemon means a second policy engine, a second audit writer, a second socket contract, a second admission rule, and a second implementation of the capability backends and validators the running system already owns. Every one of those is a place the installer and the running system can disagree, and disagreement in the most privileged code path is the worst possible place for it. |
| A privileged helper script invoked by the QML surface | **Rejected on sight.** That is a generic root path with a UI in front of it, which is §60's prohibition wearing a hat. |
| `punarctl` doing the work directly as root | **Rejected.** `punarctl` is a client (`ipc.md` §7). Making it a privileged actor for one use case destroys the property that the CLI has no authority the daemon did not grant. |
| **The same `punard`, with `install.*` gated on live mode** | **Chosen.** |

What that buys, concretely:

- **One audit writer.** The install's events are written by the same
  schema-conformant appender as everything else, and at the `seed` phase the
  live audit log is copied to `/var/lib/punar/audit/` on the new system.
  **The device's audit trail begins with its own installation.** An install
  that leaves no record in the machine it created is a hole in §53.
- **One set of capability backends.** The keymap chosen at stage 01 is
  recorded through the same code that reads `system.keymap`, not a
  parallel config writer — and it is recorded as a hint, because the
  capability is applied on the installed system by first boot, not here.
- **One admission model.** `SO_PEERCRED`, root-only mutation, the M9 AI
  authority path in front of the uid check. An agent-attributed peer calling
  `install.apply` hits the AI path first and is denied by a named rule —
  which matters, because "reinstall the operating system" is precisely the
  verb §60 exists to keep away from AI.

**The gate.** `install.*` is registered only when `/proc/cmdline` contains
`punar.live=1`. Only the installer UKI carries that token; the slot UKIs
carry `root=PARTUUID=…` and not it. On an installed system `install.apply`
returns `unknown_method` — the same answer `system.exec` gets, from the same
closed method table (I33).

**Honest note on the gate's strength.** The kernel cmdline is embedded in
the UKI, so the gate is exactly as strong as the signature over that UKI —
which is **SIMULATED** (user-blocked 1). Someone who can write to the ESP
can make an installed system live-mode. That is the same someone who can
replace the kernel outright, so the gate adds no new exposure; it is
recorded here rather than presented as a boundary it is not.

### 7.2 The typed surface

Proposed additions to `ipc.md` §5's closed method table. This document
proposes; the owners of `ipc.md` and `schemas/` decide.

| Method | AuthZ | Mutating | Audited |
|---|---|---|---|
| `install.targets` | any connected peer | no | no |
| `install.plan` | **root only**, live mode only | no | **yes** |
| `install.apply` | **root only**, live mode only; agent-attributed peers take the M9 AI path first | yes | always |
| `install.status` | any connected peer | no | no |

- **`install.targets`** enumerates block devices from `/sys/class/block`
  with model, serial, size, current partition table and detected
  filesystems. Read-only. It excludes the medium the installer booted from,
  by device, because offering to erase the thing you are running from is a
  bug with a UI — **and it excludes any device carrying a filesystem labelled
  `PUNAR_ANSWERS`** for the same reason one level up: the unattended path's
  answer disk is an input to the install, and an install that erases its own
  answer file has destroyed the record of what it was told to do. In CI the
  1 MiB answer disk would also fail the 33 GiB floor, but relying on a size
  check to protect an input is relying on an accident.
- **`install.plan`** takes the answers and returns the *entire* resulting
  layout — partition numbers, type GUIDs, literal UUIDs, byte offsets,
  sizes, filesystems, subvolumes, both the compressed-artifact and
  uncompressed-slot payload digests — **plus the target's
  physical identity: `disk.serial`, `disk.wwn` when present, `disk.size_bytes`,
  and `disk.existing_gpt_sha256`, the digest of the first and last 34 LBAs as
  they were read** — and then
  `plan_token = sha256(canonical_json(plan))`.

  **Why the physical identity is inside the hashed object and not beside it.**
  A plan that binds only to a *device node* binds to nothing: `/dev/sda` is an
  enumeration artefact, and a USB enclosure unplugged and replugged between
  stage 03 and stage 06 can hand the same node to a different physical disk.
  Because the serial is inside the canonical JSON, the token the user's typed
  serial produced is the token of *that* disk, and `install.apply` re-reads
  the target's serial, size and GPT digest **immediately before the first
  write** and refuses `invalid_params` on any mismatch — including the
  benign-looking one where the existing table changed because something else
  touched the disk while the user was reading stage 06. This is the assertion
  I37, and it is the difference between confirming a screen and confirming a
  disk. It is **audited despite
  being non-mutating**, for the same reason `update.check` is: it is the
  first observable step of an install, and a trail that begins at `apply`
  cannot explain what the device was asked to do.
- **`install.apply`** takes `{plan_token, disk, passphrase_fd,
  recovery_output_fd, keymap, seed, oobe_answers_fd, unattended}` — **and no
  `account` object, because
  the installer creates no account** (§6.4). It **refuses any token that is
  not the hash of a plan produced in this boot for this disk**
  (`invalid_params`, I36b). No free-form parameters: no partition sizes, no
  filesystem options, no command strings, no paths outside the fixed set.
  `oobe_answers_fd` is copied to the new system byte-for-byte and is never
  parsed. The definitions come from
  `/usr/share/punar/repart.d/`, on disk, in the image, unmodifiable without
  a release.
  Both input descriptors must be sealed anonymous memfds; ordinary files and
  unsealed memory files are refused. This makes “no secret on disk” an
  enforced admission rule rather than a promise the UI is expected to keep.
  `recovery_output_fd` is different by direction and accepts only a pipe or
  Unix socket; a regular file is refused so the one-time disclosure cannot be
  redirected to persistent storage by accident.
- **`install.status`** is the read side of `/run/punar/install.json`.

There is **no** `install.exec`, no `install.script`, no `install.chroot`,
no `install.postinstall_hook`, and no way to supply one. §10's
*"Prohibited: RunRootShell(command)"* and §60 are not negotiated down
because the installer is special; the installer is where they matter most.

Audit events, all using the existing twelve-key schema with no change:

| `action` | `resource` | `result` |
|---|---|---|
| `install.plan` | `system_disk` | `success`, `refused`, `failure` |
| `install.apply` | `system_image` | `success`, `denied`, `failure` |
| `install.encrypt` | `system_disk` | `success`, `skipped_by_user`, `failure` |
| `install.recovery_key` | `system_disk` | `enrolled` — **and nothing else; no material, ever** |
| `install.hardware_report` | `system_hardware` | `full`, `partial`, `unsupported` |

### 7.3 The privileged operations, exhaustively

Every privileged thing the install does, and the fixed argv or syscall
behind it. There is nothing else on the list, and the list is the
specification.

| Phase | Operation | Mechanism |
|---|---|---|
| verify | manifest signature, compressed payload digest/size and uncompressed slot digest/size | in-process ed25519 + sha256; trusted keys from `/usr/share/punar/keys/release/*.pub` |
| partition | create the GPT | `systemd-repart` with `--definitions=` pointing at the shipped directories only |
| encrypt | LUKS2 format + enroll | `systemd-repart` `Encrypt=key-file`, key on an FD; `systemd-cryptenroll --recovery-key` |
| format | vfat + btrfs + subvolumes | `systemd-repart` `Format=` / `Subvolumes=` |
| write-slot-a | stream payload → slot A | `repart` `CopyBlocks=`, or a bounded 4 MiB read/write loop in `punard` — the same loop `update.apply` uses |
| re-read | digest slot A | `fsync`, **close, and re-open the block device `O_DIRECT`**, then read `payload.uncompressed_size_bytes` bytes, sha256, and compare `payload.uncompressed_digest_sha256`. **This detail is the whole value of the phase:** a re-read served out of the page cache re-hashes the buffer that was just written and proves nothing about what reached the platter, which is the failure the step exists to catch. `update-and-rollback.md` §4.2 specifies `fsync` then re-read but does not say how the cache is defeated; this design pins it, and pins it in the shared code path so the update flow inherits it. **TO VERIFY** at the pin: `O_DIRECT` on the target block device with the 4 MiB aligned buffer the write loop already uses (the fallback, if alignment proves awkward under a device-mapper stack, is `BLKFLSBUF` on the fd before the re-read — weaker, still not a buffer hash, and named rather than assumed) |
| boot | ESP contents | `bootctl install --esp-path=… --no-variables`; copy the slot UKI; write `loader.conf`. **`--no-variables` is a decision, not a default** (§7.3.1) |
| seed | shared partition | create `/var/lib/punar` (`0700 root:root`), `machine-id`, the device id, the hardware report, `install/seed.json`, the `oobe-answers.json` passthrough; copy the audit log. **No account.** |
| verify | post-install check | re-open read-only, compare against the plan |

**Implementation checkpoint (2026-08-30).** The internal `punard` executor
now implements the first six rows through re-read, while the public
`install.apply` method remains deliberately absent. Disk preparation invokes
one fixed `systemd-repart` transaction for the partition/encrypt/format rows:
it merges only the immutable base, LUKS2 and streaming layers, revalidates the
plan at the destructive boundary, requires a block device, and provides the
passphrase on anonymous stdin. Status reports `partition` while the combined
transaction is in flight, then stops in `encrypt` for encrypted plans while
the pinned `systemd-cryptenroll` primitive generates and enrolls its typed
recovery key. The passphrase enters only on anonymous stdin and the key leaves
only on bounded anonymous stdout into a zeroizing owner; bounded LUKS metadata
identifies the `systemd-recovery` keyslot. The personal lane is wired to the
no-timeout two-group acknowledgement gate and cannot enter `format` until it
succeeds. Organization receipt orchestration, boot, seed, final verification
and the integrated audit path remain unimplemented, so this checkpoint is
not an installability claim.

Five external binaries, all from the image, all with fixed argv, all with
validated parameters. No `chroot`. No `arch-chroot`. No `pacstrap`. No
`bash -c`. Nothing read from the answer file ever becomes part of a command
line.

#### 7.3.1 Firmware boot entries — the one privileged write that is *outside* the disk

`bootctl install` writes an EFI boot variable by default, so the installer
would be mutating firmware NVRAM — the only thing it touches that is not the
disk the user confirmed, and the only one a failed install cannot leave
untouched.

**Decision: `--no-variables`, plus the removable-media path.** The installer
writes `EFI/BOOT/BOOTX64.EFI` on the target ESP and does **not** create or
reorder a firmware boot entry. Reasons, in order:

1. **The destructive confirmation is scoped to a disk.** A user typed a
   serial. Reordering the machine's boot menu is a consequence they did not
   confirm and — on a machine with another operating system on another disk —
   is the one way a whole-disk installer can affect a disk it never wrote to.
2. **NVRAM is the least reliable write on the machine.** Firmware that
   silently drops, reorders or exhausts boot variables is common on exactly
   the 2019–2022 §5.3 target classes, and a variable write that half-succeeds
   is not restartable the way §6.5.1's disk states are.
3. **The fallback path is universal.** Every UEFI implementation boots
   `\EFI\BOOT\BOOTX64.EFI` from a disk in the boot order; that is how the
   ISO itself boots.

**The honest cost, stated:** on a machine with an existing OS whose firmware
entry ranks above disk-order fallback, the user must choose the Punar disk
from the firmware's own boot menu on first boot. Stage 08 says so in one line
rather than leaving them at a screen that boots the old system. A future
`--variables` mode is a Phase-2 option gated behind an explicit question, not
a default. Recorded in §12.

---

## 8. Decision 6 — dev-convenience removal

> **A profile split is a convention. A build that fails is a mechanism.
> This design ships both, and a check that proves it afterwards.**

### 8.1 The enumeration

Everything in today's images that must never reach an installed system.
Compiled by reading `os/images/` rather than by remembering.

| # | Artefact | Where it is today | Why it must not ship |
|---|---|---|---|
| 1 | `RootPassword=punar` | `mkosi.conf` | A published root password on every device. |
| 2 | `Autologin=yes` | `mkosi.conf` | Console autologin as root. |
| 3 | `console=ttyS0` on the cmdline | `mkosi.conf` `KernelCommandLine=` | A root console on a serial port. Harmless in QEMU; a physical port on a laptop is not a hypothetical. |
| 4 | user `punar`, password `punar`, group `wheel` | `mkosi.profiles/desktop/mkosi.postinst.chroot` | A published account with admin group membership. |
| 5 | `punar:100000:65536` in `/etc/subuid`, `/etc/subgid` | same file | Follows the user. |
| 6 | `[initial_session]` autologin | `desktop/mkosi.extra/etc/greetd/config.toml` | Graphical autologin with no authentication. |
| 7 | `punar-mock-smplify.service` + `/usr/bin/punar-mock-smplify` + `/usr/share/punar/fixtures/acme/` | desktop profile | **A mock control plane on a real device.** The single most dangerous item here: a device that can be told what its policy is by a local fixture. |
| 8 | `punar-m2…m10-check.service` (9 units) + `/usr/lib/punar/m*-check.sh` | desktop profile | CI harness with root privileges, running exercises that mutate state (M4's check destroys the firewall table on purpose). |
| 9 | `punar-boot-marker.service`, `punar-desktop-marker.service`/`.path` | base + desktop | CI sentinels on the serial console. |
| 10 | `punar-idle-ram.service`, `/usr/lib/punar/idle-ram.sh` | desktop | A 15-minute measurement run at every boot. |
| 11 | `punar-desktop-diag.service`/`.timer` | desktop | A periodic wakeup — and §6.3 forbids exactly that. |
| 12 | `/usr/lib/punar/foo-agent-fixture.sh`, `punar-mock-agent`, `in-agent-scope.sh`, `desktop-ready.sh` | desktop | Test fixtures, one of which impersonates an AI agent. |
| 13 | `/usr/share/punar/fixtures/**` (Acme org, Atlas project, exec-trust binaries) | desktop | Fixture data, including a deliberately unsigned executable. |
| 14 | `Hostname=punar-dev` / `punar-desktop` | `mkosi.conf` + CLI | Every device on a network named `punar-desktop`. |

### 8.2 The profile split

```text
mkosi.conf                       no RootPassword, no Autologin, no console=ttyS0
mkosi.profiles/desktop/          product content only
mkosi.profiles/installer/        + cryptsetup, btrfs-progs, gptfdisk, the
                                   installer surface, punar.live=1
mkosi.profiles/dev/              items 1–14 above, all of them, and nothing else
```

Built as:

```text
CI / development   mkosi --profile desktop,dev
The ISO's payload  mkosi --profile desktop
The live ISO root  mkosi --profile desktop,installer
```

The dev profile is not deleted and must not be — the 542 in-VM assertions
across M2–M9 depend on it, and losing them to gain a clean image would be a
catastrophic trade. It simply stops being reachable from a release build.

### 8.3 The build-time assertion

`os/images/mkosi.finalize`, run by mkosi over the assembled tree on every
build. When `dev` is **not** in `$PROFILES`, it exits non-zero if any of
these is true:

```text
A1  any account anywhere in the image has a usable authenticator — i.e.
    /etc/shadow contains a password field that is not '!', '*' or '!!'.
    This is onboarding.md §4.4 requirement 1 as a build failure: the
    release image contains NO login-capable user.   (items 1, 4)
A2  getent passwd punar succeeds                (item 4)
A3  /etc/subuid or /etc/subgid mentions punar   (item 5)
A4  /etc/greetd/config.toml contains the string "initial_session"   (item 6)
A5  any path matching these globs exists:                    (items 7–13)
      usr/lib/systemd/system/punar-m*-check.service
      usr/lib/systemd/system/punar-surface-cost-check.service
      usr/lib/systemd/system/punar-surfaces-check.service
      usr/lib/systemd/system/punar-wifi-check.service
      usr/lib/systemd/system/punar-mock-smplify.service
      usr/lib/systemd/system/punar-boot-marker.service
      usr/lib/systemd/system/punar-desktop-marker.*
      usr/lib/systemd/system/punar-desktop-diag.*
      usr/lib/systemd/system/punar-idle-ram.service
      usr/lib/punar/m*-check.sh
      usr/lib/punar/surface-cost-check.sh
      usr/lib/punar/surfaces-check.sh
      usr/lib/punar/wifi-check.sh
      usr/lib/punar/idle-ram.sh
      usr/lib/punar/desktop-ready.sh
      usr/lib/punar/foo-agent-fixture.sh
      usr/lib/punar/punar-mock-agent
      usr/lib/punar/in-agent-scope.sh
      usr/bin/punar-mock-smplify
      usr/share/punar/fixtures
A6  any *.wants symlink points at a unit matching the A5 globs
A7  /etc/sudoers.d/* contains NOPASSWD
A8  the UKI cmdline contains "console=ttyS0", "console=ttyAMA0" or "punar.live"
    (the installer profile is exempt from the punar.live half, and only
     that half, and it is exempt by name rather than by pattern)
```

**Why an allowlist is not used instead.** A positive allowlist of every file
that may ship would be stronger and is the right long-term answer; it is
also a several-thousand-line artefact that goes stale on every package bump
and would be maintained by suppression. The denylist above is exact, it
covers every artefact this repository creates, and A9 closes the gap:

```text
A9  the set of enabled units under both
    usr/lib/systemd/system/*.target.wants/* and
    etc/systemd/system/*.target.wants/* is byte-equal to the committed,
    architecture-specific expected-enabled-units manifest. This covers both
    vendor links and links created by preset-all. Any new enabled unit fails
    the build until someone edits that file, which is exactly the moment to
    ask whether it should ship.
```

A9 is the important one: it is an allowlist over the surface that actually
matters (things that *run*), and it is small enough to keep true.

### 8.4 The proof after the fact

A build-time assertion proves the tree; it does not prove the *installed
device*. `tools/install-test.sh` runs I22–I29 (§10.2) against the installed
system, from inside it, over the serial console. Both, because the failure
mode being defended against is "someone changed the pipeline", and a check
that lives in the pipeline cannot see that.

**No-diffutils note.** The image has no `diff`. Golden-set comparisons in
guest are done by `sort` + `sha256sum` of the two lists, and on mismatch the
script prints both lists in full for the log. Every new check script is
committed `0755`.

---

## 9. Decision 7 — hardware reality

> **Punar has never touched hardware. This section designs what happens
> when it does, and claims nothing about whether it works.**

### 9.1 Firmware

`linux-firmware` is deliberately excluded today, for a good reason that
stops being good the moment there is an installer: QEMU virtio needs none,
and the image is VM-only. An ISO that boots on a laptop needs:

| Package | ≈ installed | Why |
|---|---|---|
| `linux-firmware` | ≈ 500 MB (≈ 250 MB compressed) | Wi-Fi, Bluetooth, AMD/Intel GPU firmware. Without it, most §5.3-class machines have no network and many have no display. |
| `sof-firmware` | ≈ 60 MB | Audio on essentially every 2019+ Intel laptop. |
| `intel-ucode` + `amd-ucode` | ≈ 15 MB | Microcode. **Both**, because one image ships to both vendors, and it must be in the initrd, not merely on disk. |

Against ADR-003's `R_max = 5 GB` inference that is **≈ 11 %** of the image
budget and it lands on the ISO twice (§3.1). It is not optional and there
is no clever way out: a machine that cannot see its own network card cannot
be told to go get a driver.

**This is a slot-sizing input.** ADR-003's revisit trigger — *"measured
desktop image size exceeds ~5 GB, making 8 GiB slots wrong"* — is closer
after this section than before it. Measuring the image is the first task of
the implementing milestone (§3.5), and if `1.5 × R_max` crosses 8 GiB the
answer is an ADR amendment, not a quietly bigger number.

### 9.2 Drivers — and the consequence of A/B nobody has written down

Omarchy ships, as evidence rather than marketing: `nvidia-dkms` /
`nvidia-open-dkms` / `nvidia-580xx-dkms`, `intel-media-driver`,
`intel-ipu7-camera`, `vulkan-radeon`, `vulkan-asahi`, `linux-t2` +
`apple-bcm-firmware` + `t2fanrd`, `dell-xps-touchpad-haptics`, `qmk-hid`,
`linux-firmware-marvell`, `asusctl`, `tuxedo-drivers`.

**Punar cannot answer that list the way Omarchy does, and the reason is
architectural.** On a package-based system, an unknown device is a
`pacman -S` away. On an A/B system, slot B is *built, not mutated* — so:

> **On a Punar device, "install the driver afterwards" does not exist.**
> Anything a device might need must be in the image, or in a mechanism that
> survives a slot swap. DKMS is not such a mechanism: it compiles against a
> running kernel into a filesystem that the next update replaces wholesale.

That is the sharpest consequence of ADR-003 and no document in this
repository has stated it. It is not a reason to reopen ADR-003 — the update
guarantee is worth more than out-of-tree modules — but it changes what
"hardware support" means, and it must be said before someone promises
NVIDIA.

**The MVP decision: integrated Intel/AMD graphics only.** This is not a
retreat; it is §5.1 read literally (*"supported integrated Intel/AMD
graphics"*) and §5.3's target classes are exactly the machines that have
them. In practice that means the in-tree `i915`/`xe` and `amdgpu` drivers
plus `mesa`, `vulkan-intel`, `vulkan-radeon` and `intel-media-driver` /
`libva-mesa-driver` in the image.

The rest, named and costed rather than hand-waved:

| Want | Mechanism it would need | Verdict |
|---|---|---|
| NVIDIA | A signed prebuilt module built per kernel release and shipped **inside the image** — i.e. a per-GPU-vendor release variant and a per-release build commitment. Or in-tree `nouveau`/`nova`, which is not a serious answer for a workstation. | **Deferred, named.** This is a release-pipeline decision, not a package. |
| Framework / Surface / T2 quirks | Per-model release variants, or upstreaming the quirks. | **Deferred.** Blocked on user-blocked item 3 regardless: nobody can package a quirk for a machine nobody has. |
| Printing (`cups`), Bluetooth (`bluez`), Wi-Fi management (`iwd`) | Ordinary packages, ordinary preinstall arguments under app-catalog §2.1. | **Not in this document.** They are image-content decisions and belong to app-catalog. Named here because an installer makes their absence user-visible for the first time. |

### 9.3 What an install does when it meets hardware it does not know

Stage 02, before any commit, in the design language's own coverage
vocabulary — `FULL` / `PARTIAL` / `UNSUPPORTED`, always with reasons, shown
before commit, because **silence is not support** (§7).

The mechanism is entirely offline and uses only what the kernel package
already ships:

1. Walk `/sys/bus/pci/devices` and `/sys/bus/usb/devices`; read each
   device's `modalias`, class and vendor/device ids.
2. Resolve each `modalias` against `/lib/modules/<ver>/modules.alias` — the
   kernel's own table, already in the image, no database, no network.
3. Classify:
   - **FULL** — a module claims it and is loaded, and any firmware file it
     requests is present.
   - **PARTIAL** — a module claims it but a requested firmware file is
     missing, or the module is present and did not bind.
   - **UNSUPPORTED** — no module in this kernel claims this modalias.
4. Render, grouped by function (graphics, network, storage, input, audio,
   Bluetooth, other), with the device's real name and the reason on each
   non-FULL row.

```text
PUNAR · INSTALL                                          Stage 02 of 08

  What Punar found on this machine

  GRAPHICS     FULL          Intel Iris Xe (TGL GT2) · i915
  STORAGE      FULL          Samsung 980 NVMe · nvme
  NETWORK      FULL          Intel Wi-Fi 6 AX201 · iwlwifi
  AUDIO        PARTIAL       Intel Smart Sound · snd_sof_pci_intel_tgl
                             firmware present, never tested on this model
  BLUETOOTH    FULL          Intel · btusb
  INPUT        FULL          i8042 keyboard, ELAN touchpad
  FINGERPRINT  UNSUPPORTED   Goodix 27c6:5395 · no driver in this kernel

  Punar has never been tested on this machine. Nothing here is a promise.

                                                        ↵ continue · ← back
```

**What blocks an install and what does not.** Exactly two conditions block:
**no usable graphics** (nearly unreachable — you are looking at this screen)
and **no writable disk of at least 33 GiB**. Everything else warns and
proceeds. Refusing to install because a fingerprint reader is unknown would
be absurd, and an installer that refuses on ambiguity is an installer people
route around.

The report is written to `/var/lib/punar/hardware-report.json` at the `seed`
phase and rendered in System Control → SYSTEM, so **the machine keeps its
own honest coverage record** and a support conversation starts from a fact.

### 9.4 The honesty paragraph

None of §9 is verifiable. Every measurement in this repository comes from
emulated x86_64 QEMU on an arm64 macOS host with virtio-vga and llvmpipe.
The hardware report will produce a correct, deterministic, boring answer in
that VM — six virtio devices, all FULL — and that proves the *mechanism*
and nothing about *coverage*. Firmware quirks, GPU behaviour under Wayland,
suspend/resume, Wi-Fi, docking and external displays are discoverable only
on metal, which is **user-blocked item 3**, whose own proof criterion is a
per-model results table *"published honestly, including the models that do
not work."*

Until then, the correct sentence about Punar and hardware is the one on the
stage: **Punar has never been tested on this machine.**

---

## 10. Verification — what CI can prove, offline

### 10.1 The lane

`tools/install-test.sh`, new, committed `0755`, added to the existing
workflow beside `boot-test.sh`. Nothing in it needs a network.

```text
1  Build the ISO                       tools/build-image.sh (PUNAR_IMAGES=iso)
2  Create a blank 128 GiB sparse qcow2 the §5.1 minimum, exactly
3  Create the answer disk              a 1 MiB vfat image labelled PUNAR_ANSWERS
                                       carrying answers.json
4  Boot the ISO in QEMU (OVMF, virtio) serial console captured
5  Wait for PUNAR_INSTALL_DONE
6  Power off. Detach ISO and answers.
7  Boot the installed disk             passphrase fed on the console
8  Wait for PUNAR_BOOT_OK, then run the in-guest assertion script
9  Export results over the existing virtio-serial punar.export channel
```

**Unattended without a second artefact.** The same ISO is used. The
installer reads `answers.json` only when all of: `punar.live=1` is on the
cmdline; a filesystem labelled `PUNAR_ANSWERS` is present; the file
validates against `schemas/install/answers.json`; and its
`confirm_destroy_disk` field **matches the target disk's serial** — the same
device-specific token a human types at stage 06. The install record says
`initiated: unattended`. One artefact, one confirmation grammar, no
CI-only code path in the thing users receive.

The ISO is booted **twice** in step 4 — once as `-cdrom`, once as a raw
`-drive` — so the hybrid/USB path is exercised structurally (I05).

### 10.2 The assertions

Gating unless marked. **40 assertions.**

**Artefact (host-side, on the built ISO — no VM):**

| # | Assertion |
|---|---|
| I01 | The ISO is produced from the pinned snapshot by `tools/build-image.sh`; `xorriso -indev … -toc` lists exactly the expected top-level entries and no others. |
| I02 | The appended ESP partition contains `EFI/BOOT/BOOTX64.EFI` and **exactly one** UKI; that UKI's `.cmdline` section contains `punar.live=1` and **no** `root=PARTUUID=`. |
| I03 | `release.json` validates against `schemas/update/release-manifest.json`; its `payload.digest_sha256` equals the sha256 of the compressed payload file on the ISO; decompression yields exactly `uncompressed_size_bytes` with sha256 `uncompressed_digest_sha256`; `release.json.sig` verifies against the per-run ephemeral key. *(Key custody: SIMULATED, user-blocked 7.)* |
| I04 | The live erofs tree and the slot payload tree are **identical**: same file list, same modes, same per-file sha256, compared against `tree-manifest.json`. |

**Live boot:**

| # | Assertion |
|---|---|
| I05 | The ISO boots under OVMF **both** as `-cdrom` and as a raw `-drive`, reaching `PUNAR_INSTALLER_OK` on the serial console in each case. |
| I06 | In the live environment `punard` is running and `punarctl debug rpc install.targets` returns the blank 128 GiB disk and **does not** return the boot medium. |
| I07 | `punarctl debug rpc install.plan` returns a plan validating against `schemas/install/plan.json`, and a `plan_token` equal to the sha256 of its own canonical form. |

**The ADR-003 layout — the assertions that unblock other designs:**

| # | Assertion |
|---|---|
| I08 | `sfdisk --json` on the installed disk shows **exactly four** partitions, in order, with type GUIDs esp / root-x86-64 / root-x86-64 / linux-generic. |
| I09 | Partition 1 is **≥ 1 GiB** and its filesystem is vfat. |
| I10 | Partitions 2 and 3 are **each exactly 8 GiB**; their PARTUUIDs equal the two literals in `repart.d/install/` and **differ from each other**. |
| I11 | Partition 4's PARTUUID equals its literal, and it consumes the remainder — free space after it is < 1 MiB. |
| I12 | `cryptsetup isLuks` is true on partition 4; `luksDump` reports **LUKS2** with argon2id; the header UUID matches **no literal committed in this repository** (per-device randomness). |
| I13 | The btrfs filesystem inside carries subvolumes `@var`, `@home`, `@var-tmp` — and no others. |

**The installed system:**

| # | Assertion |
|---|---|
| I14 | The installed disk boots and `findmnt -no SOURCE /` resolves to the **slot A** PARTUUID. |
| I15 | **`findmnt --json` shows `/`, `/efi`, `/var`, `/home`, `/var/tmp` as five distinct mounts, and `/home`'s mount id is not `/`'s.** *(This is the assertion that makes `execution-trust.md` V3 true and the mount-mark design buildable.)* |
| I16 | `/var/lib/punar` is on the `/var` mount, not on the root slot. |
| I17 | The ESP holds systemd-boot and **exactly one** UKI (slot A's); slot B exists, is zero-filled, and has no UKI. |
| I18 | sha256 of the first `payload.uncompressed_size_bytes` bytes of slot A equals `release.json`'s `payload.uncompressed_digest_sha256`. |
| I19 | Booting with a **wrong** passphrase does not reach `PUNAR_BOOT_OK`; with the right one it does. |
| I20 | `/etc/fstab` and `/etc/crypttab` on the installed system are **byte-identical** to the vendor copies inside the payload (nothing per-device was written into `/etc` — ADR-003's rollback-hazard rule). |
| I21 | `/dev/shm` is mounted `noexec`. |

**Dev conveniences absent:**

| # | Assertion |
|---|---|
| I22 | `passwd -S root` reports `L`. **No account on the system reports a usable authenticator** — see I29, which states the stronger form. |
| I23 | `id punar` fails; `punar` appears in neither `/etc/subuid` nor `/etc/subgid`. |
| I24 | `/etc/greetd/config.toml` contains no `initial_session`; no getty `ExecStart` anywhere in `systemd-analyze cat-config` contains `--autologin`. |
| I25 | **None** of the fourteen §8.1 artefacts exists on the installed root (glob list, checked path by path, each reported individually so a failure names the file). |
| I26 | The slot-A UKI's `.cmdline` contains neither `console=ttyS0` nor `punar.live`. |
| I27 | `sha256sum` of the sorted enabled-unit list equals the committed `expected-enabled-units.txt` golden set; on mismatch both lists print in full. *(No `diff` in the image.)* |
| I28 | No file under `/etc/sudoers.d/` contains `NOPASSWD`. |

**The accountless image, and the seam to first boot:**

The brief for this design originally asked CI to prove that *"the account
created at install can log in."* `onboarding.md` §4.2 moved account creation
out of the installer, so the assertion moves with it — **the end-to-end
property is preserved and is proven across the seam**, in four parts rather
than one, and the middle two are the parts that would otherwise go
untested — a seam is exactly where a property gets dropped by both sides.

| # | Assertion |
|---|---|
| I29 | The installed system contains **no login-capable account**: every entry in the merged `passwd`/`shadow` view has a locked or absent authenticator, `id punar` fails, and `root` reports `L`. **An install that produced a usable account would fail here** — the negative form of the requirement, which is the form that can be checked. |
| I30 | `/var/lib/punar` exists, is `0700 root:root`, and is on the `/var` mount; `/var/lib/punar/install/seed.json` validates against `onboarding.md` §4.3's shape, `diskEncrypted` is `true` for both encrypted lanes and `false` for the opt-out lane, and `diskRecovery.mode` is exactly `personal_copy`, `organization_escrow`, or `none` as appropriate. When an `oobe-answers.json` was supplied it is present and **byte-identical** to the file the answer disk carried. |
| I31 | **The seam works end to end.** With `seed.json` in place, first boot runs (no `first-boot.json` marker exists for any user, because no user exists), its Account stage creates the account, and **that account then logs in** — `su - <user>` on the serial console succeeds. This assertion is `onboarding.md`'s check invoked from the install lane rather than a second implementation of it, so a change on either side of the seam breaks it exactly once. |
| I32 | The keymap chosen at install is **pre-selected** on first boot's stage 01, labelled `from install`, and a **missing or corrupt `seed.json` degrades to the defaults with no error shown** — the advisory-not-authority rule, tested in its failing direction, which is the direction that matters. |

**The typed surface, negatively:**

| # | Assertion |
|---|---|
| I33 | On the **installed** system `punarctl debug rpc install.apply` returns `unknown_method`; in the **live** environment the same call returns a validation error and **not** `unknown_method`. Both directions of the live-mode gate. |
| I34 | `system.exec`, `shell.run`, `install.exec`, `install.script` and `install.chroot` all return `unknown_method` **in the live environment** — the existing §74.4 probe, extended to the most privileged surface Punar has. |
| I35 | The installed system's audit log contains `install.plan` and `install.apply` with `result: success`, schema-conformant against `schemas/audit/audit-event.json`, and `install.recovery_key` with `result: enrolled` **and no key-shaped field**. |

**Refusals and secrecy:**

| # | Assertion |
|---|---|
| I36 | Four refusals, each leaving the target disk byte-identical (sha256 of its first 1 MiB before and after): (a) a 20 GiB disk is refused with the arithmetic in the message; (b) an `install.apply` whose `plan_token` does not match is refused `invalid_params`; (c) an answer file whose `confirm_destroy_disk` does not match the serial is refused; (d) `install.apply` from an agent-attributed peer is **denied by the M9 AI path**, with zero bytes written. **And:** the literal recovery key and the literal passphrase appear **zero times** in the live journal, the installed journal, `/var/log/**` and the audit log. |

**The four assertions this document's own body cites and an earlier draft
never listed** *(added 2026-08-26 — §6.5.1 and §7.2 referenced I37 and I38 in
prose while the table stopped at I36, and two further properties the design
depends on had no assertion at all)*:

| # | Assertion |
|---|---|
| I37 | **The plan is bound to a disk, not to a device node.** `install.apply` re-reads the target's serial, WWN, `size_bytes` and `existing_gpt_sha256` immediately before the first write and refuses `invalid_params` on any mismatch. Exercised three ways, each leaving the disk byte-identical: (a) the target is swapped for a same-sized blank between `plan` and `apply`; (b) the existing partition table is altered between `plan` and `apply`; (c) the device node is re-enumerated onto different hardware. |
| I38 | **Foreign-Punar refusal is scoped to *other* disks.** `install.plan` refuses, naming the device, when a **non-target** block device carries any of the four literal PARTUUIDs. `install.plan` **succeeds** when the **target itself** carries them — the ordinary reinstall case. Both directions, because the naive reading of §4.2 bricks reinstallation. |
| I39 | **The btrfs top level is never mounted.** `findmnt --json` shows no mount of `/dev/mapper/punar-data` without a `subvol=` option; `/etc/fstab` contains no subvol-less entry for it; and `/proc/self/mountinfo` shows the three subvolume mounts with three distinct mount ids and three distinct `st_dev` values. **This is the assertion that makes execution-trust's mount marks sound** — a top-level mount would expose `@home` under a path that no `FAN_MARK_MOUNT` on `/home` covers. §4.3. |
| I40 | **The recovery-key gate holds in both lanes.** A personal `install.apply` that never receives `install.recovery_ack` does not proceed past `encrypt`. An escrow-required enterprise install whose signed Smplify receipt never arrives does not report `escrowed` or compliant and does not cross the configured enterprise completion gate. In either failure the LUKS2 header exists and no secret appears in state or logs. The opt-out lane has neither gate. §6.5.2. |

I36 is deliberately one assertion with parts, because the parts share a
fixture and because "the disk was not touched" is the same check five times.

### 10.3 What CI cannot prove, and will not be allowed to imply

| Claim | Status |
|---|---|
| The ISO boots on any physical machine | **NOT PROVEN.** OVMF is not firmware; virtio is not hardware. User-blocked 3. |
| A USB stick written from the ISO boots | **STRUCTURALLY EXERCISED ONLY** (I05 boots the hybrid image as a raw drive). No stick has been written. |
| Secure Boot | **SIMULATED.** User-blocked 1. |
| TPM unlock | **SIMULATED AND NOT ENROLLED** by decision. User-blocked 2. |
| The release signature chain is trustworthy | **Mechanism proven, custody unresolved.** User-blocked 7. Ephemeral per-run keys. |
| Any statement about which laptops work | **Unmakeable.** §9.4. |
| Install duration | Measurable in QEMU and meaningless — TCG emulation on an arm64 host is not a timing environment. Recorded, never gated, never quoted. |
| Recovery from a corrupt ESP | **NOT PROVEN — no repair mode exists.** §4.5, §13. |

---

## 11. Sequencing

A spike first, because one experiment can invalidate the shape of §4.7:

**V-REPART — COMPLETE on native ARM64; native x86_64 is the cross-architecture
CI authority.** `tests/images/repart-spike.sh` proved six properties against
systemd 261.2: repeated directories are first-wins; the explicit renderer is
later-wins; `MakeDirectories=` + `Subvolumes=` creates the three real btrfs
subvolumes; `Encrypt=key-file` creates an openable LUKS2 filesystem and a typed
recovery slot; the fixed streaming layout consumes its passphrase from a pipe,
creates blank root A, and does not require `payload.raw`; and `CopyBlocks=`
from `/run` reproduces the exact payload digest. The fallbacks became the
implementation because the original priority and deferred-copy assumptions
were false.

Then, in order, because each step is only testable after the one before:

1. **The layout, in the image — IMPLEMENTED, ARM64 BUILD + BOOT PROVEN
   LOCALLY; CROSS-ARCH CI PENDING.** `repart.d/install/` + the rendered mkosi
   definitions →
   the dev qcow2 becomes A/B-shaped with separate `/var`, `/home`,
   `/var/tmp`. **This alone unblocks `execution-trust.md` V3 and
   `update-and-rollback.md` A1–A3, before any installer exists.** It is the
   highest-value, lowest-risk step in the whole plan and should not wait for
   the rest.
2. **The profile split and the build-time assertion** (§8.2, §8.3). Also
   independent, also immediately valuable, and it is the thing that stops
   the dev conveniences from being an ever-growing problem.
3. **The release triple**, produced by the ordinary build — shared with the
   update milestone, and owned by whichever lands first.
4. **`install.*` in `punard`**, headless, driven by `punarctl` and the
   answer file. The whole of §10 except the graphical stages is provable
   here.
5. **The ISO assembly** (§3.3) and `tools/install-test.sh`.
6. **The QML surface** (§6). Last, deliberately: the flow is worth building
   only once the thing behind it works, and until then the answer file is a
   better test harness than a human.
7. **The firmware and hardware-report content** (§9), which can land in
   parallel with 4–6 and is gated on nothing.

### 11.1 What this does to the milestone programme

The installer is not "M14". It is one small step that belongs **before** M11
and one large body of work that belongs after M13, and pretending it is a
single milestone is what makes it look like a six-to-ten-week wall.

| Ships | Work | Where it goes |
|---|---|---|
| **Now, ahead of M11** | Step 1 — `repart.d/install/` + `mkosi.repart/`. The dev qcow2 becomes A/B-shaped with separate `/var`, `/home`, `/var/tmp` | **Insert into whatever milestone is open.** It is a config artefact and two assertions. It unblocks `execution-trust.md` V3 and `update-and-rollback.md` A1–A3, both of which are otherwise waiting on an installer that does not exist. Nothing else on this list has that property |
| **Now, ahead of M11** | Step 2 — the profile split and `mkosi.finalize` A1–A9 | Same milestone. It is the only mechanism that stops the dev-convenience list from growing, and every week it waits the list is longer. It is also `onboarding.md` §4.4 requirement 1 turned into a build failure |
| **With the update milestone** | Step 3 — the release triple from the ordinary build | Shared. Owned by whichever of update / installer lands first; neither should build it twice |
| **After M13** | Steps 4–6 — `install.*` in `punard`, ISO assembly, `tools/install-test.sh`, then the QML surface | A milestone of its own. It depends on M13's OOBE layer existing (the installer surface is the same architecture) and on `onboarding.md`'s account model existing (I29–I32 span the seam) |
| **Parallel, gated on nothing** | Step 7 — firmware and the hardware report | Any time |

**The one ordering claim worth arguing:** the installer must land **after**
onboarding's account stage, not before. An installer that ships first would
produce an image with no login-capable account and no first boot to create
one — an unusable device — so it would have to grow a temporary account, which
is the dev convenience §8 exists to delete, reintroduced by sequencing. The
seam assertions I29–I32 are the mechanical statement of that dependency.

**And the one that changes an existing plan:** `DESIGN_LANGUAGE.md` §11
previously ordered themes → catalog → execution trust. Step 1 above now goes
in front of all three, because execution trust's own spike list has V3 as a
hard prerequisite and step 1 is what makes V3 true. That is a one-line
reordering, not a re-plan.

Steps 1 and 2 are worth starting regardless of when the installer is
scheduled. Competitive analysis puts the whole of this at 6–10 weeks and
notes it *"must land after the ADR-003 A/B slot layout"* — with one
correction from this design: the layout is not a prerequisite delivered
elsewhere, it is **step 1 of this work**, and it is the part that pays other
designs immediately.

---

## 12. Honest limits

1. **Only the layout foundation has been built.** No ISO, `install.*` method,
   release triple, encrypted installed disk, profile split, recovery flow or
   installer UI exists. The register in §0 grades each separately.
2. **No bare-metal boot has ever occurred**, so the ISO's ability to start
   on a real machine is unknown in the strict sense.
3. **Encryption by default costs a passphrase at every boot** until TPM
   unlock is possible (user-blocked 2). That is a real daily tax, taken
   knowingly.
4. **The root slots are unencrypted.** Physical-access modification of the
   OS is defended by Secure Boot, which is simulated (user-blocked 1).
5. **Fixed partition UUIDs collide** if two Punar disks are attached to one
   machine. Mitigated by refusal at install; not solved.
6. **No dual-boot, no free-space install, no manual partitioning.**
   Whole-disk only. Omarchy has all three.
7. **No repair mode.** The ISO reinstalls; it cannot yet re-write a corrupt
   ESP while preserving `/home`, which is the failure
   `update-and-rollback.md` §6.5 names as having no software answer.
8. **Recovery escrow is component-proven, not installed-product-proven.** The
   device wrapper, ciphertext upload, signed receipt verification, mock
   RBAC release and non-secret release audit are implemented and host-tested;
   pinned ARM64 systemd has generated and unlocked a real loopback LUKS2
   recovery slot. The installer/installed image does not yet connect them,
   and production tenant KMS custody, authenticated portal identity, step-up
   release authorization and rotation still depend on the real control plane
   and identity provider (user-blocked 4 and 5). No current release image has
   silently created or uploaded a disk recovery key.
9. **`onboarding.md` §1.8 Layer 2 does not exist.** The ESP has room for
   the recovery UKI (§6.4, requirement 5) and this design does not build
   one, so `punar-recover` and the boot-menu recovery entry are **dashed**.
   The consequence is concrete: a person who forgets their password and
   loses their account recovery code has Layer 1 and Layer 3 and nothing in
   between.
10. **No graphical unlock prompt.** systemd's console prompt, which is
   correct and plain and does not match the design language.
11. **No NVIDIA, no per-model support**, and on an A/B system that cannot be
    fixed after the fact (§9.2).
12. **The ISO size is unmeasured.** The new sparse ARM64 minimal qcow2 is about
    352 MiB allocated with a 33 GiB virtual layout, but that is not the future
    installer ISO or full desktop payload, so the ISO and slot-size revisit
    trigger still rest on an inference.
13. **The live-mode gate is only as strong as the UKI signature**, which is
    simulated (§7.1).
14. **V-REPART is proven only in the builder environment.** Its findings are
    implemented (§4.7), including a typed recovery slot that opens the real
    loopback LUKS2 filesystem, but the encrypted production installer path
    does not exist and no physical disk has been repartitioned.
15. **The install has never been performed by a human**, and every judgement
    in §6 about what a person needs to see is a designer's judgement, not a
    finding.
16. **No firmware boot entry is written** (§7.3.1), so on a machine with
    another operating system the user picks Punar from the firmware boot menu
    on first boot. A deliberate trade, and a real one.
17. **A freshly installed device has no rollback target.** I17 requires slot B
    zero-filled, so the A/B mechanism that answers *"the update broke it"* has
    nothing to answer *"the **first** boot is broken"* with — and §9 Layer 2
    of `onboarding.md` does not exist either. See §12.1.
18. **The toolchain claims in §3 are unverified at the pin** (F1–F4, §3.6).
19. **The `re-read` phase's page-cache defeat is unverified** — `O_DIRECT` on
    the target block device is the design and the fallback is weaker (§7.3).

### 12.1 The one limit that is a recommendation, not just a disclosure

Limit 17 is the only entry in this list that this document can cheaply fix,
and `onboarding.md` §1.6.2 makes the case from the other side: on a Punar
device root is locked, nobody is in `wheel`, and `punard` is the only path to
privilege — so a `punard` that will not start on a fresh device is
unrecoverable except by reinstalling, which is a **worse** recovery story than
the dev image with `RootPassword=punar` that this design deletes.

Two answers exist and they are not exclusive:

1. **Build `punar-recover` and its fourth UKI** (§6.4 requirement 5, currently
   answered *"room reserved, artefact not built"*). This is the right answer
   and it is a milestone's worth of work.
2. **Bless slot B with the same image written to slot A**, at the `boot`
   phase. The 8 GiB is already allocated and already zero-filled; writing it
   costs one more pass of the same bounded copy loop and one more UKI on an
   ESP sized for three. It makes the firmware's own boot menu a working
   recovery path from the **first** boot rather than the second, and it
   deletes limit 17 outright.

Option 2 changes assertion **I17**, which currently requires slot B to be
zero-filled with no UKI — so it is a decision with a test attached and cannot
be taken quietly. This document **recommends option 2 for the MVP and option 1
for the first release that ships to anyone outside this repository**, and
records that the recommendation is not yet a decision: I17 stands as written
until it is taken.

---

## 13. Scope-out

| Not in this design | Where it goes |
|---|---|
| Dual-boot / free-space / manual partitioning | Phase 2 |
| Repair mode (rewrite ESP + slot A, preserve `PUNAR-DATA`) | Next, and it is the highest-value follow-on — it is the answer to `update-and-rollback.md` §6.5 |
| Recovery-key escrow implementation | Device wrap/upload/signed-receipt and dev/CI portal custody/release are implemented and host-proven (§5.3). Installer wiring, production KMS/IdP/step-up release and rotation remain user-blocked 4 + 5. |
| The Layer-2 recovery boot entry (`punar-recover`, a fourth UKI) | Next, alongside repair mode — they are the same artefact. ESP room is reserved (§6.4) |
| Account creation, password policy, the greeter, `identity.local-account` | `docs/design/onboarding.md` — the installer creates no account at all (§6.4) |
| Graphical LUKS unlock | Phase 2. Plate D-002's greeter is `onboarding.md` §5's, and ships there |
| OEM / gifting mode, factory reset | Phase 2 (Omarchy 4.0 has both) |
| Network install, netboot, PXE | Not planned. The offline install is the design. |
| Per-model or per-GPU release variants | Named in §9.2; a release-pipeline decision |
| Which packages ship in the image | `docs/design/app-catalog.md` |
| Theme selection in the **installer** | Refused, §6.6. First boot's theme question is `onboarding.md` §3.1's, and is decided there |
| ISO signing and public download | User-blocked 7 + 8 |
| `zram` configuration and swapfiles | Out of scope; §4.6 explains why the layout does not prevent them |

---

## 14. Definition of done for this design

1. The partition table is stated in full, with type GUIDs, fixed UUIDs,
   sizes, filesystems, mounts and the arithmetic against both hardware
   targets — **§4.1, §4.4.** ✔
2. It implements ADR-003 exactly, and the one number ADR-003's source
   document got wrong is corrected rather than repeated — **§4.4.** ✔
3. `execution-trust.md`'s hard prerequisite (V3) is satisfied, and its open
   `/var/tmp` question is resolved at zero cost — **§4.3.** ✔
4. LUKS2 by default for every device is argued against the spec's own
   narrower wording, with the opt-out, the recovery flow, and the honest
   daily cost stated — **§5.** ✔
5. TPM is designed for and explicitly not enrolled, with the reason —
   **§5.4.** ✔
6. The ISO mechanism names every file, every build step and the one
   non-mkosi tool, without claiming mkosi does something it does not —
   **§3.** ✔
7. The flow is keyboard-first, shell-free, in the field-note voice, with a
   destructive confirmation bound to the plan it confirms — **§6.** ✔
8. The account is delegated **entirely** — the installer creates none, and
   all six requirements `onboarding.md` §4.4 places on it are answered
   individually, including the one it answers with "no" — **§6.4.** ✔
9. The installer's relationship to `punard` is decided and argued, and the
   prohibited operations are enumerated exhaustively — **§7.** ✔
10. Every dev convenience is enumerated from source, with a mechanism that
    fails the build and a check that proves the device — **§8.** ✔
11. Hardware is answered honestly, including the A/B consequence nobody had
    written down — **§9.** ✔
12. 40 named, offline, gating assertions, and an explicit list of what they
    cannot prove — **§10.** ✔

---

## 15. Sources

- `docs/product/SPEC_v0.2.md` §§1.22, 3.6, 5.1–5.4, 6.3, 6.6, 12, 44.1–44.2,
  45, 48, 49, 52, 53, 55, 57, 59.5, 60, 61, 65, 66, 73, 74.3–74.4
- `docs/architecture/adr/ADR-003-ab-slots-over-snapper.md` (Accepted)
- `docs/architecture/adr/ADR-001-distribution-substrate.md`
- `docs/development/update-and-rollback.md` §§3.3, 3.5, 3.6, 4.1, 4.2, 6.5,
  7.1, 12.1, 13.2
- `docs/design/execution-trust.md` §§3.3, 3.5, 5.3, 13 (V3), 14
- `docs/design/theme-system.md` §§5.5, 6.1, 6.4
- `docs/design/app-catalog.md` §§2.1, 2.3, 2.5, 3
- `docs/design/DESIGN_LANGUAGE.md` §§7, 8, 9
- `docs/design/mockups/first-boot.html` (Plate D-008),
  `docs/design/mockups/boot-greeter.html` (Plate D-002)
- `docs/design/onboarding.md` §§1.7, 1.8, 1.10, 3.1, 4.2–4.5, 5.4 — the
  account seam, accepted wholesale
- `docs/development/milestone-13.md` §§5.1–5.6
- `docs/development/user-blocked.md` items 1, 2, 3, 4, 5, 7, 8
- `docs/development/image-pipeline.md` "Current limitations"
- `docs/api/ipc.md` §§1.2, 5, 6, 7
- `docs/product/competitive-position.md` axes 1, 2, 9 (Omarchy evidence)
- `os/images/mkosi.conf`, `os/images/mkosi.profiles/desktop/`,
  `os/images/scripts/container-build.sh`, `os/images/builder/Containerfile`,
  `os/images/snapshot.env`, `tools/boot-test.sh`
