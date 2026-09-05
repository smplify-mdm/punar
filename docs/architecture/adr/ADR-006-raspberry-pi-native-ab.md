# ADR-006 — Native Raspberry Pi `tryboot` for A/B rollback

- Status: **Accepted for implementation** — 2026-08-27; physical-board fault
  injection remains a release gate, not a completed claim
- Date: 2026-08-26
- Relates to: [ADR-003](ADR-003-ab-slots-over-snapper.md) (accepted A/B
  requirement), [ADR-005](ADR-005-arm64-support.md) (accepted ARM substrate)
- Product requirement: ARM64 and Raspberry Pi are first-class targets

## Context

ADR-003 requires more than two root filesystems. Its reason for existing is
rollback when the new userspace cannot come up: firmware tries a pending slot,
health-gated userspace commits it, and an uncommitted failure returns to the
permanently known-good slot.

The x86_64 mechanism uses systemd-boot boot counting and one UKI per slot. A
Raspberry Pi's native boot chain is not UEFI, so copying that mechanism through
third-party UEFI firmware would add a new privileged dependency without first
asking whether the board firmware already has the required primitive.

It does. Raspberry Pi's current official documentation specifies:

- a one-shot `tryboot` flag which is **cleared before** the candidate OS is
  started, so a crash or reset returns to the ordinary configuration;
- partition-level A/B selection through `autoboot.txt`, `boot_partition` and
  `tryboot_a_b=1`;
- the current boot partition and tryboot state exposed read-only in device
  tree under `/proc/device-tree/chosen/bootloader/`;
- an example update flow that writes the inactive partition, boots it once,
  validates it, and swaps `autoboot.txt` only after success;
- `tryboot` support on all Raspberry Pi models, with a write-protected-EEPROM
  caveat on early Pi 4 revisions.

Primary sources (verified 2026-08-26):

- <https://www.raspberrypi.com/documentation/computers/config_txt.html#example-update-flow-for-ab-booting>
- <https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#fail-safe-os-updates-tryboot>

This decides the selection and rollback mechanism only. ADR-005's Debian
pinned-sid recommendation remains separately Proposed; an accepted boot
mechanism does not choose a package substrate.

## Options considered

### A — Third-party UEFI firmware plus the x86 UKI layout

This would reuse systemd-boot almost literally. It also inserts a third-party
firmware layer ahead of every kernel boot, makes board support depend on that
project's release cadence, and still requires native Pi firmware to reach it.
The visual symmetry with x86 is not worth a larger trusted boot chain.

### B — Userspace pointer with no firmware one-shot

Write an `active-slot` file, reboot, and change it back if the candidate
userspace reports failure. This fails the exact case ADR-003 exists to handle:
if userspace never starts, nothing changes the pointer back. Rejected.

### C — Native Pi `tryboot`, with Pi-specific boot partitions

Two FAT boot partitions each carry the firmware-visible kernel/initramfs,
device tree and cmdline for one matching root slot. `autoboot.txt` selects the
known-good boot partition normally and the inactive one only under the
one-shot tryboot flag. The candidate commits by atomically swapping the two
partition numbers in `autoboot.txt` after the same health gate used by x86.

The selector is a third, small FAT partition. It contains `autoboot.txt` but
no OS payload. This separation is required by the official update flow: if
boot A also owned the selector, a later update targeting inactive A could
overwrite the last-known-good boot decision while it was still needed.

This is not the same implementation as systemd-boot counting, but it has the
same safety property without emulating a PC firmware stack.

## Decision

**Use native Raspberry Pi firmware and partition-level `tryboot_a_b` for Pi
A/B updates. Do not put third-party UEFI firmware in Punar's Pi boot chain.**

Acceptance chooses the mechanism so implementation can begin; it does not
waive §Verification required before shipping support. Until the real-board
reset, watchdog and power-loss matrix passes, generated Pi images must remain
labelled engineering previews and Punar must not claim Raspberry Pi support.

The slot is a pair:

```text
selector (FAT) ── autoboot.txt: ordinary 2, tryboot 4
boot A (FAT)   ── cmdline root=PARTUUID(root A)  ── root A
boot B (FAT)   ── cmdline root=PARTUUID(root B)  ── root B
shared data    ── /var + /home + Punar identity, never rolled back
```

The selector partition's `autoboot.txt` selects the blessed boot partition.
Its `[tryboot]` branch selects the candidate. Boot and root partitions are
always written and verified as one slot; a configuration may never point boot
A at root B. The slot boot artifact is byte-identical in boot A and B and uses
firmware's read-only `boot_partition` conditional to choose the paired root
command line.

## Update state machine

1. Identify the running boot partition from device tree, never from a mutable
   userspace preference.
2. Stream the signed release into the inactive root and boot partitions;
   verify manifest signature, admissibility, streamed digest and post-write
   re-read digest in ADR-003's order.
3. Re-read the selector partition. Leave ordinary `boot_partition` unchanged,
   require `[tryboot]` to name the inactive boot partition, and invoke
   `reboot "0 tryboot"`.
4. The firmware clears the one-shot flag before starting the candidate. A
   reset before commit therefore returns to the ordinary blessed partition.
5. A conditional oneshot is pulled into the **boot transaction** by
   `graphical.target`; it is ordered after `multi-user.target` and is not a
   path watcher. Creating `pending-pi.json` while a session is already running
   cannot trigger candidate blessing before the requested tryboot.
6. Candidate userspace proves all of: expected slot identity, root is mounted
   read-only, Punar daemons and desktop are healthy, boot reconcile completed,
   the exact signed root and boot byte ranges still match under `O_DIRECT`,
   boot-file semantics are valid, and mounted root `IMAGE_VERSION` equals the
   pending release.
7. Only then durably rewrite and re-read `autoboot.txt`, swapping ordinary and
   tryboot partition numbers. The engine leaves pending state in place. The
   privileged handler must durably append and `fdatasync` the
   `blessed_candidate` audit before removing that exact pending record and
   syncing its directory; a still-running tryboot then reboots normally.
8. The same boot-only reconcile distinguishes two recovery states. An
   uncommitted selector plus an ordinary boot of the previous slot is
   `firmware_fallback` and changes no selector bytes. A committed selector plus
   its exact previous-selector backup and a candidate boot is
   `postcommit_recovery`; it fully revalidates the candidate. Both clear
   pending only after their own durable audit, and an ordinary boot does not
   reboot again.

A kernel/userspace hang still needs a reset to take the already-cleared
tryboot path back to the blessed slot. Punar must therefore configure the
Linux hardware watchdog on supported Pi boards and a bounded kernel panic
reboot. The bootloader watchdog alone is insufficient because Raspberry Pi
documents that it is cancelled when the Arm CPU starts.

## Security and failure properties

- The candidate cannot bless itself before the health unit reaches the final
  selector write. A separately verified previous selector is retained. An
  audit outage leaves pending state and the committed-selector retry is
  idempotent. FAT does not make rename power-loss atomic, so recovery under
  selector-write fault injection remains an explicit physical-board release
  gate rather than an assumed property.
- Slot payload signatures remain user-blocked item 7, and Pi Secure Boot keys
  remain user-blocked item 1. CI uses ephemeral keys and labels that proof
  `SIMULATED`, exactly as x86 does.
- The Pi's boot partition is FAT and cannot provide Unix ownership. Trust comes
  from signed boot artifacts and a booted root that does not expose the boot
  partitions to the session user, not from pretending FAT has permissions.
- An ESP/FAT corruption can still destroy both entries. Recovery media remains
  required; no A/B scheme makes damaged boot media self-healing.
- EEPROM A/B *firmware* update support on Pi 5 is a separate mechanism. Punar's
  OS rollback must not claim it protects an OS slot merely because the EEPROM
  itself updates safely.
- **`firmware_fallback` is a boot observation, not a tryboot record.** Any
  ordinary boot of the previous slot with an uncommitted selector is
  finalized as `firmware_fallback`, including a staged candidate that was
  never rebooted into (`update.apply` without `--reboot`, then a plain
  reboot or power loss). The verified staged bytes are discarded from the
  state machine and a fresh apply is required. Recording the tryboot request
  itself is a follow-up.
- **A committed selector whose pending record survived has no API exit if the
  candidate later fails health.** `postcommit_recovery` revalidates the
  running candidate, including its health report, and `update.rollback` and
  `update.apply` refuse while the pending record exists. This window is
  reachable only through an audit or power-loss failure between selector
  commit and finalization; it is an open item for the physical-board matrix
  below, not a claimed property.

## Verification required before shipping support

1. A generated Pi image has a dedicated selector, two boot/root pairs with
   distinct fixed PARTUUIDs and shared data; every cmdline points only at its
   paired root and neither slot artifact contains `autoboot.txt`.
2. QEMU/aarch64 checks the slot builder and state machine, explicitly labelled
   as software-path evidence rather than Raspberry Pi hardware evidence. The
   software tests cover partial health, exact digest/size/version mismatch,
   firmware fallback, audit-failure retry and post-commit recovery.
3. On a real Pi, deliberately fail before the health service, during daemon
   startup, and after userspace starts but before blessing; watchdog/reset must
   return to the old slot every time.
4. Power removal during inactive-slot write and during the `autoboot.txt`
   commit must leave at least one bootable blessed slot.
5. The same security/privacy assertions run on the Pi appliance class as on
   x86_64. No class may weaken them.

## Consequences

We gain a smaller native boot chain and preserve ADR-003's central property on
Pi. We accept two platform adapters around one shared update state machine:
systemd-boot/UKI on UEFI machines, native `tryboot`/FAT boot pairs on Pi.

The update payload format must therefore carry platform boot artifacts rather
than assuming every machine consumes a UKI. Shared root/data layout,
verification order, health criteria, audit vocabulary and N-1 state rule stay
identical.

## Revisit triggers

- Raspberry Pi removes or materially changes partition-level `tryboot`.
- Bare-metal fault injection cannot reliably reset an uncommitted hang.
- Native Pi UEFI becomes vendor-supported and measurably reduces rather than
  enlarges the trusted/maintenance surface.
- A future substrate provides a vendor-supported atomic Pi deployment model
  with equal or stronger pre-userspace rollback semantics.
