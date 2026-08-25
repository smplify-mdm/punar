# ADR-003 — A/B root slots as the rollback mechanism, not btrfs+snapper

- Status: **Accepted** — ratified by Smplify (Spurti Preetham Gurram), 2026-08-25
- Date: 2026-08-25
- Supersedes: the *MVP rollback mechanism* chosen in
  [ADR-001](ADR-001-distribution-substrate.md) (the substrate decision itself
  — minimal Arch, snapshot-pinned channels, mkosi images — is unchanged and
  remains Accepted)
- Full argument: [`docs/development/update-and-rollback.md`](../../development/update-and-rollback.md)

## Context

ADR-001 accepted the Arch substrate and, for the MVP, chose **btrfs + snapper
with bootable snapshots** as the rollback mechanism, naming A/B image
deployment as the charted production trajectory (its Option D.2). Spec §80
item 25 requires a demonstrated rollback/update mechanism; it has been
unowned since M0 and is currently marked NOT MET.

Designing the update system in detail surfaced a problem with the interim
choice rather than with the substrate.

## Decision

**A Punar update is an A/B root-slot image swap.** Two root partitions with
fixed distinct PARTUUIDs, one UKI per slot on the ESP, `/var` and `/home`
shared and never rolled back. btrfs+snapper is demoted from *the* rollback
mechanism to an optional data-side convenience, and §80 item 25 does not
depend on it.

**The UKI is the slot selector.** Each slot's UKI embeds
`root=PARTUUID=<its own slot>` in its cmdline. There is no bootloader
variable, no pointer file, no shared state that can disagree with the thing
that actually booted.

## Why snapper does not satisfy the requirement

On the boot chain we ship — systemd-boot with unified kernel images — snapper
fails three ways that matter precisely when rollback matters:

1. **It cannot restore the ESP.** Kernel and initrd live in the UKI on the
   EFI system partition, outside any btrfs subvolume. A snapshot that cannot
   restore what boots is not a boot rollback.
2. **It cannot be reached when userspace does not come up.** Snapper is a
   userspace tool; the failure mode we must survive is the one where
   userspace never starts.
3. **It has no boot-menu enumeration of snapshots** under systemd-boot, so
   there is nothing for a human to select at the moment they need it.

## Consequences

**We accept:**

- A second root slot costs **6.7%** of the §5.1 minimum 128 GB disk and
  **3.4%** of the 256 GB recommended target. Full fixed OS cost is 17 GiB
  (ESP 1 GiB holding three UKIs, root A 8 GiB, root B 8 GiB), 14.3% of the
  minimum target. Sizing rule: `slot = roundup_GiB(1.5 × R_max)`. The input
  estimate (a 1.5–2.5 GB desktop image) is **unmeasured** and labelled so.
- Punar-owned mutable `/etc` state becomes a **capability output, never a
  file an update must preserve**. A new slot boots vendor `/etc` and punard's
  boot reconcile makes it match the effective document. Any Punar-owned
  `/etc` file not produced by a capability is a rollback hazard and is
  asserted absent.
- `machine-id`, the device id, users and all Punar state live on the shared
  partition — otherwise every update silently re-identifies the device. Each
  state file carries a schema version readable by the immediately preceding
  release (N-1 rule).
- ADR-001's charted trajectory is pulled forward into the MVP. Argued on
  cost, not preference: building the snapper interim first is not cheaper,
  it is differently shaped work ending in the same place minus the
  trustworthiness.

**We gain:**

- Rollback that works when userspace does not, because it is the firmware
  selecting a different, permanently-blessed UKI.
- Health-gated blessing as the automatic-rollback rule: systemd-boot's own
  boot counting (tries = 3), with blessing withheld unless health passes.
- Verification order as the security design — manifest signature, then
  admissibility, then streamed digest, then post-write re-read digest, then
  UKI install, then default. Steps 1–5 are reversible by deleting a file.

## Revisit triggers

- Measured desktop image size exceeds ~5 GB, making 8 GiB slots wrong.
- The 128 GB minimum target is dropped or raised, changing the disk argument.
- We adopt a substrate with native atomic deployments (ostree/bootc), which
  would supersede this mechanism rather than tune it.
- ESP corruption proves to be a realistic failure in the field, forcing
  recovery media to be built (currently named as unowned work).

## Open, and blocked on Smplify

Release-key custody is **user-blocked** (see
[`docs/development/user-blocked.md`](../../development/user-blocked.md) item 7).
CI proves the verification path with per-run ephemeral keys and labels custody
SIMULATED; the device fails closed with an empty trusted-key set.
