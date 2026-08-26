# ADR-005 — Supporting arm64, and what it costs ADR-001

- Status: **Proposed** — 2026-08-26
- Relates to: [ADR-001](ADR-001-distribution-substrate.md) (substrate),
  [ADR-003](ADR-003-ab-slots-over-snapper.md) (A/B slots)
- Trigger: the product owner named a Raspberry Pi as a target device, and then
  asked the question this ADR exists to answer — *"If all the future devices
  run on arm then isn't it a miss that we can't support arm architecture?"*

## Context

**Punar is x86_64 only.** `os/images/mkosi.conf` sets `Architecture=x86-64`.
No arm64 image has ever been built, booted or tested.

**ADR-001 did not weigh arm64 badly. It never weighed it at all.** Its criteria
were reproducibility, package availability, maintenance burden, enterprise
governance, transactional updates and hardware compatibility. Architecture is
absent from the list. Where it appears, it appears as a *consequence* — "CI as
the arbiter: authoritative image builds, UKI signing, and KVM boot tests on
x86_64 GitHub runners ... the arm64 Mac is for emulated iteration only."

That is a **tooling convenience shaping a product constraint**, and it is a
weak thing to be bound by once arm64 becomes a target. This ADR does not
reopen ADR-001 because its answer was wrong; it reopens it because a
requirement was added that its answer never evaluated.

## The blocker, verified rather than recalled

**There is no reproducible package archive for Arch on arm64.** Confirmed three
independent ways on 2026-08-26:

1. `https://archive.archlinux.org/repos/2026/08/20/core/os/` contains exactly
   one subdirectory: `x86_64/`.
2. The Arch Linux ARM mirror returns **404** for any date-snapshot path; its
   live layout is a single rolling repo with a different URL shape entirely.
3. mkosi's own source refuses it:
   `die("There is no known public mirror for snapshots of Arch Linux ARM")`.

ADR-001's entire reproducibility story is vendor-pinned Arch Linux Archive date
snapshots. On arm64 that mechanism **does not exist**.

Three further findings, each measured:

- **ADR-001's sharpest discriminator inverts.** It rejected Fedora partly
  because Chromium ran 1–2 weekly refreshes behind, against spec §30.2's
  days-level cadence. Arch Linux ARM's Chromium is `151.0.7922.137` against
  x86_64's `.169`. Same lag, same criterion, now on the chosen substrate.
- **Arch Linux ARM is an unofficial single-maintainer project** with no
  security advisories and no archive. 2,341 packages present on x86_64 are
  absent on arm64; `mkosi` there is version 14 from 2023 against the 26 we
  require.
- **There is no official Arch container image for arm64**, so the builder
  container base does not exist either.

**Omarchy is not a counter-example.** It supports x86_64 only. Its Apple
Silicon story is community forks on Arch Linux ARM and Asahi that tolerate
missing packages by reporting them at the end, plus `try-omarchy`, which ships a
**prebuilt** arm64 image. That pins the *output*, not the inputs: the download
is stable, the rebuild is not reproducible. Reasonable for a try-it VM,
insufficient for a fleet of appliances taking A/B updates.

## What a change would actually cost — measured

| Layer | Size | Substrate-coupled? |
|---|---:|---|
| Rust crates | 103 files, **68,614 lines** | **No** — zero references to pacman or Arch |
| QML shell | 34 files, **19,885 lines** | **No** — one comment mentions a dependency |
| Image pipeline | `mkosi.conf`, `snapshot.env`, `Containerfile`, profile | **Yes** — ~218 lines plus package names |
| Boot chain | ADR-003's UKI-on-ESP model | **Yes** — see below |

**88,499 lines of the product do not care what the substrate is.** The coupling
is a build pipeline and a boot chain. This is the cheapest this decision will
ever be: 68 commits, ~500 tracked files, no users, no published announcement.

## Options

**A. Arch, pinning the output.** Build an arm64 image from rolling Arch Linux
ARM, ship the artifact, drop the promise that a past build is reconstructible.
Works today; small. **Cost:** abandons ADR-001's reproducibility claim on half
the fleet, and inherits the browser-cadence problem ADR-001 rejected Fedora for.

**B. Arch, with a Smplify-owned arm64 mirror.** Rsync Arch Linux ARM daily and
retain it, giving us the archive that does not exist. **Cost:** we become the
only archive in existence — no date before we start is ever pinnable, and
losing the mirror loses every historical pin. **This is the only
time-sensitive item in this ADR: every day not mirroring is a date permanently
unpinnable.**

**C. Debian.** `snapshot.debian.org` covers **all architectures back to 2005**
from one host, so one pinning mechanism serves both. Hyprland 0.56.2 and
Quickshell 0.3.0 exist as real arm64 binaries. Scores best against ADR-001's
*own* original criteria once arm64 is added to them. **Cost:** re-doing the
image pipeline; two-suite tracking; ADR-001's package-freshness argument must
be re-made rather than assumed.

**D. Fedora.** Verified arm64 composes, and bootc gives transactional updates
natively — the thing ADR-003 hand-built. **Cost:** Hyprland is orphaned there,
which is the compositor Punar is built on.

**E. Two substrates.** Doubles every pipeline, gate and package decision this
project has made. Recorded for completeness, not recommended.

## Recommendation

**Adopt option C or B, and decide within days rather than weeks — but do not
decide from this document alone.**

The strategic case is not in dispute: client computing is moving to arm64
(Apple Silicon, Snapdragon X, Ampere and Graviton on the server side), and an OS
that cannot build for it is choosing a shrinking half of the market. Shipping
x86_64-only is a miss, and the reason it happened — CI convenience — is not a
reason to keep it.

**Regardless of which option wins, start the arm64 mirror now.** Option B is
the only irreversible one: history that is not being captured today cannot be
recovered later. Mirroring costs disk and a cron job, and it preserves option B
while C is evaluated. If C is chosen the mirror is discarded at no loss.

## What this ADR does NOT decide

- **The Raspberry Pi boot chain.** ADR-003 selects the A/B slot with one UKI per
  slot on an ESP and relies on systemd-boot's boot counting; the Pi's native
  chain is not UEFI. Whether third-party Pi UEFI firmware is sound enough to
  carry ADR-003's stated gain — *rollback that works when userspace does not* —
  is unresolved. A weaker mechanism wearing ADR-003's name would be worse than
  an honest second mechanism, and that belongs in its own ADR.
- **The device-class split.** See [`../../design/device-classes.md`](../../design/device-classes.md).

## Honest limits of the evidence

The research behind this ADR ran seven agents; **two of three adversarial
reviewers died on API errors**, so the counter-argument is under-developed. The
one that survived found the others asking a question the owner had already
answered, and a factual error that would have shipped a wrong build gate. Every
verified claim above carries its method; the *options* deserve a second
adversarial pass before ratification, particularly C's package-freshness claim,
which is the criterion ADR-001 turned on.
