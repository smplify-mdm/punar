# ADR-005 — Supporting arm64, and what it costs ADR-001

- Status: **Proposed, AMENDED after adversarial review** — 2026-08-26.
  ARM64/Raspberry Pi support is an accepted product requirement; the Debian
  pinned-sid substrate recommendation in this ADR still awaits ratification.
- Amendment: §A records what the second review corrected, including an error of
  mine in the original evidence. Read §A before §Options; two of the original
  recommendations are struck.
- Relates to: [ADR-001](ADR-001-distribution-substrate.md) (substrate),
  [ADR-003](ADR-003-ab-slots-over-snapper.md) (A/B slots)
- Trigger: the product owner named a Raspberry Pi as a target device, and then
  asked the question this ADR exists to answer — *"If all the future devices
  run on arm then isn't it a miss that we can't support arm architecture?"*


## A. Amendment — what the second adversarial review corrected

The first round lost two of three reviewers to API errors. A full second pass
(seven agents, no failures) returned **AMEND, then ratify** from all three
attackers: the destination is right, the argument was not.

### A.1 An error in my own evidence

The original text cited mkosi's
`die("There is no known public mirror for snapshots of Arch Linux ARM")` as
proof that mkosi *refuses* snapshot-pinned Arch ARM. **That is a misread.** The
actual source, verified directly:

```python
if context.config.architecture.is_arm_variant():
    if context.config.snapshot and not context.config.mirror:
        die("There is no known public mirror for snapshots of Arch Linux ARM")
    mirror = context.config.mirror or "http://mirror.archlinuxarm.org"
```

It fires **only when a snapshot is requested and no mirror is supplied**. Given
a mirror, mkosi proceeds. The honest claim is *"no public snapshot mirror
exists"*, not *"mkosi refuses"* — materially weaker, and it was load-bearing.

### A.2 Option B is struck, and so is its urgency

The original recommended starting a Smplify-owned Arch ARM mirror
**immediately**, calling it the only irreversible item. **That instruction is
withdrawn.** Its urgency was computed against a mechanism whose availability
was never checked: the review reports Arch Linux ARM **does not offer rsync**,
so "rsync it daily and retain it" describes an operation that may not be
available. Nobody should spend a day on this before that is verified, and the
review's verdict on Option B is **not viable**.

### A.3 Debian works — on exactly one suite, and not the one implied

Measured 2026-08-26 (chromium age = now minus the *upstream* release date of the
version each track carries; amd64 and arm64 are **identical** in every Debian
suite, so architecture is not a freshness variable):

| Track | chromium | age |
|---|---|---:|
| Debian **sid** arm64 | 151.0.7922.173 | **6.0 days** |
| Debian trixie-security arm64 | 151.0.7922.169 | 8.1 days |
| Debian **testing** arm64 | 150.0.7871.181 | **36.0 days** |
| Arch Linux ARM aarch64 | 151.0.7922.137 | 14.9 days |
| Arch x86_64 (incumbent) | 151.0.7922.173 | 6.0 days |

Scored on ADR-001's own bar (a critical browser fix reaching stable within
7 days, and its rejection of Fedora at 1–2 weekly refreshes):

- **sid passes** and matches the incumbent's version exactly.
- **testing fails badly** — 8 upstream releases behind, ~2.5× worse than the
  Fedora ADR-001 rejected.
- **Arch Linux ARM fails** — worse than Fedora. This is what ADR-001's own
  decision yields on arm64 today.

**Why testing fails is structural, not transient.** Debian's britney reports
chromium blocked into testing by a *missing build on armhf* and a
*reproducibility regression on arm64*; five consecutive uploads have failed to
migrate and testing has been stuck ~5 weeks. An architecture Punar will never
ship gates the freshness of its most security-critical component.

**So the original text's "two-suite tracking cost" understated the problem: the
suite it implied is the one that fails.** Option C means **pinned sid**, and
that must be stated as the decision, not discovered later.

Also non-monotonic and worth knowing: trixie-**security** is fresher than
**testing** by a full milestone. Any reasoning that assumes
stable < testing < unstable is wrong here.

### A.4 What Debian arm64 actually carries

Verified from Debian's own `binary-arm64` indices, at versions **identical to
amd64**: hyprland 0.56.2, quickshell 0.3.0, greetd 0.10.3, foot 1.27.0,
qt6-declarative 6.10.2, chromium 151.0.7922.173 — plus a maintained Hyprland
ecosystem (hyprlock, hypridle, hyprpaper, hyprpolkitagent, xdg-desktop-portal-hyprland
and more), and every ADR-003 boot primitive natively: systemd-boot, ukify,
sbsigntool, efibootmgr, repart.

The builder story inverts too: `debian:sid-slim` publishes `linux/arm64/v8` and
mkosi 26-4 is in the archive — against Arch ARM's absent container base and
mkosi 14 from 2023. `snapshot.debian.org` is consumed natively by mkosi
(`mkosi/distribution/debian.py`), covers all architectures, and arm64 measures
**94.3% reproducible** against amd64's 94.1%, both above Arch's ~86.9%.

**One real caveat:** chromium specifically has a reproducibility regression on
arm64 — the one package Punar cares most about is the one that does not
reproduce there, and it is half of what blocks testing.

### A.5 Fedora moved backwards since ADR-001

Hyprland was not merely orphaned: it was **retired** from rawhide and F43 on
2025-09-30 as fails-to-install. Option D is further from viable than the
original text suggested, not closer.

### A.6 Standing instruction from this amendment

**A fact about a platform is a citation and an observation, or it is labelled
unverified.** Two errors in two rounds — an invented systemd option name and a
misread mkosi guard — both survived into documents because they sounded right.

---

## Context

**Owner direction, 2026-08-26:** Punar must run on ARM, with Raspberry Pi as a
target, while pursuing bare-metal performance for engineers and enterprise
trust. This closes the question of whether ARM64 belongs in the product. It
does **not** silently ratify Debian pinned sid, nor does it resolve the Pi boot
chain recorded below; those are implementation decisions with their own
evidence and consequences.

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

**Adopt option C — Debian, tracking PINNED SID specifically** (see §A.3; no
other suite passes ADR-001's own freshness bar). Option B is struck.

The strategic case is not in dispute: client computing is moving to arm64
(Apple Silicon, Snapdragon X, Ampere and Graviton on the server side), and an OS
that cannot build for it is choosing a shrinking half of the market. Shipping
x86_64-only is a miss, and the reason it happened — CI convenience — is not a
reason to keep it.

**~~Regardless of which option wins, start the arm64 mirror now.~~ STRUCK —
see §A.2.** The urgency was computed against an rsync capability that was never
verified to exist, and the review finds Option B not viable. Do not start it.

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
