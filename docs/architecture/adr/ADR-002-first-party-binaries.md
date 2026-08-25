# ADR-002: Distribution of First-Party Binaries

- Status: Accepted
- Date: 2026-08-25
- Spec references: sections 1.22 (honesty), 6.2 (budgets), 74 (verification
  strategy), 76 Milestone 3; builds on ADR-001 (pinned-snapshot inputs)

## Context

Milestone 3 puts the first compiled first-party code into the `punar-desktop`
image: the `punard` daemon and the `punarctl` CLI. Something has to build
those binaries, and the choice of *where* and *with which toolchain*
determines their provenance.

The forces:

- **ADR-001 pins every image input** to the Arch Linux Archive snapshot
  `2026/08/20`. A binary compiled with an unpinned toolchain against a
  different glibc lineage would be the one image payload whose inputs are not
  the snapshot's.
- **The CI VM has no network** (`-nic none`). Nothing may fetch at boot; the
  binaries must be fully present and runnable in the image, linked against
  libraries the image ships.
- **The maintainer host is macOS arm64** running the x86_64 build pipeline
  under Docker emulation; local builds are non-authoritative (spec 1.22),
  CI x86_64 is canonical. Whatever strategy is chosen must work identically
  in both places.
- **A CI Rust toolchain already exists** — the `rust` job (fmt/clippy/test)
  runs on `ubuntu-24.04` with a rustup toolchain. It exists for fast test
  feedback, not for shipping artifacts.
- Committing prebuilt binaries to the repository was not seriously
  considered: unreviewable blobs, unbuildable-from-source images, and a
  standing invitation to provenance drift.

Verified facts (2026-08-25, against the snapshot indices): `rust 1:1.97.1-1`
is in the snapshot's `extra` repo and satisfies the workspace
`rust-version = "1.85"`; the emulated builder-container compile of both
release binaries measured **~50 s** warm (the workspace dependency tree is
deliberately small).

## Options considered

### Option A — Hermetic in-container build (build inside the image builder)

Add the snapshot's own `rust` package to the builder container
(`os/images/builder/Containerfile` — same pinned mirror as every other
builder tool, no rustup). `os/images/scripts/container-build.sh` gains
`stage_punar_binaries()`: when `PUNAR_BUILD_MODE=build` and the desktop
image is selected, run `cargo build --release --locked -p punard -p
punarctl` with `CARGO_HOME`/`CARGO_TARGET_DIR` under `os/images/cache`
(riding the existing CI cache key, which now also hashes `Cargo.lock`), and
install the binaries 0755 into the desktop profile's `mkosi.extra/usr/bin/`
(gitignored, like the staged desktop assets). `PUNAR_BUILD_MODE=summary`
skips compilation entirely, keeping the cheap config-validation path cheap.

Satisfies the constraints: one toolchain provenance (the snapshot's), the
binaries link against the snapshot glibc that the image itself ships, and
the local and CI build paths remain the identical
`tools/build-image.sh` invocation.

**Honest hermeticity limit:** crates.io is fetched at image-build time for
the workspace dependencies — the one build input not served from the Arch
snapshot. It is pinned by the committed `Cargo.lock` (`--locked` refuses
drift) and checksummed by cargo, and the CI cache makes it a warm no-op.
The *runtime* VM still needs no network.

Cost: the desktop image build on the arm64 Mac now also compiles two
release binaries under emulation — measured ~50 s warm, far below the
originally feared +10–30 min.

### Option B — CI artifact handoff from the `rust` job

Build the release binaries in the existing `rust` job and download them
into the image job as a workflow artifact.

Rejected: the rust job's rustup toolchain on `ubuntu-24.04` is a second,
differently-pinned toolchain and glibc lineage — the one image payload
built outside ADR-001's single-snapshot inputs. It also adds an inter-job
artifact-name contract and a download failure mode, purely to save compile
minutes that the cargo cache already saves. No hard blocker exists for
Option A, so the simpler-provenance option wins.

### Option C — `cargo vendor` for a fully offline build

Vendor all crate sources into the repository so the image build needs no
network at all.

Rejected for now: repository bloat disproportionate to M3's small
dependency tree, while `Cargo.lock` pinning plus cargo checksumming already
bounds the drift risk. This is the designated escalation path if the
supply-chain bar rises (see revisit triggers).

## Decision

**Option A: hermetic in-container build.** The builder container carries the
pinned snapshot's own `rust`; `container-build.sh` compiles the workspace
binaries `--release --locked` and stages them into the desktop extra tree
before mkosi runs. Everything the image ships is built from one snapshot's
inputs; crates.io remains the single, lock-pinned exception, stated openly.

Deciding factors: provenance continuity with ADR-001, no inter-job
contract, identical local/CI path, and a measured build cost small enough
(~50 s) that the main argument for Option B evaporates.

## Consequences

- Easier: single toolchain provenance for shipped binaries; supply-chain
  review reduces to the workspace `Cargo.lock` plus the snapshot pin; the
  dev loop is unchanged (host-side `docker run rust:1 … cargo test` for
  code, `PUNAR_BUILD_MODE=summary` for image config).
- Harder: the image build now depends on crates.io availability at build
  time (mitigated by the CI cargo cache; escalation path is Option C); the
  builder container grows by the `rust` package; `Cargo.lock` becomes an
  image-build input (the CI cache key includes it, so lockfile changes
  rebuild the cache).
- Commits us to: keeping the workspace dependency tree small (each new
  workspace dependency is individually justified — budget and supply
  chain); bumping the pinned Rust only via snapshot bumps; labeling local
  emulated builds non-authoritative per spec 1.22.

## Revisit triggers

- The supply-chain bar rises to "image builds must be fully offline" — open
  a new ADR adopting `cargo vendor` (Option C) or a private registry
  mirror.
- A snapshot bump ships a `rust` older than the workspace `rust-version`,
  or a needed crate requires a toolchain newer than the snapshot's.
- The warm in-builder compile grows past ~10 minutes (dependency-creep
  signal; also a budget smell per section 6.2 frugality).
- A first-party binary must ship in the *base* (`punar-dev`) image, which
  has no staging path today.
