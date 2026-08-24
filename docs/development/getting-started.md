# Getting Started

Development workflow for the current reality of this project (Milestone 0).
This document describes what actually works today, not the eventual developer
experience.

## Current maintainer environment

- Host: macOS on Apple Silicon (arm64).
- Installed: Docker Desktop, Lima, git.
- **Not installed locally: rust/cargo, qemu, nix, shellcheck.** Do not write
  instructions or scripts that assume these exist on the host. Anything that
  needs a Linux userland or a Rust toolchain runs in a container or a VM.

## Rust builds and tests

Run cargo through the official Rust image, mounting the repository:

```sh
docker run --rm -v /path/to/smplify-punarOS:/w -w /w rust:1 cargo test
```

Substitute `cargo build`, `cargo check`, `cargo clippy` (after
`rustup component add clippy` in the container), etc. as needed. Notes:

- The container is arm64 by default on this host, which is fine for unit and
  integration tests of the Rust crates.
- Nothing persists between runs except files written into the mounted repo.
  Expect a cold dependency download on each run until a cargo cache volume is
  added (e.g. `-v punar-cargo-cache:/usr/local/cargo/registry`).

## x86_64 image builds

CI is the canonical environment for x86_64 OS image builds and VM boot tests.
A local x86_64 run is possible via emulation:

```sh
docker run --rm --platform linux/amd64 -v /path/to/smplify-punarOS:/w -w /w <image> <build command>
```

but this is QEMU-emulated on the arm64 host: slow (often 5–10x), and any
performance number produced under emulation is meaningless against the budgets
in `PERFORMANCE_BUDGETS.md`. Use emulated local runs only to debug build
scripts, never to measure.

## Lima as an alternative Linux VM

Lima is installed and can provide a persistent Linux VM when a container is
awkward (systemd, loop devices, image assembly experiments):

```sh
limactl start default
limactl shell default
```

The default Lima guest is arm64 Linux; x86_64 guests under Lima are emulated
and share the same slowness caveat as `--platform linux/amd64` containers.

## What does not exist yet

Being explicit per spec section 1.22:

- No bootable Punar image exists. There is nothing to install or run.
- The CI workflow is authored at `.github/workflows/ci.yml`, but no run has
  executed yet; nothing it builds has been verified. See
  `docs/development/image-pipeline.md` for the verification status table.
- No local qemu means VM boot verification happens in CI, not on the host.

## Repository conventions

- The spec is authoritative: `docs/product/SPEC_v0.2.md`.
- Status tracking: `IMPLEMENTATION_STATUS.md` (update it when a deliverable
  lands, in the same change).
- Decisions: `ARCHITECTURE_DECISIONS.md` and `docs/architecture/adr/`.
- Performance claims require a measurement with its environment labeled;
  simulated or emulated results must say so.
