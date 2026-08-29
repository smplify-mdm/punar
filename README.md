# Punar

> **Status: pre-alpha, suitable for controlled VM evaluation—not production
> deployment.** The x86_64 image pipeline and generic UEFI ARM64 desktop are
> real. The shared graphical desktop and M2–M10 exercises run in clean VMs;
> the latest local ARM64 gate carries 713 passing milestone assertions plus
> 122 passing desktop-surface assertions. M11's curated Applications library
> and secure vendor-package backend are partial. M12's network daemon, typed policy
> compiler, nftables apply boundary, local connection view and simulated relay
> exist, but its planned end-to-end enforcement gate and AI-ledger join do not.
> Raspberry Pi hardware, broad bare-metal compatibility, production signing
> and update infrastructure, recovery/installer UX, external security review,
> and a release support process remain open. The tracked split between built,
> runtime-proven, and still-open work is in
> [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and
> [BUILD-QUEUE.md](BUILD-QUEUE.md).

Punar, by Smplify, is a lightweight, privacy-first, AI-native Linux operating
system for developer workstations. It targets existing 8–16 GB enterprise
hardware and combines a keyboard-first graphical desktop with fluid
multitasking, modern Chromium-class web-app support, and private networking,
while building enterprise security and Smplify's declarative governance into
the OS itself rather than layering resident MDM, VPN, and telemetry agents on
top. AI agents run as first-class, OS-managed entities: identified,
scope-limited, locally observable, and auditable, instead of opaque shell
processes with inherited user privileges.

## Authoritative specification

[`docs/product/SPEC_v0.2.md`](docs/product/SPEC_v0.2.md) is the authoritative
product and implementation specification. Where any document in this
repository disagrees with the spec, the spec wins.

## Repository layout

The layout follows spec section 67.

| Path | Contents |
| --- | --- |
| `docs/` | Documentation: `architecture/` (incl. `adr/`), `product/`, `threat-model/`, `api/`, `privacy/`, `networking/`, `development/` |
| `os/` | OS build: `modules/`, `profiles/`, `images/` |
| `crates/` | Rust workspaces: `punard`, `punarctl`, `punar-policy`, `punar-agentd`, `punar-secrets`, `punar-workspace`, `punar-netd`, `punar-common` |
| `shell/` | Graphical shell |
| `browser/` | Chromium packaging and `integration/` |
| `schemas/` | Typed schemas: `desired-state/`, `policy/`, `capability/`, `ai-agent/`, `audit/`, `network/` |
| `proto/` | IPC protocol definitions |
| `fixtures/` | Mock data: `organizations/`, `policies/`, `agents/`, `projects/` |
| `tests/` | `unit/`, `integration/`, `vm/`, `performance/`, `security/` |
| `tools/` | Development and build tooling |

Maintained tracking documents (spec section 1, instruction 18):
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md),
[ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md),
[PERFORMANCE_BUDGETS.md](PERFORMANCE_BUDGETS.md), and
[docs/threat-model/THREAT_MODEL.md](docs/threat-model/THREAT_MODEL.md).

## Trying it

```bash
./tools/punar-up.sh
```

Fetches the newest CI-built desktop image, verifies its checksum, boots it in
QEMU and opens the viewer. The ten-minute walkthrough — which chords to press,
in what order, and an explicit list of what is real, what is simulated and
what is not built at all — is
[`docs/development/testing-the-vm.md`](docs/development/testing-the-vm.md).

## Developing

See [`docs/development/getting-started.md`](docs/development/getting-started.md).
Short version: the maintainer host is macOS arm64; Rust builds and tests run in
Docker. x86_64 image builds are canonical in CI today; ARM64 and Raspberry Pi
are required targets whose image and physical-hardware gates are not built yet.

Before touching `shell/**.qml`, run `./tools/qmllint.sh` — it lints against the
image's own Qt and Quickshell, and it fails on any output because qmllint
itself exits 0 while printing warnings.

## License

Punar's first-party code is licensed under the [Apache License 2.0](LICENSE). Upstream packages shipped in Punar images retain their own licenses.
