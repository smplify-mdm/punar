# Punar

> **Status: pre-alpha. Milestone 0 (Foundation evaluation) is done; Milestone 1
> (Lightweight graphical workstation) has a green CI gate with one acceptance
> item left; Milestone 2 (Native multitasking) is done — CI-proven; Milestone 3
> (`punard` + `punarctl`) is in progress.** The `punar-desktop` image (Hyprland
> + punar-shell) builds, boots, and passes the graphical gate plus the in-VM M2
> multitasking exercise in CI
> ([run 32825539021](https://github.com/smplify-mdm/punar/actions/runs/32825539021),
> `PUNAR_DESKTOP_OK` + `PUNAR_M2_OK`; idle RAM measured at 1157 MB mean — under
> the 1.5 GB hard ceiling, over the 1.0 GB target). M1's keyboard-only human
> walkthrough is still pending. M3 — the `punard` daemon, typed IPC over a
> Unix socket, the first three real capabilities (firewall, hostname,
> timezone), the real `punarctl` CLI, and the audit trail — is implemented and
> statically validated on disk (the hermetic in-image build strategy is
> ADR-002); no CI run includes it yet. See
> [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for what exists versus
> what is proven.

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

## Developing

See [`docs/development/getting-started.md`](docs/development/getting-started.md).
Short version: the maintainer host is macOS arm64; Rust builds and tests run in
Docker, and x86_64 image builds are canonical in CI.

## License

Punar's first-party code is licensed under the [Apache License 2.0](LICENSE). Upstream packages shipped in Punar images retain their own licenses.
