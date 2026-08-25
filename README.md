# Punar

> **Status: pre-alpha. Milestone 0 (Foundation evaluation) is done;
> Milestone 1 (Lightweight graphical workstation) has a green CI gate with
> one acceptance item left; Milestones 2–6 (Native multitasking; `punard` +
> `punarctl`; Declarative desired state; Mock Smplify enrollment; Developer
> environment manager) are done — CI-proven; Milestone 7 (AI Agent Registry)
> is implemented on disk, uncommitted, awaiting its first CI run.** The last
> fully green CI run is
> [32857914904](https://github.com/smplify-mdm/punar/actions/runs/32857914904)
> (2026-08-25): the `punar-desktop` image (Hyprland + punar-shell) builds,
> boots, and passes the graphical gate plus the in-VM M2 multitasking, M3
> control-plane, M4 policy-merge/drift-remediation, M5 mock-enrollment, and
> M6 developer-environment exercises (`PUNAR_DESKTOP_OK` + `PUNAR_M2_OK` +
> `PUNAR_M3_OK` + `PUNAR_M4_OK` + `PUNAR_M5_OK` + `PUNAR_M6_OK`; 209 in-VM
> assertions; idle RAM 1162 MB mean — under the 1.5 GB hard ceiling, over
> the 1.0 GB target; `punard` services RSS 2 MB against a 100 MB target).
> M1's keyboard-only human walkthrough is still pending.
> M7 — the AI agent registry, where spec sections 18–27 become a running
> surface: `punar-agentd` serving a typed `agents.*` API on its own socket,
> `punar-env agent <name>` launching a *managed* session into its own
> `systemd` scope with a registry identity, two agent adapters shipped as
> data (Claude Code and a generic shell), identity checked from peer
> credentials and the kernel's cgroup rather than claimed, `managed` /
> `observed` / `unknown` classification whose unknown rows always say
> *suspected*, and the `SUPER + A` AI panel — is implemented: the full
> tree, including the in-VM m7-check exercise and its CI wiring, is on disk
> and statically validated locally, but it is uncommitted and nothing M7
> has ever run in CI. What M7 shows but does not yet enforce is labeled as
> such: authority rows read `declared · M9`/`declared · M12`, and the
> access ledger (spec section 21) renders as a dashed Milestone-8
> placeholder because M7 builds the registry only. See
> [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for what exists
> versus what is proven.

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
