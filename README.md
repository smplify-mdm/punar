# Punar

> **Status: pre-alpha. Milestone 0 (Foundation evaluation) is done; Milestone 1
> (Lightweight graphical workstation) has a green CI gate with one acceptance
> item left; Milestone 2 (Native multitasking) is done — CI-proven; Milestone 3
> (`punard` + `punarctl`) is done — CI-proven; Milestone 4 (Declarative
> desired state) is implemented but its CI gate is red; Milestone 5 (Mock
> Smplify enrollment) is implemented on disk, awaiting its first CI
> run.** The last fully green CI run is
> [32828986305](https://github.com/smplify-mdm/punar/actions/runs/32828986305):
> the `punar-desktop` image (Hyprland + punar-shell) builds, boots, and
> passes the graphical gate plus the in-VM M2 multitasking and M3
> control-plane exercises (`PUNAR_DESKTOP_OK` + `PUNAR_M2_OK` +
> `PUNAR_M3_OK`; idle RAM 1160 MB mean — under the 1.5 GB hard ceiling,
> over the 1.0 GB target; `punard` services RSS 2 MB against a 100 MB
> target). M1's keyboard-only human walkthrough is still pending. M4 — the
> layered desired-state store, spec section 39 preference/policy merge,
> remediating reconciliation, and `punarctl policy effective` / `policy
> explain` — is committed; its first CI run
> ([32837156881](https://github.com/smplify-mdm/punar/actions/runs/32837156881))
> failed on exactly one check-wiring assertion (timer enablement semantics)
> while every other in-VM assertion, including the timer-driven
> firewall-drift remediation demo, passed; the fix is pushed but its run
> failed earlier on in-progress M5 code bundled into the same commit, so M4
> still has no green run. M5 — an in-VM mock control plane, live
> enroll/unenroll with the shell's org chrome flipping on real enrollment
> state, spec-40 managed explain, category-level-only compliance and
> inventory sync, offline survival — is implemented: the full tree,
> including the in-VM m5-check exercise and its CI wiring, is on disk and
> statically validated locally, but it is not yet pushed and nothing M5
> has ever run in CI (the one run containing M5 code carried a
> non-compiling mid-integration snapshot). See
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
