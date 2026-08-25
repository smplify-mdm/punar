# Punar

> **Status: pre-alpha. Milestone 0 (Foundation evaluation) is done;
> Milestone 1 (Lightweight graphical workstation) has a green CI gate with
> one acceptance item left; Milestones 2–7 (Native multitasking; `punard` +
> `punarctl`; Declarative desired state; Mock Smplify enrollment; Developer
> environment manager; AI Agent Registry) are done — CI-proven; Milestone 8
> (AI Access Ledger) is committed and pushed with its host-side CI jobs
> green, but its in-VM exercise has still never run; Milestone 9 (Approval
> gates + secret broker) is implemented on disk, uncommitted, awaiting its
> first CI run.** The last fully green CI run is
> [32877949285](https://github.com/smplify-mdm/punar/actions/runs/32877949285)
> (2026-08-25): the `punar-desktop` image (Hyprland + punar-shell) builds,
> boots, and passes the graphical gate plus the in-VM M2 multitasking, M3
> control-plane, M4 policy-merge/drift-remediation, M5 mock-enrollment, M6
> developer-environment and M7 AI-agent-registry exercises
> (`PUNAR_DESKTOP_OK` + `PUNAR_M2_OK` + `PUNAR_M3_OK` + `PUNAR_M4_OK` +
> `PUNAR_M5_OK` + `PUNAR_M6_OK` + `PUNAR_M7_OK`; 282 in-VM assertions;
> idle RAM 1163 MB mean — under the 1.5 GB hard ceiling, over the 1.0 GB
> target; `punard` + `punar-agentd` services RSS 4 MB combined against a
> 100 MB target). M1's keyboard-only human walkthrough is still pending.
>
> That green run also carries an honest correction: **it did not execute
> the M8 exercise.** `m8-check.sh` shipped non-executable, its oneshot
> failed to start, and the boot harness downgraded the missing verdict to
> a warning — so a green run claimed a milestone that had not run. The
> harness now treats a missing M2..M8 verdict as a hard failure, and that
> fix is committed locally but not yet pushed. No `PUNAR_M8_OK` exists
> anywhere; M8's ledger code is CI-built and CI-tested, not CI-exercised.
>
> M9 — approval gates and the secret broker, where spec section 28 stops
> being a schema — is implemented on disk and statically validated
> locally: a typed capability call an AI agent may not make on its own
> **stops**, returning `approval_required` with nothing applied and CLI
> exit 4; a card appears on the user's own screen naming the exact
> capability, the policy that gated it and the audit promise, with a live
> expiry countdown and keyboard approve/deny; and the call executes only
> if a human answers yes. An AI agent may approve **nothing** — not its
> own request, not anyone's — and may never hold a standing privilege
> window. `punar-secrets`, a third daemon, issues short-lived **mock**
> credentials from a data catalog; a token leaves it exactly once, on a
> file descriptor, and the broker keeps only its SHA-256, so no method
> anywhere in Punar can return a token twice. `schemas/audit/approval.json`
> is not modified by one byte. The in-VM exercise, including the redaction
> sweep that greps every file Punar writes for the tokens it issued, has
> never run. See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for
> what exists versus what is proven.

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
