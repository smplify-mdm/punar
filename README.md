# Punar

> **Status: pre-alpha. Milestone 0 (Foundation evaluation) is done;
> Milestone 1 (Lightweight graphical workstation) has a green CI gate with
> one acceptance item left; Milestones 2–9 (Native multitasking; `punard` +
> `punarctl`; Declarative desired state; Mock Smplify enrollment; Developer
> environment manager; AI Agent Registry; AI Access Ledger; Approval gates +
> secret broker) are done — CI-proven, in-VM; Milestone 10 (Shadow AI
> detection MVP) is implemented on disk and statically validated, but
> uncommitted and with no CI run.** The last fully green CI run is
> [32899132191](https://github.com/smplify-mdm/punar/actions/runs/32899132191)
> (2026-08-25): the `punar-desktop` image (Hyprland + punar-shell) builds,
> boots, and passes the graphical gate plus the in-VM M2 multitasking, M3
> control-plane, M4 policy-merge/drift-remediation, M5 mock-enrollment, M6
> developer-environment, M7 AI-agent-registry, M8 access-ledger and M9
> approval-gate exercises (`PUNAR_DESKTOP_OK` + `PUNAR_M2_OK` 33 +
> `PUNAR_M3_OK` 28 + `PUNAR_M4_OK` 29 + `PUNAR_M5_OK` 63 + `PUNAR_M6_OK` 55
> + `PUNAR_M7_OK` 74 + `PUNAR_M8_OK` 123 + `PUNAR_M9_OK` 137 = **542 in-VM
> assertions**; idle RAM 1155 MB mean — under the 1.5 GB hard ceiling, over
> the 1.0 GB target; `punard` + `punar-agentd` + `punar-secrets` services
> RSS 6 MB combined against a 100 MB target). M1's keyboard-only human
> walkthrough is still pending.
>
> That run closes two honest caveats this file used to carry. **M8 and M9
> have now produced their first real verdicts.** An earlier green run had
> claimed M8 without executing it — `m8-check.sh` shipped non-executable,
> its oneshot failed to start, and the boot harness downgraded the missing
> verdict to a warning. A missing M2..M9 verdict is now a **hard failure**,
> and both exercises then ran for real. Getting there cost one genuine
> product bug in M8 (a pre-registration race dropped an attribution that
> arrived before its session existed, so a Level-4 denial never joined the
> ledger) and, in M9, **no product defect at all**: the approval gate
> executed correctly and it was the *checking* that was wrong — a stale
> proxy observation, three `jq` filters that errored instead of evaluating,
> and a redaction grep aimed at a non-secret token prefix. No assertion was
> weakened to obtain green; the corrected redaction sweep finds **zero**
> hits for the issued secrets across everything Punar writes, the journal,
> and every process environment.
>
> M10 — shadow-AI detection, where spec section 23's promise stops
> depending on someone looking — is implemented on disk and statically
> validated: a 240 s systemd timer (coalescing with the existing 120 s
> reconcile timer, no polling loop) classifies **managed / observed /
> unknown** on its own; an unmanaged agent gets a persisted record and a
> ledger that is **structurally smaller** than a managed one — a process
> class, a zone class, the security-event references, and no cmdline, no
> `cwd`, no process tree, ever; **one** alert per signature, raised from a
> **root-owned** state file, saying *suspected*, naming the policy, and
> stating plainly that **nothing was blocked**, because M10 is not armed.
> An administrator can ask this device four scoped questions — and does so
> only because **the device fetched the question**: Punar opens no inbound
> port, the daemon holding the data re-evaluates authorization from local
> enrollment state rather than from the request, and every query, answered
> or refused, is printed to the user by an **unprivileged** command. On a
> personal device the whole path is inert behind three independent gates.
> **None of this has run in a VM**: no `PUNAR_M10_OK` exists anywhere, the
> timer has never been observed firing, and no alert card has been
> screenshotted. See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)
> for what exists versus what is proven.

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
Docker, and x86_64 image builds are canonical in CI.

Before touching `shell/**.qml`, run `./tools/qmllint.sh` — it lints against the
image's own Qt and Quickshell, and it fails on any output because qmllint
itself exits 0 while printing warnings.

## License

Punar's first-party code is licensed under the [Apache License 2.0](LICENSE). Upstream packages shipped in Punar images retain their own licenses.
