# Punar Threat Model

Status: living document, created at Milestone 0 (foundation evaluation).
Authoritative source: `docs/product/SPEC_v0.2.md`, sections 59 (Threat Model), 60 (Hard Safety
Constraints), with attack-surface input from sections 18–29 (AI runtime), 44–45 (security
baseline), and 61 (local IPC).

Honesty note (spec 1.22): at Milestone 0 **no mitigation in this document is implemented**.
Every "MVP mitigation" below is a design commitment tied to a milestone (M3–M10), not shipped
code. Each threat entry states what the MVP actually provides versus what is deferred, and the
residual risk that remains even if the MVP mitigations land as specified. Anything simulated is
labeled **SIMULATED**.

---

## 1. Scope and assumptions

### 1.1 What this model covers

- The Punar MVP as defined by the Milestone 0–13 plan (spec 76): a VM-hosted developer
  workstation with the graphical shell, `punard`/`punarctl`, the AI runtime
  (`punar-agentd`, gateway, access ledger, approval gates, secret broker), declarative
  state/reconciliation, and enrollment against a **mocked** Smplify control plane.
- Local IPC between Punar services and clients (spec 61).
- AI agent sessions launched through the managed runtime, and unmanaged AI processes running
  outside it (spec 19, 23).

### 1.2 What this model does not cover (MVP)

- Physical-device installs, evil-maid attacks, DMA attacks, and firmware compromise. The MVP
  runs in VMs; physical attack surfaces are acknowledged but out of scope until Phase 2
  physical-device work (spec 77).
- Kernel 0-days and hypervisor escape. We assume the Linux kernel and the VM host are not
  actively compromised. A root-equivalent kernel compromise defeats every mitigation here.
- A real Smplify cloud. The control plane is a local mock; threats against real cloud
  infrastructure (tenant isolation, cloud credential theft, admin account takeover at
  Smplify itself) are deferred to the Phase 2 threat-model revision.
- Chromium internals. We inherit Chromium's upstream security model and explicitly avoid
  weakening it (spec 62); we do not re-model browser-internal threats.

### 1.3 Standing assumptions

1. **VM-only.** All MVP instances run under QEMU/UTM/cloud VMs on x86_64 (host builds run in CI
   or emulated Docker; the maintainer host is macOS arm64).
2. **SIMULATED boot/measurement state.** Secure Boot and TPM 2.0 state in MVP VMs is
   **SIMULATED**: compliance surfaces may display "Boot Integrity: compliant" from mock or
   VM-provided values, and this provides **no actual boot-integrity guarantee**. Every UI,
   CLI, and API surface that reports this state MUST label it simulated (spec 1.22). Real
   Secure Boot, TPM, and hardware-backed identity are Phase 2 (spec 77).
3. **Mocked control plane.** Enrollment, policy delivery, compliance reporting, and remote AI
   queries go to a mock Smplify service (M5). Its authentication is development-grade. Nothing
   in the MVP demonstrates real control-plane security; it demonstrates the *endpoint-side*
   enforcement architecture.
4. **Single interactive user.** The MVP models one developer per device. Multi-user
   local privilege separation beyond standard Unix users is not an MVP goal.
5. **AI agents are assumed adversarial.** The design position is that any LLM-driven agent may
   emit hostile actions — via prompt injection, poisoned context, model error, or a malicious
   upstream — and enforcement therefore lives outside the agent process (gateway, broker,
   policy engine, kernel primitives), never inside its prompt.
6. **Honest UX.** The demo is deterministic and partly mocked (mock credential provider,
   fixture "unknown agent"). Mocked elements MUST be presented as such in any external
   communication.

---

## 2. Assets worth protecting

Ordered roughly by damage potential.

| # | Asset | Where it lives | Why it matters |
|---|-------|----------------|----------------|
| A1 | Credentials and secrets | Secret broker (`punar-secrets`), any legacy `.env` / `~/.ssh` / `~/.aws` material on disk | Theft converts a local compromise into cloud/production compromise. The broker exists to shrink this asset class to short-lived tokens. |
| A2 | Source code and project data | Project workspaces, repos, dev containers | Core IP; primary target of exfiltration by malicious agents or processes. |
| A3 | Privileged capability APIs | `punard` typed capability surface | The only sanctioned path to host mutation. If bypassed or widened to arbitrary root execution, all other controls are decorative. |
| A4 | Policy and desired state | Local policy store, mock control-plane channel | Tampering silently disables enforcement fleet-wide. |
| A5 | Audit trail, AI registry, access ledger | `punar-agentd`, `punard` audit log | Integrity underpins attribution, incident response, and the enterprise visibility claims. Also a *privacy* asset: it must not leak prompts, source code, or secret values (spec 21.2, 53). |
| A6 | Agent/session identity | Registry records, cgroup/scope attribution | Spoofed identity defeats per-agent policy and poisons the ledger. |
| A7 | Device identity and enrollment state | `punard` | Fake enrollment or stolen device identity misleads the (mock) fleet view. |
| A8 | Disk contents at rest | LUKS2 volume (MVP: VM disk) | Lost/stolen device scenario. In VMs this is a stand-in for the physical-device story. |
| A9 | Update and build artifacts | CI, image pipeline, dependency lockfiles | Supply-chain compromise ships to every device at once. |
| A10 | User privacy | Ledger contents, telemetry paths | "Local by default" (spec 24) is a product promise; silent upload of developer AI activity is itself a threat outcome. |

---

## 3. Trust boundaries

```text
                        UNTRUSTED / EXTERNAL
   internet ▪ model APIs ▪ package registries ▪ MCP servers ▪ web content
═══════════════════════════════╦══════════════════════════[B1 network policy]
                               ║
┌──────────────────────────────╨──────────────────────────────────────┐
│ VM GUEST (Punar)                                                    │
│                                                                     │
│  ┌────────────────────────┐      ┌───────────────────────────────┐  │
│  │ AI AGENT SESSION       │      │ USER SESSION                  │  │
│  │ claude-code / codex /  │      │ shell ▪ terminal ▪ editors ▪  │  │
│  │ child procs (bash,git) │      │ browser ▪ unmanaged processes │  │
│  │ cgroup/scope, sandbox  │      │ (incl. UNMANAGED AI)          │  │
│  └───────────┬────────────┘      └───────────────┬───────────────┘  │
│       [B2 agent boundary]              [B3 user/service boundary]   │
│              │  typed IPC (UDS, peer creds)      │                  │
│  ┌───────────▼──────────────────────────────────▼───────────────┐  │
│  │ PUNAR SERVICES (least-privileged, separate identities)        │  │
│  │ punar-agentd ▪ punar-secrets ▪ punar-env ▪ punar-netd ▪ shell │  │
│  └───────────────────────────────┬───────────────────────────────┘  │
│                        [B4 privilege boundary]                      │
│  ┌───────────────────────────────▼───────────────────────────────┐  │
│  │ punard — privileged control plane daemon                      │  │
│  │ typed capability API ▪ policy ▪ reconciliation ▪ audit        │  │
│  └───────────────────────────────┬───────────────────────────────┘  │
│  ┌───────────────────────────────▼───────────────────────────────┐  │
│  │ LINUX BASE: systemd ▪ LSM ▪ namespaces ▪ cgroups ▪ seccomp    │  │
│  │ nftables ▪ LUKS2 ▪ (Secure Boot / TPM: SIMULATED in VM)       │  │
│  └───────────────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────────┘
                    [B5 enrollment boundary]
                               │  authorized, audited queries only
                    ┌──────────▼──────────┐
                    │ MOCK SMPLIFY        │   (MVP: development-grade
                    │ control plane       │    auth; NOT a real cloud)
                    └─────────────────────┘
```

Boundary summary:

- **B1 — Network policy.** All egress from agent sessions is subject to per-agent/per-project
  network policy (`punar-netd`, nftables). Everything beyond it is untrusted input, including
  LLM API responses.
- **B2 — Agent boundary.** Managed agent sessions run in dedicated cgroups/scopes with scoped
  filesystem and network access. The agent and all its children are untrusted principals with
  a policy-defined authority envelope.
- **B3 — User/service boundary.** Ordinary user processes (including unmanaged AI) get no
  special access to Punar services; the services must treat every local peer as
  unauthenticated until proven otherwise (UDS peer credentials, session tokens).
- **B4 — Privilege boundary.** Only `punard` performs privileged host mutation, only through
  typed capabilities, never via an arbitrary-command RPC (spec 10, 1.5).
- **B5 — Enrollment boundary.** The control plane sends desired state and receives inventory /
  query results. In the MVP this boundary's authentication is **mocked** and must not be
  described as secure; the endpoint-side authorization and audit logic is what the MVP proves.

---

## 4. Threat catalog

Severity/likelihood language is qualitative and reflects the MVP (VM, mock cloud) context.

### T1. Malicious or hijacked AI agent (spec 59.1)

The flagship threat. "Malicious" includes a benign agent hijacked through prompt injection —
poisoned README, hostile web page fetched into context, malicious MCP tool output — as well as
a compromised agent binary or model backend. Assume the agent will eventually attempt every
action its environment allows.

- **Threat actors.** Remote attacker via prompt injection in repo/web/tool content; malicious
  MCP server; compromised agent vendor/update; the model itself misbehaving.
- **Entry points.** Agent process and its children (bash, git, node, cargo); MCP/tool calls;
  credential requests to the secret broker; capability/approval requests; network egress;
  filesystem writes inside and outside the workspace.
- **Impact.** Secret theft (A1), source exfiltration (A2), host mutation and persistence
  (cron, systemd units, shell rc files), production access with brokered credentials,
  MCP-abuse pivoting, ledger poisoning. Worst case: agent obtains a durable foothold with
  production credentials.
- **MVP mitigations** (M7–M10, per spec 19–29, 45):
  - Agent session identity: every managed session gets a registry record, session ID, and
    cgroup/systemd scope; children remain attributable where technically possible (spec 22).
  - Project-scoped authority: filesystem policy defaults of workspace read/write, home read,
    `~/.ssh` and `~/.aws` deny (spec 20); enforced by sandboxing primitives (namespaces,
    Landlock/LSM per the MAC ADR), not by agent cooperation.
  - Network policy: per-agent egress classes (internet / corp-dev allow, production deny)
    via `punar-netd`/nftables.
  - Secret broker: no static credentials handed to agents; short-lived scoped tokens with TTL,
    deny paths, and redaction tests (M9). MVP provider is a **mock**.
  - Approval gates: system mutation (e.g. package install) is `approval_required`, satisfied
    only by human keyboard approval with expiry and audit (spec 28).
  - Typed capabilities only: no root-shell RPC exists to abuse (spec 10).
  - Ledger + security events: denied access, credential requests, production-access attempts,
    and policy bypasses are recorded (spec 21.2 level 4) for detection and forensics.
- **Deferred / Phase 2.** Stronger sandbox; eBPF-based per-agent network/process attribution;
  real secret-manager integrations; richer MCP governance (tool allowlists, per-tool policy,
  MCP server provenance); AI behavior risk scoring (Phase 3).
- **Residual risk — material.** (a) Prompt-injected *misuse of allowed authority* is not
  preventable by this architecture: an agent with workspace write and internet egress can
  still exfiltrate the workspace it is entitled to read unless egress is tightly allowlisted,
  which conflicts with normal dev workflows. Approval gates and the ledger make it visible and
  attributable, not impossible. (b) MVP sandbox depth is unproven until the MAC ADR lands;
  until then filesystem policy may be partially advisory. (c) Child-process attribution has
  known gaps (double-fork, `setsid`, exec of setuid binaries). These are accepted MVP risks
  and must not be marketed away.

### T2. Unmanaged / shadow AI (spec 59.2, 23)

An AI tool the user runs outside the managed runtime — a downloaded agent binary, an IDE
plugin, a curl-piped installer — with the user's full ambient authority.

- **Threat actors.** Well-meaning employee installing tools; malicious insider deliberately
  avoiding the managed path; malware masquerading as an AI tool.
- **Entry points.** Any user-launched process; browser-based AI tools; agents inside dev
  containers launched without `punar-env`.
- **Impact.** Invisible credential and source access with zero policy, ledger, or attribution;
  defeats the enterprise AI-visibility value proposition; org-wide blind spot (A10, A2, A1).
- **MVP mitigations** (M10):
  - Detection heuristics: process identity, executable provenance, lineage, known AI
    signatures, characteristic network destinations, MCP activity (spec 23). The MVP ships a
    fixture unknown agent and the OBSERVED / UNKNOWN-SUSPECTED classification path with a
    local alert (spec 19.1, 25).
  - Local registry records unmanaged findings; Smplify remote query can surface them to an
    admin (mock plane).
  - Credential isolation: brokered credentials are only issued to managed sessions, so
    unmanaged agents are limited to whatever static secrets still exist on disk — which the
    broker model works to eliminate.
  - Blocking policy: enterprise policy may deny known unmanaged AI executables/destinations
    (enforcement depth in MVP: network policy and application policy, best effort).
- **Deferred / Phase 2+.** Broader AI-application discovery, eBPF-based detection, per-project
  model policy, enterprise browser policy for web AI tools.
- **Residual risk — high, and honestly stated.** Detection is heuristic. Spec 23 is explicit:
  the claim is "eliminate the blind spot", never "no shadow AI can exist". A determined
  insider with local admin (or just a renamed binary and a proxy) evades MVP detection.
  Browser-delivered AI tools are essentially invisible in the MVP. The mitigation is
  visibility plus the removal of ambient static credentials, not prevention.

### T3. Malicious local process attacking Punar services (spec 59.3, 61)

A non-AI local process (malware, compromised dependency running as the user) attacks the Punar
services themselves: impersonating clients, forging agent identity, or extracting data over
IPC.

- **Threat actors.** Malware executing as the user; a compromised build tool or npm/cargo
  dependency; a hostile process inside a dev container reaching mounted sockets.
- **Entry points.** Unix-domain sockets of `punard`, `punar-agentd`, `punar-secrets`,
  `punar-netd`; any accidentally exposed localhost TCP port; D-Bus/polkit surfaces if adopted;
  files with weak permissions (policy store, ledger DB).
- **Impact.** Fake agent registration (ledger poisoning, A5/A6), theft of brokered tokens
  (A1), unauthorized capability invocation (A3), reading other principals' registry/ledger
  data, denial of service against enforcement daemons.
- **MVP mitigations** (M3, M7, M9; spec 61):
  - Unix domain sockets only, with restrictive filesystem permissions; **no unauthenticated
    localhost TCP control API** — this is a hard requirement.
  - `SO_PEERCRED` peer-credential checks on every connection; session tokens for agent-scoped
    calls; executable-identity checks where feasible.
  - Typed, schema-validated messages with structured errors and timeouts — no string-eval
    surface, reduced parser ambiguity.
  - Policy evaluation on every capability call (authorization is per-request, not
    per-connection); all decisions audited.
  - Least privilege: services run as separate identities with systemd hardening
    (`ProtectSystem`, `NoNewPrivileges`, seccomp filters per spec 45); only `punard` holds
    privileged capability implementations.
  - Security tests required by spec 74.4: unauthorized IPC, fake agent, expired approval,
    denied credential, secret-not-logged.
  - Polkit is under evaluation for human elevation prompts (spec 61) — decision to be recorded
    in an ADR.
- **Deferred / Phase 2.** Executable provenance via signed packages / IMA-style measurement;
  stronger per-service MAC confinement after the MAC ADR; container-to-host socket exposure
  policy for dev containers.
- **Residual risk — moderate.** Same-UID processes are hard to separate on Linux: a process
  running as the user can often `ptrace` or read memory of other user processes unless YAMA
  and MAC confinement forbid it, and can imitate the user's own IPC rights. Peer-cred plus
  executable identity raises the bar but does not create a true intra-user security boundary
  in the MVP. Dev containers that mount service sockets widen B3 and need explicit policy.

### T4. Compromised or malicious control plane (spec 59.4)

The control plane (real Smplify in production; the mock in MVP) is a high-value target: it
pushes desired state and policy to every enrolled device.

- **Threat actors.** Attacker who compromises Smplify infrastructure or an admin account;
  rogue Smplify/org administrator; MITM on the enrollment channel (relevant once real
  networking exists).
- **Entry points.** Desired-state/policy delivery channel (B5); remote query interface;
  update assignments; enrollment flow.
- **Impact.** Fleet-wide: malicious policy that disables the firewall or widens AI authority,
  desired state that installs hostile software, remote queries that over-collect developer
  activity (A4, A10, A3).
- **MVP mitigations — limited by design, stated plainly.** The MVP control plane is a mock;
  the MVP does **not** demonstrate control-plane channel security. What the MVP does provide:
  - Local hard safety constraints (section 5 below) evaluated on-device: even a validly
    delivered desired state cannot invoke the MUST-NOT actions; those have no remote path.
  - Remote-query authorization on the endpoint: RBAC evaluation, scope limits, and audit of
    every query happen device-side (spec 24.1, 51.1), so an over-reaching admin request is
    denied and recorded locally regardless of what the control plane claims.
  - Typed desired-state schema: the control plane can only request what the schema and
    capability registry expose — there is no "run this command on the fleet" primitive.
- **Deferred / Phase 2 (spec 59.4 lists these as future).** Signed policy and signed desired
  state with keys pinned on-device; strong device identity/verification (hardware-backed);
  restricted high-risk actions requiring additional authorization (e.g. dual control);
  real transport security and enrollment attestation; on-prem deployment.
- **Residual risk — high until Phase 2, low exposure in MVP.** In the MVP the mock plane is
  local and the exposure is theoretical; but architecturally, until signed state lands, a
  compromised plane can reconfigure everything outside the hard-constraint list. The hard
  constraints are therefore the only fleet-compromise backstop and their enforcement quality
  is critical (see section 5).

### T5. Lost or stolen device (spec 59.5)

- **Threat actors.** Opportunistic thief; targeted attacker with physical possession.
- **Entry points.** Disk at rest; suspended/locked sessions; credentials cached on the device.
- **Impact.** Disclosure of A1/A2/A8; use of still-valid credentials; enrollment identity
  abuse (A7).
- **MVP mitigations.**
  - LUKS2 full-disk encryption, on by default for managed installs (spec 44.2). In MVP this
    is a VM disk — it exercises the install/unlock/recovery flow, and the protection it
    provides against a *host*-level reader is real, but the lost-laptop scenario itself is
    not reproducible in a VM and MVP claims must say so.
  - **SIMULATED:** TPM-assisted unlock and any boot-integrity binding. VM "TPM" state, if
    surfaced, is simulated and provides no anti-tamper guarantee.
  - Short-lived credentials: the broker's TTL model means a powered-off stolen device holds
    few or no live secrets — this is the strongest genuine MVP mitigation for this threat.
  - Screen lock policy via enterprise service controls (spec 44.5).
  - No recovery material in logs (spec 44.2), covered by redaction tests.
- **Deferred / Phase 2.** Real TPM sealing and measured boot; hardware-backed device
  identity; remote credential/device revocation ("remote revocation future", spec 59.5);
  production LUKS recovery flows.
- **Residual risk — moderate.** A device stolen while unlocked exposes everything the user
  session can reach. Without TPM binding, an attacker who obtains the passphrase (shoulder
  surfing, coercion) gets everything; without remote revocation, the org cannot invalidate a
  stolen enrolled device except by rotating credentials server-side.

### T6. Supply chain (spec 59.6)

- **Threat actors.** Compromised upstream package or base-distro mirror; malicious
  crate/npm dependency; compromised CI (GitHub Actions) or maintainer account; typosquatting.
- **Entry points.** Base image composition; Rust/JS dependency graphs of Punar services;
  container images pulled by `punar-env`; the CI pipeline that produces VM images; the
  Chromium build/packaging path.
- **Impact.** Attacker code inside the trusted computing base — inside B4 — which invalidates
  every other section of this document. Also: poisoned dev containers attacking developer
  projects (feeds T1/T3).
- **MVP mitigations** (M0 onward — this threat is live *now*, at Milestone 0):
  - Pinned dependencies: lockfiles committed for every language ecosystem; base-image package
    versions pinned in the image definition.
  - Signed artifacts: verify upstream distro package signatures during image build; sign
    Punar-produced release artifacts in CI; record checksums of published VM images.
  - Reproducible builds where possible (spec 59.6's own qualifier): the image pipeline should
    be deterministic enough that CI rebuilds are comparable; full bit-for-bit reproducibility
    is not an MVP promise.
  - CI hygiene: pinned action versions, least-privilege tokens, no secrets in build logs.
- **Deferred (spec 59.6 marks these future).** SBOM generation; provenance attestation
  (SLSA-style); software provenance for detection inputs (spec 77); signed OS update chain
  with real Secure Boot anchoring.
- **Residual risk — high, industry-standard.** Dependency pinning defends against silent
  drift, not against a maliciously published pinned version. The dependency graph of a Rust +
  TypeScript + Chromium + Linux distro is enormous; the MVP posture is containment (least
  privilege, typed capabilities) and auditability, not supply-chain immunity.

---

## 5. Hard safety constraints (spec 60) — normative

The following MUST-NOT list is normative for all Punar code. "AI" below means any AI agent,
managed or not, and any action initiated by AI intent through any interface — including a
capability request that policy would otherwise allow. These actions MUST NOT be directly
executable by AI under any policy configuration; each requires an explicit privileged human
workflow (interactive, authenticated, audited, and outside the AI-reachable API surface).

| # | Constraint | Enforcement approach |
|---|-----------|----------------------|
| C1 | AI MUST NOT disable Secure Boot. | No capability API mutates Secure Boot/boot-chain configuration at all in MVP (state is **SIMULATED** in VMs anyway; simulated state is read-only to all principals). Phase 2: boot configuration handled only by a human-interactive privileged workflow with no programmatic capability mapping; capability registry review gates any addition. |
| C2 | AI MUST NOT disable disk encryption. | No `DisableEncryption`-shaped capability exists. Encryption is established at install time; the capability registry exposes status read-only. Changing encryption requires reinstall or a human-only recovery workflow. Tested by asserting the capability registry contains no mutating encryption capability reachable with `source=ai_agent`. |
| C3 | AI MUST NOT disable audit. | Audit emission is unconditional in `punard`/`punar-agentd` code paths — not policy-controllable. No capability stops the audit service; systemd restarts it; an AI-sourced request to stop/mask audit units is denied at the policy layer as a hard rule (evaluated before, and regardless of, org policy). Security event logged on attempt. |
| C4 | AI MUST NOT add persistent unrestricted root (no new root users, sudoers entries, setuid shells, or equivalent). | No generic user-management or sudoers capability is exposed to AI principals; `RunRootShell`-style APIs are prohibited by architecture (spec 10). Filesystem sandbox denies agent writes to `/etc/sudoers*`, systemd unit dirs, and PAM config. Drift detection treats unexpected root-capable accounts/units as reportable drift. Covered by the spec 74.4 fake-agent and unauthorized-IPC tests plus a dedicated persistence test fixture. |
| C5 | AI MUST NOT export recovery keys. | The secret broker has no capability that returns LUKS recovery material to any caller; recovery keys are never held by `punar-secrets` (spec 44.2: no recovery material in logs — extended here to: no recovery material via IPC). Redaction tests assert recovery-key patterns never appear in logs, ledger, or broker responses. |
| C6 | AI MUST NOT change trusted control-plane keys. | Enrollment trust anchors are stored root-owned, outside every AI-writable mount, with no mutating capability exposed. Re-keying is a human re-enrollment workflow. (MVP honesty: with a mock plane these keys are development-grade; the *enforcement shape* — no AI-reachable mutation path — is what MVP implements and tests.) |
| C7 | AI MUST NOT weaken Punar security services (stop/disable/reconfigure `punard`, `punar-agentd`, `punar-secrets`, `punar-netd`, or their sandboxing). | Hard-rule deny in the policy engine for AI-sourced service-control requests targeting the protected set, evaluated before org policy and not overridable by it. Agent sandbox denies write access to Punar binaries, unit files, and config. Attempts raise level-4 security events. |
| C8 | AI MUST NOT bypass AI policy enforcement (self-modify policy, tamper with the ledger, forge identity/attribution). | Policy store and ledger are owned by service identities, unwritable from agent sandboxes; ledger is append-only at the service API; agent session tokens cannot invoke policy-mutation capabilities (enforced by principal type, not by policy config — a misconfigured org policy cannot grant it). Fake-agent and policy-bypass attempts are required security tests (spec 74.4). |

Enforcement principles common to all eight:

1. **Absence over denial where possible.** The strongest enforcement is that no typed
   capability exists for the action (C1, C2, C5, part of C4). What does not exist cannot be
   mis-policied.
2. **Hard rules above policy.** Where a capability must exist for humans (C3, C7, C8),
   the AI-source deny is a constant in the authorization code path, evaluated before merged
   preference/org policy, and not expressible as an override in any policy schema.
3. **Kernel-backed backstops.** Sandbox/MAC denials back up API-layer denials, so a bug in one
   layer is not sufficient.
4. **Attempt visibility.** Every attempt against C1–C8 is a recorded security event (ledger
   level 4 + audit), because an agent probing these boundaries is itself a critical signal.
5. **Tests as spec.** Each constraint gets at least one automated security test (M3/M7/M9
   suites, spec 74.4). A constraint without a failing-path test is treated as unimplemented.

---

## 6. Open questions

1. **MAC mechanism.** SELinux vs AppArmor vs Landlock vs pure systemd sandboxing (spec 44.3)
   determines the real depth of B2/B3 and of constraints C4/C7/C8. Blocked on the substrate
   ADR (M0) and a dedicated MAC ADR. Until decided, sandbox claims in this document are
   design intent.
2. **Same-UID isolation.** How far can we separate an agent session from the user's other
   processes when both run as the same Unix user? Do we run agent sessions as dedicated
   subordinate UIDs / user namespaces? Affects T1 and T3 residual risk materially.
3. **Child-process attribution limits.** What is the accepted false-negative rate for
   double-fork/daemonizing children escaping the session cgroup, and do we need eBPF (Phase 2)
   sooner than planned to make ledger claims honest?
4. **Dev-container socket exposure.** Which Punar sockets, if any, are mounted into
   `punar-env` containers, and with what identity? Every mounted socket widens B3.
5. **Exfiltration vs usability.** Default-allow internet egress for agents (spec 20 example)
   makes workspace exfiltration by a prompt-injected agent trivial. Do we ship a
   domain-allowlist mode, a data-egress budget, or accept and document visibility-only?
   Needs a product decision before M10 marketing claims.
6. **Polkit adoption.** Use polkit for human approval/elevation (spec 61) or keep approvals
   fully inside `punard`? Affects the approval-gate trust chain (T3).
7. **Ledger integrity.** Append-only via service API is not tamper-proof against root. Do we
   need local sealing/forward-integrity (hash chaining) in MVP, or is that Phase 2 alongside
   SIEM export?
8. **Simulated-state labeling mechanics.** Where exactly is the "SIMULATED" flag carried —
   per-compliance-item metadata in the schema? — so that no UI/CLI surface can display
   simulated Secure Boot/TPM state without the label (spec 1.22). Should be settled in the M4
   schema design.
9. **Mock-plane security floor.** Even as a mock, should the M5 control plane exercise real
   mTLS + signed state so Phase 2 is a key-swap rather than a redesign? Cost/benefit ADR
   needed at M5.
10. **Browser-based AI visibility.** Web AI tools bypass process-level shadow-AI detection
    entirely (T2). Is any MVP-scope signal (network destination classes) worth surfacing, or
    is this explicitly deferred to enterprise browser policy (Phase 3)?

---

## Revision expectations

This document must be revised at minimum at: the substrate/MAC ADRs (M0+), IPC implementation
(M3), enrollment (M5), agent runtime (M7), secret broker/approvals (M9), shadow-AI MVP (M10),
and before any Phase 2 work replaces a SIMULATED element with a real one — at which point the
corresponding labels here must be removed, not merely the marketing updated.
