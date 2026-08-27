# Punar
## Product Requirements, Technical Architecture, and Claude Code Build Specification

**Document version:** 0.2  
**Status:** Implementation specification / reference architecture  
**Primary consumer:** Claude Code  
**Product:** Punar  
**Parent company / enterprise control plane:** Smplify  
**Product category:** Lightweight, AI-native, privacy-first, enterprise-ready developer operating system  
**Initial targets:** x86_64 developer laptops/workstations and ARM64
Raspberry Pi-class devices, on bare metal and in VMs; 8 GB–16 GB developer
machines

**Secondary target:** higher-end AI workstations

---

# 0. Executive Summary

Punar is a modern Linux operating system designed for engineers and organizations that want:

- a fast, polished developer workstation;
- excellent support for AI-assisted software development;
- strong privacy;
- enterprise-grade security;
- native Smplify management and governance;
- low memory and CPU overhead;
- long hardware life;
- auditable AI-agent usage;
- excellent graphical multitasking;
- full keyboard control without requiring a mouse;
- modern Chromium-class web-app support;
- native private relay / enterprise network routing;
- a workstation that can make older enterprise hardware useful again.

Punar should be attractive enough that an engineer chooses it voluntarily.

At the same time, an enterprise should be able to deploy Punar without layering multiple heavyweight security, MDM, VPN, privilege, telemetry, and AI-governance agents on top of the OS.

The product thesis is:

> **Developers should not have to choose between a workstation they love, a workstation that respects their privacy, and a workstation their organization can trust.**

The hardware thesis is:

> **Modern computing should not require wasteful hardware upgrades. Punar should make existing 8 GB and 16 GB enterprise laptops feel useful again.**

The platform thesis is:

> **Bare-metal performance is a product requirement, not a demo optimisation.
> x86_64 and ARM64 are first-class architectures; Raspberry Pi-class devices
> are a primary appliance and inference target, not an optional port after the
> desktop is finished.**

The AI thesis is:

> **AI agents should be powerful, visible, attributable, governed, and constrained by the operating system instead of being opaque shell processes with inherited user privileges.**

The enterprise thesis is:

> **Enterprise security should be built into the operating system through native OS primitives and Smplify’s declarative control plane rather than added through a pile of resident agents.**

---

# 1. Instructions to Claude Code

Treat this document as the authoritative product and implementation specification.

Claude Code should:

1. Keep every milestone bootable.
2. Prefer simple, auditable architecture over cleverness.
3. Treat RAM, CPU, disk I/O, boot time, and background activity as first-class engineering budgets.
4. Keep privileged system behavior deterministic.
5. Never expose a generic root-command RPC.
6. Never give AI agents unrestricted host root access.
7. Never allow an LLM to directly mutate critical host security configuration.
8. Route privileged changes through typed capability APIs.
9. Separate user preferences, organization policy, and OS hard safety constraints.
10. Build unmanaged/community mode and managed/enterprise mode from the same core OS.
11. Make enterprise functionality additive rather than required for basic usability.
12. Keep AI activity data local by default.
13. Keep the administrator query model explicit and privacy-preserving.
14. Avoid broad filesystem/network tracing when aggregation or scoped kernel primitives can provide the required evidence.
15. Build graphical UX and CLI against the same underlying capability APIs.
16. Make every first-party graphical workflow keyboard operable.
17. Do not rely on the terminal for ordinary OS administration.
18. Maintain `IMPLEMENTATION_STATUS.md`, `ARCHITECTURE_DECISIONS.md`, `PERFORMANCE_BUDGETS.md`, and `THREAT_MODEL.md`.
19. Add automated tests for policy, reconciliation, approvals, agent identity, local AI ledger, secret redaction, privilege boundaries, drift remediation, and performance budgets where practical.
20. Do not implement every roadmap item at once. Follow milestones.
21. Optimize the MVP for a deterministic hero demo.
22. Treat unsupported security claims honestly. Simulated Secure Boot/TPM state in VMs must be labeled as simulated.
23. Keep external-vendor integrations behind interfaces.
24. Avoid deep forks of upstream projects unless absolutely necessary.
25. Prefer upstream compatibility for Chromium, Linux, Wayland, and container standards.
26. Keep architecture-dependent code at the image and boot boundary; security,
    privacy, policy and agent guarantees must remain architecture-neutral.
27. Prove performance and hardware support on bare metal. VM-only evidence is
    necessary for CI but insufficient for a hardware-support claim.
28. The first success criterion is:

> A developer can boot Punar on an 8–16 GB machine, use a polished keyboard-first graphical desktop, enroll into a mocked Smplify organization, open a project workspace, run an AI coding agent with scoped authority, observe that agent locally, perform approval-gated actions, and see policy enforcement and drift remediation.

---

# 2. Product Identity

## 2.1 Name

**Punar**

Working public attribution:

> **Punar by Smplify**

Possible editions:

- Punar Community
- Punar Enterprise

## 2.2 Meaning

Punar represents:

- again;
- renewal;
- another life;
- taking capable hardware into a new computing era.

The brand must not feel like “recycled laptop Linux.” Punar is forward-looking.

The message is:

> **Use the hardware you already have for the AI era.**

## 2.3 Positioning

Primary:

> **The lightweight workstation for the AI era.**

Supporting ideas:

> **Built for developers. Designed for AI. Trusted by enterprise.**

> **Modern computing on the hardware you already own.**

> **Fast. Private. Secure. AI-native. Enterprise-ready.**

---

# 3. Core Product Pillars

## 3.1 Efficient by design

The OS should use as little RAM, CPU, disk activity, and battery as practical. The operating system must leave resources available for the developer’s workload.

## 3.2 Developer-first

Punar must be desirable without enterprise enrollment. The unmanaged edition must be a genuinely excellent engineering workstation.

## 3.3 Keyboard-first graphical computing

Punar is not terminal-only. The primary user experience is a graphical operating system whose complete first-party workflow can be operated from the keyboard. The terminal remains excellent and first-class.

## 3.4 Native multitasking

Window management, project switching, multi-monitor behavior, scratchpads, and workspace restoration should be signature product experiences.

## 3.5 AI-native

AI agents are first-class OS principals with identity, authority, observability, policy, network constraints, and auditability.

## 3.6 Private by default

Punar should minimize unnecessary data collection and make network behavior visible. AI activity data should remain local by default.

## 3.7 Enterprise-native

Punar integrates Smplify’s declarative management model directly into the OS. Enterprise controls should be native primitives rather than heavyweight after-market agents.

---

# 4. Product Non-Goals

Punar is not:

- a custom Linux kernel;
- an Omarchy clone;
- a themed stock distro;
- a terminal-only operating system;
- a traditional MDM agent;
- a security appliance;
- a mandatory cloud-connected OS;
- a browser-engine project;
- an attempt to run large local AI models on every 8 GB device;
- a collection of unrelated Linux tools;
- a surveillance platform;
- an excuse to upload detailed developer activity to Smplify Cloud.

---

# 5. Target Hardware

## 5.1 x86_64 developer baseline

```text
CPU:       4-core x86_64
RAM:       8 GB
Storage:   128 GB SSD
Graphics:  supported integrated Intel/AMD graphics
Network:   Wi-Fi/Ethernet
TPM:       optional Community; preferred/required Enterprise
UEFI:      required for production enterprise baseline
```

## 5.2 Recommended target

```text
CPU:       4–8 cores
RAM:       16 GB
Storage:   256 GB SSD
Graphics:  integrated graphics sufficient
TPM:       2.0
```

## 5.3 Representative devices

Punar should intentionally target hardware classes such as:

- 2019–2022 Lenovo ThinkPad;
- 2019–2022 Dell Latitude / Precision;
- 2019–2022 HP EliteBook;
- older Framework laptops;
- existing engineering desktops;
- VM environments.

## 5.4 Higher-end devices

Punar may expose enhanced capabilities on:

- 32 GB+ machines;
- discrete GPU workstations;
- NVIDIA/CUDA environments;
- AMD ROCm environments.

But the core OS must not assume high-end AI-PC hardware.

## 5.5 ARM64 and Raspberry Pi target

ARM64 is a first-class product architecture. Raspberry Pi-class devices are
the initial concrete target, primarily as appliances and AI-inference devices;
a sufficiently capable ARM64 machine may also provide the developer profile.

The minimum Pi generation, RAM threshold and desktop richness must be set from
measurements on real hardware, not a model-name allowlist or an assumed board
specification. The same privacy and security guarantees apply as on x86_64. If
a board cannot uphold them, Punar does not claim support for that board.

Raspberry Pi's native boot chain is not UEFI. ADR-003's A/B UKI mechanism
therefore does not automatically apply: ARM64 package/image support and Pi
boot/rollback are separate acceptance items, and neither may be labelled built
until it boots and rolls back on physical hardware.

---

# 6. Performance Budgets

Performance is an acceptance criterion.

Create and maintain `PERFORMANCE_BUDGETS.md`.

## 6.1 Idle RAM

Clean graphical desktop after boot and stabilization:

```text
Target:         < 1.0 GB RAM
Stretch:        < 750 MB RAM
Hard ceiling:   1.5 GB RAM
```

If the hard ceiling is exceeded, treat it as a release blocker unless explicitly waived.

## 6.2 Punar / Smplify service RAM

Combined idle memory target for local control-plane services:

```text
Target:       < 100 MB total idle RSS/PSS where measurable
MVP ceiling:  < 150 MB
```

## 6.3 Idle CPU

```text
Target: effectively 0% when idle
```

Continuous high-frequency polling is prohibited. Prefer event-driven observation.

## 6.4 Disk I/O

Avoid constant writes for telemetry, AI ledger, inventory, policy, and logs. Batch and aggregate. Do not log every filesystem read by AI agents.

## 6.5 Boot

Track boot-to-usable-desktop time. Every major release should measure and regress-test boot performance.

## 6.6 Memory pressure

Use zram, memory-pressure-aware service behavior, cgroups, and per-project limits where useful. On 8 GB systems, prioritize developer applications over decorative OS effects.

---

# 7. Adaptive Hardware Profiles

## 7.1 Constrained profile

Example: 8 GB RAM, integrated GPU.

Behavior:

- aggressive zram;
- minimal background services;
- reduced visual effects;
- conservative local-model defaults;
- container resource guidance;
- memory-aware browser behavior;
- no large local inference stack by default.

## 7.2 Standard profile

Example: 16 GB RAM.

Behavior:

- full desktop experience;
- common developer containers;
- small/medium local AI utilities where appropriate;
- cloud AI remains primary.

## 7.3 AI workstation profile

Example: 32–64+ GB RAM and discrete GPU.

Behavior:

- local inference optional;
- model cache;
- GPU development stack;
- larger project/container budgets.

---

# 8. Distribution Foundation

The substrate must not be permanently finalized until the MVP architecture evaluation is complete.

Candidates should be evaluated on:

- resource efficiency;
- developer familiarity;
- reproducibility;
- package availability;
- security;
- Secure Boot;
- transactional updates;
- rollback;
- hardware compatibility;
- ease of enterprise governance;
- maintenance burden;
- upstream velocity.

## 8.1 Arch direction

A **minimal Arch-based system** is a strong candidate due to its small base, current packages, developer familiarity, package ecosystem, and alignment with Omarchy-like product coherence.

However, Punar must not be raw rolling Arch with enterprise controls bolted on. Punar must provide:

- controlled package/update channels;
- reproducible build/image strategy;
- rollback/snapshot strategy;
- signed release artifacts;
- enterprise update assignments;
- declarative control surface.

## 8.2 NixOS evaluation

NixOS remains a serious alternative/reference for declarative host state, reproducibility, generations, atomic activation, and rollback.

## 8.3 Fedora Atomic evaluation

Also evaluate immutable/atomic image approaches and SELinux-first security.

## 8.4 Required ADR

Create `ADR-001 Distribution Substrate` comparing Arch, NixOS, and Fedora Atomic/image-based approaches.

---

# 9. High-Level Architecture

```text
┌───────────────────────────────────────────────────────────────────┐
│                     PUNAR GRAPHICAL EXPERIENCE                    │
│ Shell • Command Center • Window Mgmt • Projects • Browser • UX    │
├───────────────────────────────────────────────────────────────────┤
│                     DEVELOPER EXPERIENCE                          │
│ Terminal • Editors • Git • Containers • Dev Envs • Toolchains     │
│ Web Apps • Cloud CLIs • Project Workspaces                        │
├───────────────────────────────────────────────────────────────────┤
│                       AI RUNTIME                                  │
│ Agent Identity • Permissions • AI Registry • Access Ledger        │
│ MCP/Tool Gateway • Network Policy • Secret Broker                 │
├───────────────────────────────────────────────────────────────────┤
│                 PUNAR / SMPLIFY LOCAL CONTROL PLANE               │
│ Desired State • Policy • Enrollment • Compliance • Audit          │
│ Inventory • Drift • Reconciliation • Updates • Attestation        │
├───────────────────────────────────────────────────────────────────┤
│                    PRIVILEGED CAPABILITIES                        │
│ Apps • Network • Firewall • Certificates • Identity • Encryption  │
│ Privilege • Updates • Recovery • Relay • Device Controls          │
├───────────────────────────────────────────────────────────────────┤
│                         LINUX BASE                                │
│ Wayland • systemd • LSM • LUKS • TPM • Secure Boot • nftables    │
│ namespaces • cgroups • seccomp • Landlock • eBPF where justified │
└───────────────────────────────────────────────────────────────────┘
```

---

# 10. Shared Capability Architecture

All Punar interfaces must use the same capability layer.

```text
Graphical UI
    │
Command Center
    │
CLI
    │
AI Intent
    │
Smplify Remote Query
    │
    ▼
Typed Capability API
    │
Policy / Authorization
    │
Privileged Implementation
```

Good examples:

```text
SetFirewall(enabled)
ConnectWifi(network)
InstallApplication(package)
RequestCredential(scope)
RequestPrivilege(capability)
CreateProjectWorkspace(project)
SetRelayMode(mode)
```

Prohibited:

```text
RunRootShell(command)
ExecuteAsRoot(arbitrary_string)
```

---

# 11. Core Local Services

## 11.1 `punard`

Primary privileged local control-plane daemon.

Responsibilities:

- device identity;
- enrollment;
- desired-state receipt;
- state reconciliation;
- capability registry;
- compliance;
- inventory;
- drift detection;
- local policy;
- local IPC;
- update orchestration;
- audit events;
- Smplify communication;
- AI inventory coordination;
- privacy-aware remote query execution.

## 11.2 `punarctl`

Examples:

```bash
punarctl status
punarctl capabilities
punarctl compliance
punarctl policy effective
punarctl policy explain security.firewall
punarctl agents list
punarctl agents inspect <id>
punarctl agents access <id>
punarctl privacy connections
punarctl relay status
punarctl audit tail
punarctl reconcile
punarctl update status
```

## 11.3 `punar-agentd`

AI agent registry, identity, policy, attribution, and access-ledger service.

## 11.4 `punar-secrets`

Short-lived credential broker.

## 11.5 `punar-workspace`

Project workspace and window-context manager.

## 11.6 `punar-env`

Developer environment manager.

## 11.7 `punar-netd`

Network policy / relay orchestration service.

## 11.8 `punar-shell`

Graphical shell and command-center integration.

---

# 12. Graphical UX Philosophy

Punar is a **keyboard-first graphical OS with a first-class terminal**.

The terminal is not the only way to control the system. A non-terminal user should be able to manage ordinary OS functions graphically.

Every first-party graphical workflow MUST be fully operable without a mouse. Mouse and touchpad remain supported.

The primary desktop modifier is called the **Punar key**. Chords write it as
`PUNAR`; on PC keyboards it is the Windows-logo / Meta key. On Apple
keyboards connected through a VM client, it is the key the client maps to the
guest Meta position (normally Command). Compositor-specific names are an
implementation detail and MUST NOT appear in user-facing Punar surfaces.

## 12.1 Required keyboard-operable areas

At minimum:

- application launch;
- application switching;
- workspaces;
- window movement;
- window resizing;
- tiling;
- stacking;
- floating;
- Wi-Fi;
- Bluetooth;
- display configuration;
- audio;
- power;
- files;
- clipboard history;
- notifications;
- screenshots;
- application installation;
- OS updates;
- enterprise enrollment;
- compliance;
- AI agent view;
- AI permissions;
- approvals;
- privacy;
- network relay;
- project workspaces;
- containers;
- developer environments;
- MCP/tool controls;
- privilege requests.

## 12.2 Universal command center

Target:

```text
PUNAR + Space
```

Supports apps, system settings, projects, AI agents, developer actions, enterprise actions, privacy, search, and natural-language intent where safe.

Examples:

```text
> connect my headphones
> open Atlas
> why can't Claude access production?
> show active AI agents
> install Firefox
> switch relay to private mode
```

Natural language must resolve to typed capabilities. Never generate and blindly execute shell commands.

## 12.3 Discoverability

Potential interactions:

- holding `PUNAR` shows a shortcut overlay;
- `?` opens shortcut help;
- command center exposes actions by search.

Avoid requiring users to memorize dozens of undocumented shortcuts.

---

# 13. Desktop and Window Management

Multitasking is a signature Punar feature.

## 13.1 Core principle

> Every window should be where the user expects it, context switching should be nearly instantaneous, and managing many tasks should feel as effortless as managing one.

## 13.2 Window modes

Support:

- tile;
- stack/tab group;
- float;
- fullscreen/focus.

## 13.3 Window grammar

Initial target shortcuts:

```text
PUNAR + H/J/K/L              Focus
PUNAR + SHIFT + H/J/K/L      Move window
PUNAR + R                    Resize mode
PUNAR + F                    Focus/fullscreen
PUNAR + L                    Layout chooser
PUNAR + TAB                  Workspace overview
PUNAR + 1..9                 Workspace/project shortcut
PUNAR + Space                Universal command center
```

Exact bindings may evolve.

## 13.4 Fluid rearrangement

Window movement should use short, purposeful animations that explain state changes while preserving low resource usage.

```text
fluid, not decorative
```

## 13.5 Layout presets

Examples:

- balanced;
- columns;
- rows;
- focus;
- stack;
- grid.

## 13.6 Scratchpads

Support keyboard-toggle scratchpads for terminal, AI assistant, and notes.

---

# 14. Project Workspaces

Workspaces should be project-aware rather than only numeric desktops.

Example:

```text
Atlas
Punar
Website
Research
Personal
```

## 14.1 Workspace state

A project may include:

- windows;
- IDE;
- terminal;
- AI agent sessions;
- browser context;
- containers;
- dev environment;
- network policy;
- temporary credentials;
- project-specific tools.

## 14.2 Overview

`PUNAR + TAB` should provide a graphical overview of project contexts.

Keyboard navigation:

- arrows;
- Enter;
- typing to search.

## 14.3 Restoration

Punar should remember project layout state.

Future goals include application reopening, terminal restoration, browser context restoration, container reconnection, permitted network context, and AI session state where safe.

## 14.4 Activity model

Long-term, allow temporary activities such as `Investigate Production Incident` with windows, temporary credentials, terminal, browser, AI, and network access. Ending the activity should revoke temporary authority.

---

# 15. Multi-Monitor Experience

Requirements:

- remember monitor layouts;
- remember project/window placement;
- intelligently collapse windows when monitor is disconnected;
- restore layout when dock/monitor returns;
- no off-screen lost windows;
- keyboard movement across displays.

Example:

```text
PUNAR + SHIFT + RIGHT
```

moves focused window to the right display.

---

# 16. Developer Experience

Punar should provide or make frictionless:

- Git;
- GitHub CLI;
- SSH;
- curl;
- jq;
- ripgrep;
- fd;
- fzf;
- tmux or equivalent;
- modern terminal;
- Neovim;
- VS Code-compatible editor path;
- JetBrains installation path;
- Podman;
- Docker CLI compatibility where useful;
- devcontainers;
- Kubernetes CLI;
- Helm;
- Terraform/OpenTofu;
- common cloud CLIs;
- project-local language toolchains.

Avoid preinstalling excessive toolchains on the host. Prefer project isolation.

---

# 17. Developer Environments

Developer environments are both usability and security boundaries.

Commands:

```bash
punar-env init
punar-env up
punar-env shell
punar-env status
punar-env destroy
punar-env agent claude
```

Example manifest:

```yaml
apiVersion: punar.dev/v1alpha1
kind: ProjectEnvironment

project:
  name: atlas

environment:
  type: devcontainer

toolchains:
  node: "24"
  rust: stable

services:
  - postgres

ai:
  agents:
    - claude-code
    - codex

permissions:
  filesystem:
    project: read_write

  network:
    internet: allow
    corp_dev: allow
    corp_prod: deny

  credentials:
    github: allow
    aws_dev: request
    aws_prod: deny
```

---

# 18. AI-Native Architecture

AI is not merely a bundled application category. The OS should recognize AI agents as first-class principals.

Identity types:

```text
Device
Human
Organization
Project
Application
AI Agent
Service
```

---

# 19. AI Agent Registry

Punar must maintain a native local AI Agent Registry.

The registry answers:

- which AI agents are installed;
- which are currently running;
- which user started them;
- which project they belong to;
- how they were launched;
- whether they are managed;
- which permissions they have;
- whether they are approved;
- what resources they can access;
- what resources they have accessed.

## 19.1 Classifications

```text
MANAGED
Known, approved, launched through managed Punar runtime

OBSERVED
Known AI agent running outside managed runtime

UNKNOWN / SUSPECTED
Potential agentic/AI activity with uncertain identity
```

## 19.2 Example registry record

```json
{
  "session_id": "agt_123",
  "agent": "claude-code",
  "version": "x.y.z",
  "process_id": 18422,
  "user": "alice@acme.com",
  "project": "atlas",
  "environment": "atlas-dev-42",
  "status": "active",
  "classification": "managed",
  "started_at": "..."
}
```

---

# 20. AI Authority Model

Permissions should include:

- filesystem;
- network;
- credentials;
- system mutation;
- package installation;
- container access;
- MCP/tool access;
- browser automation;
- Git access;
- cloud environments;
- production resources.

Decision values:

```text
allow
deny
approval_required
```

Example:

```yaml
ai:
  agents:
    default:
      filesystem:
        workspace: read_write
        home: read
        ssh: deny
        aws: deny

      host:
        user_package: allow
        system_package: approval_required
        firewall: deny
        user_management: deny

      network:
        internet: allow
        corp_dev: allow
        corp_prod: deny

      credentials:
        github: allow
        aws_dev: request
        aws_prod: deny
```

---

# 21. AI Access Ledger

Punar must maintain a privacy-preserving local AI Access Ledger.

The ledger answers:

> What has this AI agent actually accessed?

This is separate from:

> What is this AI agent allowed to access?

## 21.1 Access categories

Track meaningful access to:

- repositories;
- project directories;
- sensitive filesystem zones;
- network destinations;
- enterprise private zones;
- MCP servers;
- tools;
- credential classes;
- processes spawned;
- privilege requests;
- policy denials;
- production-access attempts.

## 21.2 Observation levels

### Level 1 — Inventory

Which agents exist or run?

### Level 2 — Authority

What can they access?

### Level 3 — Resource summary

Which project directories, repositories, domains, MCP servers, credential classes, and process classes were used?

### Level 4 — Security events

Record precise security-relevant events:

- denied access;
- sensitive resource access;
- privilege request;
- production access;
- credential request;
- policy bypass attempt;
- unknown AI execution.

Do not record every source-code line read. Do not record prompts by default. Do not collect source code. Do not log secret contents.

---

# 22. AI Attribution

Managed agent sessions should use strong process attribution.

Potential mechanisms:

- cgroups;
- process lineage;
- executable identity;
- session IDs;
- systemd scope;
- namespace metadata.

Example:

```text
punar/agents/atlas/claude/agt_8927
```

Child processes such as bash, git, node, and cargo should remain attributable to the parent agent session where technically possible.

---

# 23. Shadow AI / Shadow IT Visibility

Punar should reduce the enterprise Shadow AI blind spot.

The OS should attempt to identify:

- known AI applications;
- known AI CLIs;
- known coding agents;
- MCP servers;
- local agent runtimes;
- suspicious unknown agent-like processes.

Do not claim perfect detection.

Product language should be:

> **Eliminate the Shadow AI blind spot**

not:

> **Guarantee that no Shadow AI can exist.**

Potential detection inputs:

- process identity;
- executable provenance;
- process lineage;
- network destinations;
- known AI signatures;
- MCP activity;
- credential usage;
- workspace behavior;
- explicit agent registration.

---

# 24. Local-First AI Privacy Model

The detailed AI Agent Registry and Access Ledger remain local by default.

Smplify Cloud should not automatically receive a complete stream of developer AI activity.

```text
Local Device
   │
   ├── AI Registry
   ├── Access Ledger
   └── Policy State
         │
         │ Authorized query
         ▼
      Smplify
```

## 24.1 Remote-query rules

Once a device is enrolled:

- an authorized Smplify administrator may query permitted AI metadata;
- the endpoint evaluates the request;
- RBAC applies;
- requested information is returned;
- the query itself is audited;
- administrators cannot silently retrieve data outside allowed scope.

## 24.2 User visibility

Principle:

> **The employee should never have less visibility into what Punar is observing than the administrator does.**

---

# 25. Local AI UX

Potential shortcut:

```text
PUNAR + A
```

Example:

```text
AI ON THIS DEVICE

Claude Code
Atlas
Active

Authority
  Workspace          Read / Write
  SSH                Denied
  AWS                Denied by default

Network
  Internet           Allowed
  Acme Dev           Allowed
  Production         Blocked

Credentials
  AWS Dev            Expires in 42m

Tools
  GitHub
  Jira
```

Unknown agent:

```text
UNKNOWN AI ACTIVITY

Executable:
~/Downloads/foo-agent

Classification:
Unmanaged / suspected AI

Access:
Atlas source repository
api.foo.ai

[Inspect]
```

---

# 26. AI Agent Gateway

Initial adapters:

- Claude Code;
- OpenAI Codex CLI;
- generic shell/agent adapter.

Responsibilities:

- session identity;
- project association;
- policy;
- credential mediation;
- privileged requests;
- MCP/tool mediation;
- audit;
- network context.

Adapters should be modular.

---

# 27. AI Session Launch

Example:

```bash
punar-env agent claude
```

Flow:

1. resolve project;
2. create agent session identity;
3. calculate effective policy;
4. create cgroup/scope;
5. configure workspace access;
6. configure network context;
7. configure secret broker;
8. configure tool gateway;
9. launch agent;
10. display authority summary.

---

# 28. Approval Gates

Approval is first-class.

```json
{
  "approval_id": "apr_123",
  "requester": {
    "type": "ai_agent",
    "id": "agt_123"
  },
  "user": "alice@acme.com",
  "capability": "system.install_package",
  "resource": "libvirt",
  "reason": "required by project Atlas",
  "risk": "medium",
  "status": "pending",
  "expires_at": "..."
}
```

MVP:

- local graphical approval;
- keyboard approve/deny;
- expiration;
- audit;
- typed capability execution after approval.

---

# 29. Secret Broker

Goal: reduce dependence on long-lived plaintext credentials.

Avoid exposing `.env` secrets, `~/.aws/credentials`, static API keys, long-lived GitHub tokens, kubeconfigs, and private keys.

Example request:

```json
{
  "user": "alice@acme.com",
  "agent": "claude-code",
  "project": "atlas",
  "credential": "aws-dev",
  "ttl": 3600
}
```

Evaluate user, device, compliance, agent, project, environment, and policy.

MVP:

- mock provider;
- short-lived token;
- expiration;
- deny path;
- redaction tests.

---

# 30. Browser Requirements

Punar must ship a modern browser experience.

## 30.1 Engine strategy

Do not build a new browser engine and do not create a deep Chromium fork in MVP.

Use:

> **upstream-current Chromium plus a small, auditable Punar integration layer.**

Goals:

- rapid security updates;
- latest web-platform support;
- Chromium extension compatibility;
- modern PWA support;
- WebGPU;
- WebRTC;
- passkeys;
- current web-app APIs;
- strong sandboxing.

## 30.2 Browser release cadence

Browser security updates must be treated as critical OS security updates and may ship independently of slower Punar feature releases.

---

# 31. Web Apps as Native Apps

Installed web apps should appear as native Punar applications.

Requirements:

- launcher entry;
- icon;
- window identity;
- notifications;
- file associations where supported;
- deep links;
- keyboard shortcuts;
- workspace assignment;
- permission visibility;
- enterprise policy;
- optional separate storage contexts.

Examples include GitHub, Slack, Linear, Figma, Notion, Grafana, ChatGPT, and internal company apps.

---

# 32. Browser Contexts and Projects

Browser state should integrate with project workspaces.

Examples:

```text
PERSONAL
ACME WORK
ATLAS
PUNAR
```

Potential isolation:

- cookies;
- tabs;
- storage;
- identity;
- certificates;
- network policy.

A project workspace can bring forward its project-specific browser context.

---

# 33. Native Private Relay

Punar should investigate a native OS-level private relay architecture.

The relay is not limited to the browser.

Eligible traffic can include:

- browser;
- AI agents;
- Git;
- project containers;
- native applications.

```text
Applications
    ↓
Punar Network Policy
    ↓
Private Relay / Enterprise Route / Direct
    ↓
Network
```

---

# 34. Private Relay Privacy Model

Long-term privacy relay should avoid putting full connection knowledge in one party.

Conceptual dual-hop:

```text
Device
  ↓
Ingress Relay
  ↓
Egress Relay
  ↓
Internet
```

Desired property:

- ingress can know device/network origin but not final destination;
- egress can know destination but not original client identity/IP;
- no single relay should have complete knowledge where practical.

Do not simply route all traffic through a single Smplify-owned VPN and call it private.

---

# 35. Enterprise Private Networking

Punar should support enterprise network access without forcing the user to think in terms of a manual VPN toggle.

Routing may depend on:

- user;
- device identity;
- compliance;
- project;
- process;
- AI agent;
- destination;
- policy.

Example:

```text
User: Alice
Device: compliant
Project: Atlas
Process: Claude Code
Destination: dev.api.acme.internal
Policy: allow
```

Punar establishes the permitted route.

---

# 36. Project-Aware Networking

Example:

```text
ATLAS

Internet             allow
Acme Dev              allow
Production            deny
```

Another workspace:

```text
PRODUCTION INCIDENT

Internet             allow
Production           temporary approval
Privileged DB        approval required
```

AI network boundaries should be enforced below the agent where possible.

---

# 37. Network Observability

Potential command:

```bash
punarctl privacy connections
```

Potential graphical view:

```text
NETWORK ACTIVITY

Claude Code
→ api.anthropic.com
Reason: AI inference

Browser
→ github.com
Reason: user navigation

punard
→ control.smplify.com
Reason: compliance synchronization
```

Goals:

- show who is communicating;
- destination;
- reason/category where known;
- relay route;
- project;
- AI session association where relevant.

Do not perform invasive content inspection by default.

---

# 38. Declarative State Model

Example:

```yaml
apiVersion: smplify.io/v1alpha1
kind: DeviceDesiredState

metadata:
  organization: acme
  device: dev_123

spec:
  security:
    diskEncryption:
      required: true

    secureBoot:
      required: true

    firewall:
      enabled: true

  applications:
    required:
      - git
      - podman

  ai:
    policy: engineering-standard

  network:
    privateRelay:
      enabled: true

  update:
    channel: stable
```

---

# 39. State Sources and Precedence

Sources:

- OS hard safety constraint;
- OS secure default;
- local user preference;
- organization baseline;
- organization role policy;
- device-specific override;
- temporary approved exception.

Suggested precedence:

```text
Hard OS Safety Constraint
        >
Organization Mandatory Policy
        >
Organization Role Policy
        >
Temporary Approved Exception
        >
User Preference
        >
OS Default
```

Encode and test.

---

# 40. Explainability

Example:

```bash
punarctl policy explain security.diskEncryption
```

Output:

```text
Effective value: required

Source:
Acme Engineering Baseline

Policy:
eng-baseline-v12

User override:
Not permitted

Compliance:
compliant
```

Graphical UX must expose the same information.

---

# 41. Capability Registry

Example:

```json
{
  "capability": "security.firewall",
  "supported": true,
  "current_state": "enabled",
  "desired_state": "enabled",
  "mutable": true,
  "requires_reboot": false,
  "risk": "high",
  "managed_by": "smplify",
  "verification": "nftables"
}
```

Capabilities must describe schema, current state, allowed desired states, privilege required, approval requirements, reboot implications, verification, risk, and audit category.

---

# 42. Reconciliation

```text
Observe
  ↓
Normalize Actual State
  ↓
Load Desired State
  ↓
Diff
  ↓
Policy
  ↓
Plan
  ↓
Apply
  ↓
Verify
  ↓
Audit
  ↓
Compliance
```

Requirements:

- idempotent;
- typed;
- testable;
- retry/backoff;
- safe failure;
- verification;
- no generic root scripts as canonical mechanism.

---

# 43. Drift

If organization policy requires the firewall enabled and it is manually disabled, Punar should:

1. detect drift;
2. identify desired state;
3. classify remediation;
4. remediate if policy allows;
5. verify;
6. create local audit event;
7. report compliance.

Policy may choose auto-remediate, alert only, or approval.

---

# 44. Enterprise Security Baseline

## 44.1 Boot

Production goals:

- UEFI;
- Secure Boot;
- signed boot artifacts;
- TPM 2.0;
- measured-boot investigation;
- hardware-backed device identity where practical.

## 44.2 Disk encryption

- LUKS2;
- encrypted install by default for managed devices;
- TPM-assisted unlock where appropriate;
- recovery flow;
- no recovery material in logs.

## 44.3 Mandatory access control

Evaluate SELinux, AppArmor, Landlock, and systemd sandboxing. Create an ADR.

## 44.4 Firewall

Declarative example:

```yaml
security:
  firewall:
    enabled: true
    inboundDefault: deny
    outboundDefault: allow
```

## 44.5 Service controls

Enterprise policy should govern SSH, Bluetooth, removable storage, local admin, screen lock, kernel/module restrictions, and developer exceptions.

---

# 45. Security Through Native OS Primitives

Prefer:

- Secure Boot;
- TPM;
- LUKS;
- Linux namespaces;
- cgroups;
- seccomp;
- LSM;
- Landlock;
- nftables;
- systemd hardening;
- eBPF where justified;
- signed packages;
- controlled system image.

Goal:

> **Security through native OS primitives instead of a pile of resident agents.**

---

# 46. Application Policy

```yaml
applications:
  required:
    - 1password
    - tailscale

  denied:
    - package: unsafe-package

  allowUserInstall: true
```

Application semantics should remain stable even if the underlying package system changes.

---

# 47. Identity

```text
Organization
Device
User
Project
Application
AI Agent
Service
```

Every privileged event should be attributable through this graph.

---

# 48. Just-In-Time Privilege

Avoid permanent local admin as the default developer solution.

```bash
punarctl privilege request \
  --capability system.install-package \
  --reason "Need libfoo for Atlas"
```

Possible result:

```text
Approved for 15 minutes.
```

No generic unrestricted root-shell API.

---

# 49. Enterprise Enrollment

```text
Boot
  ↓
Network
  ↓
Device bootstrap identity
  ↓
Choose personal or organization
  ↓
Organization discovery
  ↓
User authentication
  ↓
Device registration
  ↓
Attestation
  ↓
Desired state
  ↓
Policy
  ↓
Provision
  ↓
Verify
  ↓
Managed desktop
```

MVP uses a mocked Smplify control plane.

---

# 50. Smplify Relationship

Punar is the OS. Smplify is the enterprise control plane.

```text
Punar Endpoint
      ↕
Smplify
```

Smplify provides:

- fleet policy;
- device enrollment;
- desired state;
- compliance;
- inventory;
- approved remote queries;
- update assignments;
- approvals;
- enterprise AI visibility.

Do not require Smplify for Community mode.

---

# 51. Smplify Remote AI Queries

A managed administrator should be able to ask:

- which AI agents are active;
- which are unmanaged;
- which projects they belong to;
- effective permissions;
- network zones;
- credential classes;
- resource summaries;
- policy violations;
- unknown/suspected AI.

Detailed access information should be queried from the device when required rather than automatically uploaded continuously.

## 51.1 Query audit

Every remote query should record:

- requesting admin;
- requested scope;
- device;
- timestamp;
- result category;
- authorization decision.

---

# 52. Compliance

States:

- compliant;
- non_compliant;
- remediating;
- unknown;
- unsupported;
- exception.

Example:

```text
Overall: compliant

Boot Integrity       compliant
Disk Encryption      compliant
Firewall             compliant
AI Policy            compliant
Private Relay        compliant
OS Update            compliant
Enterprise Identity  compliant
```

---

# 53. Audit

```json
{
  "event_id": "evt_123",
  "timestamp": "...",
  "device_id": "dev_123",
  "user_id": "alice@acme.com",
  "agent_session_id": "agt_123",
  "project_id": "atlas",
  "source": "ai_agent",
  "action": "credential.request",
  "resource": "aws-dev",
  "decision": "allow",
  "policy_ids": ["eng-ai-v3"],
  "result": "success"
}
```

Never log passwords, secret values, tokens, private keys, prompt contents by default, or source code.

---

# 54. Telemetry and Privacy

Community edition:

- no hidden telemetry;
- no sensitive activity upload by default.

Enterprise separates:

- security audit;
- operational metrics;
- software inventory;
- AI inventory;
- AI resource summary;
- detailed local ledger.

The organization should explicitly configure which categories can be queried or synchronized.

---

# 55. Offline Behavior

Managed Punar must remain usable offline.

Cache:

- last valid policy;
- desired state;
- enrollment identity;
- public keys;
- local AI policy;
- project policy.

Rules:

- temporary credentials still expire;
- enrollment does not silently downgrade;
- audit can queue;
- remote query unavailable while offline;
- local policy remains enforceable.

---

# 56. Local Storage

Suggested lightweight local database for policy metadata, desired state, compliance, approvals, AI registry, AI-ledger summaries, audit queue, and inventory.

Sensitive secrets must not be stored plaintext.

Use kernel keyring, TPM, secret-service integration, and encrypted local storage as appropriate.

---

# 57. Update Architecture

Punar updates must be controlled, signed, reversible, and measurable.

Enterprise stages:

```text
Candidate
  ↓
Canary
  ↓
Health
  ↓
10%
  ↓
50%
  ↓
100%
```

Endpoint exposes current version, desired version, channel, health, and rollback state.

---

# 58. Browser / OS Update Separation

Browser emergency security updates should not wait for a full OS release.

Architecture must support rapid browser patching, staged enterprise browser rollout, and rollback where safe.

---

# 59. Threat Model

Create `docs/threat-model/THREAT_MODEL.md`.

Minimum threats:

## 59.1 Malicious AI agent

Risks:

- secret access;
- host mutation;
- persistence;
- production access;
- exfiltration;
- MCP abuse;
- privilege abuse.

Mitigations:

- identity;
- project scope;
- cgroups;
- sandbox;
- secret broker;
- network policy;
- approvals;
- native OS controls;
- audit.

## 59.2 Unmanaged AI

Mitigations:

- detection;
- local registry;
- network policy;
- credential isolation;
- Smplify query;
- blocking policy.

## 59.3 Malicious local process

Mitigations:

- peer credential checks;
- IPC permissions;
- session tokens;
- MAC;
- minimal privilege;
- executable identity.

## 59.4 Compromised control plane

Future mitigations:

- signed policy;
- signed desired state;
- local hard safety constraints;
- strong device verification;
- restricted high-risk actions.

## 59.5 Lost device

- LUKS;
- TPM;
- short-lived credentials;
- screen lock;
- remote revocation future.

## 59.6 Supply chain

- pinned dependencies;
- signed artifacts;
- reproducible builds where possible;
- SBOM future;
- provenance future.

---

# 60. Hard Safety Constraints

MVP AI must never directly:

- disable Secure Boot;
- disable encryption;
- disable audit;
- add persistent unrestricted root;
- export recovery keys;
- change trusted control-plane keys;
- weaken Punar security services;
- bypass AI policy enforcement.

These require explicit privileged workflows.

---

# 61. Local IPC Security

Requirements:

- Unix domain sockets;
- filesystem permissions;
- peer credentials;
- typed messages;
- no unauthenticated localhost TCP control API;
- policy;
- timeouts;
- structured errors;
- audit.

Evaluate polkit for human approvals/elevation.

---

# 62. Browser and Web-App Security

Punar browser integration must preserve Chromium’s upstream security model.

Avoid modifications that weaken:

- sandbox;
- site isolation;
- process boundaries;
- certificate validation;
- extension security.

Enterprise policy may control extensions, allowed web apps, browser contexts, certificate roots, relay policy, and download restrictions.

---

# 63. Graphical System Control

Potential shortcut:

```text
PUNAR + S
```

System Control should expose:

```text
SYSTEM
Network
Bluetooth
Displays
Audio
Power

SECURITY
Device
Encryption
Secure Boot
Firewall

AI
Agents
Permissions
Models
MCP

DEVELOPER
Projects
Containers
Toolchains

PRIVACY
Connections
Relay

ORGANIZATION
Enrollment
Compliance
Policies
Privilege
```

Arrow keys navigate, Enter opens, Escape returns, and `/` searches.

---

# 64. Privacy UI

Potential view:

```text
PRIVACY

Private Relay      Active
DNS Protection     Active

Who is talking to the network?

Browser            14 connections
Claude Code         2 connections
Containers          4 connections
punard               1 connection
```

Selecting an item shows destination, category, route, project, and AI session where relevant.

---

# 65. First-Boot UX

A new user should be able to:

1. boot;
2. select language/keyboard/timezone;
3. connect network;
4. create/authenticate user;
5. select personal or organization mode;
6. choose basic privacy defaults;
7. reach graphical desktop;
8. open terminal or browser;
9. clone project;
10. create project workspace;
11. launch AI agent.

Avoid requiring shell commands during first boot.

---

# 66. Installation

MVP:

- bootable ISO;
- VM image;
- repeatable build;
- development VM.

Production goals:

- encrypted install;
- Secure Boot;
- enterprise enrollment;
- hardware validation;
- recovery.

Do not build a complex custom installer before core OS architecture works.

---

# 67. Repository Structure

Suggested:

```text
punar/
├── README.md
├── LICENSE
├── IMPLEMENTATION_STATUS.md
├── ARCHITECTURE_DECISIONS.md
├── PERFORMANCE_BUDGETS.md
├── docs/
│   ├── architecture/
│   ├── product/
│   ├── threat-model/
│   ├── api/
│   ├── privacy/
│   ├── networking/
│   └── development/
├── os/
│   ├── modules/
│   ├── profiles/
│   └── images/
├── crates/
│   ├── punard/
│   ├── punarctl/
│   ├── punar-policy/
│   ├── punar-agentd/
│   ├── punar-secrets/
│   ├── punar-workspace/
│   ├── punar-netd/
│   └── punar-common/
├── shell/
├── browser/
│   └── integration/
├── schemas/
│   ├── desired-state/
│   ├── policy/
│   ├── capability/
│   ├── ai-agent/
│   ├── audit/
│   └── network/
├── proto/
├── fixtures/
│   ├── organizations/
│   ├── policies/
│   ├── agents/
│   └── projects/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── vm/
│   ├── performance/
│   └── security/
└── tools/
```

Adapt for actual substrate.

---

# 68. Preferred Implementation Languages

Privileged components:

- Rust preferred.

Graphical shell:

- Quickshell/QML if selected;
- or another lightweight native Wayland-compatible stack.

Avoid Electron for core OS UI.

Browser:

- upstream Chromium packaging/integration, not browser-engine rewrite.

---

# 69. Desktop Technology

Initial evaluation:

- Wayland;
- Hyprland;
- Quickshell.

But hardware reuse means compositor strategy must include compatibility.

Evaluate fallback for problematic legacy GPUs, potentially Sway, labwc, or another lightweight Wayland compositor.

The same Punar UX philosophy should survive on compatibility mode.

---

# 70. AI Model Strategy

AI-native does not mean everything runs locally.

## 70.1 8 GB devices

Prefer cloud AI agents and small local helper models only. No automatic heavyweight inference.

## 70.2 16 GB

Support selected small local models, embeddings, and privacy-sensitive local tasks.

## 70.3 High-end

Optional larger local models, GPU acceleration, and local inference runtime.

Policy should choose allowed model providers.

---

# 71. AI Model Governance

Future example:

```yaml
ai:
  models:
    cloud:
      allowed:
        - openai
        - anthropic

    local:
      allowed: true

    unknownEndpoints:
      deny: true
```

Sensitive project:

```yaml
project:
  classification: confidential

ai:
  cloudModels: deny
  localModels: allow
  externalMcp: deny
```

---

# 72. Enterprise AI Fleet View

Smplify should eventually present:

```text
AI FLEET

Devices              2418
Active AI users      1972

Claude Code          1241
Codex                 784
Other                 310
Unknown                14
```

Shadow AI detail:

```text
14 unmanaged agents
8 devices

3 accessing source repositories
2 accessing corporate APIs
0 production credentials
```

This view must derive from policy-controlled endpoint data.

---

# 73. Security and Privacy UX Principle

Every enterprise restriction should answer:

- what happened;
- why;
- who requested it;
- which policy;
- whether the user can change it;
- whether approval is possible;
- what the next step is.

Bad:

```text
EPERM
```

Good:

```text
Production AWS access is blocked for Claude Code
in the Atlas development workspace.

Policy:
Acme AI Engineering Baseline v3
```

---

# 74. Testing Strategy

## 74.1 Unit

Required:

- policy;
- state merge;
- precedence;
- capabilities;
- agent identity;
- AI-ledger aggregation;
- audit redaction;
- network-route policy;
- secret broker;
- approvals.

## 74.2 Integration

Required:

- daemon + CLI;
- agent registry;
- Smplify mock;
- project workspace;
- approval flow;
- secret request;
- remote AI query;
- browser-context metadata where practical.

## 74.3 VM tests

Required:

- boot;
- graphical session;
- `punard` active;
- firewall state;
- enrollment;
- desired state;
- drift remediation;
- project environment;
- AI session registration.

## 74.4 Security tests

- unauthorized IPC;
- fake agent;
- expired approval;
- denied production network access;
- denied credential;
- secret not logged;
- remote-query authorization;
- unknown-AI classification path.

## 74.5 Performance tests

Track:

- idle RAM;
- Punar service RAM;
- idle CPU;
- boot time;
- AI-ledger write rate;
- window-manager responsiveness.

---

# 75. MVP Hero Demo

Build toward this exact story.

## Step 1 — Boot

Boot Punar in a clean VM or reference laptop.

Show low idle RAM, graphical desktop, and keyboard-first navigation.

## Step 2 — Enrollment

Choose `Use with my organization` and enroll into mocked Acme.

Show:

```text
Acme Engineering

Disk Encryption      compliant/simulated
Firewall             enabled
Developer Profile    active
AI Policy            active
Private Relay        active/simulated
```

## Step 3 — Project workspace

Open command center and type:

```text
Open Atlas
```

Punar opens a named Atlas project workspace.

## Step 4 — Development

Open sample repository and run:

```bash
punar-env up
```

## Step 5 — AI

Launch Claude Code.

Show:

```text
Claude Code — Atlas

Workspace            Read / Write
Home                 Limited
SSH                   Denied
AWS Dev               Request
AWS Production        Denied
System Changes        Approval
```

AI Registry shows it as Managed.

## Step 6 — Approval

Claude requests a host-level capability. Graphical approval appears. Keyboard approve. Typed privileged API executes. Audit event recorded.

## Step 7 — Credential

Claude requests mock AWS Dev credential. Allowed. Credential expires. Secret not logged.

## Step 8 — Production attempt

Claude requests production resource. Denied. Show policy explanation.

## Step 9 — Network

Show Claude’s active network destinations and project route.

## Step 10 — Shadow AI

Launch a fixture “unknown agent.” Punar detects/classifies it as unmanaged/suspected AI. Local UI shows warning. Authorized mocked Smplify query retrieves agent metadata.

## Step 11 — Drift

Disable firewall outside supported UI. Punar detects and remediates.

## Step 12 — Multitasking

Use `PUNAR + TAB`. Switch between Atlas, Punar, and Browser. Layouts restore fluidly.

## Step 13 — Browser/web app

Launch installed web app from command center and show current Chromium-based web app behaving like a native window.

## Step 14 — Privacy

Open local Privacy panel and show relay state, active destinations, and process/agent attribution.

---

# 76. Milestone Plan

## Milestone 0 — Foundation evaluation

Deliver:

- substrate ADR;
- resource-budget baseline;
- VM build;
- CI;
- repository.

Acceptance: reproducible build and VM boot.

## Milestone 1 — Lightweight graphical workstation

Deliver:

- Wayland;
- compositor;
- shell;
- command center;
- terminal;
- browser;
- Git;
- editor;
- Podman;
- keyboard navigation.

Acceptance: idle RAM measured and no mouse required for core desktop use.

## Milestone 2 — Native multitasking

Deliver tiling, stacking, floating, overview, layouts, scratchpads, and named project workspaces.

## Milestone 3 — `punard` + `punarctl`

Deliver daemon, typed IPC, capability registry, CLI, and audit.

## Milestone 4 — Declarative desired state

Deliver schemas, preference/policy merge, reconciliation, explain, and firewall-drift demo.

## Milestone 5 — Mock Smplify enrollment

Deliver mock control plane, device enrollment, policy, compliance, and inventory.

## Milestone 6 — Developer environment manager

Deliver `punar-env`, Podman/devcontainer, and Atlas fixture.

## Milestone 7 — AI Agent Registry

Deliver managed sessions, Claude adapter, second/generic adapter, agent identity, classification, and local UI.

## Milestone 8 — AI Access Ledger

Deliver resource summaries, process attribution, security events, local retention, and privacy controls.

## Milestone 9 — Approval gates + secret broker

Deliver local graphical approval, short-lived mock credentials, and redaction tests.

## Milestone 10 — Shadow AI detection MVP

Deliver known/observed/unknown classification, fixture unknown agent, local alert, and Smplify remote query.

## Milestone 11 — Browser/web-app integration

Deliver current Chromium, native launcher integration, project/browser context prototype, and web-app install flow.

## Milestone 12 — Network privacy prototype

Deliver local network observability, project-route policy, relay abstraction, and simulated or prototype private relay.

## Milestone 13 — Demo polish

Deliver first boot, enrollment, keyboard UX, AI panel, privacy panel, and deterministic demo.

---

# 77. Phase 2

After MVP:

- real Secure Boot;
- TPM;
- hardware-backed identity;
- physical-device install;
- production LUKS recovery;
- real Smplify cloud;
- Google/Entra/Okta;
- enterprise certificates;
- Wi-Fi;
- VPN replacement/enterprise relay;
- real dual-hop private relay;
- eBPF-based agent/network attribution where justified;
- stronger sandbox;
- staged fleet updates;
- SIEM/OCSF export;
- real secret integrations;
- richer MCP governance;
- software provenance;
- on-prem Smplify.

---

# 78. Phase 3 Opportunities

Potential:

- secure local inference;
- GPU fleet management;
- per-project model policy;
- AI routing;
- sovereign enterprise deployment;
- ephemeral developer workstations;
- remote/cloud Punar environments;
- activity-scoped credentials;
- measured boot/remote attestation;
- AI behavior risk scoring;
- broader AI-application discovery;
- enterprise browser policy;
- isolated enterprise web-app packaging.

---

# 79. Non-Goals for MVP

Do not spend MVP effort on:

- custom kernel;
- every laptop model;
- full graphical installer;
- full EDR;
- full DLP;
- replacing GitHub;
- replacing VS Code;
- building a browser engine;
- supporting every AI agent;
- perfect Shadow AI detection;
- large local AI models;
- exhaustive GPU tuning;
- production global relay network;
- mobile-device management;
- Windows/macOS parity.

---

# 80. Definition of Done

MVP is done when a clean VM/reference machine can:

1. boot Punar;
2. reach graphical keyboard-first desktop;
3. remain within defined idle resource budget;
4. use universal command center;
5. manage windows without mouse;
6. switch project workspaces;
7. launch browser/web app;
8. enroll into mocked Smplify;
9. receive organization policy;
10. report compliance;
11. initialize Atlas dev environment;
12. launch Claude Code as managed AI session;
13. show effective AI authority;
14. show local AI Agent Registry;
15. show AI Access Ledger summary;
16. approval-gate a host action;
17. issue short-lived mock Dev credential;
18. deny Prod credential;
19. enforce project network rule;
20. display local network activity;
21. detect an unknown/unmanaged AI fixture;
22. allow authorized Smplify query of that local AI metadata;
23. remediate firewall drift;
24. show structured audit;
25. demonstrate rollback/update mechanism appropriate to chosen substrate;
26. complete without generic privileged root-shell RPC.

---

# 81. Product Success Tests

## Test A — Developer

> If Smplify management were removed, would an engineer still choose Punar?

The answer must be yes.

## Test B — Older hardware

> Does Punar make a well-built 8 GB or 16 GB enterprise laptop feel meaningfully more useful than a bloated modern endpoint stack?

The answer must be yes.

## Test C — Enterprise

> Can IT/security deploy Punar without destroying the developer experience?

The answer must be yes.

## Test D — AI governance

> Can the user and administrator understand which AI agents are running, what authority they have, and what important resources they are touching?

The answer must be yes.

## Test E — Privacy

> Can Punar provide enterprise visibility without silently uploading detailed developer activity?

The answer must be yes.

---

# 82. Final Architectural Rules

> **The graphical shell is keyboard-first, but the terminal remains exceptional.**

> **The OS itself should consume as little of the machine as possible.**

> **Project context is a native operating-system concept, not merely a folder.**

> **AI agents are first-class principals with identity, permissions, network boundaries, and auditability.**

> **AI activity intelligence is local-first and queried through Smplify only when authorized.**

> **Humans and AI express intent; deterministic typed capabilities execute authorized changes.**

> **Security should be implemented through native OS primitives wherever possible rather than through a pile of heavyweight resident agents.**

> **The browser is modern and upstream-compatible; web apps should feel native.**

> **Private networking and enterprise routing should be OS capabilities, not just a browser feature or a manually toggled VPN.**

> **Punar must make old hardware feel modern without making modern security feel optional.**

---

# 83. One-Sentence Product Definition

> **Punar is a lightweight, privacy-first, AI-native developer operating system that gives existing hardware a new life while providing native enterprise security, Smplify governance, fluid keyboard-first multitasking, modern web-app support, private networking, and auditable AI-agent control.**
