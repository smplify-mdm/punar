# Milestone 7 — AI Agent Registry: architecture and build record

Spec authority: section 76 Milestone 7 ("Deliver managed sessions, Claude
adapter, second/generic adapter, agent identity, classification, and local
UI"), grounded in sections 11.3 (`punar-agentd` — "AI agent registry,
identity, policy, attribution, and access-ledger service"), 18 (AI agents
as first-class principals), 19/19.1/19.2 (registry, the three
classifications, the example record), 20 (authority model — decision
values), 22 (attribution — cgroups, session IDs, systemd scope,
executable identity), 23 (shadow AI — "Do not claim perfect detection"),
25 (Local AI UX — `SUPER + A`, the panel layouts), 26 (AI Agent Gateway —
initial adapters, "Adapters should be modular"), 27 (AI Session Launch —
the ten-step flow), 61 (local IPC security), 1.22 (honesty).

**Explicitly OUT by spec sectioning:** section 21 (AI Access Ledger) is
**Milestone 8** — M7 builds the registry only; the ledger renders as a
labeled dashed placeholder (Plate D-005, DESIGN_LANGUAGE §8). Section 20
authority is **display-level only** in M7 (labels say so); enforcement
arrives M9 (credentials/approvals) and M12 (network). Continuous/periodic
shadow-AI detection with local alerts is **Milestone 10** ("Shadow AI
detection MVP"); M7 ships classification + on-demand scan only (§7).

Binding prior contracts, not relitigated: `docs/api/ipc.md` (extended
additively — new §10/§11 there are the wire contract for this milestone),
`milestone-3.md`–`milestone-6.md` (check mechanics, D-014 grammar,
idle-ram ordering, vendor-wants lesson, budgets discipline),
`schemas/ai-agent/registry-record.json` + `agent-definition.json`
(SHIPPED — records conform exactly), `fixtures/agents/` (claude-code
definition, unknown-agent foo-agent metadata),
`docs/design/mockups/ai-panel.html` (Plate D-005 — the SUPER+A surface),
DESIGN_LANGUAGE §8 (unmanaged-first).

M7 is the milestone where the AI-native thesis (sections 18–27) becomes
running code: an AI agent session is a **named principal** with an
identity (`agt_…`), a project, a classification, a cgroup, and an audit
trail — and the user can see all of it on one keyboard-first surface.

This document started as the design plan and now doubles as the build
record: the decisions below are what shipped, with every deviation marked
**As built** in place. Section 14 states exactly what has been verified
and what has not — the in-VM `m7-check` run is still the arbiter for
everything that only a booted image can prove.

---

## 1. Scope

In: `crates/punar-agentd` becomes a real **bin** crate (separate daemon,
§3); the agent registry with JSONL persistence (§4); `agents.*` typed IPC
on a new root-owned socket (§4, ipc.md §10); the managed launch path —
`punar-env agent <name>` goes from labeled stub to real (§5); adapters as
data under `/usr/share/punar/agents/adapters/` (§5.4); the dev/CI mock
agent (§6); on-demand heuristic detection with the foo-agent fixture
signature (§7); the SUPER+A AI panel in `punar-shell` fed by
`/run/punar/agents.json` (§8); `punarctl agents list|inspect` (§9); audit
events with **real** `agt_` session ids (§10); `m7-check` + boot-test
phase 9 + CI artifacts incl. the `punar-m7.png` money shot (§12); the RSS
gate grows to sum both daemons (§11).

Out (documented, never silently dropped): the Access Ledger and
`punarctl agents access` (M8 — ipc.md §10 reserves the name); authority
*enforcement* (M9/M12 — every authority surface carries the label);
approval gates (M9); continuous detection, local alerts, Smplify remote
agent queries, `BLOCK NETWORK` / `REGISTER AS MANAGED` actions from the
D-005 unknown view (M10); launching the agent *inside* the podman
environment container (§5.6, deferred); child-process lineage attribution
beyond the scope cgroup (M8, with the ledger's process classes).

## 2. Decision summary

| # | Decision |
|---|----------|
| 1 | **Separate daemon.** `punar-agentd` is its own always-on system service, exactly as spec 11.3 lists it — not folded into punard. Same frugal std-threads UDS pattern as punard; envelope/framing/error codes reused from `punar-common::ipc`. Socket `/run/punar-agentd/agentd.sock`, `0660 root:punar`, in a root-owned dir (the ipc.md §1.1 argument applies verbatim). §3. |
| 2 | **Registry model**: in-memory session table (authoritative for "now") + append-only JSONL persistence `/var/lib/punar/agents/registry.jsonl` — every persisted line is a **schema-exact** `registry-record.json` document. Managed lifecycle is persisted; heuristic detections are memory + `agents.json` only (§4.4). The record `status` enum gains `"ended"` — the additive widening the schema's own description pre-authorizes. §4. |
| 3 | **Methods** (new socket): `agents.list`, `agents.get`, `agents.register`, `agents.end`, `agents.scan`. Mutations are peer-cred-verified: a caller may register/end only sessions whose root process it owns (root may end any). Full wire contract: ipc.md §10. §4.2–4.3. |
| 4 | **Managed launch**: `punar-env agent <name>` resolves the agent against manifest `ai.agents`, loads the adapter definition, generates the session id, launches the agent under `systemd-run --user --scope --unit=punar-agent-<session_id>` (spec 22 attribution: scope = cgroup = session id), registers with agentd (which *verifies* the cgroup before granting `managed`), waits, deregisters on exit. Authority summary is displayed at launch and stored for the panel — **display-level, labeled**. §5. |
| 5 | **Adapters as data**: `/usr/share/punar/agents/adapters/claude-code.json` + `generic.json`, both valid against `agent-definition.json`; command, version probe, detection signature, and the CI mock override live in `adapter_config` (the schema's sanctioned free-form extension point). §5.4. |
| 6 | **Mock agent**: `/usr/lib/punar/punar-mock-agent` — a small POSIX **shell script** (not a crate), loudly labeled dev/CI stand-in; touches its workspace, then blocks on `wait` until signaled. Chosen over a bin crate: zero build surface, shellcheck-gated, trivially auditable. §6. |
| 7 | **Detection**: `agents.scan` walks `/proc` once (comm/exe/cmdline) against adapter signatures (known agent outside a managed scope → `observed`) and the suspected-signature set incl. `*/Downloads/foo-agent` (→ `unknown`). Runs on demand and lazily on `agents.list` when the last pass is > 30 s old. **No timer, no punard nudge, no continuous polling** (spec 6.3) — periodic detection is M10's deliverable by name. Every surface says *suspected*, never certain (spec 23). §7. |
| 8 | **Shell**: full-surface `AiPanel` (Plate D-005), `IpcHandler` target `aipanel`, bound to SUPER+A in `punar-binds.conf`; data via a new world-readable summary file `/run/punar/agents.json` that agentd writes atomically on change (the status.json pattern — event-driven FileView, no polling, no shell socket client). Ledger section renders `LEDGER · MILESTONE 8` dashed placeholder. §8. |
| 9 | **CLI**: `punarctl agents list` / `agents inspect <id>` (D-014 grammar, `--json`); `punarctl` routes `agents.*` to the agentd socket. `agents access` reserved for M8 (`unknown_method` today, said honestly). §9. |
| 10 | **Audit**: agentd appends to the **same** `/var/log/punar/audit.jsonl` through `punar_common::AuditWriter`, which gains flock-guarded rotation so two writers cannot race the 8 MiB rename. Agent lifecycle events carry **real** `agt_` ids. The deferred conditional-fields schema cleanup is **not** delivered (not trivial — it would break the "all 12 required fields" contract that events, tests, and docs pin); `agt_none` stays the documented sentinel for non-agent events. §10. |
| 11 | **Budgets**: idle-ram.sh sums PSS over **both** `punard.service` and `punar-agentd.service` cgroups into `PUNAR_SERVICES_RSS_MB` (the comment in that file already promises "the unit list grows as sibling services ship (agentd M7…)"); check-budgets prose updated to say combined. Target stays < 100 MB combined (spec 6.2, PERFORMANCE_BUDGETS §1.2). §11. |
| 12 | **m7-check**: root oneshot, never enabled, started synchronously by idle-ram.sh after m6-check; asserts the full managed lifecycle, scope attribution, schema validity, detection of the foo-agent fixture process, `agents.json`, the D-005 screenshot `punar-m7.png`, audit lines, and the negative probes. Host gate: boot-test phase 9. §12. |

---

## 3. `punar-agentd` — a separate daemon (decision)

**Decision: separate daemon, per spec.** Section 11.3 names `punar-agentd`
as one of the eight core local services, with its own responsibility
sentence, exactly parallel to 11.1 `punard`. Folding the registry into
punard was considered and rejected:

- **Spec structure.** The service list in section 11 *is* the topology
  contract; ARCHITECTURE_DECISIONS and every milestone doc treat it that
  way. Deviating needs a stronger reason than saving one unit file.
- **Privilege and blast radius.** punard owns root mutations of system
  state (firewall, hostname, enrollment). The agent registry is a
  *bookkeeping* service: it never mutates system state, only records and
  observes. Separate processes keep the section 60 hard-safety surface of
  punard unchanged — no new methods on the socket that can touch
  capabilities.
- **M8 growth.** The ledger (spec 21) lands in this daemon next
  milestone; starting it in-process with punard would mean extracting it
  later under CI pressure.
- Cost is honest and bounded: one more small resident process, gated by
  the *combined* RSS budget (§11).

Mechanics (all mirroring punard, differences noted):

- **Crate**: `crates/punar-agentd` — the M0 placeholder lib becomes a bin
  crate (`main.rs` + modules `server.rs`, `registry.rs`, `scan.rs`,
  `summary.rs`). `#![forbid(unsafe_code)]` stays. Frugal std-threads
  accept loop, one thread per connection, same 4096-byte line limit and
  10 s timeouts — all imported from `punar-common::ipc` (envelope,
  `ErrorCode`, framing constants) rather than re-implemented.
- **Socket**: `/run/punar-agentd/agentd.sock`, bind + `chown root:punar`
  + `chmod 0660` before `listen()`. Root-owned directory via tmpfiles:

  ```text
  # usr/lib/tmpfiles.d/punar-agentd.conf
  d /run/punar-agentd    0750 root punar -
  d /var/lib/punar/agents 0700 root root -
  ```

  The ipc.md §1.1 impostor argument applies unchanged: the socket must
  not live under user-writable `/run/punar`. Admission is the filesystem
  (root or group `punar`); `SO_PEERCRED` read at accept is the
  authorization input (spec 61).
- **Unit**: `usr/lib/systemd/system/punar-agentd.service`, `Type=simple`,
  root, always-on, enabled via the **vendor-level wants symlink only**
  (`usr/lib/systemd/system/multi-user.target.wants/punar-agentd.service`)
  — the twice-verified mkosi preset-wipe lesson. m7-check asserts the
  symlink and the active state, **not** `is-enabled` (which reports
  `disabled` for vendor wants). Hardening mirrors punard.service
  (`ProtectSystem=strict` + `ReadWritePaths=` for its two writable dirs
  and `/var/log/punar`, `NoNewPrivileges=yes`, …).

  **As built**, the writable set is four paths — `/var/lib/punar/agents`,
  `/var/log/punar` (the shared audit trail and its rotation lock),
  `/run/punar-agentd` and `/run/punar` (the atomic tmp+rename of
  `agents.json`) — plus `PrivateTmp=yes`, `ProtectHome=yes` and
  `RestrictAddressFamilies=AF_UNIX`: the registry has no network surface
  at all. `ProtectProc=`/`ProcSubset=` are deliberately **not** set —
  reading every process's `/proc` entry is the detection pass. The unit
  carries `After=punard.service` as ordering only (no `Wants`/`Requires`):
  agentd reads punard's `status.json` and `device-id` when they exist and
  degrades honestly when they do not.
- **What agentd talks to**: nothing at startup. It reads adapter
  definitions and signature data from `/usr/share/punar/agents/` at boot
  (and lazily on scan), replays `registry.jsonl`, writes
  `/run/punar/agents.json` (§8.2). It never dials punard — policy
  citation for the summary file comes from `/run/punar/status.json`
  (already world-readable, already the shell's source for the same fact;
  consuming it keeps agentd free of a socket client and fails closed to
  personal mode, exactly like the shell does).

## 4. The registry (spec 19)

### 4.1 Model

- **In-memory**: `HashMap<SessionId, Session>` — the authoritative "which
  agents are running now" view (spec 19). A `Session` holds the
  schema-record fields plus M7-runtime extras that are *not* persisted
  into registry.jsonl because the record schema is exact: the verified
  scope/cgroup path, the executable path, and the authority display
  summary passed at register time (§5.3).
- **Persistence**: `/var/lib/punar/agents/registry.jsonl`, `0640
  root:root`, append-only, one **schema-exact**
  `schemas/ai-agent/registry-record.json` document per line. Two lines
  per managed session lifetime: the `active` record at register, the
  `ended` record at end (same `session_id`, `status` flipped). At
  startup agentd replays the file; sessions with no `ended` line whose
  pid is gone are closed with a synthesized `ended` append (crash
  recovery — honest, and audited as such).
- **Schema delta (additive, pre-authorized)**: `status` enum widens from
  `["active"]` to `["active", "ended"]`. The shipped schema's own
  description says verbatim that "additional lifecycle values (e.g. for
  ended sessions) will be added additively to this enum" — this is that
  change, and enum widening is compatible under the versioning rules.
  No other schema file changes in M7.

### 4.2 Methods

Wire contract lives in ipc.md §10 (binding). Summary:

| Method | Peer | Effect |
|---|---|---|
| `agents.list` | any connected | All sessions this boot (active + ended) **and** current detections; triggers a scan first if the last pass is > 30 s old (§7.3). Not audited. |
| `agents.get` | any connected | One session/detection by `session_id`. Not audited. |
| `agents.register` | group `punar` / root | Called by the launch path. Verifies peer creds and cgroup (§4.3); classification is **computed by agentd**, never trusted from params. Audited. |
| `agents.end` | owner / root | Marks ended, appends the `ended` record, removes the runtime entry. Audited. |
| `agents.scan` | any connected | Forces a detection pass (§7); also reaps dead managed pids. Audited on **transitions only** (detections appear/disappear), mirroring the M5 `enroll.sync` precedent. |

### 4.3 Registration verification (spec 22 — attribution is checked, not claimed)

`agents.register` params carry `{agent, version, process_id, project,
environment, session_id, authority_summary}`. agentd then verifies:

1. **Peer**: `SO_PEERCRED` uid of the caller == owner uid of
   `/proc/<process_id>` (root exempt). Mismatch → `denied`, audited.
2. **Identity**: `session_id` matches `^agt_[A-Za-z0-9]+$` and is unused.
3. **Attribution**: `/proc/<process_id>/cgroup` contains
   `punar-agent-<session_id>.scope`. If it does → classification
   `managed` (spec 19.1: "launched through managed Punar runtime",
   *proven* by the cgroup). If it does not but the executable matches a
   known adapter signature → the session is registered `observed` — an
   honest downgrade, surfaced in the register result so `punar-env` can
   say so. Anything else → `invalid_params` (the launch path is broken;
   nothing to pretend about).
4. `user` is resolved from the peer uid by agentd (never from params),
   `started_at` is stamped by agentd.

### 4.4 Detections are not persisted (decision)

`observed`/`unknown` findings from scans live in memory and in
`agents.json` only. Rationale: a scan observation is a point-in-time
heuristic (spec 23), not a lifecycle we own — persisting every pass would
churn registry.jsonl with sentinel-heavy records and imply a certainty
the detector does not have. The durable story for observations is the M8
ledger (Level-4 `unknown_ai_execution` events) and the M10 detection MVP.
Detections still carry registry-shaped fields (synthesized `agt_` id,
sentinels `version: "unknown"`, `environment: "host"`, `project:
"unknown"`, user = the pid's owner) so `agents.list`, the panel, and
`punarctl` render one uniform row model — the same sentinel convention
the unknown-agent fixture record established (its `project: "atlas"` is
M10 hero-demo knowledge the M7 detector honestly does not have).

## 5. Managed launch — `punar-env agent <name>` goes real (spec 26–27)

### 5.1 Flow (spec 27's ten steps, with per-step honesty)

1. **Resolve project** — existing M6 manifest load; `<name>` must be in
   `ai.agents` (the stub's membership check survives verbatim). A
   declared agent with **no installed adapter** (e.g. Atlas's `codex`) is
   an honest runtime error naming the missing
   `/usr/share/punar/agents/adapters/<name>.json`.
2. **Create session identity** — `punar-env` generates
   `agt_<12 hex chars>` from the OS RNG. The launcher mints the id
   because the scope must carry it *before* registration can verify the
   scope (§4.3); agentd remains the authority that accepts or rejects it.
3. **Calculate effective policy** — M7 = **display-level authority**: the
   manifest's `permissions` block (already parsed) + the policy citation.
   Citation source: `/run/punar/status.json` — enrolled with an org →
   the org policy id (hero demo: `eng-ai-v3`); otherwise
   `PERSONAL DEFAULTS` (DESIGN_LANGUAGE §8: authority always has a named
   source). Every rendered row keeps the M6-style
   `DECLARED · enforcement M9/M12` label — spec 1.22, no faked
   enforcement.
4. **Create cgroup/scope** — `systemd-run --user --scope
   --unit=punar-agent-<session_id> --description="Punar managed AI agent
   session <session_id> (<agent>, project <project>)" -- <argv>`.
   Fixed argv discipline (M6 §3.2), no shell strings. The scope name is
   the spec 22 attribution chain: cgroup + session id; executable
   identity is recorded at register.
5. **Configure workspace access** — working directory = the project dir
   (the one grant realized, same as M6's bind-mount honesty).
6.–8. **Network context / secret broker / tool gateway** — *not
   configured in M7*; printed as labeled lines (`network · declared ·
   enforcement M12`, `credentials · declared · M9 secret broker`,
   `tools · M9+`). Spec 1.22.
9. **Launch agent** — adapter `command` argv (or the mock override, §6).
   `systemd-run --scope` stays in the foreground; `punar-env` registers
   (step 10a) then waits, passing the agent's exit code through verbatim
   (the M6 `shell` convention).
10. **Display authority summary** — the D-014-grammar block (masthead
    `AGENT SESSION · <AGT_ID>`, attribution line, AUTHORITY rows with
    decision words, `POLICY · PERSONAL DEFAULTS` or `POLICY ·
    ENG-AI-V3`) printed before handing the terminal to the agent;
    `--json` mode emits the same as one object. On exit: `agents.end`,
    then a one-line `SESSION ENDED · <AGT_ID>` epilogue.

Registration happens **after** the scope exists and the agent pid is
known (between steps 9 and 10 wall-clock; listed as 10a): register with
the real pid, receive the computed classification, print it. If agentd
is unreachable, the launch **fails closed** — kill the scope, exit 1
with the section-73-voice error ("The agent registry is not reachable…
Next step: systemctl status punar-agentd"). An unregistered "managed"
session is a contradiction we refuse to create.

### 5.2 Session end and crash honesty

Normal path: agent exits → `punar-env` calls `agents.end` → `ended`
record appended. If `punar-env` itself dies, the scope keeps the agent
attributable; the next scan (or `agents.list`) reaps sessions whose pid
is gone, appends the synthesized `ended` record, and audits it with
`result: "failure"`-free honest action `agents.reap` — no invented exit
status.

### 5.3 What punar-env sends vs. what agentd decides

`punar-env` sends facts it owns (agent name, version from the adapter's
`version_command` output — `"unknown"` if the probe fails, project,
environment, pid, session id, authority display summary). agentd decides
identity acceptance, classification, `user`, and `started_at`. The
authority summary is carried to agentd only so the panel and
`punarctl agents inspect` render the same block the launcher printed —
it is display data, stored in memory and `agents.json`, never in
registry.jsonl (§4.1).

`environment` value: the M6 container name `punar-env-<project>` when
that container is running (podman is the source of truth, one existing
query), else the established sentinel `"host"` — M7 launches the agent
process on the host (§5.6).

### 5.4 Adapters as data (spec 26 — "Adapters should be modular")

Staged at `/usr/share/punar/agents/adapters/`, world-readable, each file
valid against `schemas/ai-agent/agent-definition.json`
(`./tools/validate-schemas.sh` picks the directory up):

```json
// claude-code.json
{
  "name": "claude-code",
  "adapter": "claude_code",
  "launch": { "method": "managed", "command": "punar-env agent claude-code" },
  "adapter_config": {
    "command": ["claude"],
    "version_command": ["claude", "--version"],
    "signature": { "comm": ["claude"], "exe_glob": ["*/claude"] },
    "mock_command": ["/usr/lib/punar/punar-mock-agent"]
  }
}
```

```json
// generic.json — the spec 26 "generic shell/agent adapter" (second adapter)
{
  "name": "generic-shell",
  "adapter": "generic",
  "launch": { "method": "managed", "command": "punar-env agent generic-shell" },
  "adapter_config": {
    "command": ["/bin/sh"],
    "signature": { "comm": [], "exe_glob": [] },
    "mock_command": ["/usr/lib/punar/punar-mock-agent"]
  }
}
```

All launch-relevant keys live in `adapter_config` — the schema's
explicitly extensible object — so **no schema change** is needed and
adapter authors validate their own config (the schema says exactly this).
The generic adapter is the modularity proof: same launch path, different
data, zero new code. Its empty signature arrays are deliberate — a plain
`/bin/sh` must never be flagged `observed` by comm matching.

The fixture `fixtures/agents/claude-code.json` stays as-is (it is the
schema example); the staged adapter files are the runtime copies with
`adapter_config` added.

### 5.5 Mock override

`punar-env` uses `adapter_config.mock_command` **only** when
`PUNAR_AGENT_MOCK=1` is set in its environment; it then prints a loud
`MOCK AGENT · dev/CI stand-in — not a real AI agent` line and reports
`version` as `"mock"`. m7-check sets the variable; nothing sets it by
default. The real `command` path is the production contract; in the
no-network CI VM only the mock path can be exercised, and the report
says so.

### 5.6 In-container launch — deferred (decision)

Spec 27's example launches an agent *for* a project; running the agent
process *inside* the M6 podman environment is deferred: the busybox base
image contains no agent binary, `systemd-run --user --scope` attribution
(the spec 22 mechanism M7 banks on) applies to host processes, and
mixing podman-exec attribution with scope attribution would weaken the
one chain we can prove. The agent runs on the host in the project
directory; the container remains the *toolchain* boundary. Revisit when
toolchain provisioning lands (M6 §13's own deferral). Documented in the
launch output (`environment` row cites the container only when running).

## 6. `punar-mock-agent` (decision: shell script, not a crate)

`/usr/lib/punar/punar-mock-agent` — POSIX sh, ~30 lines, shipped in the
desktop extra tree, mode 0755:

- prints `PUNAR MOCK AGENT — dev/CI stand-in for a managed AI agent
  session; performs no AI work` on stdout (the label is the first line,
  greppable);
- `--version` prints `punar-mock-agent 0.0-mock` and exits (the adapter
  `version_command` probe works against it too, though the mock path
  reports `"mock"` regardless, §5.5);
- touches `./.punar-agent-touch` in its working directory (the workspace
  write the check asserts);
- `trap 'exit 0' TERM INT`, then `sleep infinity & wait $!` — blocks
  until signaled (a blocking wait, not a polling loop; spec 6.3).

Script over bin crate: no workspace/build/clippy surface for throwaway
CI logic, shellcheck v0.11.0 gates it like every other script, and its
entire behavior is readable in one screen — the honesty property we
want from a thing whose only job is to be obviously fake.

## 7. Detection (spec 23 — heuristic, says "suspected", never certain)

### 7.1 Inputs and signatures

One `/proc` walk per scan: for each pid, read `comm`, `exe` (readlink;
may fail for other users' processes — root daemon, so normally
readable), `cmdline`, owner uid, cgroup. Two signature sources:

- **Known-agent signatures** from the staged adapter definitions
  (`adapter_config.signature`): a match whose cgroup is **not** a
  `punar-agent-*.scope` → `observed` (spec 19.1: "Known AI agent running
  outside managed runtime"). A match inside a managed scope is already a
  session — skipped.
- **Suspected signatures**: `/usr/share/punar/agents/signatures/`
  `suspected.json` — data, documented shape (no new schema; it is an
  internal heuristic input, versioned by review not by schema):

  ```json
  {
    "v": 1,
    "patterns": [
      { "id": "downloads-foo-agent", "exe_glob": "*/Downloads/foo-agent",
        "note": "hero-demo fixture signature (spec 25/75 step 10)" },
      { "id": "downloads-agent-like", "exe_glob": "*/Downloads/*-agent",
        "note": "agent-named executable run from Downloads" }
    ]
  }
  ```

  A match → `unknown` (spec 19.1 UNKNOWN / SUSPECTED). The pattern set
  derives from `fixtures/agents/unknown-agent/foo-agent.json`'s
  `executable_path`; the CI fixture *process* is a sleeping script m7-check
  installs at `/home/punar/Downloads/foo-agent` (§12) — a real innocuous
  process for the detector to find, matching the fixture metadata.

Every detection carries `classification` plus the display label
`suspected` — the panel, CLI, and `agents.json` all say *suspected AI*,
never *AI* (spec 23: "Do not claim perfect detection"; product voice
per D-005 Sect IV).

### 7.2 Scan lifecycle within a pass

The same pass reaps managed sessions whose pid died (§5.2), re-checks
that previous detections still exist (gone → dropped from the current
view), and diffs the detection set; on any change agentd rewrites
`agents.json` and emits the transition audit events (§10).

### 7.3 Trigger — on demand only (decision: the cheapest honest design)

`agents.scan` runs the pass now; `agents.list` runs it first when the
last pass is older than 30 s (staleness cache — opening the panel or
running the CLI always shows a fresh-enough view without hammering
`/proc`). **No timer and no punard reconcile-timer nudge in M7.**
Rationale: spec 6.3 forbids background polling loops for a service whose
milestone deliverable ("Shadow AI **detection MVP**", local alerts,
remote query) is *explicitly Milestone 10* in section 76. M7's registry
needs classification to work when someone looks — and "when someone
looks" is precisely `agents.list`. The honest limitation is stated in
the panel's detection footer (`scan on view · continuous detection
arrives with M10`) and here. A punard→agentd nudge would add an IPC
edge between daemons for a capability the milestone does not claim.

## 8. Shell — the SUPER+A AI panel (spec 25, Plate D-005)

### 8.1 Surface

`shell/punar-shell/AiPanel/AiPanel.qml` — full surface like
CommandCenter/Overview:

- `IpcHandler { target: "aipanel" }` with `toggle()`, `open()`,
  `close()`, `state()` — driven by
  `qs -p /usr/share/punar/shell ipc call aipanel toggle` (the `-p` flag
  is the established lesson).
- **Keybind**: `bindd = $mod, A, AI on this device, exec, $aiPanel` in
  `os/modules/desktop/hypr/punar-binds.conf` (staged to
  `etc/xdg/hypr/punar-binds.conf`), where `$aiPanel` is the single IPC
  contract variable in `hyprland.conf` —
  `qs -p /usr/share/punar/shell ipc call aipanel toggle`, the same
  one-variable pattern `$commandCenter` and `$overview` use. Spec 25's
  `SUPER + A` was already taken by the M2 **assistant scratchpad**, which
  moves to `SUPER+SHIFT+A`: two binds on one chord is not an option
  (Hyprland fires every match), the pad is an empty special workspace
  with nothing pre-spawned, and the panel is the milestone's headline
  surface. `docs/development/keyboard-grammar.md` carries the new table.
- **Layout** (D-005): masthead `PUNAR · AI ON THIS DEVICE` + device/mode
  line (org name only when `status.json` says enrolled —
  unmanaged-first, DESIGN_LANGUAGE §8); left **agent rail** — one row
  per session/detection: managed rows calm with the green presence dot,
  observed quiet, unknown rows in the red voice (the only red on the
  surface); right **detail** for the focused row: attribution masthead
  (`AGT_… · <USER> · <ENV> · STARTED <t>`), **AUTHORITY · WHAT IT MAY
  ACCESS** section rendering the stored authority summary with decision
  words as tracked mono (spec 20 values) and the `POLICY · PERSONAL
  DEFAULTS` / `POLICY · ENG-AI-V3` citation line, each row carrying its
  `declared · M9/M12` enforcement label; then **LEDGER · MILESTONE 8**
  as a dashed-border placeholder card (dashed honesty — the D-005/M8
  boundary made visible, per the established design language). Unknown
  detail renders the D-005 unknown card: executable path, `UNMANAGED ·
  SUSPECTED AI`, no green anywhere; the Inspect/Block/Register actions
  are **not** rendered in M7 (M9/M10 capabilities — no dead buttons).
- **Keyboard-first** (spec 12): ↑/↓ rows, Esc closes, no mouse required.

### 8.2 Data — `/run/punar/agents.json` (the status.json pattern)

Not IPC — a world-readable summary file agentd writes so the shell
renders without a socket client or polling; the shell watches it with a
`FileView` (the Services/Status.qml pattern, event-driven). Written
atomically (tmp + rename inside `/run/punar`), `0644`, at agentd startup
and on every change (register, end, reap, detection diff). Content is
**summary-only** — no secrets, no cmdlines, no authority *values* beyond
the display words already shown to the same user, exactly what the panel
renders (full field list: ipc.md §11). Same non-authoritative caveat as
status.json: `/run/punar` is user-writable, the file is display data for
that user's own session; anything trusted stays on the socket. Consumers
fail closed: missing/unparsable file renders the calm empty panel
("no agent sessions").

The panel triggers freshness on open by `exec`ing a detached one-shot
`punarctl agents list --json > /dev/null` — the staleness-gated scan
(§7.3) then rewrites `agents.json` if anything changed, and the FileView
delivers it. One-shot process on user action, not a loop.

## 9. `punarctl agents` (D-014)

- `punarctl agents list` — masthead `AI AGENTS`, columns
  `SESSION · AGENT · PROJECT · CLASS · STATUS · STARTED`; classification
  words colored (managed green, observed plain, unknown red); suspected
  rows say `UNKNOWN · SUSPECTED`. Unmanaged-first: no org chrome.
- `punarctl agents inspect <id>` — the D-005 detail in terminal grammar
  (mirrors the panel; the mockup's own Sect V names this parity):
  attribution masthead, AUTHORITY rows with decision words + enforcement
  labels + the policy citation line, `LEDGER · arrives in Milestone 8`
  line. Unknown ids → exit 1 with `not_found` prose.
- `--json` on both prints the `result` object verbatim (registry field
  names unchanged). Exit codes per D-014 (0/1/2/3/5).
- Routing: `punarctl` maps `agents.*` methods to
  `/run/punar-agentd/agentd.sock`; everything else stays on punard's
  socket. `punarctl debug rpc` gains a hidden `--socket agentd` flag so
  the 74.4-style negative probes can target the new socket; `agents.*`
  method names auto-route there even under `debug rpc`.
- `punarctl agents access <id>` is **reserved, not implemented** (spec
  11.2 lists it; the data is the M8 ledger). The agentd method table
  answers `unknown_method`; the CLI does not advertise the verb.

## 10. Audit (decision: same file, shared writer, flock-guarded rotation)

agentd appends to the **same** `/var/log/punar/audit.jsonl` with
`punar_common::AuditWriter` — one audit trail, one tail verb, one
rotation policy, and agent events sit chronologically among the system
events they relate to. Two-writer mechanics:

- Appends are single `write(2)`s of one `O_APPEND` line (< 4 KiB) —
  atomic interleaving on the same file.
- **Rotation race fixed in `punar-common`**: `AuditWriter` takes an
  exclusive `flock` on `/var/log/punar/audit.jsonl.lock` around the
  size-check + rename + reopen sequence (both daemons; punard picks the
  change up by recompilation, behavior otherwise identical). Without
  this, both daemons could rotate concurrently and orphan a writer's fd
  on a renamed file.
- **Audited (with real `agt_` ids at last)**: `agents.register` (allow
  and deny; `action: "agents.register"`, `resource`: the agent name,
  `agent_session_id`: the real id), `agents.end`, `agents.reap` (§5.2),
  and detection **transitions only** (`action: "agents.scan"`,
  `result: "detected"` when a detection appears / `"cleared"` when it
  disappears — the open-string `result` set grows additively, no schema
  change; the enroll.sync precedent). Reads (`agents.list`/`get`) and
  no-change scans are not audited.
- `source` for register/end events is `"human"` (the launch is a
  CLI-originated user action; the peer is the user) — the *subject*
  agent is identified by `agent_session_id`, which is exactly what the
  field is for. Scan/reap events are `source: "service"`, `user_id:
  "punar-agentd"` (the daemon-actor convention).
- **Deferred conditional-fields cleanup — documented, not delivered
  (decision).** The M3 follow-up ("consider making the agent fields
  conditional on `source: 'ai_agent'`") is not trivial: it changes
  which fields are *required*, breaking the "all 12 required fields
  present" contract that ipc.md §6, `validate_event_schema`, and every
  existing event line pin. M7 delivers the thing the sentinel was
  waiting for — real ids on agent events — and `agt_none` remains the
  documented, greppable sentinel everywhere else. Re-examine only if a
  v2 audit schema ever exists for other reasons.

## 11. Budgets (spec 6.2, PERFORMANCE_BUDGETS.md §1.2)

- `idle-ram.sh`: the services-RSS sample loops over **two** cgroups —
  `system.slice/punard.service` + `system.slice/punar-agentd.service` —
  summing PSS into the single `PUNAR_SERVICES_RSS_MB` value (the file's
  own comment reserved exactly this growth). A missing/empty
  `punar-agentd.service` cgroup makes the value `absent` — a dead
  daemon is a gate failure, same rule as punard. **As built**, the unit
  list is one shell variable (`PUNAR_SERVICE_UNITS`) so the next sibling
  is a one-token change, the emitted line names the units it summed, and
  a unit with no readable pids also logs *why* the value went `absent`
  to the serial console.
- `tests/performance/check-budgets.sh`: prose/annotations updated to
  "punard + punar-agentd (combined)"; thresholds unchanged — **combined**
  target < 100 MB, MVP ceiling 150 MB (spec 6.2 budgets the *services
  total*, not per-daemon). PERFORMANCE_BUDGETS.md §2.3 wording updated
  to list both units. No per-service split gates in M7: one honest
  combined number, per the budget's own definition.
- agentd at idle holds the registry map and parsed adapters — target
  well under 10 MB PSS; measured, not asserted, by the existing gate.
- Scan cost is bounded by trigger design (§7.3): zero idle CPU between
  user actions (spec 6.3).

## 12. In-VM exercise plan — `m7-check`

`/usr/lib/punar/m7-check.sh`, root oneshot
(`punar-m7-check.service`, **never enabled** — the established
not-enabled pattern), started synchronously by idle-ram.sh **after
m6-check** (ordering chain intact; sampling windows unpolluted). `set
-u`, always exits 0; verdict lines in `/run/punar/m7-report.txt`, final
`PUNAR_M7_OK` / `PUNAR_M7_FAIL`; host gate boot-test **phase 9**.
Unprivileged commands use the established session pattern
(`runuser -u punar -- env XDG_RUNTIME_DIR=/run/user/1000 HOME=/home/punar …`).
All greps for rendered verdict/status words are **case-insensitive**
(fmt::verdict uppercases — the standing lesson).

Assertion groups:

1. **Daemon preflight**: `punar-agentd.service` active; vendor-wants
   symlink present + `Wants=` visible in `systemctl show` (never
   `is-enabled`); socket exists with mode `0660 root:punar`; tmpfiles
   dirs correct.
2. **Managed launch**: with `PUNAR_AGENT_MOCK=1`, run
   `punar-env -C /home/punar/atlas agent claude-code` as punar in the
   background (mock blocks); capture the launch output (`m7-launch.txt`)
   — asserts the MOCK label, the session id line, and the AUTHORITY
   block citing `PERSONAL DEFAULTS` with `declared` enforcement labels.
3. **Registry truth**: `punarctl agents list --json` shows the session:
   `classification == "managed"`, `project == "atlas"`,
   `agent == "claude-code"`, `status == "active"`; the matching
   `registry.jsonl` line is field-validated with `jq` (all 10 required
   record fields, `session_id` matches `^agt_`), and the workspace touch
   file `/home/punar/atlas/.punar-agent-touch` exists.
4. **Scope attribution** (spec 22): `runuser … systemctl --user show
   punar-agent-<id>.scope` reports the scope active; the registered
   pid's `/proc/<pid>/cgroup` contains `punar-agent-<id>.scope` — the
   cgroup path and the registry record agree.
5. **CLI detail**: `punarctl agents inspect <id>` output (captured
   `m7-inspect.txt`) contains the attribution masthead, `AUTHORITY`,
   the `PERSONAL DEFAULTS` citation, and the `MILESTONE 8` ledger
   line; `--json` parses.
6. **Shadow fixture**: install a sleeping sh script at
   `/home/punar/Downloads/foo-agent` (0755, punar-owned; `sleep
   infinity & wait` body — the "real innocuous process"), start it as
   punar; `punarctl agents scan`; `agents list --json` now contains a
   row with `classification == "unknown"` + the `suspected` label and
   the executable path.
7. **agents.json**: `/run/punar/agents.json` parses; contains both the
   managed session summary and the unknown detection; mode 0644.
8. **The money shot**: open the panel via the session pattern
   (`qs -p /usr/share/punar/shell ipc call aipanel open`), settle,
   `grim /run/punar/punar-m7.png` — the AI panel with a managed row and
   a red unknown row on one screen. Screenshot failure is a noted
   (`FAIL`-line) assertion, per the m2 precedent.
9. **End of life**: `systemctl --user stop punar-agent-<id>.scope` (as
   punar) → the backgrounded `punar-env` returns; `agents list` shows
   the session `ended`; registry.jsonl has the `ended` record. Kill the
   foo-agent process; `punarctl agents scan` → detection cleared from
   list and agents.json.
10. **Audit**: `/var/log/punar/audit.jsonl` contains
    `agents.register` and `agents.end` events whose
    `agent_session_id` equals the real session id, and one
    `agents.scan` `detected` + one `cleared` transition event.
11. **Negative probes** (spec 74.4/60/61, on the **new** socket):
    `punarctl debug rpc agents.bogus` → `unknown_method`;
    `debug rpc admin.query --socket agentd` → `unknown_method`;
    as punar, `agents.end` on a nonexistent id → `not_found`; an
    `agents.register` claiming a root-owned pid → `denied` (peer-cred
    verification is real). Socket admission itself is the same
    filesystem mechanism m3-check already proves; asserted here only as
    the perms check in group 1.

Exports (under `/run/punar`, swept by the existing tar): `m7-report.txt`,
`m7-launch.txt`, `m7-inspect.txt`, `m7-agents-list.json`,
`m7-agents-file.json` (copy of agents.json at step 7),
`m7-registry.jsonl`, `punar-m7.png`, plus per-step diagnostics. ci.yml
uploads them with the existing artifact sweep; boot-test phase 9 greps
the verdict.

**As built** (`/usr/lib/punar/m7-check.sh`, 12 numbered groups — the
plan's 11 plus a cheap group 2 that asserts the staged adapter and
signature data before anything depends on it). Deviations from the list
above, each deliberate:

- **Group 11's peer-credential denial is not exercised in-VM.** No tool
  in the image can send arbitrary typed params to the socket — there is
  no socat, nc or python, and adding one to prove one assertion is a
  worse trade than stating the gap. `agents.register` claiming another
  user's pid is covered by `punar-agentd`'s host integration tests; the
  in-VM negative probes are the closed method table (`agents.bogus`,
  `agents.access`, `system.exec`, `admin.query` forced at the agentd
  socket), the not-found path (`agents inspect` on an unknown id), and
  the socket's filesystem admission (`agents list` as `nobody` is
  refused). The report says so in an `info` line rather than implying
  more coverage than exists.
- **The shadow-AI fixture process** ships as
  `/usr/lib/punar/foo-agent-fixture.sh` (a versioned file in the image
  tree, shellcheck-gated in CI) and is installed by the check to
  `/home/punar/Downloads/foo-agent`, `0755`, punar-owned, then started
  as `sh /home/punar/Downloads/foo-agent` — an **absolute** argv, which
  is what the detector retains (§7.1).
- **The managed launch is started BY the user manager**, not merely as
  the user: `runuser … systemd-run --user --pipe --wait --collect
  --unit=punar-m7-launch --setenv=PUNAR_AGENT_MOCK=1 -- punar-env …
  agent claude-code`. This is a new hard lesson worth carrying forward.
  `punar-env` creates the agent's scope with `systemd-run --user
  --scope`, which **migrates the calling process** into a cgroup under
  `user@<uid>.service`; cgroup v2's delegation containment permits an
  unprivileged migration only when source and destination share an
  ancestor the mover can write. A process sitting in the check's own
  `system.slice/punar-m7-check.service` cgroup shares only the cgroup
  **root** with the destination, so the migration would be refused —
  even though the process runs as `punar`. Asking the user manager to
  fork the launcher (a transient *service*: no migration at all) puts
  punar-env exactly where a real desktop launch would run it, and the
  scope migration then succeeds for the same reason it does from a
  terminal. `--pipe` hands the check's redirect to the unit and `--wait`
  propagates punar-env's exit code, so the exit-code passthrough
  assertion still measures the real thing.
- **The Atlas project is re-created from the staged fixture** if
  m6-check did not leave one, so the M7 verdict never depends on M6's.
- **Two extra honesty assertions** were added because they were cheap
  and load-bearing: a no-change `agents.scan` must write **no** audit
  line (transitions only), and `agents.json` must contain no
  `process_id` or `cmdline` for any row.

## 13. Deferred, tracked

- **Access Ledger** (spec 21) + `punarctl agents access` + the panel's
  ledger section — M8; the dashed placeholder and the reserved method
  name are the M7 truth.
- **Authority enforcement** — M9 (credentials/approvals), M12 (network);
  every M7 surface carries the `declared` label.
- **Continuous detection, alerts, remote queries, unknown-view actions**
  — M10 (spec 76 names it "Shadow AI detection MVP").
- **In-container agent launch** — with toolchain provisioning (§5.6).
- **Child-process lineage attribution** beyond the scope cgroup —
  M8 (ledger process classes; spec 22 "where technically possible").
- **Audit conditional-fields schema cleanup** — documented closed as
  "not planned" unless a v2 schema happens (§10).
- **Manifest struct promotion to punar-common** (M6 §13) — **not
  needed**: `punar-env` remains the only manifest consumer; agentd
  receives display data over IPC. Closed unless a second consumer
  appears.

## 14. Verification status (spec 1.22)

This document began as the M7 **design plan**; the sections above now
describe what was built, with every deviation marked in place. What has
actually been run, and what has not:

**Repository state (audited 2026-08-25 against HEAD 0ba4ea6):** the entire
M7 tree is **working-tree only** — uncommitted and unpushed. **No CI run
contains any M7 code.** The newest CI run,
[32857914904](https://github.com/smplify-mdm/punar/actions/runs/32857914904)
(2026-08-25, all five jobs green), is M6's green run at 0ba4ea6; its
`desktop-test` job is still named for the M2–M6 exercises and its
services-RSS number (2 MB) is punard alone. Everything below labeled
"verified on the host" is local and non-authoritative per spec 1.22; the
in-VM run remains the arbiter.

**Verified on the host, 2026-08-25:**

- `cargo fmt --all -- --check` clean; `cargo clippy --workspace
  --all-targets --locked -- -D warnings` clean; `cargo test --workspace
  --locked` green (458 assertions, 0 failed) — all in the pinned
  `rust:1` container with the rustfmt/clippy components added.
- `shellcheck v0.11.0` (pinned container) clean on every touched or new
  script: `m7-check.sh`, `foo-agent-fixture.sh`, `punar-mock-agent`,
  `idle-ram.sh`, `container-build.sh`, `boot-test.sh`,
  `check-budgets.sh`.
- `actionlint` clean on `.github/workflows/ci.yml`.
- `./tools/validate-schemas.sh`: 15 schemas metaschema-checked, 125
  documents validated, ALL PASS — including the two staged adapter
  definitions (validated in place, so the file the image ships is the
  file the schema checked) and the widened `registry-record.json`
  status enum. `suspected.json` is deliberately listed as "no schema by
  design" (§7.1).
- `PUNAR_BUILD_MODE=summary ./tools/build-image.sh` completes: the
  desktop profile stages, and `mkosi summary` accepts the tree with the
  new unit, tmpfiles snippet, adapter/signature data and fixture script.
- `Hyprland --verify-config` → **"config ok"** on hyprland **0.56.2-1**
  from the ALA 2026/08/20 snapshot, in a container built on the pinned
  builder-base digest, for the edited config tree (the `SUPER+A` AI-panel
  bind and the scratchpad move to `SUPER+SHIFT+A`). Non-vacuous: a
  negative control (`exec` misspelled `execc` on that very bind) is
  rejected with a per-file per-line error.
- `qmllint` 6.11.2 (pinned container, `/usr/lib/qt6/bin/qmllint`): all
  nine `.qml` files clean, zero warnings.
- `systemd-analyze verify` and `systemd-tmpfiles --dry-run --create`
  accept `punar-agentd.service`, `punar-m7-check.service` and
  `punar-agentd.conf` on systemd 261 — every directive is a recognized
  key; the only messages are the emulated container's inability to stat
  the not-yet-built binaries.
- **Detection end to end on the host**: `punar-agentd` built and run
  against the real staged `adapters/` and `signatures/suspected.json`,
  with the real `foo-agent-fixture.sh` started under a
  `.../Downloads/foo-agent` path. It loaded both data files with **no**
  degradation warnings, wrote `agents.json` with
  `policy_citation: "personal-defaults"`, and `punarctl agents
  list` rendered `UNKNOWN · SUSPECTED` with
  `signature_id: downloads-foo-agent` — the same strings m7-check greps
  for.

**NOT verified — the in-VM run is the arbiter:**

- Nothing in `m7-check.sh` has run inside the VM. Every in-guest
  assertion (daemon active, socket modes, the managed mock session, the
  scope cgroup, the panel screenshot, the audit lines) is **planned, not
  proven**, until a `desktop-test` run delivers `PUNAR_M7_OK`.
- The combined services-RSS number (punard + punar-agentd) has never
  been measured; `PERFORMANCE_BUDGETS.md`'s table still reads "not yet
  measured". The claim here is only that the sampler now sums both
  cgroups and reports `absent` if either is missing.
- The `SUPER+A` bind is proven to *parse*, not to *behave*: `exec` binds
  are only syntax-checked by `--verify-config`, and the panel's IPC
  target is proven at runtime by m7-check group 9, not at parse.
- The `desktop-test` job has never run at its new 95-minute budget, and
  `boot-test.sh` phase 9 has never gated a real `m7-report.txt`.
- M6's CI was in flight when the plan was written, so no M6 result was
  assumed and the M7 exercise re-creates the Atlas project from the staged
  fixture rather than depending on M6 having left one. That independence
  stands, and M6 has since resolved **green**: run 32857914904 delivered
  `PUNAR_M6_OK` (56 assertions) — so `punar-env` is now CI-proven ground
  for M7 to build the managed launch on, and the in-VM chain M7 extends is
  209 assertions (M2 33, M3 28, M4 29, M5 63, M6 56).

**Independently re-run by the status audit, 2026-08-25** (a subset of the
above, re-executed against the working tree rather than taken on trust):
`cargo test --workspace --locked` in the pinned `rust:1` container — **458
passed, 0 failed** (`punar-agentd` 36 of them: 27 lib + 1 main + 8
`tests/registry.rs`); `./tools/validate-schemas.sh` — 15 schemas
metaschema-checked, 125 documents validated, ALL PASS; `shellcheck
v0.11.0` clean on `m7-check.sh`, `punar-mock-agent`,
`foo-agent-fixture.sh`, `idle-ram.sh`, `boot-test.sh` and
`check-budgets.sh`; `actionlint` clean on `ci.yml`. Not re-run by the
audit and therefore standing on the implementation record above: `cargo
fmt`/`clippy`, the mkosi summary build, `qmllint`,
`Hyprland --verify-config`, `systemd-analyze verify` /
`systemd-tmpfiles --dry-run`, and the host-side detection run.
