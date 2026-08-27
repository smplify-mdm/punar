# Milestone 8 — AI Access Ledger: design plan and build record

Spec authority: section 76 Milestone 8 ("Deliver resource summaries,
process attribution, security events, local retention, and privacy
controls"), grounded in section 21 (the ledger itself — 21.1 access
categories, 21.2 the four observation levels and the never-record
rules), 22 (attribution — cgroups, session ids, systemd scope), 24
(local-first AI privacy model; 24.1 remote-query rules, 24.2 user
visibility), 53 (audit — the single source of truth for security
events), 54 (telemetry separation: "AI resource summary" and "detailed
local ledger" are distinct categories), 11.2 (`punarctl agents access
<id>`, `punarctl privacy connections`), 11.3 (`punar-agentd` is the
"access-ledger service"), 25 (Local AI UX), 73 (restriction voice), 6.3
(no polling), 6.4 (batch disk I/O; "Do not log every filesystem read by
AI agents"), 1.14 (avoid broad tracing when aggregation or scoped
primitives suffice), 1.22 (honesty).

Binding prior contracts, not relitigated: `schemas/ai-agent/ledger-summary.json`
(**SHIPPED — the wire contract; M8 does not change one byte of it**, §2),
`docs/api/ipc.md` §10–§11 (the agentd socket and `agents.json`; M8 adds
§12–§13 additively), `docs/development/milestone-7.md` (registry,
managed launch, scope attribution, adapters-as-data, the mock agent,
the check mechanics and their hard lessons), `schemas/audit/audit-event.json`
+ `schemas/ai-agent/registry-record.json`,
`docs/design/mockups/ai-panel.html` (Plate D-005 — the ledger section
layout is the acceptance reference), `docs/design/mockups/cli-grammar.html`
(Plate D-014), DESIGN_LANGUAGE §8 (unmanaged-first).

M7 shipped the registry: an agent session is a named principal with an
`agt_` identity, a project, a classification, a cgroup and an audit
trail. M7 deliberately left the panel's ledger section a **dashed
`MILESTONE 8` placeholder** and `agents.access` reserved as
`unknown_method`. M8 fills exactly that hole and nothing more: it
answers "**what has this agent actually accessed?**" — the section 21
question, kept structurally apart from section 20's "what may it
access?" — from evidence Punar already mediates, with a privacy model
enforced in types rather than in prose, and with the user able to see
and delete every byte of it.

---

## 0. The architectural law of this milestone (spec 1.14 + 21)

**Everything in the ledger is DERIVED from a mediation point Punar
already owns. Nothing is inferred from tracing.** M8 adds no eBPF, no
fanotify, no ptrace, no `LD_PRELOAD`, no audit subsystem rules, no
filesystem or network interception of any kind. Four honest sources,
and only four:

| # | Source | Owned since | Produces |
|---|---|---|---|
| A | **Agent scope cgroup** — `punar-agent-<session_id>.scope/cgroup.procs`, enumerated at ledger sampling points | M7 §5.1 step 4 | process classes |
| B | **Audit stream filtered by `agent_session_id`** — `/var/log/punar/audit.jsonl` | M3 (audit), M7 (real `agt_` ids), M8 (punard attribution, §4.1) | Level-4 security event references |
| C | **`punar-env` workspace grant** — the project the managed launch resolved and made the session's working directory | M6/M7 §5.1 step 5 | directory zone `workspace`, repository (project) identity |
| D | **Adapter/session metadata** — the registry record itself | M7 §4 | agent name, session identity, timestamps |

Categories with **no owned producer in M8 are not invented**. They
render as explicit `NOT YET OBSERVED · MILESTONE <n>` rows, in the data
(`not_yet_observed[]`, ipc.md §12.2) and on every surface (§8, §9) —
spec 1.22. `punar-netd` does not exist until M12; there is no MCP or
tool gateway until M9+; `punar-secrets` issues no credentials until M9.
An empty array in those categories therefore means *not observed*, never
*did not happen*, and every rendering says so in those words.

---

## 1. Scope

**In:** the ledger engine inside `punar-agentd` (§3) — a per-session
aggregate accumulated from sources A–D at event-driven update points,
persisted at `/var/lib/punar/agents/ledger/` (§5); process-class
extraction from `cgroup.procs` via a data-file class table (§3.2);
punard tagging capability calls with the calling session's `agt_` id
(§4.1); Level-4 security events as **references** into the audit log
(§4); retention, compaction and pruning (§6); `agents.access` and
`ledger.purge` on the agentd socket plus the `agents.list` ledger
fingerprint (§7, ipc.md §12); the panel's real LEDGER section per Plate
D-005 replacing the dashed placeholder, plus the privacy line and the
in-panel purge keystroke (§8); `punarctl agents access <id>`,
`punarctl privacy ledger`, `punarctl privacy purge` (§9); `m8-check` +
boot-test phase 10 + `punar-m8.png` (§12).

**Out (documented, never silently dropped):** network destinations
(M12 — `punar-netd`); MCP servers and tools (M9+ — the AI Agent
Gateway, spec 26); credential classes (M9 — `punar-secrets`, spec 29);
approval-gate bypass events (M9); production-access and
sensitive-resource events (M9/M12 — nothing mediates those resources
yet); ledgers for **unknown detections** (M10 — detections are not
persisted, M7 §4.4); any upload, sync or remote query path whatsoever
(M10 implements spec 24.1's authorized query; M8 ships **no** network
code in agentd — `RestrictAddressFamilies=AF_UNIX` stays); a graphical
privacy panel (M13); org-side retention policy overriding the local
default (M10+, §6.4).

---

## 2. The schema is the contract — and it is NOT extended

**Decision 0 (loudest decision in this document): `schemas/ai-agent/ledger-summary.json`
ships unchanged. M8 conforms to it; it does not conform to M8.**

The shipped schema encodes section 21.2's privacy rules *structurally*:
`resources.*` are de-duplicated arrays of identifiers, **not** per-access
entries; `directory_zones` items are patterned `^[a-z][a-z0-9_]*$` so a
`/` cannot appear; `network_destinations` reject `:` and `/` so a URL
cannot appear; `credential_classes` are classes; `security_events` carry
`event_id` + `event_type` + optional `timestamp` and nothing else; and
there is no field anywhere for prompt text, file contents or source
code. That is the privacy model as a type. It is not negotiable and it
is not the place to bolt counts onto.

The task brief describes the internal aggregate as
`{category, resource_class, count, first_seen, last_seen}`, and Plate
D-005 renders `git × 12 · cargo × 4 · bash × 9` — counts are a **design
requirement of the panel**, and the schema has nowhere to put them.
Resolution, without touching the schema:

- **Two layers.** The **ledger record** (on disk, internal, ipc.md §13)
  is the aggregate: `entries[]` of
  `{category, resource_class, count, first_seen, last_seen, evidence}`.
  The **ledger summary** is a *total projection* of that record onto
  `ledger-summary.json`: group `entries` by `category`, emit the
  distinct `resource_class` values into the matching `resources` array,
  emit `security_events` refs verbatim. Because the summary is produced
  by one pure function over the record, conformance is guaranteed by
  construction, not by review.
- **The counts travel beside the document, never inside it.**
  `agents.access` returns `result.summary` (the schema-exact document,
  the thing a validator checks and the thing M10's authorized query will
  one day export) **and** `result.detail` (the aggregate entries with
  counts and first/last seen) as **sibling fields of the result
  object**. Adding a sibling field to an IPC result is an additive
  contract change; adding a field to `ledger-summary.json` would be a
  schema change. Only the first is warranted, so only the first happens.
- `entries[].category` is a Rust enum with exactly the six schema keys
  (`repositories`, `directory_zones`, `network_destinations`,
  `mcp_servers`, `credential_classes`, `process_classes`), so the
  projection is total and a seventh category cannot be added by
  accident.

**Privacy enforced in types (§21.2, non-negotiable):**

- `ResourceClass` is a newtype whose constructor **rejects any value
  containing `/`, `:`, whitespace, or a leading `.`**, and additionally
  validates against the per-category pattern from the schema. There is
  no `From<String>`; the only constructors are the four evidence
  extractors (§3–§4). A filesystem path is therefore unrepresentable in
  the ledger — including in `repositories`, the one schema array with no
  pattern of its own (M8 constrains it to the manifest project-name
  pattern `^[a-z][a-z0-9_-]*$`; when git-remote identity ever becomes an
  owned fact, the constraint relaxes to `host/org/name` explicitly and
  with its own rule against leading `/` and `..`, and this paragraph
  gets rewritten in that milestone, not before).
- **`comm` is never stored.** Process evidence passes through the class
  table (§3.2); an unmapped `comm` becomes the literal class `unknown`.
  A user's script named `deploy-prod-hotfix.sh` cannot reach the ledger.
- There is no argv, no cwd, no pid, no environment, no prompt, no file
  content, no secret value, and no per-access event anywhere in the
  record type. Not "we don't write them" — there is no field.
- The ledger stores **event references** for Level 4, never payloads
  (§4.3): one source of truth, and the audit log's own never-log rule
  (spec 53) then covers the payload for free.

`m8-check` group 8 (§12) is the regression test that keeps all of this
true at runtime, by grepping the stored bytes.

---

## 3. Level 3 — the resource summary

### 3.1 Category → source map (spec 21.1 → 21.2 Level 3)

| Schema array | M8 source | What is claimed, exactly | Honest limitation |
|---|---|---|---|
| `process_classes` | **A** — `cgroup.procs` of `punar-agent-<id>.scope`, sampled at update points; `comm` → class table | "processes of this class were alive inside the session's cgroup at a sampling point" | short-lived children between samples are missed; the count is **sampled-alive distinct pids**, never a spawn total (§3.3) |
| `directory_zones` | **C** — the managed launch's realized workspace grant | `workspace` for a managed session with a resolved project (its cwd was the project directory) | the *grant* is the evidence, not a read: Punar logs no per-read events (21.2, 6.4). Declared-but-unrealized zones (`home`, `ssh`, `aws`) are **authority**, not ledger, and never appear |
| `repositories` | **C** — `project.name` from the project manifest | the project workspace identity the session was bound to (Plate D-005 renders exactly `atlas`) | it is a *project* identity, not a git remote: Punar does not mediate git and does not read `.git/config` |
| `network_destinations` | — | **NOT YET OBSERVED · MILESTONE 12** | `punar-netd` does not exist; M6 containers run `--network none`; inventing domains would be spec 1.22 fraud |
| `mcp_servers` | — | **NOT YET OBSERVED · MILESTONE 9+** | no tool/MCP gateway mediates anything yet (spec 26; M7 §5.1 already printed `tools · M9+`) |
| `credential_classes` | — | **NOT YET OBSERVED · MILESTONE 9** | `punar-secrets` is the producer of `credential.request` events (spec 29) |

The three empty categories are emitted as **empty arrays in the
schema-exact summary** (they are `required`) *and* as entries in
`result.not_yet_observed[]` carrying `{level: 3, category, milestone,
reason}`. No surface may render an empty category without its
not-yet-observed label (§8.3, §9.1).

**When M9/M12 ship, no ledger code changes.** Credential classes arrive
the moment `punar-secrets` emits `credential.request` audit events
tagged with `agent_session_id` — source B already ingests them; only the
mapping table (§4.2) gains a row. Network destinations arrive when
`punar-netd` emits per-session destination *aggregates*. That is the
point of deriving from mediation points: the ledger grows when
mediation grows, and never before.

### 3.2 Process-class extraction (source A, spec 22)

- **Read path:** resolve the session's scope cgroup once at register
  time (agentd already verifies `/proc/<pid>/cgroup` contains
  `punar-agent-<id>.scope`, M7 §4.3) and store the absolute cgroup path
  (`/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/…/punar-agent-<id>.scope`).
  At each update point read that directory's `cgroup.procs` — one
  `read(2)` of one file — then for each pid read `/proc/<pid>/comm` and
  `/proc/<pid>/stat` field 22 (`starttime`).
- **Dedup key** is `(pid, starttime)`, not `pid`: pid reuse cannot
  inflate a count. Keys are held in memory for the session's lifetime
  and discarded when the session ends (they are not persisted — a pid
  is not ledger data).
- **`comm` → class** through `/usr/share/punar/agents/process-classes.json`
  (data, not code — the M7 adapters-as-data precedent; no schema: an
  internal heuristic input versioned by review, exactly like
  `signatures/suspected.json`, M7 §7.1):

  ```json
  {"v": 1, "classes": {
    "git": "git",
    "sh": "shell", "bash": "shell", "dash": "shell", "zsh": "shell",
    "node": "node", "npm": "node", "npx": "node",
    "cargo": "cargo", "rustc": "cargo", "rustup": "cargo",
    "python": "python", "python3": "python",
    "podman": "container", "crun": "container",
    "nvim": "editor", "chromium": "browser",
    "punarctl": "punar", "punar-env": "punar",
    "claude": "agent", "punar-mock-agent": "agent"
  }}
  ```

  Anything not in the table is class **`unknown`** — never the raw
  `comm`. The class vocabulary is closed by this file; the schema's own
  examples (`bash`, `git`, `node`, `cargo`) are all present.
- The agent's own root process is included (class `agent` for the
  adapter's binary) — it is a process in the scope and pretending
  otherwise would understate the session.
- **`pids.peak`** of the scope cgroup is read at the same time and
  stored on the record as `process_peak` — the kernel's own high-water
  mark of concurrent pids. It is rendered (CLI `--json` and
  `privacy ledger`) as `peak concurrent processes`, **never** as a spawn
  count, and it is the honest partial answer to section 21.1's
  "processes spawned" that sampling alone cannot give.

### 3.3 Count semantics, stated once and rendered everywhere

`count` = **distinct `(pid, starttime)` pairs of that class observed at a
sampling point**. It is not a spawn count and not a syscall count. Every
surface carries the qualifier: the panel's Ledger tagline reads
`what it accessed · local only · level 3 · sampled at scan points`, and
`punarctl agents access` prints `PROCESSES · SAMPLED AT SCAN POINTS ·
SHORT-LIVED CHILDREN MAY BE MISSED`. Spec 1.22: the number is real, and
so is its limitation.

---

## 4. Level 4 — security events (spec 21.2, 53)

### 4.1 Attribution: punard tags capability calls with the session (spec 22)

Today every punard audit event carries `agent_session_id: "agt_none"`
(M7 §10). M8 makes punard attribute a call to the agent session that
made it, using the mediation point it already owns:

> at `accept()`, punard already reads `SO_PEERCRED` (uid, gid, **pid**).
> M8 adds: read `/proc/<peer_pid>/cgroup`; if it names
> `punar-agent-<id>.scope`, set `agent_session_id = agt_<id>` and
> `source = "ai_agent"` (spec 18: the agent is the principal). Otherwise
> nothing changes — `agt_none`, `source` as today.

This is ~30 lines against a file punard already reads for authorization,
and it is *kernel-attested*: the cgroup is the same attribution chain
`agents.register` verifies. It is **not** tracing; it observes the peer
of a socket punard already terminates. No new syscalls, no new
privileges, no per-call cost beyond one small `read`.

Consequence, and it is the headline security property of M8: **a
capability call made by a process inside a managed agent session is
attributed to that session in the audit trail whether or not the agent
declared it** — including a denial, which is the case the ledger most
needs to show.

Existing events and checks are unaffected: m3–m7's `punarctl` runs are
outside any agent scope, so they keep `agt_none` and their current
`source`. `punar-agentd`'s own events already carry real ids (M7 §10).

### 4.2 Derivation: audit stream → Level-4 categories

The ledger **reads** the audit log; it never writes security events of
its own (except `ledger.purge`/`ledger.prune`, which are audit events
about the ledger, not ledger entries). Mapping table (data-driven, one
match arm per row, evaluated in order):

| Audit predicate | Level-4 `event_type` | Producer in M8? |
|---|---|---|
| `decision == "deny"` for any attributed action | `denied_access` | **yes** — punard mutations (§4.1), `agents.register` denials |
| `decision == "allow"` on a punard **mutating** capability action (`capabilities.set`, `reconcile`, `enroll.*`) | `privilege_request` | **yes** (an agent reaching for a privileged capability *is* a privilege request, spec 21.2) |
| `action == "credential.request"` | `credential_request` | no — **M9** (`punar-secrets`) |
| `decision == "approval_required"` bypassed / approval denied then retried | `policy_bypass_attempt` | no — **M9** (approval gates) |
| network action against a production zone | `production_access` | no — **M12** (`punar-netd`) |
| capability/zone flagged sensitive (`ssh`, cloud config) | `sensitive_resource_access` | no — **M9/M12** (nothing mediates those zones) |
| unknown-agent detection transition (`agents.scan`, `result: "detected"`, classification `unknown`) | `unknown_ai_execution` | **partially** — the audit event exists today, but detections have no persisted session (M7 §4.4), so it attaches to **no** ledger in M8; **M10** owns the unknown-agent ledger |

All seven enum values of the schema are accounted for: two have producers
and the other **five** appear in `result.not_yet_observed[]` with
`{level: 4, category, milestone, reason}`. `unknown_ai_execution` is one
of the five, with its own reason string rather than a footnote somewhere
else — the CLI and the panel both build their "not yet observed" line
from that array alone, so a category left out of it is a category the
reader never hears about. The reason says the honest thing: the *event*
is already recorded in the audit log today; what M8 does not do is give
an unregistered process a ledger of its own (M10).

### 4.3 Storage: references, not payloads

A ledger record's `security_events[]` holds exactly
`{event_id, event_type, timestamp}` — the schema's shape, nothing more.
The payload (action, resource, decision, policy ids, result) stays in
`/var/log/punar/audit.jsonl`, which is the single source of truth
(spec 53) and is already the thing `punarctl audit tail` renders. The
panel and the CLI render the event *category*, its time and its
`evt_` id, and tell the reader where the full record lives
(`punarctl audit tail`). Duplicating the payload would (a) create two
places to redact, (b) let the two disagree, and (c) put resource names
like `security.firewall` inside a per-session file that the user can
purge — while the audit trail, deliberately, is not purgeable (§10.3).

### 4.4 Ingestion: event-driven tail, batched writes (spec 6.3, 6.4)

- **Watch:** one `inotify` watch on `/var/log/punar/audit.jsonl`
  (`IN_MODIFY`, `IN_MOVE_SELF`) plus `IN_CREATE` on `/var/log/punar`
  for rotation. One agentd thread blocks in `read(2)` on the inotify
  fd — event-driven, zero idle CPU, no timer, no poll loop (spec 6.3;
  the same discipline the shell's `FileView` follows).
- **Tail state:** `(dev, ino, offset)` persisted in the ledger index
  (§5.2). On `IN_MOVE_SELF` (the flock-guarded 8 MiB rotation, M7 §10)
  the held fd is drained to EOF first, then the new path is opened at
  offset 0 — no event is lost across a rotation. On a cold start with a
  smaller/unknown inode, agentd resumes at offset 0 of the current file
  and relies on idempotence (below).
- **Idempotence:** every ingested `event_id` is checked against the
  session record's existing refs before appending, so a re-read of the
  same bytes cannot double-count. Ingestion is also **floored by the
  purge tombstone** (§10.4): events older than a session's `purged_at`
  are never re-ingested, so a purge cannot be undone by a later drain.
- **Lazy catch-up:** every ledger *read* (`agents.access`,
  `agents.list`, `privacy ledger`) drains pending audit bytes first, so
  a missed inotify event can never make the ledger lie to the user.
- **Bounds:** at most 4 MiB read per drain; lines that do not parse or
  carry `agt_none` are skipped without allocation; only lines whose
  `agent_session_id` names a session this device has a ledger for are
  materialized.
- **Writes are batched:** the in-memory aggregate is updated per line;
  the on-disk file is rewritten **at most once per drain batch, per
  session**, via tmp+rename. There is no per-event `fsync` — one
  `fsync` on the tmp file before `rename` per batch, which is the
  minimum that makes atomic replacement meaningful (spec 6.4: "Batch
  and aggregate"). At idle the write rate is exactly **zero**.

---

## 5. Aggregation and storage

### 5.1 Update points (all event-driven — no timers anywhere)

| Trigger | What is refreshed | Why it is honest |
|---|---|---|
| `agents.scan` pass (on demand; the panel and `agents.list` already trigger it when stale, M7 §7.3) | cgroup sample for every active session + audit drain + retention prune | the pass already walks `/proc`; the cgroup read is one extra file per active session |
| `agents.end` (and `agents.reap`) | final cgroup sample, final drain, record compaction (§6.2) | last chance to sample before the scope dies |
| audit append (inotify, §4.4) | Level-4 refs for the named session | the event *is* the trigger |
| `agents.access` / `agents.list` / `privacy ledger` read | drain + sample for the requested session | a read must not show a stale answer |
| agentd startup | replay index, resume tail offset, prune expired | crash honesty |

No `systemd` timer, no interval, no background thread other than the
blocking inotify reader. Section 6.3 compliance is structural.

### 5.2 On-disk layout

```text
/var/lib/punar/agents/ledger/                 0700 root:root   (tmpfiles)
/var/lib/punar/agents/ledger/<session_id>.json 0640 root:root  (one record per session)
/var/lib/punar/agents/ledger/index.json        0640 root:root  (rollup + tail state)
```

- Per-session record: the internal aggregate (ipc.md §13.1) —
  `{v, session_id, agent, user, project?, classification, status,
  started_at, ended_at?, updated_at, purged_at?, retention_expires_at?,
  process_peak, entries[], security_events[]}`. Written atomically
  (tmp + `fsync` + `rename` inside the same directory), batched per
  §4.4. `project` here is a **repository `ResourceClass`**, not the
  launcher's free-text project string: `registry-record.json` leaves
  `project` unpatterned, so `agents.register` will accept
  `project: "/home/punar/clients/acme"`, and the ledger's type makes
  that unrepresentable — such a session gets no `project` field, no
  repository row and no zone row. The raw string stays in the M7
  registry record; it crosses into no ledger byte.
- `index.json`: `{v, updated_at, tail: {dev, ino, offset},
  sessions: [{session_id, agent, project, user, classification, status,
  first_seen, last_seen, updated_at, retention_expires_at, purged_at?,
  counts: {resources, process_classes, security_events}}]}`. This is
  what `agents.list` serves its fingerprint from and what retention
  walks, so neither needs to open every session file.
- **Memory rule:** only **active** sessions' aggregates live in memory;
  an ended session's record lives on disk and is loaded on demand
  (`agents.access`, purge, prune). The RSS gate (M7 §11, spec 6.2) sums
  both daemons and stays the arbiter.

### 5.3 Bounds and disk budget (spec 6.4)

| Bound | Value | Rationale |
|---|---|---|
| distinct `resource_class` values per category per session | 32 | the honest ceiling on a class vocabulary; overflow increments a `truncated` flag rendered as `… and more (truncated)` rather than silently dropping |
| `security_events[]` per session | 256 refs | a session generating more has a story the audit log tells better; overflow keeps the **first 128 and last 128** and sets `truncated`, so neither the onset nor the present is lost |
| per-session file | target ≤ 8 KiB, hard cap 16 KiB | ~50 bytes/entry × (6 × 32) + 256 × ~90 bytes |
| sessions in `index.json` | 200 (oldest **ended** evicted first, its file deleted, audited `ledger.prune` `reason: "index_cap"`) | keeps the index a single small read |
| whole ledger directory | **< 4 MiB** (200 × 16 KiB + index) | states the budget the way PERFORMANCE_BUDGETS.md wants it stated |
| audit bytes read per drain | 4 MiB | bounds a cold start behind a large log |
| idle write rate | **0 B/s** | no timer means no idle write |

---

## 6. Retention (spec 76 M8 "local retention", 21, 24, 6.4)

### 6.1 The default: 14 days after a session ends

`LEDGER_RETENTION_DAYS = 14`. The spec sets no number, so the number
must be argued, not asserted:

- **Section 24's principle is minimization** — the detailed ledger stays
  local *and* the device should not accumulate a permanent behavioral
  history of its user. A retention window is the mechanism that makes
  "local-first" more than a network claim.
- **What the ledger is for** is answering "what did this agent access?"
  about a session someone still remembers — an incident review, a "what
  did that agent do last Tuesday", a support question. Two weeks covers
  a sprint and the working memory of the question; a year would serve
  nobody on the device and would serve a future subpoena or a future
  admin query (M10) rather than the user.
- **Budgets (6.4)** are satisfied by §5.3's caps regardless, so 14 days
  is not a disk decision — it is a privacy decision, and it should be
  argued as one.
- **Active sessions are never pruned**, however long they run. The
  clock starts at `ended_at`.

The window is a documented constant surfaced by
`punarctl privacy ledger` ("kept 14 days after the session ends, then
deleted automatically"), not a hidden one. Making it configurable is
deliberately **not** M8 (§6.4).

### 6.2 Compaction of ended sessions

At `agents.end`/`agents.reap` the record is compacted once: the pid
dedup set is dropped (memory), `entries` are re-sorted (category, then
descending count, then `resource_class`) so renderings are stable, an
`ended_at` and `retention_expires_at = ended_at + 14d` are stamped, the
file is written one final time, and the aggregate leaves memory. An
ended record is never rewritten again except by purge or prune.

### 6.3 Pruning

Prune runs at agentd startup, at every `agents.scan` pass, and at
`agents.end` — the same event-driven points as everything else. It
deletes files whose `retention_expires_at` is past (audited
`ledger.prune`, `result: "expired"`), enforces the 200-session index cap
(`result: "index_cap"`), and removes index rows for files that vanished
underneath it (`result: "orphan"`). One `ledger.prune` audit event per
prune *batch*, naming the count — not one per file (6.4).

### 6.4 Explicitly deferred

Configurable retention (a `PunarPreference`/policy key), and any
org-side retention override, are **M10+**: M8 has no remote query path
at all, so an org retention knob would govern data no org can reach.
Stated here so the absence is a decision, not an oversight.

---

## 7. IPC (additive; full wire contract in ipc.md §12–§13)

| Method | Peer may call | Mutating | Audited |
|---|---|---|---|
| `agents.access` | **session owner or root** | no (drains + samples) | only when a **non-owner root** reads another user's ledger (`ledger.read`) |
| `ledger.purge` | **session owner or root** | yes | **always** |
| `agents.list` (existing) | any connected | no | no |

- **`agents.access {session_id}`** — the M7-reserved name (spec 11.2),
  now implemented. Result: `{summary, detail, not_yet_observed,
  retention, privacy}` (ipc.md §12.2). `summary` is the schema-exact
  `ledger-summary.json` document; `detail` carries the counted entries
  and `process_peak`; `not_yet_observed` carries the honest rows;
  `retention` carries `{days, expires_at}` or `{days, active: true}`;
  `privacy` carries the purge command string and the "never recorded"
  list, so every renderer says the same words. Unknown id →
  `not_found`. Purged session → a record with `purged_at` set and empty
  resources, rendered as **"Purged by you · <ts>"**, never as "nothing
  happened".
- **Ownership rule** (new, and the interesting one): a ledger is
  personal data about one user's session, so `agents.access` requires
  `peer.uid == owner uid of the session` or root. This is stricter than
  `agents.list` (which shows registry rows, already visible in `/proc`)
  and it is the local half of spec 24.1's "RBAC applies".
- **`ledger.purge {session_id}` | `{all: true}`** — deletes local ledger
  data. Authorization: root may purge anything; a non-root peer may
  purge **its own** sessions, and `{all: true}` means "all sessions
  owned by the calling uid" — never another user's. Denial carries a
  section-73 message (who may act, why, next step). Always audited
  (`action: "ledger.purge"`, `resource`: the session id or `own`,
  `decision`, `result: "purged"` + the count).
- **`agents.list` gains `"ledger"` per session** — a **fingerprint of
  counts only**: `{"resources": 5, "process_classes": 3,
  "security_events": 1, "updated_at": "…"}`. No identifiers, no class
  names, no event ids. It is what the panel's rail needs to show "3
  process classes · 1 security event" without exposing one user's
  ledger contents through the world-readable summary file (§8.2).
- **Reserved, honest:** `admin.*` and any query/export method remain
  `unknown_method` (M10). `ledger.export` does not exist.

---

## 8. The AI panel — the real LEDGER section (spec 25, Plate D-005)

### 8.1 What replaces the dashed placeholder

`shell/punar-shell/AiPanel/AiPanel.qml` lines ~1176–1235 (the `Canvas`
dashed card reading `Not yet recorded · Milestone 8`) are replaced by
the D-005 ledger register, in the same `Sect` + `kv` grammar the
Authority block above it already uses:

```text
LEDGER                    what it accessed · local only · level 3 · sampled at scan points
  Repositories            atlas
  Directory zones         workspace
  Processes               git × 2 · shell × 3 · agent × 1        peak 6 concurrent
  Network destinations    Not yet observed · Milestone 12
  MCP servers             Not yet observed · Milestone 9+
  Credential classes      Not yet observed · Milestone 9
  Denied · capabilities.set · 14:02 · evt_502                    ← red voice, one row per event
```

- **Observed rows** use the calm `FactRow` value voice (`Theme.ink2`) —
  D-005 renders ledger values muted, never green: the ledger reports,
  it does not approve.
- **Not-yet-observed rows** keep the **dashed honesty grammar** M7
  established — the row's value is drawn in `Theme.inputBorder` with the
  same dashed rule the placeholder used, so the surface's existing
  vocabulary ("dashed = not real yet") carries straight through. This is
  why the placeholder is *replaced by three smaller dashed rows* rather
  than deleted: the M8/M12 boundary stays visible exactly where it is.
- **Security events** are the only red on the detail pane (D-005's
  `.evrow`): `<CATEGORY> · <action> · <hh:mm> · <evt_id>`, the category
  word in `Theme.statusBad`. Empty → `Security events · None recorded`
  (D-005's `codexView` renders exactly that), followed by one muted
  footnote: `credential, production-access and policy-bypass events
  arrive with M9 / M12`.
- **Ended and purged sessions** render honestly: an ended session shows
  its final ledger plus `Kept until <date>`; a purged one shows
  `Purged by you · <ts> · the audit trail is separate and was not
  deleted`.

### 8.2 Data path — a new, tighter side file

M7 feeds the panel from world-readable `/run/punar/agents.json`. **A
ledger is personal data and must not be world-readable, and must not be
forgeable.** Decision:

- `agents.json` (0644, `/run/punar`, user-writable dir) gains **only the
  counts fingerprint** (§7) — no identifiers. Any world-readable
  consumer sees "1 security event", never which.
- The panel reads full ledger rows from a **new side file**
  `/run/punar-agentd/ledger.json`, `0640 root:punar`, written atomically
  by agentd at the same points it rewrites `agents.json`. It lives in
  the **root-owned** agentd runtime directory (already `0750 root
  punar`, ipc.md §10.1) rather than in user-writable `/run/punar`, so
  (a) only group `punar` — the same admission set as the agentd socket —
  can read it and (b) unlike `status.json`/`agents.json` a local user
  cannot unlink it and substitute a forgery. `punar-shell` runs as
  `punar` and reads it with the same event-driven `FileView`: no socket
  client in the shell, no polling, no new mechanism.
- Same fail-closed rule as M7: missing or unparsable → the ledger
  section renders `No ledger recorded for this session yet`, never an
  error surface.
- The authoritative view remains the socket (`punarctl agents access`),
  and the side file says so in ipc.md §13.2, verbatim from the §9/§11
  caveat.

### 8.3 The privacy line (spec 24.2 — the user-facing half of M8)

D-005's `.privacy` block becomes real, and gains M8's two new facts:

```text
This ledger stays on this device · No organization is enrolled
Kept 14 days after the session ends · Delete it now: Shift+Del · punarctl privacy purge --session agt_…
```

Enrolled variant keeps D-005's managed wording plus the honest M8 truth:
`Last admin query · None — no remote query path exists until Milestone 10`.

**`Shift+Del` on the focused session purges that session's ledger**, with
a two-step inline confirm (`Press Shift+Del again to confirm · this
deletes the local ledger for agt_… · the audit trail is not deleted`).
It executes the existing one-shot detached-`punarctl` pattern the panel
already uses for refresh — fixed argv, never a shell string:
`punarctl privacy purge --session <id> --yes`. Rationale: spec 1.17
("Do not rely on the terminal for ordinary OS administration") and 1.16
(keyboard operable) mean deleting your own data cannot be CLI-only; the
confirm step and the ghost-red voice (DESIGN_LANGUAGE §"destructive
stays a ghost") keep it from being an accident. A full graphical privacy
panel is still M13; this is one keystroke on the surface that shows the
data.

---

## 9. CLI (Plate D-014; spec 11.2)

### 9.1 `punarctl agents access <id>` — the reserved verb, now real

Terminal parity with the panel (D-014 Sect I register 03 requires the
same data in the same order): masthead `AI ACCESS LEDGER · AGT_…`,
attribution line (`AGT_… · PUNAR · PUNAR-ENV-ATLAS · STARTED 13:44`),
`LEDGER · WHAT IT ACCESSED` rows with counts, the three
`NOT YET OBSERVED · MILESTONE n` rows, `SECURITY EVENTS` in the red
slot, and the privacy/retention footer with the purge command. `--json`
prints the `result` object verbatim (so `result.summary` alone is a
schema-valid `ledger-summary.json` document — that is what `m8-check`
captures and what a future export would ship). Unknown id → exit 1
(`not_found`); another user's session → exit 3 with the section-73
denial.

### 9.2 `punarctl privacy ledger [<id>]`

The privacy-side question, which is not the agent-side question:
**"what has this device recorded about me?"**

```text
PUNAR · PRIVACY — LOCAL AI LEDGER                                   punar-dev

WHAT IS RECORDED           3 sessions · 11 resource classes · 1 security event
  agt_4f21c09ab3e1         claude-code · atlas · ended 14:31 · kept until 2026-09-08
  …

WHAT IS NEVER RECORDED     file paths inside your workspace · prompts · source code
                           secret values · individual file reads          (spec 21.2)

WHERE                      /var/lib/punar/agents/ledger · root-only · never uploaded
RETENTION                  14 days after a session ends, then deleted automatically
DELETE                     punarctl privacy purge --session <id>  ·  --all
REMOTE QUERY               none — no upload path exists (Milestone 10 adds the
                           authorized, audited administrator query)
```

`--json` for scriptability. This is the section 24.2 guarantee made
inspectable: the user reads the same categories an administrator could
ever be shown, plus the list of what the device refuses to collect.

### 9.3 `punarctl privacy purge [--session <id> | --all] [--yes]`

Interactive confirmation unless `--yes` (the `enroll stop --yes`
precedent). Prints what it deleted (`PURGED · 1 SESSION · 11 RESOURCE
CLASSES · 1 EVENT REFERENCE`) and the boundary sentence: `The audit
trail is a separate record and was not deleted · punarctl audit tail`.
Denial → exit 3, section-73 voice. Nothing found → exit 1.

### 9.4 `punarctl privacy connections` — reserved honestly

The verb is in spec 11.2 and a user who discovers the `privacy` noun
will type it. It prints the section-73 notice — "Local network
observability arrives in Milestone 12 (punar-netd). Next step: punarctl
privacy ledger" — and exits 1. Named in the help text as reserved, never
silently missing.

---

## 10. The privacy guarantee, written down (spec 24.2)

1. **You can always see what this device recorded about your agent
   sessions** — `punarctl privacy ledger`, `punarctl agents access
   <id>`, and the PUNAR+A panel, all rendering the same record.
2. **You can always delete it** — `punarctl privacy purge` or `Shift+Del`
   in the panel. Purge of your own sessions is **allowed
   unconditionally** for the owning user in M8: no policy, org or
   otherwise, can withhold it, because in M8 no org can read the data
   either. (Authz rule, verbatim: `peer.uid == session.owner_uid ||
   peer.uid == 0`; `--all` scopes to the caller's own sessions; only
   root may purge another user's ledger.)
3. **Deletion is real and durable** — the file is unlinked and the index
   row is replaced by a tombstone `{session_id, purged_at}` that floors
   audit re-ingestion (§4.4), so a later drain cannot resurrect what you
   deleted. The tombstone itself carries no resource data.
4. **The audit trail is not the ledger, and purge does not touch it.**
   Spec 53's audit log is the tamper-evident record of *decisions the
   system made* — denials, mutations, enrollment — and it is deliberately
   outside a user's delete authority. Every purge surface says this in
   one sentence. The ledger, which is *derived* from it plus the cgroup,
   is yours.
5. **Nothing leaves the device in M8** — agentd has no network surface
   at all (`RestrictAddressFamilies=AF_UNIX`), there is no export method,
   and `LAST ADMIN QUERY · NONE` is a statement about a path that does
   not exist yet, not about a path nobody used.
6. **You never see less than an administrator would** — the exported
   projection (`result.summary`) *is* the schema document M10's
   authorized query will one day return, and it is the same document
   `punarctl agents access --json` hands you today.

---

## 11. Budgets (spec 6.2–6.4, PERFORMANCE_BUDGETS.md)

- **CPU:** zero at idle by construction — one blocking inotify reader,
  no timers, all other work on user action. A sampling pass costs one
  `cgroup.procs` read plus two small `/proc` reads per pid per active
  session.
- **RAM:** active-session aggregates only, each bounded by §5.3 (≤ 6 × 32
  entries + ≤ 256 refs + the pid dedup set); ended records live on disk.
  The combined `punard + punar-agentd` RSS gate (M7 §11) remains the
  arbiter; target < 100 MB combined, MVP ceiling 150 MB, unchanged.
- **Disk:** < 4 MiB for the whole ledger directory; batched writes; one
  `fsync` per batch per session; **0 B/s at idle**. PERFORMANCE_BUDGETS.md
  §2 gains a ledger row stating exactly these numbers.
- **Audit growth:** M8 adds `ledger.purge` and `ledger.prune` events
  (rare, user- or lifecycle-triggered) and attributes existing punard
  events — it does not add an event class per access. Spec 6.4's
  "do not log every filesystem read" is satisfied by having no
  filesystem read events at all.

---

## 12. In-VM exercise plan — `m8-check`

Assertion style is governed by
[checks-conventions.md](checks-conventions.md): assert the invariant that
survives fulfilment, never the placeholder text. Three of this exercise's
assertions were pinned to M8's own `not_yet_observed` snapshot and to the
`MILESTONE 10` deferral sentence, and M10 correctly deleted both — the
fourth, fifth and sixth occurrences of that class. They are now written as
biconditionals over a probe of the running device.

`/usr/lib/punar/m8-check.sh`, root oneshot (`punar-m8-check.service`,
**never enabled** — the standing pattern), started synchronously by
`idle-ram.sh` **after m7-check**; `set -u`, always exits 0; verdict lines
in `/run/punar/m8-report.txt`, final `PUNAR_M8_OK` / `PUNAR_M8_FAIL`;
host gate `boot-test.sh` **phase 10**. Unprivileged commands use the M7
session pattern, and the managed launch is started **by the user
manager** as a transient `--user` service (the M7 cgroup-delegation hard
lesson — a scope migration from `system.slice` would be refused). All
verdict greps are case-insensitive (`fmt::verdict` uppercases). Image
facts that shape the plan: **no diffutils** (use `sha256sum`), **no
python/socat/nc**, `jq` **is** present, and the installed process-class
evidence available is `git`, `sh`/`bash`, `punarctl` — **node and cargo
are not in the image and will not be faked**.

**Deterministic evidence generation inside the scope.** The M7 mock
agent (`/usr/lib/punar/punar-mock-agent`) gains one opt-in behavior,
`PUNAR_MOCK_AGENT_CHILDREN=1` (unset by default; the check sets it),
which spawns a fixed child sequence in its own cgroup before blocking:

1. `mkfifo -m 600 .punar-agent-fifo` in its working directory;
2. `sleep infinity > fifo &` — a writer that never writes and never
   exits, so the readers below can open the fifo and then block in
   `read` forever (opening a fifo for reading blocks until a writer
   opens it; both sides are backgrounded so the kernel pairs them).
   `sleep infinity` is a blocking sleep, not a polling loop (§6.3);
3. `/bin/sh < fifo &` → **blocks in `read`** → class `shell`;
4. `git hash-object --stdin-paths < fifo &` → **blocks in `read`** →
   class `git`. Verified on the host: this invocation runs and blocks
   **outside** a git repository with no error output — no repository is
   created, and `.git/config` is never read;
5. `punarctl capabilities set security.firewall enabled` — a **real,
   short-lived** child that punard **denies** (`authorize_mutation`:
   uid ≠ 0 → deny), producing the Level-4 evidence;
6. `trap`/`wait` as today.

Children 3 and 4 are the classes the image can actually supply; **node
and cargo are not installed and are not faked** (§12 preamble). If
`/bin/sh` resolves through a symlink the kernel may report `comm=bash`
— both spellings map to class `shell` in the class table (§3.2), so the
assertion is on the *class*, never on `comm`.

Children 2 and 3 stay alive across the sampling pass (process-class
evidence, source A); child 4 is gone by then and is proven only by the
audit stream (source B) — the check therefore demonstrates that the two
evidence paths are genuinely independent.

**Assertion groups (target ≈ 40 assertions):**

1. **Preflight** — `punar-agentd` active; `/var/lib/punar/agents/ledger`
   exists `0700 root:root`; `/usr/share/punar/agents/process-classes.json`
   parses and maps `git`→`git`, `sh`→`shell`.
2. **Managed launch** with `PUNAR_AGENT_MOCK=1 PUNAR_MOCK_AGENT_CHILDREN=1`
   under `systemd-run --user --pipe --wait --collect`; session id
   captured; classification `managed`.
3. **Scope children (source A)** — the scope's `cgroup.procs` lists ≥ 3
   pids; their `comm` values include a shell (`sh` **or** `bash`) and
   `git`; `pids.peak` ≥ 3.
4. **Sample** — `punarctl agents scan` succeeds.
5. **`agents.access` shape** — `punarctl agents access <id> --json`
   parses; `result.summary` has the four required keys, `resources` has
   all six required arrays, every `security_events[]` item has
   `event_id` matching `^evt_` and `event_type` in the seven-value enum
   (jq-side structural validation — the in-VM stand-in for a real
   validator; the *real* JSON-Schema check runs on the host, see below).
6. **Level-3 content** — `process_classes` contains `git` **and**
   `shell`; `directory_zones == ["workspace"]`; `repositories ==
   ["atlas"]`; `network_destinations`, `mcp_servers` and
   `credential_classes` are **empty** and `not_yet_observed[]` names
   them with milestones `M12`, `M9+`, `M9`; `detail` entries carry
   `count ≥ 1`, `first_seen ≤ last_seen`, and `evidence` values drawn
   only from `{cgroup_scope, audit_event, workspace_bind, adapter_metadata}`.
7. **Level-4 denial join (source B)** — the audit line for
   `capabilities.set` has `decision: "deny"`, `source: "ai_agent"`, and
   `agent_session_id == <the real agt_ id>`; **its `event_id` appears
   verbatim** in `result.summary.security_events[]` with
   `event_type: "denied_access"`. The `evt_` id is the join key and the
   assertion compares the two files' values directly.
8. **Privacy regression (the important one)** — across
   `/var/lib/punar/agents/ledger/*.json`, `index.json`,
   `/run/punar-agentd/ledger.json` and `/run/punar/agents.json`:
   - the workspace path string `/home/punar/atlas` appears **0** times;
   - `.punar-agent-touch`, `hash-object`, `stdin-paths`, `--version`,
     `security.firewall`, `capabilities.set` appear **0** times
     (argv tokens and audit payload must not leak into the ledger);
   - `jq` walk asserts **no string value anywhere in `resources.*` or
     `entries[].resource_class` contains `/`, `:` or whitespace**;
   - the keys `cmdline`, `argv`, `prompt`, `comm`, `cwd`, `path`,
     `executable` appear **0** times in any ledger file.
9. **`privacy ledger` renders** — masthead, the session row, `14 DAYS`,
   the never-recorded list, the purge command; `--json` parses.
10. **Fingerprint** — `punarctl agents list --json` carries
    `sessions[].ledger` whose values are only numbers plus one
    timestamp (jq type assertion), and contains **no** class names or
    `evt_` ids.
11. **Panel** — open via `qs -p /usr/share/punar/shell ipc call aipanel
    open`, settle, `grim /run/punar/punar-m8.png`; assert non-empty;
    assert `/run/punar-agentd/ledger.json` exists `0640 root:punar` and
    names the session. (Screenshot failure is a noted `FAIL` line, the
    m2 precedent.)
12. **Session end** — stop the scope; `agents list` shows `ended`; the
    ledger file gains `ended_at` + `retention_expires_at` ≈ ended + 14 d
    (date arithmetic asserted to the day).
13. **Purge as owner** — as `punar`: `punarctl privacy purge --session
    <id> --yes` → exit 0; the session file is gone; `index.json` carries
    `purged_at`; the audit log has `ledger.purge` with `decision:
    "allow"`, `result: "purged"` and the real `agt_` id.
14. **No resurrection** — `punarctl agents scan` (drains audit) → the
    purged session's file does **not** reappear; `agents access <id>`
    renders `PURGED` rather than data or a bare not-found.
15. **Retention prune** — write a synthetic ended-session ledger with
    `retention_expires_at` backdated 30 days (root, via the check) plus
    its index row; `punarctl agents scan` → file deleted, index row
    gone, audit has `ledger.prune` `result: "expired"`.
16. **Negative probes** — `agents.access` on an unknown id →
    `not_found`; `ledger.purge` with no scope → `invalid_params`;
    `debug rpc ledger.bogus --socket agentd` → `unknown_method`;
    `debug rpc ledger.export --socket agentd` → `unknown_method` (no
    export path exists); as `nobody`, `punarctl agents access` → refused
    by socket admission.
17. **Cross-user denial — stated gap, not implied coverage.** The image
    has no second interactive user and no tool to forge peer creds, so
    "user B may not read/purge user A's ledger" is proven by
    `punar-agentd`'s host integration tests (fixed-`Peer` harness), not
    in-VM. The report prints this as an `info` line — the M7 precedent
    for honest gaps.

**Host-side (CI, not in-VM):** `tools/validate-schemas.sh` validates a
**recorded** copy of the mock session's summary, added as
`fixtures/ai-agent/valid/ledger-summary.m8-mock-session.json`, against
the unchanged `ledger-summary.json` — a real JSON-Schema check of the
exact document shape the daemon produces, complementing group 5's jq
structural check inside the VM.

One invalid fixture is added —
`fixtures/ai-agent/invalid/ledger-summary.m8-count-in-resources.json`
(an object where the schema requires a string) — because the schema does
reject it. **A `/`-bearing `repositories` value is deliberately NOT added
as an invalid fixture: the shipped `repositories` items carry no
pattern, so the schema would accept it.** That hole is closed one level
down, by the `ResourceClass` newtype (§2), and is therefore pinned by a
`punar-agentd` **unit test** (`ResourceClass::repository("/home/punar/atlas")`
returns `Err`) plus `m8-check` group 8's runtime grep. Saying which
layer catches what is the point; implying the schema catches something
it does not would be exactly the dishonesty spec 1.22 forbids.

**Exports** (swept by the existing tar): `m8-report.txt`,
`m8-access.json`, `m8-ledger-file.json`, `m8-index.json`,
`m8-privacy.txt`, `m8-agents-list.json`, `m8-audit-denial.json`,
`m8-purge.txt`, `punar-m8.png`.

**Chain:** `idle-ram.sh` gains `m8-check` after `m7-check`; `boot-test.sh`
gains phase 10; `ci.yml` artifact sweep picks the new files up by the
existing glob. The in-VM assertion chain it extends **measured 282** in
run [32868450695](https://github.com/smplify-mdm/punar/actions/runs/32868450695)
(M2 33 + M3 28 + M4 29 + M5 63 + M6 55 + M7 74). This section's original
estimate — "grows from 209 to ≈ 250" — was written against the pre-M7
baseline and is superseded by that measurement and by §14.3's static
count of what M8 adds. The real M8 number is whatever a run emits, and
no run has emitted one.

---

## 13. Deferred, tracked

- **Network destinations** — M12 (`punar-netd`); the ledger row is
  already drawn and labeled, and the ingestion path (source B, or a
  per-session aggregate from netd) needs no new ledger concepts.
- **MCP servers and tools** — M9+ (AI Agent Gateway, spec 26).
- **Credential classes** — M9 (`punar-secrets`); arrives with zero
  ledger code changes once `credential.request` events carry
  `agent_session_id` (§3.1, §4.2).
- **`policy_bypass_attempt`, `production_access`,
  `sensitive_resource_access`** — M9/M12 producers.
- **A ledger for unknown/unmanaged agents** — M10 (detections are not
  persisted, M7 §4.4).
- **The authorized administrator query + its audit** — M10 (spec 24.1);
  `result.summary` is deliberately already the exportable document.
- **Configurable / org-governed retention** — M10+ (§6.4).
- **Graphical privacy panel** — M13; M8 ships the panel's ledger
  section, the privacy line and one purge keystroke.
- **Spawn-accurate process history** — would require exactly the broad
  tracing spec 1.14 forbids; the honest substitute (sampled classes +
  `pids.peak`) is documented as such on every surface.

---

## 14. Verification status (spec 1.22)

This section was written as a design plan and is updated here as the
milestone was built. **The distinction that matters: every host-side gate
below has actually been run and is green; the in-VM exercise has NOT been
run and nothing about its outcome is claimed.**

### 14.1 What exists

| Piece | State |
|---|---|
| `punar-common::ledger`, `punar-agentd::ledger` (engine, store, tail, classes) | built, unit + integration tested |
| `punarctl agents access`, `privacy ledger`, `privacy purge`, `privacy connections` | built, tested |
| `AiPanel.qml` D-005 ledger register + `Services/Ledger.qml` | built, qmllint clean |
| `punard` section-12.5 attribution rule | built, unit + integration tested |
| `crates/punar-agentd/data/process-classes.json` + image staging | built, staged, schema-manifest mapped |
| tmpfiles line for `/var/lib/punar/agents/ledger` | shipped |
| `punar-mock-agent` opt-in child generation | shipped, shellcheck clean |
| `m8-check.sh` + `punar-m8-check.service` + `idle-ram.sh` hook | shipped, shellcheck clean, never run in a VM |
| `boot-test.sh` phase 10, `ci.yml` artifacts | shipped, actionlint clean |

### 14.2 Gates actually run (2026-08-25)

- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
  --locked -- -D warnings`, `cargo test --workspace --locked` in the
  pinned `docker rust:1` container — **all green**.
- `shellcheck v0.11.0` over the full CI script list including
  `m8-check.sh` and `punar-mock-agent` — **clean**.
- `actionlint` over `.github/workflows` — **clean**.
- `./tools/validate-schemas.sh` — **15 schemas, 127 documents, all
  pass**, including the two fixtures M8 adds.
- `PUNAR_BUILD_MODE=summary ./tools/build-image.sh` — **complete**; the
  desktop staging step ran and the staged
  `process-classes.json` is byte-identical (`sha256sum`) to the crate
  file the daemon compiles in.
- `qmllint` 6.11.2 in the pinned container over all 10 `.qml` files —
  **exit 0**.

### 14.3 What is NOT verified

- **The in-VM exercise has never executed.** `m8-check.sh` is
  ~119 assertion lines of *intent*. No `PUNAR_M8_OK` has been produced,
  no screenshot has been taken, and no claim above depends on one. The
  only real arbiter is a `desktop-test` run.
- **M7's CI outcome is now known, and it is green** — that was still open
  when this plan was written. Run
  [32868450695](https://github.com/smplify-mdm/punar/actions/runs/32868450695)
  (2026-08-25, commit `f95c9c4`) is fully green on all five jobs with
  `PUNAR_M7_OK` (74 assertions); the M7 tree's own push, run
  [32865062323](https://github.com/smplify-mdm/punar/actions/runs/32865062323)
  at commit `a2b2ce5`, was red on one stale **m6**-check assertion (it
  still expected the M7-era `punar-env agent` stub's "Failed to find
  executable claude" stderr, which the real managed launch removed) —
  no M7 code was implicated. This does not soften anything below: M8's
  own exercise has still never run, and the M8 design decision it
  motivated stands unchanged — the M8 exercise re-establishes its own
  preconditions (it re-creates the Atlas project from the staged fixture
  if absent, the M7 precedent), so a future M7 regression cannot pass as
  an M8 success.
- **Cross-user denial is not proven in-VM** and the report says so in an
  `info` line: the image has one interactive user and no tool to forge
  peer credentials. It is proven by `punar-agentd`'s host integration
  tests.
- The in-VM chain M8 extends is no longer an estimate: it **measured 282
  assertions** through M7 in run 32868450695 (33 + 28 + 29 + 63 + 55 +
  74). M8 adds **~111 static assertion sites** in `m8-check.sh` — 70
  calls to the `check_eq`/`check_true`/`check_ge`/`jq_check`/
  `jq_slurp_check`/`grep_row`/`absent_from` helpers plus 41 inline
  `ok`/`FAIL` verdict lines — before `absent_from`'s per-argument
  expansion, across 17 assertion groups. The real number is whatever a
  run emits, and that run has not happened.

### 14.4 Independent re-run by the status audit (2026-08-25)

§14.2 records the build's own gate runs. The status audit re-ran the
host-side gates it could reproduce from a clean invocation, against the
same working tree, and reports the numbers it actually saw:

| Gate | Result |
|---|---|
| `cargo fmt --all --check` (`docker rust:1`) | exit 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | exit 0 |
| `cargo test --workspace --locked` | **534 passed, 0 failed** across 27 test binaries (M7's audit measured 458; M8 adds 76) |
| `./tools/validate-schemas.sh` | **15 schemas metaschema-checked, 127 documents, ALL PASS** (125 at M7; M8's two fixtures are the delta) |
| `shellcheck v0.11.0` (pinned `koalaman/shellcheck:v0.11.0`, the full CI script list incl. `m8-check.sh` and `punar-mock-agent`) | exit 0, zero findings |
| `actionlint` over `.github/workflows` | clean |

Recorded in §14.2 and **not** re-run by this audit: `qmllint` 6.11.2 over
all 10 `.qml` files, and `PUNAR_BUILD_MODE=summary ./tools/build-image.sh`
with its `sha256sum` equality check on the staged
`process-classes.json`. Neither is a runtime proof, and neither changes
§14.3: **no `PUNAR_M8_OK` exists anywhere.**

### 14.5 One deviation from the plan, stated

The plan's host-side fixture was to be *"a **recorded** copy of the mock
session's summary"*. Nothing has been recorded, so recording one would be
a fabrication. `fixtures/ai-agent/valid/ledger-summary.m8-daemon-projection.json`
is instead the **daemon's own serializer output** — `LedgerRecord::summary()`
run over a representative managed session — and its filename says exactly
that. It is a real JSON-Schema check of the document shape the daemon
produces; it is not evidence that a VM produced it. The invalid fixture
`ledger-summary.m8-count-in-resources.json` is added as planned and is
rejected by the shipped schema for the stated reason. As the plan
insisted, a `/`-bearing `repositories` value is **not** added as an
invalid fixture, because the shipped `repositories` items carry no
pattern and the schema would accept it: that hole is closed one level
down by the `ResourceClass` newtype and by `m8-check` group 8's runtime
grep.
