# Milestone 10 — Shadow AI detection MVP: design plan

Spec authority: section 76 Milestone 10 ("Deliver known/observed/unknown
classification, fixture unknown agent, local alert, and Smplify remote
query"), grounded in section 23 (shadow AI / shadow IT visibility —
"Do not claim perfect detection"; *eliminate the blind spot*, never
*guarantee no shadow AI can exist*), 19.1 (the three classifications),
24 (local-first AI privacy model), **24.1** (remote-query rules — the
endpoint evaluates, RBAC applies, the query is audited, "administrators
cannot silently retrieve data outside allowed scope"), **24.2** (the
employee never has less visibility than the administrator), 21.1/21.2
(access categories, the four observation levels, and the never-record
list), 51 (Smplify remote AI queries — the nine things an admin may
ask), **51.1** (query audit — requesting admin, scope, device,
timestamp, result category, authorization decision), 72 (enterprise AI
fleet view — "This view must derive from policy-controlled endpoint
data"), 12.1 (notifications are a required keyboard-operable area), 73
(security and privacy UX principle — what happened, why, who requested
it, which policy, whether the user can change it, what the next step
is), 59.2 (unmanaged AI mitigations: detection, local registry, Smplify
query), 59.4 (compromised control plane), 6.3 (idle CPU — "Continuous
high-frequency polling is prohibited. Prefer event-driven observation"),
6.4 (batch disk I/O), 1.14 (no broad tracing where aggregation or scoped
primitives suffice), 1.22 (honesty), 53 (audit), 61 (local IPC
security), 74.4 (security tests).

Binding prior contracts, **not relitigated**:

- `docs/api/ipc.md` §1–§16 — transport, framing, envelope, error codes,
  the punard / agentd / punar-secrets method tables, the `agents.json`
  and `ledger.json` side contracts, the M8 attribution rule §12.5. M10
  adds §17–§20 **additively, still `v: 1`**. **This document does not
  edit `ipc.md`** — §13 below is the proposed contract text that M10's
  implementation lands there.
- `schemas/ai-agent/registry-record.json`, `schemas/ai-agent/ledger-summary.json`,
  `schemas/audit/audit-event.json` — **SHIPPED. M10 conforms to them;
  they do not conform to M10.** The M8 Decision-0 law and the M9
  restatement of it hold for a third milestone: anything M10 needs that
  a shipped schema cannot hold travels as a **sibling field of the IPC
  result** or in a **separate local record**, never as a new property.
- `docs/development/milestone-5.md` — `punar-mock-smplify` (never
  enabled, UDS + NDJSON, fixtures served verbatim, `admin.devices` /
  `admin.device` **reserved by name for M10**), the enrollment chain,
  `enrollment.json`, and the **reconcile-piggybacked sync** with no new
  timers.
- `docs/development/milestone-7.md` — the registry, managed launch,
  scope attribution, adapters-and-signatures **as data**, the on-demand
  `/proc` pass with the 30 s staleness rule, `/run/punar/agents.json`,
  the AI panel (Plate D-005), and the explicit deferral: *"periodic
  detection is M10's deliverable by name."*
- `docs/development/milestone-8.md` — the ledger engine, the
  category→source map, retention/purge, the privacy guarantee, and the
  open question this milestone is required to close: *"detections have
  no persisted session (M7 §4.4), so unknown agents have no ledger in
  M8; **M10** owns the unknown-agent ledger."*
- `docs/development/milestone-9.md` — the approval overlay, and the
  **root-owned summary-file lesson**: a file that tells a human what to
  believe must not live in user-writable `/run/punar`.
- `docs/design/mockups/notifications-osd.html` (**Plate D-009 — the
  acceptance reference for the alert**; the `foo-agent` row in Sect II
  register 02 is drawn already, behind a dashed `SIMULATED` tag whose
  removal is this milestone), `docs/design/mockups/ai-panel.html`
  (Plate D-005), `docs/design/mockups/cli-grammar.html` (Plate D-014,
  whose ledger note already promises *"admin queries are scoped,
  audited, visible here"*), `docs/design/DESIGN_LANGUAGE.md` §8
  (unmanaged-first).
- `fixtures/agents/unknown-agent/` — `foo-agent.json`,
  `registry-record.json` (`agt_999`, `classification: "unknown"`,
  `status: "active"`, `version: "unknown"`, `environment: "host"`) and
  `ledger-summary.json` (`agt_999`, one `unknown_ai_execution` event).
  **These fixtures have described a persisted, ledgered unknown agent
  since M7.** §6 makes them true instead of aspirational.

M7 made classification real when someone looked. M8 made "what did it
access" real for sessions Punar itself launched, and wrote down what it
could not yet say. M9 made a human the only thing that can approve.
M10 closes the loop the product promise depends on: **the device
notices on its own, tells the user first, remembers exactly enough, and
answers an administrator only within a scope the user can read back.**

---

## 0. The architectural laws of this milestone

Four sentences, each of which decides several questions below.

1. **Punar is not a server.** Nothing in M10 opens an inbound socket,
   port, or listener of any kind, for the control plane or anyone else.
   A remote query reaches this device only because *this device went and
   fetched it* on a schedule it already owned (§7).
2. **The transport is not the authority.** `punard` carries queries and
   answers; `punar-agentd` decides what may be answered. The daemon
   holding the data re-evaluates authorization from **local** state and
   never from the request (spec 59.4 — compromised control plane).
3. **The user learns first, and can always read the record.** Every
   remote query is written to a local log the user can print with one
   command, and the answer's *content* is never larger than what the
   same user can already print about themselves (spec 24.2).
4. **Suspected, never certain, and never armed.** M10 detects, records,
   and alerts. It blocks nothing, kills nothing, and quarantines
   nothing. Blocking an unmanaged agent needs `punar-netd` (M12) and a
   policy verb; a red card that cannot act is honest, a red card that
   silently acts is not (spec 23, 1.22).

---

## 1. Scope

**In:** periodic detection as a low-frequency systemd timer, with
event-driven immediate triggers (§3); a stable **detection identity**
and the set-diff that makes a scan produce **events, not repetition**
(§4); one new detection input — executable path provenance, data-driven
(§3.5); the **local alert** — anti-nag rule, root-owned state file, a
minimal D-009 alert surface in `punar-shell`, dismissal, and the
do-not-disturb breakthrough rule (§5); **persisted detection records and
bounded unknown-agent ledgers**, closing M8's open question (§6); the
**remote query** — mock admin surface (`admin.devices`, `admin.device`,
`admin.ai_query`, `admin.query_result`, `admin.fleet`), the device-pull
mechanism on the existing sync piggyback, and the three-way scope
intersection (§7–§9); the **query audit** and `punarctl privacy queries`
(§10); the structural inertness of the whole path on a personal device
(§11); the mock's honest fleet aggregation (§12); the proposed IPC
contract for `ipc.md` §17–§20 (§13); CLI (§14); budgets (§15);
`m10-check` + boot-test **phase 12** + `punar-m10.png` (§16).

**Out (documented, never silently dropped):** every item in §17's scope
table, chief among them — real cloud and real transport; real RBAC/IdP;
any cross-device fleet **UI** beyond the mock binary's text output;
behavioural risk scoring (Phase 3); blocking, killing or quarantining an
unmanaged agent (M12 + a policy verb); network destinations and MCP
activity as detection inputs or as ledger rows for unknowns (M12, M9+);
the full notification centre, the freedesktop notification daemon, the
OSD and a persistent DND toggle (M13 — §5.6 ships only the sliver M10
needs and says so); org-governed retention override; and every tracing
mechanism spec 1.14 forbids, which is **permanently out**, not deferred.

---

## 2. Decision summary

| # | Decision |
|---|---|
| 1 | **Periodic detection is a timer, not a loop.** `punar-agentd-scan.timer` → oneshot `punar-agentd-scan.service` = `/usr/bin/punarctl agents scan --trigger timer`, root, through the normal socket/authz/audit path — the `punard-reconcile.timer` shape verbatim (M4 §5). `OnBootSec=240`, `OnUnitActiveSec=240`, `AccuracySec=30`, vendor-wants symlink only. §3. |
| 2 | **240 s, argued.** Twice the accepted 120 s reconcile cadence and an exact multiple of it, so systemd **coalesces** the two wakeups and M10 adds no new wakeup instant in the steady state. Worst-case time-to-first-sighting is 240 s + 30 s accuracy, stated on the surface. M7's 30 s staleness rule stays, so a human who looks still gets a ≤ 30 s view. §3.2. |
| 3 | **Immediate scans are event-driven, and there are exactly three:** a successful `agents.register`, a session end/reap, and an **enrollment transition** (`enroll.start` / `enroll.stop` completing). The last one opens a `punard → punar-agentd` client — an edge M7 declined to add for a capability it did not claim, and which M10 needs anyway for §7. It is a DAG edge, not a cycle: agentd never calls punard. §3.3. |
| 4 | **A scan diff is an event; a scan is not.** The pass compares the detection **set** against the previous set and emits `detected` / `cleared` **once per detection identity**. A pass that changes nothing writes **nothing** — no `agents.json` rewrite, no audit line, no disk I/O (spec 6.4). `scanned_at` in `agents.json` therefore means *as of the last change*; the live heartbeat stays in memory and is served by `agents.list`, because the socket is the authority and the file is a change log. §3.4, §4.3. |
| 5 | **Two identities, deliberately.** `detection_id` (`agt_` + 12 hex of a hash over exe-realpath, owner uid, boot id, pid, process start ticks) identifies one *running process* and is stable across scans; `signature_id` (hash over exe-realpath + owner uid) identifies *what was seen* and is the **alert** identity. Anti-nag binds to `signature_id`, persistence binds to `detection_id`. §4. |
| 6 | **One alert per `signature_id`, not per scan, not per process.** An alert is raised on first sighting of a signature; it is suppressed while any live detection of that signature exists **and for 24 h after the last one clears**. A crash-looping agent yields one alert a day; a genuinely new appearance next week yields a fresh one. §5.2. |
| 7 | **The alert state file is root-owned:** `/run/punar-agentd/alerts.json`, `0640 root:punar`, atomic write on change only — the M9 lesson applied. A forged "unknown AI suspected" card is a phishing primitive; `/run/punar` is user-writable and therefore disqualified. The shell watches it with a `FileView` (`Services/Alerts.qml`) — inotify, event-driven, no socket client, no polling. §5.3. |
| 8 | **The first sighting breaks through do-not-disturb; nothing else does.** The decisive argument is spec 24.2, not taste: in M10 an administrator can *query* this exact fact, so a quiet-mode toggle that could hide it would let an admin learn about a process on the user's machine before the user does. Bounded by decision 6 — at most one breakthrough per signature per 24 h — which is precisely what makes it affordable. Under DND it renders **without sound and without focus steal** and does not auto-dismiss. §5.5. |
| 9 | **Yes — detections get a persisted record and a ledger.** M8's open question is closed in the affirmative: `/var/lib/punar/agents/detections.jsonl` holds schema-exact `registry-record.json` documents (`classification: "unknown"`), and each gets a `ledger-summary.json`-conformant record. This is what `fixtures/agents/unknown-agent/` has described since M7. §6. |
| 10 | **The unknown ledger is strictly SMALLER than a managed one, by construction.** No child-process walk, no `cwd` read, no cmdline, no network (nothing observes it before M12). It contains: the executable's **process class**, a **zone class** for where the executable lives, and the Level-4 `unknown_ai_execution` event *references*. Everything else is `not_yet_observed[]`. The never-record list (21.2) applies to unknowns **identically** — it is not relaxed because the process is suspicious. §6.3. |
| 11 | **Detection retention is 7 days after the detection clears** — half M8's 14-day managed window — and `punarctl privacy purge` deletes it unconditionally for the owning user. The `unknown_ai_execution` **audit** event survives purge, exactly as M8 guarantee 4 already says: purge removes the derived summary, never the decision record. §6.5. |
| 12 | **The device PULLS pending admin queries; nothing pushes to it.** Queries ride the M5 sync piggyback at the end of every reconcile pass **when enrolled** — one extra request pair, no new timer, no listener, no inbound path. The administrator's client is the thing that waits (`admin.query_result` polls the mock). Answer latency is therefore ≤ one reconcile period (~120 s) plus the mock round trip, and every surface states it. §7.2. |
| 13 | **punard is the only control-plane client; punar-agentd is the only data owner.** punard fetches the pending query and hands it to agentd as `query.answer` (root-only peer). agentd authorizes, projects, records, and returns the payload; punard posts it back verbatim. The transport never assembles an answer and never sees data it was not handed. §7.3. |
| 14 | **Scope is a closed enum of four values, one per spec 21.2 level:** `inventory`, `authority`, `resource_summary`, `security_events`. There is no wildcard, no free text, and no "all". An unrecognised value is refused as `out_of_scope`, never answered best-effort. §8.1. |
| 15 | **Authorization is a three-way intersection evaluated by the data owner:** `requested ∩ org_granted ∩ device_builtin_max`. `org_granted` is read by agentd **from `/var/lib/punar/enrollment.json` itself** (root-owned), never from the request. Absent grant ⇒ empty set ⇒ **fail closed**, with a section-73 refusal naming the missing grant. §9.2. |
| 16 | **The mock enforces RBAC too — and the device does not trust it.** `fixtures/organizations/acme/admins.json` maps admin identities to roles (`helpdesk` → inventory; `fleet_viewer` → inventory + authority; `security_admin` → all four), checked before a query is enqueued. Defence in depth: two independent checks, and the device's is the one that decides (spec 59.4). §9.1. |
| 17 | **The refusal list is closed and structural**: prompts, source code, file contents, file paths, cmdlines/argv/environment, secret values, pids and cgroup paths, process trees, audit payloads, and anything outside the granted scope. Most are refused because **no field exists anywhere to carry them** (the M8 schema-as-privacy-model), not because a filter drops them. §8.3. |
| 18 | **Every query — answered or refused — is recorded locally in `/var/lib/punar/agents/queries.jsonl`** with the six spec-51.1 fields plus the granted scope and result counts. **The answered payload is not stored**: one exported copy is enough to protect, and the content is reproducible from the ledger. §10.1. |
| 19 | **The user's command is `punarctl privacy queries`.** It prints who asked, when, for what, what was decided and what category came back — readable by any peer admitted to the agentd socket, because withholding it from the user would violate 24.2. The M8 privacy footer's `REMOTE QUERY none — (Milestone 10 adds…)` line becomes live. §10.3. |
| 20 | **On a personal device the query path is inert through three independent, each-sufficient gates**, not through a hidden UI: (a) the sync hook that pulls queries only runs when enrolled — M5's existing gate, already proven by `m5-check`; (b) agentd's scope intersection reads `enrollment.json`, and no file means the empty set; (c) no inbound path exists at all, so there is nothing to reach even with a valid admin token. §11. |
| 21 | **The fleet view is text output from the mock binary, and its honest boundary is that `0` and `not answered` render differently.** The mock may aggregate only what it legitimately received; a device that never answered at a scope prints `—`, never `0`. Section 72's "0 production credentials" is a *claim*, and a claim needs an answer behind it. §12. |
| 22 | **One new detection input, and only one: executable path provenance**, expressed as data in the existing `suspected.json`. A match requires **both** an unmanaged path prefix (`~/Downloads`, `/tmp`, `~/.local/bin`) **and** an agent-like name token — never either alone, so downloading a binary does not make you a suspect. §3.5. |
| 23 | **`m10-check`**, root oneshot after `m9-check`, boot-test **phase 12**, `punar-m10.png`. The timer assertion is split: the **shipping unit** is asserted (symlink, `Wants=`, `OnUnitActiveSec=240s`, next elapse in the future) and the **real fire** is waited for with a 300 s budget absorbed behind the other groups — no drop-in doctoring the cadence, no manual `agents scan` anywhere in that window. §16. |

---

## 3. Periodic detection (spec 76 M10, 6.3, 23)

### 3.1 The unit, in the established shape

M7 shipped detection with no trigger of its own and said why: periodic
detection is M10's deliverable by name. M10 adds it in the only shape
this repo permits (§6.3 forbids polling loops; M4 §5 already litigated
timer-vs-daemon-thread and chose the timer):

```
# usr/lib/systemd/system/punar-agentd-scan.timer
[Unit]
Description=Punar periodic shadow-AI detection pass
[Timer]
OnBootSec=240
OnUnitActiveSec=240
AccuracySec=30
[Install]
WantedBy=timers.target
```

```
# usr/lib/systemd/system/punar-agentd-scan.service
[Unit]
Description=Punar shadow-AI detection pass (oneshot)
After=punar-agentd.service
[Service]
Type=oneshot
ExecStart=/usr/bin/punarctl agents scan --trigger timer
```

Wiring, per the standing hard lesson: the arming link is a **vendor
`.wants` symlink** at
`usr/lib/systemd/system/timers.target.wants/punar-agentd-scan.timer`,
and checks assert **the symlink plus `Wants=` in `systemctl show`** —
never `is-enabled` (M1's mkosi `/etc`-preset lesson; M4 §5's precedent
unit).

**The pass runs through `punarctl`, not inside agentd.** Rationale,
inherited from M4 §5: the timer path is then the *same* socket, authz
and audit path a human uses, so there is exactly one code path to
verify, and the daemon gains no internal clock. Cost is one transient
process every four minutes; §15 measures it.

### 3.2 Cadence: 240 s, and the argument for it

Three constraints have to be satisfied at once.

**Against spec 6.3.** The prohibition is on *continuous high-frequency
polling*; a low-frequency timer is the section's own preferred shape
(M4 §5 settled this for 120 s and CI has measured it since). 240 s is
an exact multiple of the already-shipping `punard-reconcile.timer`
period, and with `AccuracySec=30` systemd **coalesces** the two into the
same wakeup. The honest claim is therefore stronger than "a second
low-frequency timer": in the steady state M10 adds **no new wakeup
instant at all**, only a slightly longer one every other reconcile tick.
The idle-RAM window (600 s stabilize + 300 s sampling) already contains
~7 reconcile fires today; it will contain ~3 scan fires, at half the
frequency of something the budget gates have accepted and measured since
M4. The timer is deliberately **not** stopped for the sampling window:
budgets must be measured against the shipping configuration.

**Against how fast a shadow agent matters.** It does not matter in
seconds, because M10 is not armed (law 4): the alert informs, it does
not intervene. What the cadence must beat is (a) human patience — a user
who installs something odd should hear about it in single-digit minutes,
not next login; and (b) the query loop — an administrator's answer
should not be systematically staler than the sync cadence that carries
it. 240 s satisfies both: worst case sighting-to-alert is 240 + 30 s,
and a detection is always at most one reconcile period older than the
answer it appears in.

**Why not faster.** 60 s would quadruple wakeups and change no decision
a human or an admin makes; nothing in the product acts on a 60-second-old
detection differently from a 4-minute-old one. **Why not slower.** 900 s
would routinely miss agent runs that live ten minutes — a realistic
shape for a coding agent — and would make the honest limitation below
much larger than the feature.

**The honest limitation, stated on the surface and in `punarctl agents
list`'s footer:** *a process that starts and exits inside one interval,
and touches nothing Punar mediates, is never seen.* Sampling detection
has this hole by construction. Closing it needs exec-time notification —
which is exactly the broad tracing spec 1.14 rules out — so it is stated,
not engineered around.

### 3.3 Immediate triggers (event-driven, spec 6.3's preference)

Three, and no others:

1. **`agents.register` succeeds.** A managed launch is the moment the
   process landscape changes and the moment a sibling unmanaged agent is
   most likely to be running. The pass is already partly walked here
   (M7 reaps and re-checks on register), so this is unification, not new
   work.
2. **A session ends / is reaped.** Same pass, same reason.
3. **An enrollment transition completes** — `enroll.start` or
   `enroll.stop` in punard. Enrolling changes what may be asked about
   this device; unenrolling changes it back. Answering the org's first
   query with a view assembled before enrollment would be sloppy, and
   answering it with a stale view after unenrollment would be worse.

Trigger 3 requires punard to call agentd. **Decision: punard gains a
client for the agentd socket in M10.** M7 declined this edge with a
good reason — "an IPC edge between daemons for a capability the
milestone does not claim" — and that reason expires here: §7.3 requires
the same edge for the query path regardless, so trigger 3 is free once
it exists. The edge is one-directional: agentd never calls punard (M8
reads punard's audit *file*, which is not a call). No cycle exists; §7.3
restates this where it matters most.

The call is fire-and-forget with a 2 s timeout and a non-fatal failure
path: a missed opportunistic scan costs at most 240 s of freshness, and
enrollment must never fail because a bookkeeping daemon was busy.

**Explicitly not a trigger:** file-watching `/run/punar/status.json`.
That file is user-writable (ipc.md §9); letting an unprivileged user
force unbounded `/proc` walks by touching a path is a denial-of-service
primitive and a §6.3 violation with extra steps.

**Explicitly not a trigger:** agentd startup. The boot path stays clean
(spec 6.5); `OnBootSec=240` covers the first pass, and any human who
looks sooner gets M7's staleness-triggered scan.

### 3.4 The diff is the event

The pass builds a set of `detection_id`s (§4.1) and compares it with the
previous set:

| Transition | Emitted, once | Written |
|---|---|---|
| id absent → present | audit `agents.scan` / `result: "detected"`, classification in `resource` | `detections.jsonl` record (`status: "active"`), ledger opened (§6), `agents.json` rewritten, `alerts.json` rewritten iff a new signature (§5.2) |
| id present → absent | audit `agents.scan` / `result: "cleared"` | `detections.jsonl` record (`status: "ended"`), ledger closed with `cleared_at`, `agents.json` rewritten |
| id present → present | **nothing** | **nothing** |
| empty diff (whole pass) | **nothing** | **nothing** |

That last row is the decision that makes a 240 s timer compatible with
spec 6.4: **the steady state of periodic detection is zero bytes
written.** It also makes the audit log a log of *events* rather than a
log of *scans*, which is what makes `punarctl audit tail` readable at
all after a week of uptime.

Consequence, stated because it looks like a bug otherwise:
`agents.json`'s `scanned_at` does **not** advance on a no-change pass.
Its meaning is *"the view as of the last change"*. Liveness — "when did
the last pass actually run" — is in-memory state served by
`agents.list` (`result.last_scan_at`, `result.last_scan_trigger`), and
the panel renders the static promise `continuous · every 4 min` beside
it. The socket is the authority; the file is a change log. This is the
same layering M7 chose for authority data and M8 chose for the ledger
fingerprint.

The `--trigger` parameter (`manual` | `timer` | `register` | `enroll`)
travels into the audit event's `resource` field for scan-level events,
so `m10-check` can prove that a detection was produced by the **timer**
and by nothing a check script typed (§16 group 3).

### 3.5 One new detection input: executable provenance (spec 23)

M7 shipped two signature sources: adapter signatures (→ `observed` when
outside a managed scope) and suspected exe globs (→ `unknown`). Spec 23
lists nine potential inputs; M10 adds exactly **one**, chosen because it
needs no tracing, no new privilege and no code — only data:

```json
{ "id": "unmanaged-path-agentlike",
  "unmanaged_path_prefixes": ["~/Downloads/", "/tmp/", "~/.local/bin/"],
  "name_tokens": ["agent", "-ai", "llm", "copilot", "mcp"],
  "require": "both",
  "note": "path provenance + agent-like name; either alone is not a signal" }
```

`require: "both"` is the whole decision. Path alone would classify every
downloaded binary as suspected AI, which is how a detection product
becomes something users turn off. Name alone is M7's existing glob.
Requiring both keeps the false-positive posture defensible and keeps the
rule reviewable by a human reading one JSON file.

**Not added** (each with its owner): network destinations and MCP
activity (M12 / M9+, no observer exists), credential usage (M9 mediates
only managed sessions), process lineage beyond the detected process
(§6.3 — it is the tracing 1.14 forbids), and executable *signing*
provenance (needs a package-database query per pid per pass; revisit
when a pass has a reason to be more expensive).

---

## 4. Detection identity and the anti-nag substrate

### 4.1 `detection_id` — one running process

```
detection_id = "agt_" + hex12( sha256( exe_realpath ‖ 0x00 ‖ owner_uid ‖ 0x00
                                     ‖ boot_id ‖ 0x00 ‖ pid ‖ 0x00 ‖ starttime_ticks ) )
```

- `agt_`-prefixed because `registry-record.json` and
  `audit-event.json` both require an `agent_session_id`-shaped value,
  and because M7's `agents.json` already emits detection rows with
  `agt_`-shaped ids. No schema moves.
- `starttime_ticks` (field 22 of `/proc/<pid>/stat`) plus `boot_id`
  makes pid reuse **not** collide: a recycled pid is a different
  detection with a different id, which is the correct semantics.
- Stable across scans for the life of the process — the property the
  set-diff in §3.4 depends on.
- It is a **hash, not a path**: the id can appear in exported inventory
  answers without leaking where the binary lives.

### 4.2 `signature_id` — one thing seen

```
signature_id = "sig_" + hex12( sha256( exe_realpath ‖ 0x00 ‖ owner_uid ) )
```

Deliberately coarser: restarting the same binary is the *same* thing
seen, and the user does not need to be told twice. This is the anti-nag
key (§5.2) and the fleet-dedup key (§12).

### 4.3 What each identity is used for

| Concern | Key | Why that key |
|---|---|---|
| set-diff / audit transitions | `detection_id` | one process is one lifecycle |
| persisted record + ledger | `detection_id` | a ledger is about a run, not about a filename |
| alert raise / suppress | `signature_id` | a human wants to be told about a *thing*, once |
| `agents.json` rail row | `detection_id` | shows what is running now |
| exported inventory answer | `signature_id` count | an admin needs "how many distinct unmanaged things", not process churn |

---

## 5. The local alert (spec 12.1, 73; Plate D-009)

### 5.1 What the card says

Plate D-009 fixes the anatomy — meta row, hairline, **one** sentence,
actions — and Sect I register 02 fixes the standard: the §73 anatomy
fits in the card, or the card links out. The shipped alert:

```text
UNKNOWN AI · SUSPECTED · 14:31

Unknown AI activity suspected · foo-agent

~/Downloads/foo-agent · running as punar since 14:29
Why · an agent-named executable is running from Downloads, outside any
      managed Punar session · signature unmanaged-path-agentlike
Policy · Personal defaults          (or: Policy · Acme · eng-ai-v3, when enrolled)

  [I] Inspect · Punar+A        [D] Dismiss to record

Suspected, not certain · nothing was blocked · punarctl agents list
```

Against the §73 six questions: *what happened* (line 1 + the path and
start time), *why* (the named signature, in words and by id), *who
requested it* (nobody — this is the device's own observation, and the
card says `Punar · punar-agentd` as its source group per D-009 Sect II
register 01), *which policy* (the citation line, personal defaults by
default — DESIGN_LANGUAGE §8), *whether the user can change it* (dismiss
is offered and is not destructive), *the next step* (Inspect → the D-005
panel; the CLI command in the footer).

Section-73 voice rules, enforced in review and by `m10-check` greps:

- the word **suspected** appears in the meta row *and* in the sentence.
  Never "detected AI", never "malware", never "threat".
- **no verdict about the user.** The subject of every sentence is the
  process, not the person.
- **no capability claim.** "nothing was blocked" is present because law
  4 says M10 is not armed, and because a user who believes they are
  protected when they are not is worse off than one who knows.
- **no invented datum.** Plate D-009's subline reads
  `~/Downloads/foo-agent → api.foo.ai`. **The shipped alert drops
  `→ api.foo.ai`**: nothing observes network destinations before M12,
  and the plate is the acceptance reference for *anatomy*, not a licence
  to print a field no code produced (spec 1.22). This deviation from the
  plate is deliberate and is the kind that must be written down.

Managed annotation is additive only (DESIGN_LANGUAGE §8): when enrolled,
the policy line cites the org and a `MANAGED` pill joins the card.
Nothing moves, nothing is restructured, and the alert renders **fully**
on a personal device — a security feature is a user benefit first.

### 5.2 The anti-nag rule

**One alert per `signature_id`, not per scan and not per process.**

- First sighting of a `signature_id` with no live alert record → raise.
- Any further detection carrying that `signature_id` → update the
  existing record's `last_seen`, `live_count` and most recent
  `detection_id`. **Never re-raise, never re-toast.**
- When the last live detection of the signature clears, the record moves
  to `cleared` and starts a **24 h quiet window**. A sighting inside the
  window updates the record silently; the first sighting **after** the
  window raises a fresh alert.

Why a window at all: a cron-driven or crash-looping agent would
otherwise produce one alert per restart, and the tenth alert teaches the
user to ignore the first. Why 24 h and not "forever": a binary that
reappears next week after a quiet fortnight is genuinely new
information, and permanently suppressing it would make the feature
silently degrade over the life of the device.

Dismissal does **not** change suppression: dismissing files the card,
and the card was already never going to be raised twice. There is
therefore no "snooze" concept, no per-alert mute, and no user-facing
suppression state to explain — which is the point.

### 5.3 How it reaches the shell

**`/run/punar-agentd/alerts.json`, `0640 root:punar`, atomic
tmp + `fsync` + `rename`, written only when the alert set changes.**

The path is the decision. M9 §8.1 moved `approvals.json` out of
`/run/punar` because a file that tells a human what to believe must not
be replaceable by an unprivileged process; the same argument applies
with at least equal force here. A forged card reading *"Unknown AI
activity suspected · your-bank-helper"* with an `Inspect` action is a
phishing primitive, and `/run/punar` is `0755 punar:punar`.
`/run/punar-agentd` already exists, root-owned, since M8's
`ledger.json` (ipc.md §13.2), so this costs nothing.

The shell reads it with `shell/punar-shell/Services/Alerts.qml` — a
`FileView` change watch, the established `Status`/`Agents`/`Ledger`/
`Approvals` pattern: inotify-driven, zero polling, no socket client in
the shell. Consumers fail closed: missing or unparsable file renders
**no** alert, never a placeholder alert.

Content is display-only and identical to what the same user can already
print: `{v, updated_at, alerts: [{alert_id, signature_id, agent,
executable, owner, first_seen, last_seen, live, detection_id, signature,
policy_citation, state}]}`. No pids, no cmdlines, no hashes of anything
secret.

### 5.4 Dismissal

`D` (or `Esc` on the focused card) runs a **detached**
`punarctl agents alerts dismiss <alert_id>`; agentd sets
`dismissed_at`, rewrites `alerts.json`, and appends an audit event
(`action: "agents.alert_dismiss"`). The shell does not read the process
result — the next `FileView` change is the truth. Event-driven end to
end, exactly the M9 overlay's contract.

**Dismiss files, it never destroys** (D-009 Sect I register 03). The
alert remains in `punarctl agents alerts` and in the detection record;
when M13 builds the notification centre, the card is already there to
group. `punarctl agents alerts` shows dismissed alerts with their
dismissal time, so "I clicked it away and now I can't find it" has an
answer.

### 5.5 Do-not-disturb: the first sighting breaks through

**Decision: yes, the first sighting of a signature breaks through DND.
Every subsequent state change does not.**

D-009 Sect II register 03 states the shipped rule — *"Do-not-disturb
silences toasts, never the record — and it never silences
approval-expiry warnings; deadlines outrank quiet"* — and grants the
exception to **deadlines**. A detection is not a deadline, so the
exception does not extend by analogy and has to be argued on its own.

The argument that decides it is **spec 24.2**, and it is structural
rather than aesthetic: from this milestone onward an authorized
administrator can *query* the existence of unmanaged agents on this
device. If DND could suppress the first sighting, there would exist a
state in which the administrator knows about a process on the user's
machine and the user does not. That inverts the section-24.2 promise —
"the employee should never have less visibility than the administrator"
— for as long as quiet mode is on. No feature may create that state.

Two supporting arguments: a visibility product whose visibility a
convenience toggle can switch off is not the thing section 23 promises;
and decision 6 bounds the cost at one breakthrough per signature per
24 h, which is what makes a breakthrough affordable at all.

**The counter-argument, stated and answered rather than dismissed.** DND
exists so that a user presenting to a room is not interrupted, and a red
card reading *"Unknown AI activity suspected"* on a projector is a real
harm — possibly a worse one than a four-hour delay. The answer is
mitigation, not reversal: under DND the alert appears **without sound,
without focus steal, and without auto-dismiss**, as a persistent card in
the alert region. It does not steal the moment; it does not vanish
before the user comes back to it. The information arrives; the
interruption does not. Reversing the rule instead would trade a
presentation-slide embarrassment for an inversion of the product's
central privacy promise, which is not a trade this project makes.

### 5.6 The surface M10 actually builds (honest scope)

There is **no notification code in the shell today** — no toast stack,
no centre, no DND state, no freedesktop notification daemon. D-009 draws
all three states; M13 owns them.

M10 builds exactly the sliver its deliverable names: **one layer-shell
alert region** (`shell/punar-shell/Alert/AlertStack.qml`) at the D-009
toast position, rendering **only** `punar-agentd` detection alerts from
`alerts.json`, with the D-009 card anatomy, tokens from
`shell/theme/punar-tokens.json`, and `I`/`D` keys printed on the
buttons (spec 12.1, 12.3). `IpcHandler { target: "alerts" }` with
`open()`, `close()`, `state()`, and — so the DND rule is testable
rather than merely written — `dnd(on|off)`.

**DND in M10 is shell-local state with an IPC setter and no persistence,
no capability, and no UI toggle.** That is the honest minimum that makes
decision 8 verifiable (§16 group 5); the toggle, its persistence and its
capability are M13, and the panel says so. Third-party notifications,
grouping, `Punar+N`, `Clear all` and the OSD are untouched.

---

## 6. The unknown-agent ledger — M8's open question, decided

### 6.1 The question, restated

M8 §4.2 shipped this row and this promise:

> unknown-agent detection transition … `unknown_ai_execution` …
> **partially** — the audit event exists today, but detections have no
> persisted session (M7 §4.4), so it attaches to **no** ledger in M8;
> **M10** owns the unknown-agent ledger.

**Decision: detections DO get a persisted record and a ledger.**

### 6.2 Why — the two arguments, both of which point the same way

**Practical (spec 51, 72, 59.2).** Section 51 lists "unknown/suspected
AI" among the nine things an administrator may ask about, and section 72
draws a fleet view whose shadow-AI panel counts unmanaged agents and
devices. Without persistence, the honest answer to any question about a
process that exited an hour ago is *nothing* — and *nothing* is
indistinguishable from *it never happened*. A detection feature whose
memory is exactly as long as the process it detected cannot answer the
question the feature exists to answer. Section 59.2 lists "local
registry" and "Smplify query" as mitigations for unmanaged AI; both
presuppose a record.

**Privacy (spec 21.2, 24).** The instinct that an unregistered process
should not get a file is a good instinct, and it points the *same* way
once followed through. Recording a Level-4 `unknown_ai_execution`
security event about a session while refusing to admit the session
exists is incoherent — the event is already written today. And the
never-log list (21.2 — no prompts, no source, no per-file reads, no
secret values) is not a rule about *which* agents get a ledger; it is a
rule about *what a ledger may contain*. Applying it identically to
unknowns, with fewer available sources, produces a ledger that is
strictly smaller than a managed one. The privacy-preserving choice is
therefore not "no record" but "a record that structurally cannot hold
the sensitive things".

Corroboration that this was always the intent:
`fixtures/agents/unknown-agent/registry-record.json` and
`ledger-summary.json` have shipped since M7 describing exactly this —
`agt_999`, `foo-agent`, `classification: "unknown"`, one
`unknown_ai_execution` event reference. M10 makes the fixtures true.

### 6.3 What the unknown ledger contains — and why each absent thing is absent

M8's four sources (A cgroup, B attributed audit, C workspace grant,
D session metadata) mostly do not exist for a process Punar did not
launch. Taking each honestly:

| M8 source | For an unknown detection | Decision |
|---|---|---|
| A — agent scope cgroup | none: the process is not in a `punar-agent-*.scope` | The **detected executable's own process class** (M8's data-driven class table, §3.2 there) is recorded — one class, from the exe we already read. **The children of the process are NOT walked.** |
| B — audit filtered by session id | the process makes no attributed punard calls | The **detection transitions themselves** are attributable: `unknown_ai_execution` event *references* attach here. This is the ledger's one real entry. |
| C — workspace grant | none: nothing granted it a workspace | Repositories and directory zones are **not observed** and are **never inferred from `cwd`**. |
| D — session/adapter metadata | partial: exe path, owner, timestamps, matched signature | Recorded, with the caveats in §6.4. |

Three refusals inside that table deserve their own sentences, because
each was a real temptation:

- **No child-process walk.** Walking `/proc` for descendants of a
  suspicious pid would produce a per-user process graph — precisely the
  broad tracing spec 1.14 rules out, and a far more invasive artefact
  than anything M8 collects about a *managed* agent. Refused.
- **No `cwd` read.** `/proc/<pid>/cwd` is trivially readable by the root
  daemon and would tell us the project. It would also record a
  filesystem path from inside the user's home into a file an
  administrator can later ask about, which is exactly what 21.2's
  never-record list protects. Refused. The ledger records a **zone
  class** for the *executable's own* location (`downloads`, `tmp`,
  `home`, `system`) — a class, never a path.
- **No cmdline, no argv, no environment.** These routinely contain
  prompts, API keys and file paths in the wild. There is no field for
  them in any schema and none is added. Refused permanently.

Everything else renders as M8's `not_yet_observed[]` rows with an owning
milestone: network destinations (M12), MCP servers and tools (M9+),
credential classes (M9 — and note honestly that `punar-secrets` mediates
*managed* sessions, so an unmanaged agent's credential use may never be
observable by this mechanism at all), repositories and directory zones
(no producer for unmanaged agents, and §6.3's refusals say why).

The result validates against **`ledger-summary.json` unchanged** — the
M8 Decision-0 law survives its second milestone.

### 6.4 The persisted record

`/var/lib/punar/agents/detections.jsonl` (`0600 root`, append-only,
same writer discipline and rotation as the registry): one schema-exact
`registry-record.json` document per state change.

Field mapping, with the awkward ones decided rather than fudged:

| Field | Value | Note |
|---|---|---|
| `session_id` | the `detection_id` | `agt_`-shaped by construction (§4.1) |
| `agent` | executable basename, sanitized to `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$` | unsanitizable names fall back to the literal `unknown-agent`; the schema pattern is a constraint we meet, not one we relax |
| `version` | `"unknown"` | matches the shipped fixture; we do not execute the binary to ask it |
| `process_id` | observed pid | already visible in `/proc` to the same user |
| `user` | owner uid resolved to a username | |
| `project` | `"unknown"` | **not** inferred from `cwd` (§6.3) — the fixture's `"atlas"` is a hero-demo value that real detection cannot honestly produce, and this deviation is deliberate |
| `environment` | `"host"` | matches the fixture |
| `status` | `active` → `ended` | the M7 widening; `ended` is written when the detection clears |
| `classification` | `"unknown"` | |
| `started_at` | process start time derived from `starttime_ticks` + boot time | the process's start, not the scan's — the scan time is a separate `observed_at` in `agents.json` |

Sibling data that the schema cannot hold — `signature_id`, the matched
signature name, the executable path, the zone class, `cleared_at` —
lives in a parallel index (`detections-index.json`), never as extra
properties on a schema-validated document. Third application of the
M8 Decision-0 law.

### 6.5 Retention, purge, and the boundary that survives purge

- **7 days after the detection clears**, versus M8's 14 for a managed
  session. Shorter, because a detection is a record about a process the
  user never asked for, and the shortest window that still answers *what
  ran on this device last week* is the right one. Seven days covers a
  full working week plus a weekend — the realistic span of "we found
  something on Friday, look into it Monday" — and halves the window in
  which any query can reach it. Pruning reuses M8 §6.3's machinery
  unchanged, including the tombstone that floors re-ingestion so a
  deleted record cannot be resurrected by a later drain.
- **`punarctl privacy purge` deletes detection records and their
  ledgers, unconditionally, for the owning user.** M8's privacy
  guarantee 2 is not narrowed: no policy, org or otherwise, may withhold
  a user's delete authority over data derived about their own machine.
- **The audit event survives.** The `unknown_ai_execution` event stays
  in `/var/log/punar/audit.jsonl`, which purge has never touched (M8
  guarantee 4). Purge removes the **derived summary**, never the
  **decision record**. This is the honest resolution of the obvious
  tension — "the user can delete what the admin wants to see" — and it
  needs no new rule, because M8 already wrote it down.
- Consequence, printed on the purge surface in one sentence: *the fact
  that an unknown agent ran remains in the audit trail; what it touched
  does not.*

---

## 7. The Smplify remote query — mechanism (spec 51, 24.1)

### 7.1 The problem stated precisely

Spec 51 requires that a managed administrator be able to ask a device
questions, and that "detailed access information should be queried from
the device when required rather than automatically uploaded
continuously". A device that can be *asked* normally implies a device
that *listens*. Punar must not listen.

### 7.2 Decision: the device pulls pending queries on the existing sync piggyback

At the end of every reconcile pass, **when enrolled**, M5's sync hook
already runs (`compliance.report`, and `inventory.report` when its hash
changed). M10 adds two calls to that same hook:

```
reconcile pass ends
  └─ enrolled? ─ no ─→ nothing (this is the §11 gate, already shipped and proven)
                └ yes ─→ compliance.report          (M5)
                       ├─ inventory.report          (M5, hash-gated)
                       ├─ queries.pending {device_token}      → [ {query_id, …}, … ]
                       └─ for each: queries.answer {device_token, query_id, answer}
```

**Why this is the honest mechanism, argued against the alternatives:**

- **An inbound listener** (a socket, a port, a push channel) would make
  every Punar device a network service. That is a permanent attack
  surface added for an occasional administrative question, it inverts
  the section 24 diagram (the arrow points *from* the device), and it
  would need its own authentication, rate limiting and hardening story.
  Rejected on law 1.
- **A long-poll / persistent connection** removes the listener but keeps
  a socket open continuously and reintroduces a wakeup source — a
  polling loop wearing a different hat, against §6.3.
- **Continuous upload** of the ledger so the cloud can answer locally is
  precisely what section 24 exists to forbid.
- **The pull** costs one extra request pair on a hook that already runs,
  adds no timer, no listener and no wakeup, and has an honest, statable
  latency.

**Latency, stated on every surface that shows a query:** an answer
arrives within one reconcile period (~120 s) plus the round trip; the
mock's `admin.ai_query` returns `{query_id, status: "pending"}`
immediately, and the *administrator's* client polls `admin.query_result`.
**The waiting happens on the administrator's side, which is where a
request that a device did not initiate ought to wait.** This is not an
apology for the design; it is the design's most honest property.

Offline behaviour is M5 §7 unchanged: an unreachable control plane means
the pull simply does not happen; queries stay pending on the mock and
are answered on the next successful pass. No spool, no queue, no new
state.

### 7.3 Who does what: transport vs. authority

```
punar-mock-smplify            punard                     punar-agentd
   (control plane)         (only CP client)          (only AI data owner)
        │                        │                            │
        │◀── queries.pending ────│  (sync hook, enrolled only)│
        │─── [pending queries] ─▶│                            │
        │                        │──── query.answer ─────────▶│  root peer only
        │                        │                            │  ├ intersect scopes (§9.2)
        │                        │                            │  ├ project the answer
        │                        │                            │  ├ append queries.jsonl
        │                        │                            │  └ append audit event
        │                        │◀─── answer | refusal ──────│
        │◀── queries.answer ─────│  posted verbatim           │
```

**punard is the only control-plane client** (M5's law — it holds the
device token, `enrollment.json`, and the offline logic). **punar-agentd
is the only owner of AI data** (M7/M8's law — it holds the registry, the
ledger and the detections). M10 keeps both laws by making punard a
courier: it never assembles an answer, never reads a ledger, and never
sees a byte it was not handed by the daemon that decided to hand it
over.

The cycle question, answered once: punard → agentd is the **only**
inter-daemon call. agentd calls nobody; its relationship to punard's
data is reading an append-only file (M8 §4.4). The graph is a DAG, and
`punar-agentd.service` gains no `After=`/`Requires=` on punard as a
result — a call that fails because the peer is not up is a non-fatal
retry next pass.

`RestrictAddressFamilies=AF_UNIX` stays on `punar-agentd.service`. Even
in the mock world where the control plane is a local socket, agentd
never speaks to it.

---

## 8. Scope vocabulary and the refusal list

### 8.1 Four scopes, one per observation level (spec 21.2)

| Scope | Level | Answers (spec 51's questions it serves) | Contains |
|---|---|---|---|
| `inventory` | 1 — Inventory | *which AI agents are active; which are unmanaged; unknown/suspected AI* | counts by classification; per-session `{session_id, agent, classification, status, started_at}`; per-detection `{signature_id, agent, first_seen, live}` |
| `authority` | 2 — Authority | *effective permissions* | per managed session: the section-20 decision words and the policy citation — the org's own policy, read back |
| `resource_summary` | 3 — Resource summary | *which projects they belong to; resource summaries* | the `ledger-summary.json` projection **verbatim** — M8's `result.summary`, the document M8 §10.6 already promised would be the export — plus `not_yet_observed[]` |
| `security_events` | 4 — Security events | *policy violations* | Level-4 event **references** only: `{event_id, event_type, timestamp}` |

There is **no wildcard, no `all`, and no free text.** The scope field is
a closed enum on the wire and a Rust enum in both daemons; an
unrecognised value is refused as `out_of_scope` rather than
best-effort-answered. A query may optionally name one `session_id` to
narrow the answer; it may never widen it.

Two of spec 51's nine questions have no honest answer in M10 and are
refused with a milestone, not fudged: **network zones** (M12 —
`punar-netd` does not exist) and **credential classes** for unmanaged
agents (M9 mediates managed sessions only). They appear in the answer's
`not_yet_observed[]` so the administrator is told *why* the field is
empty — the same discipline M8 applies to the user's own surfaces.

### 8.2 What an `inventory` answer looks like

```json
{ "query_id": "qry_7c1a…", "device_id": "dev_…", "scope": "inventory",
  "answered_at": "2026-08-25T14:02:11Z",
  "counts": {"managed": 1, "observed": 0, "unknown": 1},
  "sessions": [{"session_id": "agt_4f21c09ab3e1", "agent": "claude-code",
                "classification": "managed", "status": "active",
                "started_at": "2026-08-25T13:44:02Z"}],
  "detections": [{"signature_id": "sig_9b02…", "agent": "foo-agent",
                  "classification": "unknown", "suspected": true,
                  "zone": "downloads", "first_seen": "2026-08-25T13:59:41Z",
                  "live": true}],
  "not_yet_observed": [{"level": 3, "category": "network_destinations",
                        "milestone": "M12", "reason": "punar-netd does not exist"}] }
```

Note what is **not** there even at the coarsest scope: no executable
path (only `zone`), no pid, no user, no project, no cwd, no cmdline.

### 8.3 The refusal list — closed, and mostly structural

Refused at **every** scope, on every device, regardless of role:

1. **Prompts and conversation content** — no field exists in any schema.
2. **Source code, file contents, diffs, repository contents.**
3. **File paths.** Zone *classes* only. The detection's executable path
   is Level-1 **local-only** data: the user sees it in the alert and in
   `punarctl agents list`; the export carries `zone` instead.
4. **Per-file access records.** Spec 21.2: "Do not record every source-code
   line read" — and M8 never recorded per-file access to begin with,
   so there is nothing to refuse from.
5. **Command lines, argv, environment variables.**
6. **Secret values, tokens, credential material.** Credential *classes*
   only, and only at `resource_summary`, and only for managed sessions.
7. **Pids, cgroup paths, process trees.**
8. **Audit event payloads.** `security_events` returns
   `{event_id, event_type, timestamp}`; the action, resource, decision
   and policy ids stay on the device. An administrator who needs the
   payload asks the human, which is the correct social protocol and is
   printed in the refusal text.
9. **Anything outside the granted scope** (§9.2), and **everything on an
   unenrolled device** (§11).

Points 1–5 and 7–8 are refused **because no field exists to carry them**
— the M8 privacy-model-as-a-type, extended to the export path — not
because a filter drops them at the boundary. That distinction is the one
worth defending in review: a filter can be forgotten, a missing field
cannot.

---

## 9. Authorization

### 9.1 RBAC in the mock (dev/CI fidelity, not a real IdP)

New fixture `fixtures/organizations/acme/admins.json`, served by nobody
and read only by the mock:

```json
{ "v": 1,
  "roles": {
    "helpdesk":       ["inventory"],
    "fleet_viewer":   ["inventory", "authority"],
    "security_admin": ["inventory", "authority", "resource_summary", "security_events"] },
  "admins": {
    "helpdesk@acme.com":  "helpdesk",
    "cio@acme.com":       "fleet_viewer",
    "secops@acme.com":    "security_admin" } }
```

`admin.ai_query` requires an `admin` identifier present in the fixture
and a scope allowed by that admin's role; otherwise the mock returns
`denied` **without enqueuing** — the query never reaches the device, and
"an admin cannot even ask" is the cheapest possible refusal.

The mock's posture is unchanged from M5 §4.1: never enabled, dev/CI
only, `--help` says *"dev/CI mock — not a product component"*, and its
admin identities are **fixture strings, not authenticated principals**.
Every surface that renders a requesting admin labels the identity
**asserted by the organization · not verified by this device**, because
M10 has no IdP and pretending otherwise would be the exact dishonesty
spec 1.22 forbids.

### 9.2 The device's own check — the one that decides

`punar-agentd` computes, from **local state only**:

```
answered_scope = requested_scope ∩ org_granted ∩ device_builtin_max
```

- **`requested_scope`** — from the query. Untrusted input.
- **`org_granted`** — the `remote_query_scopes[]` array persisted into
  `/var/lib/punar/enrollment.json` (`0600 root`) by punard at enrollment
  from the org document. **agentd reads this file itself.** It does not
  accept a scope grant passed alongside the request, because a courier
  that can widen its own authority is not a courier. Spec 59.4: a
  compromised control plane must not be able to talk the endpoint into
  exceeding what enrollment established.
- **`device_builtin_max`** — the four-value enum. There is no
  configuration that can add a fifth.

**Fail closed.** Absent `enrollment.json` → empty set. Absent
`remote_query_scopes` key → **empty set**, not a permissive default:
an organization that never asked for a scope never gets one. Empty
intersection → refusal with `reason: "out_of_scope"` and a section-73
message naming what is missing and who can change it:

```text
Refused · resource_summary
This device answers inventory and authority queries for Acme.
Resource summaries were not granted at enrollment.
Policy · Acme · eng-ai-v3 · remote_query_scopes
Next step · the organization grants the scope at enrollment; the device
            does not widen it locally, and neither can an administrator.
```

Both halves of spec 24.1 are then true and independently true: "RBAC
applies" (the mock, §9.1) and "the endpoint evaluates the request"
(here) — and "administrators cannot silently retrieve data outside
allowed scope" is enforced by the party with the data, with the attempt
recorded either way (§10).

### 9.3 What authorization does *not* do

It does not ask the user in real time. An approval gate on every admin
query was considered — M9's machinery would make it easy — and rejected:
a query that blocks on a human is a query that fails whenever the laptop
is closed, which would push administrators toward continuous upload, the
thing section 24 exists to prevent. The chosen guarantee is
**transparency after the fact within one command** (§10.3) plus
**scope enforcement before the fact** (§9.2). If a future milestone adds
per-query consent, it belongs in the enrollment-time grant, not in the
query path — noted in §18.

---

## 10. Query audit (spec 51.1) and user visibility (spec 24.2)

### 10.1 The local query log

`/var/lib/punar/agents/queries.jsonl` — `0600 root`, append-only, one
record per query **answered or refused**:

```json
{ "query_id": "qry_7c1a…",
  "received_at": "2026-08-25T14:02:09Z",
  "answered_at": "2026-08-25T14:02:11Z",
  "requesting_admin": "secops@acme.com",
  "admin_identity_verified": false,
  "organization": "acme.com",
  "device_id": "dev_…",
  "requested_scope": "resource_summary",
  "granted_scope": null,
  "authorization_decision": "deny",
  "refusal_reason": "out_of_scope",
  "result_category": "refused",
  "record_counts": {"sessions": 0, "detections": 0, "security_events": 0},
  "audit_event_id": "evt_611" }
```

All six spec-51.1 fields are present — requesting admin, requested
scope, device, timestamp, result category, authorization decision — plus
the granted scope (without which "authorization decision" is not
actually reconstructable) and the honesty flag on the admin identity
(§9.1).

**The answered payload is deliberately NOT stored.** Two reasons: one
exported copy of a user's resource summary is enough to protect, and a
second copy that must be pruned, purged and access-controlled in
parallel is a liability with no reader; and the content is exactly
reproducible from the ledger plus the recorded scope, so nothing is
lost. `record_counts` gives the user the shape of what left ("3
sessions, 1 detection") without a second copy of the contents.

**Retention: bounded by size and age — 365 days or 10 000 records,
whichever binds first.** Longer than any data it describes, on purpose:
the record of *who asked about you* should outlive the data they asked
about.

**`punarctl privacy purge` does NOT delete the query log.** Same
principle as the audit trail (M8 guarantee 4): the log is a record of
what the **organization** did, not data about the user's work, and a
user deleting the evidence of a query would also delete their own
recourse. Every purge surface says this in one sentence, alongside the
audit-trail sentence it already prints.

### 10.2 The audit event, without touching the schema

One `audit-event.json`-conformant event per query, through the shared
`AuditWriter`:

| Field | Value | Note |
|---|---|---|
| `action` | `admin.ai_query` | dotted snake_case, matches the pattern |
| `resource` | the requested scope | e.g. `resource_summary` |
| `decision` | `allow` \| `deny` | the shipped enum |
| `result` | `answered` \| `refused` | |
| `source` | `organization` | already in the shipped `principal_kind` enum |
| `user_id` | the **requesting admin** identifier | see below |
| `agent_session_id` | `agt_none`, or the real id for a session-narrowed query | M7's documented sentinel |
| `project_id` | `system` | M3's documented sentinel |
| `policy_ids` | the org policy ids that carried the grant | |

The `user_id` choice is the one debatable field and is decided
deliberately: the schema describes it as the human in whose session the
event occurred, and a remote query occurs in **no local session**. Two
options existed — put the local owner there and keep the admin only in
`queries.jsonl`, or put the admin there. The admin wins, because
`punarctl audit tail` must be readable on its own and an audit line
about an administrative query that does not name the administrator is a
line nobody can act on. The pair `source: "organization"` +
`user_id: "secops@acme.com"` reads unambiguously, and every rendering
carries the `not verified by this device` label from §9.1. The schema is
**not** extended to add an `admin_id` property (M8 Decision 0, fourth
application).

### 10.3 `punarctl privacy queries` — the section 24.2 command

**This is the named command.**

```text
PUNAR · PRIVACY — REMOTE AI QUERIES                                  punar-dev

WHO ASKED ABOUT THIS DEVICE      3 queries · 2 answered · 1 refused
  14:02  secops@acme.com    resource_summary   REFUSED · out of scope   evt_611
  13:58  cio@acme.com       inventory          ANSWERED · 1 session · 1 detection
  13:40  cio@acme.com       authority          ANSWERED · 1 session

IDENTITIES                asserted by acme.com · not verified by this device
WHAT IS NEVER ANSWERED    prompts · source code · file paths · command lines
                          secret values · audit payloads · anything out of scope
GRANTED SCOPES            inventory · authority                    (Acme · eng-ai-v3)
WHERE                     /var/lib/punar/agents/queries.jsonl · kept 365 days
                          this log is not deleted by punarctl privacy purge
SEE ALSO                  punarctl privacy ledger · punarctl audit tail
```

- **Readable by any peer admitted to the agentd socket** (group `punar`),
  not root-only. Withholding the log of who asked about the user from
  the user would be a direct violation of 24.2. Root-only would also be
  absurd on a single-user personal device.
- `--json`, `--since <rfc3339>` for scriptability.
- Personal device (§11): one calm line, exit 0, no error, no upsell —
  `No organization is enrolled · no remote-query path exists on this
  device · nothing has ever been asked.`
- The M8 privacy-ledger footer line changes from
  `REMOTE QUERY none — no upload path exists (Milestone 10 adds …)` to
  the live count, or to the personal-mode sentence. That line was
  written in M8 as a placeholder for this milestone; M10 is required to
  update it and `m10-check` asserts it.
- The AI panel gains **one line** in its footer when enrolled —
  `ADMIN QUERIES · 3 · LAST 14:02 · punarctl privacy queries` — and
  nothing at all when personal (DESIGN_LANGUAGE §8: enrollment
  annotates, it never restructures).

### 10.4 The 24.2 guarantee, restated for M10

M8 wrote six numbered promises. M10 adds three and breaks none:

7. **You can see every question an administrator asked about this
   device, and what was returned** — `punarctl privacy queries`.
8. **You can see the granted scope, so you can check the answers against
   it yourself** — the `GRANTED SCOPES` line comes from the same
   `enrollment.json` array agentd enforces, not from a separate copy.
9. **Nothing can be answered that you cannot print** — the export at
   `resource_summary` is byte-for-byte M8's `result.summary`, the same
   document `punarctl agents access --json` hands the user. The
   administrator's view is a **subset** of the user's, by construction
   rather than by promise.

---

## 11. Unmanaged-first: why the query surface is structurally inert (DESIGN_LANGUAGE §8, spec 3.2)

On a personal device, the requirement is not "the UI hides it" but "it
does not exist". Three independent gates, each individually sufficient:

**Gate A — the pull never runs.** The `queries.pending` call lives
inside M5's sync hook, which runs at the end of a reconcile pass **only
when `enrollment.json` exists**. This is not a new condition written for
M10; it is the gate M5 shipped and `m5-check` has asserted since. An
unenrolled device performs no control-plane call of any kind, so there
is no pending query to fetch and no code path that fetches one.

**Gate B — the data owner refuses anyway.** Even if punard were coaxed
into calling `query.answer`, agentd computes `org_granted` by reading
`enrollment.json` itself (§9.2). No file → empty set → refusal. A
mistaken or compromised courier cannot extract data from the daemon that
holds it.

**Gate C — there is nothing to reach.** No listener, no port, no
inbound path exists on any device, enrolled or not (law 1). An
administrator with a perfectly valid token and a personal device's IP
address has nowhere to send a request.

**The UI follows, it does not carry the burden.** `alerts.json`,
`agents.json` and the panel render the query line only when
`status.json` reports enrolled; `punarctl privacy queries` prints the
calm personal-mode sentence. If every UI check were deleted tomorrow,
the device would still answer nothing.

**And the honest limit.** "Structurally true" here means *three
independent gates, each sufficient, one of which (C) is an absence
rather than a check*. It does **not** mean the code is absent from the
binary: `punard` ships the client and `punar-agentd` ships
`query.answer` on every image, personal or not. A separate build with
the enterprise path compiled out is the stronger claim, and M10 does not
make it. Stated here rather than implied, because "inert" and "absent"
are different words and the difference is the kind of thing a security
reviewer is entitled to be told without asking.

---

## 12. Fleet view (spec 72) — what the mock may aggregate, and the boundary

### 12.1 What it legitimately has

Three sources, all of them things devices *sent*:

| Source | Since | Yields |
|---|---|---|
| `inventory.report` | M5 | enrolled device count, OS/kernel, capability list |
| `compliance.report` | M5 | per-device compliance **category states only** |
| answered `admin.ai_query` results | M10 | per-device counts by classification, agent names, and — only where `resource_summary` was granted **and answered** — resource **classes** |

`punar-mock-smplify --fleet` (also `admin.fleet`, role-gated to
`fleet_viewer` and above) prints the section-72 shape at CI scale:

```text
AI FLEET                                   dev/CI mock — not a product component

Devices                    1     enrolled and reporting
Active AI users            1     distinct users seen in answered inventory queries

Claude Code                1
Codex                      0
Other                      0
Unknown                    1

SHADOW AI DETAIL
1 unmanaged agent · 1 device · 1 distinct signature

  accessing source repositories        —   not answered at resource_summary scope
  accessing corporate APIs             —   not observable before M12 (punar-netd)
  production credentials               —   not observable: credentials are mediated
                                           for managed sessions only (M9)

Answers are as fresh as each device's last sync · oldest answer 00:03:41 ago
```

### 12.2 The boundary — what it must NOT be able to show

- **Per-user or per-project attribution of an unknown agent.** The
  device never exports `user` or `project` for a detection (§6.4 sets
  `project` to `unknown` and §8.2 omits `user` entirely).
- **Executable paths.** Only `zone` classes leave the device.
- **Prompts, source, file paths, cmdlines, audit payloads** — §8.3.
- **Network destinations.** Section 72's mockup shows "2 accessing
  corporate APIs"; nothing observes that before M12, so the row prints
  `—` with the milestone. The mockup depicts a Phase-2 fleet, and saying
  so is cheaper than inventing a number.
- **Data from a device that never answered at that scope.** This is the
  rule that matters most, so it is stated as a rule:

> **`0` and `—` are different, and the mock must render them
> differently.** `0` is a claim, and a claim requires a device that
> actually answered at the scope that would have produced it. `—` means
> nobody answered. Section 72's "0 production credentials" is a
> **finding**; printing it from an absence of data would be the single
> most dangerous dishonesty available to this feature, because it is the
> line an administrator would most like to believe.

- **Cross-device correlation of a user's activity.** The mock stores
  what it received per device and aggregates counts; it builds no
  per-person profile, and there is no field that would let it.
- **Retroactive reach.** A device that enrolls today has answered
  nothing about yesterday, and the fleet view says `not answered`, not
  `0`. Enrolling never applies retroactively — DESIGN_LANGUAGE §8's
  privacy sentence, made true on the server side.

---

## 13. Proposed IPC contract (to be landed in `docs/api/ipc.md` §17–§20 by M10's implementation)

This section exists because M10's planning must not edit `ipc.md` while
other milestones are being implemented in it. **The implementation lands
this text as new sections §17–§20, additively, still `v: 1`.** Nothing
below changes an existing method, error code or side contract.

### 13.1 §17 — `punar-agentd` additions (agentd socket)

| Method | Params | Result | Authz |
|---|---|---|---|
| `agents.scan` **(amended)** | `{trigger?: "manual"\|"timer"\|"register"\|"enroll"}` | existing result **+** `last_scan_at`, `last_scan_trigger`, `changed: bool` | unchanged |
| `agents.list` **(amended)** | — | existing result **+** `last_scan_at`, `last_scan_trigger` (in-memory liveness, §3.4) | unchanged |
| `alerts.list` | `{include_dismissed?: bool}` | `{alerts: [...]}` — the §5.3 shape | any admitted peer |
| `alerts.dismiss` | `{alert_id}` | `{dismissed: true, alert_id, dismissed_at}` | owner uid of the detection, or root |
| `query.answer` | `{query_id, requesting_admin, organization, requested_scope, session_id?, received_at}` | `{query_id, authorization_decision, granted_scope, result_category, payload?, refusal_reason?, audit_event_id}` | **root peer only** (`peer.uid == 0`) |
| `queries.list` | `{since?, limit?}` | `{queries: [...]}` — the §10.1 records | any admitted peer (spec 24.2) |

`agents.access` **(amended)**: accepts a `detection_id` as well as a
managed `session_id`; the returned `result.summary` remains a
schema-exact `ledger-summary.json` document and `result.detail` remains
the M8 sibling aggregate. No new fields.

New error code: `out_of_scope` (a refusal that is neither `denied` —
which means *you* may not — nor `unknown_method`). Reusing `denied`
was considered and rejected: the two produce different section-73
messages and different `queries.jsonl` rows, and collapsing them would
make the query log unable to distinguish "this admin lacks the role"
from "this device was never granted the scope".

### 13.2 §18 — `punard` additions

| Method | Params | Result | Authz |
|---|---|---|---|
| `enroll.status` **(amended)** | — | existing result **+** `remote_query_scopes: [...]`, `last_query: {at, scope, decision}` | unchanged (read, any peer) |

Plus the internal behaviour, documented as contract because it is
observable: punard's sync hook calls `queries.pending` and
`queries.answer` on the control plane when enrolled, and calls
`query.answer` on the agentd socket for each; enrollment transitions
call `agents.scan {trigger: "enroll"}`.

### 13.3 §19 — control-plane protocol additions (`punar-mock-smplify`)

Device-facing (device_token authenticated, as M5):

| Method | Params | Result |
|---|---|---|
| `queries.pending` | `{device_token}` | `{queries: [{query_id, requesting_admin, organization, requested_scope, session_id?, received_at}]}` |
| `queries.answer` | `{device_token, query_id, answer}` | `{accepted: true}` |

Admin-facing (the M5-reserved names, now real):

| Method | Params | Result |
|---|---|---|
| `admin.devices` | `{admin}` | `{devices: [{device_id, enrolled_at, last_sync, compliance_state}]}` |
| `admin.device` | `{admin, device_id}` | that device's received inventory + compliance, and its answered-query history |
| `admin.ai_query` | `{admin, device_id, scope, session_id?}` | `{query_id, status: "pending"}` — or `denied` if the role forbids the scope (§9.1) |
| `admin.query_result` | `{admin, query_id}` | `{status: "pending"\|"answered"\|"refused", answer?}` |
| `admin.fleet` | `{admin}` | the §12.1 aggregate as structured data |

Mock state grows by two files under `/var/lib/punar-mock-smplify/`:
`queries.json` (pending/answered, per device) and
`received-answers.jsonl` (append-only, what devices returned).

### 13.4 §20 — side contract: `/run/punar-agentd/alerts.json`

Path, mode (`0640 root:punar`), the §5.3 field list, the atomic-write
and change-only rules, the fail-closed consumer rule, and the explicit
statement that it is display data whose authority is the socket.

---

## 14. CLI (Plate D-014, spec 11.2)

| Command | Behaviour |
|---|---|
| `punarctl agents scan [--trigger …]` | existing; `--trigger` defaults to `manual` and is reserved for the timer unit |
| `punarctl agents alerts [--json] [--all]` | the alert register: signature, executable, first/last seen, live/cleared/dismissed, and the suppression window's expiry |
| `punarctl agents alerts dismiss <alert_id>` | files the card; prints `DISMISSED · FILED TO THE RECORD · NOT DELETED` |
| `punarctl agents list` | gains a footer line: `DETECTION · CONTINUOUS · EVERY 4 MIN · LAST CHANGE 13:59 · a process that starts and exits inside one interval is not seen` |
| `punarctl agents access <detection_id>` | now accepts detections; renders the smaller ledger with its `NOT YET OBSERVED` rows |
| `punarctl privacy queries [--since] [--json]` | **§10.3 — the section 24.2 command** |
| `punarctl privacy ledger` | the `REMOTE QUERY` footer line goes live |
| `punarctl privacy purge` | now also purges detection records + their ledgers; prints both boundary sentences (audit trail, query log) |

Verdict lines are uppercased by `fmt::verdict` — the standing lesson —
so every check grep is case-insensitive.

---

## 15. Budgets (spec 6.2–6.4, PERFORMANCE_BUDGETS.md)

- **No new daemon.** `punar-mock-smplify` is never enabled (M5 §4.1) and
  the scan unit is a transient oneshot. `PUNAR_SERVICE_UNITS` in
  `idle-ram.sh` stays `punard.service punar-agentd.service`; the
  combined target (100 MB, ceiling 150 MB) is unchanged and M10's
  resident growth is agentd's alert/detection/query state only — bounded
  by the retention caps in §6.5 and §10.1.
- **Wakeups.** One timer at 240 s, coalescing with the existing 120 s
  reconcile timer under `AccuracySec=30` (§3.2). The scan timer is
  **not** stopped for the idle-RAM window: budgets are measured against
  the shipping configuration, and a 240 s timer is half the frequency of
  one that window has contained since M4.
- **Disk I/O (§6.4).** Steady state is **zero writes** (§3.4). Writes
  occur only on a detection set change, an alert set change, or a query.
  `queries.jsonl` is bounded at 10 000 records; `detections.jsonl`
  prunes at 7 days; both reuse M8's compaction machinery.
- **CPU per pass.** One `/proc` walk — the M7 pass, unchanged in shape,
  plus one extra glob comparison per pid for §3.5. `m10-check` records
  the measured pass duration into the report so the claim is a number,
  not an adjective.

---

## 16. In-VM exercise plan — `m10-check`

`/usr/lib/punar/m10-check.sh`, root oneshot
(`punar-m10-check.service`, **never enabled** — no wants symlink), started
synchronously by `idle-ram.sh` **after `m9-check`**, strictly before the
artifact export. `set -u`, always exits 0; verdict lines into
`/run/punar/m10-report.txt`, final `PUNAR_M10_OK` / `PUNAR_M10_FAIL`;
host gate `tools/boot-test.sh` **phase 12**. Unprivileged commands use
the established session pattern (`runuser -u punar -- env
XDG_RUNTIME_DIR=/run/user/1000 HOME=/home/punar …`). All verdict/status
greps are **case-insensitive**. File comparisons use `sha256sum` — there
is no `cmp` or `diff` in the image.

**Timer determinism.** The check stops `punard-reconcile.timer` at the
top (the m5 precedent — every sync below must be exactly one pass) and
restarts it at the end. It does **not** stop
`punar-agentd-scan.timer`, because group 3 exists to watch it fire; it
restores whatever state it found.

**Cost management.** Group 2 launches the fixture **first**; groups 4–9
(queries, CLI, audit) run while the 240 s period elapses; group 3's wait
is therefore mostly absorbed. Budget for the wait: **300 s**
(240 + 30 accuracy + 30 slack).

### Groups

1. **Preflight.** `punar-agentd.service` active; the scan timer's
   **vendor-wants symlink** present at
   `usr/lib/systemd/system/timers.target.wants/punar-agentd-scan.timer`
   and `Wants=` visible in `systemctl show timers.target` (never
   `is-enabled`); `systemctl show punar-agentd-scan.timer` reports
   `OnUnitActiveSec=240s`, `AccuracySec=30s`, and a
   `NextElapseUSecMonotonic` in the future; `/run/punar-agentd` is
   `0750 root:punar`; the M10 signature data file parses and contains
   `unmanaged-path-agentlike` with `require: "both"`.
2. **Fixture unknown agent.** Install the M7 fixture — a sleeping `sh`
   script at `/home/punar/Downloads/foo-agent`, `0755`, punar-owned —
   and start it as punar. Record the current `agents.json` sha256 and
   the current audit line count. **Issue no `agents scan` from here
   until group 3 completes.**
3. **Periodic detection fires with no manual scan.** Poll
   `/run/punar/agents.json` (a `sleep 10` loop reading a file — not a
   product polling loop; the same shape m4-check uses to await the
   reconcile timer) for up to 300 s until a detection row for
   `foo-agent` appears. Assert: `classification == "unknown"`,
   `suspected == true`; the corresponding audit `agents.scan` event has
   `result == "detected"` and `resource` carrying the trigger `timer`;
   and **no** `agents.scan` event with trigger `manual` exists in the
   window. Record the elapsed time into the report.
4. **Exactly one alert.** `/run/punar-agentd/alerts.json` parses, is
   mode `0640 root:punar`, and contains **exactly one** entry for the
   `foo-agent` signature. Force a second and third pass
   (`punarctl agents scan` twice, now permitted) and re-assert: still
   exactly one alert entry, `last_seen` advanced, and **exactly one**
   `alert_raised` audit event in total. Kill the fixture, scan
   (→ `cleared`), restart the fixture, scan: still **one** alert (the
   24 h quiet window), and the audit shows `detected`/`cleared`/
   `detected` transitions but no second `alert_raised`.
5. **The alert renders (the money shot).** Open the alert surface via
   the session pattern
   (`qs -p /usr/share/punar/shell ipc call alerts open` — the `-p` is
   the standing lesson), settle, `grim /run/punar/punar-m10.png`.
   Assert `punarctl agents alerts` output contains, case-insensitively:
   `SUSPECTED`, the executable path, the signature name, a policy
   citation, and the words `nothing was blocked`; and that it does
   **not** contain `api.foo.ai` (§5.1 — the plate's datum that no code
   produces). **DND rule:** `qs … ipc call alerts dnd on`, clear the
   alert record for a *second* fixture signature
   (`/home/punar/Downloads/bar-agent`), scan, and assert the new alert
   **is present** in `alerts.json` with `quiet: true` (breakthrough,
   §5.5); then scan again and assert no second card. Screenshot failure
   is a recorded `FAIL` line, per the m2 precedent.
6. **Unknown-agent ledger (decision 3).**
   `punarctl agents access <detection_id> --json` returns a
   `result.summary` whose fields are checked with `jq`: `session_id`
   matches `^agt_`, `agent == "foo-agent"`, `process_classes` non-empty,
   `security_events[]` contains an `unknown_ai_execution` reference with
   an `evt_` id, and `repositories` / `network_destinations` /
   `credential_classes` / `mcp_servers` are **empty** with matching
   `not_yet_observed[]` rows carrying milestones. Assert the record
   contains **no** `cwd`, **no** `cmdline`, **no** absolute path under
   `/home` outside the executable field, and that `project == "unknown"`.
   `detections.jsonl` has a schema-shaped record with all ten required
   fields. Export `m10-detection-summary.json` for **host-side** schema
   validation by `tools/validate-schemas.py` in CI — the VM has no
   JSON-Schema validator, so the shape is checked in-VM with `jq` and
   validated properly on the host. That split is deliberate and stated.
7. **Enrolled device answers an authorized query.** Start the mock;
   `punarctl enroll start acme.com`; assert `enroll status --json`
   reports `remote_query_scopes` containing `inventory` and `authority`.
   Enqueue via the mock client:
   `admin.ai_query {admin: "cio@acme.com", scope: "inventory"}` →
   `{status: "pending"}`. Run **one** reconcile pass
   (`punarctl reconcile`). Assert `admin.query_result` now reports
   `answered`; the payload contains the managed session and the
   unknown detection; and it contains **none** of: an executable path,
   a pid, a cmdline, a username, a project other than `unknown`.
8. **Out-of-scope query is refused and audited.**
   `admin.ai_query {admin: "secops@acme.com", scope: "resource_summary"}`
   (role permits it; the **device's** grant does not) → after one
   reconcile pass, `admin.query_result` reports `refused` with
   `reason: "out_of_scope"`. Assert `queries.jsonl` has the row with
   `authorization_decision == "deny"`, and the audit log has one
   `admin.ai_query` event with `decision == "deny"`,
   `result == "refused"`, `source == "organization"`,
   `user_id == "secops@acme.com"`. Also assert the role gate:
   `admin.ai_query {admin: "helpdesk@acme.com", scope: "security_events"}`
   is `denied` **by the mock**, never enqueued, and therefore leaves
   **no** row in the device's `queries.jsonl` — proving the two checks
   are independent.
9. **The user can see the query log.**
   `runuser -u punar -- punarctl privacy queries` (unprivileged!)
   lists all three queries with admin, scope and decision; contains
   `not verified by this device`; contains the never-answered list; and
   `--json` parses. Assert `punarctl privacy ledger`'s `REMOTE QUERY`
   line is live (no longer the M8 `Milestone 10 adds…` placeholder).
10. **Personal device: the path is inert.** `punarctl enroll stop
    --yes`. Enqueue another `admin.ai_query` on the mock. Run **three**
    reconcile passes. Assert: `admin.query_result` still reports
    `pending`; `/var/lib/punar/enrollment.json` is absent;
    `queries.jsonl` gained no row; the mock's connection log gained no
    device connection during the window; `punarctl privacy queries`
    prints the personal-mode sentence and exits **0**; and
    `punarctl privacy ledger` shows the personal `REMOTE QUERY` line.
    Then force the negative directly: `punarctl debug rpc query.answer
    --socket agentd` with a well-formed scope → **`out_of_scope`**,
    proving gate B independently of gate A.
11. **Purge boundary.** `runuser -u punar -- punarctl privacy purge
    --all --yes`: the detection ledger is gone; `queries.jsonl` is
    **unchanged** (sha256 before/after); the audit log still contains the
    `unknown_ai_execution` and `admin.ai_query` events; the purge output
    contains both boundary sentences.
12. **Fleet aggregation and its boundary.** `punar-mock-smplify --fleet`
    output contains `Unknown 1`, `1 unmanaged agent`, and — critically —
    an em-dash `—` (not `0`) on the `accessing source repositories` and
    `production credentials` rows, because no device answered at
    `resource_summary`. Assert the string `0 production credentials`
    does **not** appear.
13. **Negative probes** (spec 74.4, 60, 61).
    `punarctl debug rpc alerts.bogus --socket agentd` →
    `unknown_method`; `alerts.dismiss` on an unknown id → `not_found`;
    as `punar`, `query.answer` → `denied` (root-only); as `nobody`,
    `queries.list` → socket admission failure; `admin.ai_query` with
    `scope: "everything"` → `out_of_scope` at the mock, and the same
    forced at the agentd socket → `out_of_scope`, never a partial
    answer.

**Exports** (under `/run/punar`, swept by the existing tar):
`m10-report.txt`, `m10-agents-file.json`, `m10-alerts.json`,
`m10-alerts-cli.txt`, `m10-detection-summary.json`,
`m10-detections.jsonl`, `m10-queries.jsonl`, `m10-privacy-queries.txt`,
`m10-fleet.txt`, `m10-query-answered.json`, `m10-query-refused.json`,
`punar-m10.png`, plus per-step diagnostics. `ci.yml` uploads them with
the existing artifact sweep; boot-test phase 12 greps the verdict.

---

## 17. Scope table

| Area | In M10 | Out — and where it lives |
|---|---|---|
| Detection cadence | timer, 240 s, three event triggers | exec-time notification / eBPF / fanotify / ptrace — **permanently out** (spec 1.14) |
| Detection inputs | adapter signatures, suspected globs, path-provenance + name (§3.5) | network destinations, MCP activity, credential usage, process lineage, signing provenance — M12 / M9+ / revisit |
| Alert | one card per signature, root-owned state file, D-009 anatomy, dismissal, DND breakthrough | notification centre, freedesktop notification daemon, OSD, persistent DND toggle + capability, grouping, `Punar+N` — **M13** |
| Response to a detection | inform, record, alert | **block / kill / quarantine / `BLOCK NETWORK` / `REGISTER AS MANAGED`** — M12 + a policy verb; M10 renders no dead buttons |
| Unknown-agent memory | persisted record + bounded ledger, 7-day retention, purgeable | repositories, zones, network, credentials, MCP for unmanaged agents — no producer; child-process trees — permanently out |
| Remote query | device-pull on the sync piggyback; four scopes; three-way intersection | **real cloud, real transport (mTLS, device attestation), real discovery** — Phase 2; push / long-poll / inbound listener — **never** |
| Authorization | mock roles from a fixture + device-side re-check | **real RBAC / IdP / SSO / SCIM / role hierarchy / admin authentication** — Phase 2; per-query user consent — §9.3, deferred |
| Query audit | `queries.jsonl`, audit event, `punarctl privacy queries` | org-side audit sync (M5 §12 deferral stands); tamper-evident/signed local logs — Phase 2 |
| Fleet | mock text output, honest `—` vs `0` | **cross-device fleet UI**, dashboards, charts, per-user rollups — Phase 2/3 |
| Risk | classification only | **behavioural risk scoring, anomaly detection, "is this agent dangerous"** — **Phase 3** (spec 78) |
| Retention | 7 d detections, 14 d managed (M8), 365 d query log | org-governed / configurable retention — M10+ (M8 §6.4 stands) |

---

## 18. Deferred, tracked

- **Per-query user consent at answer time** (§9.3) — if it lands, it
  belongs in the enrollment-time grant, not the query path.
- **A build with the enterprise query path compiled out** (§11's honest
  limit) — the stronger unmanaged-first claim; needs a feature-gated
  build and a second image target.
- **Signed / tamper-evident local logs** — `queries.jsonl` and
  `audit.jsonl` are append-only files a root compromise can rewrite.
  Stated in M3 and unchanged.
- **Org-side query audit sync** — the org has its own copy of what it
  asked; reconciling the two records is Phase 2.
- **Detection of agents running as other users on a multi-user device** —
  the pass sees them (root daemon), and the export answers for the
  device; per-user partitioning of alerts and ledgers is untested and
  unstated beyond §6.4's owner field.
- **`observed` agents' alerts.** M10 alerts on `unknown` only. A known
  agent running outside a managed scope is a *policy* conversation
  (should it have been launched through `punar-env`?), not a suspicion,
  and alerting on it would train users to dismiss. Revisit with M12's
  policy verbs.
- **Network destination in the alert** — the plate's `→ api.foo.ai`
  subline returns when M12 can produce it (§5.1).

---

## 19. Definition of done

1. `punar-agentd-scan.timer` ships vendored-wants, fires at 240 s, and a
   detection appears with **no** manual scan — asserted in-VM.
2. The fixture unknown agent produces **exactly one** alert across
   multiple scans, a clear, and a restart; the alert renders in
   `punar-m10.png` and speaks the §5.1 words including *suspected* and
   *nothing was blocked*.
3. A detection has a persisted record and a `ledger-summary.json`-valid
   ledger containing the `unknown_ai_execution` reference and nothing
   from the never-record list.
4. An enrolled device answers an authorized `inventory` query within one
   reconcile pass, over a path with no inbound listener.
5. An out-of-scope query is refused by the **device**, recorded in
   `queries.jsonl`, and audited.
6. `punarctl privacy queries` shows all of it to an **unprivileged**
   user.
7. An unenrolled device answers nothing, records nothing, and connects
   to nothing — proven for gate A *and* gate B separately.
8. `punarctl privacy purge` removes the detection ledger and leaves the
   query log and the audit trail intact.
9. The mock's fleet output distinguishes `—` from `0`.
10. `PUNAR_M10_OK` in `m10-report.txt`; boot-test phase 12 green; CI
    artifacts uploaded; host-side schema validation of
    `m10-detection-summary.json` green.
11. `ipc.md` §17–§20 landed exactly as §13 describes, additively.

---

## 20. Honest limits (spec 1.22)

Written here, and printed on the surfaces named:

- **Sampling detection misses short-lived processes.** A process that
  starts and exits inside one 240 s interval, and touches nothing Punar
  mediates, is never seen. Printed in `punarctl agents list`'s footer
  and in the panel's detection line.
- **Detection is heuristic and says so.** Every surface says
  *suspected*, never *detected AI*. Signatures are data a human wrote;
  false positives and false negatives both exist. Spec 23's own words
  are the product language.
- **M10 is not armed.** Nothing is blocked, killed or quarantined.
  Printed on the alert card.
- **The admin identity is asserted, not verified.** There is no IdP.
  Printed in `punarctl privacy queries` and on every rendering of a
  requesting admin.
- **The control plane is a mock.** UDS instead of mutually-authenticated
  TLS; roles are fixture strings; `--help` says so; the unit is never
  enabled.
- **"Inert" is not "absent".** The enterprise query code ships in every
  binary; three independent gates make it unreachable on a personal
  device, and none of them is the absence of the code (§11).
- **The unknown ledger is nearly empty, and that is the honest state.**
  For an unmanaged agent, Punar mediates nothing, so it observes almost
  nothing. Every empty category renders `NOT YET OBSERVED · MILESTONE n`
  — *not observed*, never *did not happen*.
- **This document was a plan when §1–§19 were written.** §21 is the build
  record: what shipped, which gates were actually executed on the host,
  and — stated plainly — that **nothing in §16 has run in a VM yet**,
  because the CI VM is the only place `m10-check` can execute. **§22 is
  the status of record**: the audit of the whole milestone against spec
  76 M10, the live CI state as of 2026-08-25, and the on-disk-and-static
  versus CI-pending split, item by item against §19.

---

## 21. Build record and verification (image wiring + `m10-check`)

*Written to spec 1.22 by the cluster that landed the systemd wiring, the
in-VM exercise and the host gates, on top of the detection/alert and
remote-query clusters. What is claimed here is what was run; what was not
run is named as such.*

### 21.1 What shipped in this cluster

**Image wiring** (`os/images/mkosi.profiles/desktop/mkosi.extra/`):

- `usr/lib/systemd/system/punar-agentd-scan.timer` — `OnBootSec=240`,
  `OnUnitActiveSec=240`, `AccuracySec=30`, armed by the **vendor**
  symlink `usr/lib/systemd/system/timers.target.wants/punar-agentd-scan.timer`
  (never `/etc`, never `is-enabled` — the M1/M4 lessons). The 240 s
  period is an exact multiple of the shipping 120 s reconcile period, so
  systemd coalesces the two wakeups; the unit file carries that argument
  and the honest limitation, because a unit file is where a reader looks
  for a cadence.
- `usr/lib/systemd/system/punar-agentd-scan.service` — `Type=oneshot`,
  `ExecStart=/usr/bin/punarctl agents scan --trigger timer`. The pass
  runs through the CLI, not inside the daemon, so the timer path is the
  same socket, authorization and audit path a human uses (§3.1).
- `usr/lib/systemd/system/punar-m10-check.service` — root oneshot,
  `TimeoutStartSec=15min`, **never enabled** (no `.wants` symlink),
  started synchronously by `idle-ram.sh` after `punar-m9-check.service`
  and before the artifact export.
- `usr/lib/punar/m10-check.sh` — **committed 0755** (the trap that
  silently skipped M8: a check script without the executable bit fails
  `ExecStart` and the milestone quietly does not run).
- **No new tmpfiles.** Everything M10 writes lands in directories that
  already exist and already carry their modes: `/run/punar-agentd`
  (`0750 root:punar`, M8) for `alerts.json`, and
  `/var/lib/punar/agents` (`0700 root:root`, M7) for `detections.jsonl`,
  `detections-index.json` and `queries.jsonl`.
- **No new daemon**, so `PUNAR_SERVICE_UNITS` in `idle-ram.sh` is
  unchanged (`punard.service punar-agentd.service punar-secrets.service`).
  The scan pass is a transient `punarctl` every four minutes; counting it
  as resident memory would be false, and the timer is deliberately **not**
  stopped for the sampling window — budgets are measured against the
  shipping configuration.
- The `foo-agent` fixture staging is unchanged from M7
  (`usr/lib/punar/foo-agent-fixture.sh`); `m10-check` installs it at
  **two** paths so the DND breakthrough has a genuinely second signature,
  and removes both at exit.

**Host gates**: `tools/boot-test.sh` gains **phase 12** (the
`PUNAR_M10_OK` / `PUNAR_M10_FAIL` verdict, hard-gated exactly like
M2–M9) and **phase 12b** (the exported detection ledger replayed against
the *unchanged* `schemas/ai-agent/ledger-summary.json` on the host,
because the image has no JSON-Schema validator — the same split M9 uses
for the approval document). Export timeouts rise 3600 → 4200 s (KVM) and
7200 → 7800 s (TCG); the `desktop-test` job budget rises 125 → 135 min.
`ci.yml` lints `m10-check.sh` and uploads `m10-report.txt`, `m10-*.json`,
`m10-*.jsonl`, `m10-*.txt` and `punar-m10.png`.

**Interface friction reconciled** (crates, outside the two feature
clusters' authorship, all of it required for §16 to be runnable at all):

- `punar-agentd` gained the two methods the remote-query cluster
  documented as its integration seam and could not write: **`query.answer`**
  (root peer only; the three-way intersection read from
  `enrollment.json` by the data owner; a refusal is a **result**, never
  an error frame) and **`queries.list`** (any admitted peer — spec 24.2),
  plus `crates/punar-agentd/src/queries.rs` (the `0600` append-only query
  log, bounded at 365 days / 10 000 records) and the four scope
  projections. `punarctl privacy queries`, shipped by that cluster, had
  no daemon behind it until this landed.
- `punarctl` gained `agents scan --trigger`, `agents alerts [--all]`,
  `agents alerts dismiss <id>`, the M10 `agents list` footer, and
  `debug rpc --params` (which is what lets the in-VM exercise drive both
  sockets without a second client binary in the image). `alerts.*`,
  `query.*` and `queries.*` now auto-route to the agentd socket.
- `ledger.purge` now also deletes the **detection records**, not only
  their ledgers (decision 11), and the purge surface prints **both**
  boundary sentences (audit trail, query log).
- `ipc.md` §17 gained the two method rows plus §17.8/§17.9 and the
  `admin.ai_query` audit action; §17's heading now names the answered
  query. Additive, still `v: 1`.

### 21.2 Assertions this cluster made stale, and how they now read

M10 fulfils placeholders written by M7 and M8. Every one below was
rewritten to assert the **invariant**, not the old text:

| Was | Now |
|---|---|
| `punar-common::agent` refused `admin.*` with *"reserved for the Milestone 10 shadow-AI detection MVP"* (asserted in `punar-common` and `punar-agentd/tests/registry.rs`) | the refusal states the invariant M10 established — `admin.*` belongs to the **control plane**, nothing on this device listens for an administrator, and `punarctl privacy queries` shows what did arrive. The tests assert that, plus that the word *reserved* is gone |
| the `ledger.*` refusal said *"there is no export, upload, or remote-query method"* | still true about export and upload; it now names the one thing that can leave — an answer to a query the device **fetched**, at a granted scope, recorded locally — and says why that is not a ledger export |
| `punarctl`'s detection footer promised *"continuous detection arrives in Milestone 10"* (asserted in `cli.rs`) | states the cadence (`continuous · every 4 min`) **and** the hole sampling detection has by construction. The test asserts both and asserts the deferral string is gone |
| the privacy-ledger surface said a detection has *"no access ledger in Milestone 8 … Milestone 10"* (asserted in `cli.rs`) | states the ledger's **shape** and its shorter window: a process class, a zone class and the event references, kept 7 days after it clears. The test asserts the invariant and that the old sentence is gone |
| `punarctl agents inspect` skipped the ledger fetch for detections | fetches it, because detections have one now |

Two stale assertions were left for their owners and are named here so the
integrator can see them: **`m8-check.sh` line ~374** asserts that
`not_yet_observed[]` still contains the `unknown_ai_execution` row (M10
shipped its producer, so the row leaves — the documented idiom), and
**line ~381** asserts `Evidence ⊆` the four M8 values (M10 adds
`detection_scan`). Both read a **managed** session's ledger today, so
both still pass; both should be widened to assert the partition rather
than the list.

### 21.3 Verification (run, not asserted)

| Gate | Result |
|---|---|
| `cargo fmt --all` (docker `rust:1`) | applied; `--check` clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo test --workspace` | all green, including 5 new `punar-agentd/tests/remote_query.rs` integration tests and 3 new `punarctl/tests/cli.rs` tests |
| `./tools/validate-schemas.sh` | 15 schemas, 132 documents, ALL PASS |
| `shellcheck` v0.11.0 (pinned) | clean on `m10-check.sh`, `idle-ram.sh` and `boot-test.sh` |
| `actionlint` | clean |
| `PUNAR_BUILD_MODE=summary ./tools/build-image.sh` | succeeds |
| `qmllint` 6.11.2 (pinned container) | 14 `.qml` files, zero warnings |
| **every `jq` filter in `m10-check.sh`** | **replayed against real documents** — 40 filters against `agents.json`, `alerts.json`, the `alerts.list` result, `agents.access`, the detection summary, `detections.jsonl`, `detections-index.json`, `queries.jsonl`, `enroll.status`, and the mock's `admin.ai_query` / `admin.query_result` documents, all produced by running the real daemons and the real mock. 39 evaluated **true**; the fortieth (the DND breakthrough card) evaluated true against a document carrying the second signature. **None** exited 5 — the M9 failure mode where a broken filter silently reports "false" |

**NOT run, and why.** There is no VM on this machine, so **nothing in
§16 has executed**: the timer has never been observed firing, no alert
card has been screenshotted, no query has crossed a real reconcile pass,
and `punar-m10.png` does not exist yet. Everything in §16 is *designed
and gated*, not *observed*. The first CI run on this branch is the
evidence, and until it is green no sentence anywhere may claim M10
passed in the VM.

**Two in-VM behaviours are predicted rather than proven**, and are called
out because they are where a first run is most likely to fail:

1. **The alert may already exist when `m10-check` starts.** The scan
   timer has been running since `OnBootSec=240`, and `m7-check` installs
   and runs the same `foo-agent` fixture earlier in the same boot. The
   anti-nag rule makes that *correct* — one card per signature, no
   re-raise inside the 24 h window — and the exercise is written for it:
   group 2 kills leftovers and records the detection ids that already
   exist, and group 3 requires a **new** one. The alert-raise count
   assertion (`exactly one`) holds whether the raise happened in M7's
   window or this one, which is the property being asserted.
2. **The shell's card may have been drawn in an earlier window.** The
   alert region never re-toasts a known `alert_id`, so `alerts cards`
   reports a card that has been standing since M7's window rather than
   one drawn during group 5. The assertion is that a card is drawn and
   that the screenshot shows it — both hold either way; the DND
   breakthrough uses a genuinely new signature (`bar-agent`) precisely so
   it cannot be satisfied by a standing card.

**`PUNAR_SERVICES_RSS_MB` is unchanged by M10** — no new daemon — and no
number is quoted here, because the only honest source is a CI run's
`punar-desktop-ram-report` artifact.

---

## 22. Status — audited 2026-08-25

*This section is the status of record for M10. §21 is the build record
written by the cluster that landed the wiring; this section is the audit
of the whole milestone against spec 76 M10, and it separates what is
**on disk and statically verified** from what is **CI-pending** — a
distinction spec 1.22 makes mandatory, because M10 is the milestone whose
central claims (a timer fires; a card is drawn; a query crosses a
reconcile pass) are only observable in a VM.*

### 22.1 Delivery state, stated plainly

**Implemented on disk. Uncommitted. No CI run contains one byte of M10.**

- `origin/main` is `7943f3c` ("Repair M5/M8/M9"). Local `main` is **five
  docs-only commits ahead** (`dab66ae` user-blocked list, `8a38c8f` +
  `e6f20dc` ADR-003, `a273d0d` competitive position, `b31a031` design:
  theme system / app catalog / execution trust) — **none** of them M10.
- Every M10 artefact is **working-tree only**: **48 modified files and 21
  new paths** (two of those paths are directories holding one file each),
  including `crates/punar-agentd/src/{alerts,detections,
  identity,queries,sha256}.rs`, `crates/punar-common/src/query.rs`,
  `crates/punard/src/agentd.rs`, `crates/punar-mock-smplify/src/{rbac,
  fleet}.rs`, four new test files, `shell/punar-shell/Alert/AlertStack.qml`,
  `shell/punar-shell/Services/Alerts.qml`, the two scan units, the
  vendor `timers.target.wants` symlink, `punar-m10-check.service`,
  `usr/lib/punar/m10-check.sh`, `fixtures/organizations/acme/admins.json`,
  and `ipc.md` §17–§20.
- `m10-check.sh` is mode **0755 on disk** (`-rwxr-xr-x`). It is *not yet
  committed*, so the M8 trap — a check script committed `100644`, whose
  oneshot then fails `ExecStart` while the run goes green — is **avoided
  but not yet proven avoided**. The bit must survive `git add`; verify
  with `git ls-files -s …/m10-check.sh` reading `100755` before pushing.
- **Warning for whoever commits this tree:** `git status` also shows
  `target-docker/` and `target-docker-ctl/` as untracked — **8.1 GB** of
  container build cache that `.gitignore` does not cover (it lists
  `target/` only). They are not M10 artefacts. A `git add -A` here would
  commit them. Either extend `.gitignore` or stage M10's paths explicitly.

### 22.2 The live CI state, recorded as it is

The newest run is
[**32899132191**](https://github.com/smplify-mdm/punar/actions/runs/32899132191)
(commit `7943f3c`, 2026-08-25 21:05 UTC, 33m37s) and it is **green on all
five jobs**. The M5/M8/M9 repair resolved **green**:

| In-VM exercise | Verdict | Assertions |
|---|---|---|
| desktop gate | `PUNAR_DESKTOP_OK` after 20 s (KVM) | — |
| M2 | `PUNAR_M2_OK` | 33 |
| M3 | `PUNAR_M3_OK` | 28 |
| M4 | `PUNAR_M4_OK` | 29 |
| M5 | `PUNAR_M5_OK` | 63 |
| M6 | `PUNAR_M6_OK` | 55 |
| M7 | `PUNAR_M7_OK` | 74 |
| **M8** | **`PUNAR_M8_OK` — the first M8 verdict that has ever existed** | **123** |
| **M9** | **`PUNAR_M9_OK` — the first M9 verdict that has ever existed** | **137** |
| | **total** | **542** |

Also from that run: the M9 approval document exported from the guest
**validates host-side** against the unchanged
`schemas/audit/approval.json` (boot-test phase 11b, `[PASS]`); idle RAM
**mean 1155 MB / max 1160 MB** — under the 1536 MB hard ceiling, over the
1024 MB target, carried as the standing CI warning; services RSS **6 MB**
summed over the three daemon cgroups.

**So both of M10's inherited "never run" caveats are now closed by
evidence, not by assertion:** M8's ledger and M9's approval gate are
CI-exercised, and the two milestones M10 builds on are proven at runtime
before M10's first line of CI. M10 is the only milestone in the tree with
**zero** in-VM evidence.

### 22.3 On-disk and statically verified vs CI-pending, per §19

| §19 item | On disk | Statically verified | CI-pending |
|---|---|---|---|
| 1 — scan timer ships vendor-wants, fires at 240 s, detection with no manual scan | unit + service + `timers.target.wants/punar-agentd-scan.timer` symlink | unit text asserted by review; `OnUnitActiveSec=240`, `AccuracySec=30` present | **the fire itself** — never observed |
| 2 — exactly one alert across scans/clear/restart; renders in `punar-m10.png`; speaks the §5.1 words | `alerts.rs`, `AlertStack.qml`, `Alerts.qml`, m10-check group 4/5 | anti-nag logic unit-tested; card copy reviewed against Plate D-009 | **the card, the screenshot, the DND breakthrough** |
| 3 — detection has a persisted record + `ledger-summary.json`-valid ledger | `detections.rs`, `detections.jsonl` writer, ledger projection | `cargo test` green; schema validator green on the shipped corpus | **the exported `m10-detection-summary.json` replayed against the schema (phase 12b)** |
| 4 — enrolled device answers an authorized `inventory` query in one reconcile pass | `punard/src/agentd.rs` courier, `queries.rs`, mock `queries.pending`/`answer` | 5 `remote_query.rs` integration tests | **the pass, end to end, over a real timer** |
| 5 — out-of-scope query refused **by the device**, recorded, audited | three-way intersection reading `enrollment.json` | integration-tested | **the in-VM refusal + `queries.jsonl` row** |
| 6 — `punarctl privacy queries` shows it to an **unprivileged** user | CLI + `queries.list` (any admitted peer) | CLI tests | **the `runuser -u punar` path** |
| 7 — unenrolled device answers/records/connects nothing (gates A *and* B) | M5 sync gate + agentd fail-closed | tested at unit level | **the three-pass inert window and the forced `query.answer` probe** |
| 8 — purge removes the detection ledger, leaves query log + audit intact | `ledger.purge` widened to detection records | tested | **the sha256 before/after in-VM** |
| 9 — fleet output distinguishes `—` from `0` | `fleet.rs` | tested | **the rendered text** |
| 10 — `PUNAR_M10_OK`, phase 12 green, artifacts uploaded | `m10-check.sh` (13 groups, **~113 static assertion sites** — 80 helper calls + 33 hand-written assertion blocks — plus 10 stated-gap `info` lines), boot-test phase 12 + 12b, ci.yml uploads | shellcheck clean; every `jq` filter replayed (§21.3) | **the verdict — no `PUNAR_M10_OK` exists anywhere** |
| 11 — `ipc.md` §17–§20 landed additively, still `v: 1` | §17 (agentd: `alerts.list`, `alerts.dismiss`, `query.answer`, `queries.list`, amended `agents.scan`/`agents.list`), §18 (punard courier), §19 (control plane), §20 (`alerts.json` side contract) | **done — verified by reading the file** | — |

Ten of eleven done-conditions are **designed and gated, not observed**.
The honest one-line summary: *M10 is implemented and statically clean;
nothing in §16 has ever executed.*

### 22.4 Static gates re-run by this audit (not inherited claims)

Run on this machine, 2026-08-25, against the working tree as audited:

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` (docker `rust:1`) | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo test --workspace` | **840 passed / 0 failed** across 34 suites (was 719 at M9) |
| `./tools/validate-schemas.sh` | **15 schemas metaschema-checked, 132 documents, ALL PASS** — no schema was edited by M10 (the Decision-0 law holds for a third milestone) |
| `shellcheck` v0.11.0 (pinned) on `m10-check.sh`, `idle-ram.sh`, `boot-test.sh` | clean |

Not re-run by this audit, and therefore **inherited from §21.3 rather
than re-observed**: `actionlint`, `qmllint` 6.11.2 (pinned container),
and `PUNAR_BUILD_MODE=summary ./tools/build-image.sh`. They are recorded
there as green against the same tree; this section does not restate them
as its own measurement.

### 22.5 Assertions and printed text this milestone makes stale

§21.2 lists the placeholders M10 **already rewrote** to assert the
invariant. What remains open for the integrator:

1. **`m8-check.sh` line 371** — asserts the Level-4 `not_yet_observed[]`
   set is exactly
   `["production_access","sensitive_resource_access","unknown_ai_execution"]`.
   M10 ships `unknown_ai_execution`'s producer, so that row leaves the
   list for any ledger that has one. It reads a **managed** session's
   ledger today, so it still passes; widen it to assert the **partition**
   (every Level-4 category is either produced or named with a milestone)
   rather than the literal three.
2. **`m8-check.sh` line 375** — asserts `evidence ⊆ {cgroup_scope,
   audit_event, workspace_bind, adapter_metadata}`. M10 adds a fifth
   value, `detection_scan` (`punar-common/src/ledger.rs:553`). Same
   situation: passes today because the document under test is managed;
   widen it to "every evidence value is a named mediation point", which
   is the invariant M8 meant.
3. **`tools/boot-test.sh` line 643** prints *"Services RSS from guest
   (summed PSS, **punard + punar-agentd** cgroups)"* while
   `idle-ram.sh` has summed **three** units since M9
   (`punard.service punar-agentd.service punar-secrets.service`). The
   number is right; the label under-reports what it covers. Pre-existing,
   not M10's doing, but it is a status-facing print and it is wrong.
4. **`.github/workflows/ci.yml` line 378** names the desktop step
   *"M2..M9 exercises"* and line 306's comment says *"M2..M8"*, while the
   job name (line 335) already says **M2..M10**. Cosmetic, and exactly
   the kind of drift that later gets read as evidence.

M10 introduces **no** new placeholder of its own that a later milestone
must come back and delete: every unobservable category renders as a
`not_yet_observed[]` row carrying its owning milestone, which is a data
row, not a sentence for a human to remember.

### 22.6 What the first M10 CI run will decide

§21.3 already names the two predicted-not-proven behaviours (a standing
alert from `m7-check`'s fixture in the same boot; a card drawn in an
earlier window). Beyond those, the first run decides three things this
audit cannot:

- whether a 240 s timer **actually coalesces** with the 120 s reconcile
  timer under `AccuracySec=30` in the CI VM, or merely runs beside it —
  the wakeup claim in §3.2 and §15 is arithmetic until a run shows it;
- the four-daemon-era `PUNAR_SERVICES_RSS_MB` (still three daemons; M10
  adds none) and whether M10's resident alert/detection/query state moves
  the 6 MB measured on 2026-08-25 at all;
- whether the 300 s group-3 wait really is absorbed by groups 4–9, or
  whether `desktop-test` needs more than the 135 min it was raised to.

Until that run is green, **no sentence in this repository may say M10
passed**, and this section is the place that says so.
