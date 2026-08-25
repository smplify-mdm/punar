# Milestone 9 — Approval gates + secret broker: design plan

Spec authority: section 76 Milestone 9 ("Deliver local graphical
approval, short-lived mock credentials, and redaction tests"), grounded
in section 28 (approval gates — the approval object, local graphical
approval, keyboard approve/deny, expiration, audit, typed capability
execution after approval), 29 (secret broker — mock provider,
short-lived token, expiration, deny path, redaction tests), 48
(just-in-time privilege — `punarctl privilege request`, "Approved for 15
minutes", "No generic unrestricted root-shell API"), 20 (AI authority
model — `allow` / `deny` / `approval_required`, and the `credentials`
block's `allow` / `deny` / `request`), 10 (typed capability API;
`RequestCredential(scope)`, `RequestPrivilege(capability)` are named
capabilities, `RunRootShell(command)` is prohibited), 11.1 (`punard`
owns local policy and audit events), 11.4 (`punar-secrets` is its own
service), 53 (audit; never log secret values), 60 (hard safety
constraints — no persistent unrestricted root, no bypassing AI policy
enforcement), 61 (local IPC security), 73 (restriction voice), 39 (the
policy ladder), 6.2–6.4 (budgets, no polling, batched disk I/O), 1.22
(honesty), 74.4 (security tests).

Binding prior contracts, **not relitigated**:

- `schemas/audit/approval.json` — **SHIPPED. M9 conforms to it; it does
  not conform to M9.** Every byte punard persists or serves as *the
  approval* validates against it as-is. Everything M9 needs that the
  schema cannot hold travels as **sibling fields of the envelope**,
  never inside the document (§2). This is the M8 Decision-0 law applied
  to a second schema.
- `schemas/audit/audit-event.json` — **SHIPPED and NOT extended.** M9
  adds no property to it (§2.3 records the rejected alternative).
- `schemas/policy/ai-policy.json` — the section 20 document shape,
  including its two distinct enums (`host`/`network` use
  `allow|deny|approval_required`; `credentials` uses
  `allow|deny|request`).
- `docs/api/ipc.md` §1–§13 — transport, framing, envelope, versioning,
  error codes, the punard and agentd method tables, the M8 attribution
  rule §12.5. M9 adds §14–§16 **additively, still `v: 1`**.
- `docs/development/milestone-7.md` and `milestone-8.md` — managed
  launch, scope attribution, the ledger, the check mechanics and their
  hard lessons.
- `docs/design/mockups/command-approval.html` (**Plate D-003 Sect II —
  the approval overlay is the acceptance reference**),
  `docs/design/mockups/identity-elevation.html` (**Plate D-012 Sect I/II
  — human JIT privilege and the broker issuance card**),
  `docs/design/mockups/cli-grammar.html` (Plate D-014, register 05 — the
  in-terminal approval prompt), `DESIGN_LANGUAGE.md` §8
  (unmanaged-first: personal mode cites PERSONAL DEFAULTS, org citations
  only when enrolled).

M3 made capability mutation root-only and told the truth about it: the
denial message has said *"just-in-time elevation arrives in Milestone
9"* since M3, and `capabilities.set` from a non-root peer has exited 3
ever since. M7 gave agent sessions an `agt_` identity and a
kernel-attested cgroup. M8 made punard attribute every capability call
made from inside a managed agent scope, and left `credential_classes`,
`credential_request` and `policy_bypass_attempt` in the ledger's
`not_yet_observed[]` with **`milestone: "M9"`** written on them.

M9 pays all four debts at once, and adds exactly one new capability
*kind* to the system: **the ability of a human being at this device to
say yes, once, to a specific typed call.**

---

## 0. The architectural law of this milestone

Four rules. Every decision below is downstream of them.

**Law 1 — An approval is a gate, not a notification.** The capability
does not execute until a human resolves the approval. There is no code
path in which the request proceeds and the human is merely told. Spec
28: "typed capability execution *after* approval".

**Law 2 — An AI agent may never approve anything.** Not its own request,
not another agent's, not a human's. This is enforced in code at the
strongest mediation point M9 owns (the kernel-attested cgroup, ipc.md
§12.5), tested in-VM, and it is a section-60-class rule: an approval
gate an agent can answer is not a gate. §4.4 states its honest limit
rather than pretending it is a sandbox.

**Law 3 — A secret value never leaves the broker except once, to the
caller, on a file descriptor.** It is never written to a file, never put
in an audit event, a ledger, a state file, a summary file, an
environment variable, an argv, a log line, or the shell. The broker
itself keeps only `sha256(token)` after issuance, so **there is no
method, anywhere in Punar, that can return a token a second time.** §6.

**Law 4 — Nothing is invented that has no producer.** M9 makes
`credential_classes`, `credential_request` and `policy_bypass_attempt`
real because it ships their producers. It does **not** touch
`mcp_servers`, `network_destinations`, `production_access` or
`sensitive_resource_access`, and it **re-milestones** M8's rows for
those honestly (§9.3) rather than leaving a promise M9 did not keep.

---

## 1. Scope

**In:**

- `punar-secrets` as its **own daemon** (§3), socket
  `/run/punar-secrets/secrets.sock`, a mock provider serving credential
  classes from a shipped fixture, short-lived tokens, expiry, revoke,
  deny path, full redaction (§6).
- The **approval engine inside punard** (§4): store
  `/var/lib/punar/approvals/`, lifecycle `pending → approved | denied |
  expired`, lazy expiry, human-only resolution, execution-on-resolve for
  the capabilities punard owns, consumption-on-demand for credentials.
- **AI authority evaluation in punard** (§5): a shipped personal-defaults
  AI authority document, a capability→section-20-token map, and the
  `approval_required` decision becoming a real runtime outcome for
  agent-originated mutations. No new capability is invented.
- **JIT privilege** (§7): `punarctl privilege request --capability
  --reason --duration`, a human approval, a time-boxed grant in
  `/var/lib/punar/grants/` that punard consults, real expiry, `revoke`,
  and the bar chip. No permanent local admin, ever.
- **The approval overlay** (§8) per Plate D-003 — a new Quickshell layer
  overlay driven by a `FileView` on a new root-owned summary file, live
  countdown, `A`/`D`/`Esc`, `IpcHandler { target: "approval" }`.
- **punarctl** verbs (§10): `approvals list|get|resolve|wait`,
  `privilege request|status|revoke`, `secrets list|get|validate|revoke`;
  exit code **4 = `approval_required`** stops being reserved and becomes
  real.
- **M8 integration** (§9): the ledger's `credential_classes` and
  `credential_request` fill from real `credential.request` events, and
  `policy_bypass_attempt` fills from a refused self-approval.
- **`m9-check`** (§12) + boot-test phase 11 + `punar-m9.png`, with the
  **redaction grep as the headline assertion**.

**Out (documented, never silently dropped):**

- A real (non-mock) credential provider — spec 29's MVP is a mock, and
  the `SIMULATED · MOCK PROVIDER` tag stays on every surface (D-012
  Sect II.04). No network code ships in `punar-secrets`;
  `RestrictAddressFamilies=AF_UNIX` and `PrivateNetwork=yes`.
- PAM/polkit re-authentication at the moment of approval. M9's
  authorization factor for *resolving* is **presence plus the routed
  user**, and §4.4 states that limit in full rather than implying
  cryptographic proof of a human.
- Remote/org approval routing (spec 28 says "local graphical approval";
  Smplify-side approval is out of the MVP).
- A graphical privilege dialog. Plate D-012's *dialog* is deferred to
  M13 polish; M9 ships the CLI (§7), the **bar chip** (D-012 Sect I.03)
  and the overlay for approvals. Stated, not silently skipped.
- MCP/tool gateway (spec 26) — no producer in M9, and the ledger row is
  re-milestoned accordingly (§9.3).
- Secret *scoping* per project/environment beyond the class name; §29's
  request example carries `project`, and M9 has no unforgeable project
  mediation point at the broker (§6.6).

---

## 2. The schemas are the contract

### 2.1 `approval.json` is not extended

The shipped document has exactly nine required properties and
`additionalProperties: false`: `approval_id`, `requester{type,id}`,
`user`, `capability`, `resource`, `reason`, `risk`, `status`,
`expires_at`. It has **no** field for a desired state, a decision
timestamp, an executor, an execution result, a consumption marker, or a
TTL.

M9 therefore stores an **envelope** whose `approval` member *is* the
schema document:

```json
{"v": 1,
 "approval": {
   "approval_id": "apr_7c1d9a4e",
   "requester": {"type": "ai_agent", "id": "agt_4f21c09ab3e1"},
   "user": "punar",
   "capability": "security.firewall",
   "resource": "disabled",
   "reason": "Atlas integration test needs the host firewall down",
   "risk": "high",
   "status": "pending",
   "expires_at": "2026-08-25T10:05:00Z"
 },
 "kind": "capability_set",
 "created_at": "2026-08-25T10:00:00Z",
 "request": {"method": "capabilities.set",
             "params": {"capability": "security.firewall",
                        "desired_state": "disabled"}},
 "requester_peer": {"uid": 1000, "agent_session_id": "agt_4f21c09ab3e1"},
 "policy_ids": ["personal-defaults"],
 "resolved_at": null, "resolved_by": null,
 "consumed_at": null,
 "execution": null}
```

`jq .approval <file> | validate` passes against `approval.json`
unmodified. Every sibling is outside the document. This is the M8
Decision-0 law, second application; downstream agents must not "just add
a field" to the schema.

### 2.2 `status` never leaves the shipped enum

`pending | approved | denied | expired`. Consumption of an approved
credential approval is the sibling `consumed_at`, **not** a fifth status
value. Execution of an approved capability approval is the sibling
`execution` object, **not** a status value.

### 2.3 `audit-event.json` is not extended either

**The pointer runs the other way.** Assertion (d) of the exercise wants the executed capability "audited
with the approval id". `audit-event.json` is closed and has no
`approval_id`. Two ways out were considered:

- **Rejected:** add an optional `approval_id` property. It is
  technically additive, but it opens a schema we declared shipped, for a
  link the design already draws in the opposite direction.
- **Chosen:** Plate D-003 prints *"✓ Approved · InstallPackage(libvirt)
  executed · audit evt_501"* — **the approval card references the audit
  event**, exactly as M8's ledger references events by `event_id`. So:
  - the approval envelope's `execution.audit_event_id` names the `evt_`
    id of the capability execution; and
  - the `approval.resolve` audit event carries `resource: "apr_7c1d9a4e"`
    — the approval id *is* the resource of a resolve action.

The audit trail alone therefore names the approval, and the approval
record alone names the audit event. Both directions are asserted in
§12 group 5. Zero schema bytes change.

### 2.4 The `resource` field, defined once for all three request kinds

`resource` is *the concrete argument of the typed call*, so that
`capability(resource)` reads as the contract block Plate D-003 draws.

| Request kind | `capability` | `resource` | Renders as |
|---|---|---|---|
| `capability_set` | the registry capability id | the desired-state value | `SetFirewall(disabled)` |
| `credential_request` | `credential.request` | the credential class | `RequestCredential(aws-dev)` |
| `privilege_request` | the capability being elevated | the grant window token, e.g. `15m` | `RequestPrivilege(security.firewall, 15m)` |

`credential.request` and `privilege.request` are typed **methods**, not
desired-state registry entries: the M9 capability registry is still
exactly `security.firewall`, `system.hostname`, `time.timezone`.
`approval.json` binds `capability` to the `capability_id` *pattern*, not
to registry membership, and `audit-event.json` already documents
`action` as "not restricted to registered capabilities". Nothing is
faked to make this fit.

### 2.5 New fixtures (all schema-validated in CI)

`fixtures/audit/valid/approval.m9-capability-set.json`,
`approval.m9-credential.json`, `approval.m9-privilege.json` (the
`.approval` member of each envelope shape above);
`fixtures/audit/invalid/approval.m9-consumed-status.json` (proves
`"status": "consumed"` is rejected);
`fixtures/policies/ai-policy-personal-defaults.yaml` (§5.2) added to the
`tools/validate_schemas.py` glob map next to
`fixtures/policies/ai-policy-*.yaml`, which already validates against
`schemas/policy/ai-policy.json`.

---

## 3. Topology — decision and consequences

### 3.1 `punar-secrets` is a separate daemon. Recommended, per spec 11.4.

Spec 11.4 names it as a core local service. There is no blocker; there
are four independent reasons it is also the right call:

1. **Blast radius.** The process that holds plaintext tokens in memory
   must be the smallest and most hardened on the device. punard writes
   `/etc/hostname` and `/etc/localtime`, shells out to `nft`, holds
   enrollment state and speaks to the control plane. Folding the broker
   into it makes every apply backend a secret-adjacent code path.
2. **A provable "never written to disk".** A separate unit can ship with
   **no state directory at all** — the strongest possible form of the
   §29/§53 promise is a daemon that has nowhere to write. punard
   demonstrably writes `/var/lib/punar`; the claim would become a code
   review instead of a filesystem fact.
3. **Hardening punard cannot have.** `ProtectSystem=strict`,
   `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`,
   `MemoryDenyWriteExecute=yes`, `LockPersonality=yes`,
   `ProtectKernelTunables/Modules/Logs=yes`,
   `SystemCallFilter=@system-service`, `UMask=0077`,
   `ReadWritePaths=` limited to `/run/punar-secrets` and
   `/var/log/punar` (audit only). A real provider would one day need
   network; **not pre-granting it** is only possible if it is its own
   unit.
4. **Restart semantics.** Restarting the broker drops every live token —
   which is correct and harmless. Coupling token lifetime to punard's
   lifetime would mean `reconcile`, enrollment and every punard restart
   silently revoke credentials.

**Not socket-activated.** `Type=simple`, always on, no idle exit: token
TTLs are wall-clock promises, and a broker that systemd can stop between
requests would either lose live tokens or need to persist them — the one
thing Law 3 forbids. The RAM cost of always-on is paid honestly in §11.

**Layout:**

```text
# usr/lib/tmpfiles.d/punar-secrets.conf
d /run/punar-secrets 0750 root punar -
```

Socket `/run/punar-secrets/secrets.sock`, created with a restrictive
umask then `chown root:punar` + `chmod 0660` **before** `listen()` —
byte-for-byte the punard §1.2 and agentd §10.1 pattern. Admission is the
filesystem; `SO_PEERCRED` at `accept()` is the authorization input; the
peer's `/proc/<pid>/cgroup` is read for the M8 attribution rule.
Enablement is a **vendor `.wants` symlink**:
`usr/lib/systemd/system/multi-user.target.wants/punar-secrets.service`
(mkosi applies Arch presets to `/etc` *after* extra trees — the
twice-verified M1 lesson). `m9-check` asserts the **symlink plus
`Wants=` in `systemctl show multi-user.target`**, never `is-enabled`
(the M4 lesson).

`After=punard.service` — **ordering only, no `Wants`/`Requires`.** The
broker dials punard's socket for approvals; if punard is down, a
credential class whose policy is `request` fails with
`upstream_unreachable` in the §73 voice and **issues nothing** (fail
closed). Classes whose policy is `allow` still issue, and classes whose
policy is `deny` still deny — neither needs punard.

### 3.2 The approval ENGINE lives in punard. One store, one audit path.

Spec 11.1 assigns punard "local policy" and "audit events". Spec 11.3
assigns punar-agentd "registry, identity, policy, attribution, and
access-ledger". The D-003 mockup's implementation note guesses "punard-
agentd's typed approval API"; that note predates M3–M8 and is a
**data-path sketch, not a contract** — the binding parts of the plate
are its layout, grammar and behaviour, all of which M9 honours exactly.
punard is chosen because:

- **One store.** Approvals gate punard capabilities *and* broker
  issuance *and* human elevation. Two stores would mean two expiry
  sweeps, two lock orders, two truths about `pending`.
- **One audit writer.** `punar_common::audit`'s writer and rotation lock
  already serialize punard and agentd; adding a third *writer* is fine,
  adding a second *approval authority* is not.
- **The executor is already there.** For `capabilities.set`, resolving
  an approval must run apply+verify as root — which is punard's job and
  nobody else's. Placing approvals in agentd would require agentd to
  dial punard to execute, i.e. a mutation path into the daemon M7
  deliberately kept mutation-free ("it never dials punard's socket",
  `punar-agentd.service`).
- **punard already has the requester's identity.** The M8 attribution
  rule (`agent_session_of_peer`) runs in punard at `accept()`.

**punar-secrets consults punard over the existing socket.** It runs as
root, so admission and the root-only `approvals.create` are satisfied.
It stores no approvals.

### 3.3 The one cycle, and why it is not one

Naively, `credential.request` would create an approval in punard, and
punard-on-resolve would call back into punar-secrets to issue — a
dependency cycle, and worse, a plaintext token inside punard's address
space, destroying the entire reason for §3.1.

So **execution ownership follows capability ownership**:

| Kind | On `approvals.resolve(approved)` | Who executes |
|---|---|---|
| `capability_set` | punard **executes immediately**, in the resolver's request, under the store lock. Exactly-once by construction. | punard |
| `privilege_request` | punard **writes the grant** immediately. | punard |
| `credential_request` | punard **does nothing but flip the status.** The broker later calls `approvals.consume` and issues. | punar-secrets |

An approved credential approval is therefore a *precondition*, and an
approved capability approval is a *work order*. The secret never crosses
into punard. punard never calls punar-secrets. There is no cycle.

### 3.4 Shared code, not copied code

`agent_session_of_peer` / `agent_session_in_cgroup` currently live in
`crates/punard/src/authz.rs`. punar-secrets needs the identical rule
(its `credential.request` events must carry `agent_session_id`, or M8's
ledger promise cannot be kept). **Promote both functions and their
tests to `punar_common::principal`**, and have punard and punar-secrets
call the one implementation. Internal refactor; no wire change; one
test suite; no chance of the two daemons disagreeing about who an agent
is.

---

## 4. Approval lifecycle (spec 28)

### 4.1 Store

```text
/var/lib/punar/approvals/                 0700 root:root  (tmpfiles)
/var/lib/punar/approvals/<apr_id>.json    0600 root:root
/var/lib/punar/approvals/index.json       0600 root:root
```

Root-only, for the M8 ledger's reason restated: **an approval a peer can
rewrite is an authorization forgery.** `index.json` carries `{v,
updated_at, approvals: [{approval_id, kind, status, requester, capability,
resource, expires_at, created_at, resolved_at}]}` so `approvals.list`
and the summary rewrite never open every file. Writes are atomic
tmp + `fsync` + `rename`, one per state transition — approvals are
user-paced events, so §6.4's write-amplification rule is satisfied by
there being almost no writes.

**Bounds (approval fatigue is the classic attack on an approval gate):**
at most **8 pending device-wide** and **2 pending per requester
session**; beyond either, `approvals.create` returns `denied` with
`result: "approval_flood"`, audited, and the requesting call gets a §73
message that names the limit. At most 200 records retained; oldest
**resolved/expired** evicted first; ≤ 4 KiB per file.

### 4.2 TTL — 300 s, and why

**Default 300 s (5 minutes)**, matching Plate D-003's countdown
verbatim (`Expires 04:59`, amber under a minute). It is long enough for
a human to read a contract block and decide, short enough that an
unattended machine cannot accumulate a queue of live authorizations, and
it is the number the design already drew — the countdown in the mockup
is the specification of the countdown in the shell.

The **requester may request a shorter TTL, never a longer one**
(`--ttl`, clamped to `[15 s, 300 s]`). Shortening only reduces the
requester's own chance of being approved, so it is safe to allow and
useful for tests. The **maximum is policy-owned**, not requester-owned.

For `privilege_request`, the approval TTL (how long the human has to
answer) and the **grant duration** (how long privilege lasts) are two
different clocks: 300 s and 15 minutes respectively (§7).

### 4.3 The caller does not block, and the agent cannot hang

**`capabilities.set` and `credential.request` never block.** They return
the new `approval_required` error immediately:

```json
{"code": "approval_required",
 "message": "<§73 prose>",
 "details": {"approval_id": "apr_7c1d9a4e", "expires_at": "…",
             "capability": "security.firewall", "resource": "disabled",
             "decision": "approval_required", "policy_ids": ["personal-defaults"]}}
```

punarctl maps it to **exit code 4**, which has been reserved for exactly
this since M3. Rationale, stated because it is the load-bearing choice:
ipc.md §2 gives every method a **10 s processing bound** and processes
requests on a connection **sequentially**; a method that blocked for
five minutes would blow the bound, pin a connection, and make punard
stateful in the worst place. A gate that holds the caller hostage is
also a worse gate — the human's decision must not be coupled to the
requester still being alive.

The waiting UX is a **client** concern:

```text
punarctl approvals wait apr_7c1d9a4e [--timeout <s>]
```

implemented as an **inotify watch on the summary file**
(`/run/punard/approvals.json`, §8.1) with a deadline of
`min(--timeout, expires_at)`, then one authoritative `approvals.get`
after each wake. No polling loop anywhere (§6.3); **watch for the wake,
socket for the truth** — the same law as ipc.md §9/§11/§13.2. Default
timeout is `expires_at`, so:

> **The agent path cannot hang forever. Its hard ceiling is the approval
> TTL — 300 s worst case, and the wait returns exit 4 (`still pending`),
> 0 (`approved`, with the execution result printed), 3 (`denied`) or 1
> (`expired`).**

`punarctl capabilities set … --wait` is sugar for *set → wait → print
the execution result recorded on the approval*. It never re-issues the
call: execution already happened at resolve time (§3.3).

### 4.4 Resolution is human-only — Law 2, enforced in code

```text
approvals.resolve {approval_id, decision: "approved"|"denied"}
```

Permitted **iff all three hold**:

1. the peer is **not attributed to any agent session** —
   `punar_common::principal::agent_session_of_peer(peer)` is `None`; and
2. `peer.uid == 0`, **or** `peer.uid`'s username equals the approval's
   `user` field (approvals are *routed* to a person; only that person
   answers); and
3. the approval is `pending` and not past `expires_at`.

Rule 1 is the hard rule. A resolve attempt from inside a
`punar-agent-<id>.scope` is refused **before any other check**, with
`denied`, audited as `action: "approval.resolve"`, `resource: "apr_…"`,
`decision: "deny"`, `result: "self_approval_refused"`, `source:
"ai_agent"`, `agent_session_id: <the agent's id>`, and the §73 message:

```text
An AI agent cannot approve a request.

This approval was raised by Claude Code (agt_4f21c09ab3e1) and only a
person at this device can answer it.

Policy: personal defaults — self-approval is refused by architecture,
not by configuration (spec section 60).

Next step: answer it in the approval overlay, or run
  punarctl approvals resolve apr_7c1d9a4e --decision approved
as the console user.
```

**A human may resolve their own privilege request.** Plate D-012 draws
exactly that: you request with a reason, and you authorize. The friction
is the required reason, the countdown, the visible chip and the audit
trail — not a second person. An **AI agent may never** resolve
anything, including a request made by a human.

**Honest limit, stated loudly and repeated in §13.** The cgroup is
*evidence of attribution*, not a sandbox. A managed agent that
deliberately launches a helper **outside** its own scope
(`systemd-run --user --scope` of its own) escapes attribution and would
present as the console user. M8 already rests on this same
foundation. M9 does not pretend otherwise. It hardens what it can:

- resolve refuses any peer whose cgroup path contains a `punar-agent-`
  segment at all, not only a well-formed session id — and **so do
  `approvals.create` and `privilege.request`**, through one shared test
  (`Inner::agent_shaped_peer`) rather than three copies of it. Authoring
  a card, answering one, and asking for a privilege window are three
  routes to the same human consent; `approvals.create` is in the list
  because every string on that call (`requester`, `reason`, `contract`,
  `user`) is requester-authored and *is* the card a person reads. The
  uid is not consulted by that test: root-ness inside an agent scope
  buys no bypass (spec section 60), and uid 0 stays separately required
  for `create` and `consume`;
- the resolver's uid, pid and cgroup path are recorded in the
  envelope's `resolved_by` and in the audit event, so an escape is
  *visible after the fact* even when it is not preventable.

What M9 does **not** do, said plainly because an earlier draft of this
section claimed it: there is **no seat-presence check** anywhere.
`approvals.create` does not ask whether the `user` it routes a card to
has an active logind session, and "the console user" means the owner of
the session user account, not the person at the keyboard.

**The real fixes, tracked (§13):** a dedicated uid per managed agent
session (a sandbox, not evidence), and a logind seat/`sd_session_is_
active` presence check so "the console user" means *the person at the
keyboard*, not *any process running as them*. Neither ships in M9, and
no M9 surface claims cryptographic proof of a human.

### 4.5 Expiry — lazy, no new timer

Expiry is swept:

- on every **read** (`approvals.list`, `approvals.get`, and the summary
  rewrite);
- at **resolve** and at **consume** time (a lapsed approval cannot be
  answered — error code `expired`);
- at every **`reconcile`** pass — which piggybacks on the existing
  `punard-reconcile.timer` and therefore adds **no timer** (§6.3).

Transition `pending → expired` writes the record, emits one audit event
(`action: "approval.expire"`, `decision: "deny"`, `result: "expired"`),
and rewrites the summary.

**The honest consequence, written down:** an expiry audit event's
`timestamp` is *when the lapse was observed*, not when it occurred. The
record's `expires_at` is when it occurred, and both are in the trail, so
the lapse instant is always recoverable. This is the price of having no
timer, and it is the right price.

The **overlay does not depend on the sweep**: it computes its countdown
from `expires_at` locally and renders `EXPIRED · denied by timeout`
(D-003's third verdict state) the moment the clock hits zero, whether or
not punard has swept yet. Pressing `A` on a lapsed card gets `expired`
from the daemon and the card says so. The socket remains the authority.

### 4.6 State machine, complete

```text
                 create (root only, or punard-internal)
                          │
                          ▼
                     ┌─────────┐
        resolve ─────│ pending │───── resolve ──────┐
        (approved)   └────┬────┘      (denied)      │
             │            │ expires_at passed       │
             ▼            ▼                         ▼
        ┌──────────┐  ┌─────────┐              ┌────────┐
        │ approved │  │ expired │              │ denied │
        └────┬─────┘  └─────────┘              └────────┘
             │
   kind == capability_set / privilege_request:
        execution recorded in the SAME request (sibling `execution`)
   kind == credential_request:
        broker calls approvals.consume → sibling `consumed_at` set
        (status stays "approved" — the enum is not extended, §2.2)
```

`approved | denied | expired` are **terminal**. A second `resolve`
returns `conflict` (the existing M5 error code) with
`details.state`. Double-consume returns `conflict`. Consume after
`expires_at` returns `expired` — **an approved credential approval still
expires**; a human's yes is not a standing grant.

---

## 5. Which capabilities become approval-gated (spec 20 + 28)

### 5.1 The decision: no fake capability, no new registry entry

`system.install_package` does not exist and M9 does not invent it. The
registry stays `security.firewall`, `system.hostname`, `time.timezone`.
Instead — as the spec 20/28 story actually reads — **policy gains a
real `approval_required` outcome for agent-originated mutations.** M8
already gives punard the attribution it needs, for free, at `accept()`.

The rule, in evaluation order, replacing the M3 `authorize_mutation`
step for mutating methods:

```text
0. admission (filesystem)                        — unchanged
1. attribution: agent_session_of_peer(peer)      — M8, ipc.md §12.5
2. if attributed to an agent session:
       → AI AUTHORITY PATH (§5.3)   [regardless of uid — see below]
3. else HUMAN PATH:
       uid == 0                     → allow
       live grant for (uid, capability) (§7)  → allow
       otherwise                    → deny, §73 message that now points
                                      at `punarctl privilege request`
```

**Step 2 runs before the uid check on purpose.** Root-ness must not
bypass AI policy: spec 60 forbids "bypass AI policy enforcement", so a
call from inside an agent scope is evaluated as an agent even if the
process is uid 0. A human doing the same thing as root is unaffected —
that is the whole point, and it is the spec 20/28 story exactly: *the
agent raises an approval, the human does not.*

### 5.2 The personal-defaults AI authority document

Ships at `usr/share/punar/policy/ai-defaults.yaml` (extra tree),
validating against `schemas/policy/ai-policy.json`, loaded by punard at
startup with the workspace's existing YAML dependency:

```yaml
# Punar personal defaults — AI authority (spec section 20).
# Rank 6 (os_secure_default) in the section 39 ladder. Org layers in
# /var/lib/punar/policy.d outrank this while enrolled.
ai:
  agents:
    default:
      filesystem: {workspace: read_write, home: read, ssh: deny, aws: deny}
      host:
        firewall: approval_required     # ← the M9 gate
        hostname: approval_required
        timezone: approval_required
        user_package: approval_required
        system_package: approval_required
        user_management: deny
      network: {internet: allow, corp_dev: allow, corp_prod: deny}
      credentials: {github: allow, aws_dev: request, aws_prod: deny}
```

**Deliberate divergence from the org fixture, stated:**
`fixtures/policies/ai-policy-engineering-standard.yaml` (`eng-ai-v3`)
sets `host.firewall: deny`. The personal default is
`approval_required` because in personal mode there is no organization —
**the user is the approver**, and denying outright would violate §73's
"whether approval is possible" for a device whose owner is standing in
front of it. When the device is enrolled, `eng-ai-v3` outranks the OS
default through the §39 ladder and the agent is **denied**, citing
*Acme AI Engineering Baseline v3 · eng-ai-v3* — which is the D-012
`aws_prod` story and a live demonstration of the ladder. Both paths are
correct; neither is a special case.

`host.firewall` is `approval_required` rather than `deny` for one more
reason worth writing down: the firewall is the highest-risk capability
in the M9 registry, so it is the honest subject for the demo. A gate
that only ever guards something trivial has not been tested.

### 5.3 The capability → section-20 token map, and fail-closed

```text
security.firewall → host.firewall
system.hostname   → host.hostname
time.timezone     → host.timezone
```

`host.hostname` and `host.timezone` are not in spec 20's *example*, but
§20's category list names "system mutation" and `ai-policy.json`'s
`host` block explicitly accepts any snake_case token. They are named
honestly rather than smuggled.

**Any capability with no mapping is DENIED, fail closed**, with:

```text
No AI authority rule covers <capability>.

Punar does not guess. An agent may not change a capability that policy
does not name.

Policy: personal defaults.
Next step: add a rule under ai.agents.default.host, or make the change
yourself: sudo punarctl capabilities set <capability> <state>
```

`user_package` / `system_package` / `user_management` map to **no
registry capability in M9** and are therefore **inert**. They ship in
the document because they are the spec 20 vocabulary and because the M9
gate is one policy line away from covering package installation the day
that capability exists — and `punarctl policy effective --ai` prints
them with an explicit `NO CAPABILITY · MILESTONE n` marker, the M8
`not_yet_observed` idiom applied to policy (§1.22).

### 5.4 What `allow` would mean (no M9 token uses it)

If a future policy sets a mapped host token to `allow`, punard executes
the mutation as root on the agent's behalf, audited with `source:
"ai_agent"` and the session id. That is the designed meaning of `allow`
in §20 and it is implemented, but **no shipped M9 policy uses it** — the
personal defaults are `approval_required` or `deny` across the board.

### 5.5 Attribution of the execution

When a human approves an agent's request and punard executes it, the
**execution** audit event carries `agent_session_id` = *the agent's*
session and `source: "ai_agent"`; the **resolve** event carries the
resolver's identity (`source: "human"`, `agent_session_id: "agt_none"`).

> The agent did it. The human allowed it. The trail says both.

This is §22 attribution kept honest, and it is what makes M8's Level-4
ledger fill correctly (§9).

---

## 6. Secret broker (spec 29)

### 6.1 Credential classes come from a fixture, not from code

Ships at `usr/share/punar/secrets/classes.yaml`, aligned with
`fixtures/policies/ai-policy-engineering-standard.yaml` and the §17
Atlas manifest `credentials` block:

```yaml
# Mock provider (spec 29 MVP). Simulated — no upstream exists.
version: 1
provider: mock
classes:
  - id: github
    display: GitHub (mock)
    policy_key: github          # → ai.agents.default.credentials.github
    default_ttl: 3600
    max_ttl: 3600
    risk: low
  - id: aws-dev
    display: AWS development (mock)
    policy_key: aws_dev
    default_ttl: 3600
    max_ttl: 3600
    risk: medium
  - id: aws-prod
    display: AWS production (mock)
    policy_key: aws_prod
    default_ttl: 0
    max_ttl: 0
    risk: high
```

**Naming, decided once:** the class id is **kebab-case on the wire, in
`resource`, and in the ledger** (`github`, `aws-dev`, `aws-prod`) — spec
29's request example says `"credential": "aws-dev"`. The **policy key is
snake_case** (`aws_dev`) because `ai-policy.json`'s `propertyNames`
pattern forbids hyphens. The mapping is a declared `policy_key` field,
not a `replace('-','_')` guess, so it can never drift.

The M9 ledger therefore shows `aws-dev`, not `aws_dev`; both match
`ResourceClass`'s `^[a-z][a-z0-9_-]*$`.

### 6.2 Decision path

`credential.request {credential, ttl?}` → resolve the class → read the
effective AI credentials policy for `policy_key` (§39 ladder: org layer
while enrolled, personal defaults otherwise) → three outcomes:

| Policy | Outcome | Exit | Audit |
|---|---|---|---|
| `allow` | issue immediately | 0 | `credential.request`, `decision: allow`, `result: "issued"` |
| `request` | `approvals.create` on punard (kind `credential_request`), return `approval_required` | **4** | `credential.request`, `decision: approval_required`, `result: "pending"` |
| `deny` | refuse in the §73 voice | 3 | `credential.request`, `decision: deny`, `result: "denied"` |

Every audit event carries **the class name only** (`resource:
"aws-dev"`), never a value, never a TTL secret, never a token id that
could be replayed. `agent_session_id` comes from the shared M8
attribution rule (§3.4), which is precisely what makes M8's ledger
promise come true (§9).

The `aws-prod` denial text, §73 verbatim, personal mode (D-012 Sect
II.03):

```text
Production AWS credentials are not issued to Claude Code in this
workspace.

Policy: personal defaults — you made this rule.
Requested by: Claude Code · agt_4f21c09ab3e1
Recorded: evt_502 — the agent was told the same sentence you are reading.

Change it: punarctl policy effective --ai, or System Control → AI.
Approval is not available for this class.
```

Enrolled, the citation becomes *Acme AI Engineering Baseline v3 ·
eng-ai-v3* and the last line becomes *Request an exception: approval
required* — DESIGN_LANGUAGE §8, org citations only when enrolled.

### 6.3 Issuance, TTL and the one-way door

On issue, punar-secrets:

1. generates 32 bytes from `getrandom(2)`, encodes them
   URL-safe-base64 with a class-marked prefix (`punar-mock-aws-dev-…`)
   so a leaked value is *identifiable as a mock* in any grep;
2. wraps it in `punar_common::Redacted<String>` for its entire lifetime
   in-process (the existing, tested type — `Debug`/`Display` print
   `[redacted]`, so no accidental `{:?}` can leak it);
3. stores, **in memory only**, `{sha256(token), class, owner_uid,
   agent_session_id, issued_at, expires_at, revoked}` — **not the
   token**;
4. writes the value to the caller's response exactly once and drops it.

> **There is no method that returns an issued token a second time. The
> broker cannot, not merely may not.** `credential.show`,
> `credential.export`, `secrets.dump` and every other probe answer
> `unknown_method` (§12 group 9).

**TTL:** default **3600 s** (spec 29's request example), range
`[5, 3600]`. Production default and CI values are deliberately
different and both documented:

- **Production default: 3600 s.** A class may lower it via `max_ttl`.
- **CI:** the exercise issues `aws-dev` with `--ttl 60` for the issuance
  card and countdown, and a `github` token with `--ttl 5` for the expiry
  assertion — so expiry is proven inside the check for the cost of a
  6-second sleep instead of a minute. Both TTLs are legitimate requests,
  not a test-only code path.

**Expiry is enforced on `credential.validate`**, computed from
`expires_at` against the clock — never from a timer, never from a sweep.
An expired entry is dropped from the map on the first validate that
observes it and audited **once** (`action: "credential.expire"`,
`result: "expired"`). A validate of an *unknown* token is **not
audited at all** — there is nothing to attribute, and auditing it would
hand any local process an audit-flood primitive (§6.4).

`credential.revoke` drops the entry immediately and audits
(`result: "revoked"`).

### 6.4 How the agent receives the token — decision and leak surface

**Decision: the value is printed on `stdout` by `punarctl secrets get
<class>`, bare, with no masthead, and nowhere else.** The human card
(class, agent, project, expiry, `NEVER WRITTEN TO DISK · NEVER LOGGED`,
`SIMULATED · MOCK PROVIDER`) goes to **stderr**, so

```sh
TOKEN=$(punarctl secrets get aws-dev)      # stdout: value only
```

works and the prose can never contaminate the value.

**Environment-variable injection into the agent scope is rejected**, and
this is a security decision, not a style one:

1. `/proc/<pid>/environ` is readable by the same uid and by root, and an
   injected variable is **inherited by every child** the agent spawns —
   `git`, `ssh`, a compiler, a crash reporter. One fd becomes an entire
   process tree.
2. **An environment variable cannot expire.** It outlives the TTL in
   every process that inherited it, which directly contradicts §29's
   "short-lived".
3. The agent scope's cgroup is a surface `punar-agentd` samples. Putting
   secrets inside it is one bug away from the ledger — the exact failure
   §53 exists to prevent.

**The honest leak surface of the chosen design, stated in full:**

- The caller may redirect stdout to a file. Punar cannot prevent that,
  and does not claim to. The promise is precise: **Punar never writes
  it.** Every surface says exactly that sentence and no larger one.
- The value transits the socket and `punarctl`'s memory. It is
  `Redacted` throughout and dropped after one `write(2)` to fd 1.
- `punarctl secrets get --json` serializes the value on stdout. This is
  the **one** place Punar ever serializes a secret, it is documented
  here and in ipc.md §16, and it is never persisted by Punar.
- **Secrets are never accepted on argv**, because `/proc/<pid>/cmdline`
  is world-readable. `credential.validate` and `credential.revoke` read
  the token from **stdin**:
  `printf %s "$TOKEN" | punarctl secrets validate --class github`.
  A `--token` flag does not exist and must never be added.

### 6.5 Method set (closed)

On `/run/punar-secrets/secrets.sock`: `status`, `credential.classes`,
`credential.request`, `credential.validate`, `credential.revoke`.
Everything else is `unknown_method`, forever. Full wire contract:
ipc.md §16.

### 6.6 What the broker does not claim

`project_id` on broker audit events is the existing
`punar_common::audit::PROJECT_ID_SYSTEM` sentinel (`"system"`). Spec
29's request example carries a project, but M9 has **no unforgeable
project mediation point at the broker**, and a requester-supplied
`--project` would put forgeable data in the tamper-evident record. So
there is no `--project` flag. The *display* surfaces (the D-012 card,
the AI panel) may show the project from the agent's registry record via
`agents.json`, which is already labelled display-grade and
non-authoritative. **Display may show it; the audit does not claim it.**

---

## 7. Just-in-time privilege (spec 48, Plate D-012)

```text
punarctl privilege request --capability security.firewall \
                           --reason "Reproducing the Atlas net bug" \
                           [--duration 15]
punarctl privilege status
punarctl privilege revoke [<gnt_id>]
```

- `--reason` is **required** (D-012 Sect I.02: "Authorize stays unfilled
  until a reason exists, because the reason travels verbatim into the
  audit event"). Empty or whitespace-only → `invalid_params`.
- `--duration` is **minutes**, default **15** (spec 48: *"Approved for
  15 minutes."*), range `[1, 60]`. It is a policy value, not a constant
  (D-012 Sect I.04).
- Creates an approval of kind `privilege_request`, routed to the
  requesting user, TTL 300 s (§4.2). The requester **may** resolve it
  (§4.4) — the friction is the reason, the clock and the chip.

On approval, punard writes a **grant**:

```text
/var/lib/punar/grants/                 0700 root:root  (tmpfiles)
/var/lib/punar/grants/<gnt_id>.json    0600 root:root
```

```json
{"v": 1, "grant_id": "gnt_2b8e11c4", "approval_id": "apr_…",
 "uid": 1000, "user": "punar", "capability": "security.firewall",
 "reason": "Reproducing the Atlas net bug",
 "granted_at": "…", "expires_at": "…", "revoked_at": null}
```

punard consults live grants in the **human path** of §5.1 step 3: a
non-root peer whose uid has an unexpired, unrevoked grant for exactly
that capability is allowed to `capabilities.set` it, audited with
`decision: allow`, `policy_ids: ["personal-defaults"]` and
`details.grant_id`. Expiry is **real and lazy**: evaluated against the
clock on every consult, on `privilege status`, and at each reconcile
sweep. A lapsed grant is unlinked and audited once
(`action: "privilege.expire"`, `result: "expired"`).

**Hard rules:**

- **A grant is never issued to an AI agent.** `privilege.request` from a
  peer attributed to an agent session is refused outright (`denied`,
  `result: "agent_privilege_refused"`, audited). Agents get per-request
  approvals; they never get a time window. Spec 48 ("avoid permanent
  local admin") and spec 60 ("add persistent unrestricted root") both
  point here, and the difference between *one approved call* and *five
  minutes of privilege* is the entire difference.
- A grant names **one capability**. There is no wildcard, no `--all`,
  and no grant for a capability that is not in the registry.
- No generic root shell exists to fall back to. `system.exec` /
  `shell.run` still answer `unknown_method`.

**The bar chip** (D-012 Sect I.03): `ELEVATED · 14:32 REMAINING`, green
while active, amber in the final minute, gone at expiry, `R` to revoke.
Fed by the same summary file as the overlay (§8.1), which carries a
`grants[]` array. Privilege is visible for exactly as long as it exists.

**Deferred, stated:** the graphical elevation *dialog* of D-012 Sect I
(M13 polish). M9 ships the CLI, the grant, the enforcement, the expiry
and the chip.

---

## 8. The shell — Plate D-003, made real

### 8.1 The summary file: `/run/punard/approvals.json`, `0640 root:punar`

**This is a deliberate deviation from the obvious choice
(`/run/punar/approvals.json`) and the reason is the whole point of the
milestone.** `/run/punar` is `0755 punar:punar` — user-writable. A local
process could unlink a file there and substitute a forgery. For
`agents.json` (counts and names) that is a nuisance; for **the file that
tells a human what they are about to authorize**, it is a spoofing
primitive: show a benign contract block over a dangerous `apr_` id and
the human presses `A`.

So it lives inside the already-root-owned `/run/punard`
(`0750 root:punar`), mode `0640 root:punar` — exactly the M8 reasoning
that moved `ledger.json` into `/run/punar-agentd`. The shell (user
`punar`, group `punar`) reads it; no non-root peer can replace it.

Content: pending and recently-resolved approvals plus live grants —
`{v, updated_at, approvals: [{approval_id, kind, status, requester:
{type, id, agent_name}, user, capability, resource, reason, risk,
expires_at, created_at, contract, policy: {name, policy_id}, execution?}],
grants: [{grant_id, capability, expires_at}]}`. Written atomically
(tmp + `fsync` + `rename`) by punard at every approval state transition
and every grant change. Non-authoritative for trust decisions: the
socket is the authority, and the overlay's `A` sends only the
`approval_id`; punard re-derives the contract from its own record before
executing anything.

### 8.2 The overlay

New `shell/punar-shell/Approval/ApprovalOverlay.qml` + singleton
`Services/Approvals.qml` (`FileView` change watch on the path above —
inotify, event-driven, zero polling, no socket client in the shell; the
`Status`/`Agents`/`Ledger` pattern). Registered in `shell.qml` and in
`Services/qmldir`.

Per Plate D-003 Sect II, as the acceptance reference:

- **Masthead** `Approval · apr_123`, risk pill (`Medium` warn-amber),
  and the **live countdown** `Expires 04:59` in tabular nums, turning
  warn-amber under a minute.
- **Identity chain**, one mono line:
  `AI Agent · Claude Code · Atlas · agt_123 · alice@acme.com`.
- **Prose line** then the **quoted reason** (§8.3).
- **Contract block between hairlines**: the exact typed call
  (`SetFirewall(disabled)`), the policy citation (`Policy · personal
  defaults · host.firewall = approval_required`, or the org name when
  enrolled), and `Recorded to local audit either way`.
- **Actions**: green filled **Approve · A**, red ghost **Deny · D**.
  `Esc` defers — *dismissal is not denial*; the request stays pending
  and the overlay can be reopened. `↑`/`↓` cycle when more than one is
  pending, with a count badge in the masthead.
- **Verdicts** after resolution, from the record:
  `✓ Approved · SetFirewall(disabled) executed · audit evt_501`,
  `Denied · nothing executed · audit evt_502`,
  `Expired · denied by timeout · audit evt_503`.

The overlay **appears unbidden** whenever `pending > 0` — it is a gate,
not a tray icon. The countdown `Timer` runs at 1 Hz **only while the
overlay is open and something is pending**, and stops otherwise; a UI
clock with a visible consumer is not the "continuous high-frequency
polling" §6.3 prohibits (the bar clock sets this precedent).

Actions run **detached**, never blocking the UI:
`Process { command: ["punarctl","approvals","resolve", id, "--decision","approved"] }`.
The overlay does not read the process result — the next `FileView`
change is the truth. Event-driven end to end.

`IpcHandler { target: "approval" }` with `open()`, `close()`,
`toggle()`, `state()` and `pending()` so `m9-check` can drive it with
`qs -p /usr/share/punar/shell ipc call approval open` (the `-p` is the
M2 lesson).

### 8.3 The reason text — shown, and the boundary stated

**Decision: the reason IS displayed.** D-003 renders it ("Required by
project Atlas."), D-012 says it "goes in the audit event, verbatim", and
§73 requires *why* and *who requested it*. A gate whose justification is
hidden is a rubber stamp.

The reason is also **requester-authored text**, and for an
agent-originated approval the requester is an AI. M9 handles that
directly rather than hoping:

1. **Validated at `approvals.create`:** ≤ 512 bytes, valid UTF-8, no
   control characters, **no newlines** — a one-line field. Violations →
   `invalid_params`. This kills the "draw a fake system dialog in ASCII"
   class of attack outright.
2. **Typographically quarantined.** The reason renders in a quoted
   block attributed to the requester (*Claude Code says: "…"*), in the
   requester voice, visually distinct from the system-voice contract
   block, in a plain non-interactive `Text` with no rich text, no link
   activation, and no HTML. **System prose and requester prose never
   share a typeface on this surface.** The human is never invited to
   read agent text as an OS statement.
3. **It is not redacted, and the boundary is written down.** Punar
   cannot distinguish a secret from a sentence. §53 binds *Punar* never
   to log secret values **it handles**; a requester who types their own
   password into a free-text field has disclosed it themselves. Punar
   never auto-fills a reason, and no Punar-issued value is ever placed
   in one.

**This boundary is exactly why the headline redaction test (§12 group
8) greps for the broker-issued token** — a value Punar controls end to
end, where the guarantee is absolute and testable — and not for
arbitrary user text, where it would be theatre.

### 8.4 AI panel and ledger, filled in

No new panel code. The AI panel's authority rows already render
decisions; they now show a real `approval_required` for `host.firewall`
instead of a display-only value, and its M8 LEDGER section fills
`credential_classes` from real events (§9). The D-012 broker issuance
card is **CLI-only in M9** (`punarctl secrets get` renders it on
stderr); the graphical card is M13 polish, stated.

---

## 9. M8 integration — keeping M8's written promise

### 9.1 What fills automatically

`punar-secrets` emits `credential.request` audit events carrying a real
`agent_session_id` (§3.4). M8's `tail::classify` already maps
`action == "credential.request"` → `SecurityEventType::CredentialRequest`
(`crates/punar-agentd/src/ledger/tail.rs:88`). **Level-4
`credential_request` fills with zero code change**, exactly as M8
promised.

### 9.2 What does NOT fill automatically — an honest correction

M8's `not_yet_observed` row for **Level-3 `credential_classes`** says
the producer is M9 and implies no ledger change. Reading the code:
`drain_audit` applies only `security_events` references
(`crates/punar-agentd/src/ledger/mod.rs:333–359`); Level-3 entries come
from the cgroup, the workspace bind and adapter metadata. **There is no
path by which an audit event contributes a Level-3 resource class**, and
the `Evidence::AuditEvent` variant — which `ipc.md` §12.2 documents — is
declared but unused.

So M9 adds one narrow hook to `punar-agentd`, and this document says so
rather than letting a downstream agent discover it at test time:

> In `drain_audit`, an event classified `CredentialRequest` with
> `decision == allow` also contributes a Level-3 entry
> `{category: credential_classes, resource_class: <event.resource>,
> evidence: audit_event}`. `decision == deny` contributes **only** the
> Level-4 `denied_access` reference — a refused credential is not access.

~15 lines. M8's promise holds for storage, projection, bounds, IPC,
retention and the panel; the drain needed a Level-3 door that M8 wired
for Level-4 only. Stated as a correction, not a surprise.

### 9.3 `not_yet_observed[]` after M9

`punar_common::ledger::not_yet_observed()`
(`crates/punar-common/src/ledger.rs:955`) is edited to tell the M9 truth:

| Row | M8 | M9 |
|---|---|---|
| L3 `credential_classes` | `M9` | **removed** — producer ships |
| L4 `credential_request` | `M9` | **removed** — producer ships |
| L4 `policy_bypass_attempt` | `M9` | **removed** — producer ships (§9.4) |
| L3 `mcp_servers` | `M9+` | **`M11+`** — M9 ships no MCP/tool gateway; §26 has no milestone of its own in §76, and the row must not keep pointing at a milestone that came and went |
| L4 `sensitive_resource_access` | `M9/M12` | **`M12`** — M9 mediates no sensitive zone |
| L3 `network_destinations` | `M12` | unchanged |
| L4 `production_access` | `M12` | unchanged |
| L4 `unknown_ai_execution` | `M10` | unchanged |

Re-milestoning `mcp_servers` and `sensitive_resource_access` is Law 4:
the alternative is a row that quietly lies about which milestone owes it.

### 9.4 `policy_bypass_attempt` becomes real

M8's row reads *"approval gates arrive with M9"*. M9 keeps it. But
`classify()` checks `decision == Deny` **first**, so a refused
self-approval would land as the generic `denied_access`. One rule is
inserted **ahead** of the generic deny:

> `action == "approval.resolve"` **and** `decision == deny` **and** the
> event is attributed to an agent session → `PolicyBypassAttempt`.

Narrow by construction: only a resolve, only a denial, only from an
agent. "An agent tried to answer an approval" is the textbook meaning of
§21.2's `policy_bypass_attempt`, and implementing it is what makes M8's
sentence true instead of aspirational. Asserted in §12 group 4.

---

## 10. CLI (Plate D-014; spec 11.2, 48)

New verbs, in the D-014 output grammar (tracked masthead, middle dots,
tabular columns, color only on status words), all with `--json`:

```text
punarctl approvals list                     # pending first, then recent
punarctl approvals get <apr_id>
punarctl approvals resolve <apr_id> --decision approved|denied
punarctl approvals wait <apr_id> [--timeout <s>]

punarctl privilege request --capability <id> --reason <text> [--duration <m>]
punarctl privilege status
punarctl privilege revoke [<gnt_id>]

punarctl secrets list                       # classes + effective decision, never values
punarctl secrets get <class> [--ttl <s>]    # VALUE on stdout, card on stderr
punarctl secrets validate --class <class>   # token on STDIN
punarctl secrets revoke                     # token on STDIN
```

Routing: a third `ipc::Target::Secrets` (socket
`/run/punar-secrets/secrets.sock`, env `PUNAR_SECRETS_SOCKET`,
`--socket secrets`), with `Target::of_method` sending `credential.*`
there and `approvals.*` / `privilege.*` to punard.
`punarctl debug rpc <method> --socket secrets` gains the third target
for the §74.4 probes.

**Exit codes (D-014 Sect III), now complete:** `0` ok · `1` runtime
error · `2` usage · `3` denied · **`4` approval_required — real as of
M9** · `5` unreachable. `approvals wait` returns `0` approved, `3`
denied, `1` expired, `4` still pending at timeout.

Plate D-014 register 05 (the in-terminal approval prompt) is rendered by
`punarctl approvals wait`: the same `apr_` masthead, the same contract
block, the same expiry, the same audit line either way — and, because
resolution is human-only, the `[A]`/`[D]` affordance appears **only when
the invoking peer is eligible to resolve** (§4.4). An agent running
`approvals wait` sees the card and the countdown, and no buttons.

---

## 11. Budgets (spec 6.2–6.4)

**The services RSS gate grows honestly.** `idle-ram.sh`'s
`PUNAR_SERVICE_UNITS` becomes:

```sh
PUNAR_SERVICE_UNITS="punard.service punar-agentd.service punar-secrets.service"
```

Thresholds are **unchanged** — spec 6.2 budgets the *combined* local
control-plane total: target < 100 MB, MVP ceiling < 150 MB summed PSS.
`PERFORMANCE_BUDGETS.md` §2's services row is updated to name three
units, and `tools/boot-test.sh`'s prose likewise.

Expected cost: a third Rust daemon with no network, no state directory,
an idle blocking accept loop and a bounded in-memory token map. Its
resident set is the binary's text plus a small heap. **The measured
combined value is not recorded anywhere in this repo today**, so
milestone-9.md's build record must state the before/after
`PUNAR_SERVICES_RSS_MB` from the actual CI run — measured, never
asserted. If the third unit pushes the combined figure toward the
100 MB target, the honest responses in order are: (1) report it, (2)
trim the broker (it needs no `serde_json` pretty printing, no policy
engine copy — it asks punard), (3) reconsider socket activation with
tokens accepted as lost on stop, and only then (4) discuss folding.
Silently raising the threshold is not on the list.

Other budgets:

- **CPU:** zero at idle. Three blocking accept loops, no timers anywhere
  in M9. Expiry is lazy (§4.5, §6.3) and rides the existing reconcile
  timer. The overlay's 1 Hz countdown exists only while the overlay is
  open with something pending.
- **Disk:** approvals and grants are user-paced events — a handful of
  ≤ 4 KiB atomic writes per decision, `0 B/s` at idle. `punar-secrets`
  writes **no state at all**; its only disk writes are audit events
  through the shared writer.
- **Audit growth:** M9 adds `approval.create`, `approval.resolve`,
  `approval.expire`, `approval.consume`, `credential.request`,
  `credential.expire`, `credential.revoke`, `privilege.request`,
  `privilege.grant`, `privilege.expire`, `privilege.revoke`. All are
  human- or lifecycle-paced. **Successful `credential.validate` is not
  audited** and an unknown-token validate is not audited at all — per
  §6.4 and to deny any local process an audit-flood primitive.

---

## 12. In-VM exercise plan — `m9-check`

`/usr/lib/punar/m9-check.sh`, root oneshot
(`punar-m9-check.service`, **not enabled**, no `.wants` symlink),
started synchronously by `idle-ram.sh` **after `punar-m8-check.service`
and before the artifact export**, so every `/run/punar/m9-*` file ships
in the same tar. Always exits 0; the verdict is
`PUNAR_M9_OK` / `PUNAR_M9_FAIL` in `/run/punar/m9-report.txt`, echoed to
the console. `tools/boot-test.sh` gains **phase 11**, mirroring phase 10
exactly, and adds `m9-report.txt`, `m9-*.json`, `m9-*.txt` and
`punar-m9.png` to the proof list.

Reuses verbatim: the `as_punar` runuser + session-env helper, the
`check_eq` / `check_true` / `check_ge` / `jq_check` / `jq_slurp_check` /
`grep_row` helpers, and the managed-launch block from `m8-check.sh`
(with a fresh session id). Image traps carried forward: **no diffutils**
(`sha256sum`, never `cmp`/`diff`), `qs ipc` needs
`-p /usr/share/punar/shell`, `fmt::verdict` uppercases so every rendered
grep is `grep -i`, no python/socat/nc, `jq` does all JSON work, and
**no polling loops** — bounded `sleep` for a known TTL is a wait, not a
poll.

### Groups

**1 · Preflight.** `punar-secrets.service` active; socket exists,
`0660 root:punar`; `/run/punar-secrets` is `0750 root:punar`;
`/var/lib/punar/approvals` and `/var/lib/punar/grants` are `0700
root:root`; the vendor `.wants` **symlink** exists **and**
`systemctl show multi-user.target` lists `punar-secrets.service` in
`Wants=` (never `is-enabled`). `usr/share/punar/policy/ai-defaults.yaml`
and `usr/share/punar/secrets/classes.yaml` are present.

**2 · (a) Agent-originated mutation raises an approval and changes
nothing.** Launch a managed agent session; from **inside** the scope run
`punarctl capabilities set security.firewall disabled`. Assert: exit
**4**; stderr carries `approval_required` and the `apr_` id;
`punarctl capabilities get security.firewall` still reports
`current_state: enabled`; a live `nft` read still shows the ruleset
present. → `m9-set-approval.json`, `m9-firewall-before.json`.

**3 · (b) `approvals.list` shows the pending object, schema-validated.**
`punarctl --json approvals list` → `m9-approvals-list.json`. `jq` the
`.approval` member of the pending record into `m9-approval-doc.json`.
**There is no schema validator in the image** (no python, no
`jsonschema`), so validation is two-sided and both sides are real: in-VM
`jq` asserts the schema's shape — exactly the nine required keys present,
**no tenth key**, `approval_id` matching `^apr_[A-Za-z0-9]+$`,
`requester.type` in the `principal_kind` enum, `risk` in
`low|medium|high`, `status` in `pending|approved|denied|expired` — and
the exported `m9-approval-doc.json` is validated **on the host, against
`schemas/audit/approval.json`**, by boot-test phase 11 through a new
one-off `--document <path> --schema <path>` mode on
`tools/validate_schemas.py` (the host has python and `jsonschema`; the
VM has neither). A drift between what the daemon actually emitted and
the shipped schema therefore fails CI, instead of passing a jq
spot-check. Assert `status == "pending"`,
`requester.type == "ai_agent"`,
`requester.id` equals the launched session, `capability ==
"security.firewall"`, `resource == "disabled"`, `risk` in the shipped
enum, `expires_at` present and in the future. Assert **`consumed_at` and
`execution` are NOT inside `.approval`** (the §2.1 law, tested).

**4 · (c) An AI agent may not resolve — the hard rule.** From inside the
scope: `punarctl approvals resolve <apr> --decision approved`. Assert
exit **3**; the message names *AI agent* and *cannot approve*; the
approval is **still `pending`**; the firewall is **still enabled**; the
audit tail carries `action: "approval.resolve"`, `decision: "deny"`,
`result: "self_approval_refused"`, `source: "ai_agent"`,
`agent_session_id: <sid>`, `resource: <apr_>`. Then assert
`punarctl agents access <sid>` lists a `policy_bypass_attempt` security
event (§9.4). → `m9-self-approve.txt`, `m9-audit-bypass.json`.

**5 · (k) + (d) The money shot, then the human resolve.** With the
approval still pending: `qs -p /usr/share/punar/shell ipc call approval
open`; assert `approval state` reports open with pending ≥ 1; `grim
/run/punar/punar-m9.png`; assert non-zero size — **the Plate D-003
overlay with a live contract card is the human evidence of this
milestone.** Close the overlay. Then resolve as the console user:
`punarctl approvals resolve <apr> --decision approved`. Assert exit 0;
`.approval.status == "approved"`; the sibling `execution.result ==
"success"` and `execution.changed == true`; **the firewall is now
`disabled`** (via `capabilities get` *and* a live `nft` read — the M3
"observed live, never cached" rule); the audit trail contains the
capability-execution event whose `evt_` id equals
`execution.audit_event_id`, attributed to **the agent's** session with
`source: "ai_agent"` (§5.5); and an `approval.resolve` event with
`resource: <apr_>`, `decision: "allow"`, `source: "human"`. Both pointer
directions of §2.3 are asserted. **Restore** `security.firewall` to
`enabled` as root and assert it took.

**6 · (e) Expiry — the request that was never answered.** From inside
the scope: `punarctl capabilities set security.firewall disabled
--ttl 15`. Assert exit 4 and a second `apr_`. Sleep 20 s. Assert
`punarctl --json approvals get <apr2>` reports `.approval.status ==
"expired"`; `execution` is `null`; the firewall is **still enabled**;
an `approval.expire` audit event exists with `decision: "deny"`,
`result: "expired"`; and `approvals resolve` on it now returns the
`expired` error, not `conflict`. → `m9-expired.json`.

**7 · (f) Secrets — allow, request, deny.**
- `github` (policy `allow`): from inside the scope,
  `TOK_GH=$(punarctl secrets get github --ttl 5)` — **captured into a
  non-exported shell variable, never a file, never argv**. Assert exit
  0, non-empty, and that the human card on **stderr** carries
  `NEVER WRITTEN TO DISK`, `SIMULATED` and an expiry.
- `aws-dev` (policy `request`): first call exits **4** with an `apr_`;
  the approval's `.approval` member validates and carries
  `capability: "credential.request"`, `resource: "aws-dev"`. Resolve as
  the console user. Then `TOK_AWS=$(punarctl secrets get aws-dev
  --ttl 60)` succeeds; assert the approval's `consumed_at` is set while
  `.approval.status` is still `"approved"` (§2.2 tested); assert a
  **second** `secrets get aws-dev` exits 4 again with a **new** `apr_`
  (single-use — an approval is not a standing grant).
- `aws-prod` (policy `deny`): exits **3**; the message is checked
  case-insensitively for the §73 four beats — what (`not issued`), who
  (`Claude Code`/`agt_`), which policy (`personal defaults`), next step
  (`punarctl policy` or `System Control`) — and for the honesty that
  approval is **not** available for this class. → `m9-secrets-deny.txt`.

**8 · (g) TTL expiry invalidates the token.** Sleep 6 s (the `github`
token was issued with `--ttl 5`). `printf %s "$TOK_GH" | punarctl
secrets validate --class github` → non-zero, message says expired; audit
carries one `credential.expire` event with the **class only**. Then
`punarctl secrets revoke` on `$TOK_AWS` via stdin → assert a subsequent
validate fails and a `credential.revoke` event exists.

**9 · (h) REDACTION — the headline assertion.** For **each** of
`$TOK_GH` and `$TOK_AWS`, `grep -rF` the value across:
`/var/log/punar/audit.jsonl`; `/var/lib/punar/agents/ledger/`
(every file + `index.json`); `/run/punar-agentd/ledger.json`;
`/run/punar/agents.json`; `/run/punar/status.json`;
`/run/punard/approvals.json`; `/var/lib/punar/approvals/`;
`/var/lib/punar/grants/`; `/var/lib/punar/preferences.json`;
`/var/lib/punar/policy.d/`; the **journal** (`journalctl -b --no-pager`);
**every file in `/run/punar`** (i.e. the entire export tar, including
`m9-report.txt` itself and `punar-m9.png`); and
`/proc/<pid>/environ` + `/proc/<pid>/cmdline` for every punar process.
**Every one must be absent.** A single hit is `PUNAR_M9_FAIL`. Also
assert the negative control: the class *names* (`github`, `aws-dev`) DO
appear in the audit trail — proving the grep would have found a leak.
→ `m9-redaction.txt` (which records only *counts*, never a match).

**10 · (i) M8 integration, no ledger surgery beyond §9.2.**
`punarctl --json agents access <sid>` → assert
`.summary.resources.credential_classes` contains `github` **and**
`aws-dev`; assert `credential_classes` and `credential_request` no
longer appear in `not_yet_observed[]`; assert the Level-4 events include
`credential_request`; assert `mcp_servers` is still listed with
milestone `M11+`. → `m9-access.json`.

**11 · (j) JIT privilege.** As the console user (non-root, group
`punar`): `punarctl capabilities set time.timezone Europe/Berlin` →
exit **3**, and the message now names `punarctl privilege request`.
Then `punarctl privilege request --capability time.timezone --reason
"m9 exercise" --duration 1` → an `apr_`; resolve it; assert
`privilege status` shows a `gnt_` with a countdown; assert the same
non-root `capabilities set` **now succeeds** and the timezone actually
changed (`timedatectl`); assert the audit event carries
`details.grant_id`. Sleep 65 s; assert the grant is gone, a
`privilege.expire` event exists, and the non-root `capabilities set`
**fails again with exit 3**. Assert `--reason ""` is a usage/params
error. Assert `privilege request` **from inside the agent scope** is
refused (`agent_privilege_refused`) — no grant is ever issued to an AI.
Restore the timezone as root. → `m9-privilege.txt`, `m9-grant.json`.

**12 · Negative probes (§74.4).** On the secrets socket:
`credential.show`, `credential.export`, `secrets.dump`, `system.exec`,
`shell.run` → all `unknown_method`. On punard: `approvals.create` from
the non-root console user → `denied` (only root and punard-internal
paths create). `runuser -u nobody -- punarctl secrets get github` →
blocked by the filesystem before the daemon sees it. A `--token` flag
does not exist (`punarctl secrets validate --token x` → exit 2).

**13 · Stated gaps (spec 1.22).** The report prints, as `info` lines,
not `ok` lines: (i) an agent that launches a helper outside its own
scope escapes cgroup attribution and would present as the console user —
not proven closed here, because it is not closed (§4.4, §13); (ii)
resolution has no PAM/polkit re-authentication in M9; (iii) the
provider is a mock and every surface says so; (iv) cross-user resolve
refusal is not proven in-VM (one interactive user, no way to forge peer
credentials) — it is covered by unit tests, named here.

### Timeout math (stated, not copied)

```text
180 s  managed session launch + registration
 20 s  approval-expiry wait (15 s TTL + margin)
  6 s  credential TTL-expiry wait
 65 s  grant-expiry wait (1 minute + margin)
 12 s  overlay open settle + grim
 60 s  scope teardown
 40 s  ~60 RPCs, jq passes, greps, the redaction sweep
────
~6.5 min worst case bounded waiting.
```

`TimeoutStartSec=20min` — the same generous TCG headroom M7/M8 use. It
is headroom, not an expectation; a run that needs it has gone wrong, and
the report names the assertion it stopped at.

---

## 13. Deferred, tracked

| # | Item | Why not M9 | Where it lands |
|---|---|---|---|
| 1 | Per-agent-session uid (a real sandbox, not evidence) | Needs dynamic user allocation and a rework of `punar-env`'s workspace bind | M10+ |
| 2 | logind seat/active-session presence check for `approvals.resolve` | Adds an sd-login dependency to punard; presence semantics need a design pass on headless and SSH sessions | M10+ |
| 3 | PAM/polkit re-authentication at resolve | Same | M10+ |
| 4 | Graphical elevation dialog (D-012 Sect I) | M9 ships CLI + grant + chip; the dialog is polish | M13 |
| 5 | Graphical broker issuance card (D-012 Sect II) | Same | M13 |
| 6 | Real credential provider | Spec 29's MVP is explicitly a mock; CI has no network | Phase 2 |
| 7 | Remote/org approval routing | Spec 28 says *local* graphical approval | Phase 2 |
| 8 | MCP/tool gateway → `mcp_servers` | No gateway exists (spec 26 has no §76 milestone) | M11+ |
| 9 | Approval queue UI beyond `↑`/`↓` + count badge | D-003 lists the multi-approval queue among "states not drawn" | M13 |

---

## 14. Definition of done

1. `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test
   --workspace` green in `docker rust:1`.
2. `./tools/validate-schemas.sh` green, including the new approval and
   AI-policy fixtures and the shipped `ai-defaults.yaml`.
3. `shellcheck` (v0.11.0) clean on `m9-check.sh` and the edited
   `idle-ram.sh`; `actionlint` clean; `qmllint` clean on the new QML via
   the pinned Arch container.
4. `PUNAR_BUILD_MODE=summary ./tools/build-image.sh` succeeds.
5. `PUNAR_M9_OK` in the exported `m9-report.txt`, boot-test phase 11
   green, `punar-m9.png` showing the D-003 overlay with a live approval.
6. `PUNAR_SERVICES_RSS_MB` **measured and recorded** for three units,
   inside the spec 6.2 ceiling.
7. Every claim in the build record carries the gate that proved it, and
   everything unproven is in §13 or the §12 group-13 `info` lines.
   Spec 1.22.

---

## 15. Build record — image wiring and the in-VM exercise

*Status of the image / CI / `m9-check` slice of Milestone 9, recorded
2026-08-25. Written to the rule of spec 1.22: every claim below names the
gate that proved it, and anything that was **not** run says so.*

### 15.1 What shipped

**A third daemon, wired the same way as the first two.**

| Path | What |
|---|---|
| `usr/lib/systemd/system/punar-secrets.service` | `Type=simple`, `After=punard.service` (ordering only), `ProtectSystem=strict` with `ReadWritePaths=/run/punar-secrets /var/log/punar` and **no** `StateDirectory=`, `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, `MemoryDenyWriteExecute`, `LockPersonality`, `SystemCallFilter=@system-service`, `UMask=0077`. Deliberately **not** `ProtectProc=`/`ProcSubset=`: the broker reads `/proc/<peer_pid>/cgroup` to attribute a request, and hiding that would silently disable attribution — a security control must not fail towards "no agent" without saying so. |
| `…/multi-user.target.wants/punar-secrets.service` | The vendor `.wants` symlink. `is-enabled` reports `disabled` for a `/usr/lib` wants unit, so `m9-check` asserts the **symlink** plus `Wants=` in `systemctl show multi-user.target` (the M4 lesson). |
| `usr/lib/tmpfiles.d/punar-secrets.conf` | `d /run/punar-secrets 0750 root punar`. It carries **no** state-directory line, and that absence is the design. |
| `usr/lib/tmpfiles.d/punard.conf` (extended) | `/var/lib/punar/approvals` and `/var/lib/punar/grants` at `0700 root:root`, plus the reserved `/var/lib/punar/policy.d/ai`. punard creates them itself; the lines exist so the modes are declared where an auditor can read them. |
| `scripts/container-build.sh` | Builds and stages `punar-secrets` beside the other binaries, and stages `fixtures/policies/ai-policy-personal-defaults.yaml` → `/usr/share/punar/policy/ai-defaults.yaml` and `crates/punar-secrets/share/classes.yaml` → `/usr/share/punar/secrets/classes.yaml`. Both are staged rather than committed twice for the M8 `process-classes.json` reason: each is *also* compiled into its daemon with `include_str!`, so a second hand-maintained copy is exactly the drift the compiled-in fallback exists to prevent. Both staged paths are in `os/images/.gitignore`. |
| `usr/lib/punar/in-agent-scope.sh` | New. Runs one command from **inside** a managed session's real scope cgroup by migrating itself into it, so `punard` and `punar-secrets` read the same `/proc/<pid>/cgroup` they would read for a real agent child. Nothing is faked: no scope is invented and no session id is spelled by hand. It must be forked by the **user manager** (`systemd-run --user`), because cgroup v2 delegation containment permits the migration only from inside the destination's delegated subtree — the M7 hard lesson. Exits 97/98 on harness failure, deliberately outside `punarctl`'s documented 0–5 range so a harness fault can never be read as a daemon verdict. |
| `usr/lib/punar/m9-check.sh` + `punar-m9-check.service` | The exercise. Root oneshot, **not enabled**, no `.wants`; started synchronously by `idle-ram.sh` after `punar-m8-check` and before the export. `TimeoutStartSec=20min`. Always exits 0; the verdict is `PUNAR_M9_OK`/`PUNAR_M9_FAIL` in `/run/punar/m9-report.txt`. |
| `tools/boot-test.sh` | Phase 11 (verdict gate, mirroring phase 10) **plus phase 11b**: the exported approval document is re-validated on the host against `schemas/audit/approval.json`. |
| `tools/validate_schemas.py` | New `--document <path> --schema <path>` one-off mode, sharing the same local `$ref` registry as the full harness. |
| `tests/performance/check-budgets.sh`, `PERFORMANCE_BUDGETS.md` | Three units named in the prose, the annotation and the baseline table row. Thresholds **unchanged**. |
| `.github/workflows/ci.yml` | Job renamed to M2..M9; `timeout-minutes` 105 → 125; `m9-check.sh` and `in-agent-scope.sh` added to the shellcheck list; `punar-m9.png` added to the screenshot artifact; `m9-report.txt` / `m9-*.json` / `m9-*.txt` added to the report artifact. |

`idle-ram.sh` now sums **three** service cgroups
(`PUNAR_SERVICE_UNITS="punard.service punar-agentd.service
punar-secrets.service"`) into the one `PUNAR_SERVICES_RSS_MB` the budget is
judged against. Adding a daemon and leaving it out of the sum, or raising a
threshold to make room for one, would each make the gate say something
untrue.

### 15.2 The M8 ledger integration was real work, not a no-op

§9.2 predicted this and it held: Level-4 `credential_request` fills with
zero code change, Level-3 `credential_classes` did **not**. The following
landed in `punar-agentd` / `punar-common`:

- `ledger/tail.rs`: `DrainResult` gains a `classes` channel;
  `credential_class_of()` contributes the class of an **allowed**
  `credential.request` and nothing else — a *refused* credential keeps only
  its Level-4 `denied_access` reference, because a credential that was not
  issued is not access, and recording it as a class the agent "used" would
  be a lie in the user's own privacy surface.
- `ledger/tail.rs`: `classify()` gains rule 0 — `approval.resolve` +
  `decision: deny` → `policy_bypass_attempt` — placed **ahead** of the
  generic deny, or it could never fire. This is what makes M8's written
  sentence ("approval gates arrive with M9") true rather than aspirational.
- `ledger/mod.rs`: `drain_audit` applies the Level-3 half with the same
  tombstone floor and active/ended split as the Level-4 half, producing the
  `Evidence::AuditEvent` variant M8 declared and never emitted.
- `punar_common::ledger::not_yet_observed()`: `credential_classes` (L3),
  `credential_request` (L4) and `policy_bypass_attempt` (L4) **left** the
  list because their producers shipped; `mcp_servers` was re-milestoned
  M9+ → **M11+** and `sensitive_resource_access` M9/M12 → **M12**. Eight
  rows became five.

Proved by 2 new unit tests in `tail.rs` and one new integration test
(`an_issued_credential_fills_the_level_3_row_and_a_refused_gate_is_a_bypass_attempt`)
that drives it through the socket and then asserts no token, hash or
approval payload reached disk.

### 15.3 M8's exercise had to change, and it says so

M9 changed what an agent's capability mutation *does*: `firewall:
approval_required` in the shipped AI authority document means the M8 mock
agent's `capabilities set` is now **gated** (`decision:
approval_required`, `result: pending`), not denied. Nothing is applied
either way — the invariant M8 cared about — but "denied" is now the wrong
word for it, and M8's Level-4 `denied_access` producer needed a refusal
that policy can never turn into a yes.

`punar-mock-agent` therefore makes a second short-lived call —
`punarctl privilege request` — which is refused for **any** AI agent,
always (`agent_privilege_refused`, SPEC 48/60). `m8-check.sh` group 2
greps the new lines, group 7 joins the ledger reference to *that* event and
additionally asserts the capability call was gated rather than applied, and
group 6 now asserts the honesty rows in **both** directions: the categories
that still have no producer are named, and `credential_classes` — empty in
that exercise because that session asked for no credential — must **not**
be named, because a category with a working producer may not go on claiming
it has none. This follows the established precedent of updating an earlier
milestone's check when a later milestone changes the behaviour it asserts.

### 15.4 Deviations from §12, stated rather than absorbed

1. **The expiry group uses the shipped 300 s TTL, not `--ttl 15`.** That
   flag does not exist and must not: §5.1 fixes the `capabilities.set`
   request shape as UNCHANGED, and the image ships no python/socat/nc with
   which to hand-craft a socket frame. `m9-check` starts the expiry clock
   **early** and runs the credential, ledger, privilege and negative-probe
   groups inside the window, so the incremental wall-clock cost is the
   remainder rather than 300 s. Stated as an `info` line in the report.
2. **The host-side schema replay lives in `boot-test.sh`, through Docker.**
   §12 assumed "the host has python and `jsonschema`"; `tools/validate-schemas.sh`
   states the opposite in its own header. Phase 11b therefore runs the same
   `python:3.12-slim` container the contracts job uses. A validation
   *failure* is fatal; a *missing* Docker is a warning, because the in-guest
   `jq` half already ran and the contracts job validates the committed
   fixtures on every push regardless.
3. **`m9-check` clears any pre-existing pending approval at preflight**, by
   **denying** it as root. The M8 exercise now leaves one behind (see
   §15.3), and the overlay assertions must be about *this* exercise's card.
   Denying is the honest disposal — a recorded decision, not a deletion.
4. **Agent-originated calls run through `in-agent-scope.sh`.** §12 assumed
   the M8 pattern (the mock makes the call), which cannot interleave with
   human resolutions. See §15.1.
5. **The JIT-privilege group asserts `policy_ids`, not `details.grant_id`.**
   `audit-event.json` is closed at twelve fields and has no `details`
   object. A grant **is** a section 39 Temporary Approved Exception, so the
   grant id belongs in `policy_ids` — it is the authority that permitted the
   call. §7's `details.grant_id` is superseded by this line; zero schema
   bytes changed.
6. **No new keyboard chord.** §8.2 makes the overlay appear *unbidden* when
   something is pending, so there is nothing to bind. `Esc` defers and the
   request stays pending; a deferred approval is reachable again through
   `punarctl approvals list` / `resolve`, or the overlay's next state
   transition, or `qs -p /usr/share/punar/shell ipc call approval open`.
   **Honest gap:** there is no graphical path back to a deferred card in
   M9. The multi-approval queue UI is already deferred to M13 (§13 row 9)
   and this belongs with it. `punar-binds.conf` is unchanged and was
   verified against the pinned Hyprland config.
7. **The redaction sweep adds a second, weaker probe** beyond the two
   issued values: the identifiable `punar-mock-` prefix must appear nowhere
   Punar writes. It catches a token this script never held — one a daemon
   might have logged on a path the exercise does not exercise.

### 15.5 Verification (run, not asserted)

| Gate | Result |
|---|---|
| `cargo fmt --all --check` (docker `rust:1`) | clean |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | clean, 0 warnings |
| `cargo test --workspace --locked` | **719 passed, 0 failed** across 30 test binaries |
| `./tools/validate-schemas.sh` | 15 schemas, 132 documents, ALL PASS |
| `tools/validate_schemas.py --document … --schema …` | verified both ways: a conformant approval passes; the same document with `"status":"consumed"` fails with the enum error |
| `shellcheck` v0.11.0 (pinned) | clean on all **17** linted scripts, including the new `m9-check.sh` and `in-agent-scope.sh` (the count is the `ci.yml` argument list, re-counted by the §16 audit; this row said 16 before that re-count) |
| `actionlint` | clean |
| `PUNAR_BUILD_MODE=summary ./tools/build-image.sh all` | succeeds; both M9 data files verified present in the staged extra tree |
| `qmllint` 6.11.2 (pinned container) | 12 `.qml` files, zero warnings |

**NOT run, and why.** No in-VM run: there is no VM on this machine, and the
CI VM is the only place `m9-check` can execute. Everything in §15.1–15.4
that depends on the guest — the exercise's own verdict, the D-003
screenshot, phase 11 and 11b end to end, and the redaction sweep against a
real export tar — is therefore **designed and gated but not yet observed**.
The first CI run on this branch is the evidence, and until it is green no
sentence anywhere should claim M9 passed in the VM.

**`PUNAR_SERVICES_RSS_MB` is `not yet measured`.** `PERFORMANCE_BUDGETS.md`
line 273 has said so since M0 and still does; there is no before/after
number in this repo to compare against, so none is quoted here. The first
real value comes from the `punar-desktop-ram-report` artifact of a CI run
and belongs in the baseline table, measured. If the third daemon pushes the
total towards the 100 MB target, the honest responses in order are: report
the number → trim the broker (it carries no policy-engine copy; it asks
punard) → reconsider socket activation with tokens accepted as lost on stop
→ only then discuss folding daemons. Silently raising the threshold is not
on the list.

---

## 16. Status (audited 2026-08-25)

*Owned by the status audit, written to spec 1.22. §15 is the build
record — what was built and why. This section is the narrower question:
**what is proven, by which gate, right now**, and what is not. Where the
two disagree, re-measure; nothing here is a restatement of intent.*

### 16.1 Where the tree stands

**M9 is working-tree only.** Nothing in it is committed. It sits on top
of two commits that are themselves **unpushed** — `f65c7ad` (design
plates D-015/D-016) and `dc2dc47` (the silent-skip fix) — so the first
push carrying M9 carries those with it, and `dc2dc47` is a precondition
for the M9 run being meaningful (§16.3).

| | |
|---|---|
| `origin/main` | `f31a8f2` |
| local `main` | `dc2dc47` (2 ahead, unpushed) |
| M9 tree | uncommitted working-tree changes on top of `dc2dc47` |

The M9 tree is the new `punar-secrets` daemon (the M0 placeholder crate
that said "intentionally empty until Milestone 9" is now the broker),
punard's approval engine and AI-policy layer (`src/approvals.rs`,
`src/aipolicy.rs`, `src/server/m9.rs`), `punar-common`'s `approval` and
`aipolicy` modules, punarctl's `peer`/`watch` plus the `approvals.*`,
`privilege.*` and `secrets.*` grammar, the shell's
`Approval/ApprovalOverlay.qml` + `Services/Approvals.qml` + the bar's
ELEVATED chip, the `punar-secrets.service` unit with its vendor `.wants`
symlink and tmpfiles line, `m9-check.sh` + `in-agent-scope.sh` +
`punar-m9-check.service`, five new fixtures, ipc.md §14–§16, and the
budget/CI wiring. The same working tree also carries
`docs/development/milestone-{10,11,12}.md` and
`docs/design/mockups/shortcuts.html`, which are forward planning and
**not** M9 deliverables.

### 16.2 Gates re-run by this audit

Independent of §15.5's build-time run, against the working tree as it
stands. Numbers are what was actually observed, not copied:

| Gate | Result |
|---|---|
| `cargo fmt --all --check` (`docker rust:1`) | exit 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | exit 0 |
| `cargo test --workspace --locked` | **719 passed, 0 failed** across **30 test binaries** (M8's audit measured 534 across 27 — M9 adds 185 tests and 3 binaries) |
| `./tools/validate-schemas.sh` | **15 schemas metaschema-checked, 132 documents, ALL PASS** (127 at M8; M9's five new fixtures are the delta) |
| `shellcheck v0.11.0` (pinned, the full `ci.yml` list — **17** scripts incl. `m9-check.sh` and `in-agent-scope.sh`) | exit 0, zero findings |
| `actionlint` over `.github/workflows` | clean |

Recorded in §15.5 and **not** re-run here: `qmllint` 6.11.2 over the
twelve `.qml` files, and `PUNAR_BUILD_MODE=summary
./tools/build-image.sh`. Both need the pinned Arch snapshot container;
neither is a runtime proof, and neither changes §16.4.

Two mechanical checks that matter because M8 got them wrong:
`m9-check.sh` and `in-agent-scope.sh` both ship mode `100755`, and
`boot-test.sh` phase 11 treats a **missing** M9 verdict under KVM as a
hard failure, not a warning.

### 16.3 Live CI state — what CI has actually proven

`gh run list`, 2026-08-25. Newest first:

| Run | Commit | Result |
|---|---|---|
| [32877949285](https://github.com/smplify-mdm/punar/actions/runs/32877949285) | `f31a8f2` | **green, all five jobs** — `PUNAR_DESKTOP_OK` after 20 s, `PUNAR_M2_OK` (33) + `PUNAR_M3_OK` (28) + `PUNAR_M4_OK` (29) + `PUNAR_M5_OK` (63) + `PUNAR_M6_OK` (55) + `PUNAR_M7_OK` (74) = **282 in-VM assertions**; idle RAM mean 1163 MB / max 1171 MB; services RSS 4 MB (punard + punar-agentd) |
| [32874683680](https://github.com/smplify-mdm/punar/actions/runs/32874683680) | `9027438` (M8) | **red** — `desktop-test` only; `FAIL inspect: the ledger says it arrives in Milestone 8 (missing: 'MILESTONE 8')`, a stale **m7**-check assertion M8 itself made obsolete. `rust`, `contracts`, `image`, `boot-test` green |
| [32868450695](https://github.com/smplify-mdm/punar/actions/runs/32868450695) | `f95c9c4` | green — M7's arbiter run |

**The green run did not run the M8 exercise**, and its log says so:
`##[warning]desktop-test: no m8-report.txt in the export and no M8
verdict on serial — the M8 exercise did not run`. `m8-check.sh` shipped
mode `100644`, `punar-m8-check.service` failed its `ExecStart`, no
report reached the export, and `boot-test` degraded a **missing**
verdict to a warning. A green run therefore claimed a milestone that had
not executed. `dc2dc47` fixes both halves — the exec bit, and a missing
M2..M8 verdict becoming a hard failure under KVM — and it is
**unpushed**. Until it lands, an M9 push could go green with neither the
M8 nor the M9 exercise having started.

So, stated exactly: M8's host-side jobs are CI-proven at `f31a8f2`
(fmt, clippy, the workspace tests, the schema contracts, the mkosi build
of every M8 file, the `punar-dev` boot). **No `PUNAR_M8_OK` and no
`PUNAR_M9_OK` exist anywhere.**

### 16.4 What is not proven

Everything that can only happen in the guest:

- **`m9-check` has never executed.** Its thirteen groups — the gated
  agent mutation, the schema-checked pending approval, the
  agent-may-resolve-nothing refusal, the human resolve verified against
  a live `nft` read, the broker's allow/request/deny paths, single use,
  real TTL expiry and revoke, the redaction sweep, the M8 ledger join,
  JIT privilege, the negative probes and the unanswered approval's
  expiry — are **intent**, roughly 129 static assertion sites of it,
  plus 10 stated-gap `info` lines.
- **No `punar-m9.png`.** The D-003 overlay has never been photographed
  with a live approval on it.
- **Phase 11 and 11b have never run end to end**, so the host-side
  replay of an exported approval document against
  `schemas/audit/approval.json` is designed and wired, not observed.
- **The redaction sweep has never run against a real export tar** —
  which is the one place it matters, since the tar is what leaves the
  guest.
- **`PUNAR_SERVICES_RSS_MB` for three daemons is unmeasured.** The last
  CI-measured value is 4 MB for two (run 32877949285). The thresholds
  were not moved to make room for the third.
- **The 125-minute `desktop-test` budget is untested** at the new
  exercise count.

Known gaps that are design, not oversight, and are stated rather than
absorbed (§13, §15.4): the expiry group uses the **shipped 300 s TTL**
because `--ttl 15` does not exist and must not; there is **no graphical
path back to a deferred approval card** in M9 (the multi-approval queue
is M13); the shipped AI authority document **declares filesystem zone
grants that M9 enforces nothing of**, and no surface may claim
otherwise; and the broker is a **mock provider** — there is no upstream
credential authority and the CI VM has no network.

### 16.5 The one-line summary

M9 is **built and statically green, and proven at runtime nowhere**.
The arbiter is a `desktop-test` run that contains this tree *and*
`dc2dc47`; until that run is green, no sentence in this repository may
say M9 passed in the VM.

### 16.6 Adversarial secrecy + authority audit (2026-08-25)

A second pass whose brief was to *construct* a leak and to *attempt* the
self-approval bypass rather than to re-read the tests that assert
neither is possible.

**Secrecy: no leak was found, and the paths that were walked are named
so the absence means something.** Every route a token value can take was
followed to its end — issuance return, the one `expose_secret()` on the
write path, CLI stdout, `Debug`/`Display`, serde derives on every struct
that holds one, audit builders, the M8 ledger's `credential_class_of`
door, `status`/`approvals.json`, `eprintln!` (journal) sites, and the
`.expect()` strings on both `to_json_line` implementations. `Redacted`
is used at all four sites that carry a value, no secret-bearing struct
derives `Serialize`, `PoisonError`'s `Debug` does not print its guard,
and `serde_json`'s value-quoting error text is already dropped on the
two secret-bearing methods. Two hardenings came out of it anyway:

- **`server::unknown_class` quoted a caller-authored string back.** The
  reachable mistake is ordinary — `punarctl secrets get "$TOKEN"`, the
  arguments swapped — and punarctl prints that message on stderr, which
  a script may be capturing to a file. It now quotes a requested name
  back **only when the name is shaped like a class id**
  (`classes::class_id_ok`); anything else is named by length and
  refused, the same trade `parse_secret_params` already makes. Nothing
  on that path was ever audited, which is the property that kept it out
  of the permanent record, and a regression test now pins both halves.
- The equivalent slip in `credential.validate`'s `credential` hint is
  covered by the same test.

**Authority: the self-approval bypass was attempted and lands exactly on
the documented residual, not on a hole.** Inside its cgroup an agent is
refused by `approvals.resolve` before the store is consulted, and it
cannot reach another agent's approval by any route: no method in the
closed table takes an approval id from the caller, and the broker
matches candidates on class *and* attested requester. `aws-prod` is
refused twice over — the policy arm returns before the approval engine
is dialled, and `max_ttl: 0` refuses again inside `issue()` — now pinned
by `an_approval_for_one_class_cannot_buy_a_denied_one`. What does defeat
attribution is the escape §4.4 and ipc.md §14.5 already state in the
open: a helper started outside the scope presents as the console user.
That is unchanged, and it is why the two fixes below are about *not
depending on the narrow rule anywhere it can be avoided*:

- **`approvals.create` tested `uid == 0` and nothing else.** A peer that
  is uid 0 *inside an agent scope* — the ordinary shape of a person
  running `sudo punarctl` in a terminal the agent owns — could therefore
  author an approval, and every string on that call is requester-authored:
  `requester` (an agent may write `{"type":"human"}`), `reason`,
  `contract`, and the `user` it routes to. Those four strings **are** the
  D-003 card. Refused now, `result: "agent_create_refused"`, audited with
  the attested session. Verified by negative control: with the check
  removed the new test fails at uid 0 *and* at uid 1000 (where the old
  answer was "become root" rather than "you are an agent").
- **`privilege.request` used the narrow rule** (`agent_session_id.is_some()`)
  where `resolve` used the wide one. A peer in a scope that names a
  session it cannot spell fell through to the human path; the negative
  control shows precisely what that produced — a *pending
  `privilege_request` approval for `security.firewall`*, whose card reads
  "requested by punar" and whose approval mints a 15-minute grant, the one
  thing §48 says an agent never gets. Now the wide rule, and the details
  object no longer invents an `agent_session_id` for an unattributed peer.
- The rule now exists **once**, as `Inner::agent_shaped_peer`, used by all
  three methods. The drift it prevents is the drift that produced both
  bugs.

**Gate integrity, by state rather than by return code.** `pending`,
`denied` and `expired` are each asserted to leave **no rank-5 user
preference** behind, and `approved` is asserted to write one. That is the
load-bearing half: `apply_calls == 0` only says nothing ran *then*, while
a preference recorded for an unanswered mutation would be picked up and
applied by the next `punard-reconcile` pass with no human in the loop —
a gate that leaks through the clock. The comment in
`an_agent_call_is_gated_and_nothing_executes` claimed this before; it
now asserts it.

**Two honesty corrections.** §4.4 listed a third `approvals.create`
hardening — refusing to route a card to a user with no active seat
session — that does not exist in code and that the paragraph three lines
below contradicts ("Neither ships in M9"). Replaced with what the code
does, plus an explicit "there is no seat-presence check anywhere"
(spec 1.22). And `m9-check.sh`'s `approvals.create` probe reported "is
refused" for a call that `debug rpc` sends with **no params**, so it is
refused at params parsing and never reaches authz; the row now says
which refusal it saw, and a new `info` line records that the agent-create
rule is proven in `crates/punard/tests/approvals.rs` rather than in the
guest, because the image ships no tool to hand-craft the frame.

| Gate re-run by this audit | Result |
|---|---|
| `cargo fmt --all --check` (`docker rust:1`) | exit 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | exit 0 |
| `cargo test --workspace --locked` | **723 passed, 0 failed** (719 + the four tests below) |
| `./tools/validate-schemas.sh` | 15 schemas, 132 documents, ALL PASS |
| `shellcheck v0.11.0` (pinned, full `ci.yml` list, 17 scripts) | exit 0 |
| `actionlint` | exit 0 |
| `qmllint` 6.11.2 (pinned Arch snapshot + `quickshell` 0.3.0-3) | 12 `.qml` files, **zero warnings** |
| `PUNAR_BUILD_MODE=summary ./tools/build-image.sh all` | exit 0, both profiles summarized |

New tests: `an_ai_agent_cannot_author_an_approval_even_as_root`,
`an_agent_shaped_peer_is_refused_by_every_consent_authoring_method`
(punard); and, in punar-secrets,
`a_value_pasted_where_a_class_name_belongs_is_neither_quoted_back_nor_recorded`
and `an_approval_for_one_class_cannot_buy_a_denied_one`. **§16.4 is unchanged**: none of this is runtime proof,
and the new `approvals.create` rule in particular has no in-VM assertion
by the tooling limit stated above.
