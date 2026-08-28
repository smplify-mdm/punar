# Punar local IPC — `punard` wire contract (v1, Milestones 3–5; M7 sibling socket in §10–§11; M8 ledger in §12–§13; M9 approvals, privilege and the secret broker in §14–§16)

Status: **contract for the M3 implementation** (spec section 76, Milestone 3)
**plus the Milestone 4 and Milestone 5 additions** — marked "M4"/"M5"
throughout; the protocol version stays `v: 1` per section 3.3 (new methods
and optional result fields are additive). M4 design rationale:
`docs/development/milestone-4.md`; M5 (enrollment against the mock control
plane): `docs/development/milestone-5.md`.
Everything in this document is binding on `punard` (server) and `punarctl`
(client). Spec authorities: section 10 (typed capability API only), section 11
(`punard`/`punarctl` responsibilities), section 60 (hard safety constraints —
no generic root RPC), section 61 (local IPC security), section 73
(denial-message voice), section 74.4 (security tests).

**M9 amendment (additive, still `v: 1`):** punard gains
`approvals.*` and `privilege.*` (§14), a new root-owned side file
`/run/punard/approvals.json` (§15), and a **third** local service —
`punar-secrets` on its own socket (§16, spec 11.4). Exit code 4
(`approval_required`), reserved since M3, becomes real. Design
rationale: `docs/development/milestone-9.md`.

M3 runs **unmanaged-first personal mode** (design language section 8): there is
no organization, no enrollment, no org policy source. Policy citations in this
contract say `personal-defaults` / "os default" and nothing else.
**(M5 amendment: enrollment exists — sections 5.9–5.11. An *unenrolled*
device still behaves exactly per the paragraph above; org citations appear
only while enrolled, and unenrolling restores them to absent.)**

---

## 1. Transport and socket

- **Transport:** Unix domain socket, `SOCK_STREAM` (spec section 61: "Unix
  domain sockets", "no unauthenticated localhost TCP control API"). There is
  no TCP listener of any kind.
- **Path:** `/run/punard/punard.sock`.

### 1.1 Why not `/run/punar/punard.sock`

`/run/punar` is an **M1 contract** owned `punar:punar` mode `0755`
(`usr/lib/tmpfiles.d/punar-desktop.conf`) so the unprivileged session can write
ready-markers and CI artifacts there. A control socket must not live in a
directory writable by an unprivileged user: the `punar` user could `unlink(2)`
the daemon's socket and bind its own at the same path, and every client
(including future root clients) would connect to the impostor. Spec section 61
"filesystem permissions" is only meaningful when the whole path is
root-controlled. Hence a dedicated root-owned directory:

```text
# usr/lib/tmpfiles.d/punard.conf   (shipped in the desktop extra tree)
d /run/punard    0750 root punar -
d /var/lib/punar 0700 root root  -
d /var/log/punar 0750 root punar -
```

### 1.2 Socket permissions and admission

- Directory `/run/punard`: `0750 root:punar` (tmpfiles, above).
- Socket `/run/punard/punard.sock`: created by `punard` at startup —
  bind with restrictive umask, then `chown root:punar` + `chmod 0660`
  **before** `listen()`. No systemd socket activation in M3 (the daemon is
  always-on per spec section 11.1; fewer moving parts).
- **Connection admission is the filesystem:** a peer can connect only if it is
  `root` or in group `punar` (the dev session user `punar` has primary group
  `punar`). Any other uid — `nobody` in the 74.4 test — fails `connect(2)`
  with `EACCES` before the daemon ever sees it. Consequence (honest limit):
  connection attempts blocked by the filesystem **cannot be audited** by
  `punard`; the audit trail starts at accepted connections.
- **Peer identity:** `SO_PEERCRED` (`uid`, `gid`, `pid`) read at `accept()`
  time (spec section 61 "peer credentials"). The uid is the authorization
  input for every request on that connection; the uid/pid also feed the audit
  event (`user_id`).

## 2. Framing

Newline-delimited JSON (NDJSON): one JSON object per `\n`-terminated line, in
each direction. No length prefixes, no binary framing.

- Requests on one connection are processed **sequentially, in order**; the
  response to request *k* is written before request *k+1* is read. Clients
  may keep a connection open for several requests; `punarctl` uses one
  request per connection and closes.
- **Line limit:** 4096 bytes per request line. Longer lines →
  `malformed_request` and the connection is closed (bounds server memory; no
  M3 method needs more).
- **Timeouts** (spec section 61 "timeouts"): 10 s read-idle per connection,
  10 s per-request processing, 10 s write. Expiry closes the connection.
  Client side: `punarctl` uses 5 s connect / 15 s response, and renders
  failure in section-73 voice ("The Punar daemon is not reachable…", next
  step: `systemctl status punard`).
  **M5 amendment (one method):** `enroll.start` (section 5.9) is processed
  under a **60 s** bound — its pipeline contains upstream calls plus a full
  reconcile pass, which TCG runs make slow — and `punarctl` uses a 90 s
  response timeout for the `enroll start`/`enroll stop` verbs. Every other
  method keeps the 10 s/15 s bounds unchanged.
  **Application amendment:** `apps.catalog` may spend 30 s verifying remote
  metadata (`punarctl`: 45 s), while `apps.install` and `apps.remove` have
  bounded 30-minute/10-minute backend transactions (`punarctl`: 30 minutes).
  They remain one synchronous inspect→mutate→verify transaction; expiry kills
  the child and returns a typed failure.
- Responses are emitted as a single line; UTF-8; no ANSI, no pretty-printing.

## 3. Envelope

### 3.1 Request

```json
{"v": 1, "id": "req-1", "method": "capabilities.set", "params": {"capability": "system.hostname", "desired_state": "punar-m3"}}
```

| Field    | Type   | Rules |
|----------|--------|-------|
| `v`      | int    | Protocol version. **Must be `1`.** Any other value → error `unsupported_version`. Field is required — its absence is `malformed_request`. |
| `id`     | string | Client-chosen correlation id, 1–64 chars. Echoed verbatim in the response. |
| `method` | string | Dotted lowercase method name from the table in section 5. |
| `params` | object | Method-specific; may be omitted when the method takes none. Unknown params → `invalid_params` (strict — forward compat is carried by `v`, not by ignoring fields). |

### 3.2 Response

Success:

```json
{"v": 1, "id": "req-1", "result": { "...": "method-specific" }}
```

Error (structured errors, spec section 61):

```json
{"v": 1, "id": "req-1", "error": {"code": "denied", "message": "Changing system.hostname needs administrator privileges.\nPolicy: personal defaults — just-in-time elevation arrives in Milestone 9.\nNext step: re-run as root: sudo punarctl capabilities set system.hostname <name>", "details": {"capability": "system.hostname", "decision": "deny", "policy_ids": ["personal-defaults"]}}}
```

Exactly one of `result` / `error` is present. `error.message` is **human prose
in the section 73 voice** — what happened, why, which policy, what the next
step is; never a bare errno. `error.details` is the machine layer: optional,
object, fields documented per code below.

### 3.3 Versioning and forward compatibility

- `v` is bumped only for envelope-breaking changes. Adding a *method* or
  adding an optional *result* field is **not** a version bump; clients must
  tolerate unknown fields in `result` (server→client direction only).
- M4 (desired-state/policy merge), M5 (enrollment), M9 (JIT elevation) are
  expected to add methods and result fields under `v: 1`. **M4 note:** this
  is exactly how M4 landed — `policy.effective` + `policy.explain` (sections
  5.7, 5.8), the `status.compliance` block (5.1), new optional
  `capabilities.set` / `reconcile` result fields (5.4, 5.6), all under
  `v: 1`. **M5 note:** likewise — `enroll.start` / `enroll.status` /
  `enroll.stop` (sections 5.9–5.11), the optional `status.org` field and
  the documented `mode`/`enrolled` value changes (5.1), two additive error
  codes (section 4), all under `v: 1`.
  **M9 note:** likewise, and exactly as this section predicted in M3 —
  `approvals.*` / `privilege.*` (§14), two additive error codes
  (`approval_required`, `expired`, section 4), the authorization rungs
  added to `capabilities.set` (§14.8) with its request shape, result
  object and audit action unchanged, and a whole sibling socket (§16),
  all under `v: 1`.
- A server refusing `v` reports `unsupported_version` with
  `details.supported: [1]`.

## 4. Error codes

| `code`                | Meaning | `details` fields |
|-----------------------|---------|------------------|
| `malformed_request`   | Line was not valid JSON / envelope fields missing or wrong type / line over limit. Connection closes after the response (or silently if no `id` could be parsed — then `id` is `null`). | — |
| `unsupported_version` | `v` != 1. | `supported` |
| `unknown_method`      | Method not in the section 5 table. This is the answer to `system.exec`, `shell.run`, and every other generic-execution probe (spec sections 10, 60): **such methods do not exist and will never exist**. | `method` |
| `invalid_params`      | Params missing/extra/of wrong shape, unknown capability state value, invalid hostname/timezone syntax. | `param`, `reason` |
| `denied`              | Authorization denied (M3: mutating method from non-root peer). Always audited (`decision: "deny"`). Message is the section-73 denial text. | `capability`, `decision`, `policy_ids` |
| `not_found`           | `capabilities.get`/`set` on an id not in the registry. | `capability` |
| `apply_failed`        | Backend apply step failed (e.g. `nft` exited nonzero). Audited with `result: "failure"`. | `capability`, `stage` |
| `verify_failed`       | Apply succeeded but post-apply verification did not observe the desired state (spec section 42 "Verify"). Audited with `result: "verify_failed"`. | `capability`, `expected`, `observed` |
| `internal`            | Daemon bug or I/O error. Never contains secrets (Redacted by construction). | — |
| `conflict` (M5)       | The request contradicts current enrollment state: `enroll.start` while already enrolled, `enroll.stop` while not enrolled. | `state` |
| `approval_required` (M9) | The call is **gated**: an approval was created and **nothing executed**. `punarctl` maps it to **exit code 4**, reserved for this since M3. Message is the section 73 gate text; §14.1. | `approval_id`, `expires_at`, `capability`, `resource`, `decision`, `policy_ids` |
| `expired` (M9)      | An approval passed `expires_at`, or a presented credential's TTL lapsed. Distinct from `conflict` (= already resolved). §14.1, §16.5. | `expires_at` |
| `upstream_unreachable` (M5) | The control plane did not answer (connect/call failure or timeout during `enroll.start`). Section-73 message names the stage and the next step; local state is untouched (enrollment is all-or-nothing). Sync failures **outside** `enroll.start` never surface as request errors — they queue per spec section 55 (milestone-5.md section 7). | `stage` |

## 5. Methods (M3 surface + M4/M5 additions — complete)

The method set is closed. There is **no** exec, shell, script, or
run-as-root method, by architecture (spec section 10 "Prohibited:
RunRootShell(command)"; section 60). The 74.4 security test probes this via
`punarctl debug rpc system.exec` and must get `unknown_method`.

| Method              | AuthZ                 | Mutating | Audited |
|---------------------|-----------------------|----------|---------|
| `status`            | any connected peer    | no       | no      |
| `capabilities.list` | any connected peer    | no       | no      |
| `capabilities.get`  | any connected peer    | no       | no      |
| `capabilities.set`  | **root only (uid 0)** | yes      | always (allow and deny, success and failure) |
| `audit.tail`        | any connected peer    | no       | no      |
| `reconcile`         | **root only (uid 0)** | no in M3 (re-verify only); **yes since M4** (remediates per policy, section 5.6) | always |
| `policy.effective` (M4) | any connected peer | no      | no      |
| `policy.explain` (M4)   | any connected peer | no      | no      |
| `enroll.start` (M5)     | **root only (uid 0)** | yes  | always  |
| `enroll.status` (M5)    | any connected peer | no      | no      |
| `enroll.stop` (M5)      | **root only (uid 0)** | yes  | always  |
| `approvals.list` / `approvals.get` (M9) | any connected peer | no (lazy expiry sweep) | no |
| `approvals.create` (M9) | **root only (uid 0)** | yes | always |
| `approvals.resolve` (M9) | **human only** (§14.5) | yes (may execute) | always |
| `approvals.consume` (M9) | **root only (uid 0)** | yes | always |
| `privilege.request` (M9) | any connected peer **except agent-attributed peers** | yes | always |
| `privilege.status` (M9) | any connected peer | no (lazy expiry sweep) | no |
| `privilege.revoke` (M9) | grant owner or root | yes | always |
| `apps.catalog` | any connected peer | no | no |
| `apps.list` | any connected peer | no | no |
| `apps.install` | **human, personal device only** | yes | always |
| `apps.remove` | **human, personal device only** | yes | always |
| `install.targets` | any connected peer, **live environment only** | no | no |
| `install.plan` | **root only, live environment only** | no | always (`success`, `refused`, `failure`) |
| `install.status` | any connected peer, **live environment only** | no | no |

"Any connected peer" = admission already proved root-or-group-`punar`
(section 1.2). Root-only is a fixed M3 rule named `personal-defaults`;
group-`punar` mutation via JIT elevation/polkit is Milestone 9 (spec
sections 48, 61), and the denial message says so.
**M9 amendment:** that promise is kept. `capabilities.set` keeps its
request shape, validation, errors, result object and audit action, and
gains two authorization rungs *around* the root-only rule — an AI
authority path for agent-attributed peers (which is where
`approval_required` is produced) and a time-boxed grant path for humans.
Both are specified in §14.8; polkit itself is still not used.

### 5.1 `status`

Params: none.

```json
{"v":1,"id":"1","result":{
  "protocol_version": 1,
  "daemon_version": "0.1.0",
  "started_at": "2026-08-25T07:00:12Z",
  "device_id": "dev_9f3k2v8q1x",
  "mode": "personal",
  "enrolled": false,
  "hostname": "punar-desktop",
  "capabilities_total": 3,
  "last_reconcile": "2026-08-25T07:00:13Z",
  "audit": {"path": "/var/log/punar/audit.jsonl", "events": 42},
  "device": {
    "class": "laptop", "source": "observed",
    "facts": {"memory_mib": 8192, "logical_cores": 4,
              "battery_present": true, "display_connected": true}
  }
}}
```

`device_id` is generated once at first start (`dev_` + 10 random alnum,
persisted `/var/lib/punar/device-id`, `0600`) — the first real slice of the
spec 11.1 "device identity" responsibility. `mode` is `"personal"` until M5;
no org fields exist in the result (design section 8: enrollment adds fields,
never redraws).

**M5 amendment — enrollment surfaces here, additively.** While enrolled:
`enrolled` is `true`, `mode` is `"managed"` (the value change this contract
announced above), and the result carries the optional field

```json
"org": {"id": "acme", "name": "Acme", "display_name": "Acme Engineering",
         "domain": "acme.com"}
```

While unenrolled the M3 shape is byte-identical — `org` is absent, never
`null` (enrollment adds fields, never redraws). The device token appears in
no result of any method, ever (it is `Redacted` in memory; spec section 53).

**M4 addition — `compliance` result field** (optional per 3.3; always
present since M4). Spec section 52 states, **personal scope** (the device
measured against its own effective document — OS defaults + user
preferences; no org involved before M5):

```json
"compliance": {
  "overall": "compliant",
  "capabilities": [
    {"capability": "security.firewall", "state": "compliant"},
    {"capability": "system.hostname",   "state": "compliant"},
    {"capability": "time.timezone",     "state": "compliant"}
  ],
  "drift_remediated_total": 2,
  "last_remediation_at": "2026-08-25T09:14:02Z"
}
```

`state` ∈ `compliant | remediating | non_compliant | unknown | unsupported
| exception` (section 52). States are computed at reconcile time (the boot
reconcile guarantees a value before the socket opens);
`drift_remediated_total` is a monotonic in-memory counter of successful
remediations since daemon start (`last_remediation_at` is `null` until the
first one). `overall` = worst of `non_compliant > unknown > remediating >
exception > compliant`. Semantics and computation:
docs/development/milestone-4.md section 5.

**Device-class addition — `device` result field** (optional per 3.3; always
present once the classifier ships). This is a read-only hardware observation,
not a capability: no method can apply RAM, CPUs, a battery, or a display.
`class` is the closed set `workstation | laptop | appliance`; `source` is
`observed` in production and `forced` only through the typed CI seam. Optional
boolean facts use `null` for an unreadable interface, distinct from measured
absence. An incomplete observation chooses the conservative appliance path and
keeps the unknown facts visible rather than silently inventing hardware.

### 5.2 `capabilities.list`

Params: none. Result:

```json
{"capabilities": [ { "...capability descriptor..." }, ... ]}
```

Each element **is** a `schemas/capability/capability-descriptor.json` document
— field names verbatim (`capability`, `supported`, `current_state`,
`desired_state`, `mutable`, `requires_reboot`, `risk`, `managed_by`,
`verification`, plus `state_schema`, `allowed_desired_states` where
enumerable, `privilege_required`, `approval_requirement`, `audit_category`).
`current_state` is **observed live** at request time (never cached), so
`punarctl capabilities` showing `security.firewall · enabled` is a real
nftables read. `managed_by` is `"local"` in personal mode. The M3 registry is
exactly: `security.firewall`, `system.hostname`, `time.timezone`
(backends: docs/development/milestone-3.md section 4).

### 5.3 `capabilities.get`

Params: `{"capability": "security.firewall"}` → `{"descriptor": {...}}`
(same shape as one `capabilities.list` element). Unknown id → `not_found`.

### 5.4 `capabilities.set`

Params: `{"capability": "<id>", "desired_state": <state value>}`.

Pipeline per request (spec section 42, M3 subset): validate → authorize →
record desired state (`/var/lib/punar/desired.json`, `0600`) → **apply** →
**verify** (re-observe; must equal desired) → **audit** → respond.

Result: `{"descriptor": {...post-verify...}, "changed": true|false}`
(`changed: false` when the observed state already equaled the request —
idempotent, still audited with `result: "noop"`).

Errors: `denied` (non-root — the section 73 test path), `not_found`,
`invalid_params` (state not in `allowed_desired_states` / fails the
capability's syntax rules), `apply_failed`, `verify_failed`.

**M4 semantics — compatibility stated precisely.** Request shape, authz
(root-only), validation, errors, and the audit action are **unchanged**.
The recording step changes: the request is recorded as a **User Preference
layer entry** (`/var/lib/punar/preferences.json`; the M3 `desired.json` is
migrated once and retired — milestone-4.md section 3.3), the effective
document is recomputed through the section 39 merge, and the **effective**
value for the capability is applied + verified. In personal mode nothing
outranks a user preference, so effective == requested and the
`{descriptor, changed}` result is **byte-identical to M3** — existing
callers observe no difference. When a higher-precedence source overrides
(engine/tests only until M5), the preference is still recorded, the
effective value is applied, and the result additionally carries
`"overridden": true` and `"effective_state": <value>` (optional fields per
3.3; never emitted in personal mode). `audit.policy_ids` cites the winning
source's policy id (`["personal-defaults"]` in personal mode — unchanged).

**M5 semantics — the managed path is now reachable in a running system**
(enrollment writes org layers into `policy.d`; milestone-5.md section 5.5).
Two amendments, both additive:

- **Denial citation on org-pinned paths.** A non-root `capabilities.set` is
  still denied (exit 3) by the root-only rule *before* policy is consulted,
  but when the target path is org-pinned (`user_override_permitted ==
  false` in the effective document) the denial message and
  `details.policy_ids` cite the **pinning source** in the section 73 voice
  (e.g. "security.firewall is managed by Acme Engineering Baseline
  (eng-baseline-v12). User override: not permitted. Next step: exceptions
  require approval (Milestone 9).") instead of the M3 "personal defaults"
  text, which would be a false citation on a managed device. Unpinned
  paths keep the M3/M4 denial text byte-identical.
- **Client rendering.** `punarctl` renders `overridden: true` as a neutral
  verdict line ("Recorded, not applied · <capability> is managed by
  <source name> (<policy id>) · effective: <state>"). The root caller's
  exit code is `0` — the preference was recorded and outranked, not
  forbidden (spec section 39); `--json` output was already complete in M4.

### 5.5 `audit.tail`

Params: `{"n": 20}` (optional; default 20; max 1000 — larger values are
clamped, not errors). Result: `{"events": [ {...AuditEvent...}, ... ]}` —
newest last, each element schema-conformant
(`schemas/audit/audit-event.json`). The daemon reads the file; clients never
need read access to `/var/log/punar/audit.jsonl` (its 0640 root:punar mode is
a debugging convenience, not the API).

### 5.6 `reconcile`

Params: none. **M3 semantics: re-observe and re-verify actual state against
the recorded desired state; report drift; do not remediate.** (Remediation
classification and the policy merge are Milestone 4 — spec sections 39, 42,
43.) Root-only because M4 will make it applying, and the authz surface must
not loosen later.

```json
{"v":1,"id":"1","result":{
  "reconciled_at": "2026-08-25T07:41:03Z",
  "drift_count": 1,
  "capabilities": [
    {"capability": "security.firewall", "desired_state": "enabled",
     "current_state": "disabled", "drift": true, "verified": true},
    {"capability": "system.hostname", "desired_state": "punar-m3",
     "current_state": "punar-m3", "drift": false, "verified": true},
    {"capability": "time.timezone", "desired_state": "UTC",
     "current_state": "UTC", "drift": false, "verified": true}
  ]
}}
```

Audited as `action: "reconcile"`, `resource: "capability_registry"`,
`decision: "allow"`, `result: "drift_detected"` | `"clean"`.

**M4 semantics — reconcile remediates per policy** (the semantic change M3
pre-announced by making the method root-only: "M4 will make it applying,
and the authz surface must not loosen later"). One synchronous pass of the
full spec section 42 chain — observe → normalize → load (layered merge) →
diff → policy (spec 43 classify: `auto_remediate | alert_only |
approval_required`; personal default `auto_remediate` for all three
capabilities) → plan → apply → verify → audit → compliance. Design:
docs/development/milestone-4.md section 5.

Every M3 result field keeps its M3 meaning (`drift` / `drift_count`
describe the **pre-remediation** observation). Additive result fields:

- per capability: `"classification": "auto_remediate" | "alert_only" |
  "approval_required"` and `"remediation": "applied" | "none" |
  "apply_failed" | "verify_failed" | "alert_only" | "suppressed"`
  (`suppressed` = loop protection engaged; `approval_required` classifies
  as such but behaves as `alert_only` until M9 delivers approvals);
- top level: `"remediated_count": <n>` and `"compliance": {...}` (same
  shape as the `status` compliance block, section 5.1).

**Loop protection:** at most **3** consecutive failed remediation attempts
per capability; then the capability is `non_compliant`, one audit event with
`result: "attempts_exhausted"` is emitted on the transition, and further
attempts are suppressed until the effective value changes, a manual
`capabilities.set` succeeds, or the daemon restarts. A successful verify
resets the counter.

Each remediation **attempt** is audited individually: `action:
"reconcile.remediate"`, `resource: <capability id>`, `decision: "allow"`,
`result: "success" | "apply_failed" | "verify_failed" |
"attempts_exhausted"`, `policy_ids: [<winning policy id>]` — in addition to
the M3 summary event above, which is unchanged.

### 5.7 `policy.effective` (M4)

Params: none. Read-only, any connected peer, not audited. Returns the
effective document produced by the spec section 39 layered merge
(OS defaults + user preferences in personal mode; org layers join in M5):

```json
{"v":1,"id":"1","result":{
  "computed_at": "2026-08-25T09:14:02Z",
  "entries": [
    {"path": "security.firewall", "effective_value": "enabled",
     "source": {"kind": "local_user_preference", "rank": 5,
                "policy_id": "personal-defaults",
                "name": "Personal preference"},
     "user_override_permitted": true,
     "compliance_state": "compliant"},
    {"path": "system.hostname", "effective_value": "punar-m3",
     "source": {"kind": "local_user_preference", "rank": 5,
                "policy_id": "personal-defaults",
                "name": "Personal preference"},
     "user_override_permitted": true,
     "compliance_state": "compliant"},
    {"path": "time.timezone", "effective_value": "UTC",
     "source": {"kind": "os_secure_default", "rank": 6,
                "policy_id": "personal-defaults",
                "name": "OS default"},
     "user_override_permitted": true,
     "compliance_state": "compliant"}
  ]
}}
```

`source.kind` and `source.rank` are the `policy_source_kind` enum and
precedence-rank mapping of `schemas/policy/policy-source.json` (1 = hard OS
safety constraint … 6 = OS default; lower rank wins).
`user_override_permitted` is `true` iff the winning rank is ≥ 5 — a user
may override the OS default or their own preference; anything above the
User Preference rung pins the value (personal mode: always `true`).

### 5.8 `policy.explain` (M4)

Params: `{"path": "security.firewall"}` — a capability path from the
effective document. Read-only, any connected peer, not audited. Result is
one `policy.effective` entry without `path` — exactly the spec section 40
information set:

```json
{"v":1,"id":"1","result":{
  "effective_value": "enabled",
  "source": {"kind": "local_user_preference", "rank": 5,
             "policy_id": "personal-defaults",
             "name": "Personal preference"},
  "user_override_permitted": true,
  "compliance_state": "compliant"
}}
```

Unknown path → `not_found` (`details.param: "path"` sibling shape to the
capability case; the section 73 message names the path and points at
`punarctl policy effective`). `punarctl policy explain <path>` renders this
in the spec 40 layout verbatim (milestone-4.md section 7).

While enrolled, `source` cites the winning org layer verbatim from the
merge (e.g. `{"kind": "organization_baseline", "rank": 2, "policy_id":
"eng-baseline-v12", "name": "Acme Engineering Baseline"}` with
`user_override_permitted: false`) — no M5 shape change; the M4 renderer
already prints these fields, which is how the spec section 40 managed
output becomes real without touching this method.

### 5.9 `enroll.start` (M5)

Params: `{"org_domain": "acme.com"}`. **Root only**, mutating, always
audited (`action: "enroll.start"`, `resource: "enrollment"`; success cites
the fetched policy ids in `policy_ids`). Processed under the 60 s bound
(section 2).

Pipeline (spec section 49 mapped to the mock control plane; design and the
honest-labeling rules: milestone-5.md sections 3, 5.1): guard (already
enrolled → `conflict`) → `org.discover` → `enroll.register` with the
persistent `device_id` and a fresh in-memory bootstrap secret →
store the returned device token (`/var/lib/punar/device-token`, `0600`,
`Redacted` in memory) → `policy.fetch` → strict-parse each policy-source
envelope (the M4 loader's validation) → write them to
`/var/lib/punar/policy.d/` → recompute the section 39 merge → one full
section 42 reconcile pass → first compliance + inventory report (failures
queue per section 55; they do not fail enrollment) → persist
`/var/lib/punar/enrollment.json` (`0600`) → rewrite the section 9 status
file. All-or-nothing up through the policy.d write: any failure before
that point removes everything this call created and returns
`upstream_unreachable` / `invalid_params` with local state untouched.

```json
{"v":1,"id":"1","result":{
  "enrolled": true,
  "org": {"id": "acme", "name": "Acme", "display_name": "Acme Engineering",
           "domain": "acme.com"},
  "policy_ids": ["eng-baseline-v12"],
  "attestation": "simulated",
  "enrolled_at": "2026-08-26T09:00:00Z",
  "first_sync": {"compliance": "success", "inventory": "success"}
}}
```

`attestation` is the literal honesty label: the spec 49 attestation step is
**simulated** by the mock and reported as such wherever enrollment state
appears. Errors: `conflict`, `upstream_unreachable`, `invalid_params`
(malformed domain / envelope failed the loader's validation), `denied`.

### 5.10 `enroll.status` (M5)

Params: none. Read-only, any connected peer, not audited.

```json
{"v":1,"id":"1","result":{
  "enrolled": true,
  "org": {"id": "acme", "name": "Acme", "display_name": "Acme Engineering",
           "domain": "acme.com"},
  "policy_ids": ["eng-baseline-v12"],
  "enrolled_at": "2026-08-26T09:00:00Z",
  "attestation": "simulated",
  "last_sync": {"at": "2026-08-26T09:02:00Z", "result": "success",
                 "pending": false}
}}
```

Unenrolled: `{"enrolled": false}` with the org-shaped fields absent.
`last_sync.result` ∈ `"success" | "unreachable" | null`; `pending` is true
while a report is queued (bounded latest-wins queue, spec section 55;
milestone-5.md section 7). The device token appears in no field.

### 5.11 `enroll.stop` (M5)

Params: none. **Root only**, mutating, always audited
(`action: "enroll.stop"`, `resource: "enrollment"`). Guard: not enrolled →
`conflict`. Removes exactly the policy.d files recorded at enrollment,
deletes `enrollment.json` and the device token, recomputes the merge, runs
one reconcile pass (recorded user preferences resurface as the winning
layer per spec section 39), rewrites the section 9 status file. Result:
`{"enrolled": false, "removed_policy_ids": ["eng-baseline-v12"]}`.

**Local-only (documented limit):** M5 has no unregister RPC; the mock
control plane keeps its device record and received-report history.
Unenrollment stops all future sync and restores local state; it does not
(and could not honestly claim to) retract what the org already received.
Works with the control plane unreachable — it touches only local files.

### 5.12 `apps.catalog`

Params are `{"query":"music"}` for a local catalog search,
`{"id":"spotify"}` for one exact app plus live source inspection, or `{}`
for all local summaries. `id` and `query` together are `invalid_params`.
Read-only, any connected peer, not audited.

The catalog is immutable signed-image data. A Flatpak detail query runs
`remote-info` at the catalog's exact commit, hashes the exact returned
metadata, rejects any mismatch, and derives the `containment` and
`permissions` result fields from that metadata. There is deliberately no
publisher-authored or catalog-authored containment label.

An ARM64 app with no native payload returns its curated web source instead:

```json
{"app":{"id":"spotify","name":"Spotify","source":"web",
 "url":"https://open.spotify.com/","browser":"chromium","action":"open",
 "installed":false,"disclosures":[...]}}
```

The x86_64 native result includes `app_id`, `installed`, and:

```json
"inspection":{"verified":true,"commit":"<64 hex>",
 "runtime":"org.freedesktop.Platform/x86_64/25.08",
 "metadata_sha256":"<64 hex>","containment":"sandboxed",
 "permissions":["Network access","Audio playback",...]}
```

If the remote metadata differs, no detail card claiming verified containment
is returned: the method fails `verify_failed`.

### 5.13 `apps.list`

Params: none. Read-only, any connected peer, not audited. Returns each catalog
id, selected architecture source, native installed state and observed commit.
Web apps are not falsely represented as locally installed packages.

### 5.14 `apps.install`

Params:

```json
{"id":"spotify","confirm_metadata_sha256":"<64 lowercase hex>"}
```

The digest is the value shown by the calling app card. Under a single daemon
transaction lock, punard re-inspects the exact pinned commit and requires the
catalog digest, caller-confirmed digest and observed digest to agree. It then
installs with a fixed Flatpak argv and verifies the resulting commit. No
request field can supply a remote, ref, commit, executable or option.

The call is allowed only for a human-attributed peer on a personal device.
Agent-attributed calls are denied and audited. Enrolled devices fail closed
until the organization application-policy bridge is implemented; this keeps a
personal catalog from bypassing managed software policy. Audit action is
`system.install_package`, resource is the catalog id, with `success`, `noop`,
`failure` or `verify_failed`.

### 5.15 `apps.remove`

Params: `{"id":"spotify"}`. Same human/personal authorization and
serialization as install. The Flatpak application id is resolved from the
catalog, removal is fixed-argv and absence is verified. Audit action is
`system.remove_package`; web sources have no local package and return
`conflict` rather than pretending to remove browser data.

### 5.16 `install.targets`

Params: none. Read-only and not audited. This method exists only when the
daemon read the exact `punar.live=1` token from `/proc/cmdline`; an installed
system returns `unknown_method` with `details.mode: "installed"`.

The result enumerates physical candidate disks from `/sys/class/block`, with
model, serial, WWN when present, byte size, logical-sector size, partition
table and observed partitions/filesystems. A disk below the real 33 GiB plus
GPT/alignment floor remains visible with `eligible: false` and the full
17 GiB OS + 16 GiB data-floor arithmetic. The following never appear:

- any disk or partition backing a current mount (the live boot medium);
- any disk carrying a filesystem labelled `PUNAR_ANSWERS`;
- loop, ram, zram, device-mapper, md, optical and floppy pseudo targets.

The implementation is discovery only. It opens no target device for writing.

### 5.17 `install.plan`

Strict params:

```json
{"disk":"/dev/vda","keymap":"us","encryption":"luks2",
 "recovery_mode":"personal_copy"}
```

`disk` must exactly match a device returned by `install.targets`; it is not an
arbitrary filesystem path. `encryption` is `luks2` or `none`.
`recovery_mode` is `personal_copy`, `organization_escrow`, or `none`, with
strict valid combinations (encrypted installs require a recovery lane;
unencrypted installs cannot claim one).

Root-only, non-mutating, and audited as `action: "install.plan"`,
`resource: "system_disk"`. Before returning a plan, punard:

1. re-observes every disk and refuses protected targets;
2. refuses a Punar PARTUUID on a *different* disk while allowing the selected
   disk to carry one for a legitimate reinstall;
3. verifies the exact release-manifest bytes against a trusted Ed25519 release
   key and requires its architecture/boot platform to match the live image;
4. reads the first and last 34 logical sectors and binds their SHA-256, the
   serial, optional WWN, size and device node inside the plan;
5. returns the four fixed partitions, byte offsets/sizes, filesystems,
   encryption decision, data subvolumes and signed payload digest.

The response validates against `schemas/install/plan.json`. `plan_token` is
SHA-256 over compact, recursively key-sorted JSON of the nested `plan` object
(the `jq -cS` JSON bytes, excluding jq's trailing newline). A change to either
GPT edge or any plan field changes
the token. The internal zero-write apply preflight now keeps a bounded token
registry for this daemon boot and re-reads the serial, WWN, size,
logical-sector size, both GPT edges and signed release. Only an exact match may
reach the future executor, and failed revalidation cannot silently register a
new token. Its strict parameter type carries descriptor numbers for the
passphrase and optional OOBE passthrough, never their bytes. **The public
mutating `install.apply` method is not registered in this slice**: exposing a
method that stopped after preflight would claim an installer that does not
exist. There is no `install.exec`, script, hook or caller-supplied command/path.

### 5.18 `install.status`

Params: none. Read-only, unaudited and live-only. The result is the same
secret-free object written atomically at `0644` to
`/run/punar/install.json`; the shell watches the file with `FileView`, while
typed clients use this method. Both begin in `state: "idle"` with the fixed
nine-phase order `verify_release`, `partition`, `encrypt`, `format`,
`write_slot_a`, `re_read`, `boot`, `seed`, `verify_installed`. Only
`write_slot_a` may carry `completed_bytes` and `total_bytes`, because it is the
only phase with a truthful denominator. The recovery pauses are expressed as
`state: "awaiting"` plus `awaiting: "recovery_key_ack"` or
`"organization_escrow_receipt"`.

The object validates against `schemas/install/status.json`. It has no field
for a passphrase, recovery key, account, answer contents, process id, command,
or path other than the confirmed target device. An installed system returns
`unknown_method` and does not publish this live status file.

## 6. Audit contract (spec section 53)

- File: `/var/log/punar/audit.jsonl` — one `AuditEvent` JSON object per line,
  `O_APPEND`, created `0640 root:punar` by `punard`; directory
  `0750 root:punar` via tmpfiles. Writes only by `punard`; reads for humans
  via `punarctl audit tail` (through the daemon).
- Every event conforms to `schemas/audit/audit-event.json` — all 12 required
  fields present. M3 population rules for fields the daemon cannot yet fill
  from a richer context:
  - `user_id`: username for the peer's `SO_PEERCRED` uid (`"root"`,
    `"punar"`), `"uid:<n>"` if unresolvable, `"punard"` for
    daemon-initiated events (startup reconcile).
  - `agent_session_id`: **`"agt_none"`** — a reserved, pattern-valid sentinel
    meaning "no AI agent session involved". (The shipped schema requires the
    field with pattern `^agt_`; M3 events have no agent. Recorded as a
    contract follow-up for the M4 schema owner: consider making the agent
    fields conditional on `source: "ai_agent"`. Until then the sentinel is
    the documented, greppable truth.)
  - `project_id`: `"system"` (no project workspaces in the control plane
    until M6).
  - `source`: `"human"` for CLI-originated requests, `"service"` for
    daemon-initiated events. (Errata 2026-08-25: this line originally said
    `"os"`, which is **not** a value of the shipped
    `schemas/common/defs.json#/$defs/principal_kind` enum that
    `audit-event.json` binds `source` to; the schema is the contract, so
    the implementation uses `"service"` — `punar_common::AuditActor::daemon()`
    pins this, and a test pins that `"os"` is absent from the schema enum.)
  - `action`: the method name verbatim (`"capabilities.set"`,
    `"reconcile"`).
  - `resource`: the capability id, or `"capability_registry"` for
    `reconcile`.
  - `policy_ids`: `["personal-defaults"]` — the M3 built-in root-only rule.
    Real policy ids arrive with the M4 merge. **(M4: delivered — the array
    cites the winning source's `policy_id` from the section 39 merge; in
    personal mode this is still `"personal-defaults"` for every path.)**
  - `result`: `"success"` | `"noop"` | `"denied"` | `"failure"` |
    `"verify_failed"` | `"drift_detected"` | `"clean"`. **M4 adds**
    `"apply_failed"` and `"attempts_exhausted"` (remediation attempts,
    section 5.6) — the schema's `result` is an open string by design, so
    no schema change.
- **M4 additions to the audited set:** every remediation attempt
  (`action: "reconcile.remediate"`, resource = capability id) and the
  one-shot M3-store migration (`action: "state.migrate"`,
  `resource: "state_store"`, `source: "service"`, `user_id: "punard"`).
  Both action names match the schema's dotted-lowercase `action` pattern —
  no schema change. Read methods (including the new `policy.*`) remain
  unaudited.
- **M5 additions to the audited set:** `enroll.start` and `enroll.stop`
  (resource `"enrollment"`; allow and deny, success and failure; success
  `policy_ids` cite the org policy ids), and `enroll.sync` (resource
  `"control_plane"`) — emitted on **transitions only**: `result:
  "unreachable"` once when the control plane stops answering, `result:
  "success"` once on recovery. Per-retry events (one per 120 s timer pass
  during an outage) are deliberately not emitted — they would encode no
  new fact; the steady state is readable in `enroll.status.last_sync`.
  `"unreachable"` joins the open `result` string set — no schema change.
  The device token is `Redacted` by type: no audit event can contain it.
  Read methods (`enroll.status`) remain unaudited.
- **Installer planning addition:** `install.plan` is audited even though it
  is read-only, because it is the first attributable step of a destructive
  workflow. Its resource is `system_disk`; success is `success`, a safety or
  validation refusal is `refused`, and discovery/trust I/O is `failure`.
  `install.targets` remains unaudited. Neither event shape can carry a
  passphrase, recovery key, partition bytes, or arbitrary caller payload.
- **Honest attribution limit (M4):** reconcile runs triggered by
  `punard-reconcile.timer` arrive through `punarctl` as uid 0, so their
  events carry `user_id: "root"`, `source: "human"` — the daemon sees only
  peer credentials and cannot distinguish the timer from an administrator.
  A client-asserted "I am the timer" flag would be spoofable and is not
  added.
- **What is audited:** every `capabilities.set` (allow and deny, all
  results), every `reconcile`, every `denied` authorization. Read methods are
  not audited in M3 (nothing privileged happens; revisit with remote queries,
  spec section 51).
- **No secrets by construction:** no M3 method carries a secret; state
  values are hostnames/timezones/enabled-disabled. Any future secret-bearing
  field must be typed `Redacted` in `punar-common` (spec sections 1.19, 53),
  whose `Serialize`/`Debug` emit the placeholder — the event cannot leak what
  the type cannot print.
- **Rotation: explicitly OUT of M3.** The file grows unbounded; acceptable
  for dev images at M3 event rates. Follow-up (target M5, with enrollment
  traffic): size-capped rotation in `punard` or logrotate. Documented here so
  nobody mistakes absence for oversight. **(M5: delivered — `punard`
  rotates `audit.jsonl` → `audit.jsonl.1` at 8 MiB, one rotated file kept,
  checked at write time. `audit.tail` reads the live file only.)**

## 7. Client behavior (`punarctl`)

- Connects as the invoking user; never elevates itself; the *daemon* is the
  authorization point. `sudo punarctl …` is the M3 way to run mutating verbs.
- Human output follows Plate D-014 (`docs/design/mockups/cli-grammar.html`):
  tracked-uppercase masthead + U+2500 rule, middle-dot separators, aligned
  columns, ANSI color only on status words; personal mode shows no org rows.
  `--json` on every verb prints the `result` object verbatim (registry field
  names unchanged). Non-TTY stdout or `NO_COLOR` strips ANSI.
- Exit codes (D-014 Sect III): `0` success · `1` runtime/daemon error ·
  `2` usage (clap) · `3` denied · `4` approval_required (reserved until M9) ·
  `5` daemon unreachable.
- **M4 verbs:** `punarctl policy effective` (D-014 table over 5.7) and
  `punarctl policy explain <path>` (spec section 40 layout verbatim over
  5.8; personal-mode strings "Personal preference" / "OS default",
  `personal-defaults`, "Permitted"); `punarctl status` renders the 5.1
  compliance block per the spec section 52 example. Personal mode still
  shows no org rows — personal compliance (device vs. its own effective
  document) is not an org row. Rendering contract:
  docs/development/milestone-4.md section 7.
- **M5 verbs:** `punarctl enroll start <domain>` (over 5.9; renders org,
  policy ids, and `Attestation  SIMULATED` — the honesty label is loud by
  design; 90 s client timeout per section 2), `punarctl enroll status`
  (over 5.10), `punarctl enroll stop` (over 5.11; "Personal state restored
  · org layers removed"). `punarctl status` adds an
  `Organization  <display name> · <policy id>` row while enrolled (absent
  otherwise — org rows never render on a personal device). The 5.4 M5
  amendments: the overridden-set verdict line and the org-citing denial.
  Rendering contract: docs/development/milestone-5.md section 8.3.
- `punarctl debug rpc <method>` (hidden) sends an empty-params request with an
  arbitrary method name — exists solely so the 74.4 "unauthorized IPC" /
  section 60 negative tests can probe the server from inside the image. The
  server's method table is the enforcement point; this flag adds no server
  capability.

## 8. Explicit non-goals of this contract (M3, amended M4/M5)

- No generic execution method of any kind (spec sections 10, 60) — permanent.
  There is also **no write-side `policy.*` method**: the only policy
  mutations are `capabilities.set` (user preference) and, since M5, the
  enrollment-managed `policy.d` drop (`enroll.start`/`enroll.stop` — which
  write only whole fetched envelopes, never accept policy content as
  params).
- No TCP, no abstract-namespace sockets (path perms are the admission
  mechanism), no SCM_RIGHTS fd passing. This holds for the M5 control-plane
  *client* side too: `punard` speaks to the (mock) control plane over a
  root-only UDS, and the mock itself has no TCP listener
  (milestone-5.md section 4.2).
- ~~No policy merge (`policy.*` arrives M4)~~ **(M4: landed — sections 5.7,
  5.8)**; ~~no enrollment (`M5`)~~ **(M5: landed — sections 5.9–5.11,
  against the dev/CI-only mock control plane)**; no approvals or JIT
  elevation (`M9` — `approval_required` classifications behave as
  alert-only until then), ~~no agent methods (`M7+`)~~ **(M7: landed —
  but NOT here: `agents.*` lives on the separate `punar-agentd` socket,
  section 10; `punard`'s own method table is unchanged and still
  closed)**, no remote admin
  queries (spec section 51 — `M10`; the mock reserves the `admin.*` names
  and answers `unknown_method`).
- No event subscription/streaming; `audit.tail` is pull-only. The M5 shell
  wiring is a **file** the shell watches (section 9), deliberately not a
  subscription surface. Revisit when a panel needs per-row live data (M6+).

## 9. Side contract (M5): `/run/punar/status.json`

Not IPC — a world-readable summary file `punard` writes so the shell can
render enrollment/compliance chrome without a socket connection or polling
(the shell watches it with a `FileView`; design: milestone-5.md section 8).

- Written by `punard` at startup and whenever the tuple changes; atomic
  tmp+rename within `/run/punar`; mode `0644 root:root`.
- Content — **summary only**, exactly:

  ```json
  {"v": 1, "enrolled": true, "org_name": "Acme Engineering",
   "compliance_overall": "compliant", "device_class": "laptop",
   "device_class_source": "observed", "ts": "2026-08-26T09:02:00Z"}
  ```

  (`org_name` is `null` and `enrolled` is `false` on a personal device.)
  No raw hardware facts, per-capability rows, policy ids, device id, or
  hostname: the file is world-readable and carries
  only what the shell renders or uses for its resident-cost decision. A
  missing/unknown class fails to `appliance`, the least-resident experience;
  it never changes a security or privacy guarantee.
- **Non-authoritative by design**: `/run/punar` is `0755 root:root`; daemons
  write the `0644 root:root` summaries and sessions only read them. Root
  ownership prevents local replacement, but the content remains display data,
  never an authorization input; anything root-trusted stays on the socket.
  Consumers fail closed: missing or unparsable renders as unenrolled calm
  paper. The dev profile alone overlays the directory owner for disposable
  proof artifacts; that rule is excluded from release images.

## 10. Sibling contract (M7): `punar-agentd` socket — `agents.*`

Status: **contract for the Milestone 7 implementation** (spec section 76
Milestone 7; design rationale: `docs/development/milestone-7.md`).
`punar-agentd` (spec section 11.3) is a **separate daemon with its own
socket**; nothing in sections 1–9 changes for `punard`. Everything below
is binding on `punar-agentd` (server) and its clients (`punar-env`,
`punarctl`).

### 10.1 Transport — identical mechanics, sibling socket

- **Path:** `/run/punar-agentd/agentd.sock` (`SOCK_STREAM` UDS; no TCP).
  Root-owned directory for the same impostor reason as section 1.1:

  ```text
  # usr/lib/tmpfiles.d/punar-agentd.conf   (desktop extra tree)
  d /run/punar-agentd     0750 root punar -
  d /var/lib/punar/agents 0700 root root  -
  ```

- Socket `0660 root:punar`, chown/chmod before `listen()`; admission is
  the filesystem; `SO_PEERCRED` at accept is the authorization input —
  all verbatim from section 1.2.
- **Framing, envelope, versioning, timeouts:** sections 2 and 3 apply
  unchanged (`v: 1`, NDJSON, 4096-byte lines, 10 s bounds; both daemons
  share `punar-common::ipc`). **Error codes:** the section 4 table
  applies; no new codes.

### 10.2 Methods (the complete M7 surface — closed)

There is no exec/shell/script method here either (spec sections 10, 60 —
permanent). `agents.access` (spec section 11.2, ledger data) was
**reserved for M8** and answered `unknown_method` in M7; **section 12
below is its M8 contract**, together with `ledger.purge` and the
`agents.list` ledger fingerprint. The `admin.*` names remain reserved
(M10), and no export/query method exists at all.

| Method | Peer may call | Mutating | Audited |
|---|---|---|---|
| `agents.list` | any connected | no (may trigger a scan) | no |
| `agents.get` | any connected | no | no |
| `agents.register` | group `punar` / root, peer-verified | yes | yes |
| `agents.end` | session owner / root | yes | yes |
| `agents.scan` | any connected | registry view only | transitions only |

#### `agents.list`

Params: none. Runs a detection pass first when the last pass is older
than 30 s (milestone-7.md section 7.3 — on-demand freshness, no timers).
Result:

```json
{"v":1,"id":"1","result":{
  "scanned_at": "2026-08-27T10:00:02Z",
  "sessions": [
    {"session_id": "agt_4f21c09ab3e1", "agent": "claude-code",
     "version": "mock", "process_id": 2143, "user": "punar",
     "project": "atlas", "environment": "punar-env-atlas",
     "status": "active", "classification": "managed",
     "started_at": "2026-08-27T09:58:40Z"}
  ],
  "detections": [
    {"session_id": "agt_d11e0aa7c402", "agent": "foo-agent",
     "version": "unknown", "process_id": 2410, "user": "punar",
     "project": "unknown", "environment": "host",
     "status": "active", "classification": "unknown",
     "started_at": "2026-08-27T09:59:55Z",
     "suspected": true, "executable": "/home/punar/Downloads/foo-agent",
     "signature_id": "downloads-foo-agent"}
  ]
}}
```

- `sessions[*]` entries are exactly the ten
  `schemas/ai-agent/registry-record.json` fields — sessions from this
  boot, `ended` included. `detections[*]` entries are the same ten
  fields (sentinels per milestone-7.md section 4.4: version/project
  `"unknown"`, environment `"host"`, synthesized `agt_` id) **plus**
  the detection extras `suspected` (always `true` — spec section 23
  honesty, the label is in the data), `executable`, `signature_id`.
  Detections are point-in-time observations: memory + `agents.json`
  only, never written to `registry.jsonl`.

#### `agents.get`

Params: `{"session_id": "agt_…"}`. Result: `{"session": {…}}` — one
entry in the `agents.list` row shape, plus (for managed sessions)
`"scope_unit"` (`punar-agent-<id>.scope`) and `"authority"` — the
display-level authority summary captured at launch (decision words +
enforcement labels + `policy_citation`; see 10.3). Unknown id →
`not_found`.

#### `agents.register`

Called by the managed launch path (`punar-env agent <name>`) after the
agent process is running in its scope. Params:

```json
{"session_id": "agt_4f21c09ab3e1", "agent": "claude-code",
 "version": "mock", "process_id": 2143, "project": "atlas",
 "environment": "punar-env-atlas",
 "authority": {"policy_citation": "personal-defaults", "rows": [
   {"zone": "filesystem.project", "decision": "read_write",
    "enforcement": "declared · M9"},
   {"zone": "network.internet", "decision": "allow",
    "enforcement": "declared · M12"}
 ]}}
```

Server-side verification (spec section 22 — attribution is checked,
never trusted from params):

1. peer `SO_PEERCRED` uid == owner uid of `/proc/<process_id>`
   (root exempt); mismatch → `denied`, audited;
2. `session_id` matches `^agt_[A-Za-z0-9]+$` and is unused →
   else `invalid_params`;
3. `/proc/<process_id>/cgroup` contains
   `punar-agent-<session_id>.scope` → classification `managed`;
   a known-adapter signature match outside such a scope → `observed`
   (honest downgrade, reported in the result); neither →
   `invalid_params`.

`user` and `started_at` are stamped by the daemon (peer uid → username;
never from params). `classification` is **computed**, never a param.
Result: `{"session": {…}, "classification": "managed"}`. The
schema-exact `active` record is appended to
`/var/lib/punar/agents/registry.jsonl` (`0640 root:root`).

#### `agents.end`

Params: `{"session_id": "agt_…"}`. Allowed for the peer whose uid owns
the session (or root); otherwise `denied`. Appends the `ended` record
(the registry-record `status` enum widens additively to
`["active","ended"]` — the widening the schema's own description
pre-authorizes), removes the live entry. Unknown id → `not_found`.
Sessions whose pid died without `agents.end` are reaped by the next
scan pass with a synthesized `ended` record (audited as
`agents.reap`).

#### `agents.scan`

Params: none. Forces one `/proc` pass now: known-adapter signatures
(from `/usr/share/punar/agents/adapters/*.json`,
`adapter_config.signature`) → `observed` when outside managed scopes;
suspected patterns (`/usr/share/punar/agents/signatures/suspected.json`,
e.g. `*/Downloads/foo-agent`) → `unknown`. Reaps dead managed pids,
drops vanished detections. Result: the `agents.list` shape. Detection
is **heuristic** — results carry `suspected: true` and every rendering
says *suspected*, never certain (spec section 23). No continuous or
timer-driven scanning exists in M7 (spec section 6.3).

**Amended by M10 (§17):** `agents.scan` gains an optional `trigger`,
`agents.list` and `agents.scan` gain `last_scan_at` /
`last_scan_trigger`, and `alerts.list` / `alerts.dismiss` join the
table. Periodic detection ships as a systemd timer calling
`punarctl agents scan --trigger timer` through this same socket — still
no timer inside the daemon.

### 10.3 Authority is display-level in M7

The `authority` object is what the launcher showed the user (spec
section 27 step 10): manifest-declared decisions with their enforcement
milestone labels, plus `policy_citation` — `"personal-defaults"` on an
unenrolled device, the org policy id (hero demo: `"eng-ai-v3"`) while
enrolled, sourced from `/run/punar/status.json` (section 9). Nothing in
M7 enforces these rows (M9/M12), and no surface may render them without
their labels (spec section 1.22). It is stored in memory and
`agents.json` only — `registry.jsonl` lines remain schema-exact.

### 10.4 Audit additions (same file, shared writer)

`punar-agentd` appends to `/var/log/punar/audit.jsonl` via
`punar_common::AuditWriter`, which gains **flock-guarded rotation**
(exclusive lock on `audit.jsonl.lock` around the size-check + rename)
so the two daemons cannot race the 8 MiB rotation; single-line
`O_APPEND` writes interleave atomically. Audited: `agents.register`
(allow and deny; `agent_session_id` carries the **real** `agt_` id — the
section 6 sentinel's purpose fulfilled for agent events), `agents.end`,
`agents.reap`, and `agents.scan` **transitions only** (`result:
"detected"` / `"cleared"` join the open result-string set — the
enroll.sync precedent; per-pass no-change events are not emitted).
Register/end are `source: "human"` (CLI-originated user action; the
subject agent is named by `agent_session_id`); reap/scan are `source:
"service"`, `user_id: "punar-agentd"`. The M3 follow-up about making
agent fields schema-conditional is **closed as not planned**: it would
change required-ness and break the "all 12 required fields" contract
this document and existing events pin; `agt_none` remains the sentinel
for non-agent events.

### 10.5 Client behavior

`punarctl` routes `agents.*` to the agentd socket (everything else stays
on punard's). Verbs: `punarctl agents list` and `punarctl agents
inspect <id>` (D-014 grammar, `--json` prints `result` verbatim, exit
codes unchanged; rendering contract: milestone-7.md section 9).
`punarctl agents access <id>` is not implemented until M8. For negative
probes, `punarctl debug rpc` gains a hidden `--socket agentd` flag;
`agents.*` names auto-route there.

## 11. Side contract (M7): `/run/punar/agents.json`

Not IPC — the AI-panel sibling of section 9's `status.json`:
`punar-agentd` writes a world-readable summary so `punar-shell` renders
the PUNAR+A surface (Plate D-005) with an event-driven `FileView` — no
socket client in the shell, no polling.

- Written at agentd startup and on every change (register, end, reap,
  detection diff); atomic tmp+rename within `/run/punar`; `0644`.
- Content — **summary only**, exactly what the panel renders:

  ```json
  {"v": 1,
   "scanned_at": "2026-08-27T10:00:02Z",
   "policy_citation": "personal-defaults",
   "counts": {"managed": 1, "observed": 0, "unknown": 1},
   "sessions": [
     {"session_id": "agt_4f21c09ab3e1", "agent": "claude-code",
      "project": "atlas", "environment": "punar-env-atlas",
      "classification": "managed", "status": "active",
      "started_at": "2026-08-27T09:58:40Z",
      "authority": {"policy_citation": "personal-defaults", "rows": ["…"]}}
   ],
   "detections": [
     {"session_id": "agt_d11e0aa7c402", "agent": "foo-agent",
      "classification": "unknown", "suspected": true,
      "executable": "/home/punar/Downloads/foo-agent",
      "observed_at": "2026-08-27T09:59:55Z"}
   ],
   "ts": "2026-08-27T10:00:02Z"}
  ```

  No pids beyond what the same user can read in `/proc` anyway — in
  fact none at all; no cmdlines, no secrets, no ledger data (M8; the
  panel's ledger section is a labeled dashed placeholder until then).
- **Non-authoritative by design** — the section 9 caveat verbatim:
  `/run/punar` is user-writable; this is display data for that user's
  own session; anything trusted stays on the agentd socket. Consumers
  fail closed: missing/unparsable file renders the calm empty panel.
- Freshness: opening the panel `exec`s a detached one-shot
  `punarctl agents list --json >/dev/null`, whose section 10.2
  staleness rule triggers the scan; the rewrite (if anything changed)
  reaches the shell through the FileView. One-shot on user action —
  still no polling loop anywhere.

## 12. Ledger contract (M8): `agents.access`, `ledger.purge`

Status: **contract for the Milestone 8 implementation** (spec section 76
Milestone 8; design rationale: `docs/development/milestone-8.md`). These
methods live on the **agentd socket** (`/run/punar-agentd/agentd.sock`,
section 10.1); transport, framing, envelope, versioning, timeouts and
error codes are unchanged. `punard`'s contract (sections 1–9) is
unchanged except for the attribution rule in 12.5.

**`schemas/ai-agent/ledger-summary.json` is the binding document schema
and M8 does not modify it.** Everything the schema cannot hold (counts,
first/last seen, honest not-yet-observed rows, retention) travels as
**sibling fields of the result object**, never inside the document.

### 12.1 Method table (additive)

| Method | Peer may call | Mutating | Audited |
|---|---|---|---|
| `agents.access` | session **owner** or root | no (drains audit + samples cgroup first) | only when root reads a session it does not own (`ledger.read`) |
| `ledger.purge` | session **owner** or root | yes | **always** |
| `agents.list` (§10.2) | any connected | no | no — gains a counts-only `ledger` fingerprint per session |

`ledger.export`, `ledger.query` and `admin.*` do not exist and answer
`unknown_method`: there is no upload path in M8 (spec section 24; the
authorized administrator query is Milestone 10).

### 12.2 `agents.access`

Params: `{"session_id": "agt_…"}`. Authorization: `peer.uid` equals the
uid that owns the session, or root — a ledger is personal data about one
user's session, which is stricter than `agents.list` and is the local
half of spec section 24.1's "RBAC applies". Unknown id → `not_found`;
another user's session (non-root) → `denied` with a section-73 message.

Result:

```json
{"v":1,"id":"1","result":{
  "summary": {
    "session_id": "agt_4f21c09ab3e1",
    "agent": "claude-code",
    "generated_at": "2026-08-27T10:00:02Z",
    "resources": {
      "repositories": ["atlas"],
      "directory_zones": ["workspace"],
      "network_destinations": [],
      "mcp_servers": [],
      "credential_classes": [],
      "process_classes": ["agent", "git", "shell"]
    },
    "security_events": [
      {"event_id": "evt_502", "event_type": "denied_access",
       "timestamp": "2026-08-27T09:59:12Z"}
    ]
  },
  "detail": {
    "status": "active",
    "process_peak": 6,
    "truncated": false,
    "entries": [
      {"category": "repositories", "resource_class": "atlas", "count": 1,
       "first_seen": "2026-08-27T09:58:40Z", "last_seen": "2026-08-27T09:58:40Z",
       "evidence": "workspace_bind"},
      {"category": "directory_zones", "resource_class": "workspace", "count": 1,
       "first_seen": "2026-08-27T09:58:40Z", "last_seen": "2026-08-27T09:58:40Z",
       "evidence": "workspace_bind"},
      {"category": "process_classes", "resource_class": "git", "count": 2,
       "first_seen": "2026-08-27T09:58:44Z", "last_seen": "2026-08-27T10:00:02Z",
       "evidence": "cgroup_scope"}
    ]
  },
  "not_yet_observed": [
    {"level": 3, "category": "network_destinations", "milestone": "M12",
     "reason": "punar-netd does not exist yet; no owned mediation point observes network destinations"},
    {"level": 3, "category": "mcp_servers", "milestone": "M9+",
     "reason": "no tool/MCP gateway mediates MCP traffic yet (spec section 26)"},
    {"level": 3, "category": "credential_classes", "milestone": "M9",
     "reason": "punar-secrets is the producer of credential.request events (spec section 29)"},
    {"level": 4, "category": "credential_request", "milestone": "M9",
     "reason": "no credential producer exists yet"},
    {"level": 4, "category": "policy_bypass_attempt", "milestone": "M9",
     "reason": "approval gates arrive with M9"},
    {"level": 4, "category": "production_access", "milestone": "M12",
     "reason": "no network mediation exists yet"},
    {"level": 4, "category": "sensitive_resource_access", "milestone": "M9/M12",
     "reason": "no mediation point observes sensitive zones yet"},
    {"level": 4, "category": "unknown_ai_execution", "milestone": "M10",
     "reason": "the audit event exists, but a detected unmanaged process has no registered session, so in M8 it attaches to no ledger"}
  ],
  "retention": {"days": 14, "active": true},
  "privacy": {
    "local_only": true,
    "purge_command": "punarctl privacy purge --session agt_4f21c09ab3e1",
    "never_recorded": ["file paths inside the workspace", "prompts",
                       "source code", "secret values", "individual file reads"],
    "audit_trail_separate": true
  }
}}
```

- **`summary`** is a document that validates against
  `ledger-summary.json` **as-is** — it is produced by a total projection
  of `detail.entries` (group by `category`, emit distinct
  `resource_class` values) plus the event refs. It is the exportable
  artifact: whatever Milestone 10's authorized query ever returns is
  this object, and the user already has it.
- **`detail.entries[].category`** is one of the six `resources` keys —
  no seventh category exists. `resource_class` values can never contain
  `/`, `:` or whitespace (enforced by the daemon's `ResourceClass`
  newtype, not by review). `evidence` is one of `cgroup_scope`,
  `audit_event`, `workspace_bind`, `adapter_metadata` and, since M10,
  `detection_scan` — the mediation point that proved the entry. The M10
  value was added rather than folded into `adapter_metadata` because
  this enum exists to say *how we know*, and a detection was never
  launched: there is no adapter and no registration behind it, only the
  pass that saw the process.
- **`count` semantics** for `process_classes`: distinct
  `(pid, starttime)` pairs of that class **observed alive at a sampling
  point**. Not a spawn count. Short-lived children between samples are
  missed, and every renderer says so. `process_peak` is the scope
  cgroup's `pids.peak` — peak *concurrent* pids, never a spawn total.
- **Empty is not "none happened".** A category that is empty **and**
  listed in `not_yet_observed` means *no mediation point observes it
  yet*; no surface may render it without that label (spec section 1.22).
- **`not_yet_observed` moves between milestones, in both directions,
  and the example above is an M8 snapshot.** A row leaves when its
  producer ships (`credential_classes`, `credential_request` and
  `policy_bypass_attempt` left in M9; `unknown_ai_execution` left in
  M10 — §17.6), and a row is re-milestoned when the honest date moves
  (`mcp_servers` M9+ → M11+). **Since M10 the list is also
  classification-aware**: an unmanaged detection's gains `repositories`
  and `credential_classes` with `milestone: "none"` — permanent
  limitations for a process Punar never launched, not pending
  producers. Consumers must read the rows, never assume a fixed set.
- **`retention`**: `{"days": 14, "active": true}` while the session
  runs; `{"days": 14, "expires_at": "…"}` once ended. **Since M10 the
  window is per classification**: a managed session's is 14 days, an
  unmanaged **detection's** is 7 (§17.6). The `days` field always states
  the window that actually applies.
- **Purged session**: result carries
  `"purged_at": "…"` at the top level, `summary.resources` all empty and
  `summary.security_events: []`; renderers must say *purged*, never
  *nothing recorded*.

### 12.3 `ledger.purge`

Params: exactly one of `{"session_id": "agt_…"}` or `{"all": true}`
(neither, or both → `invalid_params`).

Authorization, verbatim: `peer.uid == session.owner_uid || peer.uid == 0`.
`{"all": true}` from a non-root peer purges **only sessions owned by the
calling uid**; from root it purges every session on the device. A
non-root peer may never purge another user's ledger (`denied`, section-73
message). This right is unconditional for one's own sessions in M8 (spec
section 24.2): no policy can withhold it, because no organization can
read the data either.

Effect: the per-session file(s) are unlinked; each index row is replaced
by a tombstone `{session_id, purged_at}` that **floors audit
re-ingestion**, so a later drain cannot resurrect purged data. Result:
`{"purged": 1, "resource_classes": 11, "security_events": 1,
"purged_at": "…"}`.

**Purge does not touch `/var/log/punar/audit.jsonl`.** The audit trail is
the record of decisions the system made (spec section 53) and is outside
a user's delete authority; the ledger, which is *derived* from it plus
the scope cgroup, is not. Every surface prints this boundary in one
sentence.

Always audited: `action: "ledger.purge"`, `resource`: the session id or
`"own"`, `decision`: `allow`/`deny`, `result`: `"purged"` (with the
count) or `"denied"`, `agent_session_id`: the purged session's real
`agt_` id when scoped to one session.

### 12.4 `agents.list` — the ledger fingerprint (additive)

Each `sessions[*]` entry gains:

```json
"ledger": {"resources": 5, "process_classes": 3,
           "security_events": 1, "updated_at": "2026-08-27T10:00:02Z"}
```

**Counts only** — no class names, no `evt_` ids, no zones. This is what
the panel rail and the world-readable summary file (section 11) may
show; identifiers require `agents.access` and its ownership check.
`detections[*]` gain no ledger **fingerprint**: the list is a now-view
of processes. **Amended by M10 (§17.6):** a detection does have a ledger
from M10 onward, read with `agents.access <detection_id>` under the same
owner-or-root check as a session's; the row in `agents.list` still
carries no fingerprint.

### 12.5 Attribution addition in `punard` (spec section 22)

`punard` gains one rule, using a mediation point it already terminates:
at `accept()` it already reads `SO_PEERCRED` (uid, gid, **pid**); it now
also reads `/proc/<peer_pid>/cgroup`, and when that names
`punar-agent-<id>.scope` it sets `agent_session_id = agt_<id>` and
`source = "ai_agent"` on the audit event for that call. Otherwise
nothing changes (`agt_none`, existing `source`). No new syscalls, no
tracing, no per-call cost beyond one small read; the cgroup is
kernel-attested and is the same chain `agents.register` verifies.

Consequence: a capability call made from inside a managed agent session
— **including a denial** — is attributed to that session in the audit
trail whether or not the agent declared it, which is what makes the
Level-4 half of the ledger real in M8.

### 12.6 Audit additions (M8)

`ledger.purge` (always), `ledger.prune` (one event per prune **batch**,
`result`: `"expired"` / `"index_cap"` / `"orphan"`, `source: "service"`,
`user_id: "punar-agentd"`), and `ledger.read` (only when root reads a
ledger it does not own — the seed of Milestone 10's audited
administrator query). No per-access, per-sample or per-drain events
exist: spec section 6.4 forbids exactly that kind of write amplification.

## 13. Side contract (M8): the ledger record and its runtime view

### 13.1 `/var/lib/punar/agents/ledger/` (on disk, root-only)

```text
/var/lib/punar/agents/ledger/                  0700 root:root  (tmpfiles)
/var/lib/punar/agents/ledger/<session_id>.json 0640 root:root
/var/lib/punar/agents/ledger/index.json        0640 root:root
```

Per-session record:

```json
{"v": 1,
 "session_id": "agt_4f21c09ab3e1", "agent": "claude-code",
 "user": "punar", "project": "atlas",
 "classification": "managed", "status": "ended",
 "started_at": "…", "ended_at": "…", "updated_at": "…",
 "retention_expires_at": "…",
 "process_peak": 6, "truncated": false,
 "entries": [{"category": "process_classes", "resource_class": "git",
              "count": 2, "first_seen": "…", "last_seen": "…",
              "evidence": "cgroup_scope"}],
 "security_events": [{"event_id": "evt_502",
                      "event_type": "denied_access", "timestamp": "…"}]}
```

`index.json` carries `{v, updated_at, tail: {dev, ino, offset},
sessions: [{session_id, agent, project, user, classification, status,
first_seen, last_seen, updated_at, retention_expires_at, purged_at?,
counts: {…}}]}` — the rollup `agents.list` and retention read without
opening every file, plus the audit tail position.

Writes are **batched**: at most one atomic tmp+`fsync`+`rename` per
session per drain/sample batch; no per-event `fsync`; **0 B/s at idle**
(spec section 6.4). Bounds: 32 distinct resource classes per category
per session, 256 event refs (first 128 + last 128 kept on overflow, with
`truncated: true`), ≤ 16 KiB per file, 200 sessions in the index (oldest
**ended** evicted first), < 4 MiB for the directory.

`project` here is a **repository class**, not the launcher's project
string: `agents.register` pattern-checks `session_id` and `agent`, but
`registry-record.json` leaves `project` unpatterned, so a caller may
register `project: "/home/punar/clients/acme"`. The ledger types that
field as a `ResourceClass` (`^[a-z][a-z0-9_-]*$`), so a value that is
not one is **absent** from the record and the index row, and the session
claims no repository and no zone. The raw string stays in the M7
registry record, which is where it was already accepted; it crosses into
no ledger byte.

There is **no field** in this record for a file path, argv, cwd, pid,
`comm`, environment, prompt text, file content or secret value. `comm`
is mapped through `/usr/share/punar/agents/process-classes.json` and an
unmapped value becomes the literal class `unknown` — the raw string is
never stored. `agent` and every `security_events[].event_id` are
re-checked against their shipped-schema patterns on **both** write and
load, so the projection onto `ledger-summary.json` stays conformant even
if a producer upstream ever regressed.

### 13.2 `/run/punar-agentd/ledger.json` (the panel's view)

Not IPC — the ledger's sibling of section 11's `agents.json`, written
atomically by `punar-agentd` at the same points, so `punar-shell` can
render the D-005 ledger section with an event-driven `FileView` and no
socket client.

- **`0640 root:punar`, inside the root-owned `/run/punar-agentd`
  directory** — deliberately *not* in world-readable `/run/punar` beside
  `status.json`/`agents.json`. A ledger is personal data: (a) only group
  `punar` (the agentd socket's own admission set, section 10.1) may read
  it, and (b) because the directory is root-owned, a local user cannot
  unlink it and substitute a forgery.
- Content: per-session ledger views — the same rows `agents.access`
  returns (`entries`, event refs, `not_yet_observed`, `retention`,
  `privacy`). `agents.json` keeps **only** the counts fingerprint
  (section 12.4), so nothing world-readable carries ledger identifiers.
- Non-authoritative for trust decisions, exactly as section 9/11 state:
  the socket is the authority; `punarctl agents access` is the
  authenticated view. Consumers fail closed — missing or unparsable
  renders "no ledger recorded for this session yet", never an error
  surface.

---

## 14. Approval + privilege contract (M9): `approvals.*`, `privilege.*`

Status: **contract for the Milestone 9 implementation** (spec section 76
Milestone 9; design rationale: `docs/development/milestone-9.md`).
These methods live on **punard's** socket (`/run/punard/punard.sock`,
section 1); transport, framing, envelope, versioning, timeouts and the
existing error codes are unchanged. Still **`v: 1`** — new methods and
optional result fields are additive per section 3.3, which has named
"M9 (JIT elevation)" as an expected additive milestone since M3.

Spec authorities: 28 (approval gates), 48 (just-in-time privilege), 20
(decision values), 10 (typed capability API; `RequestPrivilege`), 60
(hard safety constraints), 73 (voice).

**`schemas/audit/approval.json` is the binding document schema and M9
does not modify it.** Everything M9 needs that the schema cannot hold —
the originating request, the resolver, the execution result, the
consumption marker — travels as **sibling fields of the envelope**,
never inside the document. This is the section 12 law applied to a
second schema.

### 14.1 Two new error codes

| `code` | Meaning | `details` fields |
|---|---|---|
| `approval_required` (M9) | The call is gated: an approval was created and **nothing was executed**. `punarctl` maps this to **exit code 4**, reserved for it since M3. | `approval_id`, `expires_at`, `capability`, `resource`, `decision` (always `"approval_required"`), `policy_ids` |
| `expired` (M9) | The approval passed `expires_at`, or the presented credential's TTL lapsed. Distinct from `conflict`, which means *already resolved*. | `expires_at` |

`conflict` (M5) gains two M9 uses: resolving an already-resolved
approval, and consuming an already-consumed one. `details.state` names
the current status.

### 14.2 Method table (additive, punard socket)

| Method | AuthZ | Mutating | Audited |
|---|---|---|---|
| `approvals.list` | any connected peer | no (lazy expiry sweep) | no |
| `approvals.get` | any connected peer | no (lazy expiry sweep) | no |
| `approvals.create` | **root only (uid 0)**, and **never from an agent-shaped peer** — see 14.5 | yes | always |
| `approvals.resolve` | **human only** — see 14.5 | yes (may execute) | always |
| `approvals.consume` | **root only (uid 0)** | yes | always |
| `privilege.request` | any connected peer **except agent-shaped peers** — see 14.5 | yes (creates an approval) | always |
| `privilege.status` | any connected peer | no (lazy expiry sweep) | no |
| `privilege.revoke` | grant owner or root | yes | always |

`approvals.approve`, `approvals.deny`, `approvals.delete`,
`privilege.grant` (as a direct call) and `privilege.extend` **do not
exist** and answer `unknown_method`. A grant is only ever produced by
resolving an approval; there is no path that mints privilege without a
recorded human decision.

### 14.3 The envelope (on disk and on the wire)

`approvals.get` result:

```json
{"v":1,"id":"1","result":{
  "v": 1,
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
  "policy": {"name": "Personal preference", "policy_id": "personal-defaults"},
  "contract": "SetFirewall(disabled)",
  "resolved_at": null, "resolved_by": null,
  "consumed_at": null,
  "execution": null
}}
```

- **`approval`** is a document that validates against
  `schemas/audit/approval.json` **as-is**. Consumers that need the
  spec-28 object take this member and nothing else.
- **`kind`** is one of `capability_set`, `credential_request`,
  `privilege_request`. It selects which sibling fields are meaningful
  and who executes (14.6).
- **`resource` semantics**, defined once for all three kinds so that
  `capability(resource)` reads as Plate D-003's contract block:

  | `kind` | `capability` | `resource` |
  |---|---|---|
  | `capability_set` | the registry capability id | the desired-state value (`"disabled"`) |
  | `credential_request` | `credential.request` | the credential class (`"aws-dev"`) |
  | `privilege_request` | the capability being elevated | the grant window (`"15m"`) |

  `credential.request` and `privilege.request` are typed **methods**, not
  desired-state registry entries — the M9 capability registry is still
  exactly `security.firewall`, `system.hostname`, `time.timezone`.
  `approval.json` binds `capability` to the `capability_id` *pattern*,
  not to registry membership.
- **`resolved_by`** (once resolved):
  `{"uid": 1000, "user": "punar", "pid": 812, "cgroup": "…"}` — the
  resolver's full identity, recorded so that an attribution escape is
  visible after the fact even where it is not preventable (14.5).
- **`execution`** (once an approved `capability_set` or
  `privilege_request` has run):
  `{"result": "success", "changed": true, "audit_event_id": "evt_501",
  "grant_id": "gnt_2b8e11c4"}`, or
  `{"result": "apply_failed", "error": "<§73 prose>"}`.
  `audit_event_id` is **the link between an approval and the audit
  trail**, and the pointer deliberately runs approval → event, exactly
  as Plate D-003 prints it ("audit evt_501") and exactly as the M8
  ledger references events. `audit-event.json` is **not** extended.
- **`consumed_at`** is set when a `credential_request` approval is spent
  (14.7). It is a sibling field, **not** a fifth `status` value: the
  shipped enum `pending|approved|denied|expired` is not widened.

### 14.4 Lifecycle, TTL and expiry

```text
pending ──resolve(approved)──▶ approved ──(consume, credential kind)──▶ consumed_at set
   │                                       (status stays "approved")
   ├──resolve(denied)────────▶ denied
   └──expires_at passed──────▶ expired
```

`approved | denied | expired` are terminal.

- **TTL: 300 s by default** — Plate D-003's countdown verbatim (amber
  under a minute). The requester may ask for a **shorter** TTL
  (`params.ttl`, clamped to `[15, 300]`) and never a longer one; the
  maximum is policy-owned.
- **Expiry is swept lazily**: on every read (`approvals.list`,
  `approvals.get`, and each summary-file rewrite), at `resolve` and
  `consume` time, and on every `reconcile` pass — which reuses the
  existing `punard-reconcile.timer` and therefore adds **no timer**
  (spec 6.3). Honest consequence: an `approval.expire` event's
  `timestamp` is when the lapse was *observed*; `expires_at` on the
  record is when it *occurred*, so the instant is always recoverable.
- **Bounds:** at most **8 pending device-wide** and **2 pending per
  requester session**. Beyond either, `approvals.create` returns
  `denied` with `details.reason: "approval_flood"`, audited — approval
  fatigue is the classic attack on an approval gate and is refused in
  code.
- **`reason`** is validated at creation: 1–512 bytes, valid UTF-8, **no
  control characters and no newlines**. It is requester-authored text
  and it *is* displayed (spec 73 requires "why" and "who requested it");
  every surface renders it in a quoted requester voice, typographically
  separated from system prose, as plain non-interactive text.

### 14.5 `approvals.resolve` is human-only (a section-60-class rule)

Params: `{"approval_id": "apr_…", "decision": "approved"|"denied"}`.

Permitted **iff all three hold**:

1. the peer is **not attributed to any agent session** — the section
   12.5 cgroup rule returns `None`, and additionally the peer's cgroup
   path contains no `punar-agent-` segment at all; **and**
2. `peer.uid == 0`, or `peer.uid`'s username equals the approval's
   `user` field (approvals are *routed* to a person; only that person
   answers); **and**
3. the approval is `pending` and not past `expires_at`.

Rule 1 is checked **first** and its violation is a `denied` response
with `result: "self_approval_refused"` in the audit event, `source:
"ai_agent"`, `agent_session_id` set, `resource` = the `apr_` id. A
human may resolve their own `privilege_request` (Plate D-012 draws
exactly that — the friction is the required reason, the countdown and
the trail). **An AI agent may resolve nothing, ever, including a
human's request.**

**Rule 1 is one rule, applied by three methods.** "Agent-shaped" — the
peer is attributed to a session id *or* its cgroup path merely names a
`punar-agent-` scope, whatever its uid — is the admission test for
`approvals.resolve` (`result: "self_approval_refused"`),
`approvals.create` (`result: "agent_create_refused"`) and
`privilege.request` (`result: "agent_privilege_refused"`). Answering,
authoring and asking for a window are three ways to reach the same
human consent, so they are gated by the same test rather than by three
tests that could drift; `punard` implements it once. `approvals.create`
is in that list because *everything on that call is requester-authored*
— `requester` (an agent may write `{"type": "human"}`), `reason`,
`contract` and the `user` the card is routed to are exactly the words a
person reads before consenting. The uid is not consulted by rule 1:
root-ness inside an agent scope buys no bypass (SPEC section 60), and
uid 0 remains separately required by `approvals.create` and
`approvals.consume`. `punar-secrets` is unaffected — it is a system
unit in `system.slice`, and the session it asks on behalf of travels in
`requester_peer`, not in its own attribution.

**Honest limit, stated in the contract rather than only in the design
doc:** the cgroup is *evidence of attribution*, not a sandbox. An agent
that deliberately launches a helper outside its own scope escapes
attribution and would present as the console user; M8 already rests on
the same foundation. M9 records the resolver's uid/pid/cgroup so an
escape is visible after the fact, and names the real fixes (a dedicated
uid per agent session; a logind seat-presence check) as deferred. No M9
surface claims cryptographic proof of a human.

### 14.6 Execution ownership follows capability ownership

| `kind` | On `resolve(approved)` | Executor |
|---|---|---|
| `capability_set` | punard runs the recorded `capabilities.set` **immediately, in the resolver's request, under the store lock** — record preference → apply → verify → audit (section 5.4 pipeline, unchanged) — and writes `execution`. Exactly-once by construction. | punard |
| `privilege_request` | punard writes the grant (section 14.8) and sets `execution.grant_id`. | punard |
| `credential_request` | punard **flips the status and does nothing else.** | `punar-secrets`, later, via `approvals.consume` |

The credential case is split deliberately: making punard issue would
put a plaintext token inside the daemon that writes `/etc` and shells
out to `nft`, destroying the reason `punar-secrets` is a separate
service (spec 11.4). punard never calls `punar-secrets`; there is no
cycle.

**Attribution of an executed capability** (spec 22): the execution audit
event carries **the requesting agent's** `agent_session_id` and
`source: "ai_agent"`; the `approval.resolve` event carries the
resolver's identity (`source: "human"`, `agent_session_id: "agt_none"`).
The agent did it, the human allowed it, and the trail says both.

### 14.7 `approvals.consume`

Params: `{"approval_id": "apr_…"}`. Root only — in practice
`punar-secrets`, which runs as root. Atomically sets `consumed_at` on an
`approved`, unconsumed, unexpired approval and returns
`{"approval": {...}, "consumed_at": "…"}`.

- Already consumed → `conflict`.
- Past `expires_at` → `expired`. **An approved credential approval still
  expires**: a human's yes is not a standing grant, and a second
  issuance of the same class raises a **new** approval.

Always audited: `action: "approval.consume"`, `resource` = the `apr_`
id, `decision: "allow"`, `result: "consumed"`.

### 14.8 `privilege.request` / `privilege.status` / `privilege.revoke`

`privilege.request` params:
`{"capability": "<registry id>", "reason": "<1–512 bytes>",
"duration_minutes": 15}` — `reason` is **required** (Plate D-012: it
travels verbatim into the audit event); `duration_minutes` defaults to
**15** (spec 48: *"Approved for 15 minutes."*), range `[1, 60]`.
Creates a `privilege_request` approval routed to the calling user and
returns `approval_required` (exit 4).

**A peer attributed to an agent session is refused outright**
(`denied`, `result: "agent_privilege_refused"`, audited). Agents get
per-request approvals; they never get a time window. Spec 48 ("avoid
permanent local admin") and spec 60 ("add persistent unrestricted
root") both land here.

On approval, punard writes a grant to
`/var/lib/punar/grants/<gnt_id>.json` (`0600` inside `0700 root:root`):

```json
{"v": 1, "grant_id": "gnt_2b8e11c4", "approval_id": "apr_…",
 "uid": 1000, "user": "punar", "capability": "time.timezone",
 "reason": "Reproducing the Atlas net bug",
 "granted_at": "…", "expires_at": "…", "revoked_at": null}
```

`privilege.status` result:
`{"grants": [{"grant_id", "capability", "reason", "granted_at",
"expires_at"}], "checked_at": "…"}` — the caller's own grants, or every
grant for root.

`privilege.revoke` params: `{"grant_id": "gnt_…"}` or `{"all": true}`
(exactly one; neither or both → `invalid_params`). Owner or root.

**Effect on `capabilities.set` (section 5.4), stated precisely.** The
M3/M4/M5 request shape, validation, errors, audit action and result
object are **unchanged**. The authorization step gains two rungs, in
this order:

```text
1. peer attributed to an agent session (section 12.5)?
     → AI AUTHORITY PATH: allow | deny | approval_required, from the
       effective section 20 AI policy (personal defaults, or the org
       layer while enrolled). Checked BEFORE the uid test, because
       spec 60 forbids bypassing AI policy enforcement — root-ness
       inside an agent scope does not buy a bypass.
       A capability with no AI-policy mapping is DENIED, fail closed.
2. otherwise HUMAN PATH:
     uid == 0                                   → allow  (unchanged)
     unexpired unrevoked grant for (uid, cap)   → allow  (NEW)
     otherwise                                  → deny   (unchanged;
       the section 73 message's long-standing "Milestone 9" pointer now
       names `punarctl privilege request`, which exists)
```

A grant-authorized mutation is audited `decision: "allow"` with
`details.grant_id`. A grant names **one** capability; there is no
wildcard, no `--all` grant, and no grant for an unregistered capability.

### 14.9 Audit additions (M9, punard)

`approval.create`, `approval.resolve`, `approval.expire`,
`approval.consume`, `privilege.request`, `privilege.grant`,
`privilege.expire`, `privilege.revoke`. `resource` is the `apr_` /
`gnt_` id on every one of them, which is how the audit trail alone names
the approval without any change to `audit-event.json`. All are human- or
lifecycle-paced; M9 adds no per-check or per-consult event class (spec
6.4).

---

## 15. Side contract (M9): `/run/punard/approvals.json`

Not IPC — the approval sibling of section 9's `status.json` and section
13.2's `ledger.json`, written atomically (tmp + `fsync` + `rename`) by
punard at **every** approval state transition and every grant change, so
`punar-shell` renders the Plate D-003 overlay and the Plate D-012
`ELEVATED` bar chip with an event-driven `FileView` and **no socket
client in the shell**.

- **`0640 root:punar`, inside the `0750 root:punar` `/run/punard`
  directory** — deliberately *not* `/run/punar` alongside the
  world-readable `status.json`/`agents.json`. Approval details are visible
  only to admitted users, and root ownership prevents local replacement.
  Both properties matter for **the file that tells a human what they are
  about to authorize**; this is the same argument that put `ledger.json` in
  `/run/punar-agentd`.
- Content:

```json
{"v": 1, "updated_at": "2026-08-25T10:00:00Z",
 "approvals": [
   {"approval_id": "apr_7c1d9a4e", "kind": "capability_set",
    "status": "pending",
    "requester": {"type": "ai_agent", "id": "agt_4f21c09ab3e1",
                  "agent_name": "claude-code"},
    "user": "punar", "capability": "security.firewall",
    "resource": "disabled", "risk": "high",
    "reason": "Atlas integration test needs the host firewall down",
    "contract": "SetFirewall(disabled)",
    "policy": {"name": "Personal preference", "policy_id": "personal-defaults"},
    "created_at": "…", "expires_at": "2026-08-25T10:05:00Z",
    "execution": null}],
 "grants": [{"grant_id": "gnt_2b8e11c4", "capability": "time.timezone",
             "expires_at": "…"}]}
```

- The **`reason` is present by design** (spec 73 requires *why* and
  *who requested it*; Plate D-003 renders it). It is requester-authored
  text, validated at creation to one line of ≤ 512 printable bytes
  (14.4), and every renderer shows it in a quoted requester voice,
  typographically separated from system prose, as plain non-interactive
  text with no rich formatting and no link activation. Spec 53 binds
  Punar never to log secret values **it handles**; a free-text field a
  requester fills in themselves is outside that guarantee, and this
  contract says so rather than implying a redaction it cannot perform.
- **Non-authoritative for trust decisions**, exactly as sections 9, 11
  and 13.2 state: the socket is the authority. The overlay's Approve
  action sends **only the `approval_id`**, and punard re-derives the
  contract from its own record before executing anything. Consumers fail
  closed — missing or unparsable renders "no approvals pending", never
  an error surface.
- The countdown is computed by the consumer from `expires_at`, so an
  overlay renders `EXPIRED · denied by timeout` the moment the clock
  reaches zero whether or not punard has swept yet (14.4). Pressing `A`
  on a lapsed card gets `expired` from the daemon and the card says so.

---

## 16. Sibling contract (M9): `punar-secrets` socket — `credential.*`

Status: **contract for the Milestone 9 implementation** (spec sections
11.4, 29). A **separate daemon**, per spec 11.4 — rationale in
`docs/development/milestone-9.md` §3.1, of which the load-bearing part
is that a broker with **no state directory at all** is the strongest
available form of the "never written to disk" promise.

### 16.1 Transport — identical mechanics, third socket

```text
# usr/lib/tmpfiles.d/punar-secrets.conf
d /run/punar-secrets 0750 root punar -
```

Socket `/run/punar-secrets/secrets.sock`, created with a restrictive
umask then `chown root:punar` + `chmod 0660` **before** `listen()`.
Admission is the filesystem (root or group `punar`; everyone else gets
`EACCES` before the daemon sees them). `SO_PEERCRED` at `accept()` is
the authorization input, and the peer's `/proc/<pid>/cgroup` feeds the
**same section 12.5 attribution rule** — promoted to
`punar_common::principal` so punard and `punar-secrets` share one
implementation and cannot disagree about who an agent is. Framing,
envelope, versioning, timeouts and error codes: sections 2–4,
unchanged, `v: 1`.

`punar-secrets.service` is ordered `After=punard.service` with **no
`Wants`/`Requires`**: it dials punard only for approvals, and when
punard is unreachable a `request`-policy class fails with
`upstream_unreachable` and **issues nothing** (fail closed), while
`allow` and `deny` classes still answer.

### 16.2 Method table — closed

| Method | Peer may call | Mutating | Audited |
|---|---|---|---|
| `status` | any connected peer | no | no |
| `credential.classes` | any connected peer | no | no |
| `credential.request` | any connected peer | yes (issues) | **always** |
| `credential.validate` | any connected peer | no | only on first-observed expiry |
| `credential.revoke` | token holder | yes | **always** |

`credential.show`, `credential.export`, `credential.list` (of issued
tokens), `secrets.dump`, `system.exec` and `shell.run` **do not exist**
and answer `unknown_method`. This is architectural, not a policy
setting:

> **After issuance the broker holds only `sha256(token)`. There is no
> method that returns an issued token a second time, because the broker
> cannot produce one.**

### 16.3 `credential.request`

Params: `{"credential": "aws-dev", "ttl": 3600}` (`ttl` optional,
seconds, clamped to `[5, class.max_ttl]`, default `class.default_ttl`).

Class definitions are **data**, not code —
`usr/share/punar/secrets/classes.yaml`, aligned with
`fixtures/policies/ai-policy-engineering-standard.yaml` and the spec
section 17 Atlas manifest `credentials` block. **Naming, decided once:**
the class id is **kebab-case** on the wire, in audit `resource`, and in
the M8 ledger (`github`, `aws-dev`, `aws-prod`) — spec 29's request
example says `"credential": "aws-dev"` — while the **policy key is
snake_case** (`aws_dev`), because `ai-policy.json`'s `propertyNames`
pattern forbids hyphens. The mapping is a declared `policy_key` field
on the class, never a `replace('-','_')` guess.

Three outcomes, from the effective section 20 `credentials` decision
(`allow | deny | request`) resolved through the section 39 ladder:

| Policy | Response | `punarctl` exit | Audit |
|---|---|---|---|
| `allow` | `{"credential": "aws-dev", "value": "<token>", "expires_at": "…", "provider": "mock"}` | 0 | `credential.request`, `decision: allow`, `result: "issued"` |
| `request` | error `approval_required` with `details.approval_id` | **4** | `credential.request`, `decision: approval_required`, `result: "pending"` |
| `deny` | error `denied`, section 73 message | 3 | `credential.request`, `decision: deny`, `result: "denied"` |

On the `request` path the broker calls punard's `approvals.create`
(kind `credential_request`, `capability: "credential.request"`,
`resource`: the class). A later `credential.request` for the same class
by the same requester finds the approved approval, calls
`approvals.consume` (14.7) — **single use** — and issues. A second
issuance raises a **new** approval.

**Every audit event carries the credential CLASS only.** Never a value,
never a token id, never a hash. `agent_session_id` comes from the shared
attribution rule, which is exactly what makes the M8 ledger's
`credential_classes` and `credential_request` fill from real events.
`project_id` is the existing `"system"` sentinel: spec 29's request
example carries a project, but M9 has no unforgeable project mediation
point at the broker, and a requester-supplied project would put
forgeable data in the tamper-evident record. Display surfaces may show
the project from the agent's registry record; the audit does not claim
it.

### 16.4 Token handling — the section 53 rule, made structural

- The value is 32 bytes from `getrandom(2)`, encoded URL-safe-base64
  behind a class-marked mock prefix (`punar-mock-aws-dev-…`) so a leaked
  value is identifiable as a mock in any grep.
- It is wrapped in `punar_common::Redacted` for its entire in-process
  lifetime; `Debug`/`Display` print `[redacted]`, so no stray `{:?}` can
  leak it.
- The broker's in-memory map holds `{sha256(token), class, owner_uid,
  agent_session_id, issued_at, expires_at, revoked}` and **not the
  token**. Nothing is persisted; `punar-secrets` has **no state
  directory**. Its only disk writes are audit events through the shared
  `punar_common::audit` writer, and its `ReadWritePaths=` is exactly
  `/run/punar-secrets /var/log/punar`.
- **How the caller receives it:** `punarctl secrets get <class>` writes
  the value to **stdout, bare, with no masthead**, and the human card
  (class, agent, expiry, `NEVER WRITTEN TO DISK · NEVER LOGGED`,
  `SIMULATED · MOCK PROVIDER`) to **stderr** — so
  `TOKEN=$(punarctl secrets get aws-dev)` works and prose can never
  contaminate the value. `--json` serializes the value on stdout; that
  is the **one** place Punar ever serializes a secret, and Punar never
  persists it.
- **Environment injection into the agent scope is rejected**, on three
  grounds: `/proc/<pid>/environ` is readable by the same uid and is
  **inherited by every child** the agent spawns; an environment variable
  **cannot expire**, contradicting spec 29's "short-lived"; and the
  agent scope's cgroup is a surface `punar-agentd` samples, so a secret
  there is one bug away from the ledger.
- **Secrets are never accepted on argv** (`/proc/<pid>/cmdline` is
  world-readable). `credential.validate` and `credential.revoke` read
  the token from **stdin**. A `--token` flag does not exist and must
  never be added.
- **Honest leak surface:** the caller may redirect stdout to a file.
  Punar cannot prevent that and does not claim to. The promise is
  precise and is the sentence every surface prints: **Punar never writes
  it.**

### 16.5 `credential.validate` / `credential.revoke`

`credential.validate` params: `{"credential": "github", "value":
"<token>"}` (the value reaches `punarctl` on stdin). Result
`{"valid": true, "credential": "github", "expires_at": "…"}` or error
`expired` / `not_found`.

Expiry is computed against the clock **on validate** — no timer, no
sweep (spec 6.3). An expired entry is dropped on the first validate that
observes it and audited **once** (`credential.expire`, `result:
"expired"`). A validate of an **unknown** token is **not audited at
all**: there is nothing to attribute, and auditing it would hand any
local process an audit-flood primitive (spec 6.4). A **successful**
validate is not audited either, for the same reason.

`credential.revoke` params: `{"value": "<token>"}` — drops the entry
immediately, audited `result: "revoked"`, class only.

---

## 17. `punar-agentd` additions (M10): periodic detection, alerts, and the answered query

Status: **shipped in Milestone 10** (spec sections 12.1, 23, 73;
`docs/development/milestone-10.md` §3–§6, §13.1). Additive, still
`v: 1`. Nothing here changes an existing method, error code or side
contract.

> **Law 4 — suspected, never certain, and never armed.** M10 detects,
> records and alerts. It blocks nothing, kills nothing and quarantines
> nothing. Every surface below says *suspected*, and the alert card says
> `nothing was blocked` in words, because a user who believes they are
> protected when they are not is worse off than one who knows.

### 17.1 Method table

| Method | Params | Result | Authz |
|---|---|---|---|
| `agents.scan` **(amended)** | `{"trigger": "manual"｜"timer"｜"register"｜"enroll"}` — optional; absent means `manual`; **a non-root peer's claim is recorded as `manual`** (§17.1) | existing result **+** `last_scan_at`, `last_scan_trigger`, `changed` | unchanged |
| `agents.list` **(amended)** | — | existing result **+** `last_scan_at`, `last_scan_trigger` | unchanged |
| `alerts.list` | `{"include_dismissed": false}` — optional | `{"alerts": [...], "quiet_window_secs": 86400}` | any admitted peer |
| `alerts.dismiss` | `{"alert_id": "alr_…"}` | `{"dismissed": true, "alert_id", "dismissed_at", "suppression_changed": false}` | owner of the detection, or root |
| `query.answer` | `{"query_id", "requesting_admin", "organization", "requested_scope", "session_id"?, "received_at"}` | `{"query_id", "authorization_decision", "granted_scope"?, "result_category", "payload"?, "refusal_reason"?, "refusal_message"?, "audit_event_id"}` | **root peer only** (`peer.uid == 0`) |
| `queries.list` | `{"since"?, "limit"?}` — optional | `{"queries": [...], "enrolled", "organization"?, "policy_citation"?, "granted_scopes", "admin_identity_verified", "never_answered", "storage"}` | any admitted peer (spec 24.2) |

`agents.access` **(amended)**: accepts a `detection_id` as well as a
managed `session_id`. The returned `result.summary` remains a
schema-exact `ledger-summary.json` document and `result.detail` remains
the M8 sibling aggregate — **no new fields**. Authorization is the M8
rule verbatim: owner or root, and an unknown owner is root-only.

**The `trigger` is provenance, so it is not taken from the caller.**
`agents.scan` is open to every peer the socket admits — the desktop
user, and any AI agent running as them — while all three non-manual
triggers name a **root** caller: the timer unit (no `User=`), punard on
an enrollment transition, and the daemon's own register/reap path. A
trigger honoured from an unprivileged peer would let any local process
write `<agent>:timer` into the section 53 record, making "the device
noticed this on its own" a claim anyone can forge — and making the
`m10-check` group 3 assertion satisfiable by a typed command. A non-root
peer's non-manual claim is therefore **downgraded to `manual`**, never
honoured and never refused: `manual` is what actually happened, and the
audit trail records what happened.

`alerts.list` runs **no** staleness-gated detection pass, deliberately —
unlike `agents.list`. A read must not be able to manufacture a
detection: if it could, the first person to *look* would be the one who
produced the `agents.scan` / `detected` event, labelled `manual` and
therefore indistinguishable from a typed command. The register is
derived state whose freshness is the scan's job.

`alerts.list` is readable by **any peer the socket admitted**,
deliberately. From M10 onward an authorized administrator can query the
existence of unmanaged agents on this device, so a register the user
could not read would create a state in which the administrator knows
about a process on the user's machine and the user does not — the exact
inversion spec 24.2 forbids.

### 17.2 The diff is the event

`agents.scan` compares the detection **set** against the previous one:

| Transition | Emitted, once | Written |
|---|---|---|
| absent → present | audit `agents.scan`, `result: "detected"` | `detections.jsonl` (`active`), a ledger, `agents.json`, and `alerts.json` iff the signature is new |
| present → absent | audit `agents.scan`, `result: "cleared"` | `detections.jsonl` (`ended`), the ledger closes, `agents.json` |
| present → present | **nothing** | **nothing** |
| empty diff | **nothing** | **nothing** |

The steady state of periodic detection is therefore **zero bytes
written** (spec 6.4), and the audit trail is a log of *events* rather
than a log of *scans*.

Consequence, stated because it looks like a bug otherwise:
`agents.json`'s `scanned_at` does **not** advance on a no-change pass.
Its meaning is *the view as of the last change*. Liveness — when a pass
last actually ran — is in-memory state served as `last_scan_at` /
`last_scan_trigger`. **The socket is the authority; the file is a change
log.**

`trigger` travels into the audit event's `resource` field as
`<agent>:<trigger>` (e.g. `foo-agent:timer`). `audit-event.json` has no
field for a trigger and does not grow one — the composite is the same
idiom M8 already uses for `ledger:<count>` on a prune batch.

### 17.3 Identity

```
detection_id = "agt_" + hex12( sha256( exe ‖ 0x00 ‖ uid ‖ 0x00 ‖ boot_id
                                       ‖ 0x00 ‖ pid ‖ 0x00 ‖ starttime ) )
signature_id = "sig_" + hex12( sha256( exe ‖ 0x00 ‖ uid ) )
```

`detection_id` names one **running process** and is stable for its whole
life — the property the set-diff depends on. `starttime` (field 22 of
`/proc/<pid>/stat`) and `boot_id` are what make **pid reuse** unable to
collide: a recycled pid yields a *different* id, reported as one process
clearing and another appearing, which is the correct semantics.

`signature_id` names one **thing seen** and is deliberately coarser:
restarting the same binary is the same thing seen. It is the anti-nag
key and the fleet-dedup key. Both are hashes, so either may appear in an
exported inventory answer without leaking where a binary lives.

> **Naming collision, resolved rather than papered over.** The M7 wire
> field `signature_id` on `agents.list` detection rows carries the
> matched **rule's name** (`downloads-foo-agent`), and it keeps that
> meaning unchanged — a shipped contract does not move for a later
> milestone. The M10 `sig_` identity appears under the name
> `signature_id` only in `alerts.json` (§20), a new file, beside a
> `signature` field carrying the rule name.

### 17.4 The anti-nag rule

**One alert per `signature_id`** — not per scan, not per process.

- First sighting of a signature with no live alert record → **raise**,
  and one `agents.alert_raise` audit event.
- Any further detection of that signature → the record's `last_seen`,
  `live` and `detection_id` update. Never re-raise.
- When the last live detection clears, the record moves to `cleared` and
  starts a **24 h quiet window** (`quiet_window_secs`). A sighting inside
  the window updates it silently; the first sighting *after* the window
  raises a fresh alert with a fresh `alert_id`.

`alerts.dismiss` **files** a card; it never deletes one, and it never
changes suppression — hence `suppression_changed: false` on the wire.
There is no snooze, no per-alert mute and no user-facing suppression
state, which is the point.

### 17.5 Audit actions added

`agents.alert_raise` (`result: "raised"`, `source: "service"`) and
`agents.alert_dismiss` (`result: "dismissed"`, `source: "human"`). Both
carry the detection's `agt_` id as `agent_session_id`. Counting
`agents.alert_raise` events is how a check proves the anti-nag rule.

`admin.ai_query` (`result: "answered"` | `"refused"`,
`source: "organization"`, `user_id`: the **requesting administrator**,
`resource`: the requested scope) — one event per decided remote query,
answered or refused (§17.8). The `user_id` choice is deliberate: the
schema describes it as the human in whose session the event occurred,
and a remote query occurs in no local session, so the field carries the
only human the line is about. `punarctl audit tail` must be readable on
its own, and an audit line about an administrative query that does not
name the administrator is a line nobody can act on. Every rendering
carries the *asserted by the organization · not verified by this device*
label, because M10 has no IdP.

### 17.6 Detection persistence and the unknown-agent ledger

`/var/lib/punar/agents/detections.jsonl` (`0600 root:root`, append-only)
holds one **schema-exact** `registry-record.json` document per detection
state change — `active` when it appears, `ended` when it clears. Never
one per pass.

Everything the shipped schema cannot hold (`signature_id`, the matched
signature name, the executable path, the zone class, `cleared_at`) lives
in the sibling `/var/lib/punar/agents/detections-index.json`. Third
application of the M8 Decision-0 law.

Each detection gets a **bounded** ledger, readable with
`agents.access <detection_id>`. It is strictly smaller than a managed
session's, by construction:

| M8 source | For a detection |
|---|---|
| A — agent scope cgroup | none; the executable's **own** process class is recorded instead. The children of the process are **not** walked. |
| B — attributed audit | the detection transition itself: the `agents.scan` / `detected` event is classified `unknown_ai_execution` and referenced here. |
| C — workspace grant | none. Repositories are not observed and are **never** inferred from `cwd`. |
| D — session metadata | partial: agent name, owner, timestamps, and a **zone class** (`downloads`, `tmp`, `home`, `system`) for where the executable lives — a class, never a path. |

Three permanent refusals: **no child-process walk** (it would produce a
per-user process graph — the tracing spec 1.14 rules out), **no `cwd`
read**, and **no cmdline, argv or environment** (they routinely carry
prompts, API keys and paths; no schema has a field for them and none is
added).

`not_yet_observed[]` is **classification-aware** from M10: an unmanaged
detection's list gains `repositories` and `credential_classes` with
`milestone: "none"` — permanent limitations for a process Punar never
launched, not pending producers. And `unknown_ai_execution` **left** the
list device-wide, because M10 shipped its producer.

Retention is **7 days after the detection clears**, half the managed
window. `punarctl privacy purge` deletes detection records and their
ledgers unconditionally for the owning user. The `unknown_ai_execution`
**audit** event survives purge, exactly as M8 guarantee 4 already says:
purge removes the derived summary, never the decision record.

### 17.7 The honest limitation

Sampling detection has one hole by construction, and it is stated on
every surface that claims continuous detection rather than engineered
around: **a process that starts and exits inside one interval, and
touches nothing Punar mediates, is never seen.** Closing it needs
exec-time notification, which is exactly the broad tracing spec 1.14
rules out.

### 17.8 `query.answer` — the data owner decides

`punar-agentd` is the only owner of AI data, so it is the only thing
that answers an administrator's question. `punard` is a courier (§18):
it hands over the question exactly as it fetched it and posts back this
result byte-identical.

**Root peer only.** The one caller is punard. A non-root peer gets a
`denied` error frame — not an authorization outcome, because a local
user asking this device to answer a question nobody asked is a caller
who is not admitted, not a decision to relay.

**A refusal is a `result`, never an error frame.** An out-of-scope query
comes back with `authorization_decision: "deny"`, `refusal_reason:
"out_of_scope"` and the section-73 `refusal_message`. This is contract,
not style: punard treats an error frame as *there is no decision to
relay* and leaves the query pending for the next pass, so a refusal
encoded as an error would never reach the administrator who asked. No
new error code is added for it (§13's `denied` still means *you* may
not; `out_of_scope` is a decision the device made about itself, and it
travels in the result where the query log and the audit event can both
carry it).

**The fields that are not the scope are validated before anything
happens.** Law 2 covers the *scope*: `authorize` reads the grant from
local state, so no request can widen one. The rest of a `query.answer`
param block is chosen by whatever answered `queries.pending` too, and
those fields are used as **keys**, not as prose — `session_id` is a
ledger lookup key, `requesting_admin` / `requested_scope` /
`received_at` are pattern-checked `audit-event.json` fields, and all of
them are rendered by `punarctl privacy queries` and appended to a
365-day log. So each is checked first: `session_id`, when present, must
match `^agt_[A-Za-z0-9]+$` (the shipped schema pattern — a narrowing key
is an agent session id or it is nothing); `query_id`,
`requesting_admin`, `organization` and `requested_scope` must be
non-blank, at most 256 bytes (64 for the scope) and free of control
characters; `received_at` must be RFC 3339.

A param block that fails these is an **`invalid_params` error frame**,
and *nothing* is projected, audited or recorded. This is the "the params
were rejected" case §18 already names: the query stays pending on the
control plane, and nothing leaves the device. It is deliberately **not**
recorded as a refusal — a refusal is a decision about a question, and
this is a thing that never became a question; writing attacker-chosen
bytes into the user's privacy log to prove someone sent garbage would be
the harm rather than the defence.

A narrowing `session_id` also **filters** the answered set rather than
replacing it. Section 8.1's rule — a query may narrow an answer, never
widen it — is structural: the ledger-backed scopes intersect the request
with the set the unnarrowed answer would have carried, so a narrowing
key can never become a lookup, and never a path.

**Authorization is computed from local state only:**

```
answered_scope = requested_scope ∩ org_granted ∩ device_builtin_max
```

`org_granted` is read by agentd **from `/var/lib/punar/enrollment.json`
itself**. There is no parameter through which a scope grant can be
passed, which is what makes spec 59.4 structural here rather than
aspirational: a compromised control plane cannot talk the endpoint into
exceeding what enrollment established, because the endpoint does not
listen to it on that subject. Absent file, absent key, or unparsable
file ⇒ the **empty set** ⇒ everything is refused.

`device_builtin_max` is the closed four-value scope enum — `inventory`,
`authority`, `resource_summary`, `security_events`. There is no
wildcard, no `all` and no free text; an unrecognised value cannot become
a scope at all, so it can never survive the intersection.

**The `authority` answer labels its rows.** The rows come from the
`authority` block the local launcher handed to `agents.register` — they
are asserted by a process on this device, not measured by it. The
payload therefore carries `authority_source: "declared by the local
launcher · not verified by this device"`, the same honesty label
`admin_identity_verified: false` carries for the requesting admin. The
block itself is bounded, single-line and printable at ingestion
(`agents.register` refuses anything else), because Milestone 10 is what
turned that display data into export data.

**What an answer may contain** is the projection of data the owning user
can already print about themselves (spec 24.2): counts and per-session /
per-detection rows at `inventory`, the org's own policy read back at
`authority`, M8's `ledger-summary.json` document verbatim at
`resource_summary`, and Level-4 event **references** —
`{event_id, event_type, timestamp}` — at `security_events`. What it may
never contain is refused because **no field exists to carry it**: no
prompts, no source, no file paths (zone *classes* only), no command
lines, argv or environment, no secret values, no pids or cgroup paths,
and no audit event payloads.

Every decided query — answered or refused — appends one record to
`/var/lib/punar/agents/queries.jsonl` (`0600 root`, six spec-51.1 fields
plus the granted scope and the identity-honesty flag, **never the
payload**) and one `admin.ai_query` audit event
(`source: "organization"`, `user_id`: the requesting admin,
`resource`: the requested scope, `decision`: `allow` | `deny`).

### 17.9 `queries.list` — the section 24.2 command's data

Readable by **any peer the socket admitted**, deliberately: withholding
the record of who asked about the user from the user would be the exact
inversion spec 24.2 forbids, and root-only would be absurd on a
single-user personal device. The result carries the granted scopes the
daemon actually enforces, the never-answered list and the storage facts,
so `punarctl privacy queries` invents nothing and the two cannot drift.

The query log is **not** deleted by `punarctl privacy purge`: it records
what the *organization* did, not data about the user's work, and a user
deleting the evidence of a query would delete their own recourse. Both
purge boundaries — the audit trail and this log — are printed on the
purge surface.

---

## 18. `punard` additions (M10): the remote-query courier

Status: **shipped in Milestone 10** (spec sections 24.1, 51, 59.4;
`docs/development/milestone-10.md` §7, §11, §13.2). Additive, still
`v: 1`. Nothing here changes an existing method, error code or side
contract.

> **Law 1 — Punar is not a server.** Nothing in M10 opens an inbound
> socket, port or listener of any kind. A remote query reaches this
> device only because **this device went and fetched it**, on a schedule
> it already owned. An administrator with a valid token and this
> device's address has nowhere to send a request. Everything below is an
> **outbound** client.

### 18.1 `enroll.status` — amended

`enroll.status` gains two optional result fields while enrolled. They
are absent on a personal device — enrollment *annotates*, it never
restructures (DESIGN_LANGUAGE §8):

| Field | Value |
|---|---|
| `remote_query_scopes` | the scopes the organization asked for at enrollment, read back from `enrollment.json` — the **same array** `punar-agentd` enforces, not a second copy |
| `last_query` | `{at, scope, decision}` — metadata about the most recent remote query. Never a payload. |

`remote_query_scopes` is published so the user can check every answered
query against the grant themselves (spec 24.2, guarantee 8). The full
record is `punarctl privacy queries` (§17).

### 18.2 The sync piggyback — observable behaviour, therefore contract

At the end of every reconcile pass, **when enrolled**, punard's M5 sync
hook runs. M10 adds two calls to that same hook and **no new timer, no
new listener and no new wakeup**:

```text
reconcile pass ends
  └─ enrolled? ─ no ─→ nothing              (§11 gate A — M5's existing gate)
                └ yes ─→ compliance.report            (M5)
                       ├─ inventory.report            (M5, hash-gated)
                       ├─ queries.pending {device_token}      → [ {query_id, …}, … ]
                       └─ for each: query.answer  (agentd socket, §17)
                                  → queries.answer {device_token, query_id, answer}
```

Answer latency is therefore **one reconcile period (~120 s) plus the
round trip**, and the waiting happens on the *administrator's* side —
which is where a request the device did not initiate ought to wait. At
most `16` queries are drained per pass.

Offline behaviour is M5 §7 unchanged: an unreachable control plane means
the pull does not happen. Queries stay pending upstream and are answered
on the next successful pass. **No spool, no queue, no new state.**

### 18.3 The courier discipline

**punard is the only control-plane client; `punar-agentd` is the only
owner of AI data.** M10 keeps both laws by making punard a courier:

- it hands the fetched question to `punar-agentd` **exactly as fetched**
  — the `query.answer` params carry no scope grant, no role, no policy
  and no token, so there is no field through which a courier, or a
  compromised control plane, could widen what comes back (spec 59.4);
- it posts the daemon's answer back **byte-identical**; it never
  assembles an answer, never reads a ledger, and never sees a byte it
  was not handed;
- if `punar-agentd` cannot be reached, or answers with an error frame,
  **punard produces nothing** — no synthesized refusal, no "assume
  denied", no partial answer. The query stays pending and is retried.

### 18.4 The single inter-daemon edge

`punard → punar-agentd` is the **only** inter-daemon call in the system,
and it is one-directional: `punar-agentd` never calls `punard` (its
relationship to punard's data is reading an append-only file, §12.5,
which is not a call). The graph is a DAG, and
`punar-agentd.service` gains **no** `After=`/`Requires=` on punard as a
result: a call that fails because the peer is not up is a non-fatal
retry next pass.

Besides `query.answer`, punard makes one other call over this edge:
`agents.scan {trigger: "enroll"}` on an enrollment transition
(`enroll.start` / `enroll.stop` completing). It is fire-and-forget with
a 2 s timeout and a non-fatal failure path — **enrollment must never
fail because a bookkeeping daemon was busy.**

`RestrictAddressFamilies=AF_UNIX` stays on `punar-agentd.service`. Even
in the mock world where the control plane is a local socket, agentd
never speaks to it.

---

## 19. Control-plane protocol additions (M10 + recovery custody): `punar-mock-smplify`

Status: **shipped in Milestone 10** (spec section 51;
`docs/development/milestone-10.md` §7, §9.1, §12, §13.3). The
counterparty is the **dev/CI mock — not a product component**; its unit
is never enabled and its `--help` says so. In production this hop is
Punar ⇄ Smplify cloud over mutually authenticated TLS; here it is a
root-only UDS with NDJSON, §2–§4 framing unchanged, `v: 1`.

The recovery methods added on 2026-08-27 are a dev/CI contract proof, not a
claim that the production portal or installer exists. Their wire documents
validate against `schemas/encryption/`; their security contract is §19.6.

### 19.1 Device-facing (`device_token` authenticated, as M5)

| Method | Params | Result |
|---|---|---|
| `recovery.key` | `{device_token}` | `{tenant_recovery_key}` — RFC 9180 suite + HPKE and receipt-verification **public** keys |
| `recovery.escrow` | `{device_token, envelope}` | `{receipt}` — Ed25519-signed and bound to device/LUKS/keyslot/key-id/envelope digest |
| `queries.pending` | `{device_token}` | `{queries: [{query_id, requesting_admin, organization, requested_scope, session_id?, received_at}]}` |
| `queries.answer` | `{device_token, query_id, answer}` | `{accepted: true}` |

A device sees only its **own** queue: the token resolves to exactly one
`device_id` and the filter is on that id. Delivery does **not** consume
an entry — a device that fetched a query and then lost power gets it
again, and an administrator is never answered with permanent silence
because of one dropped connection. `queries.answer` stores the answer
**verbatim**; the mock does not inspect, reshape or second-guess it,
because the device is the authority about its own data. Answering a
query addressed to another device is `not_found`.

The pulled question's field list is the whole field list. There is no
`payload`, no `filter`, no `path` and no `expression` — nothing an
administrator could use to ask for something the closed scope
vocabulary cannot name.

The same token-to-device rule protects recovery custody. The mock rejects an
envelope unless its organization, tenant key id and `device_id` all match the
authenticated device. Server state receives a `RecoveryEnvelope` whose type
has no plaintext field. A transport success is not enough: `punard` reports
escrowed only after it locally verifies the returned signature and every
binding field against the exact envelope digest.

### 19.2 Admin-facing (the names M5 reserved, now real)

| Method | Params | Result |
|---|---|---|
| `admin.devices` | `{admin}` | `{devices: [{device_id, enrolled_at, last_sync, compliance_state, attestation}], identity_verified: false}` |
| `admin.device` | `{admin, device_id}` | that device's received inventory + compliance (**category states only**), and its query history |
| `admin.ai_query` | `{admin, device_id, scope, session_id?}` | `{query_id, status: "pending", note}` |
| `admin.query_result` | `{admin, query_id}` | `{status: "pending"\|"answered"\|"refused", answer?, identity_verified: false}` |
| `admin.fleet` | `{admin}` | the §12.1 fleet aggregate as structured data |
| `admin.recovery_release` | `{admin, device_id, reason}` | one-time plaintext key + LUKS UUID/keyslot/key id; always `identity_verified: false` in this mock |

`admin.ai_query` returns immediately and **sends nothing anywhere**; the
administrator's client polls `admin.query_result`. `admin.query_result`
answers only the administrator who asked. `admin.fleet` is role-gated to
`fleet_viewer` and above, expressed as *a role that may ask about
`authority`* so a fixture that renames roles cannot silently open the
view.

`admin.recovery_release` is not implied by any query scope or fleet access.
The fixture's separate `recovery_release_roles` list grants it only to
`security_admin`. `reason` is a 1–63 character structured code rather than
free text, keeping recovery material and arbitrary sensitive prose out of the
audit trail. Denied, missing, unwrap-failed and successful attempts are
appended before the method returns. A successful response is explicitly
one-time and secret-bearing; clients must never log, cache or place it on a
command line.

### 19.3 Two new error codes, deliberately distinct

| Code | Meaning |
|---|---|
| `denied` | the requesting identity is unknown to the org's role table, or its role does not permit that scope — ***you* may not** |
| `out_of_scope` | the scope is not in the closed four-value vocabulary — **this scope does not exist** |

Collapsing them was considered and rejected: they produce different
section-73 messages and different query-log rows, and one code could not
distinguish "this admin lacks the role" from "this device was never
granted the scope". Both refusals happen **before** enqueuing, so a
query the organization may not ask never reaches a device at all.

### 19.4 RBAC, and the honest boundary

`fixtures/organizations/acme/admins.json` maps identities to roles and
roles to scopes (`helpdesk` → `inventory`; `fleet_viewer` → `inventory`,
`authority`; `security_admin` → all four), plus the independent
`recovery_release_roles` grant. An **absent or unreadable** table knows nobody
and permits nothing; every `admin.*` call then refuses and names the missing
file.

> These identities are **fixture strings, not authenticated
> principals**. There is no IdP, no SSO, no signature and no session.
> Every surface that renders a requesting admin carries
> `identity_verified: false`, and every refusal says so. This check is
> **defence in depth**: the device re-evaluates authorization from its
> own `enrollment.json` and refuses whatever that file does not grant,
> regardless of anything decided here (spec 59.4). Of the two checks,
> **the device's is the one that decides.**

### 19.5 Mock state

Four files join `/var/lib/punar-mock-smplify/` (0700 root):
`queries.json` (the pending/answered queue, atomic rewrite, 0600) and
`received-answers.jsonl` (append-only, what devices returned, verbatim), plus
`received-recovery-envelopes.jsonl` (tenant-wrapped envelopes only) and
`recovery-releases.jsonl` (append-only operator, device, structured reason,
time, outcome and the mock's `identity_verified: false` disclosure). No
recovery key is written to either recovery file. All persist across restarts,
deliberately: the check stops and starts the mock, and a queue or custody
store that forgot on restart would silently lose work.

**The queue stores no way to reach a device** — no address, endpoint,
host, port, URL or callback. That is not a policy this crate follows; it
is a capability it does not have.

### 19.6 Recovery cryptographic and production boundary

The device fixes one non-negotiated RFC 9180 suite:
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305. HPKE associated
data length-prefixes and domain-separates organization id, tenant key id,
device id, LUKS UUID and recovery keyslot. The envelope digest is a separate
domain-separated binary encoding, independent of JSON field order. The
receipt's Ed25519 key is distinct from the HPKE recipient key. Suite changes
require a protocol version and migration; downgrade is rejected.

The mock carries the RFC appendix's public test HPKE private key so CI can
prove release and unwrap. Its administrator strings are not authenticated,
and every release says so. A production Smplify implementation may return a
key only after authenticated tenant identity, a distinct recovery-release
RBAC grant, step-up authorization and an audited reason. The tenant private
key must remain in tenant-scoped KMS/HSM custody; there is no vendor-global
decryption key. Portal release gives an authorized operator a recovery key;
it creates no network path into pre-boot LUKS and cannot unlock a device
remotely by itself.

---

## 20. Side contract (M10): `/run/punar-agentd/alerts.json`

```text
/run/punar-agentd/alerts.json   0640 root:punar
```

**Root-owned, deliberately.** A file that tells a human what to believe must
not be replaceable by an unprivileged process. A forged card reading
*"Unknown AI activity suspected · your-bank-helper"* with an `Inspect`
action is a phishing primitive. `/run/punar-agentd` supplies both root
ownership and the `0750 root:punar` traversal boundary required for these
group-readable details; `/run/punar` holds only world-readable summaries.

```json
{ "v": 1,
  "updated_at": "2026-08-25T14:31:00Z",
  "alerts": [
    { "alert_id": "alr_9c2f01ab77de",
      "signature_id": "sig_0f1e2d3c4b5a",
      "agent": "foo-agent",
      "executable": "/home/punar/Downloads/foo-agent",
      "owner": "punar",
      "first_seen": "2026-08-25T14:31:00Z",
      "last_seen": "2026-08-25T14:31:00Z",
      "live": 1,
      "detection_id": "agt_d11e0aa7c402",
      "signature": "unmanaged-path-agentlike",
      "policy_citation": "personal-defaults",
      "state": "live" } ] }
```

Rules:

- **Written only when the alert set changes** — a raise, a clear, a
  dismissal, or a fresh raise after the quiet window. Counters and
  timestamps moving is *not* a set change, so a pass that finds the same
  processes still running writes nothing (spec 6.4). The file's
  `last_seen` therefore means *as of the last set change*, exactly as
  `agents.json`'s `scanned_at` does; live values come from `alerts.list`.
- **Atomic**: exclusive-create temp file, `fsync`, `rename`.
- **Display data whose authority is the socket.** Consumers **fail
  closed**: a missing or unparsable file renders **no** alert, never a
  placeholder alert.
- `state` is `live` · `cleared` · `dismissed`. A `dismissed` card is
  filed, not destroyed — it stays in `alerts.list --all` and in the
  detection record.
- **Exactly the twelve fields above.** No pid, no cgroup path, no
  `comm`, no command line, no argv, no environment, no hash of anything
  secret. The one path present is the single matched executable — the
  datum the D-009 card is built around, and one the same user can
  already print with `punarctl agents list`. Spec 24.2 is the rule: the
  card may not tell the user *less* than they can already read, and it
  carries nothing more than the surface it mirrors.
- There is **no** `quiet` or do-not-disturb field. DND is shell-local
  state in M10, so `punar-agentd` cannot know about it and does not
  invent a flag it could not fill (spec 1.22).
