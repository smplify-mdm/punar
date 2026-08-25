# Punar local IPC — `punard` wire contract (v1, Milestones 3–5; M7 sibling socket in §10–§11; M8 ledger in §12–§13)

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

"Any connected peer" = admission already proved root-or-group-`punar`
(section 1.2). Root-only is a fixed M3 rule named `personal-defaults`;
group-`punar` mutation via JIT elevation/polkit is Milestone 9 (spec
sections 48, 61), and the denial message says so.

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
  "audit": {"path": "/var/log/punar/audit.jsonl", "events": 42}
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
   "compliance_overall": "compliant", "ts": "2026-08-26T09:02:00Z"}
  ```

  (`org_name` is `null` and `enrolled` is `false` on a personal device.)
  No per-capability rows, policy ids, device id, or hostname: the file is
  world-readable in a user-owned directory and carries only what the bar
  renders.
- **Non-authoritative by design**: `/run/punar` is `0755 punar:punar` (M1
  contract), so the session user can replace the file — acceptable because
  it is display data consumed by that same user's own session; anything
  root-trusted stays on the socket (the section 1.1 argument, inverted).
  Consumers must fail closed: missing or unparsable file renders as
  unenrolled calm paper.

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
timer-driven scanning exists in M7 (spec section 6.3; periodic
detection is the Milestone 10 deliverable).

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
the SUPER+A surface (Plate D-005) with an event-driven `FileView` — no
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
  `audit_event`, `workspace_bind`, `adapter_metadata` — the mediation
  point that proved the entry.
- **`count` semantics** for `process_classes`: distinct
  `(pid, starttime)` pairs of that class **observed alive at a sampling
  point**. Not a spawn count. Short-lived children between samples are
  missed, and every renderer says so. `process_peak` is the scope
  cgroup's `pids.peak` — peak *concurrent* pids, never a spawn total.
- **Empty is not "none happened".** A category that is empty **and**
  listed in `not_yet_observed` means *no mediation point observes it
  yet*; no surface may render it without that label (spec section 1.22).
- **`retention`**: `{"days": 14, "active": true}` while the session
  runs; `{"days": 14, "expires_at": "…"}` once ended.
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
`detections[*]` gain no ledger field: an unregistered detection has no
persisted session and therefore no ledger in M8 (Milestone 10).

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
  directory** — deliberately *not* in user-writable `/run/punar` like
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
