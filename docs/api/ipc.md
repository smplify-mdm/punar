# Punar local IPC — `punard` wire contract (v1, Milestone 3)

Status: **contract for the M3 implementation** (spec section 76, Milestone 3).
Everything in this document is binding on `punard` (server) and `punarctl`
(client). Spec authorities: section 10 (typed capability API only), section 11
(`punard`/`punarctl` responsibilities), section 60 (hard safety constraints —
no generic root RPC), section 61 (local IPC security), section 73
(denial-message voice), section 74.4 (security tests).

M3 runs **unmanaged-first personal mode** (design language section 8): there is
no organization, no enrollment, no org policy source. Policy citations in this
contract say `personal-defaults` / "os default" and nothing else.

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
  expected to add methods and result fields under `v: 1`.
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

## 5. Methods (M3 surface — complete)

The method set is closed. There is **no** exec, shell, script, or
run-as-root method, by architecture (spec section 10 "Prohibited:
RunRootShell(command)"; section 60). The 74.4 security test probes this via
`punarctl debug rpc system.exec` and must get `unknown_method`.

| Method              | AuthZ (M3)            | Mutating | Audited |
|---------------------|-----------------------|----------|---------|
| `status`            | any connected peer    | no       | no      |
| `capabilities.list` | any connected peer    | no       | no      |
| `capabilities.get`  | any connected peer    | no       | no      |
| `capabilities.set`  | **root only (uid 0)** | yes      | always (allow and deny, success and failure) |
| `audit.tail`        | any connected peer    | no       | no      |
| `reconcile`         | **root only (uid 0)** | no in M3 (re-verify only) | always |

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
    Real policy ids arrive with the M4 merge.
  - `result`: `"success"` | `"noop"` | `"denied"` | `"failure"` |
    `"verify_failed"` | `"drift_detected"` | `"clean"`.
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
  nobody mistakes absence for oversight.

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
- `punarctl debug rpc <method>` (hidden) sends an empty-params request with an
  arbitrary method name — exists solely so the 74.4 "unauthorized IPC" /
  section 60 negative tests can probe the server from inside the image. The
  server's method table is the enforcement point; this flag adds no server
  capability.

## 8. Explicit non-goals of this contract (M3)

- No generic execution method of any kind (spec sections 10, 60) — permanent.
- No TCP, no abstract-namespace sockets (path perms are the admission
  mechanism), no SCM_RIGHTS fd passing.
- No policy merge (`policy.*` arrives M4), no enrollment (`M5`), no approvals
  or JIT elevation (`M9`), no agent methods (`M7+`).
- No event subscription/streaming; `audit.tail` is pull-only. Revisit when
  the shell needs live updates (M4+).
