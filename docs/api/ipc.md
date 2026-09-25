# Punar local IPC — `punard` wire contract (v1, Milestones 3–5; M7 sibling socket in §10–§11; M8 ledger in §12–§13; M9 approvals, privilege and the secret broker in §14–§16; F0 device administrators, passwords and the first-party app reservations in §23–§27)

Mail, Calendar and Reminders use a separate profile-scoped service and closed
contract: [`pim-ipc.md`](pim-ipc.md). PIM content and account operations are
not methods on the device-level `punard` socket.

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

**F0 amendment (additive, still `v: 1`; PLAN.md §2.1, §2.4):** a
**device-administrator role** and the rule for actions that reach other
people (§23) — applied to the existing device-wide methods, which a person
without the role can no longer use; two methods, `admins.list` and
`admins.set` (§23.3), taking the table from 45 names to 47; the password
rules every client follows (§23.5); and the names, section numbers and
skeletons the first-party apps will add (§24–§27), reserved and answering
`unknown_method` until each milestone lands its handler.

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
  **M5 amendment (two methods):** `enroll.start` (section 5.9) is processed
  under a **70 s** bound — its pipeline contains upstream calls plus a full
  reconcile pass, which TCG runs make slow — and `punarctl` uses a 90 s
  response timeout for the `enroll start`/`enroll stop` verbs. On an
  enrolled device a `reconcile` also talks to the control plane: it fetches
  the organization's policy first (section 5.6) and reports afterwards. The
  pass's calls share one budget of **25 s**, waits behind other calls
  included: `policy.fetch`, `compliance.report`, `inventory.report` and
  `queries.pending` wait at most 5 + 9 + 5 + 5 = 24 s (each at least a
  second longer than `punar-smplifyd` may spend on it), answering queries
  gets what is left, and a call that no longer fits is not sent — its report
  stays pending for the next pass. So `reconcile` is processed under a
  **35 s** bound (its local work's 10 s and the 25 s), and `punarctl
  reconcile` waits 45 s. `enroll.start`'s own three calls share 35 s
  (5 + 14 + 5 = 24 s, and room to wait behind one report of a pass already
  in flight), its reconcile pass 25 s more: 70 s with its local work. The
  agent serves one call at a time, so each call's wait starts behind every
  call punard already has in flight, never from when it was sent. The agent
  is dormant until enrolled (docs/development/smplify-enrollment.md §3.4):
  systemd holds its socket, and the first call after it went dormant (the
  first `org.discover` of an `enroll.start`, the boot reconcile's first call
  on an enrolled device) includes starting it, tens of milliseconds, inside
  the second each wait keeps above the agent's own budget. While enrolled,
  every pass first makes the liveness call `identity.status`, before the
  policy fetch. The agent answers it locally, in milliseconds when it is
  running; punard waits up to 10 s, room for a cold start (the socket
  starting a sandboxed service on slow hardware under boot load, unmeasured
  on the release image). An answer that does not come, or is not the
  agent's, ends the pass's calls to the agent (section 6, `enroll.agent`),
  so it never adds a full wait to the four above. Every other method keeps
  the 10 s/15 s bounds unchanged.
  **Application amendment:** `apps.catalog` may spend 30 s verifying remote
  metadata (`punarctl`: 45 s), while `apps.install`, `apps.update`, and
  `apps.remove` have bounded 30-minute/30-minute/10-minute per-app backend
  transactions (`punarctl`: 30 minutes for one app; 125 minutes for `--all`).
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
{"v": 1, "id": "req-1", "error": {"code": "denied", "message": "Changing system.hostname needs administrator privileges.\nPolicy: personal defaults — an ordinary user may hold privilege for a bounded window, never permanently (SPEC section 48).\nNext step: ask for time-boxed privilege: punarctl privilege request --capability system.hostname --reason \"<why>\"; once you approve it, run punarctl capabilities set system.hostname <name> again.", "details": {"capability": "system.hostname", "decision": "deny", "policy_ids": ["personal-defaults"]}}}
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
| `untrusted_artifact` | A signed update document/artifact failed signature, target, key-set, digest, size, or UKI root-binding validation. It is never retried as a transport error. | `stage` |
| `insufficient_space` | The private release cache or fixed inactive root slot cannot hold the signed release. | `stage`, `required_bytes`, `available_bytes` |

## 5. Methods (M3 surface + M4/M5 additions — complete)

The method set is closed. There is **no** exec, shell, script, or
run-as-root method, by architecture (spec section 10 "Prohibited:
RunRootShell(command)"; section 60). The 74.4 security test probes this via
`punarctl debug rpc system.exec` and must get `unknown_method`.

| Method              | AuthZ                 | Mutating | Audited | Device admin (§23) |
|---------------------|-----------------------|----------|---------|---|
| `status`            | any connected peer    | no       | no      | — |
| `device.posture`    | any connected peer    | no       | no      | — |
| `capabilities.list` | any connected peer    | no       | no      | — |
| `capabilities.get`  | any connected peer    | no       | no      | — |
| `capabilities.set`  | **root only (uid 0)** | yes      | always (allow and deny, success and failure) | **yes** on the grant path, re-checked each use (§23.2) |
| `audit.tail`        | any connected peer; **a non-root caller sees its own events and the device's, with a `withheld` count** (§5.5, F0-S3) | no       | no      | — (scoped, §23.2) |
| `reconcile`         | **root only (uid 0)** | no in M3 (re-verify only); **yes since M4** (remediates per policy, section 5.6) | always | — |
| `policy.effective` (M4) | any connected peer | no      | no      | — |
| `policy.explain` (M4)   | any connected peer | no      | no      | — |
| `policy.set`            | **root, or a re-authenticated member of the admission group; agent-attributed peers are refused whatever their uid** | yes | always (allow and deny) | **yes** (§23.2) |
| `enroll.start` (M5)     | root, or a person with a fresh `punar-authd` ticket; agents never (section 5.9) | yes  | always  | **yes** (§23.2) |
| `enroll.status` (M5)    | any connected peer | no      | no      | — |
| `enroll.stop` (M5)      | nobody, where the organization enrolled the device as not removable; otherwise root, or a person with a fresh `punar-authd` ticket; agents never (section 5.11) | yes  | always  | **yes**, the device's own list (§23.4) |
| `approvals.list` / `approvals.get` (M9) | any connected peer; **scoped to the approvals routed to the caller** (root sees all; §14.2) | no (lazy expiry sweep) | no | — |
| `approvals.create` (M9) | **root only (uid 0)** | yes | always | — |
| `approvals.resolve` (M9) | **human only** (§14.5) | yes (may execute) | always | **yes** to approve a `capability_set` or `privilege_request`, with a ticket (§23.2) |
| `approvals.consume` (M9) | **root only (uid 0)** | yes | always | — |
| `privilege.request` (M9) | any connected peer **except agent-attributed peers** | yes | always | **yes** (§23.2) |
| `privilege.status` (M9) | any connected peer | no (lazy expiry sweep) | no | — |
| `privilege.revoke` (M9) | grant owner or root | yes | always | — |
| `apps.catalog` | any connected peer | no | no | — |
| `apps.list` | any connected peer | no | no | — |
| `apps.install` | **human; managed policy decides when enrolled; then a device administrator** | yes | always | **yes** (§23.2) |
| `apps.remove` | **human; managed policy decides when enrolled; then a device administrator** | yes | always | **yes** (§23.2) |
| `apps.update` | **human; managed policy decides per installed app; a device administrator** | yes | always | **yes** (§23.2) |
| `webapps.list` / `webapps.get` | any connected peer; own uid only | no | no | — |
| `webapps.install` / `webapps.uninstall` | **human; own uid; managed policy decides when enrolled** | yes | always | — |
| `webapps.context_create` / `webapps.context_delete` | **human; own uid; reserved contexts protected** | yes | always | — |
| `pim.mail.open` | **human with a verified live desktop session; own uid only** | no | agent denials | — |
| `pim.mail.account_add` | **human with a verified live desktop session; own uid only** | verified account transaction | agent denials | — |
| `pim.mail.account_manage` | **human with a verified live desktop session; own uid only** | account removal only after explicit in-window confirmation | agent denials | — |
| `update.status` | any connected peer | no | no | — |
| `update.check` | **root, or a person with a fresh `punar-authd` ticket; agents never, at any uid** (§5.17) | verified cache only | always (`success`, `noop`, `denied`, `unreachable`, `failure`) | — |
| `update.apply` | **root, or a person with a fresh `punar-authd` ticket; agent attribution is a hard denial before uid** (§5.17a) | yes, inactive slot only | always | **yes** (§23.2) |
| `update.reconcile_candidate` | **root boot service only in normal operation; agent attribution is a hard denial before uid** | Pi selector/finalization only | required durable outcome audit before pending removal | — |
| `update.rollback` | **root, or a person with a fresh `punar-authd` ticket; agent attribution is a hard denial before uid** (§5.17c) | yes, local selector only | always | **yes** (§23.2) |
| `install.targets` | any connected peer, **live environment only** | no | no | — |
| `install.plan` | **root only, live environment only** | no | always (`success`, `refused`, `failure`) | — |
| `install.apply` | **root attended installer or independently signed unattended provisioner; live environment only** | yes | always (`success`, `denied`, `failure`) | — |
| `install.recovery_ack` | **root attended installer or signed unattended provisioner; live environment only** | recovery checkpoint only | denials; successful custody is `install.recovery_key/enrolled` | — |
| `install.status` | any connected peer, **live environment only** | no | no | — |
| `admins.list` (F0) | any connected peer | no | no | — |
| `admins.set` (F0) | **root, or a device administrator with a fresh `punar-authd` ticket; agents never, at any uid** (§23.3) | yes | always | **yes** |

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

**No refusal tells a person to become root (2026-09).** A Punar device
gives no person root: root is locked, nobody is in `wheel`, and Punar
authors no sudoers rule (docs/design/onboarding.md §1.6). So a denial's
next step is one a person can take — the grant for exactly that capability
(`capabilities.set`), the password confirmation (`policy.set`,
`enroll.start`, `enroll.stop`, `update.check`, `update.apply`,
`update.rollback` — §5.17), what the device already does on its own
(`reconcile`, `network.apply`), or, where no person's path exists, a plain
statement of that and of who can act. A root-only method whose resource is
not a registered capability (`reconcile`, `update.reconcile_candidate`,
`install.*`, `approvals.create`/`consume`) is refused with
`details.resource`, never `details.capability`, and never offers `privilege
request`, which would answer `not_found`. A password-confirmed method's
refusal instead carries `details.reason` (`reauthentication_required`, or a
`reauthentication_*` reason for a ticket that was not accepted).

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
  "capabilities_total": 6,
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
    {"capability": "time.timezone",     "state": "compliant"},
    {"capability": "system.update_channel", "state": "compliant"},
    {"capability": "browser.policy", "state": "compliant"}
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

### 5.1a `device.posture`

The device's own posture, hardware and power, readable by the person at
the device. It is an open read, like `status`, and takes no params.

```json
{"v":1,"id":"d1","method":"device.posture"}
{"v":1,"id":"d1","result":{
  "posture":{"secure_boot":true,"uefi":true,"tpm_present":true,
             "tpm_version":"2.0","is_virtual":false,"virtualization":null,
             "disk_encryption_enabled":true,"firewall_enabled":true,
             "firewall":"nftables","os_patch_status":"unknown",
             "reboot_required":null},
  "hardware":{"manufacturer":"LENOVO","model_name":"21K5CTO1WW",
              "bios_version":"R2AET53W","cpu_model":"AMD Ryzen 7 PRO 7840U",
              "cpu_vendor":"AuthenticAMD","cpu_cores":8,"cpu_threads":16,
              "memory_total_bytes":33554432000,
              "device_capacity_bytes":512000000000,
              "root_filesystem_type":"erofs","battery_present":true},
  "power":{"batteries":[{"name":"BAT0","capacity_percent":64,"status":"Charging"}]},
  "checked_at":"2026-09-24T10:00:00Z"}}
```

- **`posture` and `hardware`** are the managed inventory's own types
  (`punar_common::device`). The same collector fills them from the same
  inputs: this read's `security.firewall` observation, and the update
  engines' patch evidence. The person and their organization therefore
  read one answer.
- **The meaning of `null`:** it is "could not be established", never a
  guessed `false`.
- **`disk_encryption_enabled`:** true only when every data path (`/var`,
  `/home`) is proven LUKS2 by `punar_common::storage`, the proof the Mail
  vault also requires. It is the one encryption answer on the device, and
  System Control shows this one.
- **`power.batteries`:** found by the classifier's rule, meaning a
  `power_supply` entry named `BAT…` or one whose `type` is Battery. Each
  has `capacity_percent` (0–100) and the kernel's `status` word, and
  either is `null` when not reported. Power is local only: the inventory
  carries `battery_present`, never this.
- **What it never carries:** the serial number and the application list.
  Those belong only to an organization-owned device's inventory
  (docs/development/smplify-enrollment.md section 3).

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
nftables read. `managed_by` is `"local"` in personal mode. The original M3
registry was `security.firewall`, `system.hostname`, and `time.timezone`
(backends: docs/development/milestone-3.md section 4).
`system.update_channel` is now the fourth capability: the same layered
preference/organization-policy machinery governs `stable`, `dev`, or `edge`.
`browser.policy` is the fifth: its only desired states are `managed` and
`unmanaged`; live observation returns `drifted` when Chromium's root-owned
mandatory-policy file does not match the freshly rendered effective policy.

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
clamped, not errors). Result: `{"events": [ {...AuditEvent...}, ... ],
"withheld": 0}` — newest last, each element schema-conformant
(`schemas/audit/audit-event.json`). The daemon reads the file; clients never
need read access to `/var/log/punar/audit.jsonl`, and since F0 no person has
it (§6).

**Scoped per caller (F0-S3).** The window is the last `n` lines of the
trail. **Root** receives all of them. **Anyone else** receives their own
events — `user_id` equal to their resolved name or `uid:<n>` — and the
**device's**: events no person is attributed to (`source` `service`,
`device` or `organization`) and root's administration of the device
(`user_id: "root"`). Every other person's events are left out and counted
in **`withheld`** (additive; `v: 1` allows it, and a client that predates it
ignores it). A busy neighbour therefore shortens what a person sees rather
than making the read scan further back, and `withheld` says by how much.
`punarctl audit tail` prints the count. Reading another person's events is
§23's "reveals another person's data", and the only path to it today is
root.

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
resets the counter. "The effective value changes" means its value or its
classification: every recompute of the effective document (a
`capabilities.set`, an enrollment transition, a policy refresh that changes
the set) lifts suppression for exactly the paths that changed.

**M5 amendment — live organization-policy refresh.** On an enrolled device
each `reconcile` call first asks the control plane for the organization's
policy (`policy.fetch`), before the pass takes its snapshot of the effective
document, so a changed set is enforced and reported by **that same pass**
(spec section 42: load desired state, then diff). The two-minute
`punard-reconcile.timer` is therefore the refresh cadence; there is no new
timer. The boot reconcile and the passes `enroll.start` and `enroll.stop`
run do not refresh. The outcome is recorded in `enroll.status.policy`
(section 5.10) and audited as `enroll.policy` (section 6); it never changes
the reconcile result's shape.

- **All or nothing.** The fetched set is checked by the rules of section
  5.9 and, only if it passes all of them, replaces `policy.d` whole; the
  rendered browser document, the policy layers, the AI authority and the
  effective document follow. Anything short of that — a set that fails a
  check (`rejected`), a device that cannot install it (`failed`), a control
  plane that does not answer (`unreachable`) or answers with an error
  (`refused`) — leaves all of them exactly as they were: the last valid
  policy stays enforced (spec section 55).
- **Only `"assignment": "none"` withdraws.** An empty list withdraws the
  organization's policy (`withdrawn`; the device stays enrolled) only when
  the control plane says nothing is assigned. An empty list marked
  `unusable`, marked `policies`, or not marked at all is `held`: the last
  good policy stays enforced.
- **Unchanged costs one call.** The fetched set is compared byte for byte
  with the files the enrollment owns, the record's list of them, and the
  set the in-memory layers and the browser document were made from; if all
  three match (`unchanged`), nothing is written or audited. A file the
  record owns that is gone from `policy.d`, or layers a change could not
  undo, make the pass commit again, so a withdrawn policy's layers never
  outlive it.
- **Crash-safe.** The record owns both sets' files, with the change marked
  pending, before the swap, and says what is enforced only after it; the
  directory the swap replaced is kept until then. A rollback that cannot be
  verified from `policy.d` itself removes nothing and shrinks no record: the
  daemon enforces the set `policy.d` holds and the next pass commits again.
  A start after a crash decides from `policy.d` which set is live, records a
  change that landed as made (`changed_at` its start) and audits it once.
- **Backoff.** After the n-th consecutive failed fetch, the next
  `2^(n-1) - 1` passes (at most 15) do not fetch: 0, 1, 3, 7, 15, 15, …
  passes. Any answer, a refused set included, resets it; so does a restart.
  A set this device could not install (`failed`) counts as a failure too.
  A refusal that depended on this device's own files as well as the set
  (`foreign_file_collision`, `unsupported_entry`,
  `conflicts_with_local_policy`, `swap_unsupported`) is not staged again
  until the offer or `policy.d` changes; the first two are found by reading
  `policy.d`, before anything is written.
- **Terms are fixed.** A refresh never reads the organization document
  again and changes no enrollment term (`removable`, `organization_owned`,
  `remote_query_scopes`).

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

Two additive fields carry the device-administrator layer (section 5.8a).
Both are optional under the v1 additive-field rule, and a client that does
not see them is talking to a daemon that predates it:

- each entry's `admin_override_permitted` is `true` iff this device's
  administrator could move the value — the winning rank is greater than 4,
  or the winner already *is* the administrator's own entry. It answers the
  question `user_override_permitted: false` provokes, which is "then who
  can?", and it is what lets a surface offer editing only where editing
  would work rather than discovering the answer from a refusal.
- a top-level `local_admin` object says whether local policy editing is
  permitted at all, and by whom it was withheld:
  `{"allowed": true}` on a personal device (the default when no
  organization has an opinion), or
  `{"allowed": false, "source": {"kind": "organization_baseline", "rank": 2,
  "policy_id": "eng-baseline-v12", "name": "Acme Engineering Baseline"}}`
  when one has (spec section 44.5 names local admin among the service
  controls enterprise policy governs; the organization expresses it as
  `spec.security.localAdmin.policyEditing: "allowed" | "denied"` in its
  desired-state document).

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
  "admin_override_permitted": true,
  "compliance_state": "compliant"
}}
```

`admin_override_permitted` is the additive field described in section 5.7.

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

### 5.8a `policy.set`

Params:

```json
{"capability": "security.firewall", "value": "disabled",
 "reason": "the lab machines run without it", "ticket": "<64 hex>"}
```

Mutating, always audited (`action: "policy.set"`, `resource:` the
capability). Records (or, with `"value": null`, withdraws) the **device
administrator's** entry — `device_specific_override` at precedence rank 4 —
and then applies whatever the merge says, exactly as `capabilities.set`
does.

**It is not a document write, and the shape is the argument.** The caller
names one *registered capability* and one value that capability validates.
There is no path expression, no merge patch, and no way to reach a path the
registry does not already govern: a generic "write this policy document as
root" primitive is the root RPC spec sections 10 and 60 forbid, and it
would let a caller author policy for paths nothing can apply, verify or
explain. `deny_unknown_fields` makes a smuggled extra field a hard parse
error rather than something silently ignored.

**Where rank 4 comes from.** `schemas/policy/policy-source.json` says
`device_specific_override` "appears in the section 39 source list but has
no rung in the suggested ladder, so deployments assign its rank
explicitly". Punar assigns 4, which produces exactly the two properties
that matter: `organization_baseline` (2) and `organization_role_policy` (3)
beat it, so an enrolled device's org policy cannot be edited away locally;
and it beats `local_user_preference` (5), so an administrator's decision
binds everyone using the device. Rank 4 is shared with
`temporary_approved_exception`, and an organization's approved exception
wins that tie — it is a decision somebody already made about that exact
path.

Authorization, in the order the checks run — every reason that does not
depend on *who is asking* is settled before a password is requested:

1. an **agent-attributed peer is refused whatever its uid** (spec section
   60: root-ness inside an agent scope buys no bypass, and an agent has no
   password to re-prove);
2. a non-empty `reason` of at most 500 characters is required, and is
   persisted with the entry;
3. the value must validate against the capability (`invalid_params`);
4. `local_admin.allowed` must be true (`denied`, citing the organization);
5. the path's current winner must be one rank 4 outranks (`denied`, citing
   the pinning source — the same message `capabilities.set` gives);
6. uid 0 is authorized as-is. Any other caller must present `ticket`: a
   single-use re-authentication ticket minted by `punar-authd` for **that
   caller's own uid** within the last 120 seconds. It is spent whether or
   not it turns out to be fresh.

   **Ticket format and age (SMP-1405).** The ticket file holds one boot-clock
   stamp, `{"boot_id": "…", "raw_bt_ms": …, "sleep_ms": …, "suspends": …}`,
   written by `punar-authd` at the moment of the PAM success. punard judges
   its age on its own boot clock — never the file's mtime or the wall clock
   — by the rule of §14.4: same boot, no suspend since, and
   `elapsed_ms < 120000 − 24`. A ticket from another boot or from before a
   suspend, one stamped in the future of punard's clock, one with no
   readable stamp (an empty ticket an older `punar-authd` minted during an
   upgrade: the person types their password again), or any ticket while
   punard cannot read its clock is refused as `reauthentication_expired`,
   and is spent all the same.

   **Binding (F0 review, §23.5).** Since F0 the file is
   `{"minted": <that stamp>, "action": "<method>", "spender": {"pid": …,
   "start": …}}`: a ticket is spent only on the method named in `action`,
   and only when the connection's peer (`SO_PEERCRED`) is the process named
   by `spender` — pid and kernel start time. Presented for another call it is
   refused as `reauthentication_wrong_action`, from another process as
   `reauthentication_wrong_process`, and is spent either way. A bare stamp
   binds nothing and is refused as `reauthentication_expired`.

**F0 amendment (§23):** between steps 5 and 6, a caller other than root must
be a **device administrator** — refused with `device_admin_required` before
their ticket is spent, and audited. Device policy binds everyone who uses the
machine; a person without the role asks one who has it.

`policy.set` is deliberately **not** root-only. There is no sudo on a Punar
desktop, so "root only" would mean "nobody can do this at the keyboard".

From a terminal, `punarctl policy set <path> <value> --reason "…"` and
`punarctl policy clear <path> --reason "…"` ask for the person's password on
the controlling terminal with echo off and send it straight to `punar-authd`'s
socket, exactly as `enroll`, `update`, `approvals resolve` and `admins` do
(§23.5). Scripts hand a password or a ticket over **a socket** —
`--password-fd N` or `--ticket-fd N` — and System Control uses
`--ticket-from-parent`. `--ticket-stdin` and `--password-stdin` are gone: a
pipe on stdin can be read by any program running as the person before
punarctl reads it, and either flag is refused with a message naming its
replacements, whoever passes it (§23.5). A `denied` or
malformed ticket is refused by punarctl before anything is sent. With neither
a terminal nor a source, the request goes without a ticket and the refusal
(`reauthentication_required`) names the terminal command.

Result — a pin:

```json
{"v":1,"id":"1","result":{
  "capability": "security.firewall",
  "pinned_value": "disabled",
  "effective_value": "disabled",
  "source": {"kind": "device_specific_override", "rank": 4,
             "policy_id": "device-admin/owner",
             "name": "Device administrator"},
  "changed": true
}}
```

and a withdrawal, which hands the path back to whatever was underneath:

```json
{"v":1,"id":"1","result":{
  "capability": "security.firewall",
  "pinned_value": null,
  "effective_value": "enabled",
  "source": {"kind": "organization_baseline", "rank": 2,
             "policy_id": "eng-baseline-v12",
             "name": "Acme Engineering Baseline"},
  "changed": true
}}
```

`pinned_value` and `effective_value` are reported separately because they
genuinely differ on a withdrawal — the entry is gone and something else now
decides — and because collapsing them would make the result a claim about
the store rather than about the machine.

**A successful pin always makes the pinned value effective**, and that is a
consequence of step 5 rather than a coincidence: an administrator is refused
outright when a higher layer already holds the path, so the case where a pin
is recorded-but-overridden does not arise here. It is the one place
`policy.set` deliberately behaves *unlike* `capabilities.set`, which records
a preference even when outranked (section 5.4). The difference is who is
asking: a user recording a preference under an organization's rule is
expressing what they would like, and an administrator pinning a value that
does nothing has simply been misled.

**Withdrawing is exempt from step 5**, and must be. That step looks at who
wins *now*, and an organization can come to outrank an entry pinned earlier
— at which point the same test that stops an administrator pinning would
stop them removing what they already pinned. The entry would sit in the
store, inert while enrolled and silently back in force the day the device
unenrolls. A clear can only ever remove a local opinion, so there is nothing
for the check to protect.

**This is an administrative control, not a security boundary.**
`docs/design/execution-trust.md` says it plainly — a local root user
defeats local policy. What this method adds is that the ordinary route is
authenticated, bounded, explained and recorded.

### 5.9 `enroll.start` (M5)

Params: `{"org_domain": "acme.com", "code": "…", "ticket": "…", "accept_non_removable": true, "accept_organization_owned": true}` — `accept_non_removable` and `accept_organization_owned` optional, default `false` (step 6 below); `code` optional on the wire (the dev/CI mock needs none; the built-in Smplify agent refuses to register without one), read by punarctl from stdin or a hidden prompt, never argv, never audited or returned. Mutating, always
audited (`action: "enroll.start"`, `resource: "enrollment"`; success cites
the fetched policy ids in `policy_ids`). Processed under the 70 s bound
(section 2).

**Who may enroll: root, or a person who has just confirmed their password.**
No account on a Punar device holds sudo and root is locked (onboarding.md
section 1.6), so a person enrolls the way `policy.set` is confirmed: punarctl
asks for their password, relays it to `punar-authd` (whose socket only the
`punar` group can reach), and passes the single-use `ticket` it mints. The
checks run in this order:

1. **No agent, at any uid** — the wide M9 test (section 14.5); root inside an
   agent scope buys no bypass. Audited as a denial,
   `details.reason: "agent_scope"`. A ticket the agent carried is left
   unspent.
2. **A non-root peer must carry a ticket** — audited as a denial,
   `details.reason: "reauthentication_required"`, before anything is parsed
   or sent.
3. **A malformed domain** → `invalid_params`, not audited (as before this
   gate existed), so a typo does not cost the person their password.
4. **The ticket is spent** — audited as a denial on failure:
   `details.reason: "reauthentication_missing"` (absent from the caller's own
   uid directory: never minted, already spent, or minted for someone else),
   `"reauthentication_expired"` (older than 120 s on the boot clock, from
   another boot or before a suspend, or undatable — see the ticket format
   under §5.8a) or
   `"reauthentication_malformed"` (not 64 hexadecimal characters). The
   unlink is the commit, so a replay finds nothing. A ticket is never
   forwarded, audited, stored or returned.
5. Only then the guard and the already-enrolled `conflict`, so every event
   from here on names a caller who proved who they are. punarctl reads
   `enroll.status` first and does not ask for a code or a password on a
   device that is already enrolled. The next step's `org.discover` is the
   first call to the built-in agent a device that never enrolled makes, and
   its socket starts the agent (section 2); an agent that cannot be used is
   `upstream_unreachable` with `details: {"stage": …, "reason":
   "agent_unavailable", "agent": <section 6 reason>}`.
6. **The organization's enrollment terms**, read from the document
   `org.discover` returned and before `enroll.register`, so an organization
   never learns of a device that did not enroll
   (docs/development/smplify-enrollment.md §3.1, §3.2). Both are fixed in
   `enrollment.json` and never re-read from a policy fetch. An ordinary
   organization states neither, and its enrollment asks nothing more.
   - **Removal.** `enrollment.removable` is a boolean; absent means `true`. A
     value that is present but not a boolean is `invalid_params`
     (`details: {"stage": "discover", "reason": "enrollment.removable"}`),
     never the permissive reading. `false` needs `accept_non_removable:
     true`: an organization cannot make a device non-removable without its
     user's explicit yes. The term is written to `enrollment.json`, and to
     `enrollment-terms.json` beside it. An older punard booted from a
     retained UKI never rewrites that second file, and this build folds it
     back in when loading, so a rewrite that drops the field cannot make the
     device removable.
   - **Ownership.** `enrollment.ownership` is `"personal"` or
     `"organization"`, exactly; absent means `"personal"`. Anything else —
     another string, another spelling, or not a string — is `invalid_params`
     (`details: {"stage": "discover", "reason": "enrollment.ownership"}`),
     never either reading. `"organization"` needs `accept_organization_owned:
     true`: nothing proves an organization owns the hardware, so only the
     person's yes lets the inventory also carry the device's serial number
     and every application installed for all users (milestone-5.md §6). The
     term is written to `enrollment.json` only: an older punard that rewrites
     the file without the field can only narrow what is sent.
   - **One refusal names every unaccepted term.** `denied`, with
     `details.terms` listing each term the request did not accept, in the
     order `["non_removable", "organization_owned"]`; `details.reason`
     `"non_removable_not_accepted"` or `"organization_owned_not_accepted"`
     when it names one term, `"enrollment_terms_not_accepted"` when it names
     more; and `details.organization` and `details.organization_name`. The
     message says what each term means and names `punarctl enroll start
     <domain>` with every flag still needed (`--accept-non-removable`,
     `--accept-organization-owned`). The organization's names are cleaned
     once, where punard reads its document, and every field carrying one
     (`org.name`, `org.display_name`, `details.organization_name`, the
     status file's `org_name`) holds the cleaned text: control and
     invisible format characters dropped, whitespace collapsed to one space,
     at most 64 characters. In the message the name is quoted and each
     term's meaning is fixed text without it; a terminal replaces anything
     that could still steer it with U+FFFD, so it cannot conceal the term
     beside it. Accepting
     a term the organization did not set accepts nothing. On a terminal
     punarctl shows every named term in one prompt, asks for one `accept`,
     and sends the request again with exactly those flags and a fresh
     password (the first was spent on discovery — nothing is fetched for a
     caller who has not confirmed); without a terminal, or with `--json`,
     the refusal is the answer.

Pipeline (spec section 49 mapped to the mock control plane; design and the
honest-labeling rules: milestone-5.md sections 3, 5.1): guard (already
enrolled → `conflict`) → `org.discover` → `enroll.register` with the
persistent `device_id` and a fresh in-memory bootstrap secret →
`policy.fetch` → check the set (below) and stage it beside `policy.d` →
store the device token (`/var/lib/punar/device-token`, `0600`, `Redacted`
in memory) and `/var/lib/punar/enrollment.json` (`0600`, written and
`fsync`ed **before** `policy.d` changes, so a crash never leaves
organization policy enforced on a device that reads as personal) → swap the
staged set in as `policy.d` → render the browser document → recompute the
section 39 merge → one full section 42 reconcile pass → first compliance +
inventory report (failures queue per section 55; they do not fail
enrollment) → rewrite the section 9 status file. All-or-nothing up through
the swap: any failure before that point removes everything this call
created, releases the identity `enroll.register` issued, and returns
`upstream_unreachable` / `invalid_params` / `internal` with local state
untouched.

**The policy set.** `policy.fetch` answers `{"policies": [<envelope>, …],
"assignment": "policies" | "none" | "unusable"}`. The marker says what the
list is: `none`, the organization assigns this device nothing; `unusable`,
something is assigned that the control plane could not turn into Punar
policy (`punar-smplifyd` answers it for a Smplify bundle without a Punar
payload); `policies`, the list is the policy. A missing or unrecognised
marker reads as unstated. `enroll.start` enrolls with an empty set for any
empty list, and records `unusable` as a `held` refresh so the person sees
why; after enrollment only `none` may empty the set (section 5.6). The set
`enroll.start` and every refresh accept is checked by one set of rules,
whole, and the first failure refuses all of it (`invalid_params`,
`details: {"param": "policy", "reason": <code>}`; the two pre-existing cases
keep their earlier `reason` text):

| Rule | `reason` |
| --- | --- |
| the answer carrying it is at most 4 MiB | `answer_too_large` |
| at most 64 envelopes | `too_many_policies` |
| each is a JSON object | `envelope_not_an_object` |
| `policy_id`: 1–128 of `[A-Za-z0-9._-]`, not starting with `.` | `unusable_policy_id` |
| no two envelopes share a `policy_id` | `duplicate_policy_id` |
| each nests objects and arrays at most 32 deep, itself the first level | `envelope_too_deep` |
| each at most 256 KiB in canonical form | `envelope_too_large` |
| together at most 1 MiB in canonical form | `set_too_large` |
| `source_kind` is `organization_baseline`, `organization_role_policy`, `temporary_approved_exception` or `device_specific_override` — never a rung that belongs to the OS or the person | `source_kind_not_organizational` |
| a `device_specific_override` ranks 2 or below, never with the OS's hard safety constraints | `rank_not_organizational` |
| `none`/`unusable` with a non-empty list | `inconsistent_assignment` |
| the M4 loader accepts the set, alone | `invalid_envelope` |
| its browser policy renders into the allowlisted document | `browser_policy_refused` |
| it names no file a root administrator dropped into `policy.d` | `foreign_file_collision` |

Sizes are measured before anything is built from them: nesting first, then
each envelope's compact form counted without being kept, then its canonical
form written into a buffer that refuses to grow past 256 KiB. The answer
bound is four times the set bound, so a set within the rules always arrives
(canonical form is never shorter than the same JSON written compactly); an
answer past it is refused as `answer_too_large` — the control plane answered
— never read as an unreachable one.

The set is written as each envelope's canonical bytes (pretty JSON, keys
sorted) to `<policy_id>.json`, 0600, in a staging directory beside
`policy.d` (`/var/lib/punar/.policy.d.next`); every other entry of
`policy.d` — a root drop such as an AI authority `.yaml`, or a local
envelope — is carried over as a hard link to the same file (an empty
directory as an empty directory), never overwritten, never taken over. The
staging directory is loaded again with those files beside the set, exactly
as the next start will load it; a failure there is the device's, not the
organization's (`internal`). Only then does it replace `policy.d` in one
`renameat2(RENAME_EXCHANGE)`: there is no moment, crash included, when
`policy.d` holds part of two sets or a set that does not load (punard
refuses to start on one). A filesystem that cannot exchange directories
fails the change; there is no non-atomic fallback. The carried files are
checked on both sides of the exchange: one a root administrator added,
replaced or removed after staging stops the change (the exchange is undone)
rather than being lost with the directory it was put in. The record is
written durably before the exchange and a failure after it is undone, but
only once `policy.d` itself shows the previous directory back: when that
cannot be verified, the enrollment stands, record and token included, since
its files may be live. At the next start, a staging directory left by a
crash is removed and the enrollment's record trimmed to the files
`policy.d` holds.

```json
{"v":1,"id":"1","result":{
  "enrolled": true,
  "org": {"id": "acme", "name": "Acme", "display_name": "Acme Engineering",
           "domain": "acme.com"},
  "policy_ids": ["eng-baseline-v12"],
  "attestation": "simulated",
  "enrolled_at": "2026-08-26T09:00:00Z",
  "first_sync": {"compliance": "success", "inventory": "success"},
  "removable": true,
  "organization_owned": false
}}
```

`attestation` is the literal honesty label: the spec 49 attestation step is
**simulated** by the mock and reported as such wherever enrollment state
appears. `first_sync` says how the first pass's reports went, each
`"success"`, `"unreachable"` (the network), or `"agent_unavailable"` (the
built-in agent could not be used: section 6, `enroll.agent`); a report that
did not go stays pending for a later pass. Errors: `conflict`, `upstream_unreachable`, `invalid_params`
(malformed domain / a policy set that fails a rule above), `internal` (the
device could not stage or install a set), `denied`. `enroll.start` and
`enroll.stop` wait up to 2 s for a policy refresh that is committing before
answering `conflict`.

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
                 "pending": false},
  "removable": true,
  "organization_owned": false,
  "organization_view": {
    "sent_at": "2026-08-26T09:00:04Z",
    "categories": [
      {"category": "hardware", "fields": ["batteryPresent", "biosVersion", "…"]},
      {"category": "os", "fields": ["arch", "kernelRelease", "name", "version"]},
      {"category": "security", "fields": ["diskEncryptionEnabled", "firewall", "…"]},
      {"category": "software", "fields": ["installedPackages", "installedPackagesCount",
                                          "installedPackagesHash", "smplifydVersion"],
       "counts": {"installedPackages": 2}}
    ]
  },
  "policy": {
    "revision": "sha256:5c1e…",
    "fetched_at": "2026-08-26T11:40:02Z",
    "changed_at": "2026-08-26T09:00:00Z",
    "last_refresh": {"at": "2026-08-26T11:42:02Z", "result": "rejected",
                     "reason": "duplicate_policy_id"}
  }
}}
```

Unenrolled: `{"enrolled": false}` with the org-shaped fields absent.
`policy_ids` are the ids of the organization's set the device enforces
**now**: a refresh that adds, removes or withdraws policies changes them.
`policy` (present exactly when enrolled) says which set that is and how the
last check for a newer one went (section 5.6). `revision` is `sha256:` over
the set's files in name order (name, a NUL byte, the length as a big-endian
u64, the bytes), so it can be recomputed from `policy.d`; `null` for an
enrollment made before refresh existed, until its first refresh.
`fetched_at` is when the device fetched the answer it enforces — a refresh
that was `rejected`, `held`, `unreachable`, `refused` or `failed` does not
move it, so it says how fresh the enforced policy is — and `changed_at` when
the set last changed; both fall back to `enrolled_at`. `last_refresh` is
`null` before the first refresh; `result` ∈ `unchanged | applied |
withdrawn` (enforcing what the organization serves) `| rejected | held |
unreachable | refused | failed` (enforcing the last good set), and `reason`,
absent for the first three, is a closed code: a rule of section 5.9 for
`rejected`; `unusable_assignment | unstated_empty | empty_policies` for
`held`; `unauthorized | not_found | internal | other` for `refused`;
`io | unsupported_entry | conflicts_with_local_policy | swap_unsupported |
local_files_changed` for `failed` (`local_files_changed`: a root
administrator added, replaced or removed a file in `policy.d` while the set
was being installed; the next pass prepares again). The control plane's and the loader's own words never appear
here; they go to the journal, escaped and cut to 512 characters.
`organization_view` is what the organization can see of this device (SPEC
section 24.2), read from the inventory body that last left it
(`/var/lib/punar/organization-view.json`, root:`punar` 0640) — never from a
list of what should have been sent, so it cannot show less than left.
`sent_at` is when that send succeeded. `categories` is sorted by name; each
names the fields that carried a value (a field sent as `null` or empty told
the organization nothing and is not listed), and `counts`, present only when
a field carried a list, how many rows it had. Names only, never values.
Against Smplify the categories are the `systemInfo` sections the built-in
agent posted (docs/development/smplify-enrollment.md §3.3); against the
development mock they are punard's own inventory sections, with values that
belong to no section (`kernel`, `capabilities`, `applications`)
listed under `device`. Present exactly when enrolled; before the first
successful send, or when the record belongs to another enrollment, it is
`{"sent_at": null, "categories": []}`.
`removable` is the organization's removal term fixed at enrollment
(§5.9 step 6): whether `enroll.stop` can succeed on this device at all.
`organization_owned` is its ownership term, fixed the same way: whether the
inventory also carries the serial number and every application installed
for all users. `enroll.start`'s result carries both.
`last_sync.result` ∈ `"success" | "unreachable" | null`; `pending` is true
while a report is queued (bounded latest-wins queue, spec section 55;
milestone-5.md section 7). A pass the built-in agent could not carry is not a
sync attempt at all (the network was never asked): `last_sync` keeps the last
attempted sync, and `pending` is true. The device token appears in no field.
`management` (present exactly when enrolled) is `{"state": "active"}`, or
`{"state": "interrupted", "reason": …, "since": …}` while the built-in agent
cannot be used: `reason` is the section 6 `enroll.agent` reason the last pass
found, `since` when the episode began. While it is interrupted no report is
sent and `last_sync.pending` is true. `identity_release`, absent when there
is none and only ever on a device with no enrollment, is
`{"state": "pending", "reason": …}` while a Smplify identity punard's release
record says to wipe is not confirmed wiped (section 5.11; `reason` is an
agent reason or `refused`, absent before the first attempt), or
`{"state": "kept", "reason": "enrollment_record_missing"}` while punard keeps
an identity it holds a token for and nothing records the end of the
enrollment it belonged to (`release_record_unreadable` when the record is
not one punard wrote).

### 5.11 `enroll.stop` (M5)

Params: `{}` or none from root; `{"ticket": "…"}` from a person. Mutating,
always audited (`action: "enroll.stop"`, `resource: "enrollment"`). The gate
is section 5.9's — agents refused at any uid, a person without a ticket
refused, the ticket spent before anything changes — with one refusal between
the agent check and the ticket check: **an organization may keep its
device.** Where it enrolled the device as not removable (§5.9 step 6, with
the person's explicit yes), every local caller — root included — is refused
with `details.reason: "enrollment_not_removable"` and
`details.organization`; a ticket is neither required nor spent, because the
answer does not depend on who is asking and `enroll.status.removable`
already says it to anyone. Only erasing and reinstalling the device ends
such an enrollment; a signed release from the organization is not built.
punarctl reads `enroll.status` first and asks for neither a yes nor a
password in that case. Guard: not enrolled → `conflict`. Removes exactly the policy.d files the enrollment currently owns (the last refresh's set; a root drop stays),
asks the built-in agent to wipe the device's Smplify identity
(`enroll.unregister`), deletes `enrollment.json`, recomputes the merge, runs
one reconcile pass (recorded user preferences resurface as the winning
layer per spec section 39), rewrites the section 9 status file. Result:
`{"enrolled": false, "removed_policy_ids": ["eng-baseline-v12"],
"identity_release": "released"}`.

**The identity is released, or kept until it is.** Before anything of the
enrollment is removed, punard writes its release record
(`/var/lib/punar/identity-release.json`, 0600, durably); only that record
ever makes punard ask the agent to wipe an identity. The wipe is local on the
agent's side (it asks Smplify nothing), so unenrolling works offline, and the
agent goes dormant once it has answered. punard asks with `any_identity:
true` (it holds no enrollment, and holds its enrollment guard for the whole
exchange, so no registration can come in between): whatever the agent holds
goes, the token's identity or one the token does not name. Unenrollment
never waits on it, and never forgets the identity either: when the agent does
not confirm the wipe (its socket is gone, it does not answer, it refuses),
the result says `"identity_release": "pending"`, punard keeps the record and
the device token, audits `enroll.release` `pending` (section 6), and asks
again on every reconcile pass; once the agent confirms, the token and the
record go and `enroll.release` `success` is audited.
`enroll.status.identity_release` and `status.json` show it meanwhile. So no
key is ever left on disk with no way to finish. `enroll.start` writes the
same record before `enroll.register`, so a registration it could not commit,
or whose answer it never received (punard killed, the machine off, a broken
connection, with the identity already kept by the agent), is released the
same way, and a registration that commits removes it. A device token found
with no enrollment and no record is not an unenrollment waiting to finish:
punard keeps it, asks the agent nothing, audits `enroll.release` `kept` once,
and shows `identity_release: kept`; a new enrollment replaces it.

**What unenrolling does not do:** the organization keeps its device record
and every report it received. Unenrollment stops all future sync and
restores local state; it does not (and could not honestly claim to) retract
what the organization already received.

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

A separately named native vendor package (`chatgpt-desktop` or
`claude-desktop`) reports the package identity that will be verified during
installation. `pinned` is not a claim that bytes have already been downloaded:

```json
{"app":{"id":"chatgpt-desktop","source":"vendor_deb","installed":false,
 "version":"26.825.32147","download_bytes":409931742,
 "uri_schemes":[],
 "inspection":{"pinned":true,"verified_on_install":true,
  "package_sha256":"<64 hex>","containment":"hardened_native",
  "permissions":["Network access","Isolated app home",...]}}}
```

Web, vendor desktop and coding-agent CLI identities never share installed
state. Punar does not claim that either vendor formally supports Punar.

### 5.13 `apps.list`

Params: none. Read-only, any connected peer, not audited. Returns each catalog
id, selected architecture source, native installed state, observed identity,
signed target identity, per-app `update_available`, and the aggregate
`updates_available` count. Web apps are not falsely represented as locally
installed packages.

### 5.14 `apps.install`

Params:

```json
{"id":"spotify","confirm_metadata_sha256":"<64 lowercase hex>","ticket":"<64 hex>"}
```

`ticket` (F0 review, §23.2) is a `punar-authd` ticket minted for
`apps.install` and the calling process; absent only for root. An application
installed system-wide changes what every person on the device runs, so a
person other than root must be a device administrator — checked after the
organization's application policy and the digest shape, before the ticket is
spent. `apps.remove` and `apps.update` carry the same optional `ticket`, for
their own method. The digest is the value shown by the calling app card. Under a single daemon
transaction lock, a Flatpak install re-inspects the exact pinned commit and
requires the catalog digest, caller-confirmed digest and observed digest to
agree before fixed-argv installation and resulting-commit verification.

For `vendor_deb`, the same field confirms the signed-catalog package digest.
The package is downloaded by the unprivileged `punar-fetch` helper (see
"Download helper" under `update.check`), never by punard; the helper refuses
any URL outside the catalog's closed vendor origins and follows no redirect,
and punard copies what arrives into a private staging file the helper never
holds. punard then enforces exact byte size and SHA-256, extracts only `data.tar.xz` into a root-owned staging
tree, rejects unsafe paths/file types/symlinks, clears setuid/setgid bits, and
generates its own desktop entry. Debian control archives and maintainer scripts
are never executed, and no vendor repository is registered. A custom URI scheme
is registered only when both the upstream desktop entry and the signed Punar
catalog declare it, and only while that app is installed. The launcher accepts
only those catalog-owned schemes. Callback URIs never transit punard, the audit
log, a shell string, or an environment variable: the host launcher receives
them over an anonymous pipe and later launches use a per-app `0600` Unix socket.

The launcher uses Bubblewrap with a read-only system/app payload, isolated
writable app home, a per-app session-only temporary directory, dropped
capabilities and only the desktop runtime, display/audio, GPU and network
surfaces declared in the inspection card. One tiny session process owns that
app's PID namespace. A later open or OAuth callback is authenticated against
the signed catalog, relayed through the private socket, and launched inside the
*same* namespace; Electron can therefore deliver `second-instance` to the
process that initiated sign-in. The URI appears only as the vendor process's
fixed argv inside its app sandbox, which is Electron's Linux deep-link
contract. Other apps cannot see the socket or temporary directory, and logout
removes both. No request field can supply a URL, remote, ref, digest, executable
or option. A user's own `~/.config/mimeapps.list` and administrator defaults in
the inherited XDG config directories continue to outrank the Punar fallback.

The call is allowed for a human-attributed peer on a personal device.
Agent-attributed calls are denied and audited. On an enrolled device, punard
evaluates the catalog id against the precedence-resolved SPEC section 46
application layers: `required` is installable, `denied` is refused, and an
optional app follows the winning `allowUserInstall` value. A managed document
without a usable application opinion fails closed rather than inheriting
personal install rules. Denials return the closed `details.reason` vocabulary
`required | denied | user_install_blocked | no_managed_policy` and cite the
winning `policy_ids`. Audit action is `system.install_package`, resource is the
catalog id, with `success`, `noop`, `denied`, `failure` or `verify_failed`.

### 5.15 `apps.remove`

Params: `{"id":"spotify"}`. Same human attribution and serialization as
install. On an enrolled device, removing an `applications.required` id is
denied with the winning policy named; every other user-installed app remains
removable, including an already-present denied app. A Flatpak application id is
resolved from the catalog and removal is fixed-argv/verified. A vendor package
removes only the catalog-owned payload and desktop entry; its per-user isolated
home is retained for explicit data deletion or reinstall. Audit action is
`system.remove_package`; web sources have no local package and return
`conflict` rather than pretending to remove browser data.

### 5.15a `apps.update`

Strict params are either `{"id":"spotify","all":false}` or `{"all":true}`.
Both selectors—or neither—are `invalid_params`. The caller cannot supply a
package name, URL, remote, ref, version, commit, digest, executable, or backend
option.

Only already-installed native catalog apps are eligible. For each one, punard
derives the exact target from the signed image catalog, reuses the same
fixed-argv verification and containment path as `apps.install`, verifies the
resulting identity, and records `system.update_package`. Already-current apps
are audited as `noop`; web services are excluded because their code updates in
the browser. `--all` enforces managed application policy independently for
every installed id and returns explicit `updated`, `current`, and `failed`
counts plus named failures, so a partial transaction is never presented as
fully successful. An AI-attributed peer cannot invoke the mutation.

### 5.15b `pim.mail.open`

Params: none. This is a closed first-party launch method, not a generic process
launcher. The caller cannot supply an executable, path, account, endpoint,
environment value, URL, command, or secret. `punard` forwards only the
kernel-attested caller uid and pid to a fixed root-owned broker.

The broker verifies that pid belongs to the same non-system uid, derives a
strict `wayland-N` socket only from `/run/user/<uid>`, verifies the socket peer
and the root-owned Hyprland executable, and then transfers exactly two unnamed
capabilities to the dormant Mail bridge: a profile-scoped read-only Mail
channel and the verified Wayland connection. Mail is not given a general PIM
control socket, settings methods, credential-entry channel, filesystem path,
or network namespace. Agent-attributed callers and unverifiable sessions are
denied before either capability is issued.

Result: `{"opening":true,"application":"mail"}` after the handoff succeeds.
The UI may still show a truthful empty, account-required, authentication, or
sync error state; it never substitutes fixture mail for a live failure.

### 5.15c `pim.mail.account_add`

Params: none. This opens the separate one-use Mail account-entry surface; it
does not widen the Mail application's read capability. The caller cannot
supply a provider, host, port, username, password, account id, path, command,
URL, executable, or environment value. `punard` forwards only the
kernel-attested caller uid and pid to the same fixed broker used by Mail.

After verifying the live desktop session, the broker requests an opaque setup
id over a temporary Settings capability, consumes the corresponding one-use
credential-entry endpoint from `punar-pimd`, and transfers exactly that
endpoint plus the verified Wayland connection to the locked
`punar-mail-account` identity. Provider configuration crosses only the
one-use endpoint. The password is a separate bounded frame and never appears
in JSON, argv, environment, ordinary Mail IPC, or logs. The entry service has
no network namespace, device access, or PIM state path; `punar-pimd` alone
performs TLS verification and the encrypted transactional commit. A failed
handoff cancels the setup id. Successful verification immediately queues one
bounded first INBOX sync.

Result: `{"opening":true,"application":"mail-account-setup"}` after the
protected handoff succeeds. The visible setup surface reports only the closed
outcomes `connected`, `invalid_credentials`, `provider_unreachable`,
`tls_validation_failed`, `invalid_configuration`,
`storage_encryption_required`, or `internal`; provider response text and
credential material are not representable.

### 5.15d `pim.mail.account_manage`

Params: none. This opens a separate locked account-management surface with a
Settings-scoped PIM channel and verified Wayland stream. Mail itself never
receives `accounts.remove`. The caller cannot select an account, command,
path, endpoint, provider, or secret in the launch request; selection and an
explicit destructive confirmation happen inside the protected window.

Removal always calls `accounts.remove` with `delete_local_data: true` and the
selected opaque account id from the service-provided list. `punar-pimd`
quiesces synchronization before deleting cached messages, provider
configuration, encrypted credentials, and public account metadata. It never
deletes remote provider data. The account manager runs under its own locked
identity with no network namespace, device access, or PIM state path and has
zero idle residency.

Result: `{"opening":true,"application":"mail-accounts"}` after the protected
handoff succeeds.

### 5.16 `update.status`

Params: none. Read-only and unaudited. This is the implemented first slice of
the governed-update contract in
`docs/development/update-and-rollback.md` §8.1. Authenticated discovery now
exists as `update.check`; the corresponding typed inactive-slot transaction
and local last-known-good selector are `update.apply` and `update.rollback`.

The result has `v: 1` plus the five system facts required by spec section 57
(current, desired, channel, health, rollback) and M11's browser provenance:

```json
{
  "v": 1,
  "image_id": "punar-desktop",
  "current": {"version":"2026.08.30.1","slot":"a","blessed":true,
              "snapshot_pin":"20260820T000000Z"},
  "desired": {"version":"2026.09.01.1","slot":"b","state":"staged"},
  "channel": {"name":"stable","source":"personal-preference",
              "policy_ids":["personal-defaults"],"metadata_age_seconds":7200,
              "rollout_bps":10000,"in_cohort":true,"halted":false,
              "reachable":true},
  "health": {"state":"pass","signals":{"boot":"pass","services":"pass",
             "session":"pass","capabilities":"pass"}},
  "rollback": {"state":"available","target_version":"2026.08.29.1",
               "target_slot":"a"},
  "browser": {"engine":"chromium","version":"151.0.7922.169-1",
              "channel":"snapshot","snapshot_pin":"20260820T000000Z",
              "pin_source":"running image"}
}
```

The example is a shape example, not fallback data. The daemon derives every
value from local release, kernel/firmware, durable pending, health, policy,
and package-database evidence. Missing or malformed evidence is represented
as `unknown`/`unavailable` with a `reason`; it never becomes a sample version,
an available update, or an “up to date” claim. Raw channel metadata is not
trusted by this read: only a successful `update.check` may create the verified
cached state that status reports.

### 5.17 `update.check`

Strict params:

```json
{"force":false}
```

or, from a person, `{"force":false,"ticket":"…"}`.

**Who may check, install or roll back** (this section, §5.17a and §5.17c;
decision: docs/development/update-and-rollback.md §7.3): root, or a person
who has just confirmed their password — the `enroll.start` shape. In order:

1. **No agent, at any uid** — the `host.system_update` boundary below,
   widened to any peer whose cgroup names an agent scope; a ticket the agent
   carried is left unspent. `details.rule: "host.system_update"`.
2. **A non-root peer must carry a ticket** — `denied`,
   `details.reason: "reauthentication_required"`, before anything is read or
   fetched; the message names the `punarctl update …` command that asks.
3. **The ticket is spent** before any update-source request and before any
   allow-shaped audit event — `details.reason: "reauthentication_missing"` /
   `"…_expired"` / `"…_malformed"` as in §5.9. Never forwarded, audited,
   stored or returned.

A person gets root's authority over updates and no more: the channel is still
the precedence-resolved `system.update_channel` an organization pins, and the
same halt, rollout, minimum-version and downgrade admission run after the
gate. `update.check` needs the ticket because it writes the root-owned
verified channel cache and contacts the update source; `update.status` needs
none.

Audited. The request may select only whether to bypass the
15-minute verified cache. The 15 minutes run on the boot clock (SMP-1405,
§14.4) from the moment the fetch that filled the cache **began**, and the
stamp is held in punard's memory, not read from the cache file's mtime:
after a punard restart, a suspend or a reboot the cache is not fresh, and
a non-forced check fetches again (offline, it then reports the source
unreachable rather than serving the cached answer). A caller cannot provide a URL, path, channel, key,
target identity, mirror, artifact, digest, executable, or option. The daemon
resolves the precedence-winning `system.update_channel`, running image id and
version, host architecture, boot platform, device cohort identity, fixed
repository location, and root-owned Ed25519 key set itself.

When root-owned `/etc/punar/update-repository.url` is present, the implemented
transport issues two fixed HTTPS GETs beneath
`<base>/<channel>/<architecture>/<boot-platform>/`: `channel.json` and its
detached raw 64-byte signature. The file must be a non-symlink regular file
owned by uid 0, not group/other writable, and readable by others (`0644`):
the unprivileged download helper, which runs as a dynamic user, reads it too,
and punard refuses a file the helper could not read rather than let every
download fail. Only one unambiguous `https://` base URL is accepted. Neither device identity nor current version appears in
the request path or query. A configured HTTPS source is authoritative: invalid
configuration or network failure never downgrades to removable media.

punard does not download anything itself: the two GETs, and every artifact
download after them, go through the unprivileged `punar-fetch` helper, and
the helper refuses any update URL that is not beneath this base (see
"Download helper" below).

When that configuration file is absent, the same transaction reads the
bounded pair from `/run/punar/update-source` for offline CI and recovery media.
Signature verification covers the exact document bytes in either case. The
signed image id, architecture, boot platform and channel must all match this
device before the document can influence selection or enter the cache. The
cache directory is `0700`, both cache files are `0600`, and document
publication is the last atomic, synced write. An absent source, invalid
signature, wrong target, incomplete local identity, or cache failure never
changes the running release and never admits unverified metadata.

Example result:

```json
{
  "v": 1,
  "channel": "stable",
  "current": "2026.08.20.1",
  "available": "2026.08.27.1",
  "in_cohort": true,
  "halted": false,
  "admissible": true,
  "reason": null,
  "metadata_age_seconds": 0,
  "cached": false
}
```

`available` names a newer signed channel head; `admissible` is the actual
selection decision after halt, minimum-version, and rollout-cohort checks. A
valid but halted, already-current, below-minimum, or out-of-cohort result is a
calm audited `noop` with a human-readable `reason`. An authenticated eligible
selection is audited `success`; authorization denial, unreachable source and
trust/cache failures are all audited distinctly. This method discovers and
caches a decision only. It does not download, stage, apply, reboot, bless, or
roll back a release.

#### Download helper

punard does not download anything itself, and it cannot: `punard.service`
makes `/usr/bin/curl` and `/usr/bin/wget` inaccessible in its mount
namespace, so an exec of either by punard or anything it starts fails. Each
transfer is its own `punar-fetch@.service` instance, started by
`punar-fetch.socket` (`Accept=yes`) when punard connects to the root-only
`SOCK_SEQPACKET` socket `/run/punar-fetch/request.sock`. The protocol and both
halves of it are in `crates/punard/src/fetch.rs`.

**What the helper can reach of punard: one pipe.** punard sends the request
(kind, URL, byte and time bound) with the write end of a pipe attached, and
reads the body from the read end into a private `0600` staging file in its own
`0700` cache. The helper never holds that file, so nothing it or its
downloader does, before or after it answers, can change the bytes punard then
verifies. punard bounds the byte count itself, reads to the end of the pipe
before it reads the helper's answer, refuses the transfer when the answer's
count differs from what arrived, and empties the file on any failure. When
punard stops reading, the helper's next write fails, so a stalled or oversized
transfer ends at once. The helper makes itself undumpable before it reads a
request, so a downloader taken over by a hostile server cannot trace it or
write its memory.

**What the helper can do.** It runs as a dynamic user with no capabilities, a
read-only file system without `/home` and with nothing of `/var` or `/run` but
a private tmp and the resolver's files, and IPv4 and IPv6 sockets only. The
kernel drops every packet it sends to a loopback address (the resolver stub
at 127.0.0.53 apart), to link-local and multicast addresses (and with them
the cloud metadata addresses 169.254.169.254 and, in the unique-local range,
fd00:ec2::254), and to the private, carrier-grade NAT, reserved, benchmarking
and documentation ranges. It reaches public addresses only. The rule is by
address, not by host: a public address this machine holds on its own
interface, such as a global IPv6 address, is reachable like any other public
address.

**What the helper will fetch.** It serves only uid 0 and only a request
carrying exactly one pipe, and it builds the downloader's argument list
itself: configuration files disabled, HTTPS only, TLS 1.2 minimum, no redirect
followed (a redirect fails the transfer), connect and overall time and
response bytes bounded. An update URL must lie beneath the channel base the
helper reads itself from `/etc/punar/update-repository.url`, through the same
function and ownership rules as punard; a vendor URL must lie beneath one of
the catalog's three fixed vendor origins. punard then verifies the bytes
exactly as before, so a compromised helper can at worst make a download fail.

**An organization's own network.** An update mirror on the local network, or
a proxy, is outside the public address space the helper may reach, so it is
allowed explicitly and by address, with a drop-in for the helper:

```ini
# /etc/systemd/system/punar-fetch@.service.d/50-organization.conf
[Service]
IPAddressAllow=10.1.2.3
```

The helper uses a proxy root has configured in its environment
(`https_proxy`/`HTTPS_PROXY` and `no_proxy`/`NO_PROXY`, for example through the
service manager's `DefaultEnvironment=`), validated, and passes the downloader
those two variables and nothing else of its environment. A proxy value that
is set but invalid refuses every transfer rather than letting one go direct.
When a configured proxy cannot be reached, the error names the drop-in above.
Release images ship no such drop-in, and release gate A19 refuses one. Like
`/etc/punar/update-repository.url` itself, the drop-in and the environment
live in the slot's `/etc`, and a new slot boots the vendor's `/etc`
(ADR-003): until a capability produces them, which is not built yet, an
organization applies them again after each update.

**Not done yet.** The per-origin kernel pin the design calls for (egress to
the channel's own addresses only, through netd's per-cgroup rules) is not
built: netd's rules are CIDR zones bound to agent sessions and need the cgroup
to exist when the rule loads, and a socket-activated instance's cgroup does
not until the request arrives. Until then the origin rule above is enforced by
the helper on the URL, and the kernel rule is "public addresses only". A
helper taken over through its downloader could therefore still connect to
other public addresses, including a host on the local network that has one
(a global IPv6 address, typically); it holds no secret and can write only the
pipe.

### 5.17a `update.apply`

Strict params:

```json
{"version":"2026.08.27.1","allow_downgrade":false}
```

plus `"ticket"` from a person. Root, or a person with a fresh confirmation
(§5.17), and audited. Agent attribution is evaluated before uid, so a
process inside a `punar-agent-*.scope` is denied even when its peer uid is 0.
That denial names `host.system_update`; this is a non-overridable OS hard-safety
boundary. The caller cannot supply a channel, URL, path, key, slot, artifact,
digest, executable, command, or boot selector.

The daemon re-authenticates the exact signed channel head and release manifest,
admits the requested canonical version against the effective channel and local
cohort, and downloads only the independently signed artifact pair for the
inactive slot. UEFI releases contain distinct A- and B-bound root/UKI pairs.
The running kernel command line chooses the active fixed PARTUUID; the opposite
fixed PARTUUID chooses the destination. Punar verifies compressed and UKI
digests, verifies the UKI `.cmdline` binds exactly that destination, streams the
root image, fsyncs it, physically re-reads and hashes it, retains the blessed
old UKI, installs the new boot-counted UKI last, and durably selects it. On a
freshly installed device the first apply also retires the factory B-bound
`punar-recovery_<version>.efi` before it opens root B, proving the retirement
across an ESP read-only re-open; while slot A is still boot-counted that
retirement, and therefore the apply, is refused as `conflict`.

Every refusal that needs no write comes first, read-only, before any boot
entry is retired: a refused apply never costs the device its recovery floor
or its rollback target. In order:

- **Last-known-good.** The running slot must keep an entry to come back to:
  its blessed Punar UKI, or the factory recovery entry when the device was
  started from recovery by hand.
- **No reinstall of the running release.** Reinstalling the version the
  running slot holds is refused. Its entry could never be blessed under a
  name the running entry already has.
- **Not the next boot's slot.** An apply is refused when the next boot is
  aimed at the inactive slot (a `rollback` to it without a restart). This
  applies only while the running slot has a blessed release to go back to,
  and entries with no tries left do not count. A device running from
  recovery is repairing the slot its preferred entry points at.
- **Room.** ESP room, the destination's presence as a block device, and its
  size.

Only then is every Punar UKI bound to the inactive slot, counted or not,
removed, and the removal proven across a read-only re-open. After that, a
UKI on the ESP names the release its slot holds, and the ESP keeps exactly
the running release plus the candidate. A staged update that has since
booted and been blessed (running from its slot, with its uncounted UKI
present) is settled rather than treated as still staged. On Raspberry Pi, the equivalent
signed A/B transaction stages the inactive root and firmware set for one-shot
`tryboot`.

```json
{"v":1,"staged_version":"2026.08.27.1","staged_slot":"b",
 "requires_reboot":true,"bytes_written":2147614720,"verified":true}
```

On Raspberry Pi the result adds `"one_shot_trial": true`: the staging has
armed the firmware's one-shot `tryboot` by writing `0 tryboot` to
`/run/systemd/reboot-param` as root, so the next *restart* tries the
candidate, and a shutdown discards it (docs/development/update-and-rollback.md
§7.1). If that write fails, the staging withdraws its pending record and
fails. The daemon never reboots. `punarctl update apply … --reboot` performs
a fixed caller-side `systemctl reboot` only after this successful result, on
both platforms.

### 5.17b `update.reconcile_candidate`

Params: none. This internal native-Pi boot-service method accepts no slot,
path, digest, version or health value. It is root-only — not a person's verb;
`punar-update-health.service` calls it at boot — and an agent-attributed
peer is denied even when uid 0. The daemon binds the durable pending record to
firmware's read-only boot observation and the fixed selector layout, then
returns one of three explicit outcomes:

- `blessed_candidate`: a one-shot candidate passed every health signal; its
  exact signed root and boot byte ranges were re-read with `O_DIRECT`, its
  boot filesystem semantics and mounted read-only root `IMAGE_VERSION` matched,
  and the selector was durably committed;
- `firmware_fallback`: firmware returned to the recorded previous slot while
  the selector remained uncommitted; no selector byte is changed and no
  candidate health claim is made;
- `postcommit_recovery`: the committed selector and exact previous-selector
  backup survived an audit/power-loss window; the running candidate is fully
  revalidated before finalization.

The engine never removes pending state. The handler first appends and
`fdatasync`s an outcome-specific audit event whose resource binds release id,
version and signed-manifest digest, and only then removes the exact pending
record it reconciled and syncs its parent directory. An audit failure retains
pending state; retry is idempotent. `requires_normal_reboot` is true only for
a still-running one-shot candidate, so firmware fallback and an ordinary
post-commit recovery do not bounce the device unnecessarily. `firmware_fallback`
is a boot observation: an ordinary boot of the previous slot with an
uncommitted selector is finalized that way even when the staged candidate was
never rebooted into (`update.apply` without `--reboot`, then a shutdown),
and the device then needs a fresh `update.apply`. It is never recorded in the
boot that staged the candidate: staging leaves `/run/punard/pi-update-staged`
beside the armed tryboot request, written before it, so a crash between the
two leaves the marker and no request. While that marker exists, the same three
facts mean "not restarted into yet", and the method refuses as `conflict`
(`update-health.sh` exits early). Whenever a pending record is finalized, or
withdrawn without a reboot, the engine clears its own tryboot request and
the marker, so an armed tryboot never outlives its record.

```json
{"release_id":"punar-desktop-stable-aarch64-raspberry_pi-2026.09.04.1",
 "version":"2026.09.04.1","manifest_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
 "pending_state_sha256":"1111111111111111111111111111111111111111111111111111111111111111",
 "outcome":"firmware_fallback","candidate_slot":"b","previous_slot":"a",
 "selector_committed":false,"requires_normal_reboot":false}
```

### 5.17c `update.rollback`

Strict params:

```json
{"to_version":null}
```

`null` selects the newest previous locally retained blessed release; a
canonical version selects that exact retained release; a person adds
`"ticket"`. The authorization and audit boundary is identical to
`update.apply`. No repository is contacted and
no caller-controlled selector is accepted. On UEFI, only uncounted Punar UKIs
are rollback candidates; counted, unblessed attempts are excluded. A target is
accepted only when this device knows its slot holds it:

- **On the running slot**, only the entry for the release the running root
  reports (`IMAGE_VERSION`), however many stale entries an older build left
  there.
- **On the other slot**, only when it is the one entry, counted or not, the
  ESP names for that slot.

Otherwise the rollback is refused as `conflict` rather than boot one
release's kernel on another's root. A plain rollback takes the newest valid
target and skips ambiguous ones, so a device an older build left in that
state can always return to the release it is running.

A device started from recovery by hand runs from the factory recovery entry,
not a `punar_` one. When no `punar_` target is valid, that entry is the
running release's own target, provided it is bound to the running slot and
names the running release. Selecting it (`preferred
punar-recovery_<version>*.efi`) cancels an update staged from recovery, or
leaves one that failed its tries, and clears the pending record. On
Raspberry Pi, the current and previous selectors are validated before a
durable selector swap. A pending Pi trial must first resolve rather than being
silently overwritten.

```json
{"v":1,"previous_default":"punar_2026.08.27.1*.efi",
 "new_default":"punar_2026.08.20.1*.efi","requires_reboot":true}
```

The CLI's optional `--reboot` remains a caller-side fixed restart. Failures
leave an unverified release unselected and return the section-4 typed error
that identifies the failed stage.

### 5.18 `install.targets`

Params: none. Read-only and not audited. This method exists only when the
daemon read the exact `punar.live=1` token from `/proc/cmdline`; an installed
system returns `unknown_method` with `details.mode: "installed"`.

The result enumerates physical candidate disks from `/sys/class/block`, with
model, serial, WWN when present, byte size, logical-sector size, partition
table and observed partitions/filesystems. A disk below the real 33 GiB plus
GPT/alignment floor remains visible with `eligible: false` and the full
17 GiB OS + 16 GiB data-floor arithmetic. The following never appear:

- any disk or partition backing a current mount (the live boot medium);
- any disk carrying a filesystem labelled `PUNAR_ANSWR`;
- loop, ram, zram, device-mapper, md, optical and floppy pseudo targets.

The implementation is discovery only. It opens no target device for writing.

### 5.19 `install.plan`

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
5. returns the platform's fixed partitions (four on UEFI, six on Raspberry
   Pi), byte offsets/sizes, filesystems, encryption decision, data
   subvolumes, the signed compressed-artifact digest/size, the signed
   uncompressed-slot digest/size, and the signed boot artifact kind,
   filename, digest and size. On UEFI it also returns the signed slot-B
   `recovery_payload` and `recovery_boot_artifact` identities. Every one of
   these fields is part of the canonical JSON behind `plan_token`, so a
   B-only manifest substitution changes the token before destructive work.
6. walks PCI, USB and ARM platform devices, resolves each modalias against the
   running kernel's bounded `modules.alias`, checks the bound driver and its
   fixed-argv `modinfo` firmware requirements, and returns a privacy-minimized
   `hardware_report` conforming to
   `schemas/install/hardware-report.json`. No serial number, MAC address or
   user data exists in that object. No usable bound graphics driver is an
   install refusal; partial or unsupported non-graphics devices become a
   visible plan warning rather than a fabricated support claim.

The response validates against `schemas/install/plan.json`. `plan_token` is
SHA-256 over compact, recursively key-sorted JSON of the nested `plan` object
(the `jq -cS` JSON bytes, excluding jq's trailing newline). A change to either
GPT edge or any plan field changes
the token. The detailed `hardware_report` is deliberately adjacent evidence,
not an input to a disk-erasure authorization; its partial/unsupported summary
is copied into `plan.warnings` and therefore is token-bound. The seed phase
observes hardware again, writes that fresh report to
`/var/lib/punar/hardware-report.json`, and verifies its exact durable digest
after a read-only reopen. The apply preflight keeps a bounded token registry
for this daemon boot and re-reads the serial, WWN, size,
logical-sector size, both GPT edges and signed release. Only an exact match may
reach the executor, and failed revalidation cannot silently register a
new token. Its strict parameter type carries descriptor numbers for the
passphrase and optional OOBE passthrough, never their bytes. Each input must
be an anonymous memfd sealed against writes, growth and shrinkage; a normal
file is refused, so the descriptor mechanism cannot quietly persist a secret
to disk. The daemon rewinds the duplicated open description before applying
its 4 KiB passphrase or 1 MiB OOBE bound. Personal recovery additionally
requires `recovery_output_fd`, which must be a pipe or Unix socket; the full
key and two challenge indices travel only there. The paired acknowledgement
type is `{plan_token, groups_fd}`, where `groups_fd` is another sealed memfd,
so even the two challenged key groups stay out of IPC JSON. The in-memory gate
has no timeout/default-continue and consumes a confirmation only for the exact
plan token.

### 5.20 `install.apply` and `install.recovery_ack`

`install.apply` is root-only and live-only. Its attended lane is human-only;
its unattended lane additionally requires an independently signed,
short-lived, exact-plan authorization. Agent attribution is
checked before uid, descriptor duplication, release reads or disk access, so
uid 0 inside `punar-agent-*.scope` is denied with `disk_changed: false`. One
atomic guard admits one transaction per live boot while separate connections
remain available for status and recovery acknowledgement.

The strict apply object is:

```json
{"plan_token":"<64 lowercase hex>","disk":"/dev/vda",
 "passphrase_fd":3,"recovery_output_fd":4,"keymap":"us",
 "seed":{"locale":"C.UTF-8"},"oobe_answers_fd":5,"unattended":false}
```

Optional descriptors are omitted, not set to null. Punar validates the cached
plan and freshly re-observed physical disk, then consumes the sealed memfds and
starts the fixed transaction: verify release → partition/encrypt/format →
write slot A → direct re-read → install the platform-bound boot artifact →
seed → read-only final verification. There is no caller-selected path, argv,
partition option or executable field.

The unattended object omits `passphrase_fd` and adds
`unattended_answers_fd` plus `unattended_signature_fd`. Both are sealed
anonymous memfds populated from `answers.json` and `answers.json.sig` on the
fixed-label `PUNAR_ANSWR` filesystem. The daemon verifies the detached
Ed25519 signature over the exact bytes before parsing, then binds the
authorization to its one-day maximum lifetime, plan token, target serial,
destructive-confirmation serial, release id, exact release-manifest digest,
keymap, locale and optional OOBE digest. The trusted answer-signing keys are a
separate root under `/usr/share/punar/install-answer-keys`; release keys do not
authorize unattended disk erasure. The schema is
`schemas/install/answers.json` and structurally forbids passphrases and
recovery keys.

For personal recovery, `recovery_output_fd` receives exactly three newline-
terminated records: the literal `PUNAR-RECOVERY-V1`, the eight-group recovery
key, and two one-based challenge indices separated by one space. The original
apply call then blocks. A second root-human connection sends
`install.recovery_ack` with `{plan_token, groups_fd}`; `groups_fd` is a sealed
memfd containing exactly the two challenged groups separated by ASCII
whitespace. Success returns `{"acknowledged":true}`. No timeout or
default-continue exists.

For organization escrow, apply requires the live environment's persisted
enrollment organization and redacted device credential, wraps the generated
key locally, uploads ciphertext only, and does not cross `encrypt` until the
exact signed receipt verifies. An unavailable control plane is retried at a
quiet fixed cadence while status remains awaiting; a signature or binding
failure stops rather than retrying a trust violation. `unattended:true` is
admitted only with those two signed-answer descriptors and only for LUKS2 plus
`personal_copy`. `punard` generates the 256-bit disk passphrase. The private
recovery channel then carries four newline-terminated records:
`PUNAR-UNATTENDED-CUSTODY-V1`, the generated passphrase, the recovery key and
the two challenge indices. The provisioner atomically writes `custody.json`
to the removable answer filesystem, fsyncs, reopens and compares the exact
bytes, and only then sends the ordinary sealed-memory recovery
acknowledgement. Existing custody is never overwritten and no custody secret
is copied to the installed system. Its strict output contract is
`schemas/install/custody.json`; unlike `answers.json`, this record is secret
material and is never an input accepted by `punard`.

On success, the result is the terminal `install.status` object. Failures carry
`disk_changed`; active failures atomically publish a secret-free terminal
status and cancel any recovery gate. The installed audit is written and
byte-verified before success. There is no `install.exec`, script, hook or
caller-supplied command/path.

### 5.21 `install.status`

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
  `O_APPEND`, created **`0640 root:punar-audit`**; directory
  **`0750 root:punar-audit`** via tmpfiles (F0-S3). The four writers —
  `punard`, `punar-agentd`, `punar-secrets`, `punar-netd` — each create the
  live file, its rotation (`.1`) and its lock in that group
  (`AuditWriter::open_in_group`), and tmpfiles re-owns all three on every
  boot, so an upgrade closes the old path. **`punar-audit` has no person in
  it** (release gate A23): the trail used to be group `punar`, which is every
  account, so every person could read every person's events. Reads for
  humans go through `punarctl audit tail`, which the daemon scopes to the
  caller (§5.5).
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
  **Compliance changes:** `reconcile.compliance` (resource = capability id,
  `result` = the new SPEC section 52 state, `policy_ids` = the policy that
  decided it), when a capability's state differs from the one this event
  last recorded for it (a capability never recorded reads as `compliant`).
  What was last recorded is kept in `/var/lib/punar/compliance-audited.json`,
  written only when an event is, so a recovery is recorded however it came
  (a manual set that settles the capability, a restart that finds it
  healed), and a restart does not record a state again. It records the drift nothing remediates (alert-only, awaiting
  approval, a value only the image can change), which no remediation event
  names; with the per-pass `reconcile` event and the remediation events it
  is why the reconcile timer's own output can be quiet (`punarctl reconcile
  --quiet`: one journal line when a pass remediated or failed to, nothing
  otherwise).
  Both action names match the schema's dotted-lowercase `action` pattern —
  no schema change. The `policy.*` READS (`policy.effective`,
  `policy.explain`) remain unaudited; `policy.set` (section 5.8a) is a
  mutation and is always audited, allow and deny, under
  `action: "policy.set"` with the capability as the resource.
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
  Read methods (`enroll.status`) remain unaudited. `enroll.inventory`
  (resource `"control_plane"`) follows the same transition rule: `result:
  "applications_withheld"` once when the inventory's application list starts
  going out as `null` (over its row or size cap, or unreadable — never
  truncated), `"success"` once when a full list goes out again.
- **Live policy refresh:** `enroll.policy` (resource `"control_plane"`,
  decision `allow`, the pass's actor) — not an IPC method, like
  `enroll.sync` and `enroll.inventory` (`policy.*` names this socket's own
  methods, and there is no `policy.refresh`). `result` is the refresh
  outcome of section 5.10, emitted only when it is news: `applied` and
  `withdrawn` on every commit (`policy_ids`: the ids now enforced, or, for
  `withdrawn`, the ids taken away); `rejected` once per distinct refused
  set; `held`, `unreachable`, `refused` and `failed` when the result or its
  reason changes; `unchanged` only as the recovery from one of those. Every
  event but a commit cites the ids still enforced — never ids from a set
  that was refused, which are the control plane's untrusted strings. An
  empty list becomes `personal-defaults`, as for the other enrollment
  events. The reason is in `enroll.status`, not here: the audit schema has
  no free-text field, and none is added. A commit's `event_id` is fixed
  before the swap and kept with the pending change, so a change that landed
  before a crash is audited exactly once: by the refresh, or at the next
  start (actor `daemon`) when the log does not hold it yet.
- **The built-in agent:** `enroll.agent` (resource `agent.<reason>`, decision
  `allow`, the pass's actor) — not an IPC method, like `enroll.sync`. While
  enrolled, every pass first makes the liveness call `identity.status`, and
  an agent that cannot be used starts an episode of management interrupted:
  one event with `result: "agent_unavailable"` when it starts, one with
  `result: "success"` when it ends, never one per pass; the episode is kept in
  `enrollment.json`, so a restart neither repeats nor loses it. The reason is
  the resource's suffix, since the schema has no free-text field:
  `socket_missing` (no socket at the path: masked and stopped),
  `connection_refused` (nobody listens: the socket unit stopped or failed),
  `permission_denied`, `connect_failed`, `connection_reset` (the connection
  broke mid-call), `closed_without_answer` (killed mid-call),
  `not_answering` (no answer to a call it answers without the network, in
  the liveness call's 10 s: frozen, or unable to start), `identity_missing`
  (it holds no identity while this device is enrolled), `identity_mismatch`
  (not this device's), `identity_unreadable`, `unexpected_answer` (an answer
  the agent never gives: something else answers on its socket),
  `token_missing` (punard's own device token is gone, so this device cannot
  be asked about or reported on at all), `unexpected_listener` (the socket at
  the agent's path is not the agent's: its listener's credentials do not name
  PID 1, or its address is not the agent's path because a symlink or a bind
  mount led the connection elsewhere, both checked on every connection before
  anything is sent; or another socket unit listens at the agent's path, which
  only systemd's list of socket units shows), `unit_modified` (a unit
  management depends on — the agent's socket and service, `punard.service`,
  `punard-reconcile.timer` and `.service` — is not as the image ships it:
  masked, a fragment or drop-in outside `/usr/lib/systemd/system`, the socket
  listening elsewhere, or the agent's process not `/usr/bin/punar-smplifyd`;
  checked with `systemctl show` on every pass while enrolled, and before
  `enroll.start` sends anything), and `units_unreadable` (systemd could not
  be asked about those units, or its answer could not be read: the check
  fails closed, and `enroll.start` refuses as it does for the others). A
  socket that is gone or no longer listened on is started again
  (`systemctl start --no-block punar-smplifyd.socket`). An override of the
  control-plane socket (`PUNAR_CONTROL_PLANE_SOCKET`,
  `--control-plane-socket`) on an image that ships no development control
  plane is refused, and audited once per start as `enroll.agent` `denied`
  (resource `agent.control_plane_override`). The liveness call fails closed: the
  one answer that means the agent is there is `enrolled: true` with
  `token_matches: true`, and only a call that was not sent (it did not fit
  the pass's budget) leaves the state as it was. None of these is the
  network: the agent is on this device and answers an outage itself, inside
  its budget. So an episode is never also an `enroll.sync` outage, and a
  policy fetch the agent's socket failed is not an `enroll.policy`
  `unreachable`: the network was not asked, and the episode is the record. `enroll.release` (resource
  `agent.<reason>` or `agent`): `pending` when a wipe punard's release
  record asks for is not confirmed, again only when the reason changes,
  `success` once when it is, and `kept` once when punard finds a device
  token with no enrollment and no record and keeps the identity rather than
  wipe it (resource `agent.enrollment_record_missing` or
  `agent.release_record_unreadable`; section 5.11). An episode still open when
  the enrollment ends is closed with `enroll.agent` `ended`, so every episode
  has both ends.
- **Reconcile passes:** `enroll.gap` (resource `reconcile`, result
  `interrupted`) when the passes of an enrolled device were further apart
  than three periods of `punard-reconcile.timer` and a minute (420 s) on the
  boot's monotonic clock, which does not count suspended time: what a
  stopped timer or punard leaves. Audited once, when passes resume: on the
  same boot, or, when the gap ended in a clean stop, at the next boot's first
  pass. The last pass and a clean stop are kept in `enrollment.json`, which
  every pass already writes.
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
  authorization point. No person on a Punar device is root, so a person's
  mutating verbs carry a grant (`punarctl privilege request`) or a password
  confirmation relayed to `punar-authd` (`policy set`, `enroll start`,
  `enroll stop`, `update check`, `update apply`, `update rollback`).
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
- **M5 verbs:** `punarctl enroll start <domain> [--code-stdin]
  [--accept-non-removable] [--accept-organization-owned]` (over 5.9; asks
  for the code, then the person's password; for an organization that sets
  enrollment terms — not removable, owned by the organization — it shows
  every term the refusal named, with what each means, in one prompt and
  asks for one `accept` on the terminal, then the password again, and
  without a terminal the refusal names the flags; renders org, policy ids,
  who can unenroll, who owns the device, and `Attestation  SIMULATED` — the
  honesty label is loud by design; 90 s client timeout per section 2),
  `punarctl enroll status` (over 5.10; the same who-can-unenroll and
  ownership rows), `punarctl enroll stop` (over 5.11; asks for the password
  only for a removable enrollment; "Personal state restored · org layers
  removed"). `punarctl status` adds an
  `Organization  <display name> · <policy id>` row while enrolled (absent
  otherwise — org rows never render on a personal device). The 5.4 M5
  amendments: the overridden-set verdict line and the org-citing denial.
  Rendering contract: docs/development/milestone-5.md section 8.3.
- **Status live rows:** the human `punarctl status` adds a `RIGHT NOW`
  stanza: `Firewall` (`capabilities.get` security.firewall), `AI sessions`
  (`agents.list`), `Unknown AI` (`alerts.list`, live cards only),
  `Approvals` (`approvals.list`, pending only), `Privilege`
  (`privilege.status`) and `Updates` (`update.status`). Each row is its own
  call. A daemon that does not answer turns only its rows to `UNKNOWN`,
  with the first line of its error. `punarctl status --all --json` prints
  one document, `{status, firewall, agents, alerts, approvals, privilege,
  update, errors}`, where each key holds that method's result verbatim, or
  null with `{code, message}` under `errors` (`code` is the daemon's error
  code, or `unreachable` / `protocol` for a failure on this side). Plain
  `status --json` is still the `status` result alone.
- **`punarctl approvals watch [--answer]`:** follows every approval. Each one
  prints when it arrives and again when it settles; with `--json`, that is
  one `approvals.get` result per line. Approvals already settled when the
  watch starts are history and do not print. It wakes the way `approvals
  wait` does (an inotify watch on `/run/punard/`, section 15) and also at
  the earliest pending `expires_at`, because `approvals.list` settles a
  lapsed approval when it is read. The truth is always `approvals.list`
  plus one `approvals.get` per change. `--answer` shows each new approval
  routed to the invoking person on `/dev/tty` and reads approve / deny /
  leave it from there. Standard input is never read as an answer. Without
  a terminal it refuses with exit 2, and inside an agent scope with exit 3.
  A decision goes to `approvals.resolve`, which stays human-only
  (section 14.5); its refusal prints and the watch continues.
- **Browser-context bindings (client-side, no new method):** `punarctl
  web-apps context bind <id> --workspace <name> [--activate]` and `context
  unbind --workspace <name>` edit the bindings in the user's
  `browser-context.json` (milestone-11.md section 5.5). The context must be
  one `webapps.list` returns, and the name must pass the workspace grammar
  before anything is asked. System Control's picker runs `bind` (or `use`
  on an unnamed workspace) instead of writing the file. `context status`
  prints every binding.
- **`punarctl device` and `punarctl device posture`** (over 5.1a): `device`
  shows identity and class (from `status`, a second read that is left out
  if it fails), then hardware and power. `device posture` shows
  Encryption, Secure Boot, TPM, Virtual (the SPEC section 1.22 label),
  Firewall and Updates, and an unknown answer stays unknown. `--json` is
  the `device.posture` result verbatim for both verbs. System Control's
  Encryption, Secure Boot and Power panes read `punarctl device posture
  --json` and nothing else.
- **Session verbs (client-side, no punard method):** these act on the
  person's own session, as their own uid.
  - `punarctl workspace list|focus <id|name>|rename <id> [name]|new
    <name>`: `new` is the command center's "Open <name>". It takes the
    first id no live or stored workspace holds, then names it.
  - `punarctl layout <preset>|status`: this runs
    `/usr/lib/punar/punar-layout.sh`, the presets' one implementation.
  - `punarctl window list|active|focus --class|--address|close
    [--address]|kill --address`: kill always needs an exact address.
  - `punarctl display list`.
  - How they reach Hyprland: over its own request socket
    (`$XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket.sock`),
    sending the Lua dispatcher expressions HyprlandActions.qml used to send.
    Every value is quoted as a Lua string literal. `--json` prints
    Hyprland's own answer.
  - `punarctl session lock|end|restart|shutdown`: these run `loginctl
    lock-session`, the compositor's `exit`, and `systemctl reboot|poweroff`,
    so polkit still decides.
  - `punarctl audio status|volume ±N%|N%|mute [on|off|toggle]`: this runs
    `wpctl`, capped at 100% like the volume keys.
  - Exit codes: 5 with no compositor or PipeWire, 3 when polkit refuses, 2
    for a bad name, address or volume.
  - The GUI runs these same verbs: the overview, the command center, the
    workspace store, WindowActions, SessionMenu and System Control's Power
    actions.
- **`punarctl notifications list|dismiss <id>|clear|action <id>
  <key>|dnd on|off|status`** (client-side, over the shell's own IPC): these
  run `qs -p /usr/share/punar/shell ipc call notifications …`.
  - `list` returns the records newest first, read through the notification
    daemon's sanitising accessors, so a terminal sees exactly the words the
    centre draws. Sender text is also printed through the terminal-safe
    filter.
  - Each record is `{id, source, summary, detail, urgency, sticky,
    arrived_at, actions: [{key, label}]}`, plus `dnd`.
  - The shell is the notification server, so the centre keeps its direct
    binding.
  - Exit codes: 5 when the shell is not running, 2 for an id that is not
    the daemon's number.
- **`punarctl theme list|show|validate|set|reset|status|render` and
  `punarctl wallpaper list|set|reset|status`** (client-side,
  theme-system.md §4.5).
  - The theme gate is a port of the shell's ThemeContrast.qml (R1-R9, the
    24 pairs, the §7.1 terminal derivation), held to every figure
    theme-system.md publishes.
  - `theme set` writes the §3.3 pointer (0600, with the complete receipt),
    then calls `ipc call theme reload`.
  - A refusal exits 6, deliberately not 3.
  - Wallpapers are the shell's compiled catalog, asked over `ipc call
    wallpaper`. Exit 5 when the shell is not running.
- **The parity gate:** `tests/desktop/terminal-parity-gate-test.sh` runs in
  CI and reads the shell's source.
  - Every process the shell starts must be `punarctl`, a fixed helper
    scoped to the files that may run it and given its reason, or a
    documented funnel whose callers pass literal punarctl argv.
  - Every System Control view must name its verb in
    `tests/desktop/system-control-verbs.json`, and punarctl's unit tests
    prove each verb parses.
  - A new direct tool call fails the gate until it is routed through
    punarctl or earns an entry with a reason.
- **App parity (client-side, no new method):** `punarctl app list` joins
  `apps.catalog {}` for category, trust tier and catalog version, and its
  `--json` is still `apps.list` verbatim. `app list --all` adds every
  visible desktop entry and marks the ones the launcher hides, with the
  reason from `/usr/share/punar/catalog/launcher-hidden-entries.json`, the
  file Apps.qml reads. `--all --json` prints `{apps: [{id, name, source,
  terminal, hidden_in_launcher, hidden_why?}], launcher_hidden_list}`. `app open <catalog-id|desktop-id>` falls back to the
  desktop index when `apps.catalog` answers `not_found`, or when punard is
  unreachable. It raises an open window first, as the launcher does
  (third-party-apps.md section 2.1).
- `punarctl debug rpc <method>` (hidden) sends an empty-params request with an
  arbitrary method name — exists solely so the 74.4 "unauthorized IPC" /
  section 60 negative tests can probe the server from inside the image. The
  server's method table is the enforcement point; this flag adds no server
  capability.

## 8. Explicit non-goals of this contract (M3, amended M4/M5)

- No generic execution method of any kind (spec sections 10, 60) — permanent.
  There is also **no generic write-side `policy.*` method**, and that
  wording is the whole of the promise: the policy mutations are
  `capabilities.set` (user preference), the enrollment-managed `policy.d`
  drop since M5 (`enroll.start`/`enroll.stop`, and the refresh a
  `reconcile` runs while enrolled — which write only whole fetched sets,
  never accept policy content as params), and
  `policy.set` (section 5.8a), which takes **one registered capability and
  one value that capability validates** and can express nothing else. A
  method that accepted a path expression, a document or a merge patch would
  be the root RPC this line forbids; a typed setter over a closed registry
  is not, and the daemon test `no_generic_write_side_policy_method_exists`
  probes both halves.
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
   "device_class_source": "observed", "architecture": "aarch64",
   "management": "active", "identity_release": null,
   "ts": "2026-08-26T09:02:00Z"}
  ```

  (`org_name` and `management` are `null` and `enrolled` is `false` on a
  personal device.) `management` is `"interrupted"` while the built-in agent
  cannot be used (section 6, `enroll.agent`); the reason is in
  `enroll.status`, not here. Consumers read anything else as `"active"`.
  `identity_release` is `null` while enrolled; on a device with no
  enrollment it is `"pending"` while a Smplify identity is still to be wiped
  and `"kept"` while punard keeps one nothing ended the enrollment of
  (section 5.11), and `null` otherwise; consumers read anything else as
  `null`.
  No raw hardware facts, per-capability rows, policy ids, device id, or
  hostname: the file is world-readable and carries
  only what the shell renders or uses for its resident-cost decision. A
  missing/unknown class fails to `appliance`, the least-resident experience;
  it never changes a security or privacy guarantee.
- `architecture` is the device's package architecture as the application
  catalogue spells it (`x86_64`, `aarch64`). It is here because the catalogue
  file the shell reads is **identical on every architecture** — each app lists
  its own per-architecture sources — so without it the shell offered
  applications that exist only for another CPU and the refusal arrived after
  the person had chosen one. Consumers fail **open** on a missing value: not
  yet known means show everything, and punard's own refusal is the backstop.
  This is display data like the rest of the file and is never an authorization
  input; `apps.install` re-derives the architecture itself.
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
    "enforcement": "enforced (agent scope)"}
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

### 10.3 Authority carries its current enforcement state

The `authority` object is what the launcher showed the user (spec
section 27 step 10): manifest-declared decisions with their current
enforcement labels, plus `policy_citation` — `"personal-defaults"` on an
unenrolled device, the org policy id (hero demo: `"eng-ai-v3"`) while
enrolled, sourced from `/run/punar/status.json` (section 9). Managed
host-agent network rows say `enforced (agent scope)`; project containers
remain `--network none` and therefore deny-only. No surface may erase
that boundary (spec section 1.22). The object is stored in memory and
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
      "network_destinations": ["127.0.0.9"],
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
       "evidence": "cgroup_scope"},
      {"category": "network_destinations", "resource_class": "127.0.0.9", "count": 1,
       "first_seen": "2026-08-27T09:59:00Z", "last_seen": "2026-08-27T10:00:02Z",
       "evidence": "netd_aggregate"}
    ]
  },
  "not_yet_observed": [
    {"level": 3, "category": "mcp_servers", "milestone": "M11+",
     "reason": "no tool or MCP gateway mediates MCP traffic yet (spec section 26)"}
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
  `audit_event`, `workspace_bind`, `adapter_metadata`, `detection_scan`,
  and `netd_aggregate` — the mediation point that proved the entry. The M10
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
- **`not_yet_observed` moves between milestones, in both directions.**
  A row leaves when its
  producer ships (`credential_classes`, `credential_request` and
  `policy_bypass_attempt` left in M9; `unknown_ai_execution` left in
  M10 — §17.6), and a row is re-milestoned when the honest date moves
  (`mcp_servers` M9+ → M11+). M12 removes
  `network_destinations`, `production_access`, and
  `sensitive_resource_access` because their mediation points now exist.
  **Since M10 the list is also
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

### 13.2 `/run/punar-agentd/ledger.json` (the device-wide side file)

Not IPC — the ledger's sibling of section 11's `agents.json`, written
atomically by `punar-agentd` at the same points.

- **`0640 root:punar-audit`, inside the root-owned `/run/punar-agentd`
  directory** (F0 amendment). It holds **every** person's sessions, and a
  ledger is personal data, so no person may read it: `punar-audit` has no
  human member (§6). It was `0640 root:punar` — readable by every account —
  so on a shared device each person could read each person's agent ledger.
  Because the directory is root-owned, a local user cannot unlink the file
  and substitute a forgery.
- **The AI panel no longer reads it.** It runs `punarctl agents access
  <session> --json` — `agents.access`, owner or root (§12.2) — on the
  person's own action, and renders the answer: a per-person view through the
  same command a terminal runs.
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
| `approvals.list` | any connected peer; **a person sees the approvals routed to them, and a `withheld` count** (root sees all; F0 review, §23.2) | no (lazy expiry sweep) | no |
| `approvals.get` | any connected peer; **an approval routed to someone else answers `not_found`**, as one that does not exist (root reads all) | no (lazy expiry sweep) | no |
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
  "execution": null,
  "lifetime": {"start": {"boot_id": "0f2a6c1e-7d3b-4a59-9c8e-1b2d3e4f5a6b",
                         "raw_bt_ms": 5123456, "sleep_ms": 0,
                         "suspends": 0},
               "duration_ms": 300000}
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
- **`lifetime`** (additive, SMP-1405) is what decides expiry: the TTL as a
  window on the **boot clock**, `{"start": {"boot_id", "raw_bt_ms",
  "sleep_ms", "suspends"}, "duration_ms"}`, opened when the approval was
  raised (14.4). It is a
  sibling, never inside `approval`. A record without one — written by an
  older punard — is expired. Consumers should treat it as opaque;
  `approval.expires_at` is the same deadline on the wall clock, for
  display.

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
- **Expiry is measured on the boot clock, never the wall clock**
  (SMP-1405, trusted time phase P0a). The TTL is the record's `lifetime`
  window, stamped with `raw_bt = CLOCK_MONOTONIC_RAW + (CLOCK_BOOTTIME −
  CLOCK_MONOTONIC)` — which NTP, `timedated` and a person cannot move —
  keyed to `/proc/sys/kernel/random/boot_id`, and labelled with the time
  the kernel counted as suspended (`sleep_ms`) and its suspend count
  (`/sys/power/suspend_stats`, `suspends`). An approval is answerable iff
  it is the same boot, **no suspend** has happened since it was raised,
  and `elapsed_ms < duration_ms − ceil(duration_ms × 200 / 10⁶)`, with
  `elapsed_ms` read on `CLOCK_MONOTONIC_RAW`: the 200 ppm drift allowance
  makes it close a little **early**, never late (60 ms on a 300 s TTL).
  A suspend closes the window because on most x86 hardware the kernel
  measures sleep from the RTC in whole seconds and can under-count it —
  by about a second, or entirely. Therefore:
  - **a pending approval lapses at reboot, and at suspend**;
  - rolling the wall clock back (or reading it as 1970) revives nothing;
  - a boot clock punard cannot read answers nothing and raises nothing
    (`internal`), and the sweep is skipped rather than expiring
    everything over a failed read;
  - `approval.expires_at` is the wall-clock rendering of the same
    deadline, for people to read, and is never compared with anything.
    A card may therefore lapse before its `expires_at` (at suspend or reboot, or by
    the drift allowance).
  - **Upgrade:** a record an older punard wrote has no `lifetime` and is
    expired at the first sweep after the upgrade; its requester asks
    again.
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
 "granted_at": "…", "expires_at": "…", "revoked_at": null,
 "lifetime": {"start": {"boot_id": "…", "raw_bt_ms": 5123456,
                        "sleep_ms": 0, "suspends": 0},
              "duration_ms": 900000}}
```

**A grant is live iff it is unrevoked and its `lifetime` window on the
boot clock is open** — the rule of 14.4: same boot, no suspend since it
was granted, and `elapsed_ms < duration_ms − ceil(duration_ms × 200 /
10⁶)` (180 ms early on 15 minutes). **Grants lapse at reboot, and at
suspend.** `expires_at` is the wall-clock
rendering, for display only; rolling the wall clock back extends
nothing. A grant an older punard wrote has no `lifetime` and is dead: on
upgrade an in-flight grant lapses (audited `privilege.expire`) and the
person requests it again. A boot clock punard cannot read keeps no grant
live and mints none; `privilege.revoke --all` needs no clock and drops
every grant the caller holds.

`privilege.status` result:
`{"grants": [{"grant_id", "capability", "reason", "granted_at",
"expires_at", "lifetime"}], "checked_at": "…"}` — the caller's own
grants, or every grant for root. `lifetime` is additive (SMP-1405).

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

## 15. Side contract (M9): `/run/punard/approvals/<uid>.json`

Not IPC — the approval sibling of section 9's `status.json` and section
13.2's `ledger.json`, written atomically (tmp + `fsync` + `rename`) by
punard at **every** approval state transition and every grant change, so
`punar-shell` renders the Plate D-003 overlay and the Plate D-012
`ELEVATED` bar chip with an event-driven `FileView` and **no socket
client in the shell**.

- **One file per person (F0 review).** `/run/punard/approvals/<uid>.json`
  holds the approvals routed to that person (`user` is their name or
  `uid:<uid>`) and their own live grants, nothing else. It used to be one
  `/run/punard/approvals.json`, `0640 root:punar` — and every account is in
  `punar`, so each person could read every person's agent requests, the
  justifications written for them and every live grant. A view is written
  for every person account, the console user and every grant holder, and
  removed when its person is no longer one; root gets none (root reads the
  socket).
- **`0640 root:root` plus the POSIX ACL entry `user:<uid>:r--` (mask `r--`),
  set before the name exists**, in the `0755 root:root`
  `/run/punard/approvals` inside the `0750 root:punar` `/run/punard` — never
  `/run/punar` alongside the world-readable `status.json`/`agents.json`. Not
  a group: a person's primary group is not guaranteed to be theirs alone.
  Not the person as owner: an owner can chmod and rewrite a file, and root
  ownership is what prevents local replacement of **the file that tells a
  human what they are about to authorize**; this is the same argument that
  put `ledger.json` in `/run/punar-agentd`. A filesystem without POSIX ACLs
  gets no view at all (fail closed), never a readable one.
- The shell reads its own uid's file (the uid of its `/run/user/<uid>`
  runtime directory); `punarctl approvals wait` watches the same file as its
  wake source.
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
  The countdown is **display only**: punard decides on the boot clock
  (14.4), so a card can lapse before its countdown ends (at suspend or reboot, or by
  the drift allowance) and a wrong wall clock cannot keep one open. The
  file carries no `lifetime`; its shape is unchanged.

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

Expiry is computed **on validate** — no timer, no sweep (spec 6.3) — and
on the **boot clock**, as for approvals (14.4, SMP-1405): each credential's
TTL is a window opened at issuance, closed at the drift-shortened edge, at
suspend and at reboot, so rolling the wall clock back stretches nothing. `expires_at`
is the wall-clock rendering, for display; `expires_in` is the whole seconds
left on the drift-shortened window, floored. A broker that cannot read the
boot clock issues and validates nothing (`internal`) and leaves the
credentials it holds alone. An expired entry is dropped on the first
validate that observes it and audited **once** (`credential.expire`,
`result: "expired"`). A validate of an **unknown** token is **not audited at
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

---

## 21. Sibling contract (M12): `punar-netd` network policy and privacy view

```text
/run/punar-netd/                  0750 root:punar
/run/punar-netd/netd.sock         0660 root:punar
/run/punar-netd/connections.json  0600 root:punar   (root only: every person's rows)
/var/lib/punar/network/           0700 root:root
```

The framing and envelopes are sections 2–4 unchanged. The daemon has only
`AF_UNIX` and `AF_NETLINK`; it never opens an internet socket, proxies a
connection, resolves a name, captures a packet, or reads a payload. It owns
only the nftables table `inet punar-net`; `inet punar-base` remains punard's
table and must not be read-modify-written by netd.

### 21.1 Closed method table

| Method | Params | Admitted peer | Effect |
|---|---|---|---|
| `network.status` | absent | any | Enforcement capability and observation limits |
| `network.connections` | absent | any | One bounded, on-demand `/proc/net/tcp{,6}` pass |
| `network.zones` | absent | any | Root-owned zone definitions |
| `network.policy` | `{"project":"atlas"}` | any | Effective strictest-wins active-project policy |
| `network.explain` | `{"project":"atlas","zone":"corp_prod"}` | any | What/why/who/source/change/next-step explanation |
| `network.apply` | absent or `{"project":"atlas"}` | **root** | Atomic reconcile of every live managed session |
| `network.session_ready` | `{"session_id":"agt_…"}` | internal: the caller's own `SO_PEERCRED` pid must be inside the exact `punar-agent-<id>.scope` cgroup; no uid-0 bypass | Reconcile, then read this session's cgroupv2 selector and jump target back from the kernel table; returns `{session_id, project, state:"ready", enforcement:"nftables_cgroup_v2"}` or an error, never a pending state |
| `relay.status` | absent | any | Selected route model and honesty fields |
| `relay.set` | `{"mode":"direct"}` or `private_relay` | console owner or root | Persist the personal preference |

`network.apply.project` is an audited trigger citation, not a partial apply:
the daemon always regenerates all authoritative live bindings in one nftables
transaction. `enterprise_route` is zone data and is not accepted by
`relay.set` on a personal device.

`network.capture`, `network.inspect`, `network.export`, `system.exec`, and
`shell.run` do not exist. They return `unknown_method`; this is a probeable
privacy and execution boundary, not a missing feature hidden by the client.

### 21.2 Policy and enforcement

For each known zone:

```text
effective = strictest(project manifest, project network policy)
deny > approval_required > allow
absent from both = deny
```

Zone membership is canonical, non-overlapping CIDR data supplied by root-owned
site configuration. A hostname, DNS answer, SNI value, process name, pid, or
user claim never establishes zone membership or managed-session attribution.
Attribution comes from `agents.list` plus exact cgroup-v2 scope reproof. A
missing or invalid project document installs deny-all for that live session and
returns a warning; an unavailable enforcement backend is never reported as
available. Processes outside managed agent cgroups are unchanged.

The generated chain order is security-significant: explicit root-owned zone
sets first; then the systemd-resolved stub at `127.0.0.53:53`, but only when
the project's internet residual is `allow`; then unconditional structural
rejects for every remaining loopback and IPv4/IPv6 link-local destination;
then the project's internet residual. A project that needs another local
service must name it in an explicit zone. A rate-limited deny log precedes
every unconditional reject. The limiter never guards the reject.

### 21.3 Connection result and privacy boundary

```json
{"scanned_at":"2026-08-28T23:45:00Z",
 "enforcement":"available",
 "relay":{"mode":"direct","simulated":false},
 "dns_protection":{"state":"not_configured","milestone":"phase_2"},
 "transport":"tcp",
 "limitations":["UDP and QUIC are not observed"],
 "processes":[
   {"name":"claude","pid_class":"agent","governed":true,
    "session":{"id":"agt_4f21c09ab3e1","project":"atlas"},
    "connections":[
      {"destination":"198.51.100.10","name":"Reviewed site label",
       "zone":"corp_dev","category":"corporate","route":"direct",
       "state":"established"}]}],
 "withheld":0}
```

**Scoped to the caller (F0; §23.1).** Which destinations another person's
programs reach is that person's data. Root sees every row. Any other caller
sees the rows of processes and managed sessions running as its own uid, and
the device's — the rows netd adds about itself and punard, and processes of
system uids (root, system daemons, systemd's dynamic users: anything outside
the person range 1000–59999). Another person's rows, and a managed session
whose root process's uid could not be read from `/proc/<pid>/status`, are
left out and counted in `withheld` (additive on `v: 1`; always `0` for
root). The side file holds every row and is root-only (`0600`); it used to
be `0640 root:punar`, readable by every account. The privacy panel shows the
caller's answer, not the file.

The serializable result has no local address, local or remote port, uid, pid,
cgroup path, command line, DNS query/history, SNI, URL, packet, or payload.
`name` is present only when the trusted zone-membership file supplied a label
for that exact address. The observer retains no timer and no history. The side
file is rewritten only when its semantic result changes; `scanned_at` alone
does not cause a disk write.

### 21.4 Relay honesty

`direct` is the real packet path. `private_relay` is an explicitly simulated
two-role model in M12 and produces the identical direct packet path. Its result
must carry `simulated: true`, the limited knowledge claimed for each role,
`property_not_held` explaining that both roles remain one local process under
one operator, and `real_relay_milestone: "phase_2"`. No surface may shorten
that to “protected” or imply independent trust boundaries exist.

---

## 22. Web applications and browser contexts (M11)

These methods live on the existing punard socket and retain the v1 envelope.
There is no launch or generic-execution RPC: launching happens in the user's
session through `punarctl`'s closed Chromium argv builder.

| Method | Params | Result |
|---|---|---|
| `webapps.list` | absent or `{"include_artifacts":true}` | caller-owned `apps`, `contexts`, effective `required_web_apps`, and install-policy summary |
| `webapps.get` | `{"id":"notes","include_artifacts":false}` | one caller-owned record, optionally with derived artifacts |
| `webapps.install` | `{"app":{...strict local manifest...}}` | complete record, verified icon/launcher artifacts, and enforcement disclosure |
| `webapps.uninstall` | `{"id":"notes","purge_data":false}` | removed record and the kept/purged profile path |
| `webapps.context_create` | `{"id":"atlas","name":"Atlas"}` | created context |
| `webapps.context_delete` | `{"id":"atlas","purge_data":false}` | deleted context and profile disposition |

All records are scoped from `SO_PEERCRED`; no request accepts a uid. Mutation
from an agent-attributed peer is denied and audited. `personal` always exists
and cannot be deleted. `org-*` is reserved and synthesized from active
enrollment rather than persisted as user state. Contexts isolate Chromium
cookies, storage, sign-ins, history, and extensions; they do not claim a
separate uid, kernel boundary, or protection from a browser sandbox escape.

Install accepts only HTTPS or absolute `file:///` URLs, never fetches a
manifest or icon, and accepts no executable or command field. The record is
private root-owned state under `/var/lib/punar/web-apps/<uid>/`; `.desktop`,
icon, profile, and compositor-rule files in the user's home are rebuildable
artifacts. Supplied PNGs are regular, caller-owned (or signed-fixture-owned),
no-follow, checksum-valid, at most 64 KiB, and at most 1024×1024.

Audit additions use `webapp.install`, `webapp.uninstall`,
`webapp.context_create`, and `webapp.context_delete`, with resources
`webapp:<id>` or `browser-context:<id>`. URLs, page content, cookies, browser
storage, and icon bytes never enter the audit event.

While enrolled, `required_web_apps` contains only the winning, non-denied
`applications.web_apps.required[]` manifests from effective policy.
`punarctl web-apps sync` uses this typed list to install missing records or
adopt an exact pre-existing identity as managed; a conflicting id is refused
rather than overwritten. Personal devices receive an empty list.

An enrolled `org-*` context reports
`not_yet_observed:[{"category":"per_context_network_policy","milestone":"phase_2"}]`.
M12's delivered project/principal network enforcement does not make a
same-uid Chromium profile a separately routed cgroup.

---

## 23. Device administrators and actions that reach other people (F0)

Before F0 there was no owner or administrator on a Punar device: every person
was equal, and any person could mint an `Admin` ticket with their own password
(§5.8a). A ticket proves *who* is asking. It never proved that the person may
act on *other people*. This section adds that second question, and applies it
to every existing method that needs it.

### 23.1 The rule

An action **reaches another person** when it does any of these:

- signals, freezes or ends another uid's process, scope or session, or a
  system service;
- reveals another person's data;
- changes device-wide state that every person on the device depends on — an
  `/etc` file, device policy, who manages the device, what the operating
  system runs.

Such an action needs **uid 0, or a device administrator who has just
confirmed their password** (a fresh `punar-authd` ticket, spent by the call it
was typed for and presented by the process it was minted for — §5.8a's ticket
rules and the binding of §23.5, which punard enforces). An **agent-attributed
caller is always refused**, at any uid — the wide agent test of §14.5 rule 1 —
before either question is asked. **Every attempt is audited**, allowed or
refused.

**The order is part of the rule.** Every check that does not depend on who is
asking is settled first (a malformed request, a pinned value, a
non-removable enrollment, the last administrator); then the role; then the
ticket. The role is checked **before** the ticket is spent, so a person
without the role never uses up a password on a call that cannot succeed, and
their ticket is still theirs to spend on something they may do.

**The refusal** is `denied`:

```json
{"code": "denied",
 "message": "Changing device policy reaches everyone who uses this device, so it needs a device administrator, and bob is not one.\nAdministrators: alice.\nPolicy: personal defaults — an action that reaches other people needs an administrator who has just confirmed their password (docs/api/ipc.md section 23).\nNext step: ask alice to do it, or to make you an administrator with `punarctl admins add bob`.",
 "details": {"decision": "deny", "reason": "device_admin_required",
             "user": "bob", "administrators": ["alice"],
             "administrators_policy": "local", "policy_ids": []}}
```

`administrators_policy` is `local`, `pinned` or `none` (§23.4); when an
organization decides, the message names it and `policy_ids` cites its
document. The audit event is the ordinary denial (§6) with
`result: "device_admin_required"` and, when an organization decides, its
`policy_ids`.

### 23.2 Where it applies today

The rule applies to every existing method that reaches another person. A
person who could use these before F0 with their own password now needs the
role as well.

| Method | What reaches others | Roster (§23.4) | Ticket |
|---|---|---|---|
| `policy.set` | device policy, for everyone | organization's, else the device's | yes (unchanged) |
| `enroll.start` | who manages the device | organization's, else the device's | yes (unchanged) |
| `enroll.stop` | who manages the device | **the device's own list only** | yes (unchanged) |
| `update.apply`, `update.rollback` | what the operating system runs | organization's, else the device's | yes (unchanged) |
| `privilege.request` | a window to change a registered capability; every registered capability is device-wide (firewall, hostname, time zone, update channel, browser policy) | organization's, else the device's | no — refused up front so nobody types a password for a request they cannot approve |
| `approvals.resolve` with `decision: approved` on a `capability_set` or `privilege_request` approval | executes a device-wide change, or mints the grant for one | organization's, else the device's | **yes — new optional `ticket` param**; `reauthentication_required` without one |
| `capabilities.set` on the grant path (§14.8) | a device-wide change | organization's, else the device's | no — the grant was minted with one; the **role is re-checked at every use**, so taking it away takes the grant's effect away |
| `admins.set` | who may act on everyone | organization's, else the device's | yes |
| `apps.install`, `apps.update`, `apps.remove` (F0 review) | what every person on the device runs: the catalog's system-wide packages, installed, moved to a new version, or taken away from everyone who uses them | organization's, else the device's | **yes — new optional `ticket` param**; the organization's application policy is settled first, then the role, then the ticket; `apps.update --all` spends one ticket for the whole request |

Outside punard's socket, the same rule reaches:

| Path | What reaches others | Now |
|---|---|---|
| `org.freedesktop.login1.{reboot,power-off}-multiple-sessions` (polkit, `50-punar-power.rules`) | restarting or shutting down while another person is signed in ends their session | **refused to every subject** (F0 review): the rule needs a fresh password and, while enrolled, the organization's administrator list, and polkit can do neither — it cannot spend a `punar-authd` ticket, and it cannot read the list punard resolves. It answers NO outright rather than challenging for a password nobody at the seat can give. With no other session open, the person at the seat still restarts unprompted; root (which logind does not ask polkit about) and the power button on the case still work. A path for an administrator with a fresh password belongs with the other actions that end another uid's session |

**Reads that would reveal another person's data are scoped, not refused.** A
person keeps their own view; the rows of other people are left out and
counted, so "is this everything?" has an honest answer, and root sees every
row:

| Read | Scoping |
|---|---|
| `audit.tail` | own events and the device's, `withheld` count (§5.5; F0-S3). An event that names an agent session or a project (anything but `agt_none` / `system`) is the person's whose work it is, never the device's, even when a daemon wrote it as itself — punar-netd refusing an agent a zone, punar-agentd reaping a session: it is shown to root, and its person reads it in their session's access ledger (F0 review). The trail itself is `0640 root:punar-audit` in a setgid `2750 root:punar-audit` directory, so every writer's files are born in that group (§6) |
| `approvals.list`, `approvals.get` | the approvals routed to the caller; `list` counts the rest as `withheld`, `get` answers `not_found` for one routed to someone else (§14.2). The shell's view is one ACL-guarded file per person (§15) |
| `network.connections` (punar-netd) | own processes and managed sessions and the device's, `withheld` count (§21.3). Its side file is root-only |
| the AI panel's ledger | read through `agents.access`, owner-or-root (§12.2); the device-wide side file `/run/punar-agentd/ledger.json` is `0640 root:punar-audit` (§13.2) |

Reviewed and left as they are, with the reason:

- `update.check` refreshes the verified channel cache and changes nothing any
  person runs; it keeps its ticket and needs no role.
- `webapps.*`, `pim.mail.*` and `punar-secrets`' `credential.*` are scoped to
  the caller's own uid by `SO_PEERCRED`.
- `approvals.resolve` with `decision: denied`, or on a `credential_request`,
  changes nothing device-wide (a credential approval issues the person's own
  credential to their own session).
- On sibling sockets: `agents.end`, `ledger.purge`, `agents.access` and
  `alerts.dismiss` are owner-or-root already; `query.answer`,
  `network.apply` and `approvals.create`/`consume` are root-only;
  `relay.set` is the console owner's personal preference.
- `reconcile`, `update.reconcile_candidate` and `install.*` are root-only.

### 23.3 `admins.list`, `admins.set`

`admins.list` — any admitted peer; params none; never audited. A person must
be able to find out whom to ask.

```json
{"mode": "local",
 "administrators": ["alice"],
 "accounts": [{"user": "alice", "uid": 1000, "administrator": true, "origin": "onboarded"},
              {"user": "bob",   "uid": 1001, "administrator": false, "origin": "onboarded"}],
 "source": null,
 "group": "punar-admin",
 "caller": {"user": "bob", "root": false, "administrator": false}}
```

`source` is the organization's policy source (§5.7's shape) when one decides;
`accounts[].administrator` is the effective answer under `mode`. `origin` is
`onboarded`, or `image` for an account an image ships in `/etc/group` (the
development image only; release gate A24 refuses one in a release).

`admins.set` — params `{"user": "bob", "administrator": true, "ticket":
"<64 hex>"}` (`deny_unknown_fields`; `ticket` absent only for root). Always
audited — every refusal too, with its reason as the event's `result`
(`invalid_params`, `not_found`, `image_account`, `last_administrator`,
`device_admin_required`, `reauthentication_required`) — `action:
"admins.set"`, `resource: "account/<user>"`. One `admins.set` runs at a time
from step 4 to step 7, so two administrators removing each other at once
cannot both count the other and leave none. The ladder:

1. an agent-shaped peer, at any uid → `denied` (`agent_scope`);
2. an organization roster in `pinned` or `none` mode → `denied`
   (`administrators_set_by_organization`), naming it: the local list is inert
   while it decides;
3. not an account name → `invalid_params`; no such account → `not_found`; an
   `image` account → `invalid_params` (`image_account`);
4. **removing the last administrator** → `denied` (`last_administrator`,
   audited with that result). A device always keeps one — counting only
   administrators someone can **sign in as** (an account whose user record
   is published at `/run/userdb/<user>.user`, or one the image ships in
   `/etc/passwd`): a role held by an account boot does not publish
   administers nothing;
5. the caller is not an administrator → `denied` (`device_admin_required`);
6. no ticket → `denied` (`reauthentication_required`); the ticket is spent;
7. the account's record, then its runtime membership, is changed; audited
   `success`, or `noop` when it already stood as asked.

Result: `{"user": "bob", "administrator": true, "changed": true,
"administrators": ["alice", "bob"]}`. From a terminal:
`punarctl admins list`, `punarctl admins add <user>`,
`punarctl admins remove <user>` (each asks for the caller's password, §23.5).

### 23.4 Where the role lives, how the first account gets it, and who can pin it

**The role is membership in the system group `punar-admin`**, created empty on
every lane by the image (release gate A24). A Punar account is a systemd
userdb record, so membership lives in two places, kept in step:

- the **persistent** truth, the `groups` array of the account's record at
  `/var/lib/punar/identity/accounts/<id>/account.json` (docs/design/
  onboarding.md §1.9);
- the **runtime** edge `/run/userdb/<user>:punar-admin.membership`, which the
  account materializer publishes from that record at every boot and which is
  what nss-systemd, and so every login, sees.

punard reads the runtime view — what a login would see — and never the
caller's process groups: a process keeps the groups it logged in with, and a
revocation that waited for the revoked person to log out would not be one.
`admins.set` writes the record first and the edge second; a crash between the
two is healed by the next boot's materialization.

**The first account holds the role.** Onboarding creates the first account in
`punar-admin` when the image has the group (OD-1(a)).

**No update leaves a device with no administrator.** On every boot, before
the account is published, the materializer checks the accounts it publishes:
when **no account a person can sign in as holds the role**, the **device
owner** gets it and the grant is recorded. The device owner is the account
onboarding recorded as completing first run
(`/var/lib/punar/onboarding/completed.json`) — the first account by
construction, since onboarding creates exactly one and refuses a second first
run. The materializer publishes the owner alone today, so a role handed to
an account boot does not publish does not count (F0 review: counting it let a
device whose owner had handed the role on come up with no administrator
anyone could use); when more accounts are published at boot they count too,
and an administrator who handed the role to one of them and stepped down is
then left alone. An image without the group (an older release after a
rollback) is left exactly as it was.

**An organization can decide instead**, while the device is enrolled, through
`spec.security.localAdmin.administrators` in its desired state
(`schemas/desired-state/desired-state.json`):

| `mode` | Who administers the device | `admins.set` |
|---|---|---|
| absent | the device's own `punar-admin` members | allowed |
| `local` | the same, stated explicitly | allowed |
| `pinned` + `accounts: [...]` | exactly the named accounts | refused, naming the organization |
| `none` | nobody at the device; only root and the organization | refused, naming the organization |

A present-but-unreadable value refuses daemon start rather than falling back
to the device's own list, as `policyEditing` does (§5.7). **Leaving an
enrollment the organization made removable always follows the device's own
list**, whatever the roster says: an organization that could forbid every
local administrator could keep a device it enrolled as removable. The roster
is reloaded and cleared with the organization's other layers on every
enrollment transition.

<!-- F0-S4 -->
### 23.5 Passwords and tickets from clients (F0-S4)

Every client that turns a person's password into a ticket either uses one
library, `punar-reauth` (`crates/punar-reauth`), or — a graphical surface —
sends the password to `punar-authd` itself over the daemon's socket. No
password crosses a pipe, standard input, argv, the environment or a socket a
program of the same person could stand in for.

**What a ticket binds (F0 review).** `punar-authd` mints an `Admin` ticket
only for a request that names the IPC method it is for (`"action":
"policy.set"`); a request without one is malformed and refused before PAM is
asked. The ticket names one **spender**: the requesting process, or the
process the request names with `"for_pid"` — which must be alive and run
entirely (real, effective, saved and filesystem uid) as the requester, so a
caller can only name a process of its own and gains nothing it did not have.
The spender is recorded as its pid and kernel start time
(`/proc/<pid>/stat` field 22), so a recycled pid is a different process.
punard spends a ticket only for that method and only when the connection's
peer is that process (§5.8a). A ticket copied out of the process it was meant
for — by whatever means — is therefore worth nothing to the copier: the one
process that can spend it is the command the person started for the change
they typed their password for.

**The two framings of `punar-authd`'s socket.** The original: a 4-byte
little-endian length, then the JSON request; the answer framed the same way.
And one JSON object on one line, answered by one JSON line — what a
graphical surface can write on a socket it opens itself. A line request
starts `{"`; as a length header those two bytes would announce at least
0x227B bytes, more than any request may hold, so the two cannot be confused.
The request shape is unchanged besides the two optional binding fields:

```json
{"v": 1, "password": "…", "purpose": "admin", "action": "approvals.resolve", "for_pid": 4242}
```

```json
{"v": 1, "verdict": "ok", "ticket": "<64 hex>"}
```

**The two sources `punar-reauth` accepts:**

1. **the controlling terminal**, with echo off, canonical mode and suspend
   disabled;
2. **a descriptor that `fstat` proves is a socket**.

**Pipes, standard input and argv are refused.** Any process running as the
same uid can open `/proc/<pid>/fd/<n>` of a dumpable process; for a pipe or a
file that open succeeds and hands back a second reader that can take the
secret first, while for a socket it fails with `ENXIO`. argv and the
environment are readable in `/proc/<pid>/cmdline` and `environ` outright.

**Holders are not dumpable.** Before it reads a secret, a holder calls
`harden()`: `PR_SET_DUMPABLE=0` (which also closes its `/proc/<pid>/fd`,
`mem` and `environ` to other processes of the same uid) and `RLIMIT_CORE=0`
soft and hard — punarctl before any password, ticket or enrollment code. The
password, the request body and the ticket live in `Zeroizing` memory. The
desktop shell cannot call `harden()`; it runs with `RLIMIT_CORE` 0 soft and
hard under `/usr/lib/punar/punar-shell-run`, so no core file of it holds a
password, and Yama (F0-S2) keeps other programs from attaching to it.

**The command-line convention** (every `punarctl` verb that needs a password:
`policy set|clear`, `enroll start|stop`, `update check|apply|rollback`,
`approvals resolve`, `admins add|remove`, `app install|remove|update`):

- **the role first.** A verb that needs a device administrator asks punard
  (`admins.list`) whether the caller is one before it reads any secret; a
  caller who is not is never asked for a password, and punard's refusal —
  naming who can act — is what prints (`enroll stop`, which follows the
  device's own list, asks punard the bare request instead);
- no flag — ask on the terminal; with no terminal, send no ticket and print
  punard's refusal;
- `--password-fd N` — the password, one line, on descriptor N, which must be
  a socket (descriptors 0–2 are refused); punarctl asks for a ticket bound to
  itself;
- `--ticket-fd N` — a ticket (`ok <ticket>` or the bare 64 hex), on a socket.
  It must have been minted for this punarctl process (`for_pid`) and this
  method, or punard refuses it;
- `--ticket-from-parent` — for a graphical parent that cannot hand a child a
  descriptor. Once the role check passes, punarctl opens a listening socket
  at a fresh name inside `$XDG_RUNTIME_DIR/punar-reauth` (a `0700` directory
  of the caller, checked; `/run/user/<uid>` when the environment names
  nothing private) and prints `ticket-socket <path>` on standard output. The
  parent then sends the password to `punar-authd` itself, asking for a ticket
  for this method with `for_pid` set to the punarctl it started (it knows the
  pid because it started the process), and relays the answer — `ok <ticket>`,
  `denied` or `unavailable` — over that socket, which accepts only a
  connection `SO_PEERCRED` says comes from **its parent process, running as
  the same uid**; a connection from anyone else is closed unread and the wait
  goes on. System Control, the approval overlay and Command Center use this
  through `shell/punar-shell/Services/PasswordRun.qml`, which starts
  `/usr/bin/punarctl` by its absolute path — a `punarctl` earlier on PATH
  would be the process the ticket is bound to;
- `--password-from-parent`, `--ticket-stdin` and `--password-stdin` are
  refused with exit 2 and a message naming the replacements, before anything
  else the verb does and whoever runs it. A person without the administrator
  role is never asked for a password, so a check on the password path alone
  would have answered them with punard's role refusal and left the flag
  unmentioned (found on a booted image, F0 boot proof).

**Why the relay carries a ticket and never the password.** Another program of
the same person can replace the rendezvous socket (a rename in the person's
own directory), and can even put the parent on a false path by writing to
the parent's end of punarctl's standard output — both READ-mode opens that
Yama does not restrict. With the password on that socket, either was a way
to take it; the old design could only report an interception afterwards, and
not reliably (a program that renamed the original back left no trace). Now
what such a program can receive is a ticket only this punarctl can spend, and
punarctl then fails closed with nothing changed. `Intercepted`, reported when
a wait ends with the name gone or replaced, is a best-effort signal and not
what the protection rests on.

**The lock screen** sends the passphrase to `punar-authd` the same way, as one
line (`{"v":1,"password":"…"}`, purpose `unlock`, no ticket), over the socket
it opens itself. It used to pipe the passphrase to the `punar-auth` relay, and
the lock surface held that pipe's write end, which any program of the person
could reopen through `/proc` to read the passphrase as it went by and write
it back. The relay remains for scripts that verify an unlock (the recovery
check); it no longer mints administrator tickets, whose answer would travel
on its stdout pipe.

Descriptor numbers become owned descriptors through `pidfd_getfd` on the
process's own pidfd, which needs no `unsafe`; a seccomp filter that refuses
it (Docker's default profile) is reported as such, and the terminal still
works.

**What this does not stop, stated rather than implied.** At the terminal
prompt, a program already running as the same person can open that person's
own pseudo-terminal and compete for the keystrokes typed at it — a READ-mode
open Yama does not restrict. The password a person types into a terminal is
exposed to their own programs exactly as every other keystroke they type
there is. Closing it needs the prompt to move into a trusted process that
owns the input surface — a different uid, or the compositor — which is open
work and an owner review item; the graphical surfaces above do not have it.
<!-- /F0-S4 -->

---

## 24. punard additions for the first-party apps (reserved)

The first-party apps plan (PLAN.md §2.4) adds names to this socket over five
milestones. This amendment reserves every one of them now, so no other change
can take a name, and assigns the sections their contracts will live in. **A
reserved name has no handler and answers `unknown_method`**, exactly as a name
nobody proposed, until the milestone that brings its handler moves it into
`Method::NAMES`. `Method::RESERVED` in `crates/punar-common/src/ipc.rs` is the
list, and `the_reserved_names_are_exactly_the_amendments_list` pins it.

| Name | Milestone | What it will be | §23 |
|---|---|---|---|
| `resources.sample` | M2 Activity | a bounded sample of per-app CPU, memory, I/O and GPU for the caller's own units; root sees system units | reads only |
| `process.signal` | M2 Activity | TERM, KILL, STOP or CONT to one pidfd-pinned process, never a protected set (PID 1, kernel threads, Punar daemons, greetd, the compositor, the lock) | **yes** for another uid or a system unit |
| `sysfiles.list` | M5 Editor | the registry of editable system files (`hosts` only at first) and their state | reads only |
| `sysfiles.apply` | M5 Editor | replace one registered file from a sealed memfd (the descriptor rule below) | **yes** |
| `sysfiles.revert` | M5 Editor | restore the previous version of one registered file | **yes** |
| `storage.share_mount` | Files P2 | mount one allowlisted network share | **yes** |
| `storage.share_unmount` | Files P2 | unmount one | **yes** |
| `storage.share_list` | Files P2 | the caller's shares | reads only |
| `storage.share_forget` | Files P2 | drop a remembered share and its credential | **yes** |

With F0 the table is 47 names; after M2, M5 and Files P2 it is 56. Terminal
adds nothing here: its `terminal.policy` capability uses `policy.*`.
`apps.catalog` gains an optional `{mime}` parameter in Files P2; that is an
additive param, not a name.

**The descriptor rule.** A method that takes a secret or a content blob names
a descriptor number in its JSON, and punard fetches that descriptor from the
caller by pid with `pidfd_getfd` and requires a sealed memfd, exactly as
`install.apply` does (`read_peer_descriptor`,
`crates/punard/src/install.rs`). There is no SCM_RIGHTS on the NDJSON socket
and no per-method socket. `pidfd_getfd` keeps working under Yama
`ptrace_scope=1` because punard holds `CAP_SYS_PTRACE` (F0-S2,
`usr/lib/sysctl.d/50-punar-yama.conf`).

## 25. Sibling contract: `punar-logd` (reserved)

Skeleton; nothing here is built. The Logs milestone (M1) writes the contract.

- Socket `/run/punar-logd/logd.sock`, `0660 root:punar`, `Accept=yes` — one
  short-lived process per connection, nothing resident at idle.
- Closed table: `logs.sources`, `logs.query`, `logs.wait`, `logs.get`,
  `logs.boots`, `logs.units`, `logs.unlock`, `logs.lock`, `logs.export`.
  Anything else answers `unknown_method`.
- Scopes: a person's own journal; the device's (`device`); and `system`,
  which reveals other people's data — **`logs.unlock` into `system` scope is a
  §23 action**: root, or a device administrator with a fresh ticket; agents
  never; always audited through punard (§26).
- Streaming is allowed on this socket only (`logs.wait`); the main socket's
  one-request-per-connection rule (§8) is unchanged.
- The broker runs as `punar-logs`, which is **not** in group `punar`: it
  cannot open `punard.sock` or `agentd.sock`, and reaches punard only through
  §26.

## 26. Internal socket: punard ← `punar-logd` (reserved)

Skeleton; nothing here is built.

- Socket `/run/punard/logs.sock`, `0660 root:punar-logs`; `SO_PEERCRED` must
  be the `punar-logs` uid.
- Closed table: `logs.authorize` (spend a person's ticket and apply §23 for a
  `system` unlock), `logs.audit` (append one Logs audit event through punard's
  writer), `logs.policy` (the effective `diagnostics.*` policy).
- This is the one new inter-daemon edge (`punar-logd → punard`); §18.4's graph
  stays acyclic.

## 27. Per-session app sockets (reserved)

Skeleton; nothing here is built. Every first-party app host serves its window
and its terminal verbs on sockets under the person's runtime directory:

| Socket | Owner | Closed table |
|---|---|---|
| `$XDG_RUNTIME_DIR/punar/terminal/control.sock` | the Terminal UI | `open`, `list`, `focus`, `close`, `restore`, `status` |
| `$XDG_RUNTIME_DIR/punar/activity/control.sock`, `…/punar/logs/control.sock` | the hosts | navigation, and `ready` or `state`, only |
| `$XDG_RUNTIME_DIR/punar-editor/host.sock` | the Editor host | `punarctl edit` requests, and the host ↔ editor table |
| each host's private `ui.sock` | the hosts | the window protocol: framing and caps only |

Rules every one of them keeps:

- **same-uid admission**: `SO_PEERCRED` uid equals the socket owner's, in a
  `0700` directory;
- **agent scopes refused**: a peer whose cgroup names `punar-agent-*.scope`
  is refused, as on every Punar socket that can act;
- **closed tables**: fixed method names, `deny_unknown_fields`, bounded
  frames; no generic execution, ever (§8);
- anything that reaches another person goes to punard and is decided there
  by §23 — a per-session socket never decides it.
