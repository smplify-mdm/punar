# Milestone 5 — Mock Smplify enrollment: architecture plan

Spec authority: section 76 Milestone 5 ("mock control plane, device
enrollment, policy, compliance, and inventory"), grounded in sections 24
(local-first AI privacy / remote-query rules), 49 (enrollment chain — "MVP
uses a mocked Smplify control plane"), 50 (Punar⇄Smplify relationship), 51
(remote queries — deferred, see §12), 52 (compliance states), 54 (telemetry
categories), 55 (offline behavior), 61 (local IPC security), 73 (restriction
UX voice), 40 (the managed explain output, now rendered for real). Binding
prior contracts, not relitigated: `docs/api/ipc.md` (M5 changes are
**additive under `v: 1`**, marked "M5" there) and
`docs/development/milestone-3.md` / `milestone-4.md` (daemon architecture,
layered store, policy.d loader/flattener/merge, reconcile chain, check
mechanics, budgets).

M5 is the milestone where **unmanaged-first flips to managed and back, live,
in the VM**: the M4 engine already merges org layers (Acme fixtures, host
tests); M5 makes the VM enroll against an in-VM mock control plane, renders
the spec 40 managed output for real, syncs category-level compliance and
inventory, survives the control plane dying (section 55), and un-enrolls
back to calm paper (design language section 8). The CI VM has **no network**
(`-nic none` in tools/boot-test.sh), so the mock lives inside the image —
as a test harness, never as product.

---

## 1. Scope

In: `punar-mock-smplify` dev/CI-only mock control plane (new workspace bin
crate); `enroll.start` / `enroll.status` / `enroll.stop` IPC + `punarctl
enroll` verbs; policy.d populated/emptied by the enrollment chain (the M4
loader finally gets real files); compliance + inventory sync piggybacked on
the existing reconcile pass; bounded latest-wins offline queue;
`/run/punar/status.json` summary file + `Status.qml` wired to it (the M1
stub retires; org bar chrome flips on); the two small CLI amendments the
managed path makes necessary (overridden-set verdict line, org-policy
denial citation); audit rotation (the M3 §6 follow-up targeted at M5);
`m5-check` exercising the full lifecycle with two screenshots.

Out (unchanged non-goals): remote admin queries (`admin.*` — spec 51; M10,
names reserved in the mock), approvals/JIT elevation (M9 —
`approval_required` still degrades to alert-only), real attestation
(explicitly **simulated and labeled**, §5.2), user authentication in the
section 49 chain (no IdP exists; documented gap, §5.1), event
streaming (status.json is a file the shell watches, not a subscription),
mock unenroll RPC (unenroll is local-only in M5, §5.4), agent methods and
the audit-schema conditional-agent-fields change (deferred again — §11).

## 2. Decision summary

| # | Decision |
|---|----------|
| 1 | **Mock crate**: `punar-mock-smplify`, new workspace **bin** crate, dev/CI-only. Transport: root-only **UDS** `/run/punar-mock-smplify/api.sock`, NDJSON, the established `{v,id,method,params}` envelope. Serves the Acme fixtures **verbatim** from `/usr/share/punar/fixtures/acme/` (staged by `container-build.sh`); records what it receives under `/var/lib/punar-mock-smplify/` so checks assert the *received* side. Never enabled; started/stopped only by m5-check. §4. |
| 2 | **Enrollment chain in `punard`**: `enroll.start{org_domain}` (root-only) → discover → register (generated bootstrap secret; **attestation simulated and labeled**) → fetch policy → strict-parse/validate → write policy.d envelopes → recompute merge → reconcile → first compliance + inventory report → status.json. `enroll.status` (read), `enroll.stop` (root-only, local restore). State: `/var/lib/punar/enrollment.json` (0600) + `/var/lib/punar/device-token` (0600, `Redacted` in memory, never serialized). §5. |
| 3 | **Sync**: compliance report (category **states only**, spec 54/24) at the end of every reconcile pass **when enrolled** — piggybacks the existing 120 s `punard-reconcile.timer`, no new timers. Inventory (os-release + kernel + capability list/states) at enroll and afterwards only when its hash changes. §6. |
| 4 | **Offline (spec 55)**: enrollment and policy.d persist; failed reports set a `pending` flag (bounded, latest-wins — one pending compliance, one pending inventory); next reconcile pass retries; sync audit on **transitions** only (reachable→unreachable→reachable). Local policy stays enforceable with the mock stopped. §7. |
| 5 | **Managed-path set behavior (read from the M4 code, stated exactly)**: for **root**, a set on an org-pinned path is **recorded-but-overridden** — exit 0, `changed:false`, `overridden:true`, `effective_state` (crates/punard/src/server.rs, `handle_capabilities_set`: preference recorded, *effective* value applied, optional fields emitted). For **non-root** it is authz-denied exit 3 *before* policy is consulted; M5 amends that denial message to cite the pinning org policy instead of "personal defaults" when the path is org-pinned. `punarctl` gains the overridden verdict line. §5.5. |
| 6 | **Shell wiring**: `punard` atomically writes `/run/punar/status.json` (0644, **summary only**: `{v, enrolled, org_name, compliance_overall, ts}`) at startup and on change; `Status.qml` watches it with a Quickshell `FileView` (event-driven, zero polling) — the existing §8-gated bar chrome flips on; org name renders in the bar per the system-control mockup grammar. Fail-closed to personal on missing/invalid file. §8. |
| 7 | **m5-check**: root oneshot after m4-check; starts the mock itself; asserts the full enroll → managed → sync → offline → recover → unenroll lifecycle incl. the spec 40 managed explain, file modes, mock received-state, both screenshots, and the audit trail. §10. |
| 8 | **Budgets**: the mock runs **only inside the m5-check window**; the `PUNAR_SERVICES_RSS_MB` gate reads the `punard.service` cgroup only, so the mock is structurally excluded — documented, plus the idle-RAM sampling window closes before any check starts. §9. |

## 3. Section 49 chain, mapped honestly to the mock

| Spec 49 step | M5 reality | Honest label |
|---|---|---|
| Boot / Network | VM boot; **no network** — transport is a local UDS | mock stands in for the cloud |
| Device bootstrap identity | existing `/var/lib/punar/device-id` (M3) + a per-enroll random bootstrap secret | real |
| Choose personal or organization | `punarctl enroll start <domain>` — explicit, root, audited (spec 24: enrollment is explicit) | real |
| Organization discovery | `org.discover{domain}` → `org.json` fixture verbatim | mocked data, real flow |
| User authentication | **absent** — no IdP in the MVP; the enrolling actor is the root admin running the verb | documented gap |
| Device registration | `enroll.register{device_id, bootstrap}` → `device_token` | real flow, mock issuer |
| Attestation | mock accepts the bootstrap and answers `"attestation": "simulated"`; punard stores and reports that string; nothing measures anything | **SIMULATED, labeled** in results, `enroll.status`, and this doc |
| Desired state / Policy | `policy.fetch{device_token}` → policy-source envelope with embedded `DeviceDesiredState`, written to `/var/lib/punar/policy.d/` | fixture data, real M4 loader/merge |
| Provision / Verify | recompute merge → full section 42 reconcile pass | real (M4 engine) |
| Managed desktop | status.json → bar chrome; spec 40 managed explain; compliance sync | real |

## 4. `punar-mock-smplify` — the mock control plane

### 4.1 Position and posture (dev/CI-only, stated plainly)

A new workspace member `crates/punar-mock-smplify` (bin). It is a **test
harness with the same standing as the `m*-check.sh` scripts**: it ships in
the CI/dev desktop image because the CI VM has no network and the milestone
requires an in-VM counterparty — and it must never appear in any production
image narrative. Concretely:

- the unit `punar-mock-smplify.service` is **never enabled** — no wants
  symlink anywhere; only `m5-check.sh` starts it and it is stopped again
  before the check ends;
- the binary's `--help` and startup log line both say
  `dev/CI mock — not a product component`;
- nothing in `punard` requires it: an unenrolled device never contacts it,
  and an enrolled device degrades per section 55 when it is absent.

### 4.2 Transport and trust boundary (spec 61, decided deliberately)

**UDS `SOCK_STREAM` at `/run/punar-mock-smplify/api.sock`, NDJSON.** The
section 61 rule — the OS control surface must never be unauthenticated
localhost TCP — is about `punard`'s surface, but a localhost-TCP mock would
put an unauthenticated control-plane look-alike on every CI image and teach
the wrong shape. A root-only UDS avoids the smell entirely and needs no
network stack.

Honest trust-boundary statement: **in production this hop is
Punar ⇄ Smplify cloud over mutually-authenticated TLS; the mock replaces
that transport with filesystem admission** (`RuntimeDirectory` mode 0750
root:root; socket chmod 0600 root before `listen()` — only root connects:
`punard` and the check). The `device_token` check is still enforced at the
protocol layer even though transport admission already implies root —
because the token flow is the thing M5 is rehearsing, and the mock must
reject a wrong token so punard's error path is testable. The mock performs
no SO_PEERCRED authz beyond the filesystem; it is not an authority.

`punard` reaches the mock via a compiled-in default endpoint
(`/run/punar-mock-smplify/api.sock`) overridable by the
`PUNAR_CONTROL_PLANE_SOCKET` environment variable (host tests point it at a
temp socket). Real discovery (DNS/HTTPS) is out of scope; this seam is the
documented simulation boundary. `punard.service` needs no hardening change:
the unit sets no `RestrictAddressFamilies` (verified), so an outbound UDS
connect is already permitted.

### 4.3 Protocol (NDJSON RPC, established envelope)

Requests `{"v":1,"id":"…","method":"…","params":{…}}`, responses
`{"v":1,"id":"…","result":{…}}` or `{"v":1,"id":"…","error":{"code","message"}}`
— the ipc.md §2/§3 framing verbatim (4096-byte lines, sequential,
10 s timeouts). Methods:

| Method | Params | Result | Notes |
|---|---|---|---|
| `org.discover` | `{domain}` | the `org.json` fixture **verbatim** as `{"organization": {…}}` | unknown domain → `not_found` |
| `enroll.register` | `{device_id, bootstrap}` | `{"device_token": "tok_<32 hex>", "attestation": "simulated", "organization": {…}}` | bootstrap must be ≥32 hex chars ("simulated-accept" logged); device recorded in `devices.json`; re-register of a known `device_id` rotates the token (idempotent re-enroll) |
| `policy.fetch` | `{device_token}` | `{"policies": [ <envelope> ]}` | see 4.4; bad token → `unauthorized` |
| `compliance.report` | `{device_token, report}` | `{"accepted": true}` | appended verbatim + `received_at`/`device_id` to `received-compliance.jsonl` |
| `inventory.report` | `{device_token, inventory}` | `{"accepted": true}` | appended likewise to `received-inventory.jsonl` |
| `admin.devices`, `admin.device` | — | `unknown_method` | **names reserved for M10** (spec 51 remote queries); documented so nobody invents a different admin surface later |

### 4.4 Fixtures served verbatim; the one mechanical composition

`container-build.sh` stages `fixtures/organizations/acme/*` →
`/usr/share/punar/fixtures/acme/` (same pattern as the shell QML staging it
already does; `PUNAR_BUILD_MODE=summary` untouched). The repo keeps the
envelope (`policy-source-eng-baseline-v12.json`) and the payload
(`desired-state-eng-baseline-v12.json`) as **separate fixture files**, while
a policy.d drop carries them **combined** (the M4 loader's own test states
this: crates/punard/src/policy.rs — "the two ship as separate fixture
files; a policy.d drop carries them combined"). `policy.fetch` therefore
performs exactly one mechanical composition: envelope fields verbatim +
`"policy": <desired-state file contents verbatim>`. Nothing is edited.

**Decision — baseline only.** `policy.fetch` serves `eng-baseline-v12`
alone. `policy-source-eng-ai-v3.json` (fixtures/policies/) has no embedded
`DeviceDesiredState`, and no registered capability consumes `spec.ai` — the
M4 flattener maps only `spec.security.firewall.enabled` and logs-and-ignores
the rest (milestone-4.md §3.2; policy.rs handles the payload-less envelope
with a load-time note). Serving it would add a warning line and zero
observable state; it joins the fetch set when AI capabilities land (M7+).
Consequence, stated for the mockup-literate: in-VM compliance has exactly
the three registered capability rows, not the system-control mockup's full
eight-row list — the mockup depicts the M5+ hero device.

### 4.5 Mock state (what the server RECEIVED)

`StateDirectory=punar-mock-smplify` → `/var/lib/punar-mock-smplify/`
(0700 root):

- `devices.json` — `{device_id: {device_token, registered_at,
  attestation: "simulated"}}` (atomic rewrite);
- `received-compliance.jsonl`, `received-inventory.jsonl` — append-only,
  one received report per line with `received_at` + resolved `device_id`.

State **persists across mock restarts** deliberately: the m5-check
stop→start (offline recovery, §10) must not invalidate the device token,
and "mock keeps history" after unenroll is the honest record that
unenrollment was local (§5.4). m5-check reads these files directly (root)
instead of an admin API — that is why `admin.*` can stay reserved.

### 4.6 Unit

`punar-mock-smplify.service` (desktop extra tree): `Type=simple`,
`ExecStart=/usr/bin/punar-mock-smplify` (defaults: fixtures
`/usr/share/punar/fixtures/acme`, socket + state per RuntimeDirectory/
StateDirectory), `RuntimeDirectory=punar-mock-smplify`
`RuntimeDirectoryMode=0750`, `StateDirectory=punar-mock-smplify`,
`NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`. **No wants
symlink** (the not-enabled discipline of the check services; asserted by
m5-check). Built and staged by `container-build.sh` alongside
punard/punarctl (`cargo build … -p punar-mock-smplify`).

## 5. Enrollment in `punard`

Contract text lives in `docs/api/ipc.md` §§5.9–5.11 (additive, `v: 1`,
exactly like the M4 additions per ipc.md §3.3). Design here.

### 5.1 `enroll.start {org_domain}` — root-only, audited

Pipeline (one synchronous request; ipc.md documents the raised per-request
processing bound of 60 s for this method — the chain contains a full
reconcile pass and, on TCG, nft operations are slow):

1. **Guard** — already enrolled → error `conflict` (new additive error
   code). Non-root → the standard denial (audited).
2. **Discover** — `org.discover{domain}` on the control-plane socket
   (2 s connect / 5 s per call). Unreachable → `upstream_unreachable`
   (additive code; section 73 message: what, why, "Next step: is the
   control plane running?"), nothing written.
3. **Register** — generate a 32-byte hex bootstrap secret (`rand`, in
   memory only, never persisted, never logged); `enroll.register{device_id
   (from /var/lib/punar/device-id), bootstrap}` → `device_token`.
   **Attestation is simulated**: punard stores the mock's literal
   `"attestation": "simulated"` string and surfaces it in `enroll.start`
   / `enroll.status` results — the honesty label travels with the data.
4. **Token storage** — token wrapped in `punar_common::Redacted`
   immediately (Serialize/Debug print the placeholder — the audit trail
   cannot leak what the type cannot print, spec 53); written alone to
   `/var/lib/punar/device-token`, 0600 root, atomic.
5. **Fetch policy** — `policy.fetch{device_token}` → envelopes.
6. **Validate** — the M4 loader's strict serde parse + its
   rank-contradiction check per envelope (milestone-4.md §3.2). Full
   JSON-Schema validation remains host-side
   (`./tools/validate-schemas.sh` covers the fixtures the mock serves —
   same bytes), stated honestly: in-daemon validation is the loader's
   strictness, not a JSON-Schema engine.
7. **Write policy.d** — each envelope → `/var/lib/punar/policy.d/
   <policy_id>.json`, 0600 root, atomic. Invalid envelope → abort: remove
   anything written this call, delete the token file, error out —
   enrollment is all-or-nothing.
8. **Recompute + reconcile** — reload policy.d layers, recompute the
   effective document, run one full section 42 pass (daemon-initiated:
   audit actor `punard`/`service`, exactly like the boot reconcile). This
   is M4's "policy.d hot-reload arrives with M5 enrollment": **the
   enrollment path reloads live; a manual root file-drop into policy.d
   still requires a daemon restart** (documented limit — the authoritative
   policy.d writer is now the enrollment chain, and a restart-free path
   for hand-drops is not worth an inotify mesh).
9. **First sync** — compliance report + inventory report (§6). Failures
   here do **not** fail enrollment (section 55: sync degrades, enrollment
   does not) — they mark the queue pending.
10. **Persist + publish** — write `enrollment.json`, rewrite
    `status.json` (§8), audit `enroll.start` success with
    `policy_ids: ["eng-baseline-v12"]`.

`enrollment.json` (private daemon store, peer of `device-id` /
`preferences.json` — documented here, deliberately not a public schema),
0600 root, atomic:

```json
{
  "version": 1,
  "org": {"id": "acme", "name": "Acme", "display_name": "Acme Engineering",
           "domain": "acme.com"},
  "enrolled_at": "2026-08-26T09:00:00Z",
  "attestation": "simulated",
  "policy_files": ["eng-baseline-v12.json"],
  "last_sync": {"at": null, "result": null},
  "last_inventory_hash": null
}
```

The token is **not** in this file (separate 0600 file, separate blast
radius; m5-check asserts both modes and asserts the token string appears
nowhere in audit/status/results).

### 5.2 What "simulated attestation" means, exactly

No measurement, no quote, no verification of anything. The mock's register
response carries the constant `"attestation": "simulated"`; punard treats
it as an opaque label and repeats it wherever enrollment state is shown.
The spec 49 attestation step is thereby *present in the chain and honest
about being fake* — grep for `simulated` finds every place it surfaces
(result, enroll.status, enrollment.json, this doc, the mockups' own
`Simulated · VM` tags).

### 5.3 `enroll.status` — read, any connected peer, not audited

`{"enrolled", "org"|null, "policy_ids", "enrolled_at"|null,
"attestation"|null, "last_sync": {"at", "result": "success"|"unreachable"|null,
"pending": bool}}`. Never the token. `status` (5.1) additionally flips
`enrolled: true`, `mode: "managed"` (the M3 contract said "personal until
M5"), and gains the optional `org` object — additive fields, never a
redraw (design §8).

### 5.4 `enroll.stop` — root-only, audited, local restore

Guard: not enrolled → `conflict`. Then: delete exactly the
`policy_files` recorded in `enrollment.json` from policy.d → delete
`enrollment.json` + `device-token` → recompute merge → one reconcile pass →
rewrite `status.json` → audit `enroll.stop`. Result
`{"enrolled": false, "removed_policy_ids": [...]}`.

**Local-only, stated plainly:** there is no unregister RPC in M5. The mock
keeps its device record and received history — which is the honest shape:
a real control plane would also remember a device that walked away, and
"the org's copy of past category reports" is not something unenrollment can
retract (spec 24's "enrolling later never applies retroactively" cuts the
other way: unenrolling stops future flow; it does not rewrite the past).
Works offline by construction (touches only local files) — m5-check
un-enrolls with the mock stopped to prove it.

**Preference resurfacing (spec 39, designed and asserted):** removing the
org layer makes the recorded user preference the winner again — including
a preference recorded *while overridden* (M4: "it becomes effective the
moment the override goes away"). m5-check exercises the overridden-set with
`disabled`, then deliberately records `enabled` again before unenrolling,
so the restored personal state is firewall-enabled and the check ends
green; the resurfacing semantics themselves are asserted via provenance
(post-unenroll explain shows `local_user_preference`, not
`os_secure_default` — the preference written during the managed phase is
the surviving witness).

### 5.5 Managed-path `capabilities.set` — what M4 actually does (verified)

Read from `crates/punard/src/server.rs` (`handle_capabilities_set`) —
stated exactly, per the task's either/or:

- **Root caller, org-pinned path: recorded-but-overridden.** Exit 0. The
  preference is recorded, the merge recomputed, the **effective** (org)
  value applied/kept; since observed == effective the noop branch returns
  `changed: false` **plus** `overridden: true` and
  `effective_state: "enabled"`; the audit event is `result: "noop"` with
  `policy_ids: ["eng-baseline-v12"]`. It is **not** denied-by-policy —
  spec 39's precedence is "your preference is recorded and outranked", not
  "your preference is forbidden".
- **Non-root caller: denied exit 3** — but by the root-only authz rule,
  *before* any policy consult, and today's message says "Policy: personal
  defaults — just-in-time elevation arrives in Milestone 9"
  (`punar_common::IpcError::denied_needs_root`), which becomes a false
  citation on a managed path. **M5 amendment (small, honest):** when the
  target path is org-pinned (`user_override_permitted == false`), the
  denial message and `details.policy_ids` cite the pinning source in the
  section 73 voice — "security.firewall is managed by Acme Engineering
  Baseline (eng-baseline-v12). User override: not permitted. Next step:
  exceptions require approval (Milestone 9)." Exit code stays 3; unpinned
  paths keep the M3/M4 message byte-identical.
- **`punarctl` render amendment:** the overridden result fields exist
  since M4 but never fired in-VM; the human view ignores them
  (crates/punarctl/src/views.rs `set`). M5 adds the verdict line for
  `overridden: true`: neutral slot, "Recorded, not applied ·
  security.firewall is managed by Acme Engineering Baseline
  (eng-baseline-v12) · effective: enabled". `--json` was already complete.

## 6. Compliance and inventory sync (spec 52, 54, 24)

**Piggyback, no new timers (decision):** the sync hook runs at the end of
every full reconcile pass — boot, 120 s timer, manual, and the passes
inside enroll.start/stop — **when enrolled**. The 120 s
`punard-reconcile.timer` cadence (justified in milestone-4.md §6) is
therefore also the sync cadence; a second timer would add a wakeup source
for nothing.

**Compliance report — category states only** (spec 54: the org sees
security-audit/operational categories, not activity; spec 24: no automatic
stream of detail):

```json
{"overall": "compliant",
 "categories": [
   {"category": "security.firewall", "state": "compliant"},
   {"category": "system.hostname",   "state": "compliant"},
   {"category": "time.timezone",     "state": "compliant"}
 ]}
```

States, not values: the report never contains the hostname string, the
timezone, nft contents, audit events, or anything behavioral. m5-check
asserts the received line's key set **exactly** (jq allowlist) — absence of
extra keys is a first-class privacy assertion, not a hope.

**Inventory — device info + capability states, nothing behavioral**
(spec 50 "inventory"; spec 54 "software inventory" category):

```json
{"os": {"id": "...", "version_id": "...", "pretty_name": "..."},
 "kernel": "...",
 "hostname": "...",
 "capabilities": [
   {"capability": "security.firewall", "supported": true, "current_state": "enabled"},
   {"capability": "system.hostname",   "supported": true, "current_state": "..."},
   {"capability": "time.timezone",     "supported": true, "current_state": "UTC"}
 ]}
```

Sources: `/etc/os-release` fields, `uname -r`, the live descriptor reads
the registry already does. Sent once inside enroll.start, then **only when
changed**: SHA-256 of the canonically-serialized inventory is stored as
`last_inventory_hash` in `enrollment.json`; the sync hook compares and
skips (the hash gate). m5-check asserts the second reconcile grows the
compliance file but not the inventory file.

Send order per pass: compliance, then inventory-if-changed; each is one
RPC with the stored token; per-call failure marks that report pending (§7).

## 7. Offline behavior (spec 55) — the minimal honest version

- **Enrollment persists**: `enrollment.json`, `device-token`, and the
  policy.d envelopes are ordinary root files; nothing about them references
  the mock's liveness. "Enrollment does not silently downgrade."
- **Policy stays enforceable**: the merge reads policy.d from disk at
  startup and holds it in memory; reconcile remediates against the cached
  org layer with the mock stopped — the m5-check offline phase is exactly
  spec 55's "local policy remains enforceable".
- **Queue — bounded, latest-wins (decision)**: two in-memory slots,
  `pending_compliance: bool` and `pending_inventory: bool`. A failed
  report sets its flag; every subsequent reconcile pass (≤120 s later via
  the timer) rebuilds the *current* report and retries. No spool of
  historical reports: compliance/inventory are **state snapshots**, so an
  intermediate report that never got through carries no information the
  next snapshot doesn't supersede — latest-wins is the correct semantics,
  not a shortcut (contrast audit events, which are history and already
  persist locally in `audit.jsonl`; audit *upload* is no part of M5).
  Bounded by construction: two booleans.
- **`last_sync`**: `{at, result}` persisted in `enrollment.json` on every
  attempt outcome (success timestamps refresh; `"unreachable"` recorded on
  failure); `enroll.status` adds the in-memory `pending`.
- **Audit on transitions only (decision)**: `action: "enroll.sync"`,
  `resource: "control_plane"`, `result: "unreachable"` once when
  reachable→unreachable, `result: "success"` once on recovery — not one
  event per 120 s retry, which would be log spam encoding no new fact.
  The task's "sync-failure audited" is satisfied by the transition event;
  the steady state is visible in `enroll.status.last_sync`.

## 8. Shell wiring — `/run/punar/status.json` + `Status.qml`

### 8.1 The file (side contract, documented in ipc.md §9)

Written by `punard` — at startup, and whenever the summary tuple changes
(enroll, unenroll, any reconcile pass that changes `compliance_overall`,
org rename via re-enroll). Atomic tmp+rename **within `/run/punar`**, mode
0644 root:root. Content, summary ONLY:

```json
{"v": 1, "enrolled": true, "org_name": "Acme Engineering",
 "compliance_overall": "compliant", "ts": "2026-08-26T09:02:00Z"}
```

Nothing else — no per-capability rows, no policy ids, no device id, no
hostname: the file is world-readable in a user-owned directory, so it
carries exactly what the bar renders and nothing an unprivileged reader
shouldn't have (it duplicates only what `status` already tells any
group-punar peer, minus detail).

Honest placement note (the ipc.md 1.1 argument, inverted): `/run/punar` is
`0755 punar:punar` (M1 contract), so the session user can delete/replace
this file. That is acceptable **because the file is non-authoritative
display data consumed by that same user's own session** — a user spoofing
their own bar spoofs nobody; authority (and anything root-trusted) stays on
the socket. The daemon rewrites the file on the next state change;
`enrolled:false` is the fail-closed default when it is missing or invalid.

`punard` startup order note: `/run/punar` is created by tmpfiles
(`punar-desktop.conf`) before basic.target, hence before punard starts —
no ordering change needed (same guarantee punard already relies on for its
own directories, see punard.service comments).

### 8.2 `Status.qml` (the M1 stub retires)

The singleton keeps its consumer surface (`enrolled`, `state`, `label`,
`color`, `project`) and gains `orgName`. Internals: a Quickshell
`FileView` on `/run/punar/status.json` with change-watching (the
`WorkspaceState.qml` / `Theme.qml` pattern already in the tree — FileView
is the established file-watch primitive; **event-driven, zero polling**),
`JSON.parse` on content change:

- parse ok → `enrolled = j.enrolled === true`, `orgName = j.org_name || ""`,
  `state` mapped from `compliance_overall`: `compliant → "ok"`,
  `non_compliant → "bad"`, everything else (`remediating`, `unknown`,
  `exception`) → `"warn"`; `label` keeps its existing §52 word mapping
  with `Unknown`/`Exception` words added.
- file missing / parse error → `enrolled = false` (calm paper; design §8
  enforced at the source, as the stub's comment promised).

`Bar.qml`: one added `MetaLabel` in the right-hand row — `visible:
Status.enrolled`, `text: Status.orgName + " · "` — before the existing
dot + label + clock. Rendered result (MetaLabel uppercases):
`ACME ENGINEERING · COMPLIANT · 14:02`, the system-control mockup masthead
grammar (`Acme Engineering · eng-baseline-v12 · reported 08:24` compressed
to bar scale — org name + state; the policy id stays in `punarctl status`
and the future control panel, not the 30 px bar). Enrollment is additive
chrome on the same surface: the personal bar is byte-identical to M4.

Verification: qmllint via the pinned container (`shell/.qmllint.ini`);
visual truth via the two m5-check screenshots.

### 8.3 CLI surface (D-014)

- `punarctl enroll start <domain>` — masthead `PUNAR · ENROLL`; renders
  org, policy ids, `Attestation  SIMULATED` (uppercased, deliberately
  loud), first-sync results. Client response timeout raised to 90 s for
  this verb (ipc.md §2 amendment).
- `punarctl enroll status` / `punarctl enroll stop` — same grammar;
  stop renders "Personal state restored · org layers removed".
- `punarctl status` — adds an `Organization  Acme Engineering ·
  eng-baseline-v12` row when enrolled (absent otherwise — no org rows on
  personal devices, unchanged rule).
- Managed-path strings in `policy explain` need **zero work**: the M4
  renderer prints the server's source fields verbatim, so
  `Acme Engineering Baseline` / `eng-baseline-v12` / `Not permitted`
  appear as soon as the merge says so (spec 40 output, now real).
- The §5.5 overridden verdict line and org-citing denial are the only
  render changes.

## 9. Budgets (spec 6.2/6.3, PERFORMANCE_BUDGETS.md)

- **The mock runs only during the m5-check window** — started by the
  check, stopped by the check (twice: the offline phase and final
  teardown). It is not running during boot, the idle-RAM sampling window
  (which closes before idle-ram.sh starts any check service), or steady
  state. The `PUNAR_SERVICES_RSS_MB` gate sums the **`punard.service`
  cgroup only** (M4-verified: first real reading 2 MB), so the mock is
  structurally outside the gate — justification: it is CI scaffolding, not
  a Punar service; gating it would gate the test harness, not the product.
  Expected footprint anyway: single-threaded, serde + std, well under
  10 MB.
- **`punard` growth** (enrollment client, sync, status.json writer) lands
  inside the existing gated cgroup — the gate, not an estimate, is the
  check.
- **No new wakeup sources**: sync piggybacks the existing timer; the shell
  watches one file event-driven; status.json writes happen only on change.

## 10. In-VM exercise plan — `m5-check`

### 10.1 Mechanics

Mirror of m2/m3/m4: `punar-m5-check.service` — root, `Type=oneshot`,
**not enabled**, `TimeoutStartSec=15min` — runs
`/usr/lib/punar/m5-check.sh`; always exits 0; verdict in
`/run/punar/m5-report.txt` (`ok`/`FAIL` lines, final `PUNAR_M5_OK` /
`PUNAR_M5_FAIL`). `idle-ram.sh` starts it synchronously after
`punar-m4-check.service`, before the export; `tools/boot-test.sh` gains
the copy + hard-fail phase (export/CI timeouts bumped accordingly);
`ci.yml` ships `m5-report.txt`, `punar-m5.png`, `punar-m5-personal.png` in
the same artifact tar; shellcheck (pinned v0.11.0) covers the new script.

Timer determinism: m4-check phase B leaves `punard-reconcile.timer`
running; m5-check **stops it at the top** (every sync below has exactly one
actor: the script's own `punarctl reconcile` calls) and restarts it at the
end (shipped default restored).

Screenshot mechanics: m5-check runs as root (m4 pattern), so screenshots
use the m2-check session-env discovery re-run under the session user —
`runuser -u punar` with `XDG_RUNTIME_DIR=/run/user/$(id -u punar)` and the
discovered `WAYLAND_DISPLAY`, then `grim`. Before each shot: a bounded
wait (≤10 s) after the status.json change — the FileView reload is
event-driven but not synchronous with the check; the screenshot is human
evidence, while every machine assertion reads status.json / IPC directly.

### 10.2 Assertions (machine checks via `--json` + `jq`)

Setup / pre-state:

1. `systemctl is-enabled punar-mock-smplify.service` → **not** `enabled`
   (the dev-only discipline is itself asserted); `systemctl start` it;
   socket `/run/punar-mock-smplify/api.sock` appears (bounded wait).
2. Pre-enroll: `status.json` exists with `enrolled == false`;
   `enroll status --json` → `enrolled == false`; `policy.d` empty;
   `punarctl status --json` → `mode == "personal"`.

Enroll:

3. `punarctl --json enroll start acme.com` → exit 0; result:
   `org.name == "Acme"`, `org.display_name == "Acme Engineering"`,
   `attestation == "simulated"`, `policy_ids == ["eng-baseline-v12"]`.
4. Modes: `enrollment.json` and `device-token` both `0600 root:root`;
   token value (read once by the check, held in a shell var) appears **0**
   times in `audit.jsonl`, `status.json`, and the `enroll status` output.
5. `policy.d/eng-baseline-v12.json` present, `0600`, and is the envelope
   with embedded `policy` payload (`jq .policy.kind ==
   "DeviceDesiredState"`).
6. **Spec 40 managed output, now real**: `punarctl --json policy explain
   security.firewall` → `source.kind == "organization_baseline"`,
   `source.rank == 2`, `source.policy_id == "eng-baseline-v12"`,
   `source.name == "Acme Engineering Baseline"`,
   `user_override_permitted == false`. Human output greps:
   `Acme Engineering Baseline`, `eng-baseline-v12`, `Not permitted`.

Managed set (the §5.5 behaviors, both callers):

7. As punar: `runuser -u punar -- punarctl capabilities set
   security.firewall disabled` → **exit 3**; stderr cites the org policy
   (greps: `Acme Engineering Baseline`, `eng-baseline-v12`, section-73
   prose — the M5-amended denial). Denial audited.
8. As root: `punarctl --json capabilities set security.firewall disabled`
   → **exit 0** with `changed == false`, `overridden == true`,
   `effective_state == "enabled"` (**recorded-but-overridden — the
   verified M4 behavior**); `nft` still shows the table (org value held);
   audit event `capabilities.set` `result == "noop"`,
   `policy_ids == ["eng-baseline-v12"]`; human run greps the new
   "Recorded, not applied" verdict. Then root sets `enabled` again
   (records the preference the post-unenroll assertions rely on, §5.4).

Sync (received side):

9. Root `punarctl --json reconcile` → exit 0,
   `compliance.overall == "compliant"`.
   `received-compliance.jsonl`: ≥1 line; last line `device_id` equals
   `/var/lib/punar/device-id`; `report.overall == "compliant"`;
   `report.categories` is exactly the 3 `{category, state}` pairs; **top-
   level and per-entry key sets match the §6 allowlist exactly** (the
   spec 24/54 category-only privacy assertion).
10. `received-inventory.jsonl`: exactly 1 line (sent at enroll);
    `inventory.os.id` and `inventory.kernel` non-empty;
    `inventory.capabilities | length == 3`; key-set allowlist holds.
    Second `reconcile` → compliance file grew, inventory file **still 1
    line** (hash gate).
11. `status.json`: `enrolled == true`, `org_name == "Acme Engineering"`,
    `compliance_overall == "compliant"`, mode `0644`;
    `punarctl status --json` → `mode == "managed"`, `org.id == "acme"`.
12. **Screenshot** `punar-m5.png` — enrolled bar chrome (org name + dot +
    state word).

Offline (spec 55) and recovery:

13. `systemctl stop punar-mock-smplify` → root `punarctl --json reconcile`
    → exit 0, `compliance.overall == "compliant"` (cached org policy
    enforced with the control plane dead); `nft` table present;
    `enroll status` → `last_sync.result == "unreachable"`,
    `pending == true`; audit contains one `enroll.sync` /
    `result == "unreachable"` transition event.
14. `systemctl start punar-mock-smplify` → `reconcile` → `enroll status`
    `last_sync.result == "success"`, `pending == false`;
    `received-compliance.jsonl` grew by exactly one line (latest-wins —
    the queue is a flag, not a spool); recovery `enroll.sync` /
    `result == "success"` event present.

Unenroll (offline, deliberately):

15. `systemctl stop punar-mock-smplify`; `punarctl --json enroll stop` →
    exit 0 with the mock **down** (local restore needs no counterparty);
    `policy.d` empty; `enrollment.json` and `device-token` absent.
16. Back to personal: `punarctl --json policy explain security.firewall`
    → `source.kind == "local_user_preference"`, `source.rank == 5`,
    `user_override_permitted == true`; human greps `Personal preference`,
    `Permitted`; `effective_value == "enabled"` and the nft table stands
    (the §5.4 deliberate re-record); `status --json` →
    `mode == "personal"`; `status.json` `enrolled == false`.
17. **Screenshot** `punar-m5-personal.png` — chrome gone (calm paper).
18. Audit lifecycle complete: events exist for `enroll.start` (success,
    `policy_ids ["eng-baseline-v12"]`), the step-7 denial, the step-8
    noop, `reconcile`/`reconcile.remediate` as applicable, both
    `enroll.sync` transitions, `enroll.stop` (success); token appears
    nowhere (step 4's grep re-run at the end).
19. Teardown/default state: mock stopped (it already is),
    `punard-reconcile.timer` restarted and `is-active`.

### 10.3 What the VM cannot show (honest)

- **Real transport security** — mTLS, certificate pinning, real discovery:
  out of scope by design; the trust boundary statement (§4.2) is the
  deliverable, not a simulation of TLS.
- **Attestation** — simulated end-to-end and labeled as such everywhere.
- **Multi-envelope orgs, role policies, exceptions** (ranks 1, 3, 4) —
  the mock serves one baseline envelope; the merge rungs stay host-test
  territory (M4 fixtures, unchanged).
- **Token-rotation/expiry, re-enroll flows** — `enroll.register` rotates
  on re-register (host-tested); no in-VM assertion in M5.
- **Queue behavior across a punard restart while pending** — pending flags
  are in-memory; a restart during an outage re-detects on the next pass
  (the snapshot semantics make this loss-free); host-tested, not VM-timed.

## 11. Schema deltas — none again (decision)

- `enroll.*` results, the mock protocol, and `status.json` are IPC/side
  contracts — ipc.md (and §8.1 here) is their documentation;
  `enrollment.json`, `device-token`, and the mock's state files are
  private stores (peers of `device-id`).
- policy.d content is already schema-bound
  (`schemas/policy/policy-source.json` + `schemas/desired-state`) and the
  staged fixtures are byte-copies of the repo fixtures
  `./tools/validate-schemas.sh` already validates.
- New audit strings — `action: "enroll.start"` / `"enroll.stop"` /
  `"enroll.sync"`, `result: "unreachable"` — conform to the shipped
  schema's dotted-action pattern and open `result` string.
- The **conditional-agent-fields** audit-schema follow-up (M3 §6 note,
  deferred by M4 to M5) is **deferred again, to M7, with justification**:
  no M5 event carries `source: "ai_agent"` either — the first producer of
  real agent events is the M7 registry work, and churning `required` plus
  every consumer/fixture ahead of any producer buys nothing. The
  `agt_none` / `project_id: "system"` sentinels remain the documented,
  greppable contract.
- **Audit rotation (the M3 §6 follow-up "target M5") is delivered in M5**:
  punard rotates `audit.jsonl` → `audit.jsonl.1` at 8 MiB (one rotated
  file kept, older discarded), checked at write time. Not asserted in-VM
  (M5 event volumes are nowhere near 8 MiB); host-tested. ipc.md §6
  amended.

## 12. Deferred, tracked

- `admin.devices` / `admin.device{id}` on the mock: **M10** (spec 51
  remote queries + query audit + RBAC — a real feature, not a fixture
  server's side quest). Names reserved now (§4.3).
- Real control plane transport (mTLS), IdP user auth in the enroll chain,
  real attestation: post-MVP, per spec 49's own "MVP uses a mocked Smplify
  control plane".
- Event streaming for the shell (ipc.md §8 note "revisit M5+"): status.json
  satisfies the M5 need (one summary tuple) without a subscription
  surface; revisit when a panel needs per-row live data (M6+).
- Audit **upload** (spec 54 "security audit" category, spec 55 "audit can
  queue"): local `audit.jsonl` remains the M5 record; org-side audit sync
  is control-plane work beyond the mock's stand-in role.

## 13. Verification status (spec 1.22)

Verified today (2026-08-25, repo reading): the M4 managed-set code path
(recorded-but-overridden with `overridden`/`effective_state`, noop-branch
inclusion — `crates/punard/src/server.rs handle_capabilities_set`); the
denial message's fixed "personal defaults" citation
(`crates/punar-common/src/ipc.rs denied_needs_root`) motivating the §5.5
amendment; `punarctl` set-view ignoring the overridden fields
(`crates/punarctl/src/views.rs`); the policy.d envelope-with-embedded-
payload shape and the separate-fixture-files note
(`crates/punard/src/policy.rs`, `schemas/policy/policy-source.json`
properties incl. optional `policy`); Acme fixture contents (org.json
discovery/enrollment blocks, envelope rank 2 "Acme Engineering Baseline");
`punard.service` hardening set (no `RestrictAddressFamilies` — outbound
UDS permitted); `/run/punar` 0755 punar:punar vs `/run/punard` 0750
root:punar (tmpfiles, ipc.md 1.1) grounding §8.1's placement argument;
`Status.qml` stub surface + `Bar.qml` `visible: Status.enrolled` gating;
FileView watch precedent (`WorkspaceState.qml`, `Theme.qml`);
`container-build.sh` staging pattern (shell QML → /usr/share/punar) that
the fixture staging copies; m2-check session-env/grim pattern
(`User=punar` service) and m4-check root+runuser pattern; idle-ram.sh
check chaining; ipc.md §3.3 additive rule, §2 timeouts, §4 code table, §6
rotation follow-up, §8 non-goals; system-control mockup enrollment/
compliance grammar; DESIGN_LANGUAGE §8.

Asserted, not yet verified (lands with implementation, checked by CI):
every §10.2 assertion; enroll.start total latency under TCG within the
60 s processing / 90 s client bounds; FileView pickup latency vs the ≤10 s
screenshot wait; mock RSS; the m5-report/screenshot export additions.
M4's CI run was **in flight** at planning time — if it lands red, its
fixes precede M5 implementation; nothing in this plan assumes its outcome
beyond what M3-green already proved.
